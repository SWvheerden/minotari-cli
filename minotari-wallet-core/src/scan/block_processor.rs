//! Block processing logic for wallet output detection and balance tracking.
//!
//! This module contains the [`BlockProcessor`] which is responsible for analyzing
//! scanned blocks to detect wallet-owned outputs, track spending via inputs,
//! manage confirmation status, and emit events for each processed block.

use chrono::{DateTime, Utc};
use log::{error, info, trace, warn};
use minotari_scanning::BlockScanResult;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use tari_common_types::payment_reference::generate_payment_reference;
use tari_common_types::transaction::TxId;
use tari_common_types::types::{FixedHash, PrivateKey};
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::transaction_components::{Transaction, WalletOutput};
use thiserror::Error;

use crate::scan::block_event_accumulator::BlockEventAccumulator;
use crate::{
    db::{self, WalletDbError, get_burn_proof_by_output_hash},
    log::{mask_amount, mask_string},
    models::{BalanceChange, OutputStatus, WalletEvent, WalletEventType},
    scan::events::{
        DetectedOutput, DisplayedTransactionsEvent, EventSender, NoopEventSender, ProcessingEvent, ScanStatusEvent,
        SpentInput, TransactionsUpdatedEvent,
    },
    transactions::{TransactionDisplayStatus, displayed_transaction_processor::DisplayedTransactionProcessor},
    webhooks::{WebhookTriggerConfig, utils::trigger_webhook_with_balance},
};

/// Errors that can occur during block processing.
#[derive(Debug, Error)]
pub enum BlockProcessorError {
    /// A database operation failed.
    #[error("Database execution error: {0}")]
    DbError(#[from] WalletDbError),

    /// Failed to insert or process a wallet event.
    #[error("Failed to insert wallet event: {0}")]
    WalletEvent(#[from] anyhow::Error),
}

/// Processes scanned blocks and persists wallet data.
///
/// The `BlockProcessor` is the workhorse of the scanning system. For each block,
/// it performs the following operations:
///
/// 1. **Output Detection**: Identifies outputs owned by the wallet and persists them
/// 2. **Input Tracking**: Detects when wallet outputs are spent as inputs
/// 3. **Confirmation Tracking**: Updates output confirmation status as blocks mature
/// 4. **Balance Changes**: Records all balance-affecting events
/// 5. **Event Emission**: Sends real-time events for UI updates
///
/// # Type Parameter
///
/// The processor is generic over the event sender type, defaulting to [`NoopEventSender`]
/// for cases where real-time events are not needed.
///
/// # Example
///
/// ```rust,ignore
/// use crate::scan::{BlockProcessor, ChannelEventSender};
///
/// // Create with event sender
/// let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
/// let event_sender = ChannelEventSender::new(tx);
/// let mut processor = BlockProcessor::with_event_sender(
///     vec![(account_id, view_key)],
///     event_sender,
///     false,
///     6,
/// );
///
/// // Process a block
/// processor.process_block(&tx, &scanned_block, account_id)?;
///
/// // Retrieve generated wallet events
/// let events = processor.into_wallet_events();
/// ```
pub struct BlockProcessor<E: EventSender = NoopEventSender> {
    /// Mapping of wallet index to account ID for active scanning set.
    wallet_index_to_account_id: Vec<i64>,
    /// Account view keys indexed by account ID.
    account_view_keys: HashMap<i64, PrivateKey>,
    /// Accumulated wallet events for the current processing session.
    wallet_events: Vec<WalletEvent>,
    /// Event sender for real-time notifications.
    event_sender: E,
    /// Accumulator for the block currently being processed.
    current_block: Option<BlockEventAccumulator>,
    /// Current blockchain tip height (for confirmation calculations).
    current_tip_height: u64,
    /// Whether there are pending outbound transactions to match against.
    has_pending_outbound: bool,
    /// Required confirmations
    required_confirmations: u64,
    /// Webhook Configuration
    webhook_config: Option<WebhookTriggerConfig>,
    /// When true, uses OR IGNORE inserts for outputs/inputs/balance_changes
    /// to skip already-existing records during history backfill (Phase 3 of FastSync).
    backfill_mode: bool,
    /// When true, the scan leaves inputs out of every block (Phase 1 of
    /// FastSync), so no send can be matched against a block. See
    /// [`Self::set_inputs_excluded`].
    inputs_excluded: bool,
    /// What the block being processed showed of the wallet's own sends. Only
    /// collected while `has_pending_outbound` is set. See [`Self::match_sends`].
    send_block: Option<SendBlock>,
    /// The inputs of the block being processed that spent none of the account's
    /// outputs. A block arrives as several results in no fixed order, so the
    /// output an input spends can come in a later result; it is retried then.
    unmatched_inputs: Option<UnmatchedInputs>,
}

/// The parts of one block needed to recognise the wallet's own sends in it.
///
/// A block with many outputs or inputs arrives as several [`BlockScanResult`]s
/// that share its hash, so these are collected over all of them and the sends
/// are matched once the whole block is in.
struct SendBlock {
    account_id: i64,
    height: u64,
    block_hash: FixedHash,
    /// Every input hash in the block.
    inputs: HashSet<FixedHash>,
    /// Hashes of the block's outputs that belong to this account.
    wallet_outputs: HashSet<FixedHash>,
    /// `locked_by_request_id` of every wallet output the block spends.
    request_ids: Vec<String>,
}

/// See [`BlockProcessor::unmatched_inputs`].
struct UnmatchedInputs {
    account_id: i64,
    height: u64,
    block_hash: FixedHash,
    /// Each input hash, with the block a copy of it was already spent in, if any.
    inputs: HashMap<FixedHash, Option<Vec<u8>>>,
}

impl BlockProcessor<NoopEventSender> {
    /// Creates a new block processor without event streaming.
    ///
    /// Use this constructor when you don't need real-time event updates
    /// and will retrieve wallet events via [`into_wallet_events`](Self::into_wallet_events)
    /// after processing.
    ///
    /// # Arguments
    ///
    /// * `accounts` - Ordered list mapping scanner wallet index to (account_id, account_view_key)
    pub fn new(accounts: Vec<(i64, PrivateKey)>, required_confirmations: u64) -> Self {
        let (wallet_index_to_account_id, account_view_keys) = Self::build_account_mappings(accounts);
        Self {
            wallet_index_to_account_id,
            account_view_keys,
            wallet_events: Vec::new(),
            event_sender: NoopEventSender,
            current_block: None,
            current_tip_height: 0,
            has_pending_outbound: false,
            required_confirmations,
            webhook_config: None,
            backfill_mode: false,
            inputs_excluded: false,
            send_block: None,
            unmatched_inputs: None,
        }
    }
}

impl<E: EventSender> BlockProcessor<E> {
    /// Creates a new block processor with a custom event sender.
    ///
    /// Use this constructor when you need real-time event streaming during
    /// block processing.
    ///
    /// # Arguments
    ///
    /// * `accounts` - Ordered list mapping scanner wallet index to (account_id, account_view_key)
    /// * `event_sender` - Implementation of [`EventSender`] for event notifications
    /// * `has_pending_outbound` - Whether there are pending outbound transactions
    ///   that should be matched against scanned inputs
    pub fn with_event_sender(
        accounts: Vec<(i64, PrivateKey)>,
        event_sender: E,
        has_pending_outbound: bool,
        required_confirmations: u64,
    ) -> Self {
        let (wallet_index_to_account_id, account_view_keys) = Self::build_account_mappings(accounts);
        Self {
            wallet_index_to_account_id,
            account_view_keys,
            wallet_events: Vec::new(),
            event_sender,
            current_block: None,
            current_tip_height: 0,
            has_pending_outbound,
            required_confirmations,
            webhook_config: None,
            backfill_mode: false,
            inputs_excluded: false,
            send_block: None,
            unmatched_inputs: None,
        }
    }

    fn build_account_mappings(accounts: Vec<(i64, PrivateKey)>) -> (Vec<i64>, HashMap<i64, PrivateKey>) {
        let wallet_index_to_account_id = accounts.iter().map(|(account_id, _)| *account_id).collect();
        let account_view_keys = accounts.into_iter().collect();
        (wallet_index_to_account_id, account_view_keys)
    }

    fn account_view_key(&self, account_id: i64) -> Result<&PrivateKey, BlockProcessorError> {
        self.account_view_keys
            .get(&account_id)
            .ok_or_else(|| BlockProcessorError::WalletEvent(anyhow::anyhow!("Unknown account id: {}", account_id)))
    }

    /// Updates the pending outbound transaction flag.
    ///
    /// Set to `true` when there are pending outbound transactions that should
    /// be matched against scanned inputs to link them with blockchain data.
    /// When `false`, spent inputs are not looked up as the wallet's own sends,
    /// which keeps long syncs fast.
    pub fn set_has_pending_outbound(&mut self, value: bool) {
        self.has_pending_outbound = value;
    }

    /// Sets webhook config
    pub fn set_webhook_config(&mut self, config: Option<WebhookTriggerConfig>) {
        self.webhook_config = config;
    }

    /// Enables or disables backfill mode for history backfill (Phase 3 of FastSync).
    /// In backfill mode, outputs and inputs use OR IGNORE inserts to skip duplicates.
    pub fn set_backfill_mode(&mut self, value: bool) {
        self.backfill_mode = value;
    }

    /// Tells the processor the scan leaves inputs out of every block (Phase 1
    /// of FastSync, `exclude_inputs`).
    ///
    /// Sends are then never matched against a block: without inputs the full
    /// rule cannot hold, and a mismatch would wrongly reject them. The one thing
    /// still done is settling a send the monitor rejected when its change output
    /// turns up: that change is the proof the send landed, it is linked back to
    /// the send, and nothing would look at it again later.
    pub fn set_inputs_excluded(&mut self, value: bool) {
        self.inputs_excluded = value;
    }

    /// Processes a single scanned block.
    ///
    /// This is the main entry point for block processing. It performs all
    /// processing steps in sequence:
    ///
    /// 1. Process detected outputs (wallet-owned UTXOs)
    /// 2. Process inputs (spent outputs)
    /// 3. Record the scanned block for reorg detection
    /// 4. Update confirmation status for maturing outputs
    /// 5. Save and emit displayed transactions
    /// 6. Emit a [`BlockProcessedEvent`]
    ///
    /// # Arguments
    ///
    /// * `tx` - Database transaction for atomic operations
    /// * `block` - The scanned block result from the blockchain scanner
    /// * `account_id` - Account ID to process this block for
    ///
    /// # Errors
    ///
    /// Returns [`BlockProcessorError`] if any database operation fails.
    pub fn process_block(
        &mut self,
        tx: &Connection,
        block: &BlockScanResult,
        account_id: i64,
    ) -> Result<(), BlockProcessorError> {
        let account_view_key = self.account_view_key(account_id)?.clone();

        // The previous block is complete once a result with another hash arrives.
        let starts_new_block = match &self.send_block {
            Some(send_block) => send_block.block_hash != block.block_hash || send_block.account_id != account_id,
            None => false,
        };
        if starts_new_block {
            self.match_sends(tx, true)?;
        }

        self.current_tip_height = block.height;

        self.current_block = Some(BlockEventAccumulator::new(
            account_id,
            block.height,
            block.block_hash.to_vec(),
        ));

        let same_block = matches!(
            &self.unmatched_inputs,
            Some(open) if open.account_id == account_id && open.block_hash == block.block_hash
        );
        if !same_block {
            self.close_unmatched_inputs();
            self.unmatched_inputs = Some(UnmatchedInputs {
                account_id,
                height: block.height,
                block_hash: block.block_hash,
                inputs: HashMap::new(),
            });
        }

        let mut request_ids = self.process_outputs(tx, block, account_id, &account_view_key)?;
        // Inputs of earlier results of this block that spend an output stored just now.
        let mut inputs = Vec::new();
        if let Some(open) = &mut self.unmatched_inputs {
            for (hash, _output, wallet_idx) in &block.wallet_outputs {
                if self.wallet_index_to_account_id.get(*wallet_idx).copied() == Some(account_id)
                    && open.inputs.remove(hash).is_some()
                {
                    inputs.push(*hash);
                }
            }
        }
        inputs.extend_from_slice(&block.inputs);
        request_ids.extend(self.process_inputs(tx, block, account_id, &inputs)?);
        if !self.inputs_excluded && (self.has_pending_outbound || !request_ids.is_empty()) {
            self.collect_send_block(block, account_id, request_ids);
        }
        self.record_scanned_block(tx, block, account_id)?;
        self.process_confirmations(tx, block, account_id)?;

        if let Some(acc) = self.current_block.take() {
            if !acc.is_empty() {
                self.save_and_emit_displayed_transactions(tx, block.height, account_id, &acc)?;
            }

            let block_event = acc.into_event();
            self.event_sender.send(ProcessingEvent::BlockProcessed(block_event));
        }

        Ok(())
    }

    fn save_and_emit_displayed_transactions(
        &self,
        tx: &Connection,
        block_height: u64,
        account_id: i64,
        accumulator: &BlockEventAccumulator,
    ) -> Result<(), BlockProcessorError> {
        if accumulator.is_empty() {
            return Ok(());
        }

        let processor = DisplayedTransactionProcessor::new(self.current_tip_height, self.required_confirmations);
        let (mut updated_transactions, mut new_transactions) = processor
            .create_new_updated_display_transactions_for_height(accumulator, tx)
            .map_err(|e| {
                error!(
                    block_height = block_height,
                    error:% = e;
                    "Failed to process displayed transactions"
                );
                BlockProcessorError::WalletEvent(anyhow::anyhow!("Failed to process displayed transactions: {}", e))
            })?;
        for updated in &updated_transactions {
            db::update_displayed_transaction_mined(tx, updated)?;
        }
        for new in &new_transactions {
            db::insert_displayed_transaction(tx, new)?;
        }
        updated_transactions.append(&mut new_transactions);
        self.event_sender
            .send(ProcessingEvent::TransactionsReady(DisplayedTransactionsEvent {
                account_id,
                transactions: updated_transactions,
                block_height: Some(block_height),
                is_initial_sync: false,
            }));

        Ok(())
    }

    /// Emits a scan status event through the event sender.
    ///
    /// This is a convenience method for emitting status updates during
    /// processing operations.
    pub fn emit_status(&self, status: ScanStatusEvent) {
        self.event_sender.send(ProcessingEvent::ScanStatus(status));
    }

    /// Consumes the processor and returns all accumulated wallet events.
    ///
    /// Call this after processing all blocks to retrieve the generated
    /// wallet events for persistence or further processing.
    pub fn into_wallet_events(self) -> Vec<WalletEvent> {
        self.wallet_events
    }

    /// Drains and returns accumulated wallet events while keeping the processor alive.
    pub fn take_wallet_events(&mut self) -> Vec<WalletEvent> {
        std::mem::take(&mut self.wallet_events)
    }

    /// Processes all detected outputs in the block.
    ///
    /// For each output owned by the wallet:
    /// - Inserts the output into the database
    /// - Creates a wallet event for detection
    /// - Records the balance change (credit)
    /// - Adds to the block accumulator for event emission
    ///
    /// Returns the sends the monitor rejected whose change output is in this
    /// block: they were mined after all, and are matched by `match_sends`.
    fn process_outputs(
        &mut self,
        tx: &Connection,
        block: &BlockScanResult,
        account_id: i64,
        account_view_key: &PrivateKey,
    ) -> Result<Vec<String>, BlockProcessorError> {
        let mut generated_events: Vec<(i64, WalletEvent)> = Vec::new();
        let mut request_ids = Vec::new();

        // The scanner (`scan_for_recoverable_output`) attributes each output to the
        // first account whose keys recover it, so an output shared by two accounts
        // scanned together reaches only one of them here.
        for (hash, output, wallet_idx) in &block.wallet_outputs {
            let Some(mapped_account_id) = self.wallet_index_to_account_id.get(*wallet_idx).copied() else {
                continue;
            };

            if mapped_account_id != account_id {
                continue;
            }

            let memo = MemoInfo::from_output(output);

            // Compute the payment reference from block hash and output hash
            let payment_reference = generate_payment_reference(&block.block_hash, hash);

            let is_burn = output.is_burned();

            // The change output of a send the monitor rejected: the send landed
            // after all (the hash is unique to it). Its change row is restored so
            // it is updated in place below and stays the send's change, and its
            // displayed transaction goes back to pending before this block's
            // history is built, so the block updates that one entry. The send is
            // then matched under the full rule (all inputs and change).
            if !self.backfill_mode
                && let Some((request_id, completed_tx_id)) =
                    db::restore_change_of_rejected_send(tx, account_id, account_view_key, hash)?
            {
                if let Some(displayed) = db::get_displayed_transaction_by_id(tx, &completed_tx_id.to_string())?
                    && displayed.status == TransactionDisplayStatus::Rejected
                {
                    db::reset_displayed_transaction_to_pending(tx, completed_tx_id)?;
                }
                if self.inputs_excluded {
                    // The inputs cannot be checked in this scan, and once the
                    // change is an active row nothing would find the send again,
                    // so the change (decrypted with the wallet's own keys, its hash
                    // unique to the send) settles it now.
                    let event = self.settle_rejected_send_by_change(
                        tx,
                        account_id,
                        completed_tx_id,
                        block.height,
                        &block.block_hash,
                    )?;
                    generated_events.push(event);
                } else {
                    request_ids.push(request_id);
                }
            }

            // A send's change output was written at send time as `UNCONFIRMED`.
            // Update that row in place rather than inserting a second one, so it
            // stays the send's change; the credit, event and accumulator entry
            // below are recorded as for a new output.
            let status_when_found = if self.backfill_mode {
                OutputStatus::SpentUnconfirmed
            } else {
                OutputStatus::Unspent
            };
            let change_output_id = db::confirm_unconfirmed_change_output(
                tx,
                account_id,
                hash,
                block.height,
                &block.block_hash,
                block.mined_timestamp,
                memo.parsed.clone(),
                memo.hex.clone(),
                payment_reference,
                status_when_found,
            )?;

            let output_id = if let Some(id) = change_output_id {
                id
            } else if self.backfill_mode {
                match db::insert_spent_output_if_not_exists(
                    tx,
                    account_id,
                    account_view_key,
                    hash,
                    output,
                    block.height,
                    &block.block_hash,
                    block.mined_timestamp,
                    memo.parsed.clone(),
                    memo.hex.clone(),
                    payment_reference,
                    is_burn,
                )? {
                    Some(id) => id,
                    None => continue, // Output already exists, skip events and balance changes
                }
            } else {
                let (output_id, newly_inserted) = db::insert_output(
                    tx,
                    account_id,
                    account_view_key,
                    hash,
                    output,
                    block.height,
                    &block.block_hash,
                    block.mined_timestamp,
                    memo.parsed.clone(),
                    memo.hex.clone(),
                    payment_reference,
                    is_burn,
                )?;
                if !newly_inserted {
                    // A re-read of this block: its event, webhook and credit are already recorded.
                    continue;
                }
                output_id
            };
            let tx_id = db::get_output_tx_id(tx, output_id)?;

            info!(
                target: "audit",
                account_id = account_id,
                block_height = block.height,
                value = &*mask_amount(output.value()),
                is_coinbase = output.features().is_coinbase();
                "Detected wallet output"
            );

            let event = self.make_output_detected_event(account_id, *hash, block, &memo);
            self.wallet_events.push(event.clone());

            let event_id = db::insert_wallet_event(tx, account_id, &event)?;
            generated_events.push((event_id, event));

            let balance_change = self.record_output_balance_change(tx, account_id, output_id, block, output)?;

            if let Some(ref mut acc) = self.current_block {
                acc.add_credit_change(
                    balance_change,
                    DetectedOutput {
                        tx_id,
                        height: block.height,
                        mined_in_block_hash: block.block_hash,
                        output: output.clone(),
                    },
                );
            }
        }

        if let Some(config) = &self.webhook_config {
            for (event_id, event) in generated_events {
                trigger_webhook_with_balance(tx, account_id, event_id, &event, config)?;
            }
        }

        Ok(request_ids)
    }

    /// Decides, from what the scan recorded, the wallet's pending sends
    /// (`Completed` or `Broadcast`, stalled ones included) whose inputs were
    /// spent in a block below `before_height`: a block the scan has moved past,
    /// so it is complete.
    ///
    /// A send's input may have been spent in the last block of an earlier batch,
    /// where a mismatch is not acted on (defensively; see [`Self::match_sends`]). For
    /// each such send the block is rebuilt from the database (the wallet's
    /// inputs spent in it and its outputs mined in it) and matched as a complete
    /// block by [`Self::match_sends`]: a match marks it mined, a mismatch rejects
    /// it as a send whose inputs went to a different transaction. Being database
    /// based, this also happens after a restart.
    ///
    /// Nothing is decided in a scan without inputs (FastSync Phase 1, which
    /// records no input spends) or in backfill.
    pub fn settle_sends_in_passed_blocks(
        &mut self,
        tx: &Connection,
        account_id: i64,
        before_height: u64,
    ) -> Result<(), BlockProcessorError> {
        if self.inputs_excluded || self.backfill_mode {
            return Ok(());
        }
        // Any block still open stays open.
        let open_block = self.send_block.take();

        let mut sends =
            db::get_completed_transactions_by_status(tx, account_id, db::CompletedTransactionStatus::Completed)?;
        sends.extend(db::get_completed_transactions_by_status(
            tx,
            account_id,
            db::CompletedTransactionStatus::Broadcast,
        )?);

        for send in sends {
            let Ok(transaction) = serde_json::from_slice::<Transaction>(&send.serialized_transaction) else {
                continue;
            };
            // The block the earliest of its inputs was spent in.
            let mut spend: Option<(u64, Vec<u8>)> = None;
            for input in transaction.body().inputs() {
                if let Some((height, block_hash)) = db::get_output_spend(tx, account_id, &input.output_hash())?
                    && spend.as_ref().is_none_or(|(earliest, _)| height < *earliest)
                {
                    spend = Some((height, block_hash));
                }
            }
            let Some((height, block_hash)) = spend else {
                continue;
            };
            if height >= before_height {
                // Not yet moved past: decided once the scan has (defensively).
                continue;
            }
            let Ok(block_hash) = FixedHash::try_from(block_hash) else {
                continue;
            };

            let inputs = db::get_output_hashes_spent_in_block(tx, account_id, height, block_hash.as_slice())?;
            let wallet_outputs = db::get_output_hashes_mined_in_block(tx, account_id, height, block_hash.as_slice())?;
            self.send_block = Some(SendBlock {
                account_id,
                height,
                block_hash,
                inputs: inputs.into_iter().collect(),
                wallet_outputs: wallet_outputs.into_iter().collect(),
                request_ids: vec![send.pending_tx_id.clone()],
            });
            self.match_sends(tx, true)?;
        }

        self.send_block = open_block;
        Ok(())
    }

    /// Marks a send the monitor rejected `MinedUnconfirmed` in the block at
    /// `height`, on the evidence of its change output alone, and persists
    /// `TransactionUnconfirmed`. Used only when the inputs cannot be checked: a
    /// scan that excludes them (see [`Self::set_inputs_excluded`]), or the last
    /// block of a batch, which is defensively not treated as decided.
    fn settle_rejected_send_by_change(
        &mut self,
        tx: &Connection,
        account_id: i64,
        completed_tx_id: TxId,
        height: u64,
        block_hash: &FixedHash,
    ) -> Result<(i64, WalletEvent), BlockProcessorError> {
        info!(
            target: "audit",
            height = height;
            "Transaction the monitor rejected was mined after all (its change is in a block)"
        );
        trace!(
            target: "audit",
            id = completed_tx_id.to_string().as_str();
            "Transaction the monitor rejected was mined after all (its change is in a block)"
        );
        #[allow(clippy::cast_possible_wrap)]
        db::mark_completed_transaction_as_mined_unconfirmed(tx, completed_tx_id, height as i64, block_hash.as_slice())?;
        let event = WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::TransactionUnconfirmed {
                tx_id: completed_tx_id,
                mined_height: height,
                confirmations: 0,
            },
            description: format!("Transaction {} mined at height {}", completed_tx_id, height),
        };
        let event_id = db::insert_wallet_event(tx, account_id, &event)?;
        self.wallet_events.push(event.clone());
        Ok((event_id, event))
    }

    /// Creates a wallet event for a newly detected output.
    fn make_output_detected_event(
        &self,
        account_id: i64,
        hash: FixedHash,
        block: &BlockScanResult,
        memo: &MemoInfo,
    ) -> WalletEvent {
        WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::OutputDetected {
                hash,
                block_height: block.height,
                block_hash: block.block_hash.to_vec(),
                memo_parsed: memo.parsed.clone(),
                memo_hex: memo.hex.clone(),
            },
            description: format!("Detected output at height {}", block.height),
        }
    }

    /// Records a balance change for a detected output (credit).
    fn record_output_balance_change(
        &self,
        tx: &Connection,
        account_id: i64,
        output_id: i64,
        block: &BlockScanResult,
        output: &WalletOutput,
    ) -> Result<BalanceChange, BlockProcessorError> {
        let change = make_balance_change_for_output(account_id, output_id, block.mined_timestamp, block.height, output);
        // One credit per output row, however often its block is read.
        db::insert_balance_change_if_not_exists(tx, &change)?;
        Ok(change)
    }

    /// Processes all inputs in the block to detect spent outputs.
    ///
    /// For each input that references a wallet-owned output:
    /// - Picks the output row it spends (see [`db::get_output_copies`])
    /// - Inserts the input record into the database
    /// - Records the balance change (debit)
    /// - Updates the output status to Spent
    /// - Adds to the block accumulator for event emission
    ///
    /// While `has_pending_outbound` is set, also returns the
    /// `locked_by_request_id` of every spent output that had one: the sends
    /// that may have landed in this block.
    fn process_inputs(
        &mut self,
        tx: &Connection,
        block: &BlockScanResult,
        account_id: i64,
        inputs: &[FixedHash],
    ) -> Result<Vec<String>, BlockProcessorError> {
        let mut request_ids = Vec::new();
        for input_hash in inputs {
            let copies = db::get_output_copies(tx, account_id, input_hash)?;
            if copies.is_empty() {
                // Not the account's, or its output is in a later result of this block.
                if let Some(open) = &mut self.unmatched_inputs {
                    open.inputs.entry(*input_hash).or_insert(None);
                }
                continue;
            }
            // Already recorded for this block: a re-read, a later result of it, or a repeat within one.
            if copies
                .iter()
                .any(|c| c.spent_in_block_hash.as_deref() == Some(block.block_hash.as_slice()))
            {
                continue;
            }
            // The newest copy mined at or below this block that is not spent yet. An
            // older copy was spent before a newer one was created, even when that
            // spend is not recorded yet (FastSync processes spends out of height order).
            let Some(copy) = copies.iter().rev().find(|c| {
                c.spent_in_block_hash.is_none()
                    && u64::try_from(c.mined_in_block_height).is_ok_and(|h| h <= block.height)
            }) else {
                // Nothing left to spend yet: a later result of this block can still
                // store a re-created copy. See `close_unmatched_inputs`.
                if let Some(open) = &mut self.unmatched_inputs {
                    let spent_in = copies.iter().rev().find_map(|c| c.spent_in_block_hash.clone());
                    open.inputs.insert(*input_hash, spent_in);
                }
                continue;
            };
            let output_id = copy.id;
            let other_copy_ids: Vec<i64> = copies.iter().map(|c| c.id).filter(|id| *id != output_id).collect();
            #[allow(clippy::cast_sign_loss)]
            let tx_id = TxId::from(copy.tx_id as u64);
            let output: WalletOutput = serde_json::from_str(&copy.wallet_output_json).map_err(WalletDbError::from)?;

            info!(
                target: "audit",
                account_id = account_id,
                block_height = block.height,
                value = &*mask_amount(output.value());
                "Detected spent input"
            );
            trace!(
                target: "audit",
                tx_id:% = tx_id;
                "Detected spent input"
            );

            let input_id = db::insert_input(
                tx,
                account_id,
                output_id,
                block.height,
                block.block_hash.as_slice(),
                block.mined_timestamp,
            )?;

            let balance_change = self.record_input_balance_change(tx, account_id, input_id, output.value(), block)?;
            db::update_output_status(tx, output_id, OutputStatus::Spent)?;

            if self.has_pending_outbound
                && let Some(request_id) = db::get_output_lock_request_id(tx, output_id)?
            {
                request_ids.push(request_id);
            }

            if let Some(ref mut acc) = self.current_block {
                acc.add_debit_change(
                    balance_change,
                    SpentInput {
                        tx_id,
                        mined_in_block: block.block_hash,
                        mined_in_block_height: block.height,
                        output_id,
                        other_copy_ids,
                        output,
                    },
                );
            }
        }

        Ok(request_ids)
    }

    /// Ends the batch: its last block is complete (a base node never splits a
    /// block across batches), so its unmatched inputs are settled now rather than
    /// carried into a rollback or the next poll.
    pub fn finish_batch(&mut self) {
        self.close_unmatched_inputs();
    }

    #[cfg(test)]
    pub(crate) fn has_unmatched_inputs(&self) -> bool {
        self.unmatched_inputs.is_some()
    }

    /// Ends the open block's unmatched inputs. One that lists a copy already spent
    /// in another block is logged: that spend cannot happen again (a reorg would
    /// have removed its record first), so the input is ignored.
    fn close_unmatched_inputs(&mut self) {
        let Some(open) = self.unmatched_inputs.take() else {
            return;
        };
        for spent_in_block in open.inputs.values().flatten() {
            warn!(
                target: "audit",
                account_id = open.account_id,
                block_height = open.height,
                block_hash = &*hex::encode(open.block_hash),
                spent_in_block_hash = &*hex::encode(spent_in_block);
                "Input lists a wallet output already spent in another block; ignoring it"
            );
        }
    }

    /// Adds this block result's inputs, wallet outputs and spent requests to
    /// [`Self::send_block`].
    fn collect_send_block(&mut self, block: &BlockScanResult, account_id: i64, request_ids: Vec<String>) {
        let send_block = self.send_block.get_or_insert_with(|| SendBlock {
            account_id,
            height: block.height,
            block_hash: block.block_hash,
            inputs: HashSet::new(),
            wallet_outputs: HashSet::new(),
            request_ids: Vec::new(),
        });
        send_block.inputs.extend(block.inputs.iter().copied());
        for (hash, _output, wallet_idx) in &block.wallet_outputs {
            if self.wallet_index_to_account_id.get(*wallet_idx).copied() == Some(account_id) {
                send_block.wallet_outputs.insert(*hash);
            }
        }
        send_block.request_ids.extend(request_ids);
    }

    /// Matches the wallet's own sends against the last block collected by
    /// [`Self::collect_send_block`]. Call after the last block of a batch with
    /// `block_is_complete = false`; earlier blocks are matched, complete, when
    /// a result with another hash starts.
    ///
    /// A send whose locked input was spent in the block is looked up (only
    /// `Completed` or `Broadcast` sends), once per block. It counts as mined
    /// in this block when every one of its inputs is spent in the block and
    /// its change output appears in the block. Only the change output is
    /// checked among the send's own outputs: other outputs the wallet owns
    /// (self-sends) cannot be told apart before the scan finds them. A send
    /// without a change row (made before change was required, or assembled
    /// outside this crate) is matched on its inputs alone.
    ///
    /// A mined send is marked `MinedUnconfirmed`. Otherwise its inputs were
    /// spent by a different transaction: it is marked `Rejected` (recording the
    /// block so a reorg can revert it), its change `REJECTED` and its displayed
    /// transaction rejected. Its inputs that were spent in the block stay
    /// `SPENT`; any it still had locked are released.
    ///
    /// The base node sends blocks whole, so the last block of a batch is complete
    /// too; defensively, it is still not treated as decided: when
    /// `block_is_complete` is false a mismatch is only logged and the send is
    /// left as it is; once the scan has moved past that block,
    /// [`Self::settle_sends_in_passed_blocks`] decides it from what the scan
    /// recorded (match or rejection). The node's word never does.
    ///
    /// This relies on the wallet seeing the whole block. A mismatch is logged at
    /// `warn` on the audit target.
    pub fn match_sends(&mut self, tx: &Connection, block_is_complete: bool) -> Result<(), BlockProcessorError> {
        let Some(send_block) = self.send_block.take() else {
            return Ok(());
        };
        // Without inputs no send can match, and none may be rejected.
        if self.inputs_excluded {
            return Ok(());
        }

        let mut generated_events: Vec<(i64, WalletEvent)> = Vec::new();
        let mut rejected_displayed_transactions = Vec::new();
        let mut seen_request_ids = HashSet::new();

        for request_id in &send_block.request_ids {
            if !seen_request_ids.insert(request_id.as_str()) {
                continue;
            }
            let Some(completed) = db::get_completed_transaction_to_match(tx, send_block.account_id, request_id)? else {
                continue;
            };
            // Rejected by the monitor, whose inputs were released; not one the
            // scan rejected (that has a `mined_height` and is not returned).
            let was_rejected = completed.status == db::CompletedTransactionStatus::Rejected;

            // A row that cannot be decoded must not fail the block: the batch
            // would roll back and the same block be retried for ever.
            let transaction: Transaction = match serde_json::from_slice(&completed.serialized_transaction) {
                Ok(transaction) => transaction,
                Err(e) => {
                    warn!(
                        target: "audit",
                        error:% = e;
                        "Cannot decode stored transaction; not matching it against this block"
                    );
                    continue;
                },
            };

            let mut all_inputs_in_block = true;
            let mut input_hashes = Vec::new();
            for input in transaction.body().inputs() {
                if !send_block.inputs.contains(&input.output_hash()) {
                    all_inputs_in_block = false;
                }
                input_hashes.push(input.output_hash());
            }

            let change_in_block = match db::get_change_output_hash_for_request(tx, request_id)? {
                Some(change_hash) => send_block.wallet_outputs.contains(&change_hash),
                // Legacy send: no change row to look for, so the inputs decide;
                // but never for a send the monitor rejected, which needs its change
                // as proof that it landed.
                None => !was_rejected,
            };

            #[allow(clippy::cast_possible_wrap)]
            let block_height = send_block.height as i64;

            if all_inputs_in_block && change_in_block {
                info!(
                    target: "audit",
                    height = send_block.height;
                    "Transaction mined (unconfirmed)"
                );
                trace!(
                    target: "audit",
                    id = completed.id.to_string().as_str();
                    "Transaction mined (unconfirmed)"
                );
                db::mark_completed_transaction_as_mined_unconfirmed(
                    tx,
                    completed.id,
                    block_height,
                    send_block.block_hash.as_slice(),
                )?;
                // The inputs are spent by this send: record it as their holder.
                // One may still be locked to another send that tried to spend it
                // (and is rejected for it); a reorg must not hand it to that one.
                db::record_spender_of_inputs(
                    tx,
                    send_block.account_id,
                    request_id,
                    &input_hashes,
                    send_block.block_hash.as_slice(),
                )?;

                let event = WalletEvent {
                    id: 0,
                    account_id: send_block.account_id,
                    event_type: WalletEventType::TransactionUnconfirmed {
                        tx_id: completed.id,
                        mined_height: send_block.height,
                        confirmations: 0,
                    },
                    description: format!("Transaction {} mined at height {}", completed.id, send_block.height),
                };
                let event_id = db::insert_wallet_event(tx, send_block.account_id, &event)?;
                self.wallet_events.push(event.clone());
                generated_events.push((event_id, event));

                if was_rejected {
                    info!(target: "audit", "Transaction the monitor rejected was mined after all");
                    trace!(
                        target: "audit",
                        id = completed.id.to_string().as_str();
                        "Transaction the monitor rejected was mined after all"
                    );
                }
                continue;
            }

            if !block_is_complete {
                warn!(
                    target: "audit",
                    height = send_block.height,
                    all_inputs_in_block = all_inputs_in_block,
                    change_in_block = change_in_block;
                    "Transaction not matched in the last block of a batch; deciding once the scan moves past it"
                );
                if was_rejected && change_in_block {
                    // A send the monitor rejected is only taken up when its change
                    // is in this block, and that change has been restored, credited
                    // and shown in its history entry. Rejecting it again in a block
                    // not yet treated as decided would be wrong, and leaving it rejected
                    // would leave it so for good (nothing finds it again once its
                    // change is active). The change is the proof it landed, as in a
                    // scan without inputs: settle it on that.
                    let event = self.settle_rejected_send_by_change(
                        tx,
                        send_block.account_id,
                        completed.id,
                        send_block.height,
                        &send_block.block_hash,
                    )?;
                    generated_events.push(event);
                }
                continue;
            }

            if was_rejected {
                // Not this send after all: it stays rejected. Its displayed
                // transaction was put back to pending for this block (and may have
                // been shown at this block's height); make it the unmined, rejected
                // entry it was, and announce it.
                db::reset_displayed_transaction_to_pending(tx, completed.id)?;
                if let Some(displayed) = db::mark_displayed_transaction_rejected(tx, completed.id)? {
                    rejected_displayed_transactions.push(displayed);
                }
                continue;
            }

            let reason = "inputs spent by a different transaction".to_string();
            warn!(
                target: "audit",
                height = send_block.height,
                all_inputs_in_block = all_inputs_in_block,
                change_in_block = change_in_block;
                "Transaction inputs spent by a different transaction; marking it rejected"
            );
            db::mark_completed_transaction_as_rejected_in_block(
                tx,
                completed.id,
                &reason,
                block_height,
                send_block.block_hash.as_slice(),
            )?;
            db::mark_change_output_rejected(tx, request_id)?;
            // Inputs of the send that were not spent in this block are still
            // locked to it; hand them back. Inputs spent here are already
            // `SPENT` and the change is already `REJECTED`, so neither is touched.
            db::unlock_outputs_for_request(tx, request_id)?;
            if let Some(displayed) = db::mark_displayed_transaction_rejected(tx, completed.id)? {
                rejected_displayed_transactions.push(displayed);
            }

            let event = WalletEvent {
                id: 0,
                account_id: send_block.account_id,
                event_type: WalletEventType::TransactionRejected {
                    tx_id: completed.id,
                    reason,
                },
                description: format!(
                    "Transaction {} rejected: its inputs were spent by a different transaction at height {}",
                    completed.id, send_block.height
                ),
            };
            let event_id = db::insert_wallet_event(tx, send_block.account_id, &event)?;
            self.wallet_events.push(event.clone());
            generated_events.push((event_id, event));
        }

        if !rejected_displayed_transactions.is_empty() {
            self.event_sender
                .send(ProcessingEvent::TransactionsUpdated(TransactionsUpdatedEvent {
                    account_id: send_block.account_id,
                    updated_transactions: rejected_displayed_transactions,
                }));
        }

        if let Some(config) = &self.webhook_config {
            for (event_id, event) in generated_events {
                trigger_webhook_with_balance(tx, send_block.account_id, event_id, &event, config)?;
            }
        }

        Ok(())
    }

    /// Records a balance change for a spent input (debit).
    fn record_input_balance_change(
        &self,
        tx: &Connection,
        account_id: i64,
        input_id: i64,
        value: MicroMinotari,
        block: &BlockScanResult,
    ) -> Result<BalanceChange, BlockProcessorError> {
        #[allow(clippy::cast_possible_wrap)]
        let effective_date = DateTime::<Utc>::from_timestamp(block.mined_timestamp as i64, 0)
            .unwrap_or_else(Utc::now)
            .naive_utc();

        let change = BalanceChange {
            account_id,
            caused_by_output_id: None,
            caused_by_input_id: Some(input_id),
            description: "Output spent as input".to_string(),
            balance_credit: 0.into(),
            balance_debit: value,
            effective_date,
            effective_height: block.height,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_hex: None,
            memo_parsed: None,
            claimed_fee: None,
            claimed_amount: None,
            is_reversal: false,
            reversal_of_balance_change_id: None,
            is_reversed: false,
        };
        // One debit per input row, however often its block is read.
        db::insert_balance_change_if_not_exists(tx, &change)?;
        Ok(change)
    }

    /// Records the scanned block for reorg detection.
    ///
    /// Stores the block height and hash in the scanned_tip_blocks table,
    /// which is used to detect chain reorganizations.
    fn record_scanned_block(
        &self,
        tx: &Connection,
        block: &BlockScanResult,
        account_id: i64,
    ) -> Result<(), BlockProcessorError> {
        #[allow(clippy::cast_possible_wrap)]
        db::insert_scanned_tip_block(tx, account_id, block.height as i64, block.block_hash.as_slice())?;
        Ok(())
    }

    /// Processes confirmation status updates for maturing outputs.
    ///
    /// Finds outputs that have reached the required confirmation depth
    /// and updates their status to confirmed.
    fn process_confirmations(
        &mut self,
        tx: &Connection,
        block: &BlockScanResult,
        account_id: i64,
    ) -> Result<(), BlockProcessorError> {
        let mut generated_events: Vec<(i64, WalletEvent)> = Vec::new();

        let unconfirmed_outputs =
            db::get_unconfirmed_outputs(tx, account_id, block.height, self.required_confirmations)?;

        for unconfirmed_output in unconfirmed_outputs {
            info!(
                target: "audit",
                account_id = account_id,
                original_height = unconfirmed_output.mined_in_block_height,
                confirmed_at = block.height;
                "Output confirmed"
            );
            trace!(
                target: "audit",
                output_hash = &*mask_string(&hex::encode(unconfirmed_output.output_hash));
                "Output confirmed"
            );

            let event = self.make_confirmation_event(
                account_id,
                &unconfirmed_output.output_hash,
                unconfirmed_output.mined_in_block_height as u64,
                block.height,
                unconfirmed_output.memo_parsed,
                unconfirmed_output.memo_hex,
            );

            self.wallet_events.push(event.clone());
            let event_id = db::insert_wallet_event(tx, account_id, &event)?;
            generated_events.push((event_id, event));

            db::mark_output_confirmed(tx, unconfirmed_output.id, block.height, block.block_hash.as_slice())?;

            // If this is a burn output, check if we have a matching pending burn proof
            // and log that the daemon should pick it up for burn output proof fetching.
            if unconfirmed_output.is_burn != 0 {
                match get_burn_proof_by_output_hash(tx, &unconfirmed_output.output_hash) {
                    Ok(Some(_proof)) => {
                        info!(target: "audit", "Burn output confirmed — daemon will fetch burn output proof");
                        trace!(
                            target: "audit",
                            output_hash = &*mask_string(&hex::encode(unconfirmed_output.output_hash));
                            "Burn output confirmed — daemon will fetch burn output proof"
                        );
                    },
                    Ok(None) => {
                        // Burn output detected but not created by this wallet instance; nothing to do.
                    },
                    Err(e) => {
                        error!(
                            error:% = e;
                            "Failed to look up burn proof for confirmed burn output"
                        );
                    },
                }
            }
        }

        if let Some(config) = &self.webhook_config {
            for (event_id, event) in generated_events {
                trigger_webhook_with_balance(tx, account_id, event_id, &event, config)?;
            }
        }

        Ok(())
    }

    /// Creates a wallet event for an output reaching confirmation depth.
    fn make_confirmation_event(
        &self,
        account_id: i64,
        output_hash: &FixedHash,
        original_height: u64,
        confirmation_height: u64,
        memo_parsed: Option<String>,
        memo_hex: Option<String>,
    ) -> WalletEvent {
        WalletEvent {
            id: 0,
            account_id,
            event_type: WalletEventType::OutputConfirmed {
                hash: *output_hash,
                block_height: original_height,
                confirmation_height,
                memo_parsed,
                memo_hex,
            },
            description: format!(
                "Output confirmed at height {} (originally at {})",
                confirmation_height, original_height
            ),
        }
    }
}

/// Extracted memo information from an output's payment ID.
pub struct MemoInfo {
    /// Human-readable interpretation of the memo (UTF-8 lossy).
    pub parsed: Option<String>,
    /// Hexadecimal encoding of the raw memo bytes.
    pub hex: Option<String>,
}

impl MemoInfo {
    /// Extracts memo information from a wallet output's payment ID.
    pub fn from_output(output: &WalletOutput) -> Self {
        let payment_info = output.payment_id();
        let memo_bytes = payment_info.get_payment_id();

        if memo_bytes.is_empty() {
            Self {
                parsed: None,
                hex: None,
            }
        } else {
            Self {
                parsed: Some(String::from_utf8_lossy(&memo_bytes).to_string()),
                hex: Some(hex::encode(&memo_bytes)),
            }
        }
    }
}

/// Creates a balance change record for a detected output.
///
/// Handles both regular outputs and coinbase outputs, extracting payment
/// information including recipient/sender addresses, fees, and amounts
/// from the output's payment ID.
fn make_balance_change_for_output(
    account_id: i64,
    output_id: i64,
    timestamp: u64,
    height: u64,
    output: &WalletOutput,
) -> BalanceChange {
    #[allow(clippy::cast_possible_wrap)]
    let effective_date = DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(Utc::now)
        .naive_utc();

    let payment_info = output.payment_id();
    let memo_bytes = payment_info.get_payment_id();

    if output.features().is_coinbase() {
        return BalanceChange {
            account_id,
            caused_by_output_id: Some(output_id),
            caused_by_input_id: None,
            description: "Coinbase output found in blockchain scan".to_string(),
            balance_credit: output.value(),
            balance_debit: 0.into(),
            effective_date,
            effective_height: height,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: Some(String::from_utf8_lossy(&memo_bytes).to_string()),
            memo_hex: Some(hex::encode(&memo_bytes)),
            claimed_fee: payment_info.get_fee(),
            claimed_amount: payment_info.get_amount(),
            is_reversal: false,
            reversal_of_balance_change_id: None,
            is_reversed: false,
        };
    }

    BalanceChange {
        account_id,
        caused_by_output_id: Some(output_id),
        caused_by_input_id: None,
        description: "Output found in blockchain scan".to_string(),
        balance_credit: output.value(),
        balance_debit: 0.into(),
        effective_date,
        effective_height: height,
        claimed_recipient_address: payment_info.get_recipient_address(),
        claimed_sender_address: payment_info.claimed_sender_address(),
        memo_parsed: Some(String::from_utf8_lossy(&memo_bytes).to_string()),
        memo_hex: Some(hex::encode(&memo_bytes)),
        claimed_fee: payment_info.get_fee(),
        claimed_amount: payment_info.get_amount(),
        is_reversal: false,
        reversal_of_balance_change_id: None,
        is_reversed: false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_wrap)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::db::{SqlitePool, create_account, get_account_by_name, init_db};
    use crate::transactions::idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint};
    use crate::transactions::{
        BlockchainInfo, DisplayedTransaction, TransactionDetails, TransactionDirection, TransactionDisplayStatus,
        TransactionSource,
    };
    use rusqlite::named_params;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::transaction::TxId;
    use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey};
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::key_manager::{KeyManager, TariKeyId, TransactionKeyManagerInterface};
    use tari_transaction_components::transaction_components::{
        EncryptedData, MemoField, OutputFeatures, TransactionInput, TransactionOutputVersion, covenants::Covenant,
    };
    use tari_utilities::ByteArray;
    use tempfile::TempDir;

    struct TestWallet {
        pool: SqlitePool,
        account_id: i64,
        view_key: PrivateKey,
        _dir: TempDir,
    }

    fn test_wallet() -> TestWallet {
        let dir = tempfile::tempdir().expect("temp dir");
        let pool = init_db(dir.path().join("processor.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;
        let view_key = KeyManager::new(wallet).unwrap().get_private_view_key();
        TestWallet {
            pool,
            account_id,
            view_key,
            _dir: dir,
        }
    }

    fn processor(wallet: &TestWallet, has_pending_outbound: bool) -> BlockProcessor {
        let mut processor = BlockProcessor::new(vec![(wallet.account_id, wallet.view_key.clone())], 3);
        processor.set_has_pending_outbound(has_pending_outbound);
        processor
    }

    fn hash(byte: u8) -> FixedHash {
        FixedHash::from([byte; 32])
    }

    fn test_wallet_output(value: u64, hash_byte: u8) -> WalletOutput {
        WalletOutput::new_from_parts(
            TransactionOutputVersion::default(),
            MicroMinotari::from(value),
            TariKeyId::default(),
            OutputFeatures::default(),
            TariScript::default(),
            ExecutionStack::default(),
            TariKeyId::default(),
            CompressedPublicKey::default(),
            ComAndPubSignature::default(),
            0,
            Covenant::default(),
            EncryptedData::default(),
            MicroMinotari::from(0),
            None,
            MemoField::new_empty(),
            hash(hash_byte),
            Default::default(),
        )
    }

    fn block(height: u64, wallet_outputs: Vec<WalletOutput>, inputs: Vec<FixedHash>) -> BlockScanResult {
        BlockScanResult {
            height,
            #[allow(clippy::cast_possible_truncation)]
            block_hash: FixedHash::from([200u8.wrapping_add(height as u8); 32]),
            wallet_outputs: wallet_outputs.into_iter().map(|o| (o.output_hash(), o, 0)).collect(),
            inputs,
            mined_timestamp: 1_700_000_000,
        }
    }

    fn output_row(conn: &Connection, output_hash: &FixedHash) -> (i64, String, i64, Vec<u8>, Option<String>) {
        conn.query_row(
            "SELECT id, status, mined_in_block_height, mined_in_block_hash, payment_reference
             FROM outputs WHERE output_hash = :hash AND deleted_at IS NULL",
            named_params! { ":hash": output_hash.as_slice() },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .expect("output row")
    }

    #[test]
    fn the_change_row_is_updated_in_place_when_the_scan_finds_it() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let change = test_wallet_output(5_000, 7);
        let change_id =
            db::insert_unconfirmed_change_output(&conn, wallet.account_id, &wallet.view_key, "request-1", &change)
                .expect("insert change");
        let (_, status, height, _, payref) = output_row(&conn, &change.output_hash());
        assert_eq!(status, "UNCONFIRMED");
        assert_eq!(height, 0, "sentinel height until mined");
        assert!(payref.is_none());

        let mined_block = block(50, vec![change.clone()], Vec::new());
        processor(&wallet, false)
            .process_block(&conn, &mined_block, wallet.account_id)
            .expect("process block");

        let (id, status, height, block_hash, payref) = output_row(&conn, &change.output_hash());
        assert_eq!(id, change_id, "the same row is updated, not a second one inserted");
        assert_eq!(status, "UNSPENT");
        assert_eq!(height, 50);
        assert_eq!(block_hash, mined_block.block_hash.to_vec());
        assert!(payref.is_some(), "the payment reference is set when mined");

        let credit_id = db::get_balance_change_id_by_output(&conn, change_id).expect("query");
        assert!(credit_id.is_some(), "the credit balance change is recorded");
    }

    /// A broadcast send recorded the way `TransactionManager` records one.
    struct TestSend {
        request_id: String,
        tx_id: TxId,
        input_hashes: Vec<FixedHash>,
        change: Option<WalletOutput>,
    }

    /// Records a `Broadcast` send spending new wallet outputs `input_bytes`
    /// (locked to the send), with a pending displayed transaction and, when
    /// `change_byte` is given, an `UNCONFIRMED` change row.
    fn record_send(
        wallet: &TestWallet,
        conn: &Connection,
        id: u64,
        input_bytes: &[u8],
        change_byte: Option<u8>,
    ) -> TestSend {
        let binding = IdempotencyBinding::new(
            Some(format!("send-{id}")),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let request_id = db::create_pending_transaction(
            conn,
            &format!("send-{id}"),
            &binding,
            wallet.account_id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("pending transaction");

        let mut input_hashes = Vec::new();
        let mut inputs = Vec::new();
        for byte in input_bytes {
            let output = test_wallet_output(10_000, *byte);
            // An input another send released can be spent again.
            if let Some(copy) = db::get_output_copies(conn, wallet.account_id, &output.output_hash())
                .expect("lookup")
                .pop()
            {
                let output_id = copy.id;
                db::lock_output(conn, output_id, &request_id, Utc::now()).expect("lock input");
                input_hashes.push(output.output_hash());
                inputs.push(TransactionInput::new_with_output_hash(
                    output.output_hash(),
                    ExecutionStack::default(),
                    ComAndPubSignature::default(),
                ));
                continue;
            }
            let (output_id, _) = db::insert_output(
                conn,
                wallet.account_id,
                &wallet.view_key,
                &output.output_hash(),
                &output,
                10,
                &hash(10),
                1_700_000_000,
                None,
                None,
                FixedHash::zero(),
                false,
            )
            .expect("input output");
            db::lock_output(conn, output_id, &request_id, Utc::now()).expect("lock input");
            input_hashes.push(output.output_hash());
            inputs.push(TransactionInput::new_with_output_hash(
                output.output_hash(),
                ExecutionStack::default(),
                ComAndPubSignature::default(),
            ));
        }

        let transaction = Transaction::new(
            inputs,
            Vec::new(),
            Vec::new(),
            PrivateKey::default(),
            PrivateKey::default(),
        );
        let tx_id = TxId::from(id);
        db::create_completed_transaction(
            conn,
            wallet.account_id,
            &request_id,
            &[],
            &serde_json::to_vec(&transaction).expect("serialize"),
            None,
            tx_id,
        )
        .expect("completed transaction");
        db::mark_completed_transaction_as_broadcasted(conn, tx_id, 1).expect("broadcast");

        let change = change_byte.map(|byte| test_wallet_output(3_000, byte));
        if let Some(change) = &change {
            db::insert_unconfirmed_change_output(conn, wallet.account_id, &wallet.view_key, &request_id, change)
                .expect("change row");
        }

        let displayed = pending_displayed_send(wallet.account_id, tx_id, &input_hashes, change.as_ref());
        db::insert_displayed_transaction(conn, &displayed).expect("displayed");

        TestSend {
            request_id,
            tx_id,
            input_hashes,
            change,
        }
    }

    /// The pending displayed transaction `TransactionManager` records for a send:
    /// its inputs and its change, so the scan can recognise it.
    fn pending_displayed_send(
        account_id: i64,
        tx_id: TxId,
        input_hashes: &[FixedHash],
        change: Option<&WalletOutput>,
    ) -> DisplayedTransaction {
        let mut inputs = Vec::new();
        for input_hash in input_hashes {
            inputs.push(crate::transactions::TransactionInput {
                output_hash: *input_hash,
                amount: MicroMinotari::from(10_000),
                matched_output_id: 0,
                mined_in_block_hash: FixedHash::default(),
            });
        }
        let mut outputs = Vec::new();
        if let Some(change) = change {
            outputs.push(crate::transactions::TransactionOutput {
                hash: change.output_hash(),
                amount: change.value(),
                status: OutputStatus::Unspent,
                mined_in_block_height: 0,
                mined_in_block_hash: FixedHash::default(),
                output_type: tari_transaction_components::transaction_components::OutputType::Standard,
                is_change: true,
            });
        }
        DisplayedTransaction {
            id: tx_id,
            direction: TransactionDirection::Outgoing,
            source: TransactionSource::OneSided,
            status: TransactionDisplayStatus::Pending,
            amount: MicroMinotari::from(1_000),
            message: None,
            counterparty: None,
            blockchain: BlockchainInfo {
                block_height: 0,
                timestamp: Utc::now().naive_utc(),
                confirmations: 0,
                block_hash: FixedHash::zero(),
            },
            fee: None,
            details: TransactionDetails {
                account_id,
                total_credit: MicroMinotari::from(0),
                total_debit: MicroMinotari::from(1_000),
                inputs,
                outputs,
                output_type: None,
                coinbase_extra: None,
                memo_hex: None,
                sent_output_hashes: Vec::new(),
                sent_payrefs: Vec::new(),
            },
            lock_height: 0,
        }
    }

    fn completed(conn: &Connection, tx_id: TxId) -> db::CompletedTransaction {
        db::get_completed_transaction_by_id(conn, tx_id)
            .expect("query")
            .expect("completed transaction exists")
    }

    fn change_row(conn: &Connection, send: &TestSend) -> (i64, String, i64, Option<String>) {
        conn.query_row(
            "SELECT id, status, mined_in_block_height, payment_reference
             FROM outputs WHERE created_by_request_id = :req AND deleted_at IS NULL",
            named_params! { ":req": send.request_id },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("change row")
    }

    fn input_statuses(conn: &Connection, send: &TestSend) -> Vec<String> {
        let mut statuses = Vec::new();
        for input_hash in &send.input_hashes {
            statuses.push(output_row(conn, input_hash).1);
        }
        statuses
    }

    fn stored_event_types(conn: &Connection, account_id: i64) -> Vec<String> {
        db::get_events_by_account_id(conn, account_id, 100, 0)
            .expect("events")
            .into_iter()
            .map(|e| e.event_type)
            .collect()
    }

    /// Processes `blocks` as one batch, the way `ScanDbHandler` does.
    fn process<E: EventSender>(
        processor: &mut BlockProcessor<E>,
        conn: &Connection,
        account_id: i64,
        blocks: &[BlockScanResult],
    ) {
        for block in blocks {
            processor.process_block(conn, block, account_id).expect("process block");
        }
        processor.finish_batch();
        processor.match_sends(conn, false).expect("match sends");
        if let Some(last) = blocks.last() {
            processor
                .settle_sends_in_passed_blocks(conn, account_id, last.height)
                .expect("settle sends");
        }
    }

    #[test]
    fn a_send_in_a_block_split_across_two_batches_is_not_rejected() {
        // The node split block 50 into two results and the batch ended between
        // them. The first batch sees one input and the change but not the other
        // input; that is not a different transaction spending the inputs.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let first_part = block(50, vec![send.change.clone().unwrap()], vec![send.input_hashes[0]]);
        let mut processor = processor(&wallet, true);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&first_part),
        );

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Broadcast
        );
        assert_eq!(change_row(&conn, &send).1, "UNSPENT", "the change is not rejected");
        let displayed = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_ne!(displayed.status, TransactionDisplayStatus::Rejected);
    }

    #[test]
    fn a_send_that_cannot_be_decoded_is_skipped_without_failing_the_block() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        conn.execute("UPDATE completed_transactions SET serialized_transaction = x'00ff'", [])
            .expect("corrupt");

        let mined_block = block(50, vec![send.change.clone().unwrap()], send.input_hashes.clone());
        let mut processor = processor(&wallet, true);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&mined_block),
        );

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Broadcast
        );
        // The rest of the block was still processed.
        assert_eq!(change_row(&conn, &send).1, "UNSPENT");
    }

    #[test]
    fn a_send_seen_in_a_block_is_marked_mined_unconfirmed() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let mined_block = block(50, vec![send.change.clone().unwrap()], send.input_hashes.clone());
        let mut processor = processor(&wallet, true);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&mined_block),
        );

        let completed = completed(&conn, send.tx_id);
        assert_eq!(completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(completed.mined_height, Some(50));
        assert_eq!(completed.mined_block_hash, Some(mined_block.block_hash.to_vec()));

        let events = processor.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, mined_height: 50, confirmations: 0 } if tx_id == send.tx_id
        )));
        assert!(stored_event_types(&conn, wallet.account_id).contains(&"TransactionUnconfirmed".to_string()));
        assert_eq!(change_row(&conn, &send).1, "UNSPENT");
    }

    #[test]
    fn a_send_split_over_several_results_of_one_block_is_still_matched() {
        // A large block arrives as several results sharing its hash; the send's
        // inputs and change can be in different ones.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let first = block(50, vec![send.change.clone().unwrap()], vec![send.input_hashes[0]]);
        let second = block(50, Vec::new(), vec![send.input_hashes[1]]);
        let mut processor = processor(&wallet, true);
        process(&mut processor, &conn, wallet.account_id, &[first, second]);

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );
    }

    #[test]
    fn a_send_whose_inputs_were_spent_by_another_transaction_is_rejected_and_its_unspent_inputs_released() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        // Only one of the inputs is spent, and the change is not in the block.
        let other_block = block(50, Vec::new(), vec![send.input_hashes[0]]);
        let mut processor = processor(&wallet, true);
        // The next block closes block 50, so it is known to be complete.
        let next_block = block(51, Vec::new(), Vec::new());
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[other_block.clone(), next_block],
        );

        let completed = completed(&conn, send.tx_id);
        assert_eq!(completed.status, db::CompletedTransactionStatus::Rejected);
        assert_eq!(
            completed.last_rejected_reason.as_deref(),
            Some("inputs spent by a different transaction")
        );
        assert_eq!(
            completed.mined_height,
            Some(50),
            "the block is recorded for a reorg revert"
        );
        assert_eq!(completed.mined_block_hash, Some(other_block.block_hash.to_vec()));

        assert_eq!(change_row(&conn, &send).1, "REJECTED");

        let displayed = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_eq!(displayed.status, TransactionDisplayStatus::Rejected);

        // The input spent in the block stays spent; the other is handed back.
        assert_eq!(
            input_statuses(&conn, &send),
            vec!["SPENT".to_string(), "UNSPENT".to_string()]
        );
        let released_lock: Option<String> = conn
            .query_row(
                "SELECT locked_by_request_id FROM outputs WHERE output_hash = :hash",
                named_params! { ":hash": send.input_hashes[1].as_slice() },
                |row| row.get(0),
            )
            .expect("input");
        assert_eq!(released_lock, None, "the released input is no longer locked");
        // The release does not touch the rejected change.
        assert_eq!(change_row(&conn, &send).1, "REJECTED");

        let events = processor.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            &e.event_type,
            WalletEventType::TransactionRejected { tx_id, reason }
                if *tx_id == send.tx_id && reason == "inputs spent by a different transaction"
        )));
        assert!(stored_event_types(&conn, wallet.account_id).contains(&"TransactionRejected".to_string()));
    }

    #[test]
    fn a_legacy_send_without_a_change_row_is_matched_on_its_inputs_alone() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], None);

        let mined_block = block(50, Vec::new(), send.input_hashes.clone());
        let mut processor = processor(&wallet, true);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&mined_block),
        );

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );
    }

    #[test]
    fn without_pending_outbound_sends_are_not_looked_up() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let mined_block = block(50, vec![send.change.clone().unwrap()], send.input_hashes.clone());
        let mut processor = processor(&wallet, false);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&mined_block),
        );

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Broadcast
        );
        let events = processor.take_wallet_events();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.event_type, WalletEventType::TransactionUnconfirmed { .. }))
        );
    }

    #[test]
    fn a_reorg_reverts_a_mined_send_and_keeps_its_change_as_unconfirmed() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let mined_block = block(50, vec![send.change.clone().unwrap()], send.input_hashes.clone());
        let mut mine_processor = processor(&wallet, true);
        process(
            &mut mine_processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&mined_block),
        );
        let (change_id, ..) = change_row(&conn, &send);

        let tx = conn.transaction().expect("tx");
        let info = crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");

        let completed = completed(&conn, send.tx_id);
        assert_eq!(completed.status, db::CompletedTransactionStatus::Completed);
        assert_eq!(completed.mined_height, None);

        let (id, status, height, payref) = change_row(&conn, &send);
        assert_eq!(id, change_id, "the change row is kept, not soft-deleted");
        assert_eq!(status, "UNCONFIRMED");
        assert_eq!(height, 0);
        assert!(payref.is_none());
        assert!(
            db::get_balance_change_id_by_output(&conn, change_id)
                .expect("query")
                .is_none(),
            "the change's credit is reversed"
        );

        let change_hash = send.change.as_ref().unwrap().output_hash();
        assert!(info.invalidated_output_hashes.contains(&change_hash));
        assert!(stored_event_types(&conn, wallet.account_id).contains(&"OutputRolledBack".to_string()));

        // Re-mined after the reorg, it is found again by the same row.
        let remined = block(51, vec![send.change.clone().unwrap()], send.input_hashes.clone());
        db::mark_completed_transaction_as_broadcasted(&conn, send.tx_id, 1).expect("rebroadcast");
        let mut remine_processor = processor(&wallet, true);
        process(
            &mut remine_processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&remined),
        );
        assert_eq!(change_row(&conn, &send).0, change_id);
        assert_eq!(change_row(&conn, &send).1, "UNSPENT");
    }

    #[test]
    fn a_reorg_reverts_a_scan_rejected_send_and_its_change() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let other_block = block(50, Vec::new(), vec![send.input_hashes[0]]);
        let mut processor = processor(&wallet, true);
        // The next block closes block 50, so it is known to be complete.
        let next_block = block(51, Vec::new(), Vec::new());
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[other_block.clone(), next_block],
        );
        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );

        let tx = conn.transaction().expect("tx");
        let info = crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");

        let completed = completed(&conn, send.tx_id);
        assert_eq!(completed.status, db::CompletedTransactionStatus::Completed);
        assert_eq!(completed.mined_height, None);
        assert_eq!(completed.last_rejected_reason, None);
        assert_eq!(completed.broadcast_attempts, 0);
        assert_eq!(change_row(&conn, &send).1, "UNCONFIRMED");

        // The displayed transaction is unmined and pending again, so the scan
        // matches it when the send is mined instead of adding a second entry.
        let displayed = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_eq!(displayed.status, TransactionDisplayStatus::Pending);
        assert_eq!(displayed.blockchain.block_height, 0);
        assert!(
            info.reorganized_displayed_transactions
                .iter()
                .any(|d| d.id == send.tx_id && d.status == TransactionDisplayStatus::Pending),
            "consumers are told about the update"
        );

        // Both inputs are the send's again: the one the rejection released, and
        // the one the rolled-back block had spent.
        assert_eq!(
            input_statuses(&conn, &send),
            vec!["LOCKED".to_string(), "LOCKED".to_string()]
        );
        for input_hash in &send.input_hashes {
            let lock: Option<String> = conn
                .query_row(
                    "SELECT locked_by_request_id FROM outputs WHERE output_hash = :hash",
                    named_params! { ":hash": input_hash.as_slice() },
                    |row| row.get(0),
                )
                .expect("input");
            assert_eq!(lock.as_deref(), Some(send.request_id.as_str()));
        }
        assert!(stored_event_types(&conn, wallet.account_id).contains(&"TransactionReorged".to_string()));
    }

    #[test]
    fn a_reorg_keeps_a_scan_rejected_send_rejected_if_its_inputs_went_elsewhere() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let other_block = block(50, Vec::new(), vec![send.input_hashes[0]]);
        let next_block = block(51, Vec::new(), Vec::new());
        let mut processor = processor(&wallet, true);
        process(&mut processor, &conn, wallet.account_id, &[other_block, next_block]);
        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );

        // The released input is now locked by another send.
        let (other_id, ..) = output_row(&conn, &send.input_hashes[1]);
        db::lock_output(&conn, other_id, "another-send", Utc::now()).expect("lock");

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");

        let completed = completed(&conn, send.tx_id);
        assert_eq!(completed.status, db::CompletedTransactionStatus::Rejected);
        assert_eq!(completed.mined_height, None);
        assert_eq!(change_row(&conn, &send).1, "REJECTED");
        let displayed = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_eq!(displayed.status, TransactionDisplayStatus::Rejected);
        let lock: Option<String> = conn
            .query_row(
                "SELECT locked_by_request_id FROM outputs WHERE id = :id",
                named_params! { ":id": other_id },
                |row| row.get(0),
            )
            .expect("input");
        assert_eq!(lock.as_deref(), Some("another-send"), "the other send keeps its input");
    }

    /// What the monitor does when it gives up on a send: rejected, inputs
    /// released (change soft-deleted), displayed transaction rejected.
    fn reject_as_the_monitor_does(conn: &Connection, send: &TestSend) {
        db::mark_completed_transaction_as_rejected(conn, send.tx_id, "Exceeded 10 broadcast attempts").expect("reject");
        db::unlock_outputs_for_request(conn, &send.request_id).expect("release");
        db::mark_displayed_transaction_rejected(conn, send.tx_id).expect("displayed");
    }

    fn displayed_count(conn: &Connection, account_id: i64) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM displayed_transactions WHERE account_id = :account_id",
            named_params! { ":account_id": account_id },
            |row| row.get(0),
        )
        .expect("count")
    }

    #[test]
    fn a_send_the_monitor_rejected_is_reconciled_when_it_is_mined_after_all() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        let (original_change_id, ..) = change_row(&conn, &send);
        reject_as_the_monitor_does(&conn, &send);
        assert_eq!(
            input_statuses(&conn, &send),
            vec!["UNSPENT".to_string(), "UNSPENT".to_string()]
        );

        // Nothing is pending any more, and the send is still found.
        let mined_block = block(50, vec![send.change.clone().unwrap()], send.input_hashes.clone());
        let mut processor = processor(&wallet, false);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&mined_block),
        );

        let completed = completed(&conn, send.tx_id);
        assert_eq!(completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(completed.mined_height, Some(50));
        assert_eq!(completed.last_rejected_reason, None);
        let events = processor.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, mined_height: 50, .. } if tx_id == send.tx_id
        )));
        assert!(stored_event_types(&conn, wallet.account_id).contains(&"TransactionUnconfirmed".to_string()));

        // The same history entry is brought back, not a second one added.
        let displayed = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_ne!(displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(displayed.blockchain.block_height, 50);
        assert_eq!(displayed_count(&conn, wallet.account_id), 1);

        // The change found in the block is the send's own change row, updated in
        // place, so a reorg reverts it rather than deleting it.
        let (change_id, status, height, _) = change_row(&conn, &send);
        assert_eq!(change_id, original_change_id);
        assert_eq!(status, "UNSPENT");
        assert_eq!(height, 50);
    }

    #[test]
    fn a_send_the_monitor_rejected_stays_rejected_if_the_block_does_not_match_it() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        reject_as_the_monitor_does(&conn, &send);

        // Its change is in the block, so it is taken up, but only one of its
        // released inputs is spent: it does not match.
        let other_block = block(50, vec![send.change.clone().unwrap()], vec![send.input_hashes[0]]);
        let next_block = block(51, Vec::new(), Vec::new());
        let (sender, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut processor = BlockProcessor::with_event_sender(
            vec![(wallet.account_id, wallet.view_key.clone())],
            crate::scan::events::ChannelEventSender::new(sender),
            false,
            3,
        );
        process(&mut processor, &conn, wallet.account_id, &[other_block, next_block]);

        let completed = completed(&conn, send.tx_id);
        assert_eq!(completed.status, db::CompletedTransactionStatus::Rejected);
        assert_eq!(
            completed.mined_height, None,
            "not handled a second time as a scan rejection"
        );
        let displayed = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_eq!(displayed.status, TransactionDisplayStatus::Rejected);
        // Back to the unmined entry it was, not left at this block's height.
        assert_eq!(displayed.blockchain.block_height, 0);
        assert_eq!(displayed.blockchain.confirmations, 0);
        assert_eq!(displayed.blockchain.block_hash, FixedHash::zero());
        let column_height: i64 = conn
            .query_row(
                "SELECT block_height FROM displayed_transactions WHERE id = :id",
                named_params! { ":id": send.tx_id.to_string() },
                |row| row.get(0),
            )
            .expect("row");
        assert_eq!(column_height, 0);

        // Consumers are told it is rejected again, after this block showed it mined.
        let mut announced = false;
        while let Ok(event) = events_rx.try_recv() {
            if let ProcessingEvent::TransactionsUpdated(update) = event {
                announced |= update
                    .updated_transactions
                    .iter()
                    .any(|t| t.id == send.tx_id && t.status == TransactionDisplayStatus::Rejected);
            }
        }
        assert!(announced, "a TransactionsUpdated with the rejected entry is sent");

        let events = processor.take_wallet_events();
        assert!(!events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { .. } | WalletEventType::TransactionRejected { .. }
        )));
    }

    #[test]
    fn a_monitor_rejected_send_is_reconciled_even_after_a_later_send_locked_its_input() {
        // The monitor gave up on X and released its inputs; the user sent Y,
        // which locked one of them. Then X is mined after all.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        reject_as_the_monitor_does(&conn, &x);
        let y = record_send(&wallet, &conn, 2, &[1], Some(9));
        assert_eq!(y.input_hashes, vec![x.input_hashes[0]]);

        let mined_block = block(50, vec![x.change.clone().unwrap()], x.input_hashes.clone());
        let next_block = block(51, Vec::new(), Vec::new());
        let mut processor = processor(&wallet, true);
        process(&mut processor, &conn, wallet.account_id, &[mined_block, next_block]);

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(x_completed.mined_height, Some(50));
        let events = processor.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, .. } if tx_id == x.tx_id
        )));

        // Y's input went to X: Y is rejected.
        assert_eq!(
            completed(&conn, y.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );

        // X keeps its one history entry, now mined; Y's is rejected; nothing else.
        let x_displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("x displayed");
        assert_ne!(x_displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(x_displayed.blockchain.block_height, 50);
        let y_displayed = db::get_displayed_transaction_by_id(&conn, &y.tx_id.to_string())
            .expect("query")
            .expect("y displayed");
        assert_eq!(y_displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(
            displayed_count(&conn, wallet.account_id),
            2,
            "no phantom incoming entry"
        );

        // X's change is linked to X again.
        assert_eq!(change_row(&conn, &x).1, "UNSPENT");
    }

    #[test]
    fn a_monitor_rejected_send_without_a_change_row_is_never_reconciled_by_its_inputs() {
        // X (legacy, no change row) was rejected by the monitor; Y re-locked one
        // of its released inputs and is mined with it.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1], None);
        reject_as_the_monitor_does(&conn, &x);
        let y = record_send(&wallet, &conn, 2, &[1, 5], Some(9));

        let mined_block = block(50, vec![y.change.clone().unwrap()], y.input_hashes.clone());
        let next_block = block(51, Vec::new(), Vec::new());
        let mut processor = processor(&wallet, true);
        process(&mut processor, &conn, wallet.account_id, &[mined_block, next_block]);

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::Rejected);
        assert_eq!(x_completed.mined_height, None);
        let events = processor.take_wallet_events();
        assert!(
            !events.iter().any(|e| matches!(
                e.event_type,
                WalletEventType::TransactionUnconfirmed { tx_id, .. } if tx_id == x.tx_id
            )),
            "no false mined event for X"
        );
        let x_displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("x displayed");
        assert_eq!(x_displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(x_displayed.blockchain.block_height, 0);

        // Y is processed as usual and its history shows it mined.
        assert_eq!(
            completed(&conn, y.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );
        let y_displayed = db::get_displayed_transaction_by_id(&conn, &y.tx_id.to_string())
            .expect("query")
            .expect("y displayed");
        assert_eq!(y_displayed.blockchain.block_height, 50);
        assert_eq!(displayed_count(&conn, wallet.account_id), 2);
    }

    #[test]
    fn a_monitor_rejected_send_is_left_alone_when_its_released_input_is_spent_elsewhere() {
        // X's released input is spent by something outside this wallet's sends,
        // and X's change is not in the block.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        reject_as_the_monitor_does(&conn, &x);

        let other_block = block(50, Vec::new(), vec![x.input_hashes[0]]);
        let next_block = block(51, Vec::new(), Vec::new());
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &[other_block, next_block]);

        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );
        let x_displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("x displayed");
        assert_eq!(x_displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(x_displayed.blockchain.block_height, 0);
        // The spend gets its own history entry instead of being swallowed by X's.
        assert_eq!(displayed_count(&conn, wallet.account_id), 2);
        let events = processor.take_wallet_events();
        assert!(!events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { .. } | WalletEventType::TransactionRejected { .. }
        )));
    }

    #[test]
    fn a_monitor_rejected_send_is_reconciled_after_a_retry_of_it_was_refused() {
        // The monitor gave up on X and released its inputs. The user retried as
        // Y, which locked one of them, but the node refused Y (X was still in
        // mempools) and Y's inputs were released in turn. Then X is mined.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        let (original_change_id, ..) = change_row(&conn, &x);
        reject_as_the_monitor_does(&conn, &x);
        let y = record_send(&wallet, &conn, 2, &[1], Some(9));
        db::mark_completed_transaction_as_rejected(&conn, y.tx_id, "Transaction rejected: DoubleSpend")
            .expect("reject y");
        db::unlock_outputs_for_request(&conn, &y.request_id).expect("release y");
        db::mark_displayed_transaction_rejected(&conn, y.tx_id).expect("displayed y");

        let mined_block = block(50, vec![x.change.clone().unwrap()], x.input_hashes.clone());
        let next_block = block(51, Vec::new(), Vec::new());
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &[mined_block, next_block]);

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(x_completed.mined_height, Some(50));
        let events = processor.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, .. } if tx_id == x.tx_id
        )));

        // The change is X's own row, linked to X.
        let (change_id, status, height, _) = change_row(&conn, &x);
        assert_eq!(change_id, original_change_id);
        assert_eq!(status, "UNSPENT");
        assert_eq!(height, 50);

        // One entry for X, now mined; Y's stays rejected; nothing else.
        let x_displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("x displayed");
        assert_ne!(x_displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(x_displayed.blockchain.block_height, 50);
        assert_eq!(displayed_count(&conn, wallet.account_id), 2);
        assert_eq!(
            completed(&conn, y.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );
    }

    #[test]
    fn a_scan_without_inputs_settles_a_monitor_rejected_send_by_its_change_and_rejects_nothing() {
        // FastSync Phase 1 scans without inputs. X was rejected by the monitor
        // and its change turns up there.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        let (original_change_id, ..) = change_row(&conn, &x);
        reject_as_the_monitor_does(&conn, &x);

        let (sender, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut processor = BlockProcessor::with_event_sender(
            vec![(wallet.account_id, wallet.view_key.clone())],
            crate::scan::events::ChannelEventSender::new(sender),
            false,
            3,
        );
        processor.set_inputs_excluded(true);
        let phase_one_block = block(50, vec![x.change.clone().unwrap()], Vec::new());
        let next_block = block(51, Vec::new(), Vec::new());
        process(&mut processor, &conn, wallet.account_id, &[phase_one_block, next_block]);

        // Settled on its change: mined at 50, with its event.
        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(x_completed.mined_height, Some(50));
        let events = processor.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, mined_height: 50, .. } if tx_id == x.tx_id
        )));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.event_type, WalletEventType::TransactionRejected { .. }))
        );

        // Its change is its own row, linked to it, and its one entry is mined.
        let (change_id, status, height, _) = change_row(&conn, &x);
        assert_eq!(change_id, original_change_id);
        assert_eq!(status, "UNSPENT");
        assert_eq!(height, 50);
        let displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_ne!(displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(displayed.blockchain.block_height, 50);
        assert_eq!(displayed_count(&conn, wallet.account_id), 1);

        // No rejection is announced.
        while let Ok(event) = events_rx.try_recv() {
            if let ProcessingEvent::TransactionsUpdated(update) = event {
                assert!(
                    !update
                        .updated_transactions
                        .iter()
                        .any(|t| t.status == TransactionDisplayStatus::Rejected),
                    "no rejection may be announced"
                );
            }
        }
    }

    #[test]
    fn a_scan_without_inputs_never_rejects_a_pending_send() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let mut processor = processor(&wallet, true);
        processor.set_inputs_excluded(true);
        let phase_one_block = block(50, vec![send.change.clone().unwrap()], Vec::new());
        let next_block = block(51, Vec::new(), Vec::new());
        process(&mut processor, &conn, wallet.account_id, &[phase_one_block, next_block]);

        // Neither matched nor rejected: the later phases or the monitor settle it.
        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Broadcast
        );
        assert_eq!(
            input_statuses(&conn, &send),
            vec!["LOCKED".to_string(), "LOCKED".to_string()]
        );
    }

    #[test]
    fn a_reorg_keeps_a_scan_rejected_send_rejected_if_another_send_spent_its_input() {
        // X is rejected by the scan at 50 and its unspent input released; send Z
        // then locks and spends that input at 52. A reorg back to 50 removes both
        // blocks: the input is Z's, so X must stay rejected.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let mut first = processor(&wallet, true);
        let other_block = block(50, Vec::new(), vec![x.input_hashes[0]]);
        process(
            &mut first,
            &conn,
            wallet.account_id,
            &[other_block, block(51, Vec::new(), Vec::new())],
        );
        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );

        let z = record_send(&wallet, &conn, 2, &[2], Some(9));
        assert_eq!(z.input_hashes, vec![x.input_hashes[1]]);
        let mut second = processor(&wallet, true);
        let z_block = block(52, vec![z.change.clone().unwrap()], z.input_hashes.clone());
        process(
            &mut second,
            &conn,
            wallet.account_id,
            &[z_block, block(53, Vec::new(), Vec::new())],
        );
        assert_eq!(
            completed(&conn, z.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::Rejected);
        assert_eq!(x_completed.mined_height, None);
        let reorged: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'TransactionReorged'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(reorged, 0, "X is not announced as revived");

        let lock: Option<String> = conn
            .query_row(
                "SELECT locked_by_request_id FROM outputs WHERE output_hash = :hash AND deleted_at IS NULL",
                named_params! { ":hash": x.input_hashes[1].as_slice() },
                |row| row.get(0),
            )
            .expect("input");
        assert_eq!(lock.as_deref(), Some(z.request_id.as_str()), "the input stays Z's");
        assert_eq!(
            completed(&conn, z.tx_id).status,
            db::CompletedTransactionStatus::Completed
        );
    }

    #[test]
    fn a_reorg_does_not_revive_a_send_that_lost_its_input_to_a_reconciled_send() {
        // W was rejected by the monitor and its input A released; X locked A.
        // Then W landed: W is reconciled and matched, X is rejected by the scan.
        // A reorg removing that block must not revive X: A was W's.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let w = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        reject_as_the_monitor_does(&conn, &w);
        let x = record_send(&wallet, &conn, 2, &[1], Some(9));
        let input_a = w.input_hashes[0];
        assert_eq!(x.input_hashes, vec![input_a]);

        let mut processor = processor(&wallet, true);
        let w_block = block(50, vec![w.change.clone().unwrap()], w.input_hashes.clone());
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[w_block, block(51, Vec::new(), Vec::new())],
        );
        assert_eq!(
            completed(&conn, w.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );
        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );

        let lock_of_a = |conn: &Connection| -> Option<String> {
            conn.query_row(
                "SELECT locked_by_request_id FROM outputs WHERE output_hash = :hash AND deleted_at IS NULL",
                named_params! { ":hash": input_a.as_slice() },
                |row| row.get(0),
            )
            .expect("input A")
        };
        assert_eq!(
            lock_of_a(&conn).as_deref(),
            Some(w.request_id.as_str()),
            "A records W as its spender"
        );

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::Rejected);
        assert_eq!(x_completed.mined_height, None);
        let reorged: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'TransactionReorged'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(reorged, 0, "X is not revived");
        assert_eq!(lock_of_a(&conn).as_deref(), Some(w.request_id.as_str()));
        assert_eq!(
            completed(&conn, w.tx_id).status,
            db::CompletedTransactionStatus::Completed
        );
    }

    /// Moves the send's inputs into block 50, so a reorg back to 50 removes them.
    fn mine_inputs_at_50(conn: &Connection, send: &TestSend) {
        for input_hash in &send.input_hashes {
            conn.execute(
                "UPDATE outputs SET mined_in_block_height = 50 WHERE output_hash = :hash",
                named_params! { ":hash": input_hash.as_slice() },
            )
            .expect("move input");
        }
    }

    fn rollback_to_50(conn: &mut Connection, account_id: i64) {
        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");
    }

    #[test]
    fn a_reorg_that_cancels_a_mined_send_keeps_its_change_for_the_rebroadcast() {
        // The send's input was mined at 50 and the send itself at 51; a reorg back
        // to 50 removes both. The send is reset to be rebroadcast, so its change
        // must stay its change.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1], Some(3));
        mine_inputs_at_50(&conn, &send);
        let (change_id, ..) = change_row(&conn, &send);

        let mut first = processor(&wallet, true);
        let send_block = block(51, vec![send.change.clone().unwrap()], send.input_hashes.clone());
        process(
            &mut first,
            &conn,
            wallet.account_id,
            &[send_block, block(52, Vec::new(), Vec::new())],
        );
        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );

        rollback_to_50(&mut conn, wallet.account_id);

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Completed
        );
        let (id, status, height, _) = change_row(&conn, &send);
        assert_eq!(id, change_id, "the change row is kept and still the send's");
        assert_eq!(status, "UNCONFIRMED");
        assert_eq!(height, 0);

        // Mined again, the change is updated in place.
        let mut again = processor(&wallet, false);
        let remined = block(51, vec![send.change.clone().unwrap()], Vec::new());
        process(&mut again, &conn, wallet.account_id, std::slice::from_ref(&remined));
        let (id, status, height, _) = change_row(&conn, &send);
        assert_eq!(id, change_id);
        assert_eq!(status, "UNSPENT");
        assert_eq!(height, 51);
    }

    #[test]
    fn a_reorg_that_cancels_a_broadcast_send_keeps_its_change() {
        // The send's input was mined at 50 and the send is broadcast, not yet mined.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1], Some(3));
        mine_inputs_at_50(&conn, &send);
        let (change_id, ..) = change_row(&conn, &send);

        rollback_to_50(&mut conn, wallet.account_id);

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Broadcast
        );
        let (id, status, ..) = change_row(&conn, &send);
        assert_eq!(id, change_id, "the change row is kept and still the send's");
        assert_eq!(status, "UNCONFIRMED");
    }

    #[test]
    fn a_monitor_rejected_send_in_a_possibly_incomplete_last_block_is_not_rejected_again() {
        // X's change is in the last block of a batch, but not all its inputs: the
        // block may be cut short. X must not be rejected again.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        reject_as_the_monitor_does(&conn, &x);

        let (sender, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut processor = BlockProcessor::with_event_sender(
            vec![(wallet.account_id, wallet.view_key.clone())],
            crate::scan::events::ChannelEventSender::new(sender),
            false,
            3,
        );
        let last_block = block(50, vec![x.change.clone().unwrap()], vec![x.input_hashes[0]]);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&last_block),
        );

        // Settled on its change, not rejected.
        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(x_completed.mined_height, Some(50));
        let displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_ne!(displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(displayed_count(&conn, wallet.account_id), 1);

        let events = processor.take_wallet_events();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.event_type, WalletEventType::TransactionRejected { .. }))
        );
        while let Ok(event) = events_rx.try_recv() {
            if let ProcessingEvent::TransactionsUpdated(update) = event {
                assert!(
                    !update
                        .updated_transactions
                        .iter()
                        .any(|t| t.status == TransactionDisplayStatus::Rejected),
                    "no rejection may be announced"
                );
            }
        }
    }

    #[test]
    fn a_send_double_spent_in_the_last_block_of_a_batch_is_rejected_once_the_scan_moves_on() {
        // Caught up: each new block is the last of its batch. One of X's inputs is
        // spent by a different transaction in block 50.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let mut first = processor(&wallet, true);
        let tip = block(50, Vec::new(), vec![x.input_hashes[0]]);
        process(&mut first, &conn, wallet.account_id, std::slice::from_ref(&tip));
        // Possibly partial: not decided yet.
        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::Broadcast
        );

        // The next block arrives in the next batch (even after a restart: the
        // decision comes from the database).
        let mut second = processor(&wallet, true);
        let next = block(51, Vec::new(), Vec::new());
        process(&mut second, &conn, wallet.account_id, std::slice::from_ref(&next));

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::Rejected);
        assert_eq!(x_completed.mined_height, Some(50));
        assert_eq!(change_row(&conn, &x).1, "REJECTED");
        assert_eq!(
            input_statuses(&conn, &x),
            vec!["SPENT".to_string(), "UNSPENT".to_string()],
            "the input it still had locked is released"
        );
        let events = second.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionRejected { tx_id, .. } if tx_id == x.tx_id
        )));
    }

    #[test]
    fn a_send_missed_in_the_last_block_of_a_batch_is_matched_once_the_scan_moves_on() {
        // Nothing was pending when block 50 was scanned (as far as that batch
        // knew), so X was not matched there; its inputs and change are in it.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));

        let mut first = processor(&wallet, false);
        let mined = block(50, vec![x.change.clone().unwrap()], x.input_hashes.clone());
        process(&mut first, &conn, wallet.account_id, std::slice::from_ref(&mined));
        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::Broadcast
        );

        let mut second = processor(&wallet, false);
        process(
            &mut second,
            &conn,
            wallet.account_id,
            &[block(51, Vec::new(), Vec::new())],
        );

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(x_completed.mined_height, Some(50));
        let events = second.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, mined_height: 50, .. } if tx_id == x.tx_id
        )));
        let displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_eq!(displayed.blockchain.block_height, 50);
        assert_eq!(displayed_count(&conn, wallet.account_id), 1);
    }

    #[test]
    fn an_abandoned_send_that_is_mined_after_all_is_reconciled() {
        // The user abandoned X, but a node still had it and mined it.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        let (original_change_id, ..) = change_row(&conn, &x);
        crate::transactions::abandon::abandon_send(&mut conn, wallet.account_id, x.tx_id, true, false, None)
            .expect("abandon");
        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::Rejected
        );

        let mined = block(50, vec![x.change.clone().unwrap()], x.input_hashes.clone());
        let mut processor = processor(&wallet, false);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[mined, block(51, Vec::new(), Vec::new())],
        );

        let x_completed = completed(&conn, x.tx_id);
        assert_eq!(x_completed.status, db::CompletedTransactionStatus::MinedUnconfirmed);
        assert_eq!(x_completed.mined_height, Some(50));
        let events = processor.take_wallet_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            WalletEventType::TransactionUnconfirmed { tx_id, .. } if tx_id == x.tx_id
        )));
        let (change_id, status, height, _) = change_row(&conn, &x);
        assert_eq!(change_id, original_change_id);
        assert_eq!(status, "UNSPENT");
        assert_eq!(height, 50);
        let displayed = db::get_displayed_transaction_by_id(&conn, &x.tx_id.to_string())
            .expect("query")
            .expect("displayed");
        assert_ne!(displayed.status, TransactionDisplayStatus::Rejected);
        assert_eq!(displayed_count(&conn, wallet.account_id), 1, "a single history entry");
    }

    #[test]
    fn abandoning_never_strands_a_change_output_locked_by_another_send() {
        // X is mined and its change C becomes an input of Y. A reorg resets X and
        // turns C back into UNCONFIRMED, still locked by Y.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let x = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        let x_block = block(50, vec![x.change.clone().unwrap()], x.input_hashes.clone());
        let mut first = processor(&wallet, true);
        process(
            &mut first,
            &conn,
            wallet.account_id,
            &[x_block.clone(), block(51, Vec::new(), Vec::new())],
        );
        let (change_id, ..) = change_row(&conn, &x);
        let y = record_send(&wallet, &conn, 2, &[3], Some(9));
        assert_eq!(y.input_hashes, vec![x.change.as_ref().unwrap().output_hash()]);

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");
        let lock_of_c = |conn: &Connection| -> (String, Option<String>) {
            conn.query_row(
                "SELECT status, locked_by_request_id FROM outputs WHERE id = :id",
                named_params! { ":id": change_id },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("change C")
        };
        assert_eq!(
            lock_of_c(&conn),
            ("UNCONFIRMED".to_string(), Some(y.request_id.clone()))
        );

        // X cannot be abandoned while C is Y's input.
        let refused =
            crate::transactions::abandon::abandon_send(&mut conn, wallet.account_id, x.tx_id, true, false, None);
        assert!(
            matches!(
                &refused,
                Err(crate::transactions::abandon::AbandonSendError::ChangeInUse { by, .. }) if *by == y.request_id
            ),
            "got {refused:?}"
        );
        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::Completed
        );

        // Abandoning Y releases C.
        crate::transactions::abandon::abandon_send(&mut conn, wallet.account_id, y.tx_id, true, false, None)
            .expect("abandon Y");
        assert_eq!(lock_of_c(&conn), ("UNCONFIRMED".to_string(), None));

        // Now X can be abandoned, and when it is mined after all C is spendable.
        crate::transactions::abandon::abandon_send(&mut conn, wallet.account_id, x.tx_id, true, false, None)
            .expect("abandon X");
        let mut again = processor(&wallet, false);
        let remined = block(51, vec![x.change.clone().unwrap()], x.input_hashes.clone());
        process(
            &mut again,
            &conn,
            wallet.account_id,
            &[remined, block(52, Vec::new(), Vec::new())],
        );
        assert_eq!(lock_of_c(&conn), ("UNSPENT".to_string(), None));
        assert_eq!(
            completed(&conn, x.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );
    }

    #[test]
    fn a_reorg_releases_the_inputs_of_a_cancelled_reservation_but_not_of_a_send_in_play() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let insert_locked = |conn: &Connection, byte: u8, height: u64, request_id: &str| -> i64 {
            let output = test_wallet_output(10_000, byte);
            let (id, _) = db::insert_output(
                conn,
                wallet.account_id,
                &wallet.view_key,
                &output.output_hash(),
                &output,
                height,
                &hash(byte),
                1_700_000_000,
                None,
                None,
                FixedHash::zero(),
                false,
            )
            .expect("output");
            db::lock_output(conn, id, request_id, Utc::now()).expect("lock");
            id
        };
        let lock_of = |conn: &Connection, id: i64| -> (String, Option<String>) {
            conn.query_row(
                "SELECT status, locked_by_request_id FROM outputs WHERE id = :id",
                named_params! { ":id": id },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("output")
        };

        // A reservation (never signed) with one input mined before the reorg
        // and one in a block it removes.
        let binding = IdempotencyBinding::new(
            Some("reserve".to_string()),
            IdempotencyOperation::SendTransaction,
            RequestFingerprint::new(IdempotencyOperation::SendTransaction),
        );
        let reservation = db::create_pending_transaction(
            &conn,
            "reserve",
            &binding,
            wallet.account_id,
            true,
            MicroMinotari(0),
            MicroMinotari(0),
            MicroMinotari(0),
            Utc::now() + chrono::Duration::hours(1),
        )
        .expect("reservation");
        let kept_input = insert_locked(&conn, 20, 10, &reservation);
        insert_locked(&conn, 21, 60, &reservation);

        // A send in play, likewise.
        let send = record_send(&wallet, &conn, 2, &[3], Some(9));
        insert_locked(&conn, 22, 60, &send.request_id);
        let send_input = output_row(&conn, &send.input_hashes[0]).0;

        let tx = conn.transaction().expect("tx");
        let info = crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 50, None).expect("rollback");
        tx.commit().expect("commit");
        assert!(info.cancelled_transaction_ids.contains(&reservation));

        // The reservation will not land: its remaining input is spendable again.
        assert_eq!(lock_of(&conn, kept_input), ("UNSPENT".to_string(), None));
        // The send is rebroadcast: its input stays locked to it.
        assert_eq!(
            lock_of(&conn, send_input),
            ("LOCKED".to_string(), Some(send.request_id.clone()))
        );
    }

    /// `(credits, debits)` recorded for the account (reversals left out) and the
    /// ledger total, which is what the balance is built from.
    fn ledger(conn: &Connection, account_id: i64) -> (i64, i64, i64) {
        conn.query_row(
            "SELECT COUNT(*) FILTER (WHERE balance_credit > 0 AND NOT is_reversal),
                    COUNT(*) FILTER (WHERE balance_debit > 0 AND NOT is_reversal),
                    COALESCE(SUM(balance_credit), 0) - COALESCE(SUM(balance_debit), 0)
             FROM balance_changes WHERE account_id = :account_id",
            named_params! { ":account_id": account_id },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("ledger")
    }

    /// `(row id, tx_id, block hash of its active input)` of each active row of
    /// `output` in the account, oldest first.
    fn instances(conn: &Connection, account_id: i64, output: &WalletOutput) -> Vec<(i64, i64, Option<Vec<u8>>)> {
        let mut stmt = conn
            .prepare(
                "SELECT o.id, o.tx_id, i.mined_in_block_hash
                 FROM outputs o LEFT JOIN inputs i ON i.output_id = o.id AND i.deleted_at IS NULL
                 WHERE o.account_id = :account_id AND o.output_hash = :hash AND o.deleted_at IS NULL
                 ORDER BY o.mined_in_block_height",
            )
            .expect("prepare");
        stmt.query_map(
            named_params! { ":account_id": account_id, ":hash": output.output_hash().as_slice() },
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
    }

    /// Block heights of the account's history entries, lowest first.
    fn history_heights(conn: &Connection, account_id: i64) -> Vec<i64> {
        let mut stmt = conn
            .prepare(
                "SELECT block_height FROM displayed_transactions WHERE account_id = :account_id ORDER BY block_height",
            )
            .expect("prepare");
        stmt.query_map(named_params! { ":account_id": account_id }, |row| row.get(0))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows")
    }

    fn rollback_to(conn: &mut Connection, account_id: i64, height: u64) {
        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, account_id, height, None).expect("rollback");
        tx.commit().expect("commit");
    }

    #[test]
    fn a_block_read_twice_credits_and_debits_once() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let b = test_wallet_output(3_000, 2);
        let tip = block(20, vec![b.clone()], vec![a.output_hash()]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new()), tip.clone()],
        );
        // The Continuous scan reads the tip again on its next poll.
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&tip),
        );

        assert_eq!(ledger(&conn, wallet.account_id), (2, 1, 3_000));
        assert_eq!(instances(&conn, wallet.account_id, &b).len(), 1);
        assert_eq!(
            instances(&conn, wallet.account_id, &a)[0].2.as_deref(),
            Some(tip.block_hash.as_slice())
        );
    }

    #[test]
    fn an_input_repeated_within_one_result_debits_once() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(20, Vec::new(), vec![a.output_hash(); 3]),
            ],
        );

        assert_eq!(ledger(&conn, wallet.account_id), (1, 1, 0));
        let inputs: i64 = conn
            .query_row("SELECT COUNT(*) FROM inputs", [], |row| row.get(0))
            .expect("count");
        assert_eq!(inputs, 1);
    }

    #[test]
    fn a_block_split_across_two_results_records_each_part_once() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let b = test_wallet_output(5_000, 2);
        let c = test_wallet_output(2_000, 3);
        let d = test_wallet_output(1_000, 4);
        // Both results share block 20's hash; the second also repeats the first's input.
        let first = block(20, vec![c.clone()], vec![a.output_hash()]);
        let second = block(20, vec![d.clone()], vec![b.output_hash(), a.output_hash()]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone(), b.clone()], Vec::new()), first, second],
        );

        assert_eq!(ledger(&conn, wallet.account_id), (4, 2, 3_000));
    }

    #[test]
    fn a_spend_re_listed_in_a_later_block_is_ignored() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let spend = block(20, Vec::new(), vec![a.output_hash()]);
        let mut re_listing = processor(&wallet, false);
        process(
            &mut re_listing,
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                spend.clone(),
                block(30, Vec::new(), vec![a.output_hash()]),
            ],
        );

        // Logged as a warning and skipped: no second input row, debit or status change.
        // Nothing of the batch's last block is left open for a rollback or the next poll.
        assert!(!re_listing.has_unmatched_inputs());
        assert_eq!(ledger(&conn, wallet.account_id), (1, 1, 0));
        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2.as_deref(), Some(spend.block_hash.as_slice()));
        let inputs: i64 = conn
            .query_row("SELECT COUNT(*) FROM inputs", [], |row| row.get(0))
            .expect("count");
        assert_eq!(inputs, 1);
        assert_eq!(output_row(&conn, &a.output_hash()).1, "SPENT");
    }

    #[test]
    fn a_re_created_output_is_credited_and_debited_once_per_instance() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(20, Vec::new(), vec![a.output_hash()]),
            block(30, vec![a.clone()], Vec::new()),
            block(40, Vec::new(), vec![a.output_hash()]),
        ];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].2.as_deref(), Some(blocks[1].block_hash.as_slice()));
        assert_eq!(rows[1].2.as_deref(), Some(blocks[3].block_hash.as_slice()));
        assert_ne!(rows[0].1, rows[1].1, "each instance has its own tx_id");
        assert_eq!(
            rows[0].1,
            TxId::new_deterministic(wallet.view_key.as_bytes(), &a.output_hash()).as_i64_wrapped(),
            "the first instance keeps the original tx_id"
        );
        assert_eq!(ledger(&conn, wallet.account_id), (2, 2, 0));
        assert_eq!(
            history_heights(&conn, wallet.account_id),
            vec![10, 20, 30, 40],
            "one history entry per credit and per spend"
        );

        // Reading every block again changes nothing, the tx_ids included.
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);
        assert_eq!(instances(&conn, wallet.account_id, &a), rows);
        assert_eq!(ledger(&conn, wallet.account_id), (2, 2, 0));
    }

    #[test]
    fn a_re_created_output_re_mined_in_another_block_after_a_reorg_keeps_its_tx_id() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(20, Vec::new(), vec![a.output_hash()]),
                block(30, vec![a.clone()], Vec::new()),
            ],
        );
        let tx_id = instances(&conn, wallet.account_id, &a)[1].1;

        rollback_to(&mut conn, wallet.account_id, 30);
        assert_eq!(instances(&conn, wallet.account_id, &a).len(), 1);

        let remined = BlockScanResult {
            block_hash: hash(99),
            ..block(31, vec![a.clone()], Vec::new())
        };
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&remined),
        );

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].1, tx_id);
        assert_eq!(ledger(&conn, wallet.account_id).2, 10_000);
    }

    #[test]
    fn an_output_in_two_accounts_is_credited_and_debited_once_in_each() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let other = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "second", &other, "password").unwrap();
        let second_id = get_account_by_name(&conn, "second").unwrap().unwrap().id;
        // The same view key for both, so the tx_id derivation has to step past the first account's id.
        let mut processor = BlockProcessor::new(
            vec![
                (wallet.account_id, wallet.view_key.clone()),
                (second_id, wallet.view_key.clone()),
            ],
            3,
        );
        let a = test_wallet_output(10_000, 1);
        let mut created = block(10, Vec::new(), Vec::new());
        created.wallet_outputs = vec![(a.output_hash(), a.clone(), 0), (a.output_hash(), a.clone(), 1)];
        let spent = block(20, Vec::new(), vec![a.output_hash()]);

        for _ in 0..2 {
            for account_id in [wallet.account_id, second_id] {
                process(&mut processor, &conn, account_id, &[created.clone(), spent.clone()]);
            }
        }

        for account_id in [wallet.account_id, second_id] {
            assert_eq!(ledger(&conn, account_id), (1, 1, 0));
            assert_eq!(instances(&conn, account_id, &a).len(), 1);
            assert_eq!(
                history_heights(&conn, account_id),
                vec![10, 20],
                "each account keeps its own receive and spend entries"
            );
        }
        assert_ne!(
            instances(&conn, wallet.account_id, &a)[0].1,
            instances(&conn, second_id, &a)[0].1,
            "tx_ids are unique across accounts"
        );
    }

    #[test]
    fn a_spend_block_presented_again_and_again_debits_once() {
        // Regression: each presentation of a spend block added another debit.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let b = test_wallet_output(4_000, 2);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone(), b], Vec::new())],
        );
        let spend = block(20, Vec::new(), vec![a.output_hash()]);
        for _ in 0..3 {
            process(
                &mut processor(&wallet, false),
                &conn,
                wallet.account_id,
                std::slice::from_ref(&spend),
            );
        }

        let (_, debits, total) = ledger(&conn, wallet.account_id);
        assert_eq!(debits, 1);
        assert_eq!(total, 4_000);
    }

    #[test]
    fn a_reorg_below_a_re_read_spend_restores_the_balance_exactly() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let b = test_wallet_output(4_000, 2);
        let spend = block(20, Vec::new(), vec![a.output_hash()]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone(), b], Vec::new()), spend.clone()],
        );
        for _ in 0..2 {
            process(
                &mut processor(&wallet, false),
                &conn,
                wallet.account_id,
                std::slice::from_ref(&spend),
            );
        }
        assert_eq!(ledger(&conn, wallet.account_id).2, 4_000);

        rollback_to(&mut conn, wallet.account_id, 20);
        assert_eq!(ledger(&conn, wallet.account_id).2, 14_000, "the pre-spend balance");

        // The reorg left the row SPENT but removed its input: mined again, the spend debits again.
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&spend),
        );
        assert_eq!(ledger(&conn, wallet.account_id).2, 4_000);
    }

    #[test]
    fn a_re_created_output_whose_spends_arrive_out_of_height_order_debits_each_instance() {
        // FastSync scans recent blocks before it backfills history.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let first_spend = block(20, Vec::new(), vec![a.output_hash()]);
        let second_spend = block(40, Vec::new(), vec![a.output_hash()]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(30, vec![a.clone()], Vec::new()),
            ],
        );
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&second_spend),
        );
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&first_spend),
        );

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].2.as_deref(), Some(first_spend.block_hash.as_slice()));
        assert_eq!(rows[1].2.as_deref(), Some(second_spend.block_hash.as_slice()));
        assert_eq!(ledger(&conn, wallet.account_id), (2, 2, 0));
        assert_eq!(history_heights(&conn, wallet.account_id), vec![10, 20, 30, 40]);
    }

    #[test]
    fn an_older_copy_found_after_a_newer_one_gets_its_own_row_and_tx_id() {
        // FastSync stores the unspent copy first, then backfill finds the older copy and its spend.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(30, vec![a.clone()], Vec::new())],
        );
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        let spend = block(20, Vec::new(), vec![a.output_hash()]);
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new()), spend.clone()],
        );

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].1, rows[1].1);
        assert_eq!(rows[0].2.as_deref(), Some(spend.block_hash.as_slice()));
        assert_eq!(rows[1].2, None);
        assert_eq!(ledger(&conn, wallet.account_id), (2, 1, 10_000));
    }

    #[test]
    fn an_input_in_an_earlier_result_of_its_block_than_its_output_is_debited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        // Created and spent in block 20, whose results arrive input first.
        let input_first = block(20, Vec::new(), vec![a.output_hash()]);
        let output_second = block(20, vec![a.clone()], Vec::new());
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[input_first, output_second],
        );

        assert_eq!(ledger(&conn, wallet.account_id), (1, 1, 0));
        assert_eq!(output_row(&conn, &a.output_hash()).1, "SPENT");
    }

    #[test]
    fn an_older_spent_unconfirmed_copy_is_resolved_spent_by_its_newer_copy() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let newer = block(30, vec![a.clone()], Vec::new());
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&newer),
        );
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new())],
        );

        assert_eq!(
            db::resolve_superseded_spent_unconfirmed(&conn, wallet.account_id, false).expect("resolve"),
            1
        );
        // Never asked about again, and never marked unspent.
        assert!(
            db::get_unresolved_spent_unconfirmed_outputs(&conn, wallet.account_id, false)
                .expect("unresolved")
                .is_empty()
        );
        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(
            rows[0].2.as_deref(),
            Some(newer.block_hash.as_slice()),
            "the inferred spend is in the newer copy's block"
        );
        assert_eq!(rows[1].2, None);
        assert_eq!(ledger(&conn, wallet.account_id), (2, 1, 10_000));
        assert_eq!(
            db::resolve_superseded_spent_unconfirmed(&conn, wallet.account_id, false).expect("resolve again"),
            0
        );
        assert_eq!(ledger(&conn, wallet.account_id), (2, 1, 10_000));
    }

    #[test]
    fn only_the_newest_of_two_spent_unconfirmed_copies_is_left_for_the_base_node() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(30, vec![a.clone()], Vec::new()),
            ],
        );

        db::resolve_superseded_spent_unconfirmed(&conn, wallet.account_id, false).expect("resolve");
        let unresolved =
            db::get_unresolved_spent_unconfirmed_outputs(&conn, wallet.account_id, false).expect("unresolved");
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].mined_in_block_height, 30);
        assert_eq!(ledger(&conn, wallet.account_id), (2, 1, 10_000));
    }

    #[test]
    fn a_reorg_between_an_inferred_spend_and_the_newer_copy_keeps_the_balance() {
        // The real spend of the copy at 10 (at 20) was never stored; the newer copy is at 30.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let newer = block(30, vec![a.clone()], Vec::new());
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&newer),
        );
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new())],
        );
        db::resolve_superseded_spent_unconfirmed(&conn, wallet.account_id, false).expect("resolve");
        let before = ledger(&conn, wallet.account_id).2;
        assert_eq!(before, 10_000);

        rollback_to(&mut conn, wallet.account_id, 25);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&newer),
        );
        // What the scan's post-scan pass does once caught up.
        db::resolve_superseded_spent_unconfirmed(&conn, wallet.account_id, true).expect("resolve");

        assert_eq!(ledger(&conn, wallet.account_id).2, before);
        assert!(
            instances(&conn, wallet.account_id, &a)[0].2.is_some(),
            "the older copy stays spent"
        );
    }

    #[test]
    fn a_rejected_sends_change_restored_after_another_account_took_its_tx_id_gets_a_fresh_one() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let other = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "second", &other, "password").unwrap();
        let second_id = get_account_by_name(&conn, "second").unwrap().unwrap().id;
        let send = record_send(&wallet, &conn, 1, &[1, 2], Some(3));
        let change = send.change.clone().unwrap();
        reject_as_the_monitor_does(&conn, &send);

        // Both accounts share the view key; the second finds the change while the
        // first's change row is soft-deleted, and takes its tx_id.
        let mut processor = BlockProcessor::new(
            vec![
                (wallet.account_id, wallet.view_key.clone()),
                (second_id, wallet.view_key.clone()),
            ],
            3,
        );
        let mut mined = block(50, Vec::new(), send.input_hashes.clone());
        mined.wallet_outputs = vec![
            (change.output_hash(), change.clone(), 1),
            (change.output_hash(), change.clone(), 0),
        ];
        process(&mut processor, &conn, second_id, std::slice::from_ref(&mined));
        process(&mut processor, &conn, wallet.account_id, std::slice::from_ref(&mined));

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );
        let (change_id, status, ..) = change_row(&conn, &send);
        assert_eq!(status, "UNSPENT");
        let first = instances(&conn, wallet.account_id, &change);
        let second = instances(&conn, second_id, &change);
        assert_eq!(first[0].0, change_id);
        assert_ne!(first[0].1, second[0].1);
        assert_eq!(ledger(&conn, second_id), (1, 0, 3_000));
    }

    #[test]
    fn a_re_created_output_spent_in_a_split_block_with_the_input_first_is_debited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        // Block 60 re-creates and spends the hash; its input arrives in the first result.
        let input_first = block(60, Vec::new(), vec![a.output_hash()]);
        let output_second = block(60, vec![a.clone()], Vec::new());
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(20, Vec::new(), vec![a.output_hash()]),
                input_first.clone(),
                output_second,
            ],
        );

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].2.as_deref(), Some(input_first.block_hash.as_slice()));
        assert_eq!(ledger(&conn, wallet.account_id), (2, 2, 0));
    }

    #[test]
    fn a_reorg_between_an_older_copy_and_its_spend_unsettles_an_inferred_spend() {
        // The copy at 10 was inferred spent (its newer copy is at 30). A fork at 15
        // removes the newer copy, and the new chain does not spend the copy at 10.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(30, vec![a.clone()], Vec::new())],
        );
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new())],
        );
        db::resolve_superseded_spent_unconfirmed(&conn, wallet.account_id, false).expect("resolve");

        rollback_to(&mut conn, wallet.account_id, 15);
        let fork = BlockScanResult {
            block_hash: hash(98),
            ..block(15, Vec::new(), Vec::new())
        };
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&fork),
        );
        db::resolve_superseded_spent_unconfirmed(&conn, wallet.account_id, true).expect("resolve");

        let (_, status, ..) = output_row(&conn, &a.output_hash());
        assert_eq!(status, "SPENT_UNCONFIRMED", "not left spent; the base node settles it");
        let unresolved =
            db::get_unresolved_spent_unconfirmed_outputs(&conn, wallet.account_id, true).expect("unresolved");
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].mined_in_block_height, 10);
        assert_eq!(ledger(&conn, wallet.account_id).2, 10_000, "the copy's value is back");
    }

    #[test]
    fn a_reorg_keeps_a_rebroadcast_sends_inputs_spent_and_unsettles_a_spend_by_a_request_that_is_gone() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1], Some(3));
        // Another output, spent in the same block under a lock of a request that is gone.
        let other = test_wallet_output(7_000, 5);
        let (other_id, _) = db::insert_output(
            &conn,
            wallet.account_id,
            &wallet.view_key,
            &other.output_hash(),
            &other,
            10,
            &hash(11),
            1_700_000_000,
            None,
            None,
            FixedHash::zero(),
            false,
        )
        .expect("other output");
        db::lock_output(&conn, other_id, "gone", Utc::now()).expect("lock");

        let mined = block(
            50,
            vec![send.change.clone().unwrap()],
            vec![send.input_hashes[0], other.output_hash()],
        );
        process(
            &mut processor(&wallet, true),
            &conn,
            wallet.account_id,
            &[mined, block(51, Vec::new(), Vec::new())],
        );
        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );

        rollback_to(&mut conn, wallet.account_id, 50);

        // The send is rebroadcast: its input stays spent and its own.
        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::Completed
        );
        let input: (String, Option<String>) = conn
            .query_row(
                "SELECT status, locked_by_request_id FROM outputs WHERE output_hash = :hash AND deleted_at IS NULL",
                named_params! { ":hash": send.input_hashes[0].as_slice() },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("input");
        assert_eq!(input, ("SPENT".to_string(), Some(send.request_id.clone())));
        // Nothing can land under the dead lock: the spend is settled again.
        assert_eq!(output_row(&conn, &other.output_hash()).1, "SPENT_UNCONFIRMED");
    }

    #[test]
    fn a_send_re_mined_after_a_reorg_that_also_replaced_its_input_keeps_one_history_entry() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let x = test_wallet_output(10_000, 1);
        let received = block(10, vec![x.clone()], Vec::new());
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&received),
        );
        let send = record_send(&wallet, &conn, 1, &[1], Some(3));
        // The entry names the spent row, as `TransactionManager` records it.
        let (old_row, ..) = output_row(&conn, &x.output_hash());
        let mut entry = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("entry");
        entry.details.inputs[0].matched_output_id = old_row;
        db::insert_displayed_transaction(&conn, &entry).expect("entry");

        let mined = block(50, vec![send.change.clone().unwrap()], vec![x.output_hash()]);
        let blocks = [received, mined, block(51, Vec::new(), Vec::new())];
        process(&mut processor(&wallet, true), &conn, wallet.account_id, &blocks[1..]);

        // The reorg reaches back past the block X was received in; X gets a new row.
        rollback_to(&mut conn, wallet.account_id, 10);
        db::mark_completed_transaction_as_broadcasted(&conn, send.tx_id, 1).expect("rebroadcast");
        process(&mut processor(&wallet, true), &conn, wallet.account_id, &blocks);
        assert_ne!(output_row(&conn, &x.output_hash()).0, old_row);

        let displayed = db::get_displayed_transaction_by_id(&conn, &send.tx_id.to_string())
            .expect("query")
            .expect("send entry");
        assert_eq!(displayed.blockchain.block_height, 50);
        let spend_entries: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM displayed_transactions WHERE account_id = :account_id AND block_height = 50",
                named_params! { ":account_id": wallet.account_id },
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(spend_entries, 1, "no second entry for the same spend");
    }
}
