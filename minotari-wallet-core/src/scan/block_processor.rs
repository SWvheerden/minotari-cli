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
    /// Per account, inputs of the block being processed that matched no output yet.
    unmatched_inputs: HashMap<i64, UnmatchedInputs>,
}

/// Inputs of one block that matched no output of the account. A block split over
/// several results can list an input before the output it spends (an output
/// created and spent in the block), so each is tried again when a later result
/// of the block stores its output. Kept for the account's open block only.
struct UnmatchedInputs {
    height: u64,
    block_hash: FixedHash,
    /// Per input hash: `Some(block it was spent in, or "none")` when the account
    /// has copies of the hash, which is warned about (once) if it is still unmatched
    /// at the end of the batch; `None` for a hash the account does not hold or one
    /// already warned about.
    hashes: HashMap<FixedHash, Option<String>>,
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
            unmatched_inputs: HashMap::new(),
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
            unmatched_inputs: HashMap::new(),
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
        if self
            .unmatched_inputs
            .get(&account_id)
            .is_some_and(|open| open.block_hash != block.block_hash)
            && let Some(mut open) = self.unmatched_inputs.remove(&account_id)
        {
            Self::warn_unmatched(account_id, &mut open);
        }

        self.current_tip_height = block.height;

        self.current_block = Some(BlockEventAccumulator::new(
            account_id,
            block.height,
            block.block_hash.to_vec(),
        ));

        let mut request_ids = self.process_outputs(tx, block, account_id, &account_view_key)?;
        request_ids.extend(self.process_inputs(tx, block, account_id, &block.inputs)?);
        // Inputs an earlier result of this block listed before the outputs this one holds.
        let retried: Vec<FixedHash> = match self.unmatched_inputs.get_mut(&account_id) {
            Some(open) => block
                .wallet_outputs
                .iter()
                .filter(|(hash, ..)| open.hashes.remove(hash).is_some())
                .map(|(hash, ..)| *hash)
                .collect(),
            None => Vec::new(),
        };
        if !retried.is_empty() {
            request_ids.extend(self.process_inputs(tx, block, account_id, &retried)?);
        }
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
    /// - Records the balance change (credit), except for a burn output
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

        for (hash, output, wallet_idx) in &block.wallet_outputs {
            let Some(mapped_account_id) = self.wallet_index_to_account_id.get(*wallet_idx).copied() else {
                continue;
            };

            // The scanner gives an output to the first account of the scan that can read it, so accounts scanned
            // together never both store a shared output; accounts scanned separately each do.
            if mapped_account_id != account_id {
                continue;
            }
            // The row key and tx_id are built from `hash`, so it must be the output's own.
            if *hash != output.output_hash() {
                warn!(
                    target: "audit",
                    account_id = account_id,
                    block_height = block.height;
                    "Wallet output listed under a hash that is not its own; ignoring it"
                );
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
                && let Some((request_id, completed_tx_id)) = db::restore_change_of_rejected_send(tx, account_id, hash)?
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
            // Update that row in place rather than inserting a second row for the
            // same output (the send's change would stay unmined); the credit,
            // event and accumulator entry below are recorded as for a new output.
            // A burn output can never be spent, so it is unspent whichever scan finds it.
            let status_when_found = if self.backfill_mode && !is_burn {
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

            // Two unspent copies of one hash cannot be on chain: a copy still unspent in another block means the scan
            // crossed a reorg it has not rolled back. Not checked without inputs (no spend is ever recorded).
            if change_output_id.is_none()
                && !self.inputs_excluded
                && let Some(copy_block) =
                    db::get_unspent_copy_block(tx, account_id, hash, block.height, &block.block_hash)?
            {
                warn!(
                    target: "audit",
                    account_id = account_id,
                    block_height = block.height,
                    block_hash = &*hex::encode(block.block_hash),
                    unspent_in_block = &*hex::encode(copy_block);
                    "Output already unspent in another block; ignoring this copy"
                );
                continue;
            }

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
                    // Seen before (the continuous scan re-reads the tip): its event, webhook and credit are recorded.
                    continue;
                }
                output_id
            };
            let tx_id = db::get_output_by_id(tx, output_id)?
                .map(|row| TxId::from(row.tx_id.cast_unsigned()))
                .ok_or_else(|| WalletDbError::Unexpected(format!("Output {output_id} not found after insert")))?;

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

            let detected = DetectedOutput {
                height: block.height,
                mined_in_block_hash: block.block_hash,
                output: output.clone(),
                tx_id,
            };
            // A burn is an outflow: its output is kept and shown, but never credits the balance.
            if is_burn {
                #[allow(clippy::cast_possible_wrap)]
                let mined_at = DateTime::<Utc>::from_timestamp(block.mined_timestamp as i64, 0)
                    .unwrap_or_else(Utc::now)
                    .naive_utc();
                if let Some(ref mut acc) = self.current_block {
                    acc.add_burn_output(mined_at, detected);
                }
                continue;
            }

            let balance_change = self.record_output_balance_change(tx, account_id, output_id, block, output)?;

            if let Some(ref mut acc) = self.current_block {
                acc.add_credit_change(balance_change, detected);
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
                if let Some((height, block_hash)) =
                    db::get_output_spend(tx, account_id, &send.pending_tx_id, &input.output_hash())?
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
        // One credit per output row, however often its block is presented.
        db::insert_balance_change_if_not_exists(tx, &change)?;

        Ok(change)
    }

    /// Processes all inputs in the block to detect spent outputs.
    ///
    /// For each input that references a wallet-owned output:
    /// - Inserts the input record into the database
    /// - Records the balance change (debit)
    /// - Updates the output status to Spent
    /// - Adds to the block accumulator for event emission
    ///
    /// An input hash spends the newest active instance of the hash mined at or
    /// below this block, if that instance has no active input. This block counts:
    /// an output can be created and spent in the same block (a zero-conf spend,
    /// such as a send's change spent at once). An older instance was spent before the
    /// newer one was created, even when its spend is not recorded yet (a backfill
    /// that has not reached it). A hash already spent
    /// in this block (a re-read, a later result of the same block, or a repeat
    /// in one result) is skipped silently; one with no such instance is skipped
    /// with a warning. Both are decided from the database, so they hold across
    /// results and batches.
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
            let mut instances = db::get_output_instances_for_account(tx, account_id, input_hash)?;
            if instances
                .iter()
                .any(|o| o.spent_in_block_hash.as_deref() == Some(block.block_hash.as_slice()))
            {
                continue;
            }
            let Some(db::OutputInstance {
                id: output_id,
                tx_id,
                output,
                ..
            }) = instances
                .iter()
                // shortcut: an input listed before its re-created output in a split block can match a backfilled
                // SpentUnconfirmed older copy (its spend not yet recorded) instead of the new copy. Upgrade if
                // re-creations in a backfill gap become realistic: make a match against a SpentUnconfirmed copy
                // provisional until the block closes.
                .rposition(|o| o.mined_in_block_height <= block.height)
                .filter(|i| instances.get(*i).is_some_and(|o| o.spent_in_block_hash.is_none()))
                .map(|i| instances.swap_remove(i))
            else {
                let spent_in_block = (!instances.is_empty()).then(|| {
                    instances
                        .iter()
                        .rev()
                        .find_map(|o| o.spent_in_block_hash.as_deref())
                        .map_or_else(|| "none".to_string(), hex::encode)
                });
                self.unmatched_inputs
                    .entry(account_id)
                    .or_insert_with(|| UnmatchedInputs {
                        height: block.height,
                        block_hash: block.block_hash,
                        hashes: HashMap::new(),
                    })
                    .hashes
                    .entry(*input_hash)
                    .or_insert(spent_in_block);
                continue;
            };

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
                        mined_in_block: block.block_hash,
                        mined_in_block_height: block.height,
                        output_id,
                        output,
                        tx_id,
                    },
                );
            }
        }

        Ok(request_ids)
    }

    /// The warning still due for an unmatched input of the account's open block.
    #[cfg(test)]
    fn unmatched_input_warning(&self, account_id: i64, input_hash: &FixedHash) -> Option<Option<&String>> {
        self.unmatched_inputs
            .get(&account_id)
            .and_then(|open| open.hashes.get(input_hash))
            .map(Option::as_ref)
    }

    /// Drops what the processor holds of a batch whose transaction was rolled back.
    pub fn discard_batch(&mut self) {
        self.current_block = None;
        self.send_block = None;
        self.unmatched_inputs.clear();
        self.wallet_events.clear();
    }

    /// Warns about the inputs still unmatched in each account's open block. Call
    /// at the end of a batch; the inputs stay open, in case the next result
    /// continues the block.
    pub fn warn_unmatched_inputs(&mut self) {
        for (account_id, open) in &mut self.unmatched_inputs {
            Self::warn_unmatched(*account_id, open);
        }
    }

    /// Warns, once, about each unmatched input the account holds copies of: no
    /// unspent copy mined at or below the block was found.
    fn warn_unmatched(account_id: i64, open: &mut UnmatchedInputs) {
        for spent_in_block in open.hashes.values_mut().filter_map(Option::take) {
            warn!(
                target: "audit",
                account_id = account_id,
                block_height = open.height,
                block_hash = &*hex::encode(open.block_hash),
                spent_in_block = spent_in_block.as_str();
                "Input matches no unspent output mined at or below its block; ignoring it"
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
        for (hash, output, wallet_idx) in &block.wallet_outputs {
            if self.wallet_index_to_account_id.get(*wallet_idx).copied() == Some(account_id)
                && *hash == output.output_hash()
            {
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
                    send_block.block_hash.as_slice(),
                    &input_hashes,
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
        let effective_date = i64::try_from(block.mined_timestamp)
            .ok()
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
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

        // One debit per input row.
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
    let effective_date = i64::try_from(timestamp)
        .ok()
        .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
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
    use tari_common_types::tari_address::TariAddress;
    use tari_common_types::transaction::TxId;
    use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey};
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::key_manager::{KeyManager, TariKeyId, TransactionKeyManagerInterface};
    use tari_transaction_components::transaction_components::{
        EncryptedData, MemoField, OutputFeatures, OutputType, TransactionInput, TransactionOutputVersion,
        covenants::Covenant, memo_field::TxType,
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
        test_output(value, hash_byte, OutputFeatures::default(), MemoField::new_empty())
    }

    fn test_output(value: u64, hash_byte: u8, features: OutputFeatures, memo: MemoField) -> WalletOutput {
        WalletOutput::new_from_parts(
            TransactionOutputVersion::default(),
            MicroMinotari::from(value),
            TariKeyId::default(),
            features,
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
            memo,
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
        let mut input_rows = Vec::new();
        let mut inputs = Vec::new();
        for byte in input_bytes {
            let output = test_wallet_output(10_000, *byte);
            // An input another send released can be spent again.
            if let Some((output_id, ..)) =
                db::get_output_info_by_hash_for_account(conn, wallet.account_id, &output.output_hash()).expect("lookup")
            {
                db::lock_output(conn, output_id, &request_id, Utc::now()).expect("lock input");
                input_hashes.push(output.output_hash());
                input_rows.push(output_id);
                inputs.push(TransactionInput::new_with_output_hash(
                    output.output_hash(),
                    ExecutionStack::default(),
                    ComAndPubSignature::default(),
                ));
                continue;
            }
            let output_id = db::insert_output(
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
            .expect("input output")
            .0;
            db::lock_output(conn, output_id, &request_id, Utc::now()).expect("lock input");
            input_hashes.push(output.output_hash());
            input_rows.push(output_id);
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

        let displayed = pending_displayed_send(wallet.account_id, tx_id, &input_hashes, &input_rows, change.as_ref());
        db::insert_displayed_transaction(conn, &displayed).expect("displayed");

        TestSend {
            request_id,
            tx_id,
            input_hashes,
            change,
        }
    }

    /// The pending displayed transaction `TransactionManager` records for a send:
    /// its inputs (with the rows it locked) and its change, so the scan can recognise it.
    fn pending_displayed_send(
        account_id: i64,
        tx_id: TxId,
        input_hashes: &[FixedHash],
        input_rows: &[i64],
        change: Option<&WalletOutput>,
    ) -> DisplayedTransaction {
        let mut inputs = Vec::new();
        for (input_hash, row) in input_hashes.iter().zip(input_rows) {
            inputs.push(crate::transactions::TransactionInput {
                output_hash: *input_hash,
                amount: MicroMinotari::from(10_000),
                matched_output_id: *row,
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
        processor.match_sends(conn, false).expect("match sends");
        if let Some(last) = blocks.last() {
            processor
                .settle_sends_in_passed_blocks(conn, account_id, last.height)
                .expect("settle sends");
        }
        processor.warn_unmatched_inputs();
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
            let id = db::insert_output(
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
            .expect("output")
            .0;
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
        let send_input = db::get_output_info_by_hash_for_account(&conn, wallet.account_id, &send.input_hashes[0])
            .expect("lookup")
            .expect("send input")
            .0;

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

    // ── Burns ──────────────────────────────────────────────────────────────────

    /// A recovered burn output, carrying the open memo a burn gives it.
    fn burn_output(value: u64, hash_byte: u8) -> WalletOutput {
        let memo = MemoField::new_open_from_string("to L2", TxType::Burn).expect("memo");
        test_output(value, hash_byte, OutputFeatures::create_burn_output(), memo)
    }

    /// The change of a burn of `burned` with `fee`, carrying the memo the burn's transaction builder gives it: it
    /// names the burn output, which in these tests is always `hash(4)`.
    fn burn_change(value: u64, hash_byte: u8, burned: u64, fee: u64) -> WalletOutput {
        let memo = MemoField::new_transaction_info(
            TariAddress::default(),
            burned.into(),
            fee.into(),
            false,
            TxType::Burn,
            vec![hash(4)],
            Vec::new(),
        )
        .expect("memo");
        test_output(value, hash_byte, OutputFeatures::default(), memo)
    }

    /// Receives two 6_000 outputs at height 10 and lets them confirm; returns their hashes, the inputs of a burn.
    fn fund_burn(wallet: &TestWallet, conn: &Connection) -> Vec<FixedHash> {
        let funding = block(
            10,
            vec![test_wallet_output(6_000, 1), test_wallet_output(6_000, 2)],
            Vec::new(),
        );
        let mut blocks = vec![funding];
        blocks.extend((11..=15).map(|h| block(h, Vec::new(), Vec::new())));
        process(&mut processor(wallet, false), conn, wallet.account_id, &blocks);
        vec![hash(1), hash(2)]
    }

    /// The block at `height` with a burn of 7_000 (fee 100) from the funded inputs, leaving 4_900 change, and
    /// `burn_outputs` recovered alongside.
    fn own_burn_block(height: u64, inputs: Vec<FixedHash>, burn_outputs: Vec<WalletOutput>) -> BlockScanResult {
        let mut outputs = vec![burn_change(4_900, 3, 7_000, 100)];
        outputs.extend(burn_outputs);
        block(height, outputs, inputs)
    }

    fn displays_at(conn: &Connection, account_id: i64, height: u64) -> Vec<DisplayedTransaction> {
        db::get_displayed_transactions_from_height(conn, account_id, height)
            .expect("displays")
            .into_iter()
            .filter(|d| d.blockchain.block_height == height)
            .collect()
    }

    fn selectable(conn: &Connection, account_id: i64) -> u64 {
        let tip = db::get_latest_scanned_tip_block_by_account(conn, account_id)
            .expect("tip")
            .expect("scanned")
            .height;
        db::fetch_unspent_outputs(conn, account_id, tip, tip)
            .expect("unspent")
            .iter()
            .map(|o| o.output.value().as_u64())
            .sum()
    }

    fn credit_rows_for(conn: &Connection, output_hash: &FixedHash) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM balance_changes WHERE caused_by_output_id IN
                 (SELECT id FROM outputs WHERE output_hash = :hash)",
            named_params! { ":hash": output_hash.as_slice() },
            |row| row.get(0),
        )
        .expect("count")
    }

    type DisplayShape = (
        String,
        TransactionSource,
        u64,
        u64,
        Vec<(FixedHash, String)>,
        Vec<FixedHash>,
    );

    fn display_shape(d: &DisplayedTransaction) -> DisplayShape {
        (
            d.id.to_string(),
            d.source,
            d.details.total_credit.as_u64(),
            d.details.total_debit.as_u64(),
            d.details
                .outputs
                .iter()
                .map(|o| (o.hash, format!("{:?}", o.output_type)))
                .collect(),
            d.details.inputs.iter().map(|i| i.output_hash).collect(),
        )
    }

    /// History rebuilt from the stored ledger and burn outputs matches what the scan built.
    fn assert_rebuild_matches_scan(wallet: &TestWallet, conn: &Connection) {
        let mut scanned: Vec<_> = db::get_displayed_transactions_from_height(conn, wallet.account_id, 0)
            .expect("displays")
            .iter()
            .map(display_shape)
            .collect();
        conn.execute("DELETE FROM displayed_transactions", []).expect("clear");
        let (updated, rebuilt) = DisplayedTransactionProcessor::new(100, 3)
            .process_all_stored_with_conn(wallet.account_id, conn)
            .expect("rebuild");
        assert!(updated.is_empty());
        let mut rebuilt: Vec<_> = rebuilt.iter().map(display_shape).collect();
        scanned.sort_by(|a, b| a.0.cmp(&b.0));
        rebuilt.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(rebuilt, scanned);
    }

    #[test]
    fn a_recovered_burn_output_never_credits_the_balance() {
        for (output, expected) in [(test_wallet_output(7_000, 1), 7_000u64), (burn_output(7_000, 1), 0)] {
            let wallet = test_wallet();
            let conn = wallet.pool.get().expect("conn");
            let mut blocks = vec![block(20, vec![output], Vec::new())];
            blocks.extend((21..=30).map(|h| block(h, Vec::new(), Vec::new())));
            process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);

            let balance = db::get_balance(&conn, wallet.account_id).expect("balance");
            assert_eq!(balance.total, expected.into());
            assert_eq!(balance.available, expected.into());
            let totals = db::get_output_totals_for_account(&conn, wallet.account_id, 30).expect("totals");
            assert_eq!(totals.available, expected.into());
            assert_eq!(
                db::get_total_unspent_balance(&conn, wallet.account_id, 30).expect("unspent"),
                expected
            );
            assert_eq!(selectable(&conn, wallet.account_id), expected);
            assert_eq!(balance.available.as_u64(), selectable(&conn, wallet.account_id));
        }
    }

    #[test]
    fn an_own_burn_with_its_output_recovered_is_one_burn_transaction() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let inputs = fund_burn(&wallet, &conn);

        let burn_block = own_burn_block(20, inputs.clone(), vec![burn_output(7_000, 4)]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&burn_block),
        );

        let displays = displays_at(&conn, wallet.account_id, 20);
        assert_eq!(displays.len(), 1, "one transaction, no separate received entry");
        let burn = &displays[0];
        assert_eq!(burn.source, TransactionSource::Burn);
        assert_eq!(burn.direction, TransactionDirection::Outgoing);
        assert_eq!(burn.details.total_debit, 12_000.into());
        assert_eq!(burn.details.total_credit, 4_900.into());
        assert_eq!(burn.amount, 7_100.into(), "burn plus fee");
        assert_eq!(burn.details.output_type, Some(OutputType::Burn));
        assert_eq!(burn.details.inputs.len(), inputs.len());
        let burned = burn
            .details
            .outputs
            .iter()
            .find(|o| o.hash == hash(4))
            .expect("burn output attached");
        assert_eq!(burned.output_type, OutputType::Burn);
        assert_eq!(burned.amount, 7_000.into());
        assert!(!burned.is_change);

        let balance = db::get_balance(&conn, wallet.account_id).expect("balance");
        assert_eq!(balance.total, 4_900.into(), "dropped by the burn and its fee");
        assert_eq!(credit_rows_for(&conn, &hash(4)), 0);

        assert_rebuild_matches_scan(&wallet, &conn);
    }

    #[test]
    fn an_own_burn_without_its_output_recovered_is_a_burn_transaction() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let inputs = fund_burn(&wallet, &conn);

        let burn_block = own_burn_block(20, inputs, Vec::new());
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&burn_block),
        );

        let displays = displays_at(&conn, wallet.account_id, 20);
        assert_eq!(displays.len(), 1);
        assert_eq!(displays[0].source, TransactionSource::Burn);
        assert_eq!(displays[0].details.total_debit, 12_000.into());
        assert_eq!(displays[0].details.total_credit, 4_900.into());
        assert_eq!(displays[0].details.outputs.len(), 1, "only the change");

        assert_rebuild_matches_scan(&wallet, &conn);
    }

    #[test]
    fn a_burn_this_wallet_sent_is_shown_as_a_burn_once_mined() {
        // As `persist_burn_records` leaves a burn: a completed transaction and its change row, no displayed entry.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let send = record_send(&wallet, &conn, 1, &[1, 2], None);
        conn.execute("DELETE FROM displayed_transactions", [])
            .expect("no display");
        let change = burn_change(12_900, 3, 7_000, 100);
        db::insert_unconfirmed_change_output(&conn, wallet.account_id, &wallet.view_key, &send.request_id, &change)
            .expect("change row");

        let mined = block(50, vec![change], send.input_hashes.clone());
        process(
            &mut processor(&wallet, true),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&mined),
        );

        assert_eq!(
            completed(&conn, send.tx_id).status,
            db::CompletedTransactionStatus::MinedUnconfirmed
        );
        let displays = displays_at(&conn, wallet.account_id, 50);
        assert_eq!(displays.len(), 1);
        assert_eq!(displays[0].source, TransactionSource::Burn);
        assert_eq!(displays[0].details.total_debit, 20_000.into());
        assert_eq!(displays[0].details.total_credit, 12_900.into());
    }

    #[test]
    fn a_third_party_burn_is_stored_and_shown_without_value() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let mut blocks = vec![block(10, vec![test_wallet_output(5_000, 1)], Vec::new())];
        blocks.extend((11..=15).map(|h| block(h, Vec::new(), Vec::new())));
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);
        let available_before = db::get_balance(&conn, wallet.account_id).expect("balance").available;
        assert_eq!(available_before, 5_000.into());

        let mut burn_processor = processor(&wallet, false);
        burn_processor.set_webhook_config(Some(WebhookTriggerConfig {
            url: "https://example.invalid/hook".to_string(),
            send_only_event_types: None,
        }));
        let burn_block = block(20, vec![burn_output(7_000, 4)], Vec::new());
        process(
            &mut burn_processor,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&burn_block),
        );

        let (_, status, height, ..) = output_row(&conn, &hash(4));
        assert_eq!(
            (status.as_str(), height),
            ("UNSPENT", 20),
            "the burn output row is stored"
        );
        assert_eq!(credit_rows_for(&conn, &hash(4)), 0);
        assert!(burn_processor.take_wallet_events().iter().any(|e| matches!(
            e.event_type,
            WalletEventType::OutputDetected { hash: h, .. } if h == hash(4)
        )));
        let balance = db::get_balance(&conn, wallet.account_id).expect("balance");
        assert_eq!(balance.available, available_before);
        assert_eq!(balance.available.as_u64(), selectable(&conn, wallet.account_id));

        let displays = displays_at(&conn, wallet.account_id, 20);
        assert_eq!(displays.len(), 1);
        let burn = &displays[0];
        assert_eq!(burn.source, TransactionSource::Burn);
        assert_eq!(burn.direction, TransactionDirection::Incoming);
        assert_eq!(burn.amount, 0.into());
        assert_eq!(burn.details.total_credit, 0.into());
        assert_eq!(burn.details.total_debit, 0.into());
        assert_eq!(burn.message.as_deref(), Some("to L2"));
        assert_eq!(burn.details.outputs.len(), 1);
        assert_eq!(burn.details.outputs[0].amount, 7_000.into());
        assert_eq!(burn.details.outputs[0].output_type, OutputType::Burn);

        // The webhook sent for the burn output carries the unchanged balance.
        let payload: String = conn
            .query_row(
                "SELECT payload FROM webhook_queue WHERE event_type = 'OutputDetected'",
                [],
                |row| row.get(0),
            )
            .expect("webhook");
        let payload: serde_json::Value = serde_json::from_str(&payload).expect("json");
        assert_eq!(payload["balance"]["available"], 5_000);

        assert_rebuild_matches_scan(&wallet, &conn);
    }

    #[test]
    fn two_burn_outputs_in_one_block_are_each_shown_once() {
        // Another account's burn ahead of ours, of a different amount and of the same amount: ours is paired by the
        // hash its change memo names, not by order or amount.
        for other_value in [3_000u64, 7_000] {
            let wallet = test_wallet();
            let conn = wallet.pool.get().expect("conn");
            let inputs = fund_burn(&wallet, &conn);

            let burn_block = own_burn_block(20, inputs, vec![burn_output(other_value, 5), burn_output(7_000, 4)]);
            process(
                &mut processor(&wallet, false),
                &conn,
                wallet.account_id,
                std::slice::from_ref(&burn_block),
            );

            let displays = displays_at(&conn, wallet.account_id, 20);
            assert_eq!(displays.len(), 2);
            assert!(displays.iter().all(|d| d.source == TransactionSource::Burn));
            let own = displays
                .iter()
                .find(|d| !d.details.inputs.is_empty())
                .expect("own burn");
            let burns: Vec<_> = own
                .details
                .outputs
                .iter()
                .filter(|o| o.output_type == OutputType::Burn)
                .collect();
            assert_eq!(burns.len(), 1);
            assert_eq!(burns[0].hash, hash(4));
            let other = displays
                .iter()
                .find(|d| d.details.inputs.is_empty())
                .expect("other burn");
            assert_eq!(other.amount, 0.into());
            assert_eq!(other.details.outputs[0].hash, hash(5));
            assert_eq!(
                db::get_balance(&conn, wallet.account_id).expect("balance").total,
                4_900.into()
            );
        }
    }

    #[test]
    fn another_burn_of_the_same_amount_is_not_taken_for_an_own_burn_whose_output_was_not_recovered() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let inputs = fund_burn(&wallet, &conn);

        // Our burn output (`hash(4)`) is not recovered; another burn of the same 7_000 is.
        let burn_block = own_burn_block(20, inputs, vec![burn_output(7_000, 5)]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&burn_block),
        );

        let displays = displays_at(&conn, wallet.account_id, 20);
        assert_eq!(displays.len(), 2);
        assert!(displays.iter().all(|d| d.source == TransactionSource::Burn));
        let own = displays
            .iter()
            .find(|d| !d.details.inputs.is_empty())
            .expect("own burn");
        assert_eq!(own.details.outputs.len(), 1, "only the change, no burn output attached");
        let other = displays
            .iter()
            .find(|d| d.details.inputs.is_empty())
            .expect("other burn");
        assert_eq!(other.amount, 0.into());
        assert_eq!(other.details.outputs[0].hash, hash(5));
    }

    #[test]
    fn a_zero_value_output_claiming_a_burn_does_not_take_the_burn_output() {
        // A 0-value output whose memo claims a burn of 0 naming our burn output: no inputs add up to 0, so it is
        // not matched as a send and leaves the burn output to our own burn.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let inputs = fund_burn(&wallet, &conn);
        let claim = MemoField::new_transaction_info(
            TariAddress::default(),
            0.into(),
            0.into(),
            false,
            TxType::Burn,
            vec![hash(4)],
            Vec::new(),
        )
        .expect("memo");
        let zero = test_output(0, 6, OutputFeatures::default(), claim);

        let burn_block = own_burn_block(20, inputs, vec![zero, burn_output(7_000, 4)]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&burn_block),
        );

        let displays = displays_at(&conn, wallet.account_id, 20);
        let own = displays
            .iter()
            .find(|d| !d.details.inputs.is_empty())
            .expect("own burn");
        assert_eq!(own.source, TransactionSource::Burn);
        assert!(
            own.details.outputs.iter().any(|o| o.hash == hash(4)),
            "keeps its burn output"
        );
        let zero = displays
            .iter()
            .find(|d| d.details.outputs.iter().any(|o| o.hash == hash(6)))
            .expect("zero-value output shown");
        assert_ne!(zero.source, TransactionSource::Burn);
        assert!(zero.details.inputs.is_empty());
        assert!(!zero.details.outputs.iter().any(|o| o.hash == hash(4)));
        assert_eq!(displays.len(), 2);
    }

    #[test]
    fn a_burn_output_found_in_backfill_is_not_credited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        let burn_block = block(20, vec![burn_output(7_000, 4)], Vec::new());
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&burn_block),
        );

        let (_, status, ..) = output_row(&conn, &hash(4));
        assert_eq!(status, "UNSPENT", "as in a normal scan: a burn output is never spent");
        assert_eq!(credit_rows_for(&conn, &hash(4)), 0);
        assert_eq!(
            db::get_balance(&conn, wallet.account_id).expect("balance").total,
            0.into()
        );
    }

    #[test]
    fn a_reorg_of_a_block_with_burn_outputs_rolls_back_cleanly() {
        // This wallet's burn, with its output recovered.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let inputs = fund_burn(&wallet, &conn);
        let blocks = [
            own_burn_block(50, inputs, vec![burn_output(7_000, 4)]),
            block(51, Vec::new(), Vec::new()),
        ];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);
        assert_eq!(
            db::get_balance(&conn, wallet.account_id).expect("balance").total,
            4_900.into()
        );

        rollback_to_50(&mut conn, wallet.account_id);

        assert_eq!(
            db::get_balance(&conn, wallet.account_id).expect("balance").total,
            12_000.into()
        );
        assert_eq!(
            credit_rows_for(&conn, &hash(4)),
            0,
            "nothing reversed for the burn output"
        );
        let displays = displays_at(&conn, wallet.account_id, 50);
        assert_eq!(displays.len(), 1);
        assert_eq!(displays[0].status, TransactionDisplayStatus::Reorganized);

        // Another account's burn.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let blocks = [
            block(10, vec![test_wallet_output(5_000, 1)], Vec::new()),
            block(50, vec![burn_output(7_000, 4)], Vec::new()),
        ];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);

        rollback_to_50(&mut conn, wallet.account_id);

        assert_eq!(
            db::get_balance(&conn, wallet.account_id).expect("balance").total,
            5_000.into()
        );
        assert_eq!(credit_rows_for(&conn, &hash(4)), 0);
        let displays = displays_at(&conn, wallet.account_id, 50);
        assert_eq!(displays.len(), 1);
        assert_eq!(displays[0].status, TransactionDisplayStatus::Reorganized);
    }

    /// (credits, debits) the account's ledger holds, reversals left out.
    fn ledger_counts(conn: &Connection, account_id: i64) -> (i64, i64) {
        conn.query_row(
            "SELECT COUNT(*) FILTER (WHERE balance_credit > 0), COUNT(*) FILTER (WHERE balance_debit > 0)
             FROM balance_changes WHERE account_id = :account_id AND is_reversal = 0",
            named_params! { ":account_id": account_id },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("ledger counts")
    }

    fn total(conn: &Connection, account_id: i64) -> u64 {
        db::get_balance(conn, account_id).expect("balance").total.as_u64()
    }

    fn block_with_hash(
        height: u64,
        block_hash: FixedHash,
        wallet_outputs: Vec<WalletOutput>,
        inputs: Vec<FixedHash>,
    ) -> BlockScanResult {
        BlockScanResult {
            block_hash,
            ..block(height, wallet_outputs, inputs)
        }
    }

    fn instances(conn: &Connection, account_id: i64, output: &WalletOutput) -> Vec<db::OutputInstance> {
        db::get_output_instances_for_account(conn, account_id, &output.output_hash()).expect("instances")
    }

    #[test]
    fn a_block_processed_twice_credits_and_debits_once() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let (a, b) = (test_wallet_output(10_000, 1), test_wallet_output(4_000, 2));
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(20, vec![b], vec![a.output_hash()]),
        ];
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &blocks);
        // The continuous scan re-reads the tip on its next poll.
        process(&mut processor, &conn, wallet.account_id, &blocks[1..]);
        process(&mut processor, &conn, wallet.account_id, &blocks);

        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 1));
        assert_eq!(total(&conn, wallet.account_id), 4_000);
    }

    #[test]
    fn an_input_repeated_in_one_result_debits_once() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(20, Vec::new(), vec![a.output_hash(), a.output_hash()]),
        ];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);

        assert_eq!(ledger_counts(&conn, wallet.account_id), (1, 1));
        assert_eq!(total(&conn, wallet.account_id), 0);
    }

    #[test]
    fn a_block_split_across_two_results_is_recorded_once() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let (a, b) = (test_wallet_output(10_000, 1), test_wallet_output(6_000, 2));
        let (c, d) = (test_wallet_output(3_000, 3), test_wallet_output(2_000, 4));
        let funding = block(10, vec![a.clone(), b.clone()], Vec::new());
        // Each result lists the other's input again: the second must not debit it twice.
        let first = block(20, vec![c], vec![a.output_hash()]);
        let second = block(20, vec![d], vec![b.output_hash(), a.output_hash()]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[funding, first, second],
        );

        assert_eq!(ledger_counts(&conn, wallet.account_id), (4, 2));
        assert_eq!(total(&conn, wallet.account_id), 5_000);
    }

    #[test]
    fn a_spend_re_listed_in_a_later_block_is_ignored() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let (a, b) = (test_wallet_output(10_000, 1), test_wallet_output(4_000, 2));
        let blocks = [
            block(10, vec![a.clone(), b], Vec::new()),
            block(20, Vec::new(), vec![a.output_hash()]),
            block(21, Vec::new(), vec![a.output_hash()]),
        ];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);

        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 1));
        assert_eq!(total(&conn, wallet.account_id), 4_000);
        let spent = instances(&conn, wallet.account_id, &a);
        assert_eq!(spent.len(), 1);
        assert_eq!(
            spent[0].spent_in_block_hash.as_deref(),
            Some(blocks[1].block_hash.as_slice())
        );
    }

    #[test]
    fn a_re_created_output_is_credited_and_spent_per_instance() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(20, Vec::new(), vec![a.output_hash()]),
            block(30, vec![a.clone()], Vec::new()),
            block(40, Vec::new(), vec![a.output_hash()]),
        ];
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &blocks[..3]);
        assert_eq!(total(&conn, wallet.account_id), 10_000);
        process(&mut processor, &conn, wallet.account_id, &blocks[3..]);
        process(&mut processor, &conn, wallet.account_id, &blocks);

        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 2));
        assert_eq!(total(&conn, wallet.account_id), 0);
        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].spent_in_block_hash.as_deref(),
            Some(blocks[1].block_hash.as_slice())
        );
        assert_eq!(
            rows[1].spent_in_block_hash.as_deref(),
            Some(blocks[3].block_hash.as_slice())
        );
        // The first instance keeps the id every earlier version stored; the second gets its own.
        assert_eq!(
            rows[0].tx_id,
            TxId::new_deterministic(wallet.view_key.as_bytes(), &a.output_hash())
        );
        assert_ne!(rows[0].tx_id, rows[1].tx_id);
        // Each instance has its own history entry.
        for row in &rows {
            assert!(
                db::get_displayed_transaction_by_id(&conn, &row.tx_id.to_string())
                    .expect("displayed")
                    .is_some()
            );
        }
    }

    #[test]
    fn a_re_created_output_re_mined_after_a_reorg_keeps_its_tx_id() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(20, Vec::new(), vec![a.output_hash()]),
            block(30, vec![a.clone()], Vec::new()),
        ];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);
        let before = instances(&conn, wallet.account_id, &a)[1].tx_id;

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 30, None).expect("rollback");
        tx.commit().expect("commit");
        let re_mined = block_with_hash(31, hash(99), vec![a.clone()], Vec::new());
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &[re_mined]);

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].tx_id, before);
        assert_eq!(total(&conn, wallet.account_id), 10_000);
    }

    #[test]
    fn an_output_of_two_accounts_is_credited_once_in_each() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        // Two accounts that can both read the output. They are given the same view key, so the output's tx_id is
        // the same in both.
        let other = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "other", &other, "password").unwrap();
        let (first, second) = (
            wallet.account_id,
            get_account_by_name(&conn, "other").unwrap().unwrap().id,
        );
        let mut processor = BlockProcessor::new(
            vec![(first, wallet.view_key.clone()), (second, wallet.view_key.clone())],
            3,
        );

        let a = test_wallet_output(10_000, 1);
        let mut found = block(10, Vec::new(), Vec::new());
        found.wallet_outputs = vec![(a.output_hash(), a.clone(), 0), (a.output_hash(), a, 1)];
        for _ in 0..2 {
            for account_id in [first, second] {
                process(&mut processor, &conn, account_id, std::slice::from_ref(&found));
            }
        }

        for account_id in [first, second] {
            assert_eq!(ledger_counts(&conn, account_id), (1, 0));
            assert_eq!(total(&conn, account_id), 10_000);
        }
    }

    #[test]
    fn a_spend_listed_many_times_and_re_read_debits_once() {
        // Regression: a block listing one spend three times, read again on the
        // next poll, recorded three debits and drove the balance to zero.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let (a, b) = (test_wallet_output(10_000, 1), test_wallet_output(5_000, 2));
        let spend = block(20, Vec::new(), vec![a.output_hash(); 3]);
        let mut processor = processor(&wallet, false);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[block(10, vec![a, b], Vec::new()), spend.clone()],
        );
        process(&mut processor, &conn, wallet.account_id, &[spend]);

        let debits: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM balance_changes WHERE account_id = :account_id AND balance_debit > 0",
                named_params! { ":account_id": wallet.account_id },
                |row| row.get(0),
            )
            .expect("debits");
        assert_eq!(debits, 1);
        assert_eq!(total(&conn, wallet.account_id), 5_000);
    }

    #[test]
    fn a_reorg_below_a_re_read_spend_restores_the_balance() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let (a, b) = (test_wallet_output(10_000, 1), test_wallet_output(5_000, 2));
        let spend = block(20, Vec::new(), vec![a.output_hash()]);
        let mut processor = processor(&wallet, false);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[block(10, vec![a, b], Vec::new()), spend.clone()],
        );
        process(&mut processor, &conn, wallet.account_id, std::slice::from_ref(&spend));
        assert_eq!(total(&conn, wallet.account_id), 5_000);

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 15, None).expect("rollback");
        tx.commit().expect("commit");
        assert_eq!(total(&conn, wallet.account_id), 15_000);

        // The rescan finds the spend again.
        process(&mut processor, &conn, wallet.account_id, &[spend]);
        assert_eq!(total(&conn, wallet.account_id), 5_000);
    }

    /// Fast sync stores the newer copy of `a` (at 30) first; backfill then stores the older one (at 10).
    fn store_newer_copy_then_older(wallet: &TestWallet, conn: &Connection, a: &WalletOutput) {
        process(
            &mut processor(wallet, false),
            conn,
            wallet.account_id,
            &[block(30, vec![a.clone()], Vec::new())],
        );
        let mut backfill = processor(wallet, false);
        backfill.set_backfill_mode(true);
        process(
            &mut backfill,
            conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new())],
        );
    }

    fn rollback_to(conn: &mut Connection, account_id: i64, height: u64) {
        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, account_id, height, None).expect("rollback");
        tx.commit().expect("commit");
    }

    #[test]
    fn a_fork_between_an_older_copy_and_its_inferred_spend_gives_the_copy_back() {
        // The copy at 10 is inferred spent because a newer copy is at 30. A fork at 15
        // removes the newer copy, and the new chain does not spend the copy at 10.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        store_newer_copy_then_older(&wallet, &conn, &a);
        db::resolve_spent_unconfirmed_with_newer_copy(&conn, wallet.account_id, false).expect("resolve");
        assert_eq!(total(&conn, wallet.account_id), 10_000);

        rollback_to(&mut conn, wallet.account_id, 15);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block_with_hash(15, hash(98), Vec::new(), Vec::new())],
        );
        // What the scan's post-scan pass does once caught up.
        db::resolve_spent_unconfirmed_with_newer_copy(&conn, wallet.account_id, true).expect("resolve");

        let older = &instances(&conn, wallet.account_id, &a)[0];
        let status = db::get_output_by_id(&conn, older.id)
            .expect("row")
            .expect("exists")
            .status;
        assert_eq!(
            status, "SPENT_UNCONFIRMED",
            "left to be settled again, not spent for good"
        );
        assert_eq!(total(&conn, wallet.account_id), 10_000, "the copy's value is back");
        let unresolved =
            db::get_unresolved_spent_unconfirmed_outputs(&conn, wallet.account_id, true).expect("unresolved");
        assert_eq!(unresolved.len(), 1, "the base node settles it");
        assert_eq!(unresolved[0].output_id, older.id);
    }

    #[test]
    fn a_fork_between_an_inferred_spend_and_the_newer_copy_keeps_the_balance() {
        // The copy at 10 was really spent (at 20, never stored); the newer copy is at 30.
        // A fork at 25 removes the newer copy and the inferred spend, then the newer copy is mined again.
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        store_newer_copy_then_older(&wallet, &conn, &a);
        db::resolve_spent_unconfirmed_with_newer_copy(&conn, wallet.account_id, false).expect("resolve");
        // The inferred spend is at the newer copy's block, the latest it can be in.
        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows[0].spent_in_block_hash, Some(rows[1].mined_in_block_hash.clone()));
        let before = total(&conn, wallet.account_id);
        assert_eq!(before, 10_000);

        rollback_to(&mut conn, wallet.account_id, 25);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(30, vec![a.clone()], Vec::new())],
        );
        db::resolve_spent_unconfirmed_with_newer_copy(&conn, wallet.account_id, true).expect("resolve");

        assert_eq!(total(&conn, wallet.account_id), before);
        assert!(instances(&conn, wallet.account_id, &a)[0].spent_in_block_hash.is_some());
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
    fn an_older_copy_found_in_backfill_is_resolved_spent_by_its_newer_copy() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        store_newer_copy_then_older(&wallet, &conn, &a);
        assert_eq!(total(&conn, wallet.account_id), 20_000);
        // Each copy has its own receive entry at its own height.
        for (row, height) in instances(&conn, wallet.account_id, &a).iter().zip([10, 30]) {
            let entry = displayed(&conn, row.tx_id);
            assert_eq!(entry.blockchain.block_height, height);
            assert_eq!(entry.details.total_credit.as_u64(), 10_000);
        }

        for _ in 0..2 {
            db::resolve_spent_unconfirmed_with_newer_copy(&conn, wallet.account_id, false).expect("resolve");
        }

        let rows = instances(&conn, wallet.account_id, &a);
        let statuses: Vec<String> = rows
            .iter()
            .map(|row| {
                db::get_output_by_id(&conn, row.id)
                    .expect("row")
                    .expect("exists")
                    .status
            })
            .collect();
        assert_eq!(statuses, ["SPENT", "UNSPENT"]);
        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 1));
        assert_eq!(total(&conn, wallet.account_id), 10_000);
        // The node is asked about the newer copy only.
        assert!(
            db::get_unresolved_spent_unconfirmed_outputs(&conn, wallet.account_id, false)
                .expect("unresolved")
                .is_empty()
        );
    }

    #[test]
    fn a_copy_stored_before_an_older_one_keeps_its_tx_id_when_re_mined_after_a_reorg() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        store_newer_copy_then_older(&wallet, &conn, &a);
        let rows = instances(&conn, wallet.account_id, &a);
        let (older, newer) = (rows[0].tx_id, rows[1].tx_id);
        // Found out of chain order, the newer copy has the first-instance id.
        assert_eq!(
            newer,
            TxId::new_deterministic(wallet.view_key.as_bytes(), &a.output_hash())
        );

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 30, None).expect("rollback");
        tx.commit().expect("commit");
        let re_mined = block_with_hash(31, hash(99), vec![a.clone()], Vec::new());
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &[re_mined]);

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!((rows[0].tx_id, rows[1].tx_id), (older, newer));
    }

    #[test]
    fn an_output_still_unspent_in_another_block_is_not_stored_again() {
        // The scan crossed a reorg it has not rolled back: the output shows up again in another block.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(12, vec![a.clone()], Vec::new()),
        ];
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &blocks);
        process(&mut processor, &conn, wallet.account_id, &blocks);

        assert_eq!(instances(&conn, wallet.account_id, &a).len(), 1);
        assert_eq!(ledger_counts(&conn, wallet.account_id), (1, 0));
        assert_eq!(total(&conn, wallet.account_id), 10_000);
    }

    #[test]
    fn an_output_created_and_spent_in_one_block_is_debited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [block(20, vec![a.clone()], vec![a.output_hash()])];
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &blocks);
        process(&mut processor, &conn, wallet.account_id, &blocks);

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].spent_in_block_hash.as_deref(),
            Some(blocks[0].block_hash.as_slice())
        );
        let (_, status, ..) = output_row(&conn, &a.output_hash());
        assert_eq!(status, "SPENT");
        assert_eq!(ledger_counts(&conn, wallet.account_id), (1, 1));
        assert_eq!(total(&conn, wallet.account_id), 0);
    }

    #[test]
    fn a_re_created_output_spent_in_its_own_block_is_debited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(20, Vec::new(), vec![a.output_hash()]),
            block(30, vec![a.clone()], vec![a.output_hash()]),
        ];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &blocks);

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].spent_in_block_hash.as_deref(),
            Some(blocks[1].block_hash.as_slice())
        );
        assert_eq!(
            rows[1].spent_in_block_hash.as_deref(),
            Some(blocks[2].block_hash.as_slice())
        );
        for row in &rows {
            let status = db::get_output_by_id(&conn, row.id)
                .expect("row")
                .expect("exists")
                .status;
            assert_eq!(status, "SPENT");
        }
        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 2));
        assert_eq!(total(&conn, wallet.account_id), 0);
    }

    #[test]
    fn a_change_output_spent_in_the_block_it_is_mined_in_is_debited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let input = test_wallet_output(10_000, 1);
        let mut processor = processor(&wallet, true);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[block(10, vec![input.clone()], Vec::new())],
        );
        let send = record_send(&wallet, &conn, 1, &[1], Some(3));
        let change = send.change.clone().expect("change");
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[block(
                50,
                vec![change.clone()],
                vec![input.output_hash(), change.output_hash()],
            )],
        );

        let (_, status, height, ..) = output_row(&conn, &change.output_hash());
        assert_eq!((status.as_str(), height), ("SPENT", 50));
        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 2));
        assert_eq!(total(&conn, wallet.account_id), 0);
    }

    #[test]
    fn a_scan_without_inputs_stores_a_re_created_output() {
        // Without inputs the earlier copy's spend is never seen, so it still looks unspent.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let mut processor = processor(&wallet, false);
        processor.set_inputs_excluded(true);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(30, vec![a.clone()], Vec::new()),
            ],
        );

        assert_eq!(instances(&conn, wallet.account_id, &a).len(), 2);
        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 0));
    }

    #[test]
    fn a_wallet_output_listed_under_another_hash_is_ignored() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let mut listed = block(10, Vec::new(), Vec::new());
        listed.wallet_outputs = vec![(a.output_hash(), a.clone(), 0), (hash(77), a.clone(), 0)];
        process(&mut processor(&wallet, false), &conn, wallet.account_id, &[listed]);

        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outputs WHERE account_id = :account_id",
                named_params! { ":account_id": wallet.account_id },
                |row| row.get(0),
            )
            .expect("rows");
        assert_eq!(rows, 1);
        assert_eq!(instances(&conn, wallet.account_id, &a).len(), 1);
        assert_eq!(ledger_counts(&conn, wallet.account_id), (1, 0));
    }

    #[test]
    fn backfill_does_not_store_a_copy_of_an_output_fast_sync_holds_in_another_block() {
        // A reorg between fast sync and backfill moved the output to another block at the same height.
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let mut fast_sync = processor(&wallet, false);
        fast_sync.set_inputs_excluded(true);
        process(
            &mut fast_sync,
            &conn,
            wallet.account_id,
            &[block(20, vec![a.clone()], Vec::new())],
        );
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            &[block_with_hash(20, hash(99), vec![a.clone()], Vec::new())],
        );
        db::resolve_spent_unconfirmed_with_newer_copy(&conn, wallet.account_id, false).expect("resolve");

        assert_eq!(instances(&conn, wallet.account_id, &a).len(), 1);
        assert_eq!(ledger_counts(&conn, wallet.account_id), (1, 0));
        assert_eq!(total(&conn, wallet.account_id), 10_000);
        // Nothing is left for the node to mark unspent.
        assert!(
            db::get_unresolved_spent_unconfirmed_outputs(&conn, wallet.account_id, false)
                .expect("unresolved")
                .is_empty()
        );
    }

    #[test]
    fn an_input_never_spends_an_unmined_change_row() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let change = test_wallet_output(5_000, 7);
        db::insert_unconfirmed_change_output(&conn, wallet.account_id, &wallet.view_key, "request-1", &change)
            .expect("insert change");
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            &[block(20, Vec::new(), vec![change.output_hash()])],
        );

        assert_eq!(ledger_counts(&conn, wallet.account_id), (0, 0));
        let (_, status, ..) = output_row(&conn, &change.output_hash());
        assert_eq!(status, "UNCONFIRMED");
    }

    #[test]
    fn a_sends_input_is_the_copy_it_locked_even_after_the_hash_is_re_created() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let mut processor = processor(&wallet, false);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new())],
        );
        let locked = instances(&conn, wallet.account_id, &a)[0].id;
        db::lock_output(&conn, locked, "send-1", Utc::now()).expect("lock");
        let spend = block(20, Vec::new(), vec![a.output_hash()]);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[spend.clone(), block(30, vec![a.clone()], Vec::new())],
        );

        assert_eq!(
            db::get_output_spend(&conn, wallet.account_id, "send-1", &a.output_hash()).expect("spend"),
            Some((20, spend.block_hash.to_vec()))
        );
        // Without a send that locked it, the newest copy (unspent) counts.
        assert_eq!(
            db::get_output_spend(&conn, wallet.account_id, "other", &a.output_hash()).expect("spend"),
            None
        );
    }

    fn displayed(conn: &Connection, id: TxId) -> DisplayedTransaction {
        db::get_displayed_transaction_by_id(conn, &id.to_string())
            .expect("displayed")
            .expect("exists")
    }

    #[test]
    fn a_backfilled_spend_of_an_older_copy_leaves_the_newer_copys_entry() {
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
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(20, Vec::new(), vec![a.output_hash()]),
            ],
        );

        let rows = instances(&conn, wallet.account_id, &a);
        let newer = displayed(&conn, rows[1].tx_id);
        assert_eq!(newer.blockchain.block_height, 30);
        assert_eq!(newer.details.total_credit.as_u64(), 10_000);
        assert!(newer.details.inputs.is_empty());
        // The spend is the older copy's. Its entry takes that copy's id, as every unpaired spend takes its output's.
        let spend = displayed(&conn, rows[0].tx_id);
        assert_eq!(spend.blockchain.block_height, 20);
        assert_eq!(spend.details.inputs.len(), 1);
        assert_eq!(spend.details.inputs[0].matched_output_id, rows[0].id);
    }

    #[test]
    fn a_live_spend_takes_the_newer_copy_before_backfill_resolves_the_older() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        store_newer_copy_then_older(&wallet, &conn, &a);
        let live_spend = block(40, Vec::new(), vec![a.output_hash()]);
        process(
            &mut processor(&wallet, false),
            &conn,
            wallet.account_id,
            std::slice::from_ref(&live_spend),
        );

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows[0].spent_in_block_hash, None);
        assert_eq!(
            rows[1].spent_in_block_hash.as_deref(),
            Some(live_spend.block_hash.as_slice())
        );

        // Backfill then reaches the older copy's own spend.
        let mut backfill = processor(&wallet, false);
        backfill.set_backfill_mode(true);
        let old_spend = block(20, Vec::new(), vec![a.output_hash()]);
        process(
            &mut backfill,
            &conn,
            wallet.account_id,
            std::slice::from_ref(&old_spend),
        );
        db::resolve_spent_unconfirmed_with_newer_copy(&conn, wallet.account_id, false).expect("resolve");

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(
            rows[0].spent_in_block_hash.as_deref(),
            Some(old_spend.block_hash.as_slice())
        );
        for row in &rows {
            let status = db::get_output_by_id(&conn, row.id)
                .expect("row")
                .expect("exists")
                .status;
            assert_eq!(status, "SPENT");
        }
        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 2));
        assert_eq!(total(&conn, wallet.account_id), 0);
    }

    #[test]
    fn a_pending_send_whose_input_was_reorged_and_re_mined_keeps_one_entry() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        process(
            &mut processor(&wallet, true),
            &conn,
            wallet.account_id,
            &[block(10, vec![a.clone()], Vec::new())],
        );
        let receive_id = instances(&conn, wallet.account_id, &a)[0].tx_id;
        let send = record_send(&wallet, &conn, 1, &[1], Some(3));

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 10, None).expect("rollback");
        tx.commit().expect("commit");
        let change = send.change.clone().expect("change");
        process(
            &mut processor(&wallet, true),
            &conn,
            wallet.account_id,
            &[
                block_with_hash(11, hash(98), vec![a.clone()], Vec::new()),
                block(12, vec![change], vec![a.output_hash()]),
            ],
        );

        let at_12 = displays_at(&conn, wallet.account_id, 12);
        assert_eq!(at_12.len(), 1);
        assert_eq!(at_12[0].id, send.tx_id);
        let receive = displayed(&conn, receive_id);
        assert_eq!(receive.blockchain.block_height, 11);
        assert_ne!(receive.status, TransactionDisplayStatus::Reorganized);
        assert!(receive.details.inputs.is_empty());
    }

    #[test]
    fn a_rescan_after_a_reorg_below_two_copies_restores_each_copys_entry() {
        let wallet = test_wallet();
        let mut conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        // Without inputs both copies are stored though the first one's spend is not seen.
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(30, vec![a.clone()], Vec::new()),
        ];
        let scan = || {
            let mut processor = processor(&wallet, false);
            processor.set_inputs_excluded(true);
            processor
        };
        process(&mut scan(), &conn, wallet.account_id, &blocks);
        let ids: Vec<TxId> = instances(&conn, wallet.account_id, &a)
            .iter()
            .map(|r| r.tx_id)
            .collect();

        let tx = conn.transaction().expect("tx");
        crate::scan::reorg::rollback_from_height(&tx, wallet.account_id, 5, None).expect("rollback");
        tx.commit().expect("commit");
        process(&mut scan(), &conn, wallet.account_id, &blocks);

        for (id, height) in ids.into_iter().zip([10, 30]) {
            let entry = displayed(&conn, id);
            assert_eq!(entry.blockchain.block_height, height);
            assert_ne!(entry.status, TransactionDisplayStatus::Reorganized);
        }
    }

    #[test]
    fn a_zero_conf_spend_listed_before_its_output_in_a_split_block_is_debited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        // The node split block 30; the result with the input is handled first.
        let results = [
            block(30, Vec::new(), vec![a.output_hash()]),
            block(30, vec![a.clone()], Vec::new()),
        ];
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &results);

        let check = |conn: &Connection| {
            let rows = instances(conn, wallet.account_id, &a);
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].spent_in_block_hash.as_deref(),
                Some(results[0].block_hash.as_slice())
            );
            let (_, status, ..) = output_row(conn, &a.output_hash());
            assert_eq!(status, "SPENT");
            assert_eq!(ledger_counts(conn, wallet.account_id), (1, 1));
            assert_eq!(total(conn, wallet.account_id), 0);
        };
        check(&conn);
        // Re-reading both results changes nothing.
        process(&mut processor, &conn, wallet.account_id, &results);
        check(&conn);
    }

    #[test]
    fn a_re_created_output_zero_conf_spent_before_its_output_in_a_split_block_is_debited() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let blocks = [
            block(10, vec![a.clone()], Vec::new()),
            block(20, Vec::new(), vec![a.output_hash()]),
            block(30, Vec::new(), vec![a.output_hash()]),
            block(30, vec![a.clone()], Vec::new()),
        ];
        let mut processor = processor(&wallet, false);
        process(&mut processor, &conn, wallet.account_id, &blocks);
        process(&mut processor, &conn, wallet.account_id, &blocks[2..]);

        let rows = instances(&conn, wallet.account_id, &a);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].spent_in_block_hash.as_deref(),
            Some(blocks[1].block_hash.as_slice())
        );
        assert_eq!(
            rows[1].spent_in_block_hash.as_deref(),
            Some(blocks[2].block_hash.as_slice())
        );
        for row in &rows {
            let status = db::get_output_by_id(&conn, row.id)
                .expect("row")
                .expect("exists")
                .status;
            assert_eq!(status, "SPENT");
        }
        assert_eq!(ledger_counts(&conn, wallet.account_id), (2, 2));
        assert_eq!(total(&conn, wallet.account_id), 0);
    }

    #[test]
    fn another_accounts_result_does_not_drop_a_pending_zero_conf_input() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let other = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "other", &other, "password").unwrap();
        let other_id = get_account_by_name(&conn, "other").unwrap().unwrap().id;
        let mut processor = BlockProcessor::new(
            vec![
                (wallet.account_id, wallet.view_key.clone()),
                (other_id, wallet.view_key.clone()),
            ],
            3,
        );
        let a = test_wallet_output(10_000, 1);
        let input = block(30, Vec::new(), vec![a.output_hash()]);
        let output = block(30, vec![a.clone()], Vec::new());

        processor
            .process_block(&conn, &input, wallet.account_id)
            .expect("input");
        processor
            .process_block(&conn, &block(30, Vec::new(), Vec::new()), other_id)
            .expect("other account");
        processor
            .process_block(&conn, &output, wallet.account_id)
            .expect("output");

        let (_, status, ..) = output_row(&conn, &a.output_hash());
        assert_eq!(status, "SPENT");
        assert_eq!(ledger_counts(&conn, wallet.account_id), (1, 1));
    }

    #[test]
    fn an_unmatched_input_is_warned_about_once_across_re_reads() {
        let wallet = test_wallet();
        let conn = wallet.pool.get().expect("conn");
        let a = test_wallet_output(10_000, 1);
        let relisted = block(21, Vec::new(), vec![a.output_hash()]);
        let mut processor = processor(&wallet, false);
        process(
            &mut processor,
            &conn,
            wallet.account_id,
            &[
                block(10, vec![a.clone()], Vec::new()),
                block(20, Vec::new(), vec![a.output_hash()]),
                relisted.clone(),
            ],
        );
        assert_eq!(
            processor.unmatched_input_warning(wallet.account_id, &a.output_hash()),
            Some(None)
        );

        // The continuous scan re-reads the tip in the next batch: nothing is due to be warned about again.
        processor
            .process_block(&conn, &relisted, wallet.account_id)
            .expect("re-read");
        assert_eq!(
            processor.unmatched_input_warning(wallet.account_id, &a.output_hash()),
            Some(None)
        );
        assert_eq!(ledger_counts(&conn, wallet.account_id), (1, 1));
    }
}
