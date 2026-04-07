use log::{debug, info, warn};
use minotari_scanning::{HttpBlockchainScanner, ScanConfig, scanning::BlockchainScanner};
use std::{collections::VecDeque, sync::Arc};
use tari_common_types::{seeds::cipher_seed::BIRTHDAY_GENESIS_FROM_UNIX_EPOCH, types::PrivateKey};
use tari_transaction_components::key_manager::KeyManager;
use tokio_util::sync::CancellationToken;

use crate::{
    PauseReason, ScanStatusEvent,
    db::{AccountRow, SqlitePool},
    http::WalletHttpClient,
    models::{OutputStatus, WalletEvent},
    scan::{
        DisplayedTransactionsEvent, ReorgDetectedEvent, ScanError, ScanMode, ScanRetryConfig, TransactionsUpdatedEvent,
        block_processor::BlockProcessor,
        config::{MAX_BACKOFF_EXPONENT, MAX_BACKOFF_SECONDS, OPTIMAL_SCANNING_THREADS},
        events::{EventSender, FastSyncPhase, ProcessingEvent},
        reorg,
        scan_db_handler::ScanDbHandler,
        scanner_state_manager::ScannerStateManager,
    },
    transactions::{MonitoringResult, MonitoringState, TransactionMonitor},
    webhooks::WebhookTriggerConfig,
};
use tari_transaction_components::key_manager::TransactionKeyManagerInterface;
use tari_utilities::hex::Hex;

const MAX_CONTINUOUS_BUFFERED_EVENTS: usize = 10_000;

/// Represents an account that is part of the current global scan session.
/// This is an internal state object and should not be exposed publicly.
pub(crate) struct AccountSyncTarget {
    pub(crate) account: AccountRow,
    pub(crate) key_manager: KeyManager,
    pub(crate) view_key: PrivateKey,
    pub(crate) next_block_to_scan: u64,
    pub(crate) transaction_monitor: TransactionMonitor,
}

pub struct ScanCoordinator<E: EventSender> {
    pool: SqlitePool,
    base_url: String,
    client: WalletHttpClient,
    event_sender: E,
    retry_config: ScanRetryConfig,
    required_confirmations: u64,
    webhook_config: Option<WebhookTriggerConfig>,
    processing_threads: usize,
    reorg_check_interval: u64,
    batch_size: u64,
}

impl<E: EventSender + Clone + Send + 'static> ScanCoordinator<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: SqlitePool,
        base_url: String,
        event_sender: E,
        retry_config: ScanRetryConfig,
        required_confirmations: u64,
        webhook_config: Option<WebhookTriggerConfig>,
        processing_threads: usize,
        reorg_check_interval: u64,
        batch_size: u64,
    ) -> Result<Self, ScanError> {
        let client = WalletHttpClient::new(
            base_url
                .parse()
                .map_err(|e| ScanError::Fatal(anyhow::anyhow!("Invalid Base URL: {}", e)))?,
        )
        .map_err(ScanError::Fatal)?;
        Ok(Self {
            pool,
            base_url,
            client,
            event_sender,
            retry_config,
            required_confirmations,
            webhook_config,
            processing_threads,
            reorg_check_interval,
            batch_size,
        })
    }

    /// The main entry point for the multi-account scan.
    pub async fn run(
        &self,
        accounts: Vec<AccountRow>,
        password: &str,
        mode: ScanMode,
        scanning_offset: u64,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        if accounts.is_empty() {
            return Ok((Vec::new(), false));
        }

        let mut conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;

        let first_km = accounts
            .first()
            .expect("is already checked")
            .get_key_manager(password)?;
        let mut shared_reorg_scanner = self.create_reorg_scanner(first_km).await?;

        let mut sync_targets = Vec::with_capacity(accounts.len());

        for account in accounts {
            let target = self
                .prepare_target(
                    account,
                    password,
                    &self.client,
                    scanning_offset,
                    &mut conn,
                    &mut shared_reorg_scanner,
                )
                .await?;
            sync_targets.push(target);
        }

        match mode {
            ScanMode::FastSync { safety_buffer } => self.run_fast_sync(sync_targets, safety_buffer, cancel_token).await,
            _ => self.unified_scan_loop(sync_targets, mode, cancel_token).await,
        }
    }

    /// Prepares a scan context for an account.
    async fn prepare_target(
        &self,
        account: AccountRow,
        password: &str,
        wallet_client: &WalletHttpClient,
        scanning_offset: u64,
        conn: &mut rusqlite::Connection,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
    ) -> Result<AccountSyncTarget, ScanError> {
        let key_manager = account.get_key_manager(password)?;
        let view_key = key_manager.get_private_view_key();
        let reorg_result = reorg::handle_reorgs(scanner, conn, account.id, self.webhook_config.clone())
            .await
            .map_err(ScanError::Fatal)?;

        let mut next_block = reorg_result.resume_height;

        if next_block == 0 {
            // Use birthday logic
            let timestamp = (account.birthday as u64).saturating_sub(scanning_offset) * 24 * 60 * 60
                + BIRTHDAY_GENESIS_FROM_UNIX_EPOCH;
            next_block = wallet_client
                .get_height_at_time(timestamp)
                .await
                .map_err(ScanError::Fatal)?;
        }

        let monitor_state = MonitoringState::new();
        monitor_state.initialize(conn, account.id).map_err(ScanError::Fatal)?;

        let transaction_monitor =
            TransactionMonitor::new(monitor_state, self.required_confirmations, self.webhook_config.clone());

        Ok(AccountSyncTarget {
            account,
            key_manager,
            view_key,
            next_block_to_scan: next_block,
            transaction_monitor,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn unified_scan_loop(
        &self,
        mut targets: Vec<AccountSyncTarget>,
        mode: ScanMode,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut all_events = VecDeque::new();
        let max_buffered_events = match mode {
            ScanMode::Continuous { .. } => Some(MAX_CONTINUOUS_BUFFERED_EVENTS),
            _ => None,
        };
        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            self.event_sender.clone(),
            false,
            self.required_confirmations,
        );
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);
        let mut total_scanned_globally = 0;
        let mut blocks_since_reorg_check = 0;

        let mut state_manager = ScannerStateManager::new();
        loop {
            if let Some(token) = &cancel_token
                && token.is_cancelled()
            {
                return self.handle_pause(&targets, PauseReason::Cancelled, all_events);
            }

            let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);

            // Determine which accounts are active at this height
            let active_account_ids: Vec<i64> = targets
                .iter()
                .filter(|target| target.next_block_to_scan == global_next_block)
                .map(|target| target.account.id)
                .collect();

            let next_horizon_height = targets
                .iter()
                .map(|t| t.next_block_to_scan)
                .filter(|&h| h > global_next_block)
                .min();

            let mut end_height = next_horizon_height.map(|h| h.saturating_sub(1));
            if let ScanMode::Partial { max_blocks } = mode {
                let max_height_to_scan = global_next_block
                    .saturating_add(max_blocks)
                    .saturating_sub(total_scanned_globally);
                end_height = match end_height {
                    Some(h) => Some(h.min(max_height_to_scan)),
                    None => Some(max_height_to_scan),
                };
            }

            let effective_batch_size = next_horizon_height
                .map(|h| h.saturating_sub(global_next_block).min(self.batch_size))
                .unwrap_or(self.batch_size);

            let (scanner, scanner_config) = state_manager
                .get_scanner_and_config(
                    &active_account_ids,
                    global_next_block,
                    end_height,
                    effective_batch_size,
                    &targets,
                    &self.base_url,
                    self.processing_threads,
                    &self.retry_config,
                )
                .await?;
            let mut utxo_stream = scanner
                .scan_blocks(&scanner_config)
                .await
                .map_err(|e| ScanError::Intermittent(e.to_string()))?;
            let mut is_batch_empty = false;
            let mut max_new_height_in_batch = 0;
            while let Some(response) = utxo_stream.recv().await {
                let scanned_blocks = response.map_err(|e| ScanError::Intermittent(e.to_string()))?;
                let new_blocks_count = scanned_blocks.len() as u64;
                is_batch_empty = scanned_blocks.is_empty();
                // Go on, if we stopped on artificial horizon
                if is_batch_empty {
                    break;
                }

                for account_id in &active_account_ids {
                    self.event_sender
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::MoreBlocksAvailable {
                            account_id: *account_id,
                            last_scanned_height: global_next_block.saturating_sub(1),
                        }));
                }

                max_new_height_in_batch = global_next_block;

                let shared_blocks = Arc::new(scanned_blocks);

                for account_id in &active_account_ids {
                    let Some(target) = targets.iter_mut().find(|target| target.account.id == *account_id) else {
                        return Err(ScanError::Fatal(anyhow::anyhow!(
                            "Unknown active account id: {}",
                            account_id
                        )));
                    };

                    let events = db_handler
                        .process_blocks(
                            shared_blocks.clone(),
                            *account_id,
                            target.transaction_monitor.has_pending_outbound(),
                            self.webhook_config.clone(),
                            target.next_block_to_scan,
                        )
                        .await?;
                    Self::push_events_with_limit(&mut all_events, events, max_buffered_events);
                    if let Some(last) = shared_blocks.last() {
                        target.next_block_to_scan = last.height + 1;
                    }
                    if let Some(last) = shared_blocks.last()
                        && last.height >= target.next_block_to_scan
                    {
                        if last.height > max_new_height_in_batch {
                            max_new_height_in_batch = last.height;
                        }

                        let monitor_res = target
                            .transaction_monitor
                            .monitor_if_needed(&self.client, &self.pool, target.account.id, last.height)
                            .await
                            .map_err(ScanError::Fatal)?;

                        Self::push_events_with_limit(
                            &mut all_events,
                            monitor_res.wallet_events.clone(),
                            max_buffered_events,
                        );
                        self.emit_monitor_events(target.account.id, last.height, monitor_res);

                        db_handler.prune_tips(target.account.id, last.height).await?;

                        self.event_sender
                            .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                                account_id: target.account.id,
                                current_height: last.height,
                                blocks_scanned: total_scanned_globally,
                            }));
                    }
                }

                blocks_since_reorg_check += new_blocks_count;
                total_scanned_globally += new_blocks_count;

                if blocks_since_reorg_check >= self.reorg_check_interval {
                    self.check_global_reorgs(&mut targets, &db_handler, scanner).await?;
                    blocks_since_reorg_check = 0;
                }
            }
            if let ScanMode::Partial { max_blocks } = mode
                && total_scanned_globally >= max_blocks
            {
                info!(last_scanned_block = max_new_height_in_batch; "Scan completed successfully up to stop height");
                return self.handle_pause(
                    &targets,
                    PauseReason::MaxBlocksReached { limit: max_blocks },
                    all_events,
                );
            }
            if is_batch_empty {
                for account_id in &active_account_ids {
                    let Some(target) = targets.iter().find(|target| target.account.id == *account_id) else {
                        return Err(ScanError::Fatal(anyhow::anyhow!(
                            "Unknown active account id: {}",
                            account_id
                        )));
                    };
                    self.event_sender
                        .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Completed {
                            account_id: target.account.id,
                            final_height: target.next_block_to_scan.saturating_sub(1),
                            total_blocks_scanned: total_scanned_globally,
                        }));
                }

                if let ScanMode::Continuous { poll_interval } = mode {
                    self.wait_for_next_poll_cycle(&mut targets, &db_handler, poll_interval, &cancel_token, scanner)
                        .await?;
                    continue;
                }

                return Ok((all_events.into_iter().collect(), false));
            }
        }
    }

    fn push_events_with_limit(
        all_events: &mut VecDeque<WalletEvent>,
        events: Vec<WalletEvent>,
        max_buffered_events: Option<usize>,
    ) {
        all_events.extend(events);
        if let Some(limit) = max_buffered_events {
            while all_events.len() > limit {
                all_events.pop_front();
            }
        }
    }

    async fn check_global_reorgs(
        &self,
        targets: &mut [AccountSyncTarget],
        db_handler: &ScanDbHandler<E>,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
    ) -> Result<(), ScanError> {
        if targets.is_empty() {
            return Ok(());
        }

        let mut conn = db_handler.get_connection().await?;
        for target in targets {
            let res = reorg::handle_reorgs(scanner, &mut conn, target.account.id, self.webhook_config.clone())
                .await
                .map_err(ScanError::Fatal)?;

            if let Some(info) = res.reorg_information {
                self.emit_reorg_event(target.account.id, info, res.resume_height);
                target.next_block_to_scan = res.resume_height;
            }
        }
        Ok(())
    }

    async fn wait_for_next_poll_cycle(
        &self,
        targets: &mut [AccountSyncTarget],
        db_handler: &ScanDbHandler<E>,
        interval: std::time::Duration,
        cancel: &Option<CancellationToken>,
        scanner: &mut HttpBlockchainScanner<KeyManager>,
    ) -> Result<(), ScanError> {
        for target in targets.iter_mut() {
            target.next_block_to_scan = target.next_block_to_scan.saturating_sub(1);

            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Waiting {
                    account_id: target.account.id,
                    resume_in: interval,
                }));
        }

        if let Some(token) = cancel {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = token.cancelled() => return Ok(()),
            }
        } else {
            tokio::time::sleep(interval).await;
        }

        self.check_global_reorgs(targets, db_handler, scanner).await
    }

    fn handle_pause(
        &self,
        targets: &[AccountSyncTarget],
        reason: PauseReason,
        events: VecDeque<WalletEvent>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        for t in targets {
            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Paused {
                    account_id: t.account.id,
                    last_scanned_height: t.next_block_to_scan.saturating_sub(1),
                    reason: reason.clone(),
                }));
        }
        Ok((events.into_iter().collect(), true))
    }

    fn emit_monitor_events(&self, account_id: i64, height: u64, res: MonitoringResult) {
        if !res.updated_displayed_transactions.is_empty() {
            self.event_sender
                .send(ProcessingEvent::TransactionsUpdated(TransactionsUpdatedEvent {
                    account_id,
                    updated_transactions: res.updated_displayed_transactions.clone(),
                }));
            self.event_sender
                .send(ProcessingEvent::TransactionsReady(DisplayedTransactionsEvent {
                    account_id,
                    transactions: res.updated_displayed_transactions,
                    block_height: Some(height),
                    is_initial_sync: false,
                }));
        }
    }

    fn emit_reorg_event(&self, account_id: i64, reorg_info: reorg::ReorgInformation, resume_height: u64) {
        self.event_sender
            .send(ProcessingEvent::ReorgDetected(ReorgDetectedEvent {
                account_id,
                reorg_from_height: reorg_info.rolled_back_from_height,
                new_height: resume_height,
                blocks_rolled_back: reorg_info.rolled_back_blocks_count,
                invalidated_output_hashes: reorg_info.invalidated_output_hashes,
                cancelled_transaction_ids: reorg_info.cancelled_transaction_ids,
                reorganized_displayed_transactions: reorg_info.reorganized_displayed_transactions,
            }));
    }

    /// Runs the three-phase fast sync strategy.
    #[allow(clippy::too_many_lines)]
    async fn run_fast_sync(
        &self,
        mut targets: Vec<AccountSyncTarget>,
        safety_buffer: u64,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut all_events = Vec::new();

        // Get chain tip to compute fast_sync_target
        let tip_response = self.client.get_tip_info().await.map_err(ScanError::Fatal)?;
        let tip_height = tip_response
            .metadata
            .as_ref()
            .map(|m| m.best_block_height())
            .unwrap_or(0);
        let fast_sync_target = tip_height.saturating_sub(safety_buffer);

        info!(
            tip = tip_height,
            fast_sync_target = fast_sync_target,
            safety_buffer = safety_buffer;
            "Starting fast sync"
        );

        // --- Phase 1: Fast UTXO scan (birthday -> fast_sync_target, exclude_spent=true) ---
        for target in &targets {
            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::FastUtxoScan,
                    from_height: target.next_block_to_scan,
                    to_height: Some(fast_sync_target),
                }));
        }

        let (events, _) = self
            .fast_sync_loop(&mut targets, fast_sync_target, &cancel_token)
            .await?;
        all_events.extend(events);

        for target in &targets {
            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseCompleted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::FastUtxoScan,
                }));
        }

        // Check cancellation between phases
        if let Some(token) = &cancel_token
            && token.is_cancelled()
        {
            return Ok((all_events, true));
        }

        // --- Phase 2: Recent full scan (fast_sync_target -> tip) ---
        // Targets already have next_block_to_scan set to fast_sync_target + 1
        // from Phase 1, so no reset needed.
        for target in &targets {
            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::RecentFullScan,
                    from_height: fast_sync_target,
                    to_height: None,
                }));
        }

        // Phase 2 uses the same simple loop pattern as fast_sync_loop but without
        // exclude_spent, effectively doing a full scan of recent blocks.
        let (events, _) = self.recent_full_scan_loop(&mut targets, &cancel_token).await?;
        all_events.extend(events);

        for target in &targets {
            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseCompleted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::RecentFullScan,
                }));
        }

        info!("Fast sync completed (wallet is now usable; run backfill separately for full history)");
        Ok((all_events, false))
    }

    /// Runs the history backfill phase separately.
    ///
    /// Scans from each account's birthday to `backfill_to_height` with full block
    /// processing (outputs + inputs) using backfill mode (OR IGNORE for duplicates,
    /// SpentUnconfirmed status for new outputs). After scanning, resolves
    /// SpentUnconfirmed outputs by checking inputs and verifying against the base node.
    pub async fn run_backfill(
        &self,
        accounts: Vec<AccountRow>,
        password: &str,
        backfill_to_height: u64,
        scanning_offset: u64,
        cancel_token: Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        if accounts.is_empty() {
            return Ok((Vec::new(), false));
        }

        let mut conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;

        let first_km = accounts
            .first()
            .expect("is already checked")
            .get_key_manager(password)?;
        let mut shared_reorg_scanner = self.create_reorg_scanner(first_km).await?;

        let mut targets = Vec::with_capacity(accounts.len());
        for account in accounts {
            let target = self
                .prepare_target(
                    account,
                    password,
                    &self.client,
                    scanning_offset,
                    &mut conn,
                    &mut shared_reorg_scanner,
                )
                .await?;
            targets.push(target);
        }

        let mut all_events = Vec::new();

        for target in &targets {
            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseStarted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::HistoryBackfill,
                    from_height: target.next_block_to_scan,
                    to_height: Some(backfill_to_height),
                }));
        }

        let (events, _) = self
            .backfill_loop(&mut targets, backfill_to_height, &cancel_token)
            .await?;
        all_events.extend(events);

        // Resolve SpentUnconfirmed outputs:
        // 1. Mark outputs with matching inputs as Spent
        // 2. Verify remaining outputs against the base node
        let conn = self.pool.get().map_err(|e| ScanError::DbError(e.into()))?;
        for target in &targets {
            let marked_spent = crate::db::resolve_spent_unconfirmed_with_inputs(&conn, target.account.id)
                .map_err(ScanError::DbError)?;
            info!(
                account_id = target.account.id,
                marked_spent = marked_spent;
                "Resolved SpentUnconfirmed outputs with matching inputs"
            );

            let unresolved = crate::db::get_unresolved_spent_unconfirmed_outputs(&conn, target.account.id)
                .map_err(ScanError::DbError)?;

            if !unresolved.is_empty() {
                info!(
                    account_id = target.account.id,
                    count = unresolved.len();
                    "Verifying remaining SpentUnconfirmed outputs against base node"
                );
                self.verify_spent_unconfirmed_outputs(&conn, target, &unresolved)
                    .await?;
            }

            self.event_sender
                .send(ProcessingEvent::ScanStatus(ScanStatusEvent::FastSyncPhaseCompleted {
                    account_id: target.account.id,
                    phase: FastSyncPhase::HistoryBackfill,
                }));
        }

        info!("History backfill completed");
        Ok((all_events, false))
    }

    /// Phase 1: Fast sync loop scanning only unspent outputs.
    async fn fast_sync_loop(
        &self,
        targets: &mut [AccountSyncTarget],
        end_height: u64,
        cancel_token: &Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut all_events = Vec::new();
        let mut state_manager = ScannerStateManager::new();
        let mut total_scanned = 0u64;

        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            self.event_sender.clone(),
            false,
            self.required_confirmations,
        );
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);

        loop {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                break;
            }

            let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);
            if global_next_block > end_height {
                break;
            }

            let active_account_ids: Vec<i64> = targets
                .iter()
                .filter(|t| t.next_block_to_scan <= end_height)
                .map(|t| t.account.id)
                .collect();

            if active_account_ids.is_empty() {
                break;
            }

            let (scanner, mut scanner_config) = state_manager
                .get_scanner_and_config(
                    &active_account_ids,
                    global_next_block,
                    Some(end_height),
                    self.batch_size,
                    targets,
                    &self.base_url,
                    self.processing_threads,
                )
                .await?;

            // Set exclude_spent and exclude_inputs for fast sync
            scanner_config.exclude_spent = true;
            scanner_config.exclude_inputs = true;

            let (scanned_blocks, _more) = self.scan_blocks_with_timeout(scanner, &scanner_config).await?;
            let is_empty = scanned_blocks.is_empty();
            total_scanned += scanned_blocks.len() as u64;

            if !is_empty {
                let shared_blocks = Arc::new(scanned_blocks);

                for account_id in &active_account_ids {
                    let Some(target) = targets.iter_mut().find(|t| t.account.id == *account_id) else {
                        continue;
                    };

                    let events = db_handler
                        .process_blocks(
                            shared_blocks.clone(),
                            *account_id,
                            false,
                            self.webhook_config.clone(),
                            target.next_block_to_scan,
                        )
                        .await?;
                    all_events.extend(events);

                    if let Some(last) = shared_blocks.last() {
                        target.next_block_to_scan = last.height + 1;

                        self.event_sender
                            .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                                account_id: target.account.id,
                                current_height: last.height,
                                blocks_scanned: total_scanned,
                            }));
                    }
                }
            }

            if is_empty {
                break;
            }
        }

        Ok((all_events, false))
    }

    /// Phase 2: Full scan of recent blocks from fast_sync_target to tip.
    async fn recent_full_scan_loop(
        &self,
        targets: &mut [AccountSyncTarget],
        cancel_token: &Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut all_events = Vec::new();
        let mut state_manager = ScannerStateManager::new();
        let mut total_scanned = 0u64;

        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            self.event_sender.clone(),
            false,
            self.required_confirmations,
        );
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);

        loop {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                break;
            }

            let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);

            let active_account_ids: Vec<i64> = targets.iter().map(|t| t.account.id).collect();

            let (scanner, scanner_config) = state_manager
                .get_scanner_and_config(
                    &active_account_ids,
                    global_next_block,
                    None, // scan to tip
                    self.batch_size,
                    targets,
                    &self.base_url,
                    self.processing_threads,
                )
                .await?;

            let (scanned_blocks, more_blocks) = self.scan_blocks_with_timeout(scanner, &scanner_config).await?;
            let is_empty = scanned_blocks.is_empty();
            total_scanned += scanned_blocks.len() as u64;

            if !is_empty {
                let shared_blocks = Arc::new(scanned_blocks);

                for account_id in &active_account_ids {
                    let Some(target) = targets.iter_mut().find(|t| t.account.id == *account_id) else {
                        continue;
                    };

                    let events = db_handler
                        .process_blocks(
                            shared_blocks.clone(),
                            *account_id,
                            target.transaction_monitor.has_pending_outbound(),
                            self.webhook_config.clone(),
                            target.next_block_to_scan,
                        )
                        .await?;
                    all_events.extend(events);

                    if let Some(last) = shared_blocks.last() {
                        target.next_block_to_scan = last.height + 1;

                        let monitor_res = target
                            .transaction_monitor
                            .monitor_if_needed(&self.client, &self.pool, target.account.id, last.height)
                            .await
                            .map_err(ScanError::Fatal)?;

                        all_events.extend(monitor_res.wallet_events.clone());
                        self.emit_monitor_events(target.account.id, last.height, monitor_res);

                        self.event_sender
                            .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                                account_id: target.account.id,
                                current_height: last.height,
                                blocks_scanned: total_scanned,
                            }));
                    }
                }
            }

            if is_empty || !more_blocks {
                break;
            }
        }

        Ok((all_events, false))
    }

    /// Phase 3: Backfill loop scanning full blocks with OR IGNORE for existing data.
    async fn backfill_loop(
        &self,
        targets: &mut [AccountSyncTarget],
        end_height: u64,
        cancel_token: &Option<CancellationToken>,
    ) -> Result<(Vec<WalletEvent>, bool), ScanError> {
        let mut all_events = Vec::new();
        let mut state_manager = ScannerStateManager::new();
        let mut total_scanned = 0u64;

        let all_accounts: Vec<(i64, PrivateKey)> = targets
            .iter()
            .map(|target| (target.account.id, target.view_key.clone()))
            .collect();
        let mut block_processor = BlockProcessor::with_event_sender(
            all_accounts,
            self.event_sender.clone(),
            false,
            self.required_confirmations,
        );
        block_processor.set_backfill_mode(true);
        let mut db_handler = ScanDbHandler::new(self.pool.clone(), block_processor);

        loop {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                break;
            }

            let global_next_block = targets.iter().map(|t| t.next_block_to_scan).min().unwrap_or(0);
            if global_next_block > end_height {
                break;
            }

            let active_account_ids: Vec<i64> = targets
                .iter()
                .filter(|t| t.next_block_to_scan <= end_height)
                .map(|t| t.account.id)
                .collect();

            if active_account_ids.is_empty() {
                break;
            }

            let (scanner, scanner_config) = state_manager
                .get_scanner_and_config(
                    &active_account_ids,
                    global_next_block,
                    Some(end_height),
                    self.batch_size,
                    targets,
                    &self.base_url,
                    self.processing_threads,
                )
                .await?;

            let (scanned_blocks, _more) = self.scan_blocks_with_timeout(scanner, &scanner_config).await?;
            let is_empty = scanned_blocks.is_empty();
            total_scanned += scanned_blocks.len() as u64;

            if !is_empty {
                let shared_blocks = Arc::new(scanned_blocks);

                for account_id in &active_account_ids {
                    let Some(target) = targets.iter_mut().find(|t| t.account.id == *account_id) else {
                        continue;
                    };

                    let events = db_handler
                        .process_blocks(
                            shared_blocks.clone(),
                            *account_id,
                            false,
                            self.webhook_config.clone(),
                            target.next_block_to_scan,
                        )
                        .await?;
                    all_events.extend(events);

                    if let Some(last) = shared_blocks.last() {
                        target.next_block_to_scan = last.height + 1;

                        self.event_sender
                            .send(ProcessingEvent::ScanStatus(ScanStatusEvent::Progress {
                                account_id: target.account.id,
                                current_height: last.height,
                                blocks_scanned: total_scanned,
                            }));
                    }
                }
            }

            if is_empty {
                break;
            }
        }

        Ok((all_events, false))
    }

    /// Verifies remaining SpentUnconfirmed outputs against the base node using
    /// the `get_utxos_deleted_info` endpoint. If `spent_in_header` is present,
    /// the output is confirmed Spent and an input record + debit balance change
    /// are created so the balance sums correctly. Otherwise it's marked Unspent.
    async fn verify_spent_unconfirmed_outputs(
        &self,
        conn: &rusqlite::Connection,
        target: &AccountSyncTarget,
        unresolved: &[crate::db::UnresolvedSpentOutput],
    ) -> Result<(), ScanError> {
        use std::collections::HashMap;

        let hash_to_output: HashMap<Vec<u8>, &crate::db::UnresolvedSpentOutput> =
            unresolved.iter().map(|o| (o.output_hash.clone(), o)).collect();

        let all_output_hashes: Vec<Vec<u8>> = unresolved.iter().map(|o| o.output_hash.clone()).collect();

        let mut marked_unspent = 0u64;
        let mut confirmed_spent = 0u64;

        for output_hashes in all_output_hashes.chunks(50) {
            let response = self
                .client
                .get_utxos_deleted_info(output_hashes.to_vec())
                .await
                .map_err(|e| ScanError::Intermittent(format!("Failed to query UTXO deleted info: {}", e)))?;

            for utxo_info in &response.utxos {
                let Some(output) = hash_to_output.get(&utxo_info.utxo_hash) else {
                    continue;
                };

                if let Some((spent_height, spent_block_hash)) = &utxo_info.spent_in_header {
                    // Create input record so the spend is tracked in the DB
                    let input_id = crate::db::insert_input(
                        conn,
                        target.account.id,
                        output.output_id,
                        *spent_height,
                        spent_block_hash,
                        0, // timestamp not available from deleted info
                    )
                    .map_err(ScanError::DbError)?;

                    // Create debit balance change so credits - debits nets correctly
                    let change = crate::models::BalanceChange {
                        account_id: target.account.id,
                        caused_by_output_id: None,
                        caused_by_input_id: Some(input_id),
                        description: "Output spent (verified by base node)".to_string(),
                        balance_credit: 0.into(),
                        balance_debit: output.value.into(),
                        effective_date: chrono::Utc::now().naive_utc(),
                        effective_height: *spent_height,
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
                    crate::db::insert_balance_change(conn, &change).map_err(ScanError::DbError)?;

                    crate::db::update_output_status(conn, output.output_id, OutputStatus::Spent)
                        .map_err(ScanError::DbError)?;
                    confirmed_spent += 1;
                } else if utxo_info.found_in_header.is_some() {
                    crate::db::update_output_status(conn, output.output_id, OutputStatus::Unspent)
                        .map_err(ScanError::DbError)?;
                    marked_unspent += 1;
                } else {
                    debug!(
                        account = &*target.account.friendly_name,
                        output_hash = &*utxo_info.utxo_hash.to_hex();
                        "Ouput unkown by base node, status kept as SpentUnconfirmed"
                    );
                }
            }
        }

        info!(
            account_id = target.account.id,
            marked_unspent = marked_unspent,
            confirmed_spent = confirmed_spent;
            "Verified SpentUnconfirmed outputs against base node"
        );

        Ok(())
    }

    async fn create_reorg_scanner(
        &self,
        key_manager: KeyManager,
    ) -> Result<HttpBlockchainScanner<KeyManager>, ScanError> {
        HttpBlockchainScanner::new(self.base_url.clone(), vec![key_manager], OPTIMAL_SCANNING_THREADS)
            .await
            .map_err(|e| ScanError::Intermittent(e.to_string()))
    }
}
