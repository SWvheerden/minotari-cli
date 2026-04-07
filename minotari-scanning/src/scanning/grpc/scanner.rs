//! GRPC-based blockchain scanner implementation
//!
//! This module provides a GRPC implementation of the `BlockchainScanner` trait
//! that connects to a Tari base node via GRPC to scan for wallet outputs.
//!
//! ## Wallet Key Integration
//!
//! The GRPC scanner supports wallet key integration for identifying outputs that belong
//! to a specific wallet.

use std::{sync::RwLock, time::Duration};

use crate::{
    BlockHeaderInfo,
    errors::{WalletError, WalletResult},
    scanning::{BlockScanResult, InProgressScan, ScanConfig, TipInfo, interface::BlockchainScanner},
};
use async_trait::async_trait;
use minotari_app_grpc::tari_rpc;
use primitive_types::U512;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tari_common_types::types::FixedHash;
use tari_node_components::blocks::Block;
use tari_transaction_components::{
    key_manager::TransactionKeyManagerInterface,
    transaction_components::{TransactionInput, TransactionKernel, TransactionOutput, WalletOutput},
};
use tokio::sync::mpsc;
use tonic::{Request, transport::Channel};
use tracing::debug;
use tracing::log::error;
/// GRPC client for connecting to Tari base node
#[derive(Clone)]
pub struct GrpcBlockchainScanner<KM> {
    /// GRPC channel to the base node
    client: tari_rpc::base_node_client::BaseNodeClient<Channel>,
    /// Connection timeout
    timeout: Duration,
    /// key manager used for the keys
    pub key_managers: Vec<KM>,
    current_in_progress: InProgressScan,
    number_processing_threads: usize,
}

impl<KM> GrpcBlockchainScanner<KM>
where
    KM: TransactionKeyManagerInterface,
{
    /// Create a new GRPC scanner with the given base URL
    pub async fn new(base_url: String, key_managers: Vec<KM>, number_processing_threads: usize) -> WalletResult<Self> {
        let thread_count = if number_processing_threads > 0 {
            number_processing_threads
        } else {
            (num_cpus::get().saturating_sub(2)).max(1)
        };
        if key_managers.is_empty() {
            return Err(WalletError::ConfigurationError(
                "At least one key manager must be specified".to_string(),
            ));
        }
        let timeout = Duration::from_secs(30);
        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Invalid URL: {e}"
                )))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Connection failed: {e}"
                )))
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            key_managers,
            current_in_progress: InProgressScan::new_empty(),
            number_processing_threads: thread_count,
        })
    }

    /// Create a new GRPC scanner with custom timeout
    pub async fn with_timeout(
        base_url: String,
        timeout: Duration,
        key_managers: Vec<KM>,
        number_processing_threads: usize,
    ) -> WalletResult<Self> {
        let thread_count = if number_processing_threads > 0 {
            number_processing_threads
        } else {
            (num_cpus::get().saturating_sub(2)).max(1)
        };
        if key_managers.is_empty() {
            return Err(WalletError::ConfigurationError(
                "At least one key manager must be specified".to_string(),
            ));
        }

        let channel = Channel::from_shared(base_url.clone())
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Invalid URL: {e}"
                )))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "Connection failed: {e}"
                )))
            })?;

        // Set message size limits on the client to handle large blocks (16MB should be sufficient)
        let client = tari_rpc::base_node_client::BaseNodeClient::new(channel)
            .max_decoding_message_size(16 * 1024 * 1024) // 16MB
            .max_encoding_message_size(16 * 1024 * 1024); // 16MB

        Ok(Self {
            client,
            timeout,
            key_managers,
            current_in_progress: InProgressScan::new_empty(),
            number_processing_threads: thread_count,
        })
    }

    /// Create a scan config with wallet keys for block scanning
    pub const fn create_scan_config_with_wallet_keys(
        &self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> WalletResult<ScanConfig> {
        Ok(ScanConfig {
            start_height,
            end_height,
            batch_size: Some(100),
            request_timeout: self.timeout,
            exclude_spent: false,
            exclude_inputs: false,
        })
    }

    /// Scan for regular recoverable outputs using encrypted data decryption
    pub fn scan_for_recoverable_output(
        &self,
        output: &TransactionOutput,
    ) -> WalletResult<Option<(WalletOutput, usize)>> {
        for (index, key_manager) in self.key_managers.iter().enumerate() {
            if let Some((commitment_mask, value, memo)) = key_manager.try_output_key_recovery(
                &output.commitment,
                &output.encrypted_data,
                &output.sender_offset_public_key,
            )? {
                return WalletOutput::new_imported(value, commitment_mask, memo, output.clone(), key_manager)
                    .map_or_else(|_| Ok(None), |wallet_output| Ok(Some((wallet_output, index))));
            }
        }
        Ok(None)
    }

    /// Get all outputs from a specific block
    pub async fn get_outputs_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionOutput>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(tari_block.dissolve().2);
        }

        Ok(Vec::new())
    }

    /// Get all inputs from a specific block
    pub async fn get_inputs_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionInput>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(tari_block.dissolve().1);
        }

        Ok(Vec::new())
    }

    /// Get all kernels from a specific block
    pub async fn get_kernels_from_block(&mut self, block_height: u64) -> WalletResult<Vec<TransactionKernel>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(tari_block.dissolve().3);
        }

        Ok(Vec::new())
    }

    /// Get complete block data including outputs, inputs, and kernels
    pub async fn get_complete_block_data(&mut self, block_height: u64) -> WalletResult<Option<Block>> {
        // Get the block at the specified height
        let request = tari_rpc::GetBlocksRequest {
            heights: vec![block_height],
        };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        if let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "Stream error: {e}"
            )))
        })? && let Some(block) = grpc_block.block
        {
            let tari_block: Block = block.try_into()?;
            return Ok(Some(tari_block));
        }

        Ok(None)
    }

    /// Scan a single block for wallet outputs using the provided entropy
    pub async fn scan_block(&mut self, block_height: u64) -> WalletResult<Vec<(WalletOutput, usize)>> {
        let mut wallet_outputs = Vec::new();

        // Get all outputs from the block
        let outputs = self.get_outputs_from_block(block_height).await?;

        if outputs.is_empty() {
            return Ok(wallet_outputs);
        }

        // Process each output
        for output in &outputs {
            if let Some(found_wallet_outputs) = self.scan_for_recoverable_output(output)? {
                wallet_outputs.push(found_wallet_outputs);
            }
        }

        Ok(wallet_outputs)
    }

    /// Get blocks by their heights in a batch
    pub async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                blocks.push(tari_block);
            }
        }

        Ok(blocks)
    }

    /// Convert GRPC tip info to lightweight tip info
    fn convert_tip_info(grpc_tip: &tari_rpc::TipInfoResponse) -> TipInfo {
        let metadata = grpc_tip.metadata.as_ref();

        TipInfo {
            best_block_height: metadata.map_or(0, |m| m.best_block_height),
            best_block_hash: FixedHash::try_from(metadata.map(|m| m.best_block_hash.clone()).unwrap_or_default())
                .unwrap_or_default(),
            accumulated_difficulty: metadata
                .map(|m| U512::from_big_endian(&m.accumulated_difficulty).to_string())
                .unwrap_or_default(),
            pruned_height: metadata.map_or(0, |m| m.pruned_height),
            timestamp: metadata.map_or(0, |m| m.timestamp),
        }
    }

    pub async fn update_scan_config(&mut self, config: &ScanConfig) -> WalletResult<()> {
        debug!(
            "String new scan, scanning from: {} to  {:?}",
            config.start_height, config.end_height
        );
        if let Some(end_height) = config.end_height {
            let tip_info = self.get_tip_info().await?;
            if end_height > tip_info.best_block_height {
                debug!(
                    "End height is higher than current tip height, will only scan to tip {:?}",
                    tip_info.best_block_height
                );
            }
            let adjusted_config = ScanConfig {
                start_height: config.start_height,
                end_height: None,
                batch_size: config.batch_size,
                request_timeout: config.request_timeout,
                exclude_spent: config.exclude_spent,
                exclude_inputs: config.exclude_inputs,
            };
            self.current_in_progress = InProgressScan::new(adjusted_config);
            return Ok(());
        }
        self.current_in_progress = InProgressScan::new(config.clone());
        Ok(())
    }

    pub fn clear_in_progress_scan(&mut self) {
        self.current_in_progress.clear();
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl<KM> BlockchainScanner for GrpcBlockchainScanner<KM>
where
    KM: TransactionKeyManagerInterface,
{
    async fn scan_blocks(
        &mut self,
        config: &ScanConfig,
    ) -> WalletResult<mpsc::Receiver<WalletResult<Vec<BlockScanResult>>>> {
        if let Some(end_height) = config.end_height
            && config.start_height > end_height
        {
            return Err(WalletError::OperationNotSupported(
                "start_height cannot be greater than end_height".to_string(),
            ));
        }

        let (send_scan_result, rec_scan_result) = mpsc::channel(1000);
        self.update_scan_config(config).await?;
        let download_scanner = self.clone();
        let tip_info = self.get_tip_info().await?;
        let end_height = std::cmp::min(
            config.end_height.unwrap_or(tip_info.best_block_height),
            tip_info.best_block_height,
        );
        let heights: Vec<u64> = (config.start_height..=end_height).collect();
        let request = tari_rpc::GetBlocksRequest { heights };
        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.number_processing_threads)
            .build()
            .map_err(|e| WalletError::ConfigurationError(format!("Failed to build thread pool: {e}")))?;
        tokio::spawn(async move {
            loop {
                let grpc_block_response = stream.message().await;
                let grpc_block = match grpc_block_response {
                    Ok(Some(block_response)) => block_response,
                    Err(e) => {
                        let _unused = send_scan_result
                            .send(Err(WalletError::GrpcError(e.to_string())))
                            .await
                            .inspect_err(|e| {
                                error!("Failed to send download result with error: {}", e);
                            });
                        return;
                    },
                    Ok(None) => {
                        return;
                    },
                };
                let tari_block: Block = match grpc_block.block.map(|b| b.try_into()) {
                    Some(Ok(block)) => block,
                    Some(Err(e)) => {
                        let _unused = send_scan_result
                            .send(Err(WalletError::GrpcError(e.to_string())))
                            .await
                            .inspect_err(|e| {
                                error!("Failed to send download result with error: {}", e);
                            });
                        return;
                    },
                    None => {
                        return;
                    },
                };
                let errors = RwLock::new(Vec::new());
                let wallet_outputs = RwLock::new(Vec::new());
                pool.install(|| {
                    tari_block.body.outputs().par_iter().for_each(|output| {
                        match download_scanner.scan_for_recoverable_output(output) {
                            Ok(Some((wallet_output, index))) => {
                                wallet_outputs.write().expect("wallet_outputs lock poisoned").push((
                                    output.hash(),
                                    wallet_output,
                                    index,
                                ));
                            },
                            Ok(None) => {},
                            Err(e) => {
                                errors.write().expect("wallet_outputs lock poisoned").push(e);
                            },
                        }
                    });
                });

                let inputs = if config.exclude_inputs {
                    Vec::new()
                } else {
                    tari_block
                        .body
                        .inputs()
                        .iter()
                        .map(tari_transaction_components::transaction_components::TransactionInput::output_hash)
                        .collect()
                };

                let block_res = BlockScanResult {
                    height: tari_block.header.height,
                    block_hash: tari_block.hash(),
                    wallet_outputs: wallet_outputs.into_inner().expect("wallet_outputs lock poisoned"),
                    inputs,
                    mined_timestamp: tari_block.header.timestamp.as_u64(),
                };
                let _unused = send_scan_result.send(Ok(vec![block_res])).await.inspect_err(|e| {
                    error!("Failed to send scan error with error: {}", e);
                });
            }
        });

        Ok(rec_scan_result)
    }

    async fn get_tip_info(&mut self) -> WalletResult<TipInfo> {
        let request = Request::new(tari_rpc::Empty {});

        let response = self.client.clone().get_tip_info(request).await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC error: {e}"
            )))
        })?;

        let tip_info = response.into_inner();
        Ok(Self::convert_tip_info(&tip_info))
    }

    async fn get_blocks_by_heights(&mut self, heights: Vec<u64>) -> WalletResult<Vec<Block>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let request = tari_rpc::GetBlocksRequest { heights };

        let mut stream = self
            .client
            .clone()
            .get_blocks(Request::new(request))
            .await
            .map_err(|e| {
                WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                    "GRPC error: {e}"
                )))
            })?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(grpc_block) = stream.message().await.map_err(|e| {
            WalletError::ScanningError(crate::errors::ScanningError::blockchain_connection_failed(&format!(
                "GRPC stream error: {e}"
            )))
        })? {
            if let Some(block) = grpc_block.block {
                let tari_block: Block = block.try_into()?;
                blocks.push(tari_block);
            }
        }

        Ok(blocks)
    }

    async fn get_block_by_height(&mut self, height: u64) -> WalletResult<Option<Block>> {
        let blocks = self.get_blocks_by_heights(vec![height]).await?;
        Ok(blocks.into_iter().next())
    }

    async fn get_header_by_height(&mut self, height: u64) -> WalletResult<Option<BlockHeaderInfo>> {
        let block = self.get_block_by_height(height).await?;
        if let Some(b) = block {
            Ok(Some(BlockHeaderInfo {
                height: b.header.height,
                hash: b.hash(),
                timestamp: b.header.timestamp,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Builder for creating GRPC blockchain scanners
pub struct GrpcScannerBuilder<KM> {
    base_url: Option<String>,
    timeout: Option<Duration>,
    key_managers: Vec<KM>,
    number_processing_threads: usize,
}

impl<KM> Default for GrpcScannerBuilder<KM>
where
    KM: TransactionKeyManagerInterface,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<KM> GrpcScannerBuilder<KM>
where
    KM: TransactionKeyManagerInterface,
{
    /// Create a new builder
    pub const fn new() -> Self {
        Self {
            base_url: None,
            timeout: None,
            key_managers: Vec::new(),
            number_processing_threads: 8,
        }
    }

    /// Set the base URL for the GRPC connection
    #[must_use]
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Set the timeout for GRPC operations
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[must_use]
    pub const fn with_processing_threads(mut self, number_processing_threads: usize) -> Self {
        self.number_processing_threads = number_processing_threads;
        self
    }

    /// Set the key manager for wallet key integration
    #[must_use]
    pub fn with_key_manager(mut self, key_manager: KM) -> Self {
        self.key_managers.push(key_manager);
        self
    }

    /// Build the GRPC scanner
    pub async fn build(self) -> WalletResult<GrpcBlockchainScanner<KM>> {
        let base_url = self
            .base_url
            .ok_or_else(|| WalletError::ConfigurationError("Base URL not specified".to_string()))?;

        if self.key_managers.is_empty() {
            return Err(WalletError::ConfigurationError(
                "No Key managers not specified".to_string(),
            ));
        }

        match self.timeout {
            Some(timeout) => {
                GrpcBlockchainScanner::with_timeout(
                    base_url,
                    timeout,
                    self.key_managers,
                    self.number_processing_threads,
                )
                .await
            },
            None => GrpcBlockchainScanner::new(base_url, self.key_managers, self.number_processing_threads).await,
        }
    }
}
