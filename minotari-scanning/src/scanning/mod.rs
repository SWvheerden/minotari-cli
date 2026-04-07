//! UTXO scanning module for lightweight wallet libraries
//!
//! This module provides a lightweight interface for scanning the Tari blockchain
//! for wallet outputs. It uses a trait-based approach that allows different
//! backend implementations (gRPC, HTTP, etc.) to be plugged in.
//!
//! ## Scanner Refactoring Components
//!
//! The following modules support the refactored scanner.rs binary:
//! - `scan_config`: Configuration structures for scanner binary operations
//! - `storage_manager`: Storage abstraction for scanner binary
//! - `background_writer`: Async database operations for scanner binary
//! - `wallet_scanner`: Main scanning implementation for scanner binary
//! - `progress`: Progress tracking utilities for scanner binary

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tari_common_types::types::FixedHash;
use tari_transaction_components::transaction_components::WalletOutput;
use tari_utilities::epoch_time::EpochTime;

// Include GRPC scanner when the feature is enabled
#[cfg(feature = "grpc")]
pub mod grpc;

// Include HTTP scanner
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "grpc")]
pub use grpc::scanner::{GrpcBlockchainScanner, GrpcScannerBuilder};
pub use http::scanner as http_scanner;
// Re-export HTTP scanner types
#[cfg(feature = "http")]
pub use http_scanner::HttpBlockchainScanner;

use crate::http::models::IncompleteScannedOutput;

mod interface;
pub use interface::BlockchainScanner;

/// Configuration for blockchain scanning
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanConfig {
    /// Starting block height (wallet birthday)
    pub start_height: u64,
    /// Ending block height (optional, if None scans to tip)
    pub end_height: Option<u64>,
    /// Maximum number of blocks to scan in one request, default 10
    pub batch_size: Option<u64>,
    /// Timeout for requests
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
    pub exclude_spent: bool,
    pub exclude_inputs: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            start_height: 0,
            end_height: None,
            batch_size: Some(100),
            request_timeout: Duration::from_secs(30),
            exclude_spent: false,
            exclude_inputs: false,
        }
    }
}

impl ScanConfig {
    #[must_use]
    pub const fn with_start_height(mut self, start_height: u64) -> Self {
        self.start_height = start_height;
        self
    }

    #[must_use]
    pub const fn with_end_height(mut self, end_height: u64) -> Self {
        self.end_height = Some(end_height);
        self
    }

    #[must_use]
    pub const fn with_start_end_heights(mut self, start_height: u64, end_height: u64) -> Self {
        self.start_height = start_height;
        self.end_height = Some(end_height);
        self
    }

    #[must_use]
    pub const fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.batch_size = Some(batch_size);
        self
    }

    #[must_use]
    pub const fn with_exclude_spent(mut self, exclude_spent: bool) -> Self {
        self.exclude_spent = exclude_spent;
        self
    }

    #[must_use]
    pub const fn with_exclude_inputs(mut self, exclude_inputs: bool) -> Self {
        self.exclude_inputs = exclude_inputs;
        self
    }
}

// Helper module for Duration serialization
mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Chain tip information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipInfo {
    /// Current best block height
    pub best_block_height: u64,
    /// Current best block hash
    pub best_block_hash: FixedHash,
    /// Accumulated difficulty
    pub accumulated_difficulty: String,
    /// Pruned height (minimum height this node can provide complete blocks for)
    pub pruned_height: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Result of a block scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoScanResult {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: FixedHash,
    /// Wallet outputs extracted from transaction outputs
    pub wallet_outputs: Vec<IncompleteScannedOutput>,
    /// Input hashes
    pub inputs: Vec<FixedHash>,
    /// Timestamp when block was mined
    pub mined_timestamp: u64,
}

/// Result of a block scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockScanResult {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: FixedHash,
    /// Wallet outputs extracted from transaction outputs (hash, output)
    pub wallet_outputs: Vec<(FixedHash, WalletOutput, usize)>,
    /// Input hashes
    pub inputs: Vec<FixedHash>,
    /// Timestamp when block was mined
    pub mined_timestamp: u64,
}

/// Block header information
#[derive(Debug, Clone)]
pub struct BlockHeaderInfo {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: FixedHash,
    /// Timestamp
    pub timestamp: EpochTime,
}

#[derive(Debug, Clone)]
struct InProgressScan {
    config: Option<ScanConfig>,
    header: Option<String>,
    current_page: u64,
}

impl InProgressScan {
    pub const fn new(config: ScanConfig) -> Self {
        Self {
            config: Some(config),
            header: None,
            current_page: 0,
        }
    }

    pub const fn new_empty() -> Self {
        Self {
            config: None,
            header: None,
            current_page: 0,
        }
    }

    pub fn clear(&mut self) {
        self.config = None;
        self.header = None;
        self.current_page = 0;
    }

    pub const fn page(&self) -> u64 {
        self.current_page
    }

    pub const fn is_active(&self) -> bool {
        self.config.is_some()
    }

    pub const fn increment_page(&mut self) {
        self.current_page += 1;
    }

    pub fn set_next_request(&mut self, header: String) {
        self.header = Some(header);
        self.current_page = 0;
    }

    pub const fn get_header(&self) -> Option<&String> {
        self.header.as_ref()
    }

    pub const fn get_config(&self) -> Option<&ScanConfig> {
        self.config.as_ref()
    }
}
