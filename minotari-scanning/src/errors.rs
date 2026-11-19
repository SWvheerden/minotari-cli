use tari_script::ScriptError;
use tari_transaction_components::{key_manager::error::KeyManagerError, transaction_components::TransactionError};
use thiserror::Error;

/// Main error type for the lightweight wallet library
#[derive(Debug, Error, Clone)]
pub enum WalletError {
    #[error("Scanning error: {0}")]
    ScanningError(#[from] ScanningError),
    #[error("Conversion error: {0}")]
    ConversionError(String),
    #[error("Invalid argument: {argument} = {value}. {message}")]
    InvalidArgument {
        argument: String,
        value: String,
        message: String,
    },
    #[error("Operation not supported: {0}")]
    OperationNotSupported(String),
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(String),
    #[error("Timeout error: {0}")]
    Timeout(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("gRPC error: {0}")]
    GrpcError(String),
    #[error("Data error: {0}")]
    DataError(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Transaction error: {0}")]
    TransactionError(#[from] TransactionError),
    #[error("Script error: {0}")]
    ScriptError(#[from] ScriptError),
    #[error("Key Manager error: {0}")]
    KeyManagerError(#[from] KeyManagerError),
}

/// Errors related to UTXO scanning operations
#[derive(Debug, Error, Clone)]
pub enum ScanningError {
    #[error("Blockchain connection failed: {0}")]
    BlockchainConnectionFailed(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Output not found: {0}")]
    OutputNotFound(String),

    #[error("Scan interrupted: {0}")]
    ScanInterrupted(String),

    #[error("Scan timeout: {0}")]
    ScanTimeout(String),

    #[error("Invalid block height: {0}")]
    InvalidBlockHeight(String),

    #[error("Invalid block hash: {0}")]
    InvalidBlockHash(String),

    #[error("Invalid transaction hash: {0}")]
    InvalidTransactionHash(String),

    #[error("Invalid output hash: {0}")]
    InvalidOutputHash(String),

    #[error("Scan progress error: {0}")]
    ScanProgressError(String),

    #[error("Scan resume failed: {0}")]
    ScanResumeFailed(String),

    #[error("Scan state corrupted: {0}")]
    ScanStateCorrupted(String),

    #[error("Scan configuration error: {0}")]
    ScanConfigurationError(String),

    #[error("Scan memory error: {0}")]
    ScanMemoryError(String),

    #[error("Scan performance error: {0}")]
    ScanPerformanceError(String),

    #[error("Scan data corruption: {0}")]
    ScanDataCorruption(String),

    #[error("Scan network error: {0}")]
    ScanNetworkError(String),

    #[error("Scan rate limit exceeded: {0}")]
    ScanRateLimitExceeded(String),

    #[error("Invalid block data from base node: {0}")]
    InvalidBlockData(String),
}

impl From<String> for WalletError {
    fn from(err: String) -> Self {
        Self::InternalError(err)
    }
}

impl From<&str> for WalletError {
    fn from(err: &str) -> Self {
        Self::InternalError(err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for WalletError {
    fn from(err: wasm_bindgen::JsValue) -> Self {
        let message = if let Some(string) = err.as_string() {
            string
        } else {
            format!("{:?}", err)
        };
        Self::NetworkError(format!("WASM error: {}", message))
    }
}

impl ScanningError {
    /// Create a blockchain connection failed error
    pub fn blockchain_connection_failed(details: &str) -> Self {
        Self::BlockchainConnectionFailed(details.to_string())
    }

    /// Create a block not found error
    pub fn block_not_found(block_id: &str) -> Self {
        Self::BlockNotFound(block_id.to_string())
    }

    /// Create a scan timeout error
    pub fn scan_timeout(operation: &str) -> Self {
        Self::ScanTimeout(operation.to_string())
    }
}

/// Result type for lightweight wallet operations
pub type WalletResult<T> = Result<T, WalletError>;
