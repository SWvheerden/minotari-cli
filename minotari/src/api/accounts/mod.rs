//! Account management API endpoint handlers.
//!
//! This module provides HTTP endpoint handlers for account-related operations
//! in the Minotari wallet REST API. It includes functionality for:
//!
//! - Querying account balances
//! - Retrieving wallet events
//! - Locking funds for transaction preparation
//! - Creating unsigned transactions for one-sided payments
//!
//! All endpoints follow RESTful conventions and return JSON responses.
//! Error responses use the [`crate::api::error::ApiError`] type for consistent error formatting.
//!
//! # Endpoint Overview
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/accounts/{name}/balance` | Retrieve account balance |
//! | GET | `/accounts/{name}/events` | Retrieve wallet events |
//! | POST | `/accounts/{name}/lock_funds` | Lock UTXOs for spending |
//! | POST | `/accounts/{name}/create_unsigned_transaction` | Create unsigned transaction |
//!
//! # Authentication
//!
//! Every endpoint requires the daemon's API token, sent as
//! `Authorization: Bearer <token>` or `X-API-Key: <token>`. Requests without a valid
//! token are answered with `401 Unauthorized` before reaching a handler, unless the
//! operator started the daemon with `--api-disable-auth`. See [`crate::api::auth`].
//!
//! # Example Usage
//!
//! ```bash
//! # Get account balance
//! curl -X GET http://localhost:8080/accounts/default/balance \
//!   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
//!
//! # Get wallet events
//! curl -X GET http://localhost:8080/accounts/default/events \
//!   -H "Authorization: Bearer $MINOTARI_API_TOKEN"
//!
//! # Lock funds for a transaction
//! curl -X POST http://localhost:8080/accounts/default/lock_funds \
//!   -H "Authorization: Bearer $MINOTARI_API_TOKEN" \
//!   -H "Content-Type: application/json" \
//!   -d '{"amount": 1000000}'
//! ```

mod balance;
mod burn;
mod events;
mod fees;
mod fund_lock;
mod params;
mod transactions;

pub use balance::{
    CreatePaymentIdAddressRequest, api_create_address_with_payment_id, api_get_address, api_get_balance,
    api_get_scan_status, api_get_version,
};
pub use burn::{BurnFundsRequest, BurnFundsResponse, api_burn_funds};
pub use events::api_get_events;
pub use fees::{EstimateFeeRequest, api_estimate_fees};
pub use fund_lock::{
    CreateTransactionRequest, LockFundsRequest, RecipientRequest, api_create_unsigned_transaction, api_lock_funds,
};
pub use params::{PaginationParams, PayrefParams, WalletParams};
pub use transactions::{
    api_get_completed_transaction_by_payref, api_get_completed_transactions, api_get_displayed_transactions,
    api_get_displayed_transactions_by_payref,
};

// Re-export utoipa-generated path structs so that the OpenApi derive in api/mod.rs
// can resolve `accounts::__path_*` names.
pub use balance::{
    __path_api_create_address_with_payment_id, __path_api_get_address, __path_api_get_balance,
    __path_api_get_scan_status, __path_api_get_version,
};
pub use burn::__path_api_burn_funds;
pub use events::__path_api_get_events;
pub use fees::__path_api_estimate_fees;
pub use fund_lock::{__path_api_create_unsigned_transaction, __path_api_lock_funds};
pub use transactions::{
    __path_api_get_completed_transaction_by_payref, __path_api_get_completed_transactions,
    __path_api_get_displayed_transactions, __path_api_get_displayed_transactions_by_payref,
};
