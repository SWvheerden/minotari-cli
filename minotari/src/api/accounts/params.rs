//! Shared request parameters and types for account endpoints.

use serde::Deserialize;
use tari_transaction_components::tari_amount::MicroMinotari;
use utoipa::{
    IntoParams,
    openapi::{ObjectBuilder, Schema, Type, schema::SchemaType},
};

/// Default lock duration for UTXOs, in seconds.
///
/// UTXOs are locked for 24 hours (86,400 seconds) by default to prevent
/// double-spending while a transaction is being prepared and broadcast.
pub(super) const DEFAULT_SECONDS_TO_LOCK_UTXOS: u64 = 86400;

/// Default number of outputs for a transaction.
///
/// One output is suitable for simple single-recipient transactions.
pub(super) const DEFAULT_NUM_OUTPUTS: usize = 1;

/// Default fee per gram for transactions, in MicroMinotari.
///
/// 5 MicroMinotari per gram provides a reasonable balance between transaction
/// confirmation speed and cost.
pub(super) const DEFAULT_FEE_PER_GRAM: MicroMinotari = MicroMinotari(5);

/// Serde default for `seconds_to_lock_utxos`.
///
/// Note that `#[serde(default = ..)]` only fires when the field is *absent*; a
/// request that sends an explicit `null` still deserializes to `None`, so
/// handlers must fall back to [`DEFAULT_SECONDS_TO_LOCK_UTXOS`] rather than
/// assuming the value is populated.
pub(super) fn default_seconds_to_lock_utxos() -> Option<u64> {
    Some(DEFAULT_SECONDS_TO_LOCK_UTXOS)
}

/// Serde default for `num_outputs`. See [`default_seconds_to_lock_utxos`] for
/// why the handler must still handle `None`.
pub(super) fn default_num_outputs() -> Option<usize> {
    Some(DEFAULT_NUM_OUTPUTS)
}

/// Serde default for `fee_per_gram`. See [`default_seconds_to_lock_utxos`] for
/// why the handler must still handle `None`.
pub(super) fn default_fee_per_gram() -> Option<MicroMinotari> {
    Some(DEFAULT_FEE_PER_GRAM)
}

pub(super) fn confirmation_window_schema() -> Schema {
    ObjectBuilder::new()
        .schema_type(SchemaType::new(Type::Integer))
        .description(Some("Number of confirmations required"))
        .build()
        .into()
}

/// Default number of items per page for paginated endpoints.
pub(super) const DEFAULT_PAGE_LIMIT: i64 = 50;

/// Maximum number of items that can be requested per page.
pub(super) const MAX_PAGE_LIMIT: i64 = 1000;

/// Query parameters for pagination.
///
/// Used to control the number of results returned and offset for paginated
/// endpoints.
#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationParams {
    /// Maximum number of items to return (default: 50, max: 1000)
    pub limit: Option<i64>,
    /// Number of items to skip for pagination (default: 0)
    pub offset: Option<i64>,
}

/// Path parameters for wallet/account identification.
///
/// Used to extract the account name from URL path segments in account-related
/// endpoints.
///
/// # Example
///
/// For a request to `/accounts/my_wallet/balance`, the `name` field would
/// contain `"my_wallet"`.
#[derive(Debug, Deserialize, IntoParams, utoipa::ToSchema)]
pub struct WalletParams {
    /// The unique name identifying the wallet account.
    pub name: String,
}

/// Path parameters for payref lookup.
///
/// Used to extract the payment reference from URL path segments.
#[derive(Debug, Deserialize, IntoParams, utoipa::ToSchema)]
pub struct PayrefParams {
    /// The unique name identifying the wallet account.
    pub name: String,
    /// The payment reference to search for.
    pub payref: String,
}
