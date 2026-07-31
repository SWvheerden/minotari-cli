//! Burn funds endpoint handler.

use axum::{
    Json,
    extract::{Path, State},
};
use log::info;
use serde::{Deserialize, Serialize};
use tari_transaction_components::tari_amount::MicroMinotari;

use crate::{
    api::{AppState, error::ApiError},
    db::get_account_by_name,
    http::WalletHttpClient,
    transactions::burn::{BurnTxParams, create_burn_tx, persist_burn_records},
    utils::crypto::{parse_private_key_hex, parse_public_key_hex},
};

use super::params::{WalletParams, default_fee_per_gram, default_seconds_to_lock_utxos};

/// Request body for burning funds and generating an L2 claim proof.
///
/// # JSON Example
///
/// ```json
/// {
///   "amount": 1000000,
///   "claim_public_key": "a3f9...",
///   "fee_per_gram": 5,
///   "payment_id": "optional memo",
///   "seconds_to_lock": 86400
/// }
/// ```
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BurnFundsRequest {
    /// Amount to burn in MicroMinotari.
    #[schema(value_type = u64)]
    pub amount: MicroMinotari,

    /// L2 claim public key in hex. Required to generate a burn proof for L2 claiming.
    pub claim_public_key: Option<String>,

    /// Sidechain deployment key in hex, for L2 template burns.
    pub sidechain_deployment_key: Option<String>,

    /// Fee per gram in MicroMinotari (default: 5).
    #[schema(value_type = u64)]
    #[serde(default = "default_fee_per_gram")]
    pub fee_per_gram: Option<MicroMinotari>,

    /// Optional payment memo attached to the transaction.
    pub payment_id: Option<String>,

    /// Optional idempotency key to prevent duplicate burn requests.
    pub idempotency_key: Option<String>,

    /// Seconds to lock input UTXOs (default: 86400 = 24 h).
    #[serde(default = "default_seconds_to_lock_utxos")]
    pub seconds_to_lock: Option<u64>,
}

/// Response returned after a successful burn transaction.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BurnFundsResponse {
    /// Transaction ID assigned to the burn transaction.
    pub tx_id: String,
    /// Hex-encoded output hash of the burn output.
    ///
    /// The daemon will use this to track when the proof is ready.
    pub output_hash: String,
}

/// Burns funds from an account and records a partial burn proof for L2 claiming.
///
/// Creates a burn transaction, broadcasts it, and stores the partial proof in the
/// database. The daemon's `BurnProofWorker` will automatically fetch the kernel
/// merkle proof once the transaction is confirmed and write the complete
/// `CompleteClaimBurnProof` JSON file to the configured `burn_proofs_dir`.
///
/// # Path Parameters
///
/// - `name`: The account to burn funds from
///
/// # Request Body
///
/// See [`BurnFundsRequest`] for the complete schema.
///
/// # Response
///
/// Returns a [`BurnFundsResponse`] with:
/// - `tx_id`: the transaction ID
/// - `output_hash`: hex-encoded output hash (use this to identify the proof file)
///
/// # Errors
///
/// - `400 Bad Request`: invalid `claim_public_key` or `sidechain_deployment_key` hex
/// - `404 Not Found`: account does not exist
/// - `500`: insufficient funds, broadcast failure, or other internal error
///
/// # Example Request
///
/// ```bash
/// curl -X POST http://127.0.0.1:9000/accounts/default/burn \
///   -H "Authorization: Bearer $MINOTARI_API_TOKEN" \
///   -H "Content-Type: application/json" \
///   -d '{"amount": 1000000, "claim_public_key": "a3f9..."}'
/// ```
#[utoipa::path(
    post,
    path = "/accounts/{name}/burn",
    request_body = BurnFundsRequest,
    responses(
        (status = 200, description = "Burn transaction broadcast successfully", body = BurnFundsResponse),
        (status = 400, description = "Invalid request parameters", body = ApiError),
        (status = 404, description = "Account not found", body = ApiError),
        (status = 500, description = "Burn failed", body = ApiError),
    ),
    params(
        ("name" = String, Path, description = "Name of the account to burn from"),
    )
)]
pub async fn api_burn_funds(
    State(app_state): State<AppState>,
    Path(WalletParams { name }): Path<WalletParams>,
    Json(body): Json<BurnFundsRequest>,
) -> Result<Json<BurnFundsResponse>, ApiError> {
    info!(
        target: "audit",
        account = &*name,
        amount = body.amount.as_u64();
        "API: Burn funds request"
    );

    let pool = app_state.db_pool.clone();
    let network = app_state.network;
    let password = app_state.password.clone();
    let fee_per_gram = body.fee_per_gram.unwrap_or(MicroMinotari(5));
    let seconds_to_lock = body.seconds_to_lock.unwrap_or(86400);
    let confirmation_window = app_state.required_confirmations;
    let idempotency_key = body.idempotency_key.clone();
    let amount = body.amount;

    let (result, tx_id, output_hash) = tokio::task::spawn_blocking(move || {
        let claim_public_key = body
            .claim_public_key
            .as_deref()
            .map(parse_public_key_hex)
            .transpose()
            .map_err(|e| ApiError::BadRequest(format!("Invalid claim_public_key: {}", e)))?;

        let sidechain_deployment_key = body
            .sidechain_deployment_key
            .as_deref()
            .map(parse_private_key_hex)
            .transpose()
            .map_err(|e| ApiError::BadRequest(format!("Invalid sidechain_deployment_key: {}", e)))?;

        let idempotency_key = idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;
        let account = get_account_by_name(&conn, &name)
            .map_err(|e| ApiError::DbError(e.to_string()))?
            .ok_or_else(|| ApiError::AccountNotFound(name.clone()))?;

        let params = BurnTxParams {
            account_id: account.id,
            amount,
            claim_public_key,
            sidechain_deployment_key,
            fee_per_gram,
            payment_id: body.payment_id.clone(),
            idempotency_key: Some(idempotency_key.clone()),
            seconds_to_lock,
            confirmation_window,
        };

        let result = create_burn_tx(&account, pool.clone(), network, &password, params)
            .map_err(|e| ApiError::FailedToBurnFunds(e.to_string()))?;

        persist_burn_records(&conn, &result, account.id, &idempotency_key)
            .map_err(|e| ApiError::DbError(e.to_string()))?;

        let tx_id = result.tx_id;
        let output_hash = result.output_hash;

        Ok::<_, ApiError>((result, tx_id, output_hash))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    let client = WalletHttpClient::new(
        app_state
            .base_node_url
            .parse()
            .map_err(|e| ApiError::InternalServerError(format!("Invalid base node URL: {}", e)))?,
    )
    .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

    let response = client
        .submit_transaction(result.transaction)
        .await
        .map_err(|e| ApiError::FailedToBurnFunds(format!("Broadcast failed: {}", e)))?;

    if !response.accepted {
        return Err(ApiError::FailedToBurnFunds(format!(
            "Transaction rejected: {}",
            response.rejection_reason
        )));
    }

    // Mark broadcasted.
    let pool = app_state.db_pool.clone();
    tokio::task::spawn_blocking(move || {
        let conn = pool.get().map_err(|e| ApiError::DbError(e.to_string()))?;
        crate::db::mark_completed_transaction_as_broadcasted(&conn, tx_id, 1)
            .map_err(|e| ApiError::DbError(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    info!(
        target: "audit",
        tx_id = &*tx_id.to_string(),
        output_hash = &*hex::encode(output_hash);
        "API: Burn transaction broadcasted"
    );

    Ok(Json(BurnFundsResponse {
        tx_id: tx_id.to_string(),
        output_hash: hex::encode(output_hash),
    }))
}
