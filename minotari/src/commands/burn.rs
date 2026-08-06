//! CLI handler for the `burn-funds` command.
//!
//! Builds, signs, and broadcasts a burn transaction, then persists the partial
//! burn proof so the daemon can later fetch the kernel merkle proof and write
//! the complete [`CompleteClaimBurnProof`] JSON file.

use std::path::PathBuf;

use anyhow::anyhow;
use log::info;
use tari_common::configuration::Network;
use tari_transaction_components::tari_amount::MicroMinotari;

use crate::{
    db::{self, init_db},
    http::WalletHttpClient,
    transactions::burn::{BurnTxParams, BurnTxResult, create_burn_tx, persist_burn_records},
    utils::crypto::{parse_private_key_hex, parse_public_key_hex},
};

/// Parameters consumed by [`handle_burn_funds`].
#[allow(clippy::too_many_arguments)]
pub async fn handle_burn_funds(
    account_name: String,
    amount: MicroMinotari,
    claim_public_key: Option<String>,
    fee_per_gram: MicroMinotari,
    payment_id: Option<String>,
    sidechain_deployment_key: Option<String>,
    database_file: PathBuf,
    network: Network,
    password: String,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    base_url: String,
) -> Result<(), anyhow::Error> {
    let claim_public_key = claim_public_key
        .as_deref()
        .map(parse_public_key_hex)
        .transpose()
        .map_err(|e| anyhow!("Invalid claim-public-key: {}", e))?;
    let sidechain_deployment_key = sidechain_deployment_key
        .as_deref()
        .map(parse_private_key_hex)
        .transpose()
        .map_err(|e| anyhow!("Invalid sidechain-deployment-key: {}", e))?;

    let idempotency_key = idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let pool = init_db(database_file)?;
    let mut conn = pool.get()?;

    let account = db::get_account_by_name(&conn, &account_name)?
        .ok_or_else(|| anyhow!("Account '{}' not found", account_name))?;

    let params = BurnTxParams {
        account_id: account.id,
        amount,
        claim_public_key,
        sidechain_deployment_key,
        fee_per_gram,
        payment_id,
        idempotency_key: Some(idempotency_key.clone()),
        seconds_to_lock,
        confirmation_window,
    };

    let result = create_burn_tx(&account, pool.clone(), network, &password, params)
        .map_err(|e| anyhow!("Failed to build burn transaction: {}", e))?;

    // Persist partial burn proof before broadcasting (so it's never lost).
    persist_burn_records(&mut conn, &result, account.id, &idempotency_key)?;
    info!(
        target: "audit",
        output_hash = &*hex::encode(result.output_hash);
        "Burn proof record saved to database"
    );

    let BurnTxResult {
        transaction,
        output_hash,
        tx_id,
        ..
    } = result;

    // Broadcast.
    let client = WalletHttpClient::new(base_url.parse()?)?;
    let response = client.submit_transaction(transaction).await;

    match response {
        Ok(r) if r.accepted => {
            db::mark_completed_transaction_as_broadcasted(&conn, tx_id, 1)?;
            info!(
                target: "audit",
                tx_id = &*tx_id.to_string(),
                output_hash = &*hex::encode(output_hash);
                "Burn transaction broadcasted"
            );
            println!(
                "Burn transaction broadcasted. tx_id={}, output_hash={}",
                tx_id,
                hex::encode(output_hash)
            );
        },
        Ok(r) => return Err(anyhow!("Transaction rejected by network: {}", r.rejection_reason)),
        Err(e) => return Err(anyhow!("Broadcast failed: {}", e)),
    }

    Ok(())
}
