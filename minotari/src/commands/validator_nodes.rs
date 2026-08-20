//! CLI handlers for validator node commands.
//!
//! Each handler parses its CLI inputs, builds the appropriate params struct,
//! calls the transaction constructor, then signs, persists, and broadcasts the result.

use std::{fs, path::PathBuf};

use crate::{
    db::{self, AccountRow, init_db},
    http::WalletHttpClient,
    models::PendingTransactionStatus,
    transactions::validator_node::{
        eviction::{ValidatorNodeEvictionParams, create_validator_node_eviction_tx},
        exit::{ValidatorNodeExitParams, create_validator_node_exit_tx},
        registration::{ValidatorNodeRegistrationParams, create_validator_node_registration_tx},
    },
};
use anyhow::anyhow;
use log::info;
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::{
    epoch::VnEpoch,
    types::{CompressedPublicKey, CompressedSignature, PrivateKey},
};
use tari_transaction_components::{
    consensus::ConsensusConstantsBuilder,
    offline_signing::{models::PrepareOneSidedTransactionForSigningResult, sign_locked_transaction},
    tari_amount::MicroMinotari,
};
use tari_utilities::byte_array::ByteArray;

// ── Parsing helpers ──────────────────────────────────────────────────────────

fn parse_compressed_public_key(hex_str: &str, field_name: &str) -> Result<CompressedPublicKey, anyhow::Error> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("Invalid {} hex: {}", field_name, e))?;
    CompressedPublicKey::from_canonical_bytes(&bytes).map_err(|e| anyhow!("Invalid {}: {}", field_name, e))
}

/// Parses the three hex strings that describe a VN Schnorr signature.
///
/// Returns `(vn_public_key, signature)` where the signature bundles the public nonce
/// and the scalar component.
fn parse_vn_signature(
    pk_hex: &str,
    nonce_hex: &str,
    sig_hex: &str,
) -> Result<(CompressedPublicKey, CompressedSignature), anyhow::Error> {
    let vn_public_key = parse_compressed_public_key(pk_hex, "vn-public-key")?;
    let nonce = parse_compressed_public_key(nonce_hex, "vn-sig-nonce")?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| anyhow!("Invalid vn-sig hex: {}", e))?;
    let sig_scalar =
        PrivateKey::from_canonical_bytes(&sig_bytes).map_err(|e| anyhow!("Invalid vn-sig scalar: {}", e))?;
    Ok((vn_public_key, CompressedSignature::new(nonce, sig_scalar)))
}

fn parse_sidechain_deployment_key(key: Option<String>) -> Result<Option<PrivateKey>, anyhow::Error> {
    key.map(|k| {
        let bytes = hex::decode(&k).map_err(|e| anyhow!("Invalid sidechain-deployment-key hex: {}", e))?;
        PrivateKey::from_canonical_bytes(&bytes).map_err(|e| anyhow!("Invalid sidechain-deployment-key: {}", e))
    })
    .transpose()
}

// ── Sign + persist + broadcast ────────────────────────────────────────────────

/// Signs an unsigned VN transaction, saves it to the DB, and broadcasts it.
///
/// This is the common post-processing step shared by all three VN commands.
/// `tx_kind` is used in log/error messages (e.g. `"VN registration"`).
#[allow(clippy::too_many_arguments)]
async fn sign_save_and_broadcast(
    unsigned_result: PrepareOneSidedTransactionForSigningResult,
    account: &AccountRow,
    conn: &Connection,
    password: &str,
    network: Network,
    idempotency_key: &str,
    base_url: &str,
    tx_kind: &str,
) -> Result<(), anyhow::Error> {
    let key_manager = account.get_key_manager(password)?;
    let consensus_constants = ConsensusConstantsBuilder::new(network).build();
    let signed_result = sign_locked_transaction(&key_manager, consensus_constants, network, unsigned_result)
        .map_err(|e| anyhow!("Failed to sign {} transaction: {}", tx_kind, e))?;

    let completed_tx_id = signed_result.signed_transaction.tx_id;
    let kernel_excess = signed_result
        .signed_transaction
        .transaction
        .body()
        .kernels()
        .first()
        .map(|k| k.excess.as_bytes().to_vec())
        .unwrap_or_default();
    let serialized_tx = serde_json::to_vec(&signed_result.signed_transaction.transaction)
        .map_err(|e| anyhow!("Failed to serialize transaction: {}", e))?;
    let sent_output_hash = signed_result.signed_transaction.sent_hashes.first().map(hex::encode);

    if let Some(pending_tx) = db::find_pending_transaction_by_idempotency_key(conn, idempotency_key, account.id)? {
        let pending_tx_id = pending_tx.id.to_string();
        db::update_pending_transaction_status(conn, &pending_tx_id, PendingTransactionStatus::Completed)?;
        db::create_completed_transaction(
            conn,
            account.id,
            &pending_tx_id,
            &kernel_excess,
            &serialized_tx,
            sent_output_hash,
            completed_tx_id,
        )?;
    }

    let client = WalletHttpClient::new(base_url.parse()?)?;
    let response = client
        .submit_transaction(signed_result.signed_transaction.transaction)
        .await;

    match response {
        Ok(r) if r.accepted => {
            db::mark_completed_transaction_as_broadcasted(conn, completed_tx_id, 1)?;
            info!(target: "audit", tx_id = completed_tx_id.to_string().as_str(); "{} broadcasted", tx_kind);
            println!("{} transaction broadcasted. tx_id={}", tx_kind, completed_tx_id);
        },
        Ok(r) => return Err(anyhow!("Transaction rejected by network: {}", r.rejection_reason)),
        Err(e) => return Err(anyhow!("Broadcast failed: {}", e)),
    }

    Ok(())
}

// ── Shared command runner ─────────────────────────────────────────────────────

/// Handles the shared boilerplate for all three VN commands: initialise the
/// database, fetch the account, call the operation-specific transaction
/// constructor, then sign, persist, and broadcast the result.
///
/// `create_tx` is a closure that captures the operation-specific params and
/// returns an unsigned transaction ready for signing.
#[allow(clippy::too_many_arguments)]
async fn run_vn_command<F>(
    database_file: PathBuf,
    account_name: &str,
    network: Network,
    password: &str,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    base_url: &str,
    tx_kind: &str,
    create_tx: F,
) -> Result<(), anyhow::Error>
where
    F: FnOnce(
        &AccountRow,
        &mut Connection,
        Network,
        &str,
        Option<String>,
        u64,
        u64,
    ) -> Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error>,
{
    let idempotency_key = idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let pool = init_db(database_file)?;
    // One connection for the command: the VN transaction is built on it and the result is
    // then saved and broadcast with it, so nothing is held idle while `lock` waits.
    let mut conn = pool.get()?;
    let account =
        db::get_account_by_name(&conn, account_name)?.ok_or_else(|| anyhow!("Account not found: {}", account_name))?;

    let unsigned_result = create_tx(
        &account,
        &mut conn,
        network,
        password,
        Some(idempotency_key.clone()),
        seconds_to_lock,
        confirmation_window,
    )?;

    sign_save_and_broadcast(
        unsigned_result,
        &account,
        &conn,
        password,
        network,
        &idempotency_key,
        base_url,
        tx_kind,
    )
    .await
}

// ── Public handlers ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn handle_register_validator_node(
    vn_public_key: String,
    vn_sig_nonce: String,
    vn_sig: String,
    claim_public_key: String,
    max_epoch: u64,
    fee_per_gram: u64,
    payment_id: Option<String>,
    sidechain_deployment_key: Option<String>,
    database_file: PathBuf,
    account_name: String,
    network: Network,
    password: String,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    base_url: String,
) -> Result<(), anyhow::Error> {
    let (vn_public_key, vn_signature) = parse_vn_signature(&vn_public_key, &vn_sig_nonce, &vn_sig)?;
    let claim_public_key = parse_compressed_public_key(&claim_public_key, "claim-public-key")?;
    let sidechain_deployment_key = parse_sidechain_deployment_key(sidechain_deployment_key)?;

    let params = ValidatorNodeRegistrationParams {
        validator_node_public_key: vn_public_key,
        validator_node_signature: vn_signature,
        claim_public_key,
        max_epoch: VnEpoch(max_epoch),
        fee_per_gram: MicroMinotari(fee_per_gram),
        payment_id,
        sidechain_deployment_key,
    };

    run_vn_command(
        database_file,
        &account_name,
        network,
        &password,
        idempotency_key,
        seconds_to_lock,
        confirmation_window,
        &base_url,
        "VN registration",
        |account, conn, network, password, idempotency_key, seconds_to_lock, confirmation_window| {
            create_validator_node_registration_tx(
                account,
                params,
                conn,
                network,
                password,
                idempotency_key,
                seconds_to_lock,
                confirmation_window,
            )
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_submit_validator_node_exit(
    vn_public_key: String,
    vn_sig_nonce: String,
    vn_sig: String,
    max_epoch: u64,
    fee_per_gram: u64,
    payment_id: Option<String>,
    sidechain_deployment_key: Option<String>,
    database_file: PathBuf,
    account_name: String,
    network: Network,
    password: String,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    base_url: String,
) -> Result<(), anyhow::Error> {
    let (vn_public_key, vn_signature) = parse_vn_signature(&vn_public_key, &vn_sig_nonce, &vn_sig)?;
    let sidechain_deployment_key = parse_sidechain_deployment_key(sidechain_deployment_key)?;

    let params = ValidatorNodeExitParams {
        validator_node_public_key: vn_public_key,
        validator_node_signature: vn_signature,
        max_epoch: VnEpoch(max_epoch),
        fee_per_gram: MicroMinotari(fee_per_gram),
        payment_id,
        sidechain_deployment_key,
    };

    run_vn_command(
        database_file,
        &account_name,
        network,
        &password,
        idempotency_key,
        seconds_to_lock,
        confirmation_window,
        &base_url,
        "VN exit",
        |account, conn, network, password, idempotency_key, seconds_to_lock, confirmation_window| {
            create_validator_node_exit_tx(
                account,
                params,
                conn,
                network,
                password,
                idempotency_key,
                seconds_to_lock,
                confirmation_window,
            )
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_submit_validator_eviction_proof(
    proof_file: PathBuf,
    fee_per_gram: u64,
    payment_id: Option<String>,
    sidechain_deployment_key: Option<String>,
    database_file: PathBuf,
    account_name: String,
    network: Network,
    password: String,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
    base_url: String,
) -> Result<(), anyhow::Error> {
    let proof_json = fs::read_to_string(&proof_file)
        .map_err(|e| anyhow!("Failed to read proof file '{}': {}", proof_file.display(), e))?;
    let eviction_proof: tari_sidechain::EvictionProof =
        serde_json::from_str(&proof_json).map_err(|e| anyhow!("Failed to parse eviction proof JSON: {}", e))?;

    let sidechain_deployment_key = parse_sidechain_deployment_key(sidechain_deployment_key)?;

    let params = ValidatorNodeEvictionParams {
        eviction_proof,
        fee_per_gram: MicroMinotari(fee_per_gram),
        payment_id,
        sidechain_deployment_key,
    };

    run_vn_command(
        database_file,
        &account_name,
        network,
        &password,
        idempotency_key,
        seconds_to_lock,
        confirmation_window,
        &base_url,
        "VN eviction proof",
        |account, conn, network, password, idempotency_key, seconds_to_lock, confirmation_window| {
            create_validator_node_eviction_tx(
                account,
                params,
                conn,
                network,
                password,
                idempotency_key,
                seconds_to_lock,
                confirmation_window,
            )
        },
    )
    .await
}
