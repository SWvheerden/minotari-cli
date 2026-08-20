//! Validator node eviction proof transaction construction.
//!
//! This module provides functionality for creating validator node eviction proof
//! transactions on the Tari base layer. The eviction embeds a self-validating
//! [`EvictionProof`] (containing sidechain quorum certificates and a Merkle inclusion
//! proof) into a pay-to-self transaction with special [`OutputFeatures`].
//!
//! Unlike registration and exit, no wallet-side signature validation is performed —
//! the proof is self-validating via embedded quorum certificates.
//! Only [`WalletType::SeedWords`] wallets are supported.
//!
//! # Flow
//!
//! 1. Build [`OutputFeatures::for_validator_node_eviction`] from the proof
//! 2. Lock the deposit UTXOs via [`FundLocker`] and prepare the transaction for signing

use anyhow::anyhow;
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::types::PrivateKey;
use tari_sidechain::EvictionProof;
use tari_transaction_components::{
    key_manager::wallet_types::WalletType, offline_signing::models::PrepareOneSidedTransactionForSigningResult,
    tari_amount::MicroMinotari, transaction_components::OutputFeatures,
};

use super::common::build_vn_pay_to_self_tx;
use crate::db::AccountRow;
use crate::transactions::idempotency::IdempotencyOperation;

/// Parameters for validator node eviction
///
/// The `eviction_proof` is self-validating via embedded quorum certificates and a
/// Merkle inclusion proof — no additional wallet signature is required.
pub struct ValidatorNodeEvictionParams {
    /// The self-validating eviction proof containing sidechain block commit data.
    pub eviction_proof: EvictionProof,
    /// Fee rate in MicroMinotari per gram.
    pub fee_per_gram: MicroMinotari,
    /// Optional payment memo attached to the transaction.
    pub payment_id: Option<String>,
    /// Optional sidechain deployment private key. If provided, creates a [`SideChainId`]
    /// knowledge proof signed over the evicted node's public key.
    pub sidechain_deployment_key: Option<PrivateKey>,
}

/// Creates an unsigned validator node eviction proof transaction.
///
/// Unlike registration and exit, no signature validation is performed — the
/// [`EvictionProof`] is self-validating via embedded quorum certificates.
///
/// # Errors
///
/// Returns an error if:
/// - The account is not a [`WalletType::SeedWords`] wallet
/// - There are insufficient funds for the consensus-required deposit
/// - Transaction construction fails
#[allow(clippy::too_many_arguments)]
pub fn create_validator_node_eviction_tx(
    account: &AccountRow,
    params: ValidatorNodeEvictionParams,
    conn: &mut Connection,
    network: Network,
    password: &str,
    idempotency_key: Option<String>,
    seconds_to_lock: u64,
    confirmation_window: u64,
) -> Result<PrepareOneSidedTransactionForSigningResult, anyhow::Error> {
    let wallet_type = account.decrypt_wallet_type(password)?;
    if !matches!(wallet_type, WalletType::SeedWords(_)) {
        return Err(anyhow!(
            "Validator node eviction requires a SeedWords wallet, not a view-only wallet"
        ));
    }

    let output_features =
        OutputFeatures::for_validator_node_eviction(params.eviction_proof, params.sidechain_deployment_key.as_ref());

    build_vn_pay_to_self_tx(
        account,
        conn,
        network,
        password,
        output_features,
        params.fee_per_gram,
        params.payment_id.as_deref(),
        idempotency_key,
        seconds_to_lock,
        confirmation_window,
        IdempotencyOperation::ValidatorNodeEviction,
    )
}
