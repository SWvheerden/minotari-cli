//! Burn transaction construction.
//!
//! Creates a burn transaction that destroys L1 funds and produces a
//! [`NewBurnProof`] that can later be combined with a kernel merkle proof
//! to form a complete L2 claim proof.
//!
//! # Flow
//!
//! 1. Lock UTXOs via [`FundLocker`]
//! 2. Build a burn output with [`OutputFeatures::create_burn_confidential_output`]
//! 3. Set burn kernel features on the transaction
//! 4. Build + sign the transaction using the wallet key manager
//! 5. Generate the ownership proof (Schnorr signature over the commitment)
//! 6. Return the signed [`Transaction`] and a [`NewBurnProof`] for DB storage

use anyhow::anyhow;
use log::{info, warn};
use rusqlite::Connection;
use tari_common::configuration::Network;
use tari_common_types::{
    tari_address::{TariAddress, TariAddressFeatures},
    transaction::TxId,
    types::{CompressedPublicKey, PrivateKey},
};
use tari_script::script;
use tari_transaction_components::{
    MicroMinotari, TransactionBuilder,
    consensus::ConsensusConstantsBuilder,
    key_manager::{TariKeyId, TransactionKeyManagerInterface},
    transaction_components::{
        KernelFeatures, OutputFeatures, WalletOutputBuilder,
        memo_field::{MemoField, TxType},
    },
};
use tari_utilities::{ByteArray, hex::Hex};

use crate::{
    db::{AccountRow, NewBurnProof, SqlitePool},
    models::PendingTransactionStatus,
    transactions::{
        fund_locker::FundLocker,
        idempotency::{IdempotencyBinding, IdempotencyOperation, RequestFingerprint},
    },
};

/// Result returned from a successful burn transaction build.
pub struct BurnTxResult {
    /// The fully signed transaction, ready to broadcast.
    pub transaction: tari_transaction_components::transaction_components::Transaction,
    /// Output hash of the burn output (used to link the burn_proofs DB record).
    pub output_hash: tari_common_types::types::FixedHash,
    /// Partial proof data to persist in the `burn_proofs` table.
    pub new_burn_proof: NewBurnProof,
    /// The generated tx_id.
    pub tx_id: TxId,
}

/// Parameters for a burn transaction.
pub struct BurnTxParams {
    pub account_id: i64,
    pub amount: MicroMinotari,
    /// L2 claim public key. When `None`, the burn is unclaimed (no proof generated).
    pub claim_public_key: Option<CompressedPublicKey>,
    /// Optional sidechain deployment key for L2 template burns.
    pub sidechain_deployment_key: Option<PrivateKey>,
    pub fee_per_gram: MicroMinotari,
    pub payment_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub seconds_to_lock: u64,
    pub confirmation_window: u64,
}

impl BurnTxParams {
    /// Binds this burn's idempotency key to the burn it was issued for.
    ///
    /// A burn is irreversible, so the binding matters twice over: it stops a key
    /// minted at `/lock_funds` from being redeemed here (which would broadcast a
    /// burn over UTXOs the client only meant to reserve), and it stops a burn
    /// key from being replayed with a different amount or a different L2 claim
    /// key.
    fn idempotency_binding(&self) -> IdempotencyBinding {
        let operation = IdempotencyOperation::BurnFunds;
        let fingerprint = RequestFingerprint::new(operation)
            .field("account_id", self.account_id.to_le_bytes())
            .field("amount", self.amount.as_u64().to_le_bytes())
            .optional_field("claim_public_key", self.claim_public_key.as_ref().map(|k| k.to_hex()))
            // The deployment key decides which sidechain may claim the burn, so
            // it is part of the request even though it is a secret. Only its
            // derived public key is hashed; the fingerprint is stored in the
            // database and read back in error paths.
            .optional_field(
                "sidechain_deployment_public_key",
                self.sidechain_deployment_key
                    .as_ref()
                    .map(|k| CompressedPublicKey::from_secret_key(k).to_hex()),
            )
            .field("fee_per_gram", self.fee_per_gram.as_u64().to_le_bytes())
            .optional_field("payment_id", self.payment_id.as_deref())
            .field("seconds_to_lock", self.seconds_to_lock.to_le_bytes())
            .field("confirmation_window", self.confirmation_window.to_le_bytes());
        IdempotencyBinding::new(self.idempotency_key.clone(), operation, fingerprint)
    }
}

/// Builds, signs, and returns a burn transaction along with its partial proof data.
///
/// A `claim_public_key` must be supplied, as this function is designed to
/// always produce a burn proof.
pub fn create_burn_tx(
    account: &AccountRow,
    db_pool: SqlitePool,
    network: Network,
    password: &str,
    params: BurnTxParams,
) -> Result<BurnTxResult, anyhow::Error> {
    let consensus_constants = ConsensusConstantsBuilder::new(network).build();

    info!(
        target: "audit",
        amount = params.amount.as_u64(),
        account_id = params.account_id;
        "Creating burn transaction"
    );

    let sender_address = account.get_address(network, password)?;
    let fund_locker = FundLocker::new(db_pool);
    let locked_funds = fund_locker.lock(
        account.id,
        params.amount,
        1,
        params.fee_per_gram,
        None,
        params.idempotency_binding(),
        params.seconds_to_lock,
        params.confirmation_window,
    )?;

    let key_manager = account.get_key_manager(password)?;

    let output_features = match &params.claim_public_key {
        Some(cpk) => {
            OutputFeatures::create_burn_confidential_output(cpk.clone(), params.sidechain_deployment_key.as_ref())
        },
        None => OutputFeatures::create_burn_output(),
    };

    // Derive the commitment mask key and sender offset key for the burn output.
    let (commitment_mask_key, _script_key) = key_manager.get_next_commitment_mask_and_script_key()?;
    let sender_offset_key = key_manager.get_random_key(None, None)?;

    // The encrypted data in the burn output is DH-encrypted to the claim_public_key
    // (so the L2 wallet can decrypt it). Fall back to the wallet's view key if no
    // claim_public_key is provided.
    let recovery_key_id = match &params.claim_public_key {
        Some(cpk) => TariKeyId::DHEncryptedData {
            public_key: cpk.clone(),
            private_key: sender_offset_key.key_id.clone().into(),
        },
        None => key_manager.get_view_key().key_id,
    };

    let memo = params
        .payment_id
        .as_deref()
        .and_then(|s| MemoField::new_open_from_string(s, TxType::Burn).ok())
        .unwrap_or_else(|| MemoField::new_open_from_string("", TxType::Burn).unwrap_or_default());

    // Build the burn output with explicit key material (not stealth-address derivation).
    let burn_output = WalletOutputBuilder::new(params.amount, commitment_mask_key.key_id.clone())
        .with_features(output_features)
        .with_script(script!(Nop)?)
        .with_input_data(Default::default())
        .with_sender_offset_public_key(sender_offset_key.pub_key.clone())
        .with_script_key(TariKeyId::Zero)
        .with_minimum_value_promise(MicroMinotari::zero())
        .encrypt_data_for_recovery(&key_manager, Some(&recovery_key_id), memo.clone())?
        .sign_metadata_signature(&key_manager, &sender_offset_key.key_id)?
        .try_build(&key_manager)?;

    let output_hash = burn_output.output_hash();
    let commitment = burn_output.commitment().clone();

    // Assemble the transaction.
    let mut tx_builder = TransactionBuilder::new(consensus_constants, key_manager.clone(), network)?;
    tx_builder.with_fee_per_gram(params.fee_per_gram);
    tx_builder.with_kernel_features(KernelFeatures::create_burn());
    tx_builder.with_tx_type(TxType::Burn);
    tx_builder.with_memo(memo);

    for utxo in &locked_funds.utxos {
        tx_builder.with_input(utxo.clone())?;
    }

    // Default address used as placeholder — burn outputs have no real "recipient".
    tx_builder.add_recipient(
        TariAddress::new_dual_address(
            key_manager.get_view_key().pub_key,
            sender_address.public_spend_key().clone(),
            network,
            TariAddressFeatures::create_one_sided_only(),
            None,
        )?,
        burn_output,
        Some(sender_offset_key.key_id),
        Some(recovery_key_id),
    )?;

    let finalized = tx_builder.build()?;

    // Generate the ownership proof: a Schnorr signature binding the commitment to
    // the claim public key. Needed by L2 to verify the burn.
    let new_burn_proof = if let Some(cpk) = params.claim_public_key {
        let ownership_proof = key_manager.generate_burn_claim_signature(
            &commitment_mask_key.key_id,
            params.amount.as_u64(),
            &cpk,
            None,
        )?;

        let kernel = finalized
            .transaction
            .body
            .kernels()
            .iter()
            .find(|k| k.features.is_burned())
            .ok_or_else(|| anyhow!("No burn kernel found in transaction"))?;

        NewBurnProof {
            account_id: params.account_id,
            output_hash,
            commitment: commitment.as_bytes().to_vec(),
            claim_public_key: cpk.to_hex(),
            ownership_proof_nonce: ownership_proof.get_compressed_public_nonce().as_bytes().to_vec(),
            ownership_proof_sig: ownership_proof.get_signature().as_bytes().to_vec(),
            kernel_excess: kernel.excess.as_bytes().to_vec(),
            kernel_excess_nonce: kernel.excess_sig.get_compressed_public_nonce().as_bytes().to_vec(),
            kernel_excess_sig: kernel.excess_sig.get_signature().as_bytes().to_vec(),
            sender_offset_public_key: sender_offset_key.pub_key.as_bytes().to_vec(),
            encrypted_data: finalized
                .sent_outputs
                .first()
                .map(|op| op.output.encrypted_data().to_byte_vec())
                .unwrap_or_default(),
            value: params.amount.as_u64(),
            kernel_fee: kernel.fee.as_u64(),
            kernel_lock_height: kernel.lock_height,
        }
    } else {
        return Err(anyhow!("claim_public_key is required to generate a burn proof"));
    };

    Ok(BurnTxResult {
        transaction: finalized.transaction,
        output_hash,
        new_burn_proof,
        tx_id: finalized.tx_id,
    })
}

/// Persists all DB records for a completed burn transaction.
///
/// Inserts the burn proof, then (if a matching pending transaction exists) updates
/// its status to `Completed` and creates a completed-transaction record.
///
/// Errors from the pending-transaction steps are logged as warnings rather than
/// propagated: the burn proof is already safely stored at this point, so these
/// failures must not cause the caller to report the burn as failed.
///
/// Call this before broadcasting the transaction so the proof is never lost.
pub fn persist_burn_records(
    conn: &Connection,
    result: &BurnTxResult,
    account_id: i64,
    idempotency_key: &str,
) -> Result<(), anyhow::Error> {
    crate::db::insert_burn_proof(conn, &result.new_burn_proof)
        .map_err(|e| anyhow!("Failed to insert burn proof: {}", e))?;

    let kernel_excess = result
        .transaction
        .body
        .kernels()
        .iter()
        .find(|k| k.features.is_burned())
        .map(|k| k.excess.as_bytes().to_vec())
        .unwrap_or_default();
    let serialized_tx =
        serde_json::to_vec(&result.transaction).map_err(|e| anyhow!("Failed to serialize transaction: {}", e))?;
    let sent_output_hash = Some(hex::encode(result.output_hash));

    match crate::db::find_pending_transaction_by_idempotency_key(conn, idempotency_key, account_id) {
        Ok(Some(pending_tx)) => {
            let pending_tx_id = pending_tx.id.to_string();
            if let Err(e) =
                crate::db::update_pending_transaction_status(conn, &pending_tx_id, PendingTransactionStatus::Completed)
            {
                warn!(
                    "Burn tx succeeded but failed to update pending tx status (idempotency_key={}): {}",
                    idempotency_key, e
                );
            }
            if let Err(e) = crate::db::create_completed_transaction(
                conn,
                account_id,
                &pending_tx_id,
                &kernel_excess,
                &serialized_tx,
                sent_output_hash,
                result.tx_id,
            ) {
                warn!(
                    "Burn tx succeeded but failed to record completed transaction (idempotency_key={}): {}",
                    idempotency_key, e
                );
            }
        },
        Ok(None) => {},
        Err(e) => {
            warn!(
                "Burn tx succeeded but failed to look up pending transaction (idempotency_key={}): {}",
                idempotency_key, e
            );
        },
    }

    Ok(())
}
