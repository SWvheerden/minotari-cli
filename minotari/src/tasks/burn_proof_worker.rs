//! Background task that fetches kernel merkle proofs for confirmed burn outputs
//! and writes complete [`CompleteClaimBurnProof`] JSON files to disk.
//!
//! # Flow
//!
//! 1. Poll `burn_proofs` table for records with `status = 'pending_merkle'`
//! 2. For each, call `/generate_kernel_merkle_proof` on the base node
//! 3. Assemble [`CompleteClaimBurnProof`] from the stored partial proof + merkle response
//! 4. Write `{claim_public_key}-{commitment_hex}.json` to `burn_proofs_dir`
//! 5. Mark the DB record as `complete`

use std::{path::PathBuf, time::Duration};

use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use tari_common_types::{
    burn_proof::EncodedMerkleProof,
    serializers,
    types::{CompressedCommitment, CompressedPublicKey},
};
use tari_crypto::ristretto::CompressedRistrettoSchnorr;
use tari_transaction_components::rpc::models::GenerateKernelMerkleProofResponse;
use tokio::{fs, sync::broadcast, task::JoinHandle, time::interval};

// TODO: Remove these three local type definitions once the `tari` workspace dependency is bumped to a version that
// includes commit 5a278cb ("fix(wallet): save complete burn proof in file", 2026-03-20).
// At that point `tari_sidechain` will export `CompleteClaimBurnProof`, `BurnClaimProof`, and
// `AbridgedTransactionKernel` directly. Replace the three structs below with:
//
//   use tari_sidechain::{AbridgedTransactionKernel, BurnClaimProof, CompleteClaimBurnProof};
//
// and add `tari_sidechain = { workspace = true }` back to minotari/Cargo.toml and
// `tari_sidechain = { version = "..." }` to the workspace Cargo.toml.

/// Mirrors `tari_sidechain::CompleteClaimBurnProof`. Matches the exact JSON format the L2 wallet daemon expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteClaimBurnProof {
    pub claim_proof: BurnClaimProof,
    #[serde(with = "serializers::base64")]
    pub encrypted_data: Vec<u8>,
}

/// Mirrors `tari_sidechain::BurnClaimProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnClaimProof {
    pub burn_public_key: CompressedPublicKey,
    pub commitment: CompressedCommitment,
    pub ownership_proof: CompressedRistrettoSchnorr,
    pub encoded_merkle_proof: EncodedMerkleProof,
    pub kernel: AbridgedTransactionKernel,
    pub value: u64,
    pub sender_offset_public_key: CompressedPublicKey,
}

/// Mirrors `tari_sidechain::AbridgedTransactionKernel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbridgedTransactionKernel {
    pub version: u8,
    pub fee: u64,
    pub lock_height: u64,
    pub excess: CompressedCommitment,
    pub excess_sig: CompressedRistrettoSchnorr,
}

use crate::{
    db::{DbBurnProof, SqlitePool, get_pending_burn_proofs, mark_burn_proof_complete},
    http::WalletHttpClient,
};

const LOG_TARGET: &str = "wallet::tasks::burn_proof_worker";
const POLL_INTERVAL_SECS: u64 = 60;

pub struct BurnProofWorker {
    db_pool: SqlitePool,
    client: WalletHttpClient,
    burn_proofs_dir: PathBuf,
}

impl BurnProofWorker {
    pub fn new(db_pool: SqlitePool, client: WalletHttpClient, burn_proofs_dir: PathBuf) -> Self {
        Self {
            db_pool,
            client,
            burn_proofs_dir,
        }
    }

    pub fn run(self, mut shutdown_rx: broadcast::Receiver<()>) -> JoinHandle<Result<(), anyhow::Error>> {
        tokio::spawn(async move {
            info!(target: LOG_TARGET, "Burn proof worker started.");
            let mut ticker = interval(Duration::from_secs(POLL_INTERVAL_SECS));

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = self.process_pending_proofs().await {
                            error!(target: LOG_TARGET, error:% = e; "Error processing pending burn proofs");
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!(target: LOG_TARGET, "Burn proof worker received shutdown signal. Exiting gracefully.");
                        break;
                    }
                }
            }

            info!(target: LOG_TARGET, "Burn proof worker has shut down.");
            Ok(())
        })
    }

    async fn process_pending_proofs(&self) -> Result<(), anyhow::Error> {
        // Fetch pending proofs and immediately release the connection before any await.
        let pending = {
            let conn = self.db_pool.get()?;
            get_pending_burn_proofs(&conn)?
        };

        if pending.is_empty() {
            return Ok(());
        }

        info!(
            target: LOG_TARGET,
            count = pending.len();
            "Processing pending burn proofs"
        );

        for proof in pending {
            let proof_id = proof.id;
            if let Err(e) = self.process_single_proof(&proof).await {
                warn!(
                    target: LOG_TARGET,
                    burn_proof_id = proof_id,
                    error:% = e;
                    "Failed to process burn proof — will retry next cycle"
                );
            }
        }

        Ok(())
    }

    async fn process_single_proof(&self, proof: &DbBurnProof) -> Result<(), anyhow::Error> {
        // Fetch the merkle proof asynchronously.
        let merkle_response = self
            .client
            .get_kernel_merkle_proof(&proof.kernel_excess_nonce, &proof.kernel_excess_sig)
            .await?;

        let complete_proof = assemble_complete_proof(proof, &merkle_response)?;

        write_proof_file(
            &self.burn_proofs_dir,
            &proof.claim_public_key,
            &proof.commitment,
            &complete_proof,
        )
        .await?;

        // Mark complete — get a fresh connection after the await.
        let conn = self.db_pool.get()?;
        mark_burn_proof_complete(&conn, proof.id)?;

        Ok(())
    }
}

fn assemble_complete_proof(
    proof: &DbBurnProof,
    merkle: &GenerateKernelMerkleProofResponse,
) -> Result<CompleteClaimBurnProof, anyhow::Error> {
    use tari_common_types::{burn_proof::EncodedMerkleProof, types::PrivateKey};
    use tari_utilities::byte_array::ByteArray;

    let sender_offset_public_key = CompressedPublicKey::from_canonical_bytes(&proof.sender_offset_public_key)
        .map_err(|e| anyhow::anyhow!("Invalid sender_offset_public_key: {}", e))?;

    let commitment = CompressedCommitment::from_canonical_bytes(&proof.commitment)
        .map_err(|e| anyhow::anyhow!("Invalid commitment: {}", e))?;

    let nonce = CompressedPublicKey::from_canonical_bytes(&proof.ownership_proof_nonce)
        .map_err(|e| anyhow::anyhow!("Invalid ownership_proof_nonce: {}", e))?;
    let sig_scalar = PrivateKey::from_canonical_bytes(&proof.ownership_proof_sig)
        .map_err(|e| anyhow::anyhow!("Invalid ownership_proof_sig: {}", e))?;
    let ownership_proof = CompressedRistrettoSchnorr::new(nonce, sig_scalar);

    let excess_commitment = CompressedCommitment::from_canonical_bytes(&proof.kernel_excess)
        .map_err(|e| anyhow::anyhow!("Invalid kernel_excess: {}", e))?;
    let excess_nonce = CompressedPublicKey::from_canonical_bytes(&proof.kernel_excess_nonce)
        .map_err(|e| anyhow::anyhow!("Invalid kernel_excess_nonce: {}", e))?;
    let excess_sig_scalar = PrivateKey::from_canonical_bytes(&proof.kernel_excess_sig)
        .map_err(|e| anyhow::anyhow!("Invalid kernel_excess_sig: {}", e))?;
    let excess_sig = CompressedRistrettoSchnorr::new(excess_nonce, excess_sig_scalar);

    let burn_public_key = CompressedPublicKey::from_canonical_bytes(
        &hex::decode(&proof.claim_public_key).map_err(|e| anyhow::anyhow!("Invalid claim_public_key hex: {}", e))?,
    )
    .map_err(|e| anyhow::anyhow!("Invalid claim_public_key: {}", e))?;

    let encoded_merkle_proof = EncodedMerkleProof {
        block_hash: merkle.block_hash,
        encoded_merkle_proof: merkle.encoded_merkle_proof.clone(),
        leaf_index: merkle.leaf_index,
    };

    Ok(CompleteClaimBurnProof {
        claim_proof: BurnClaimProof {
            burn_public_key,
            commitment,
            ownership_proof,
            encoded_merkle_proof,
            kernel: AbridgedTransactionKernel {
                version: 0,
                fee: proof.kernel_fee as u64,
                lock_height: proof.kernel_lock_height as u64,
                excess: excess_commitment,
                excess_sig,
            },
            value: proof.value as u64,
            sender_offset_public_key,
        },
        encrypted_data: proof.encrypted_data.clone(),
    })
}

async fn write_proof_file(
    burn_proofs_dir: &PathBuf,
    claim_public_key_hex: &str,
    commitment: &[u8],
    proof: &CompleteClaimBurnProof,
) -> Result<(), anyhow::Error> {
    fs::create_dir_all(burn_proofs_dir).await?;

    let filename = format!("{}-{}.json", claim_public_key_hex, hex::encode(commitment));
    let path = burn_proofs_dir.join(&filename);

    let json = serde_json::to_vec_pretty(proof)?;
    fs::write(&path, &json).await?;

    info!(
        target: LOG_TARGET,
        path = &*path.display().to_string();
        "Wrote complete burn proof file"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use tari_common_types::types::FixedHash;
    use tari_transaction_components::rpc::models::GenerateKernelMerkleProofResponse;

    use super::*;

    /// Build a `DbBurnProof` where every byte-array field holds 32 zero bytes.
    ///
    /// The Ristretto identity element serialises as 32 zero bytes, so all
    /// compressed-point fields are valid and `assemble_complete_proof` will
    /// succeed without hitting a curve-decode error.
    fn make_test_db_proof() -> DbBurnProof {
        DbBurnProof {
            id: 1,
            account_id: 1,
            output_hash: FixedHash::default(),
            commitment: vec![0u8; 32],
            // 64 hex chars = 32 zero bytes (Ristretto identity)
            claim_public_key: "00".repeat(32),
            ownership_proof_nonce: vec![0u8; 32],
            ownership_proof_sig: vec![0u8; 32],
            kernel_excess: vec![0u8; 32],
            kernel_excess_nonce: vec![0u8; 32],
            kernel_excess_sig: vec![0u8; 32],
            sender_offset_public_key: vec![0u8; 32],
            encrypted_data: vec![0xAB, 0xCD, 0xEF],
            value: 1_000_000,
            kernel_fee: 250,
            kernel_lock_height: 0,
            status: "pending_merkle".to_string(),
        }
    }

    fn make_test_merkle_response() -> GenerateKernelMerkleProofResponse {
        GenerateKernelMerkleProofResponse {
            block_hash: FixedHash::default(),
            encoded_merkle_proof: vec![1, 2, 3],
            leaf_index: 42,
            block_height: Some(1),
        }
    }

    #[test]
    fn test_assemble_complete_proof_success() {
        let proof = make_test_db_proof();
        let merkle = make_test_merkle_response();

        let result = assemble_complete_proof(&proof, &merkle);
        assert!(result.is_ok(), "Expected Ok but got: {:?}", result.err());

        let complete = result.unwrap();
        assert_eq!(complete.claim_proof.value, 1_000_000);
        assert_eq!(complete.encrypted_data, vec![0xAB, 0xCD, 0xEF]);
        assert_eq!(complete.claim_proof.kernel.version, 0);
        assert_eq!(complete.claim_proof.kernel.fee, 250);
        assert_eq!(complete.claim_proof.kernel.lock_height, 0);
        assert_eq!(complete.claim_proof.encoded_merkle_proof.leaf_index, 42);
        assert_eq!(
            complete.claim_proof.encoded_merkle_proof.encoded_merkle_proof,
            vec![1, 2, 3]
        );
    }

    #[test]
    fn test_assemble_complete_proof_value_preserved() {
        let mut proof = make_test_db_proof();
        proof.value = 999_999;

        let result = assemble_complete_proof(&proof, &make_test_merkle_response());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().claim_proof.value, 999_999);
    }

    #[test]
    fn test_assemble_complete_proof_encrypted_data_preserved() {
        let mut proof = make_test_db_proof();
        proof.encrypted_data = vec![0x11, 0x22, 0x33, 0x44];

        let result = assemble_complete_proof(&proof, &make_test_merkle_response());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().encrypted_data, vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_assemble_complete_proof_invalid_claim_public_key_hex() {
        let mut proof = make_test_db_proof();
        proof.claim_public_key = "not-valid-hex".to_string();

        let result = assemble_complete_proof(&proof, &make_test_merkle_response());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("claim_public_key"),
            "Error should mention claim_public_key, got: {err}"
        );
    }

    #[test]
    fn test_assemble_complete_proof_invalid_sender_offset_public_key() {
        let mut proof = make_test_db_proof();
        proof.sender_offset_public_key = vec![]; // wrong length — definitely invalid

        let result = assemble_complete_proof(&proof, &make_test_merkle_response());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("sender_offset_public_key"),
            "Error should mention sender_offset_public_key, got: {err}"
        );
    }

    #[test]
    fn test_assemble_complete_proof_invalid_commitment() {
        let mut proof = make_test_db_proof();
        proof.commitment = vec![]; // wrong length — definitely invalid

        let result = assemble_complete_proof(&proof, &make_test_merkle_response());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("commitment"),
            "Error should mention commitment, got: {err}"
        );
    }
}
