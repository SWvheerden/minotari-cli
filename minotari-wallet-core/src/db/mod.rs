//! Database layer for wallet data persistence using SQLite.
//!
//! This module provides the complete database interface for the Minotari wallet,
//! handling all persistent storage including accounts, outputs, transactions,
//! and blockchain scanning state.
//!
//! # Database Schema
//!
//! The database consists of several interconnected tables:
//!
//! - **accounts** - Encrypted wallet keys and account metadata
//! - **outputs** - Detected UTXOs with confirmation status
//! - **inputs** - Spent outputs (transaction inputs)
//! - **balance_changes** - Transaction history with credits and debits
//! - **wallet_events** - Timeline of wallet activity
//! - **scanned_tip_blocks** - Scanning progress and reorg detection
//! - **pending_transactions** - Transactions being constructed
//! - **completed_transactions** - Broadcasted transactions and their status
//! - **displayed_transactions** - User-friendly transaction view
//!
//! # Migrations
//!
//! Database migrations are managed by rusqlite_migration and automatically applied on initialization.
//! Migration files are located in the `migrations/` directory.
//!
//! # Usage Example
//!
//! ```ignore
//! use minotari_wallet_core::db::{init_db, get_accounts, get_balance};
//! use std::path::PathBuf;
//!
//! # fn example() -> Result<(), anyhow::Error> {
//! // Initialize database and run migrations
//! let pool = init_db(PathBuf::from("wallet.db"))?;
//! let conn = pool.get()?;
//!
//! // Query accounts
//! let accounts = get_accounts(&conn, None)?;
//!
//! // Check balance (account_id = 1)
//! let balance = get_balance(&conn, 1)?;
//! println!("Available: {} µT", balance.available);
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use std::sync::LazyLock;
use std::{env::current_dir, fs};

use include_dir::{Dir, include_dir};
use log::{debug, error, info};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use rusqlite_migration::Migrations;

mod error;
pub(crate) mod sqlite_amount;
mod sqlite_time;
pub use error::{WalletDbError, WalletDbResult};

mod accounts;
#[cfg(test)]
pub(crate) use accounts::WALLET_PARSES;
pub use accounts::{
    AccountBalance, AccountRow, change_passphrase, create_account, get_account_by_name, get_accounts, get_balance,
};
pub(crate) use accounts::{delete_account, update_account_name};

mod scanned_tip_blocks;
pub use scanned_tip_blocks::{
    LatestScannedBlock, delete_scanned_tip_blocks_from_height, get_latest_scanned_block_with_timestamp,
    get_latest_scanned_tip_block_by_account, get_scanned_tip_block_hash_at_height, get_scanned_tip_blocks_by_account,
    insert_scanned_tip_block, is_other_block_scanned_at_height, prune_scanned_tip_blocks,
};

mod outputs;
pub use outputs::{
    ChangeOutputToRevert, DbOutput, DbWalletOutput, OutputInstance, UnresolvedSpentOutput, clear_dead_lock,
    confirm_unconfirmed_change_output, derive_output_tx_id, fetch_outputs_by_lock_request_id, fetch_unspent_outputs,
    get_active_burn_outputs, get_active_outputs_from_height, get_change_output_hash_for_request, get_output_by_id,
    get_output_hashes_mined_in_block, get_output_hashes_spent_in_block, get_output_info_by_hash_for_account,
    get_output_instances_for_account, get_output_lock_request_id, get_output_spend, get_output_totals_for_account,
    get_total_unspent_balance, get_unconfirmed_outputs, get_unresolved_spent_unconfirmed_outputs,
    get_unspent_copy_block, insert_output, insert_spent_output_if_not_exists, insert_unconfirmed_change_output,
    is_lock_holder_live, lock_output, mark_change_output_rejected, mark_output_confirmed, record_spender_of_inputs,
    relock_inputs_for_revived_send, resolve_spent_unconfirmed_with_inputs, resolve_spent_unconfirmed_with_newer_copy,
    restore_change_of_rejected_send, revert_change_outputs_from_height, revert_rejected_change_output,
    soft_delete_outputs_from_height, soft_delete_unconfirmed_change_output, unlock_outputs_for_request,
    unlock_outputs_for_request as unlock_outputs_for_pending_transaction, update_output_status,
};

mod pending_transactions;
pub use pending_transactions::{
    PendingTransaction, PendingTransactionRecord, cancel_pending_transactions_by_ids,
    check_if_transaction_is_expired_by_idempotency_key, claim_pending_transaction_for_broadcast,
    create_pending_transaction, expire_and_unlock_pending_transaction, find_expired_pending_transactions,
    find_pending_transaction_by_idempotency_key, find_pending_transaction_record_by_idempotency_key,
    locked_funds_for_pending_transaction, update_pending_transaction_status, update_pending_transaction_status_if,
};

mod completed_transactions;
pub use completed_transactions::{
    CompletedTransaction, CompletedTransactionStatus, create_completed_transaction, get_completed_transaction_by_id,
    get_completed_transaction_by_payref, get_completed_transaction_to_match, get_completed_transactions_by_account,
    get_completed_transactions_by_status, get_last_broadcast_error, get_pending_completed_transactions,
    get_scan_rejected_pending_tx_ids_from_height, keep_rejected_after_reorg, mark_completed_transaction_as_broadcasted,
    mark_completed_transaction_as_confirmed, mark_completed_transaction_as_mined_unconfirmed,
    mark_completed_transaction_as_rejected, mark_completed_transaction_as_rejected_in_block,
    record_failed_broadcast_attempt, record_last_broadcast_error, reset_mined_completed_transactions_from_height,
    revert_completed_transaction_to_completed, update_completed_transaction_status,
};

mod events;
pub use events::{DbWalletEvent, get_events_by_account_id, insert_wallet_event};

mod webhooks;
pub use webhooks::{delete_webhooks_older_than, enqueue_webhook, fetch_due_webhooks, update_webhook_status};

mod balance_changes;
pub use balance_changes::{
    get_all_active_balance_changes_by_account_id, get_all_balance_changes_by_account_id,
    get_balance_change_id_by_input, get_balance_change_id_by_output, insert_balance_change,
    insert_balance_change_if_not_exists,
};

mod inputs;
pub use inputs::{DbInput, get_input_by_id, insert_input, soft_delete_inputs_from_height};

mod burn_proofs;
pub use burn_proofs::{
    DbBurnProof, NewBurnProof, advance_burn_proof_reorg_generation, burn_proof_files_from_height,
    burn_proof_is_current_complete, burn_proof_scan_state, get_burn_proof_by_output_hash,
    get_completed_burn_proof_files, get_pending_burn_proofs, insert_burn_proof, mark_burn_proof_complete,
    mark_burn_proof_complete_if_current, remember_pending_burn_proof_height, reset_burn_proofs_from_height,
    reset_completed_burn_proof_for_missing_file,
};

mod payref_history;
pub use payref_history::{
    get_transaction_id_by_historical_payref, save_completed_transaction_payrefs_before_reorg,
    save_displayed_transaction_payrefs_before_reorg, save_payref_history,
};

mod displayed_transactions;
pub use displayed_transactions::{
    find_pending_outbound_by_output_hash, get_displayed_transaction_by_id, get_displayed_transactions_by_account,
    get_displayed_transactions_by_payref, get_displayed_transactions_by_status,
    get_displayed_transactions_excluding_reorged, get_displayed_transactions_from_height,
    get_displayed_transactions_needing_confirmation_update, get_displayed_transactions_paginated,
    insert_displayed_transaction, mark_displayed_transaction_rejected, mark_displayed_transactions_reorganized,
    mark_displayed_transactions_reorganized_and_return, reset_displayed_transaction_to_pending,
    update_displayed_transaction_confirmations, update_displayed_transaction_mined,
    update_displayed_transaction_status,
};

const DB_POOL_SIZE: u32 = 5;

pub type SqlitePool = Pool<SqliteConnectionManager>;

static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/migrations");

static MIGRATIONS: LazyLock<Migrations<'static>> = LazyLock::new(|| {
    Migrations::from_directory(&MIGRATIONS_DIR).expect("Failed to load migrations from embedded directory")
});

/// Initializes the SQLite database and runs migrations.
///
/// This function:
/// 1. Resolves the database path (handles relative paths)
/// 2. Creates parent directories if they don't exist
/// 3. Creates the database file if it doesn't exist
/// 4. Creates a connection pool with up to 5 connections
/// 5. Runs all pending migrations from `migrations/` directory
///
/// # Parameters
///
/// * `db_path` - Path to the SQLite database file (relative or absolute)
///
/// # Returns
///
/// Returns a `SqlitePool` ready for use, or an error if:
/// - The path is invalid
/// - Directory creation fails
/// - Database file creation fails
/// - Connection fails
/// - Migrations fail
///
/// # Example
///
/// ```ignore
/// use minotari_wallet_core::db::init_db;
/// use std::path::PathBuf;
///
/// # fn example() -> Result<(), anyhow::Error> {
/// // Initialize database in current directory
/// let pool = init_db(PathBuf::from("wallet.db"))?;
///
/// // Or use absolute path
/// let pool = init_db(PathBuf::from("/path/to/wallet.db"))?;
/// # Ok(())
/// # }
/// ```
pub fn init_db(db_path: PathBuf) -> WalletDbResult<SqlitePool> {
    debug!(path:? = db_path; "Initializing database");

    let mut path = db_path;
    if path.is_relative() {
        path = current_dir()?.join(path);
    }

    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid database file path"))?;
    fs::create_dir_all(parent)?;

    match connect_and_migrate(&path) {
        Ok(pool) => Ok(pool),
        Err(e) => {
            error!(
                error:% = e,
                path:? = &path;
                "Database migration failed. Please, remove database manually"
            );
            Err(WalletDbError::Unexpected(
                "Unexpected error occurred. It is possibly a migration from sqlx that has failed. Consider removing database file and try again".to_string(),
            ))
        },
    }
}

fn connect_and_migrate(path: &PathBuf) -> WalletDbResult<SqlitePool> {
    debug!(path:? = path; "Connecting to database");
    let manager = SqliteConnectionManager::file(path).with_init(|c| {
        // WAL mode: Allows concurrent reads and writes (crucial for connection pooling).
        // synchronous NORMAL: Optimized performance; safe from app crashes in WAL mode.
        // foreign_keys ON: Enforces table relationships (SQLite defaults to OFF).
        // busy_timeout: Prevents "database is locked" errors by waiting up to 5s for locks to clear.
        c.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        Ok(())
    });
    let pool = Pool::builder().max_size(DB_POOL_SIZE).build(manager)?;
    let mut conn = pool.get()?;

    attempt_sqlx_adoption(&mut conn).ok();

    debug!("Applying migrations");
    MIGRATIONS.to_latest(&mut conn)?;

    Ok(pool)
}

/// Attempts to detect if the database was managed by sqlx and updates the
/// user_version PRAGMA to match the number of applied migrations, allowing
/// rusqlite_migration to pick up where sqlx left off.
fn attempt_sqlx_adoption(conn: &mut Connection) -> WalletDbResult<()> {
    let table_exists: bool = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if table_exists {
        let count: i32 = conn.query_row("SELECT count(*) FROM _sqlx_migrations", [], |row| row.get(0))?;

        if count > 0 {
            let pragma_sql = format!("PRAGMA user_version = {}", count);
            conn.execute(&pragma_sql, [])?;

            info!(count = count; "Migrated from sqlx: updated user_version");
        }

        conn.execute("DROP TABLE _sqlx_migrations", [])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::OutputStatus;
    use crate::transactions::{DisplayedTransactionBuilder, TransactionOutput, TransactionSource};
    use rusqlite::named_params;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_common_types::types::FixedHash;
    use tari_common_types::types::{ComAndPubSignature, CompressedPublicKey};
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::TariKeyId;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tari_transaction_components::transaction_components::{
        EncryptedData, MemoField, OutputFeatures, OutputType, TransactionOutputVersion, WalletOutput,
        covenants::Covenant,
    };

    /// A wallet output as the scan stores it, serialized.
    fn wallet_output_json(value: u64, hash: FixedHash, features: OutputFeatures) -> String {
        let output = WalletOutput::new_from_parts(
            TransactionOutputVersion::default(),
            MicroMinotari::from(value),
            TariKeyId::default(),
            features,
            TariScript::default(),
            ExecutionStack::default(),
            TariKeyId::default(),
            CompressedPublicKey::default(),
            ComAndPubSignature::default(),
            0,
            Covenant::default(),
            EncryptedData::default(),
            MicroMinotari::from(0),
            None,
            MemoField::new_empty(),
            hash,
            Default::default(),
        );
        serde_json::to_string(&output).unwrap()
    }

    fn seed_output(conn: &Connection, account_id: i64, hash: FixedHash, value: i64, is_burn: bool) -> i64 {
        seed_output_with_json(conn, account_id, hash, value, is_burn, "{}")
    }

    fn seed_output_with_json(
        conn: &Connection,
        account_id: i64,
        hash: FixedHash,
        value: i64,
        is_burn: bool,
        json: &str,
    ) -> i64 {
        conn.execute(
            "INSERT INTO outputs (account_id, tx_id, output_hash, mined_in_block_hash, mined_in_block_height, value,
                                  mined_timestamp, wallet_output_json, is_burn)
             VALUES (:account_id, :value, :hash, x'00', 10, :value, CURRENT_TIMESTAMP, :json, :is_burn)",
            named_params! {
                ":account_id": account_id,
                ":hash": hash.as_slice(),
                ":value": value,
                ":is_burn": is_burn,
                ":json": json,
            },
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn seed_balance_change(
        conn: &Connection,
        account_id: i64,
        output_id: i64,
        credit: i64,
        debit: i64,
        reversal_of: Option<i64>,
    ) -> i64 {
        conn.execute(
            "INSERT INTO balance_changes (account_id, caused_by_output_id, description, balance_credit, balance_debit,
                                          effective_date, effective_height, is_reversal, reversal_of_balance_change_id)
             VALUES (:account_id, :output_id, 'seed', :credit, :debit, CURRENT_TIMESTAMP, 10, :is_reversal, :reversal_of)",
            named_params! {
                ":account_id": account_id,
                ":output_id": output_id,
                ":credit": credit,
                ":debit": debit,
                ":is_reversal": reversal_of.is_some(),
                ":reversal_of": reversal_of,
            },
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// A spend of `output_id` with its debit, as base-node verification recorded one; returns (input, debit) ids.
    fn seed_spend(conn: &Connection, account_id: i64, output_id: i64, value: i64, status: &str) -> (i64, i64) {
        conn.execute(
            "INSERT INTO inputs (account_id, output_id, mined_in_block_hash, mined_in_block_height, mined_timestamp)
             VALUES (:account_id, :output_id, x'00', 11, CURRENT_TIMESTAMP)",
            named_params! { ":account_id": account_id, ":output_id": output_id },
        )
        .unwrap();
        let input_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO balance_changes (account_id, caused_by_input_id, description, balance_credit, balance_debit,
                                          effective_date, effective_height)
             VALUES (:account_id, :input_id, 'seed', 0, :value, CURRENT_TIMESTAMP, 11)",
            named_params! { ":account_id": account_id, ":input_id": input_id, ":value": value },
        )
        .unwrap();
        let debit_id = conn.last_insert_rowid();
        conn.execute(
            "UPDATE outputs SET status = :status WHERE id = :id",
            named_params! { ":status": status, ":id": output_id },
        )
        .unwrap();
        (input_id, debit_id)
    }

    fn seed_received_display(conn: &Connection, account_id: i64, id: u64, hashes: &[FixedHash], value: u64) {
        let outputs = hashes
            .iter()
            .map(|hash| TransactionOutput {
                hash: *hash,
                amount: value.into(),
                status: OutputStatus::Unspent,
                mined_in_block_height: 10,
                mined_in_block_hash: FixedHash::zero(),
                output_type: OutputType::Standard,
                is_change: false,
            })
            .collect();
        let display = DisplayedTransactionBuilder::new()
            .account_id(account_id)
            .source(TransactionSource::Transfer)
            .credits_and_debits(value.into(), 0.into())
            .outputs(outputs)
            .build(id.into())
            .unwrap();
        insert_displayed_transaction(conn, &display).unwrap();
    }

    #[test]
    fn migration_37_removes_burn_credits_and_their_received_entries_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = Connection::open(dir.path().join("migrate.db")).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        MIGRATIONS.to_version(&mut conn, 36).unwrap();

        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(CipherSeed::random()).unwrap());
        create_account(&conn, "default", &wallet, "password").unwrap();
        let account_id = get_account_by_name(&conn, "default").unwrap().unwrap().id;

        let burn_hash = FixedHash::from([0xab; 32]);
        let normal_hash = FixedHash::from([0x01; 32]);
        let burn_id = seed_output(&conn, account_id, burn_hash, 7_000, true);
        let normal_id = seed_output(&conn, account_id, normal_hash, 5_000, false);
        // A burn credit that a reorg reversed, then booked again, as the scan used to.
        let reversed = seed_balance_change(&conn, account_id, burn_id, 7_000, 0, None);
        seed_balance_change(&conn, account_id, burn_id, 0, 7_000, Some(reversed));
        seed_balance_change(&conn, account_id, burn_id, 7_000, 0, None);
        let normal_credit = seed_balance_change(&conn, account_id, normal_id, 5_000, 0, None);
        // Stored before `is_burn` existed: a real serialized burn output, and a real standard one, both flagged 0.
        let legacy_burn_hash = FixedHash::from([0xcd; 32]);
        let legacy_normal_hash = FixedHash::from([0x02; 32]);
        let legacy_burn_json = wallet_output_json(3_000, legacy_burn_hash, OutputFeatures::create_burn_output());
        let legacy_normal_json = wallet_output_json(2_000, legacy_normal_hash, OutputFeatures::default());
        let legacy_burn_id =
            seed_output_with_json(&conn, account_id, legacy_burn_hash, 3_000, false, &legacy_burn_json);
        let legacy_normal_id =
            seed_output_with_json(&conn, account_id, legacy_normal_hash, 2_000, false, &legacy_normal_json);
        seed_balance_change(&conn, account_id, legacy_burn_id, 3_000, 0, None);
        let legacy_normal_credit = seed_balance_change(&conn, account_id, legacy_normal_id, 2_000, 0, None);
        // A burn row a backfill left SPENT_UNCONFIRMED and base-node verification then recorded as spent, and a
        // normal output spent the same way, which is kept.
        let spent_burn_id = seed_output(&conn, account_id, FixedHash::from([0xef; 32]), 4_000, true);
        seed_balance_change(&conn, account_id, spent_burn_id, 4_000, 0, None);
        seed_spend(&conn, account_id, spent_burn_id, 4_000, "SPENT_UNCONFIRMED");
        let spent_normal_id = seed_output(&conn, account_id, FixedHash::from([0x03; 32]), 1_000, false);
        let spent_normal_credit = seed_balance_change(&conn, account_id, spent_normal_id, 1_000, 0, None);
        let (spent_normal_input, spent_normal_debit) = seed_spend(&conn, account_id, spent_normal_id, 1_000, "SPENT");
        seed_received_display(&conn, account_id, 4, &[legacy_burn_hash], 3_000);
        seed_received_display(&conn, account_id, 5, &[legacy_normal_hash], 2_000);
        seed_received_display(&conn, account_id, 1, &[burn_hash], 7_000);
        seed_received_display(&conn, account_id, 2, &[normal_hash], 5_000);
        // Not built from a burn credit alone: kept.
        seed_received_display(&conn, account_id, 3, &[burn_hash, normal_hash], 12_000);
        assert_eq!(get_balance(&conn, account_id).unwrap().total, 17_000.into());

        MIGRATIONS.to_latest(&mut conn).unwrap();

        let remaining: Vec<i64> = conn
            .prepare("SELECT id FROM balance_changes")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            remaining,
            vec![
                normal_credit,
                legacy_normal_credit,
                spent_normal_credit,
                spent_normal_debit
            ]
        );
        assert_eq!(get_balance(&conn, account_id).unwrap().total, 7_000.into());

        let displays: Vec<String> = conn
            .prepare("SELECT id FROM displayed_transactions ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(displays, vec!["2".to_string(), "3".to_string(), "5".to_string()]);

        let inputs: Vec<i64> = conn
            .prepare("SELECT id FROM inputs")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(inputs, vec![spent_normal_input], "the burn output's spend is gone");

        let burn_flags: Vec<(i64, bool, String)> = conn
            .prepare("SELECT id, is_burn, status FROM outputs ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            burn_flags,
            vec![
                (burn_id, true, "UNSPENT".to_string()),
                (normal_id, false, "UNSPENT".to_string()),
                (legacy_burn_id, true, "UNSPENT".to_string()),
                (legacy_normal_id, false, "UNSPENT".to_string()),
                (spent_burn_id, true, "UNSPENT".to_string()),
                (spent_normal_id, false, "SPENT".to_string()),
            ],
            "every burn output row is kept and flagged"
        );
        // The legacy rows are otherwise untouched.
        let legacy_json: Vec<String> = conn
            .prepare("SELECT wallet_output_json FROM outputs WHERE id IN (:a, :b) ORDER BY id")
            .unwrap()
            .query_map(named_params! { ":a": legacy_burn_id, ":b": legacy_normal_id }, |row| {
                row.get(0)
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(legacy_json, vec![legacy_burn_json, legacy_normal_json]);
    }
}
