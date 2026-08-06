use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::models::BalanceChange;
use log::debug;
use rusqlite::{Connection, OptionalExtension, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;

pub fn insert_balance_change(conn: &Connection, change: &BalanceChange) -> WalletDbResult<i64> {
    insert_balance_change_inner(conn, change, false)?
        .ok_or_else(|| WalletDbError::Unexpected("Balance change insert affected no rows".to_string()))
}

/// Inserts a balance change unless one already exists for the same output or input.
///
/// Returns `Some(id)` if a row was inserted, `None` if a matching one was already
/// there. Backed by the partial unique indexes on `caused_by_output_id` /
/// `caused_by_input_id` (see migration `00033`), so the check and the insert are one
/// atomic statement rather than a read followed by a write that another writer can
/// slip between.
pub fn insert_balance_change_if_not_exists(conn: &Connection, change: &BalanceChange) -> WalletDbResult<Option<i64>> {
    insert_balance_change_inner(conn, change, true)
}

#[allow(clippy::cast_possible_wrap)]
fn insert_balance_change_inner(
    conn: &Connection,
    change: &BalanceChange,
    ignore_duplicates: bool,
) -> WalletDbResult<Option<i64>> {
    debug!(
        target: "audit",
        account_id = change.account_id,
        credit = &*mask_amount(change.balance_credit),
        debit = &*mask_amount(change.balance_debit),
        is_reversal = change.is_reversal;
        "DB: Inserting balance change"
    );

    let balance_credit = change.balance_credit.as_u64() as i64;
    let balance_debit = change.balance_debit.as_u64() as i64;
    let effective_height = change.effective_height as i64;
    // Unlike the credit/debit above, these two come from the sender-controlled memo and are never validated against
    // the commitment, so they can be any u64. SQLite integers are signed, and a wrapping `as i64` cast would persist a
    // negative that no longer deserialises back into `MicroMinotari`, breaking every later read of this account's
    // balance changes. Saturate instead: these are unverified claims kept for display only, and no real amount comes
    // anywhere near `i64::MAX`.
    let claimed_fee = change
        .claimed_fee
        .map(|v| i64::try_from(v.as_u64()).unwrap_or(i64::MAX));
    let claimed_amount = change
        .claimed_amount
        .map(|v| i64::try_from(v.as_u64()).unwrap_or(i64::MAX));

    let insert_verb = if ignore_duplicates {
        "INSERT OR IGNORE"
    } else {
        "INSERT"
    };

    let sql = format!(
        r#"
       {insert_verb} INTO balance_changes (
         account_id,
         caused_by_output_id,
         caused_by_input_id,
         description,
         balance_credit,
         balance_debit,
         effective_date,
         effective_height,
         claimed_recipient_address,
         claimed_sender_address,
         memo_parsed,
         memo_hex,
         claimed_fee,
         claimed_amount,
         is_reversal,
         reversal_of_balance_change_id,
         is_reversed)
         VALUES (
            :account_id,
            :caused_by_output_id,
            :caused_by_input_id,
            :description,
            :balance_credit,
            :balance_debit,
            :effective_date,
            :effective_height,
            :claimed_recipient_address,
            :claimed_sender_address,
            :memo_parsed,
            :memo_hex,
            :claimed_fee,
            :claimed_amount,
            :is_reversal,
            :reversal_of_balance_change_id,
            :is_reversed
         )
        "#
    );

    let inserted = conn.execute(
        &sql,
        named_params! {
            ":account_id": change.account_id,
            ":caused_by_output_id": change.caused_by_output_id,
            ":caused_by_input_id": change.caused_by_input_id,
            ":description": change.description,
            ":balance_credit": balance_credit,
            ":balance_debit": balance_debit,
            ":effective_date": change.effective_date,
            ":effective_height": effective_height,
            ":claimed_recipient_address": change.claimed_recipient_address.as_ref().map(|v| v.to_base58()),
            ":claimed_sender_address": change.claimed_sender_address.as_ref().map(|v| v.to_base58()),
            ":memo_parsed": change.memo_parsed,
            ":memo_hex": change.memo_hex,
            ":claimed_fee": claimed_fee,
            ":claimed_amount": claimed_amount,
            ":is_reversal": change.is_reversal,
            ":reversal_of_balance_change_id": change.reversal_of_balance_change_id,
            ":is_reversed": change.is_reversed,
        },
    )?;

    if inserted == 0 {
        return Ok(None);
    }

    Ok(Some(conn.last_insert_rowid()))
}

pub fn get_all_balance_changes_by_account_id(conn: &Connection, account_id: i64) -> WalletDbResult<Vec<BalanceChange>> {
    debug!(
        account_id = account_id;
        "DB: Fetching all balance changes"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT 
            account_id,
            caused_by_output_id,
            caused_by_input_id,
            description,
            balance_credit,
            balance_debit,
            REPLACE(effective_date, ' ', 'T') as effective_date,
            effective_height,
            claimed_recipient_address,
            claimed_sender_address,
            memo_parsed,
            memo_hex,
            claimed_fee,
            claimed_amount,
            is_reversal,
            reversal_of_balance_change_id,
            is_reversed
        FROM balance_changes
        WHERE account_id = :account_id
        ORDER BY effective_height ASC, id ASC
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let results: Vec<BalanceChange> = from_rows::<BalanceChange>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

// ignores all balance changes that have been reversed
pub fn get_all_active_balance_changes_by_account_id(
    conn: &Connection,
    account_id: i64,
) -> WalletDbResult<Vec<BalanceChange>> {
    debug!(
        account_id = account_id;
        "DB: Fetching all balance changes"
    );

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            account_id,
            caused_by_output_id,
            caused_by_input_id,
            description,
            balance_credit,
            balance_debit,
            REPLACE(effective_date, ' ', 'T') as effective_date,
            effective_height,
            claimed_recipient_address,
            claimed_sender_address,
            memo_parsed,
            memo_hex,
            claimed_fee,
            claimed_amount,
            is_reversal,
            reversal_of_balance_change_id,
            is_reversed
        FROM balance_changes
        WHERE account_id = :account_id AND is_reversed = FALSE AND is_reversal = FALSE
        ORDER BY effective_height ASC, id ASC
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let results: Vec<BalanceChange> = from_rows::<BalanceChange>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

#[derive(Debug, Default, Deserialize)]
pub struct DbBalanceAggregates {
    pub total_credits: Option<i64>,
    pub total_debits: Option<i64>,
    pub max_height: Option<i64>,
    pub max_date: Option<chrono::NaiveDateTime>,
}

pub fn get_balance_aggregates_for_account(conn: &Connection, account_id: i64) -> WalletDbResult<DbBalanceAggregates> {
    let mut stmt = conn.prepare_cached(
        r#"
            SELECT
              SUM(balance_credit) as total_credits,
              SUM(balance_debit) as total_debits,
              MAX(effective_height) as max_height,
              REPLACE(MAX(effective_date), ' ', 'T') as max_date
            FROM balance_changes
            WHERE account_id = :account_id
        "#,
    )?;

    let rows = stmt.query(named_params! { ":account_id": account_id })?;
    let result = from_rows::<DbBalanceAggregates>(rows)
        .next()
        .ok_or_else(|| WalletDbError::Unexpected("Aggregate query returned no rows".to_string()))??;
    Ok(result)
}

/// Get the balance change ID for an output (non-reversal balance changes only)
pub fn get_balance_change_id_by_output(conn: &Connection, output_id: i64) -> WalletDbResult<Option<i64>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id
        FROM balance_changes
        WHERE caused_by_output_id = :output_id
          AND is_reversal = FALSE
          AND is_reversed = FALSE
        ORDER BY id DESC
        LIMIT 1
        "#,
    )?;

    let id: Option<i64> = stmt
        .query_row(named_params! { ":output_id": output_id }, |row| row.get(0))
        .optional()?;

    Ok(id)
}

/// Get the balance change ID for an input (non-reversal balance changes only)
pub fn get_balance_change_id_by_input(conn: &Connection, input_id: i64) -> WalletDbResult<Option<i64>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id
        FROM balance_changes
        WHERE caused_by_input_id = :input_id
          AND is_reversal = FALSE
          AND is_reversed = FALSE
        ORDER BY id DESC
        LIMIT 1
        "#,
    )?;

    let id: Option<i64> = stmt
        .query_row(named_params! { ":input_id": input_id }, |row| row.get(0))
        .optional()?;

    Ok(id)
}

/// Mark a balance change as reversed
pub fn mark_balance_change_as_reversed(conn: &Connection, balance_change_id: i64) -> WalletDbResult<()> {
    debug!(
        balance_change_id = balance_change_id;
        "DB: Marking balance change as reversed"
    );

    conn.execute(
        r#"
        UPDATE balance_changes
        SET is_reversed = TRUE
        WHERE id = :id
        "#,
        named_params! { ":id": balance_change_id },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db};
    use chrono::Utc;
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::MicroMinotari;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::tempdir;

    fn create_test_account(conn: &Connection) -> i64 {
        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).unwrap());
        create_account(conn, "default", &wallet, "password").unwrap();
        get_account_by_name(conn, "default").unwrap().unwrap().id
    }

    fn credit_change(account_id: i64, claimed_amount: u64, claimed_fee: u64) -> BalanceChange {
        BalanceChange {
            account_id,
            caused_by_output_id: None,
            caused_by_input_id: None,
            description: "test".to_string(),
            balance_credit: MicroMinotari::from(1),
            balance_debit: MicroMinotari::from(0),
            effective_date: Utc::now().naive_utc(),
            effective_height: 50,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: Some(MicroMinotari::from(claimed_fee)),
            claimed_amount: Some(MicroMinotari::from(claimed_amount)),
            is_reversal: false,
            reversal_of_balance_change_id: None,
            is_reversed: false,
        }
    }

    fn stored_claims(conn: &Connection, id: i64) -> (i64, i64) {
        conn.query_row(
            "SELECT claimed_amount, claimed_fee FROM balance_changes WHERE id = :id",
            named_params! { ":id": id },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read back claims")
    }

    /// Creates a real outputs+inputs row pair and returns the input id.
    ///
    /// `balance_changes.caused_by_input_id` is a foreign key, so the tests need an
    /// input that actually exists.
    fn seed_spent_output(conn: &Connection, account_id: i64, marker: u8) -> i64 {
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash, value,
                mined_timestamp, wallet_output_json, is_burn, maturity
            ) VALUES (
                :account_id, :tx_id, :output_hash, 10, :block_hash, 1000,
                :mined_ts, '{}', 0, 0
            )
            "#,
            named_params! {
                ":account_id": account_id,
                ":tx_id": i64::from(marker),
                ":output_hash": vec![marker; 32],
                ":block_hash": vec![marker; 32],
                ":mined_ts": Utc::now(),
            },
        )
        .expect("insert output");
        let output_id = conn.last_insert_rowid();

        conn.execute(
            r#"
            INSERT INTO inputs (account_id, output_id, mined_in_block_height, mined_in_block_hash, mined_timestamp)
            VALUES (:account_id, :output_id, 11, :block_hash, :mined_ts)
            "#,
            named_params! {
                ":account_id": account_id,
                ":output_id": output_id,
                ":block_hash": vec![marker; 32],
                ":mined_ts": Utc::now(),
            },
        )
        .expect("insert input");
        conn.last_insert_rowid()
    }

    fn change_for_input(account_id: i64, input_id: i64, debit: u64) -> BalanceChange {
        BalanceChange {
            account_id,
            caused_by_output_id: None,
            caused_by_input_id: Some(input_id),
            description: "Output spent as input".to_string(),
            balance_credit: MicroMinotari::from(0),
            balance_debit: MicroMinotari::from(debit),
            effective_date: Utc::now().naive_utc(),
            effective_height: 10,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: None,
            claimed_amount: None,
            is_reversal: false,
            reversal_of_balance_change_id: None,
            is_reversed: false,
        }
    }

    #[test]
    fn one_input_debits_the_balance_exactly_once() {
        // The scanner can present the same spend more than once — a repeated input hash
        // in a block, a re-scanned block on the next poll cycle, the backfill pass. Each
        // repeat previously appended another full-value debit, so the reported balance
        // fell every time the same spend was seen again.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("dupes.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);
        let input_id = seed_spent_output(&conn, account_id, 1);

        let first =
            insert_balance_change_if_not_exists(&conn, &change_for_input(account_id, input_id, 1_000)).expect("insert");
        assert!(first.is_some(), "the first debit is recorded");

        for _ in 0..5 {
            let repeat = insert_balance_change_if_not_exists(&conn, &change_for_input(account_id, input_id, 1_000))
                .expect("repeat insert");
            assert!(repeat.is_none(), "a repeated spend must not be recorded again");
        }

        let total_debits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(balance_debit), 0) FROM balance_changes WHERE account_id = :id",
                named_params! { ":id": account_id },
                |row| row.get(0),
            )
            .expect("sum debits");
        assert_eq!(
            total_debits, 1_000,
            "the spend must be debited once, not once per sighting"
        );
    }

    #[test]
    fn the_schema_refuses_a_second_debit_for_the_same_input() {
        // The idempotent helper is the first line of defence; the unique index is what
        // makes the invariant hold even for a caller that reaches for the plain insert.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("dupes_index.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);
        let input_id = seed_spent_output(&conn, account_id, 2);

        insert_balance_change(&conn, &change_for_input(account_id, input_id, 500)).expect("first insert");
        insert_balance_change(&conn, &change_for_input(account_id, input_id, 500))
            .expect_err("a second debit for the same input is a constraint violation");
    }

    #[test]
    fn hostile_claimed_amount_is_never_stored_negative() {
        // `claimed_amount`/`claimed_fee` are copied out of a sender-controlled memo without validation, so they can be
        // any u64. SQLite integers are signed, so a wrapping cast would persist a negative — a value that is not a
        // valid `MicroMinotari` and that no reader can make sense of.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("claims.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        let hostile = insert_balance_change(&conn, &credit_change(account_id, u64::MAX, u64::MAX)).expect("insert");
        assert_eq!(stored_claims(&conn, hostile), (i64::MAX, i64::MAX));

        // Ordinary claims are still stored exactly.
        let ordinary = insert_balance_change(&conn, &credit_change(account_id, 1_234, 56)).expect("insert");
        assert_eq!(stored_claims(&conn, ordinary), (1_234, 56));
    }
}
