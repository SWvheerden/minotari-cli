// Burn Funds Step Definitions
//
// Step definitions for testing the `burn-funds` CLI command.

use cucumber::{then, when};
use std::process::Command;
use tari_utilities::hex::Hex;

use super::common::MinotariWorld;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Execute `burn-funds` with the given parameters and capture output.
fn execute_burn_funds(world: &mut MinotariWorld, amount: &str, claim_public_key: Option<&str>, base_url: &str) {
    let db_path = world.database_path.as_ref().expect("Database path not set");

    let (program, base_args) = world.get_minotari_command();
    let mut args = base_args;

    args.extend_from_slice(&[
        "--network".to_string(),
        "localnet".to_string(),
        "burn-funds".to_string(),
        "--database-path".to_string(),
        db_path.to_str().unwrap().to_string(),
        "--password".to_string(),
        world.test_password.clone(),
        "--account-name".to_string(),
        "default".to_string(),
        "--amount".to_string(),
        amount.to_string(),
        "--base-url".to_string(),
        base_url.to_string(),
    ]);

    if let Some(cpk) = claim_public_key {
        args.extend_from_slice(&["--claim-public-key".to_string(), cpk.to_string()]);
    }

    // Without TARI_NETWORK the burn only signs for LocalNet if `--network` sets the global network.
    let output = Command::new(&program)
        .args(&args)
        .env_remove("TARI_NETWORK")
        .output()
        .expect("Failed to execute burn-funds command");

    world.last_command_exit_code = output.status.code();
    world.last_command_output = Some(String::from_utf8_lossy(&output.stdout).to_string());
    world.last_command_error = Some(String::from_utf8_lossy(&output.stderr).to_string());
}

// ─────────────────────────────────────────────────────────────────────────────
// When steps
// ─────────────────────────────────────────────────────────────────────────────

#[when(regex = r#"^I try to burn "([^"]*)" microTari$"#)]
async fn try_burn_no_claim_key(world: &mut MinotariWorld, amount: String) {
    // Use a dummy base URL — the command will fail before reaching broadcast
    // because there are no funds to lock. A burn needs a claim public key
    // before it gets as far as locking funds; the wallet's own public spend
    // key stands in for the L2 claim key.
    let claim_public_key = world.wallet.get_public_spend_key().to_hex();
    execute_burn_funds(world, &amount, Some(&claim_public_key), "http://127.0.0.1:1");
}

#[when(regex = r#"^I try to burn "([^"]*)" microTari with claim public key "([^"]*)"$"#)]
async fn try_burn_with_claim_key(world: &mut MinotariWorld, amount: String, claim_public_key: String) {
    execute_burn_funds(world, &amount, Some(&claim_public_key), "http://127.0.0.1:1");
}

#[when(regex = r#"^I burn "([^"]*)" microTari targeting an unreachable base node$"#)]
async fn burn_unreachable_node(world: &mut MinotariWorld, amount: String) {
    // Port 1 is reserved; nothing listens there, so broadcast will fail.
    // However, the burn proof record must be inserted into the DB before the
    // broadcast attempt — this is the durability property being tested.
    // Use the wallet's own public spend key as a stand-in L2 claim public key.
    let claim_public_key = world.wallet.get_public_spend_key().to_hex();
    execute_burn_funds(world, &amount, Some(&claim_public_key), "http://127.0.0.1:1");
}

// ─────────────────────────────────────────────────────────────────────────────
// Then steps
// ─────────────────────────────────────────────────────────────────────────────

#[then("the burn command should fail")]
async fn burn_command_failed(world: &mut MinotariWorld) {
    assert_ne!(
        world.last_command_exit_code,
        Some(0),
        "Expected burn-funds to fail, but it succeeded.\nstdout: {}\nstderr: {}",
        world.last_command_output.as_deref().unwrap_or(""),
        world.last_command_error.as_deref().unwrap_or(""),
    );
}

#[then(regex = r#"^the error output should contain "([^"]*)"$"#)]
async fn error_contains(world: &mut MinotariWorld, expected: String) {
    let stderr = world.last_command_error.as_deref().unwrap_or("");
    let stdout = world.last_command_output.as_deref().unwrap_or("");
    let combined = format!("{stderr}{stdout}");
    assert!(
        combined.to_lowercase().contains(&expected.to_lowercase()),
        "Expected output to contain '{expected}', got:\nstderr: {stderr}\nstdout: {stdout}",
    );
}

#[then("the burn is recorded as pending")]
async fn burn_recorded_as_pending(world: &mut MinotariWorld) {
    let stderr = world.last_command_error.as_deref().unwrap_or("");
    let stdout = world.last_command_output.as_deref().unwrap_or("");

    // A recorded burn is the wallet's to see through: the node not taking it is
    // not an error (an error would invite the user to burn again).
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "Expected burn-funds to record the burn, but it failed:\nstderr: {stderr}\nstdout: {stdout}",
    );
    assert!(
        stdout.contains("Burn transaction recorded, pending"),
        "Expected the burn to be reported as pending, got:\nstderr: {stderr}\nstdout: {stdout}",
    );
}

#[then(regex = r#"^the database should contain a "([^"]*)" burn proof record$"#)]
async fn database_has_burn_proof(world: &mut MinotariWorld, expected_status: String) {
    let db_path = world
        .database_path
        .as_ref()
        .expect("Database path not set")
        .to_str()
        .unwrap()
        .to_string();

    // Open the SQLite DB directly and query the burn_proofs table.
    let conn = rusqlite::Connection::open(&db_path).unwrap_or_else(|e| panic!("Failed to open DB at {db_path}: {e}"));

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM burn_proofs WHERE status = ?1",
            rusqlite::params![expected_status],
            |row| row.get(0),
        )
        .unwrap_or_else(|e| panic!("Failed to query burn_proofs table: {e}"));

    assert!(
        count > 0,
        "Expected at least one burn proof with status '{expected_status}' in the database, found none",
    );
}
