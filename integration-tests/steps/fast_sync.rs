// Fast Sync Step Definitions
//
// Step definitions for testing fast sync scanning functionality,
// including performance comparisons and balance correctness.

use cucumber::{then, when};
use minotari::db;
use minotari::scan::{ScanMode, Scanner};
use std::time::Instant;
use tari_common::configuration::Network::LocalNet;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_transaction_components::key_manager::wallet_types::WalletType;

use super::common::MinotariWorld;

/// Safety buffer used for fast sync tests. Small enough to exercise the
/// fast sync phases even with short test chains.
const TEST_FAST_SYNC_SAFETY_BUFFER: u64 = 5;

// =============================
// Scan Execution Steps
// =============================

#[when("I perform a fast sync without backfill")]
async fn perform_fast_sync_no_backfill(world: &mut MinotariWorld) {
    let db_path = world.database_path.as_ref().expect("Database not set up");
    let base_url = get_base_url(world);

    let scanner = Scanner::new(&world.test_password, &base_url, db_path.clone(), 120, 3)
        .mode(ScanMode::FastSync {
            safety_buffer: TEST_FAST_SYNC_SAFETY_BUFFER,
        })
        .account("default");

    let result = scanner.run().await;
    match &result {
        Ok((events, _)) => {
            world.last_command_exit_code = Some(0);
            world.last_command_output = Some(format!("Fast sync completed with {} events", events.len()));
            println!("Fast sync completed: {} events", events.len());
        },
        Err(e) => {
            world.last_command_exit_code = Some(1);
            world.last_command_error = Some(format!("{}", e));
            println!("Fast sync failed: {}", e);
        },
    }
}

#[when("I perform a backfill scan")]
async fn perform_backfill(world: &mut MinotariWorld) {
    let db_path = world.database_path.as_ref().expect("Database not set up");
    let base_url = get_base_url(world);

    // Get the current tip to determine backfill_to_height
    let tip_client = minotari::http::WalletHttpClient::new(base_url.parse().unwrap()).unwrap();
    let tip = tip_client.get_tip_info().await.expect("Failed to get tip");
    let tip_height = tip.metadata.as_ref().map(|m| m.best_block_height()).unwrap_or(0);
    let backfill_to = tip_height.saturating_sub(TEST_FAST_SYNC_SAFETY_BUFFER);

    let scanner = Scanner::new(&world.test_password, &base_url, db_path.clone(), 100, 3).account("default");

    let result = scanner.run_backfill(backfill_to).await;
    match &result {
        Ok((events, _)) => {
            world.last_command_exit_code = Some(0);
            world.last_command_output = Some(format!("Backfill completed with {} events", events.len()));
            println!("Backfill completed: {} events", events.len());
        },
        Err(e) => {
            world.last_command_exit_code = Some(1);
            world.last_command_error = Some(format!("{}", e));
            println!("Backfill failed: {}", e);
        },
    }
}

#[when("I perform a normal full scan")]
async fn perform_normal_full_scan(world: &mut MinotariWorld) {
    let db_path = world.database_path.as_ref().expect("Database not set up");
    let base_url = get_base_url(world);

    let scanner = Scanner::new(&world.test_password, &base_url, db_path.clone(), 100, 3)
        .mode(ScanMode::Full)
        .account("default");

    let result = scanner.run().await;
    match &result {
        Ok((events, _)) => {
            world.last_command_exit_code = Some(0);
            world.last_command_output = Some(format!("Normal scan completed with {} events", events.len()));
            println!("Normal scan completed: {} events", events.len());
        },
        Err(e) => {
            world.last_command_exit_code = Some(1);
            world.last_command_error = Some(format!("{}", e));
            println!("Normal scan failed: {}", e);
        },
    }
}

// =============================
// Mining to a different address (no wallet outputs)
// =============================

#[when(expr = "I mine {int} blocks on {word} to a different address")]
async fn mine_blocks_to_different_address(world: &mut MinotariWorld, num_blocks: u64, node_name: String) {
    let node = world
        .base_nodes
        .get(&node_name)
        .unwrap_or_else(|| panic!("Node {} not found", node_name));

    // Create a completely separate wallet address for mining rewards
    // so the test wallet receives no funds
    let other_wallet = WalletType::new_random().expect("Failed to create random wallet");
    let other_address = TariAddress::new_dual_address(
        other_wallet.get_public_view_key(),
        other_wallet.get_public_spend_key(),
        LocalNet,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .unwrap();

    node.mine_blocks(num_blocks, &other_address)
        .await
        .expect("Failed to mine blocks");

    let height = node.get_tip_height().await.expect("Failed to get tip height");
    println!(
        "Mined {} blocks on {} to different address, height: {}",
        num_blocks, node_name, height
    );
}

// =============================
// Performance Measurement Steps
// =============================

#[when("I measure the time for a normal full scan")]
async fn measure_normal_scan(world: &mut MinotariWorld) {
    let start = Instant::now();
    perform_normal_full_scan(world).await;
    let duration = start.elapsed();

    println!("Normal full scan completed in {:?}", duration);
    world.benchmark_timings.insert("normal_scan".to_string(), duration);
}

#[when("I measure the time for a fast sync without backfill")]
async fn measure_fast_sync_no_backfill(world: &mut MinotariWorld) {
    let start = Instant::now();
    perform_fast_sync_no_backfill(world).await;
    let duration = start.elapsed();

    println!("Fast sync (no backfill) completed in {:?}", duration);
    world.benchmark_timings.insert("fast_sync".to_string(), duration);
}

#[when("I measure the time for a fast sync with backfill")]
async fn measure_fast_sync_with_backfill(world: &mut MinotariWorld) {
    let start = Instant::now();
    perform_fast_sync_no_backfill(world).await;
    perform_backfill(world).await;
    let duration = start.elapsed();

    println!("Fast sync + backfill completed in {:?}", duration);
    world
        .benchmark_timings
        .insert("fast_sync_with_backfill".to_string(), duration);
}

// =============================
// Database Reset Steps
// =============================

#[when("I reset the wallet database")]
async fn reset_wallet_database(world: &mut MinotariWorld) {
    let db_path = world.database_path.as_ref().expect("Database not set up").clone();

    // Delete and recreate the database, then re-import the wallet
    std::fs::remove_file(&db_path).ok();

    let (cmd, mut args) = world.get_minotari_command();
    args.extend_from_slice(&[
        "import-view-key".to_string(),
        "--view-private-key".to_string(),
        tari_utilities::hex::Hex::to_hex(world.wallet.get_view_key()),
        "--spend-public-key".to_string(),
        tari_utilities::hex::Hex::to_hex(&world.wallet.get_public_spend_key()),
        "--password".to_string(),
        world.test_password.clone(),
        "--database-path".to_string(),
        db_path.to_str().unwrap().to_string(),
    ]);

    let output = std::process::Command::new(&cmd)
        .args(&args)
        .output()
        .expect("Failed to re-import wallet");

    assert!(output.status.success(), "Failed to reset wallet database");
    println!("Wallet database reset and wallet re-imported");
}

#[when("I reset the wallet database keeping account")]
async fn reset_wallet_database_keeping_account(world: &mut MinotariWorld) {
    let db_path = world.database_path.as_ref().expect("Database not set up").clone();

    // Delete scanning state but keep the account
    let pool = db::init_db(db_path).expect("Failed to init db");
    let conn = pool.get().expect("Failed to get connection");

    // Clear wallet state in FK-safe order:
    // balance_changes references outputs and inputs
    // inputs references outputs
    // completed_transactions references pending_transactions
    conn.execute_batch(
        "DELETE FROM displayed_transactions;
         DELETE FROM completed_transactions;
         DELETE FROM balance_changes;
         DELETE FROM events;
         DELETE FROM inputs;
         DELETE FROM outputs;
         DELETE FROM scanned_tip_blocks;
         DELETE FROM pending_transactions;
         DELETE FROM burn_proofs;",
    )
    .expect("Failed to clear wallet state");

    println!("Wallet state cleared (account kept)");
}

// =============================
// Assertion Steps
// =============================

#[then("the fast sync should complete successfully")]
async fn fast_sync_succeeds(world: &mut MinotariWorld) {
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "Fast sync/backfill failed: {}",
        world.last_command_error.as_deref().unwrap_or("unknown error")
    );
}

#[then("the fast sync balance should be zero")]
async fn fast_sync_balance_is_zero(world: &mut MinotariWorld) {
    let balance = world.fetch_balance();
    println!("Balance after fast sync: {} µT", balance);
    assert_eq!(balance, 0, "Expected zero balance after fast sync, got {}", balance);
}

#[then(regex = r"^the fast sync balance should be at least (\d+) microTari$")]
async fn fast_sync_balance_at_least(world: &mut MinotariWorld, minimum: u64) {
    let balance = world.fetch_balance();
    println!(
        "Balance after fast sync: {} µT (expected at least {} µT)",
        balance, minimum
    );

    // Also print DB diagnostics for debugging
    if let Some(db_path) = &world.database_path
        && let Ok(pool) = db::init_db(db_path.clone())
        && let Ok(conn) = pool.get()
    {
        let accounts = db::get_accounts(&conn, Some("default")).unwrap_or_default();
        if let Some(account) = accounts.first() {
            if let Ok(bal) = db::get_balance(&conn, account.id) {
                println!(
                    "  DB balance detail: total={}, available={}, locked={}, unconfirmed={}, credits={:?}, debits={:?}",
                    bal.total, bal.available, bal.locked, bal.unconfirmed, bal.total_credits, bal.total_debits
                );
            }

            // Count outputs by status
            let output_counts: String = conn
                        .query_row(
                            "SELECT GROUP_CONCAT(status || ':' || cnt) FROM (SELECT status, COUNT(*) as cnt FROM outputs WHERE account_id = ?1 AND deleted_at IS NULL GROUP BY status)",
                            [account.id],
                            |row| row.get(0),
                        )
                        .unwrap_or_else(|_| "error".to_string());
            println!("  Output counts by status: {}", output_counts);
        }
    }

    assert!(
        balance >= minimum,
        "Expected balance at least {} microTari after fast sync, got {}",
        minimum,
        balance
    );
}

#[then("the fast sync and normal scan should complete in similar time")]
async fn fast_sync_similar_time(world: &mut MinotariWorld) {
    let normal = world
        .benchmark_timings
        .get("normal_scan")
        .expect("Normal scan timing not recorded");
    let fast = world
        .benchmark_timings
        .get("fast_sync")
        .expect("Fast sync timing not recorded");

    println!("Normal scan: {:?}", normal);
    println!("Fast sync:   {:?}", fast);

    // With no spent outputs, both should take roughly the same time.
    // Allow fast sync to be up to 3x slower due to phase overhead on small chains.
    let ratio = fast.as_secs_f64() / normal.as_secs_f64().max(0.001);
    println!("Ratio (fast/normal): {:.2}x", ratio);
    assert!(
        ratio < 3.0,
        "Fast sync ({:?}) took more than 3x longer than normal scan ({:?}) with no spent outputs",
        fast,
        normal
    );
}

#[then("the fast sync should be faster than the normal scan")]
async fn fast_sync_is_faster(world: &mut MinotariWorld) {
    let normal = world
        .benchmark_timings
        .get("normal_scan")
        .expect("Normal scan timing not recorded");
    let fast = world
        .benchmark_timings
        .get("fast_sync")
        .expect("Fast sync timing not recorded");

    println!("Normal scan: {:?}", normal);
    println!("Fast sync:   {:?}", fast);
    println!(
        "Speedup:     {:.1}x",
        normal.as_secs_f64() / fast.as_secs_f64().max(0.001)
    );

    assert!(
        fast <= normal,
        "Fast sync ({:?}) should be faster than or equal to normal scan ({:?})",
        fast,
        normal
    );
}

#[then("I print the fast sync benchmark results")]
async fn print_fast_sync_benchmarks(world: &mut MinotariWorld) {
    println!("\n========================================");
    println!("     FAST SYNC BENCHMARK RESULTS");
    println!("========================================");

    if let Some(normal) = world.benchmark_timings.get("normal_scan") {
        println!("  Normal scan:             {:?}", normal);
    }
    if let Some(fast) = world.benchmark_timings.get("fast_sync") {
        println!("  Fast sync (no backfill): {:?}", fast);
    }
    if let Some(fast_bf) = world.benchmark_timings.get("fast_sync_with_backfill") {
        println!("  Fast sync + backfill:    {:?}", fast_bf);
    }

    if let (Some(normal), Some(fast)) = (
        world.benchmark_timings.get("normal_scan"),
        world.benchmark_timings.get("fast_sync"),
    ) {
        println!(
            "  Speedup (no backfill):   {:.1}x",
            normal.as_secs_f64() / fast.as_secs_f64().max(0.001)
        );
    }

    if let (Some(normal), Some(fast_bf)) = (
        world.benchmark_timings.get("normal_scan"),
        world.benchmark_timings.get("fast_sync_with_backfill"),
    ) {
        println!(
            "  Speedup (with backfill): {:.1}x",
            normal.as_secs_f64() / fast_bf.as_secs_f64().max(0.001)
        );
    }

    println!("========================================\n");
}

// =============================
// Helpers
// =============================

fn get_base_url(world: &MinotariWorld) -> String {
    if let Some((_, node)) = world.base_nodes.iter().next() {
        format!("http://127.0.0.1:{}", node.http_port)
    } else {
        panic!("No base node available for scanning");
    }
}
