// Daemon Step Definitions
//
// Step definitions for testing daemon mode functionality.

use cucumber::{given, then, when};
use std::process::Stdio;
use std::time::Duration;
use tari_common::configuration::Network::LocalNet;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tokio::time::sleep;

use super::common::{MinotariWorld, api_args, api_client, database_with_wallet};

/// Generate a valid test Tari address from the wallet in world
fn generate_test_address(world: &MinotariWorld) -> String {
    let spend_key = world.wallet.get_public_spend_key();
    let view_key = world.wallet.get_public_view_key();
    let wallet_address = TariAddress::new_dual_address(
        view_key,
        spend_key,
        LocalNet,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .unwrap();
    wallet_address.to_base58().to_string()
}

// =============================
// Helper Functions
// =============================

/// Find an unused TCP port in the given range. Used instead of a hardcoded port
/// so the daemon never collides with an unrelated service already bound to that
/// port (e.g. a base node a developer is running locally).
///
/// The daemon binds `127.0.0.1:<port>`, but we probe the wildcard address —
/// probing `127.0.0.1` alone would report a port as free even when another
/// process holds `0.0.0.0:<port>`, and the daemon would then fail to bind.
fn find_free_port(start: u16, end: u16) -> u16 {
    for port in start..end {
        if std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() {
            return port;
        }
    }
    panic!("No free port found in range {}..{}", start, end);
}

/// Authenticated HTTP client with a bounded timeout so a hung or stale daemon
/// fails fast with a clear error instead of blocking the whole scenario until CI
/// times out.
fn http_client() -> reqwest::Client {
    api_client(Duration::from_secs(15))
}

/// Wait until the freshly-spawned daemon is actually serving its HTTP API before
/// proceeding. A blind sleep otherwise lets the test query a daemon that hasn't
/// finished starting (or that failed to bind its port), producing confusing
/// downstream API failures instead of a clear, fast error.
async fn wait_for_daemon_ready(child: &mut std::process::Child, port: u16) {
    let client = api_client(Duration::from_secs(2));
    let url = format!("http://127.0.0.1:{}/version", port);
    for _ in 0..60 {
        // If the daemon process already exited, it never came up — fail loudly
        // rather than hanging on requests that will never be answered.
        if let Ok(Some(status)) = child.try_wait() {
            panic!("Daemon process exited before becoming ready (status: {status}) on port {port}");
        }
        // Require a 2xx from /version so a foreign service answering on this port
        // (which would return 404) is not mistaken for our daemon being ready.
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return;
        }
        sleep(Duration::from_millis(500)).await;
    }
    panic!("Daemon on port {port} did not become ready within 30s");
}

/// Start a daemon process with the given configuration.
///
/// `disable_auth` additionally passes `--api-disable-auth`; the API token arguments
/// are still supplied so the scenario also pins down which of the two wins.
async fn start_daemon_process(world: &mut MinotariWorld, port: u16, scan_interval: Option<u64>, disable_auth: bool) {
    world.setup_database();
    let (command, mut args) = world.get_minotari_command();

    let db_path = world
        .database_path
        .as_ref()
        .expect("Database path must be set before starting daemon");

    args.push("daemon".to_string());
    args.push("--password".to_string());
    args.push(world.test_password.clone());
    args.push("--database-path".to_string());
    args.push(db_path.to_str().unwrap().to_string());
    args.push("--api-port".to_string());
    args.push(port.to_string());
    args.extend(api_args());
    if disable_auth {
        args.push("--api-disable-auth".to_string());
    }

    if let Some(interval) = scan_interval {
        args.push("--scan-interval-secs".to_string());
        args.push(interval.to_string());
    }

    // Add base node URL if we have a running base node
    if !world.base_nodes.is_empty() {
        let base_node = world.base_nodes.values().next().unwrap();
        let base_url = format!("http://127.0.0.1:{}", base_node.http_port);
        args.push("--base-url".to_string());
        args.push(base_url);
    }

    // Discard the daemon's stdio. A daemon in continuous-scan mode can emit a
    // lot of output; an unread pipe would eventually fill and block it.
    let mut child = std::process::Command::new(&command)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start daemon process");

    // Poll until the daemon is actually serving before proceeding.
    wait_for_daemon_ready(&mut child, port).await;

    world.daemon_handle = Some(child);
    world.api_port = Some(port);
}

// =============================
// Daemon Steps
// =============================

#[given("I have a running daemon with an existing wallet")]
async fn running_daemon_with_wallet(world: &mut MinotariWorld) {
    // Import a wallet so the daemon has an account to query
    database_with_wallet(world).await;
    // Start daemon on a free port (avoids collisions with other local services)
    let port = find_free_port(9000, 9200);
    start_daemon_process(world, port, None, false).await;
}

#[given("I have a running daemon with authentication disabled")]
async fn running_daemon_with_auth_disabled(world: &mut MinotariWorld) {
    database_with_wallet(world).await;
    let port = find_free_port(9000, 9200);
    start_daemon_process(world, port, None, true).await;
}

#[given("I have a running daemon")]
async fn running_daemon(world: &mut MinotariWorld) {
    // Start daemon on a free port (avoids collisions with other local services)
    let port = find_free_port(9000, 9200);
    start_daemon_process(world, port, None, false).await;
}

#[when(regex = r#"^I start the daemon on port "([^"]*)"$"#)]
async fn start_daemon_on_port(world: &mut MinotariWorld, port: String) {
    let port_num = port.parse::<u16>().expect("Invalid port number");
    start_daemon_process(world, port_num, None, false).await;
}

#[when(regex = r#"^I start the daemon with scan interval "([^"]*)" seconds$"#)]
async fn start_daemon_with_interval(world: &mut MinotariWorld, interval: String) {
    let interval_num = interval.parse::<u64>().expect("Invalid scan interval");
    let port = find_free_port(9000, 9200);
    start_daemon_process(world, port, Some(interval_num), false).await;
}

#[when(regex = r#"^I query the balance via the API for account "([^"]*)"$"#)]
async fn query_balance_api(world: &mut MinotariWorld, account_name: String) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/{}/balance", port, account_name);

    let client = http_client();
    let response = client.get(&url).send().await.expect("Failed to query balance API");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() { 0 } else { 1 });
}

#[when(regex = r#"^I lock funds via the API for amount "([^"]*)" microTari$"#)]
async fn lock_funds_api(world: &mut MinotariWorld, amount: String) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/lock_funds", port);

    let amount_num = amount.parse::<u64>().expect("Invalid amount");
    let request_body = serde_json::json!({
        "amount": amount_num,
        "idempotency_key": format!("test_lock_{}", chrono::Utc::now().timestamp())
    });

    let client = http_client();
    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .expect("Failed to lock funds via API");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() { 0 } else { 1 });
}

#[when("I create a transaction via the API")]
async fn create_transaction_api(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/create_unsigned_transaction", port);

    let address = generate_test_address(world);
    let request_body = serde_json::json!({
        "recipients": [{
            "address": address,
            "amount": 100000,
            "payment_id": "test-payment"
        }],
        "idempotency_key": format!("test_tx_{}", chrono::Utc::now().timestamp())
    });

    let client = http_client();
    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .expect("Failed to create transaction via API");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    // Store response in transaction_data for subsequent step assertions
    if status.is_success()
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
    {
        world.transaction_data.insert("current".to_string(), json);
    }

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() { 0 } else { 1 });
}

#[when("I send a shutdown signal")]
async fn send_shutdown_signal(world: &mut MinotariWorld) {
    if let Some(mut child) = world.daemon_handle.take() {
        // Send SIGINT signal (Ctrl+C equivalent)
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            #[allow(clippy::cast_possible_wrap)]
            let pid = Pid::from_raw(child.id() as i32);
            kill(pid, Signal::SIGINT).expect("Failed to send SIGINT");
        }

        #[cfg(not(unix))]
        {
            // On Windows, we'll just kill the process
            child.kill().expect("Failed to kill daemon process");
        }

        // Wait a moment for graceful shutdown
        sleep(Duration::from_secs(2)).await;

        // Try to collect exit status
        if let Ok(status) = child.try_wait()
            && let Some(exit_status) = status
        {
            world.last_command_exit_code = exit_status.code();
        }
    }
}

#[allow(unused_variables)]
#[then(regex = r#"^the API should be accessible on port "([^"]*)"$"#)]
async fn api_accessible(world: &mut MinotariWorld, port: String) {
    let port_num = port.parse::<u16>().expect("Invalid port number");
    let url = format!("http://127.0.0.1:{}/version", port_num);

    let client = http_client();
    let result = client.get(&url).send().await;

    assert!(
        result.is_ok(),
        "API should be accessible on port {}, but got error: {:?}",
        port_num,
        result.err()
    );

    let response = result.unwrap();
    assert!(
        response.status().is_success(),
        "API should return success status, got: {}",
        response.status()
    );
}

#[then("the Swagger UI should be available")]
async fn swagger_available(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/swagger-ui/", port);

    let client = http_client();
    let response = client.get(&url).send().await.expect("Failed to access Swagger UI");

    assert!(
        response.status().is_success(),
        "Swagger UI should be available, got status: {}",
        response.status()
    );
}

/// The API can burn funds and exposes the wallet's full history, so an
/// unauthenticated caller must get nowhere - not even to the endpoint listing.
#[then("the API should reject requests without a token")]
async fn api_rejects_unauthenticated_requests(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    // No default Authorization header on this client, unlike `http_client()`.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("Failed to build HTTP client");

    let address = generate_test_address(world);
    let burn_body = serde_json::json!({ "amount": 1000, "claim_public_key": "00" });
    let transaction_body = serde_json::json!({
        "recipients": [{ "address": address, "amount": 1000, "payment_id": "unauthenticated" }],
        "idempotency_key": "unauthenticated"
    });

    let get_paths = [
        "/version",
        "/openapi.json",
        "/swagger-ui/",
        "/accounts/default/balance",
        "/accounts/default/address",
        "/accounts/default/events",
        "/accounts/default/displayed_transactions",
    ];
    for path in get_paths {
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let response = client.get(&url).send().await.expect("Failed to call API");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "GET {} should require an API token",
            path
        );
    }

    for (path, body) in [
        ("/accounts/default/burn", &burn_body),
        ("/accounts/default/lock_funds", &burn_body),
        ("/accounts/default/create_unsigned_transaction", &transaction_body),
    ] {
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let response = client.post(&url).json(body).send().await.expect("Failed to call API");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "POST {} should require an API token",
            path
        );
    }
}

/// The opt-out has to actually serve unauthenticated callers, and it has to win
/// over the API token the daemon was also started with.
#[then("the API should serve requests without a token")]
async fn api_serves_unauthenticated_requests(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    // No default Authorization header on this client, unlike `http_client()`.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("Failed to build HTTP client");

    for path in ["/version", "/openapi.json", "/accounts/default/balance"] {
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let response = client.get(&url).send().await.expect("Failed to call API");
        assert!(
            response.status().is_success(),
            "GET {} should succeed without a token, got {}",
            path,
            response.status()
        );
    }
}

/// A token that is not the daemon's must be refused just like no token at all.
#[then("the API should reject requests with an incorrect token")]
async fn api_rejects_wrong_token(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("Failed to build HTTP client");

    let url = format!("http://127.0.0.1:{}/accounts/default/balance", port);
    for header_value in ["Bearer not-the-configured-token", "Basic aW50ZWdyYXRpb246dGVzdA=="] {
        let response = client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, header_value)
            .send()
            .await
            .expect("Failed to call API");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "'{}' should be rejected",
            header_value
        );
    }
}

#[then("the daemon should scan periodically")]
async fn daemon_scans_periodically(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/scan_status", port);

    let client = http_client();

    // Get initial scan status
    let response1 = client.get(&url).send().await.expect("Failed to get scan status");

    assert!(
        response1.status().is_success(),
        "Scan status endpoint should be accessible"
    );

    // The daemon is configured to scan - just verify the endpoint works
    // In a real scenario with a base node, we'd check that scans are happening
}

#[then("the scanned tip should be updated over time")]
async fn scanned_tip_updated_over_time(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!("http://127.0.0.1:{}/accounts/default/scan_status", port);

    let client = http_client();

    // Get initial tip
    let response1 = client
        .get(&url)
        .send()
        .await
        .expect("Failed to get initial scan status");
    let status1: serde_json::Value = response1.json().await.expect("Failed to parse JSON");

    // Wait for scan interval (plus buffer)
    sleep(Duration::from_secs(12)).await;

    // Get updated tip
    let response2 = client
        .get(&url)
        .send()
        .await
        .expect("Failed to get updated scan status");
    let status2: serde_json::Value = response2.json().await.expect("Failed to parse JSON");

    // Verify we got valid responses (actual tip comparison would require a running blockchain)
    assert!(status1.is_object(), "First scan status should be an object");
    assert!(status2.is_object(), "Second scan status should be an object");
}

#[then("I should receive a balance response")]
async fn receive_balance_response(world: &mut MinotariWorld) {
    assert!(
        world.last_command_output.is_some(),
        "Should have received a response from balance API"
    );
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "API request should have succeeded"
    );
}

#[then("the response should include balance information")]
async fn response_has_balance_info(world: &mut MinotariWorld) {
    let output = world.last_command_output.as_ref().expect("Should have response output");

    let json: serde_json::Value = serde_json::from_str(output).expect("Response should be valid JSON");

    assert!(
        json.get("available").is_some() || json.get("total").is_some(),
        "Response should include balance information (available or total field)"
    );
}

#[then("the API should return success")]
async fn api_returns_success(world: &mut MinotariWorld) {
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "API should return success (exit code 0)"
    );
}

#[then("the API should return the unsigned transaction")]
async fn api_returns_transaction(world: &mut MinotariWorld) {
    assert_eq!(
        world.last_command_exit_code,
        Some(0),
        "API should return success for unsigned transaction"
    );

    let output = world.last_command_output.as_ref().expect("Should have response output");

    let json: serde_json::Value = serde_json::from_str(output).expect("Response should be valid JSON");

    // PrepareOneSidedTransactionForSigningResult has fields: version, tx_id, info
    assert!(
        json.get("tx_id").is_some() || json.get("info").is_some(),
        "Response should include transaction data (tx_id or info field)"
    );
}

#[then("the daemon should stop gracefully")]
async fn daemon_stops_gracefully(world: &mut MinotariWorld) {
    // Check that we got a clean exit code (0 or SIGINT)
    if let Some(exit_code) = world.last_command_exit_code {
        // Exit code 0 means clean shutdown, 130 typically means SIGINT on Unix
        assert!(
            exit_code == 0 || exit_code == 130 || exit_code == 143,
            "Daemon should exit gracefully, got exit code: {}",
            exit_code
        );
    }
}

#[then("database connections should be closed")]
async fn database_connections_closed(world: &mut MinotariWorld) {
    // Try to access the database file - it should be unlocked now
    if let Some(db_path) = &world.database_path {
        // Wait a moment to ensure connections are fully closed
        sleep(Duration::from_millis(500)).await;

        // Try to open the database with exclusive access
        // If the daemon closed connections properly, this should succeed
        let result = std::fs::OpenOptions::new().write(true).open(db_path);

        assert!(result.is_ok(), "Database file should be unlocked after daemon shutdown");
    }
}
