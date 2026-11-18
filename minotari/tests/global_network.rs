//! Its own test binary: the process-global network can be set only once per process.

use minotari::config::{
    defaults::WalletConfig,
    loader::{load_configuration, set_global_network},
};
use tari_common::{DefaultConfigLoader, configuration::Network};

#[test]
fn the_cli_network_becomes_the_process_global_network() {
    let dir = tempfile::tempdir().unwrap();
    let config = load_configuration(&dir.path().join("config.toml"), Some(Network::LocalNet)).unwrap();
    let wallet_config = WalletConfig::load_from(&config).unwrap();

    set_global_network(wallet_config.network).unwrap();
    assert_eq!(Network::get_current(), Network::LocalNet);

    let err = set_global_network(Network::Esmeralda).unwrap_err();
    assert!(err.to_string().contains("already set to localnet"), "{err}");
}

/// Only `main`'s startup network check can refuse mainnet on a testnet-target build, so this
/// fails if `main` stops applying the resolved network.
#[test]
fn the_binary_refuses_a_network_invalid_for_its_build() {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_minotari"))
        .current_dir(dir.path())
        .env_remove("TARI_NETWORK")
        .args(["--network", "mainnet", "balance", "--database-path", "wallet.db"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("invalid for this binary built for TestNet"), "{stderr}");
}
