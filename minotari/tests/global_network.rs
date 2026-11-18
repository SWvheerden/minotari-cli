//! Its own test binary: the process-global network can be set only once per process.

use minotari::config::{
    defaults::WalletConfig,
    loader::{load_configuration, set_global_network},
};
use tari_common::{DefaultConfigLoader, configuration::Network, network_check::is_network_choice_valid};

const NETWORKS: [Network; 6] = [
    Network::MainNet,
    Network::StageNet,
    Network::NextNet,
    Network::LocalNet,
    Network::Igor,
    Network::Esmeralda,
];

fn networks_valid_for_this_build(valid: bool) -> impl Iterator<Item = Network> {
    NETWORKS
        .into_iter()
        .filter(move |n| is_network_choice_valid(*n).is_ok() == valid)
}

#[test]
fn the_cli_network_becomes_the_process_global_network() {
    let mut valid = networks_valid_for_this_build(true);
    let network = valid.next().unwrap();
    // A nextnet build supports one network only, so the later one is then also refused as invalid.
    let other = valid
        .next()
        .or_else(|| networks_valid_for_this_build(false).next())
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = load_configuration(&dir.path().join("config.toml"), Some(network)).unwrap();
    let wallet_config = WalletConfig::load_from(&config).unwrap();

    set_global_network(wallet_config.network).unwrap();
    assert_eq!(Network::get_current(), network);

    set_global_network(other).unwrap_err();
    assert_eq!(Network::get_current(), network);
}

/// Only `main`'s startup network check refuses a network the build does not support, so this
/// fails if `main` stops applying the resolved network.
#[test]
fn the_binary_refuses_a_network_invalid_for_its_build() {
    let invalid = networks_valid_for_this_build(false).next().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_minotari"))
        .current_dir(dir.path())
        .env_remove("TARI_NETWORK")
        .args([
            "--network",
            &invalid.to_string(),
            "balance",
            "--database-path",
            "wallet.db",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("is not supported by this build"), "{stderr}");
    assert!(stderr.contains("is invalid for this binary"), "{stderr}");
}
