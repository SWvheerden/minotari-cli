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
