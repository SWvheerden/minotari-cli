use anyhow::bail;
use tari_common::configuration::Network;

/// Consensus hashes and signatures take their domain from the process-global network, not from
/// the `network` a caller passes in, so a mismatch would sign for another chain.
///
/// Pins the global network as a side effect if it is not set yet.
pub fn ensure_global_network(network: Network) -> Result<(), anyhow::Error> {
    // Pin the resolved network so it cannot change between this check and the signing that follows;
    // an `Err` only means it was already set.
    let _ = Network::set_current(Network::get_current_or_user_setting_or_default());
    let global = Network::get_current();
    if global != network {
        bail!(
            "Refusing to sign for network {network}: the process-global network is fixed to {global} for this \
             process. Embedders must call `Network::set_current` once at startup, before any wallet-core call."
        );
    }
    Ok(())
}

/// A network other than the process-global one, for tests of the check above.
#[cfg(test)]
pub(crate) fn a_network_other_than_the_global_one() -> Network {
    let global = Network::get_current();
    if global == Network::LocalNet {
        Network::Esmeralda
    } else {
        Network::LocalNet
    }
}
