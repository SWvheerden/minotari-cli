use anyhow::bail;
use tari_common::configuration::Network;

/// Consensus hashes and signatures take their domain from the process-global network, not from
/// the `network` a caller passes in, so a mismatch would sign for another chain.
pub fn ensure_global_network(network: Network) -> Result<(), anyhow::Error> {
    let global = Network::get_current_or_user_setting_or_default();
    if global != network {
        bail!(
            "Refusing to sign for network {network}: the process-global network is {global}. Call \
             `Network::set_current({network:?})` before building transactions."
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
