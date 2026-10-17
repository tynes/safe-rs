use alloy::eips::BlockId;
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use clap::ValueEnum;
use color_eyre::eyre::{bail, Result};
use safe_rs::{
    read_safe_state, ChainAddresses, Error, ReadSafeStateOptions, SafeState, WalletBuilder,
    WalletConfig,
};

use crate::cli::SafeVersion;
use crate::commands::HttpProvider;

/// Reads the default Safe of a signer: the one `safe create` deploys
/// when run without options.
///
/// Its address depends on the Safe version, so every version is tried, newest
/// first.
pub(super) async fn read_default_safe(
    provider: &HttpProvider,
    signer: PrivateKeySigner,
    block: BlockId,
) -> Result<SafeState> {
    let signer_address = signer.address();
    let builder = WalletBuilder::new(provider.clone(), signer);

    let mut candidates = Vec::new();
    for version in SafeVersion::value_variants() {
        let addresses = ChainAddresses::from(*version);
        // A chain without this version's factory has no Safe created by it.
        if provider
            .get_code_at(addresses.proxy_factory)
            .await?
            .is_empty()
        {
            continue;
        }
        let config = WalletConfig::new().with_addresses(addresses);
        let safe = builder.compute_address(&config).await?;
        match read_safe_state(provider, safe, block, ReadSafeStateOptions::default()).await {
            Err(Error::SafeNotDeployed(_)) => candidates.push(format!("{safe} (v{version})")),
            state => return Ok(state?),
        }
    }

    let checked = if candidates.is_empty() {
        "this chain has no known Safe proxy factory".to_string()
    } else {
        format!("nothing is deployed at {}", candidates.join(" or "))
    };
    bail!(
        "No default Safe found for signer {signer_address}: {checked}. Deploy one with \
         `safe create`, or pass the address of a Safe created with other options"
    )
}
