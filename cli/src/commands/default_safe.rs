use alloy::eips::BlockId;
use alloy::primitives::Address;
use alloy::providers::Provider;
use clap::ValueEnum;
use color_eyre::eyre::eyre;
use color_eyre::eyre::{bail, Result};
use safe_rs::rotation::RotationState;
use safe_rs::{
    fetch_proxy_creation_code, predict_safe_address, read_safe_state, ChainAddresses, Error,
    ReadSafeStateOptions, SafeState, WalletConfig,
};

use crate::any_signer::AnySigner;
use crate::cli::{SafeVersion, SignerArgs};
use crate::commands::HttpProvider;
use crate::console::Console;
use crate::signers::{create_signer, SIGNER_FLAGS_HELP};

/// The signer `args` name, if they name one and it is `wanted`. A signer that
/// only picks the default Safe is not wanted when the Safe is known, so a
/// keystore is not unlocked for nothing.
pub(super) async fn optional_signer(
    args: &SignerArgs,
    wanted: bool,
    console: &Console,
) -> Result<Option<AnySigner>> {
    if wanted && args.is_set() {
        Ok(Some(create_signer(args, console).await?))
    } else {
        Ok(None)
    }
}

/// The Safe a `--safe` command acts on: `--safe` (or `SAFE_ADDRESS`) when
/// given, else the signer's default Safe, read at `block`.
pub(super) async fn safe_or_default(
    provider: &HttpProvider,
    safe: Option<Address>,
    signer: Option<&AnySigner>,
    block: BlockId,
    console: &Console,
) -> Result<Address> {
    if let Some(safe) = safe {
        return Ok(safe);
    }
    let Some(signer) = signer else {
        bail!(
            "No Safe specified. Pass --safe (or set SAFE_ADDRESS), or {SIGNER_FLAGS_HELP} to use \
             the signer's default Safe"
        );
    };
    let safe = read_default_safe(provider, signer.address(), block)
        .await?
        .address;
    console.warn(format!(
        "using the default Safe of signer {}: {safe}",
        signer.address()
    ));
    Ok(safe)
}

/// Reads the default Safe of a signer: the one `safe create` deploys
/// when run without options.
///
/// Its address depends on the Safe version, so every version is tried, newest
/// first.
pub(super) async fn read_default_safe(
    provider: &HttpProvider,
    signer_address: Address,
    block: BlockId,
) -> Result<SafeState> {
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
        let config = WalletConfig::new().with_addresses(addresses.clone());
        let creation_code = fetch_proxy_creation_code(provider, addresses.proxy_factory).await?;
        let (safe, _) = predict_safe_address(
            addresses.proxy_factory,
            addresses.safe_singleton,
            &config.owners(signer_address),
            config.threshold,
            config.fallback_handler(),
            config.salt_nonce,
            &creation_code,
        );
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

/// Select only within the connected chain; never guess between wallet bindings.
///
/// `choose` tells how to pass an address instead, such as "--safe <SAFE>".
pub(crate) fn recorded_safe(state: &RotationState, chain_id: u64, choose: &str) -> Result<Address> {
    let mut candidates = Vec::new();
    for key in state.safes.keys() {
        let (chain, safe) = key
            .split_once(':')
            .ok_or_else(|| eyre!("invalid Safe binding {key}"))?;
        let chain: u64 = chain
            .parse()
            .map_err(|_| eyre!("invalid chain ID in Safe binding {key}"))?;
        if chain == chain_id {
            let safe: Address = safe
                .parse()
                .map_err(|_| eyre!("invalid address in Safe binding {key}"))?;
            candidates.push(safe);
        }
    }
    match candidates.as_slice() {
        [safe] => Ok(*safe),
        [] => bail!(
            "No Safe recorded for this wallet on chain {chain_id}. Pass its address with \
             {choose}, or recover its state with \
             `safe wallet sync --safe <SAFE>` using the same wallet and RPC URL"
        ),
        _ => bail!(
            "Multiple Safes recorded for this wallet on chain {chain_id}: {}. \
             Choose one with {choose}",
            candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safe_rs::rotation::{binding_key, OwnerRef};

    #[test]
    fn recorded_safes_are_selected_only_when_unambiguous_on_this_chain() {
        let mut state = RotationState::new(Address::ZERO, 1);
        let first = Address::repeat_byte(1);
        let second = Address::repeat_byte(2);
        let owner = OwnerRef::Derived {
            index: 1,
            address: Address::repeat_byte(3),
        };
        state.bind(&binding_key(10, second), owner).unwrap();
        let before = state.clone();
        let error = recorded_safe(&state, 1, "--safe").unwrap_err().to_string();
        assert!(error.contains("No Safe recorded"));
        assert!(error.contains("wallet sync"));
        assert_eq!(state, before);

        state.bind(&binding_key(1, first), owner).unwrap();
        assert_eq!(recorded_safe(&state, 1, "--safe").unwrap(), first);
        assert_eq!(recorded_safe(&state, 10, "--safe").unwrap(), second);

        state.bind(&binding_key(1, second), owner).unwrap();
        let before = state.clone();
        let error = recorded_safe(&state, 1, "--safe").unwrap_err().to_string();
        assert!(error.contains("Multiple Safes"));
        assert!(error.contains(&first.to_string()));
        assert!(error.contains(&second.to_string()));
        assert_eq!(state, before);
    }
}
