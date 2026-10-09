use alloy::eips::BlockId;
use alloy::providers::Provider;
use clap::ValueEnum;
use color_eyre::eyre::{bail, Result};
use safe_rs::{
    read_safe_state, ChainAddresses, Error, ParentHeader, ReadSafeStateOptions, SafeState,
    WalletBuilder, WalletConfig,
};

use crate::cli::{InfoArgs, PasswordArgs, SafeVersion, WalletArgs};
use crate::commands::{http_provider, HttpProvider};
use crate::output::{Report, SafeInfoOutput};
use crate::wallet::create_signer;

pub async fn run(args: InfoArgs, json: bool) -> Result<()> {
    let provider = http_provider(&args.rpc.rpc_url);

    // Resolve the block to a hash first so every read sees the same state.
    let header = ParentHeader::fetch(&provider, args.block.unwrap_or(BlockId::latest())).await?;
    let block = header.block_id();
    let state = match args.safe {
        Some(safe) => {
            read_safe_state(&provider, safe, block, ReadSafeStateOptions::default()).await?
        }
        None => read_default_safe(&provider, &args.wallet, &args.password, block).await?,
    };

    SafeInfoOutput::new(state, header.number, header.hash).print(json);
    Ok(())
}

/// Reads the default Safe of the wallet's signer: the one `safe create` deploys
/// when run without options.
///
/// Its address depends on the Safe version, so every version is tried, newest
/// first.
async fn read_default_safe(
    provider: &HttpProvider,
    wallet: &WalletArgs,
    password: &PasswordArgs,
    block: BlockId,
) -> Result<SafeState> {
    if !wallet.is_set() {
        bail!(
            "No Safe specified. Pass its address, or --private-key, --keystore or \
             --interactive to use the signer's default Safe"
        );
    }
    let signer = create_signer(wallet, password)?;
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
