use alloy::network::AnyNetwork;
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use color_eyre::eyre::Result;
use safe_rs::ISafe;

use crate::cli::InfoArgs;
use crate::output::SafeInfoOutput;

pub async fn run(args: InfoArgs, json: bool) -> Result<()> {
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(args.rpc_url.parse()?);

    let safe_address: Address = args.safe.parse()?;

    let safe = ISafe::new(safe_address, &provider);

    let nonce = safe.nonce().call().await?;
    let threshold = safe.getThreshold().call().await?;
    let owners = safe.getOwners().call().await?;

    let output = SafeInfoOutput {
        address: safe_address,
        nonce,
        threshold: threshold.to::<u64>(),
        owners,
    };

    output.print(json);

    Ok(())
}
