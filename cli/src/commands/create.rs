use color_eyre::eyre::Result;
use safe_rs::{is_safe_with, ChainAddresses, WalletBuilder, WalletConfig};

use crate::cli::CreateArgs;
use crate::commands::http_provider;
use crate::output::{confirm_prompt, CreateOutput, Report};
use crate::wallet::create_signer;

pub async fn run(args: CreateArgs, json: bool) -> Result<()> {
    let signer = create_signer(&args.wallet)?;
    let signer_address = signer.address();

    let mut addresses = ChainAddresses::v1_4_1();
    if let Some(singleton) = args.singleton {
        addresses.safe_singleton = singleton;
    }
    if let Some(factory) = args.factory {
        addresses.proxy_factory = factory;
    }
    let mut config = WalletConfig::new()
        .with_salt_nonce(args.salt_nonce)
        .with_additional_owners(args.owners.clone())
        .with_threshold(args.threshold)
        .with_addresses(addresses.clone());
    if let Some(handler) = args.fallback_handler {
        config = config.with_fallback_handler(handler);
    }
    config.validate(signer_address)?;
    let owners = config.owners(signer_address);

    let provider = http_provider(&args.rpc.rpc_url);
    let builder = WalletBuilder::new(provider.clone(), signer);
    let safe_address = builder.compute_address(&config).await?;

    if !json {
        println!("Computing Safe address...");
        println!("  Factory: {}", addresses.proxy_factory);
        println!("  Singleton: {}", addresses.safe_singleton);
        println!("  Salt Nonce: {}", args.salt_nonce);
        println!("  Owners: {:?}", owners);
        println!("  Threshold: {}", args.threshold);
        println!();
    }

    let already_deployed =
        is_safe_with(&provider, safe_address, &[addresses.safe_singleton]).await?;
    let output = |tx_hash| CreateOutput {
        safe_address,
        tx_hash,
        owners: owners.clone(),
        threshold: args.threshold,
        already_deployed,
    };

    if args.compute_only || already_deployed {
        if already_deployed && !args.compute_only && !json {
            println!("Safe already deployed at {}", safe_address);
        }
        output(None).print(json);
        return Ok(());
    }

    if !json {
        println!("Safe Address: {}", safe_address);
        println!();
    }

    // Confirm before deployment
    if !args.no_confirm && !json && !confirm_prompt("Deploy new Safe?") {
        println!("Aborted");
        return Ok(());
    }

    let deployment = builder
        .deploy_detailed(args.rpc.rpc_url.clone(), config)
        .await?;
    output(deployment.tx_hash).print(json);

    Ok(())
}
