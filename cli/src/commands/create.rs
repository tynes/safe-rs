use alloy::network::AnyNetwork;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use color_eyre::eyre::{eyre, Result};
use safe_rs::{compute_create2_address, encode_setup_call, ChainAddresses, ISafeProxyFactory};

use crate::cli::CreateArgs;
use crate::output::{confirm_prompt, CreateOutput};
use crate::wallet::create_signer;

pub async fn run(args: CreateArgs, json: bool) -> Result<()> {
    let signer = create_signer(&args.wallet)?;
    let signer_address = signer.address();

    // Build owners array: signer + additional owners
    let mut owners = vec![signer_address];
    for owner_str in &args.owners {
        let owner: Address = owner_str
            .parse()
            .map_err(|e| eyre!("Invalid owner address '{}': {}", owner_str, e))?;
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }

    // Validate threshold
    if args.threshold == 0 || args.threshold as usize > owners.len() {
        return Err(eyre!(
            "Invalid threshold: {} (must be 1-{})",
            args.threshold,
            owners.len()
        ));
    }

    let addresses = ChainAddresses::v1_4_1();

    // Get fallback handler
    let fallback_handler = if let Some(handler) = &args.fallback_handler {
        handler.parse()?
    } else {
        addresses.fallback_handler
    };

    // Encode the initializer (Safe.setup call)
    let initializer = encode_setup_call(&owners, args.threshold, fallback_handler);

    // Parse salt nonce
    let salt_nonce: U256 = args.salt_nonce.parse()?;

    // Create provider
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(args.rpc_url.parse()?);

    // Get proxy creation code for CREATE2 computation
    let factory = ISafeProxyFactory::new(addresses.proxy_factory, &provider);
    let creation_code = factory.proxyCreationCode().call().await?;

    // Compute deterministic address
    let safe_address = compute_create2_address(
        addresses.proxy_factory,
        addresses.safe_singleton,
        &initializer,
        salt_nonce,
        &creation_code,
    );

    if !json {
        println!("Computing Safe address...");
        println!("  Factory: {}", addresses.proxy_factory);
        println!("  Singleton: {}", addresses.safe_singleton);
        println!("  Salt Nonce: {}", salt_nonce);
        println!("  Owners: {:?}", owners);
        println!("  Threshold: {}", args.threshold);
        println!();
    }

    // Check if already deployed
    let code = provider.get_code_at(safe_address).await?;
    let already_deployed = !code.is_empty();

    if args.compute_only {
        let output = CreateOutput {
            safe_address,
            tx_hash: None,
            owners,
            threshold: args.threshold,
            already_deployed,
        };
        output.print(json);
        return Ok(());
    }

    if already_deployed {
        if !json {
            println!("Safe already deployed at {}", safe_address);
        }
        let output = CreateOutput {
            safe_address,
            tx_hash: None,
            owners,
            threshold: args.threshold,
            already_deployed: true,
        };
        output.print(json);
        return Ok(());
    }

    if !json {
        println!("Safe Address: {}", safe_address);
        println!();
    }

    // Confirm before deployment
    if !args.no_confirm && !json {
        if !confirm_prompt("Deploy new Safe?") {
            println!("Aborted");
            return Ok(());
        }
    }

    // Create wallet provider for sending transaction
    let wallet_provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(args.rpc_url.parse()?);

    let factory = ISafeProxyFactory::new(addresses.proxy_factory, &wallet_provider);

    // Deploy the Safe
    let pending_tx = factory
        .createProxyWithNonce(addresses.safe_singleton, initializer, salt_nonce)
        .send()
        .await
        .map_err(|e| eyre!("Failed to send transaction: {}", e))?;

    let receipt = pending_tx
        .get_receipt()
        .await
        .map_err(|e| eyre!("Failed to get receipt: {}", e))?;

    let tx_hash = receipt.transaction_hash;

    // Verify deployment
    let code = provider.get_code_at(safe_address).await?;
    if code.is_empty() {
        return Err(eyre!(
            "Deployment failed: no code at expected address {}",
            safe_address
        ));
    }

    let output = CreateOutput {
        safe_address,
        tx_hash: Some(tx_hash),
        owners,
        threshold: args.threshold,
        already_deployed: false,
    };

    output.print(json);

    Ok(())
}

