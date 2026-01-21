use alloy::network::AnyNetwork;
use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::SolCall;
use color_eyre::eyre::{eyre, Result};
use safe_rs::{ChainAddresses, ISafeProxyFactory, ISafeSetup};

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

/// Encodes the Safe.setup() call
fn encode_setup_call(owners: &[Address], threshold: u64, fallback_handler: Address) -> Bytes {
    let setup_call = ISafeSetup::setupCall {
        _owners: owners.to_vec(),
        _threshold: U256::from(threshold),
        to: Address::ZERO,
        data: Bytes::new(),
        fallbackHandler: fallback_handler,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    };

    Bytes::from(setup_call.abi_encode())
}

/// Computes the CREATE2 address for a Safe proxy
///
/// Formula:
/// salt = keccak256(keccak256(initializer) ++ saltNonce)
/// init_code = proxyCreationCode ++ singleton_address_padded
/// address = keccak256(0xff ++ factory ++ salt ++ keccak256(init_code))[12:]
fn compute_create2_address(
    factory: Address,
    singleton: Address,
    initializer: &Bytes,
    salt_nonce: U256,
    creation_code: &Bytes,
) -> Address {
    // Compute salt: keccak256(keccak256(initializer) ++ saltNonce)
    let initializer_hash = keccak256(initializer);

    let mut salt_input = [0u8; 64];
    salt_input[..32].copy_from_slice(initializer_hash.as_slice());
    salt_input[32..64].copy_from_slice(&salt_nonce.to_be_bytes::<32>());

    let salt = keccak256(&salt_input);

    // Compute init_code_hash: keccak256(creation_code ++ singleton_padded)
    let mut init_code = creation_code.to_vec();
    // Append singleton address as 32-byte padded value
    let mut singleton_padded = [0u8; 32];
    singleton_padded[12..].copy_from_slice(singleton.as_slice());
    init_code.extend_from_slice(&singleton_padded);

    let init_code_hash = keccak256(&init_code);

    // Compute CREATE2 address
    let mut create2_input = Vec::with_capacity(1 + 20 + 32 + 32);
    create2_input.push(0xff);
    create2_input.extend_from_slice(factory.as_slice());
    create2_input.extend_from_slice(salt.as_slice());
    create2_input.extend_from_slice(init_code_hash.as_slice());

    let hash = keccak256(&create2_input);

    Address::from_slice(&hash[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_encode_setup_call() {
        let owners = vec![address!("1234567890123456789012345678901234567890")];
        let threshold = 1;
        let fallback_handler = address!("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99");

        let data = encode_setup_call(&owners, threshold, fallback_handler);

        // Should not be empty and should start with setup selector
        assert!(!data.is_empty());
    }
}
