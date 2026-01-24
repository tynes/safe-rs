//! Multicall ERC20 example
//!
//! This example demonstrates how to batch multiple ERC20 operations into a single
//! Safe transaction using the MultiSend contract.
//!
//! # Usage
//!
//! Set the following environment variables:
//! - `RPC_URL`: Ethereum RPC endpoint
//! - `PRIVATE_KEY`: Private key of the Safe owner
//! - `SAFE_ADDRESS`: Address of the Safe contract
//! - `TOKEN_ADDRESS`: Address of the ERC20 token

use alloy::network::AnyNetwork;
use alloy::primitives::{address, Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use safe_rs::{Safe, IERC20};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let rpc_url: Url = std::env::var("RPC_URL")
        .expect("RPC_URL required")
        .parse()?;
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY required");
    let safe_address: Address = std::env::var("SAFE_ADDRESS")
        .expect("SAFE_ADDRESS required")
        .parse()?;
    let token_address: Address = std::env::var("TOKEN_ADDRESS")
        .expect("TOKEN_ADDRESS required")
        .parse()?;

    // Example addresses (replace with real addresses for actual use)
    let recipient1 = address!("0x1111111111111111111111111111111111111111");
    let recipient2 = address!("0x2222222222222222222222222222222222222222");
    let spender = address!("0x3333333333333333333333333333333333333333");

    // Create provider and signer
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(rpc_url);
    let signer: PrivateKeySigner = private_key.parse()?;

    println!("Connecting to Safe at {}", safe_address);

    // Connect to the Safe
    let safe = Safe::connect(provider, signer, safe_address).await?;

    // Verify we're an owner with threshold 1
    safe.verify_single_owner().await?;
    println!("Verified as single owner");

    // Build a batch of ERC20 operations
    println!("\nBuilding multicall batch:");
    println!("  1. Transfer 100 tokens to {}", recipient1);
    println!("  2. Transfer 200 tokens to {}", recipient2);
    println!("  3. Approve {} to spend unlimited tokens", spender);

    let simulated = safe
        .multicall()
        // Transfer to recipient 1
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient1,
                amount: U256::from(100),
            },
        )
        // Transfer to recipient 2
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient2,
                amount: U256::from(200),
            },
        )
        // Approve spender
        .add_typed(
            token_address,
            IERC20::approveCall {
                spender,
                amount: U256::MAX,
            },
        )
        // Use MultiSendCallOnly for safety (no delegatecall in batch)
        .call_only()
        .simulate()
        .await?;

    println!("\nSimulation successful!");
    let sim_result = simulated.simulation_result().unwrap();
    println!("  Gas used: {}", sim_result.gas_used);
    println!("  Logs emitted: {}", sim_result.logs.len());

    // Execute the batch
    let result = simulated.execute().await?;

    println!("\nTransaction submitted!");
    println!("  Tx Hash: {}", result.tx_hash);
    println!("  Success: {}", result.success);

    Ok(())
}
