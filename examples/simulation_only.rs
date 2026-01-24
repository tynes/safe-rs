//! Simulation-only example
//!
//! This example demonstrates how to simulate Safe transactions without executing them.
//! Useful for testing, gas estimation, and validating transaction parameters.
//!
//! # Usage
//!
//! Set the following environment variables:
//! - `RPC_URL`: Ethereum RPC endpoint
//! - `SAFE_ADDRESS`: Address of the Safe contract (any Safe, doesn't need to be yours)
//! - `TOKEN_ADDRESS`: Address of an ERC20 token the Safe holds

use alloy::network::AnyNetwork;
use alloy::primitives::{address, Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use safe_rs::{ChainConfig, Safe, IERC20};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let rpc_url: Url = std::env::var("RPC_URL")
        .expect("RPC_URL required")
        .parse()?;
    let safe_address: Address = std::env::var("SAFE_ADDRESS")
        .expect("SAFE_ADDRESS required")
        .parse()?;
    let token_address: Address = std::env::var("TOKEN_ADDRESS")
        .expect("TOKEN_ADDRESS required")
        .parse()?;

    // Create provider
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(rpc_url);

    // For simulation-only, we can use any signer (even a random one)
    // The simulation doesn't require actual ownership
    let signer = PrivateKeySigner::random();

    println!("Simulating transactions for Safe at {}", safe_address);
    println!("Using dummy signer: {}", signer.address());

    // Get chain ID and create config
    let chain_id = provider.get_chain_id().await?;
    let config = ChainConfig::new(chain_id);

    println!("Chain ID: {}", chain_id);

    // Create Safe client (note: we won't execute, just simulate)
    let safe = Safe::new(provider.clone(), signer, safe_address, config);

    // Get Safe info
    let nonce = safe.nonce().await?;
    let threshold = safe.threshold().await?;
    let owners = safe.owners().await?;

    println!("\nSafe Info:");
    println!("  Nonce: {}", nonce);
    println!("  Threshold: {}", threshold);
    println!("  Owners: {:?}", owners);

    // Simulate a transfer (will work even if we're not an owner)
    let recipient = address!("0xdead000000000000000000000000000000000000");
    let amount = U256::from(1_000_000); // 1 token with 6 decimals

    println!("\n--- Simulation 1: ERC20 Transfer ---");
    println!("  Token: {}", token_address);
    println!("  Recipient: {}", recipient);
    println!("  Amount: {}", amount);

    match safe
        .multicall()
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient,
                amount,
            },
        )
        .simulate()
        .await
    {
        Ok(simulated) => {
            println!("  ✓ Simulation successful!");
            let sim_result = simulated.simulation_result().unwrap();
            println!("    Gas used: {}", sim_result.gas_used);
            println!("    Logs: {}", sim_result.logs.len());

            // We can inspect logs
            for (i, log) in sim_result.logs.iter().enumerate() {
                println!("    Log {}: {} topics", i, log.topics().len());
            }
        }
        Err(e) => {
            println!("  ✗ Simulation failed: {}", e);
        }
    }

    // Simulate a batch operation
    println!("\n--- Simulation 2: Multicall Batch ---");

    let recipient2 = address!("0xbeef000000000000000000000000000000000000");

    match safe
        .multicall()
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient,
                amount: U256::from(500_000),
            },
        )
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient2,
                amount: U256::from(500_000),
            },
        )
        .call_only()
        .simulate()
        .await
    {
        Ok(simulated) => {
            println!("  ✓ Batch simulation successful!");
            let sim_result = simulated.simulation_result().unwrap();
            println!("    Total gas used: {}", sim_result.gas_used);
            println!("    Logs: {}", sim_result.logs.len());
        }
        Err(e) => {
            println!("  ✗ Batch simulation failed: {}", e);
        }
    }

    // Simulate with raw calldata
    println!("\n--- Simulation 3: Raw Calldata ---");

    // Build raw transfer calldata manually
    let transfer_selector = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
    let mut calldata = transfer_selector.to_vec();

    // Pad recipient address to 32 bytes
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(recipient.as_slice());

    // Pad amount to 32 bytes
    calldata.extend_from_slice(&amount.to_be_bytes::<32>());

    match safe
        .multicall()
        .add_raw(token_address, U256::ZERO, Bytes::from(calldata))
        .simulate()
        .await
    {
        Ok(simulated) => {
            println!("  ✓ Raw calldata simulation successful!");
            println!("    Gas used: {}", simulated.simulation_result().unwrap().gas_used);
        }
        Err(e) => {
            println!("  ✗ Raw calldata simulation failed: {}", e);
        }
    }

    // Simulate an ETH transfer
    println!("\n--- Simulation 4: ETH Transfer ---");

    let eth_recipient = address!("0xcafe000000000000000000000000000000000000");
    let eth_amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH

    match safe
        .multicall()
        .add_raw(eth_recipient, eth_amount, Bytes::new())
        .simulate()
        .await
    {
        Ok(simulated) => {
            println!("  ✓ ETH transfer simulation successful!");
            println!("    Gas used: {}", simulated.simulation_result().unwrap().gas_used);
        }
        Err(e) => {
            println!("  ✗ ETH transfer simulation failed: {}", e);
            println!("    (This is expected if Safe doesn't have 1 ETH)");
        }
    }

    println!("\nSimulation complete! No transactions were submitted.");

    Ok(())
}
