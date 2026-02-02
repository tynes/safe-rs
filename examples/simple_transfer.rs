//! Simple ERC20 transfer example
//!
//! This example demonstrates how to execute a single ERC20 transfer through a Safe.
//!
//! # Usage
//!
//! Set the following environment variables:
//! - `RPC_URL`: Ethereum RPC endpoint
//! - `PRIVATE_KEY`: Private key of the Safe owner
//! - `SAFE_ADDRESS`: Address of the Safe contract
//! - `TOKEN_ADDRESS`: Address of the ERC20 token
//! - `RECIPIENT`: Address to send tokens to
//! - `AMOUNT`: Amount of tokens to send (in wei)

use alloy::network::AnyNetwork;
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use safe_rs::{Account, Safe, IERC20};
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
    let recipient: Address = std::env::var("RECIPIENT")
        .expect("RECIPIENT required")
        .parse()?;
    let amount: U256 = std::env::var("AMOUNT")
        .expect("AMOUNT required")
        .parse()?;

    // Create provider and signer
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(rpc_url);
    let signer: PrivateKeySigner = private_key.parse()?;

    println!("Connecting to Safe at {}", safe_address);
    println!("Signer: {}", signer.address());

    // Connect to the Safe
    let safe = Safe::connect(provider, signer, safe_address).await?;

    // Verify we're an owner with threshold 1
    safe.verify_single_owner().await?;
    println!("Verified as single owner");

    // Get current nonce
    let nonce = safe.nonce().await?;
    println!("Safe nonce: {}", nonce);

    // Build the transfer call
    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount,
    };

    println!("\nExecuting transfer:");
    println!("  Token: {}", token_address);
    println!("  Recipient: {}", recipient);
    println!("  Amount: {}", amount);

    // Execute through the Safe
    let result = safe
        .batch()
        .add_typed(token_address, transfer_call)
        .simulate()
        .await?
        .execute()
        .await?;

    println!("\nTransaction submitted!");
    println!("  Tx Hash: {}", result.tx_hash);
    println!("  Success: {}", result.success);

    Ok(())
}
