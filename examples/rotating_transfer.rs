#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "example program: panics and stdout are the intended UX"
)]
//! One-time owner keys example
//!
//! Sends ETH from a Safe and, in the same transaction, swaps the Safe's owner
//! for the next unused key of an HD wallet. The old owner's remaining ETH is
//! then moved to the new owner, which pays for the next transaction.
//!
//! The Safe must be a threshold-1 Safe (v1.4.1 or v1.5.0) whose owner is a key
//! of the wallet (in the CLI, `safe create --rotate --mnemonic <name>` creates
//! one and `safe wallet sync` records an existing one), and that owner must
//! hold ETH for gas.
//!
//! # Usage
//!
//! Set the following environment variables:
//! - `RPC_URL`: Ethereum RPC endpoint
//! - `KEYSTORE`: Path to a mnemonic keystore (`safe wallet new` writes one)
//! - `KEYSTORE_PASSWORD`: Its password
//! - `STATE_FILE`: Where to keep the record of used keys
//! - `SAFE_ADDRESS`: Address of the Safe contract
//! - `RECIPIENT`: Address to send ETH to
//! - `AMOUNT`: Amount to send (in wei)
//!
//! Run with `cargo run --features hd-wallet --example rotating_transfer`.

use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::ProviderBuilder;
use safe_rs::rotation::{RotatingSafe, RotationStatus};
use safe_rs::{Call, HdWallet};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment
    let rpc_url: Url = std::env::var("RPC_URL")
        .expect("RPC_URL required")
        .parse()?;
    let keystore = std::env::var("KEYSTORE").expect("KEYSTORE required");
    let password = std::env::var("KEYSTORE_PASSWORD").expect("KEYSTORE_PASSWORD required");
    let state_file = std::env::var("STATE_FILE").expect("STATE_FILE required");
    let safe_address: Address = std::env::var("SAFE_ADDRESS")
        .expect("SAFE_ADDRESS required")
        .parse()?;
    let recipient: Address = std::env::var("RECIPIENT")
        .expect("RECIPIENT required")
        .parse()?;
    let amount: U256 = std::env::var("AMOUNT").expect("AMOUNT required").parse()?;

    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(rpc_url);

    // Decrypt the phrase; every owner key is derived from it.
    let json = std::fs::read_to_string(&keystore)?;
    let wallet = HdWallet::from_keystore_json(&json, password.as_bytes())?;
    println!("Wallet: {}", wallet.id());

    // Opening reads the owner list and brings the state file up to date. The
    // file stays locked until `safe` is dropped.
    let mut safe = RotatingSafe::open(provider, safe_address, wallet, state_file).await?;
    let owner = safe.binding()?.current;
    println!("Safe: {safe_address}");
    println!("Owner: {} (key {:?})", owner.address(), owner.index());

    // The transfer, followed by the owner swap, as one Safe transaction.
    let outcome = safe
        .execute(&[Call::new(recipient, amount, Bytes::new())])
        .await?;

    println!("\nTransaction: {}", outcome.tx_hash);
    match outcome.status {
        RotationStatus::Rotated => {
            let owner = safe.binding()?.current;
            println!("New owner: {} (key {:?})", owner.address(), owner.index());
        }
        RotationStatus::RotatedElsewhere => {
            println!("The owner was rotated by another transaction; this one reverted.");
        }
        RotationStatus::NotRotated => {
            println!("The transaction reverted and the owner key is now public.");
            println!("Call `rotate()` to retire it.");
        }
    }
    if let Some(sweep) = outcome.sweep {
        println!(
            "Swept {} wei from {} to {} ({})",
            sweep.amount, sweep.from, sweep.to, sweep.tx_hash
        );
    }
    for warning in safe.warnings() {
        println!("Warning: {warning}");
    }

    Ok(())
}
