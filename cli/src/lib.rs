//! The `safe` CLI as a library, for other CLIs that send Safe transactions.
//!
//! An app builds its own calls and takes the `safe send` options by
//! flattening [`args::SendOpts`] into its command. It resolves the RPC URL,
//! the signer and the Safe itself into a [`SendContext`], so its own
//! `--rpc-url` and `--private-key` keep their meaning. [`send`] returns how
//! the send ended:
//!
//! ```no_run
//! use clap::Parser;
//! use safe_rs_cli::args::SendOpts;
//! use safe_rs_cli::safe_rs::{Address, Bytes, Call, U256};
//! use safe_rs_cli::{Output, PrivateKeySigner, SendContext, SendOutcome, Url};
//!
//! #[derive(Parser)]
//! struct Deposit {
//!     #[arg(long)]
//!     rpc_url: Url,
//!     #[arg(long)]
//!     private_key: PrivateKeySigner,
//!     #[arg(long)]
//!     safe: Address,
//!
//!     #[command(flatten)]
//!     send: SendOpts,
//! }
//!
//! # async fn example() -> color_eyre::Result<()> {
//! let deposit = Deposit::parse();
//! let calls = vec![Call::new(deposit.safe, U256::ZERO, Bytes::new())];
//! let ctx = SendContext::new(deposit.rpc_url, deposit.safe)
//!     .with_signer(deposit.private_key)
//!     .with_output(Output::Quiet);
//! match safe_rs_cli::send(ctx, calls, deposit.send).await? {
//!     SendOutcome::Executed { tx_hash, .. } => println!("deposited in {tx_hash}"),
//!     SendOutcome::Aborted { .. } => println!("cancelled"),
//!     other => println!("{other:?}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`Commands`] and [`run`] embed the whole `safe` command tree instead.

// CLI-specific lint overrides
#![allow(clippy::print_stdout, reason = "CLI tools print to stdout")]
#![allow(clippy::print_stderr, reason = "CLI tools print to stderr")]
#![allow(clippy::unwrap_used, reason = "CLI can unwrap for user-facing errors")]
#![allow(clippy::expect_used, reason = "CLI can expect for user-facing errors")]

mod bundle;
mod cli;
mod commands;
mod keys;
mod output;
mod paths;
mod sig_parser;
mod wallet;

use color_eyre::eyre::Result;

pub use alloy::signers::local::PrivateKeySigner;
pub use cli::{Cli, Commands};
pub use commands::send::{send, Output, SendContext, SendOutcome};
/// The library the calls are built with, at the version this crate uses.
pub use safe_rs;
pub use url::Url;

/// The flag groups of the `safe` commands, for flattening into another CLI's
/// commands with `#[command(flatten)]`.
///
/// [`SendOpts`](args::SendOpts) is the one a send needs. `RpcArgs`,
/// `SafeArgs` and `WalletArgs` are the `safe` CLI's own `--rpc-url`, `--safe`
/// and wallet flags, with their `ETH_RPC_URL`, `SAFE_ADDRESS` and
/// `PRIVATE_KEY` environment variables, for a CLI that wants those too.
pub mod args {
    pub use crate::cli::{
        parse_block_id, parse_ether_value, parse_fee_value, EvmSpec, HdArgs, PasswordArgs,
        PayerArgs, RpcArgs, SafeArgs, SendOpts, SimArgs, SweepArgs, WalletArgs, DEFAULT_BLOCK_TIME,
        DEFAULT_TIMEOUT,
    };
}

/// Runs one `safe` command. `json` is the global `--json` flag.
pub async fn run(command: Commands, json: bool) -> Result<()> {
    match command {
        Commands::Send(args) => commands::send::run(*args, json).await,
        Commands::Call(args) => commands::call::run(args, json).await,
        Commands::Info(args) => commands::info::run(args, json).await,
        Commands::Approvals(args) => commands::approvals::run(args, json).await,
        Commands::Config(args) => commands::config::run(*args, json).await,
        Commands::Create(args) => commands::create::run(args, json).await,
        Commands::Rotate(args) => commands::rotate::run(*args, json).await,
        Commands::Wallet(command) => commands::wallet::run(command, json).await,
    }
}
