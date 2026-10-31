//! The `safe` CLI as a library, for other CLIs that send Safe transactions.
//!
//! An app builds its own calls and takes the `safe send` flags by flattening
//! [`args::SendOpts`] into its command, then hands both to [`send`]:
//!
//! ```no_run
//! use clap::Parser;
//! use safe_rs_cli::args::SendOpts;
//! use safe_rs_cli::safe_rs::{Address, Bytes, Call, U256};
//!
//! #[derive(Parser)]
//! struct Deposit {
//!     /// Recipient of the app-specific call
//!     #[arg(long)]
//!     to: Address,
//!
//!     #[command(flatten)]
//!     safe: SendOpts,
//! }
//!
//! # async fn example() -> color_eyre::Result<()> {
//! let deposit = Deposit::parse();
//! let calls = vec![Call::new(deposit.to, U256::ZERO, Bytes::new())];
//! safe_rs_cli::send(calls, deposit.safe, false).await
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

pub use cli::{Cli, Commands};
pub use commands::send::send;
/// The library the calls are built with, at the version this crate uses.
pub use safe_rs;

/// The flag groups of the `safe` commands, for flattening into another CLI's
/// commands with `#[command(flatten)]`.
pub mod args {
    pub use crate::cli::{
        parse_block_id, parse_ether_value, parse_fee_value, EvmSpec, HdArgs, PasswordArgs,
        PayerArgs, RpcArgs, SafeArgs, SendOpts, SimArgs, SweepArgs, WalletArgs,
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
