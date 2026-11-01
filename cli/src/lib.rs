//! The `safe` CLI as a library, for other CLIs that send Safe transactions,
//! create Safes and manage HD wallets.
//!
//! Each command follows one pattern:
//!
//! - Its flags come in an `*Opts` group without `--rpc-url`, the signer or
//!   `--safe`, which another CLI flattens into its own command with
//!   `#[command(flatten)]`: [`args::SendOpts`], [`create::CreateOpts`],
//!   [`wallet::WalletCommand`].
//! - What the host resolves itself goes in a `*Context`: [`SendContext`],
//!   [`create::CreateContext`], [`wallet::WalletContext`].
//! - A library function returns a typed outcome or a typed error:
//!   [`send`], [`create::create`], the [`wallet`] functions.
//! - The library never prints. Progress and warnings go to the context's
//!   [`log::Logger`] (silent by default), and confirmations and passwords to
//!   its [`prompt::Prompt`] (the terminal by default).
//!
//! An app builds its own calls and takes the `safe send` options:
//!
//! ```no_run
//! use clap::Parser;
//! use safe_rs_cli::args::SendOpts;
//! use safe_rs_cli::log::{ConsoleLogger, Level};
//! use safe_rs_cli::safe_rs::{Address, Bytes, Call, U256};
//! use safe_rs_cli::{PrivateKeySigner, SendContext, SendError, SendOutcome, Url};
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
//!     .with_logger(ConsoleLogger::new(Level::Info));
//! match safe_rs_cli::send(ctx, calls, deposit.send).await {
//!     Ok(SendOutcome::Executed { tx_hash, .. }) => println!("deposited in {tx_hash}"),
//!     Ok(SendOutcome::Aborted { .. }) => println!("cancelled"),
//!     Ok(other) => println!("{other:?}"),
//!     Err(e) if e.may_be_pending() => eprintln!("not confirmed, check before retrying: {e}"),
//!     Err(SendError::SimulationFailed { reason }) => eprintln!("would revert: {reason}"),
//!     Err(e) => return Err(e.into()),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! A CLI whose Safes come from a factory of its own sets
//! [`CreateOpts::implementation`](create::CreateOpts) (see
//! [`create::SafeImplementation`]); [`create::create`] then deploys through it,
//! and [`info`] shows the implementation (singleton) the Safe uses.
//!
//! [`SendContext::eoa`] sends the same calls from the signer's own account,
//! one transaction per call, for an app that also supports accounts without a
//! Safe.
//!
//! [`Commands`] and [`run`] embed the whole `safe` command tree instead. They
//! report errors with `eyre`, like the `safe` binary.

// CLI-specific lint overrides. Printing is denied: only the logger, the
// prompt and `run` reach the terminal.
#![allow(clippy::unwrap_used, reason = "CLI can unwrap for user-facing errors")]
#![allow(clippy::expect_used, reason = "CLI can expect for user-facing errors")]

mod any_signer;
mod bundle;
mod cli;
mod commands;
pub mod config_file;
mod console;
mod error;
mod keys;
pub mod log;
mod output;
mod paths;
pub mod policy;
pub mod prompt;
mod sig_parser;
mod signers;
pub mod wallet;

use std::sync::Arc;

use color_eyre::eyre::Result;

pub use alloy::signers::local::PrivateKeySigner;
pub use any_signer::AnySigner;
pub use cli::{Cli, Commands};
pub use commands::info::{info, InfoError, SafeInfo};
pub use commands::send::{send, EoaTx, SendContext, SendOutcome, Sender};
pub use error::{BroadcastError, CreateError, OptionsError, SendError};
pub use output::Report;
pub use paths::{home, HOME_ENV};
/// The library the calls are built with, at the version this crate uses.
pub use safe_rs;
pub use url::Url;

use crate::console::{Console, Reports};
use crate::log::{ConsoleLogger, Level, Logger};
use crate::prompt::{Prompt, TerminalPrompt};

/// The flag groups of the `safe` commands, for flattening into another CLI's
/// commands with `#[command(flatten)]`.
///
/// [`SendOpts`](args::SendOpts) is the one a send needs. It is made of
/// [`CollectArgs`](args::CollectArgs), [`SimulateArgs`](args::SimulateArgs),
/// [`FeeArgs`](args::FeeArgs) and [`RawTxArgs`](args::RawTxArgs), which
/// `safe config` and `safe rotate` share, and which a host can flatten one
/// by one into a command of its own. `RpcArgs`,
/// `SafeArgs` and `SignerArgs` are the `safe` CLI's own `--rpc-url`, `--safe`
/// and signer flags, with their `ETH_RPC_URL`, `SAFE_ADDRESS` and
/// `PRIVATE_KEY` environment variables, for a CLI that wants those too.
///
/// `PasswordArgs` (`SAFE_PASSWORD_FILE`), `PayerArgs`
/// (`SAFE_PAYER_PRIVATE_KEY`) and `HdArgs` (`SAFE_HD_WALLET`) read the `safe`
/// CLI's environment variables wherever they are flattened. A host that does
/// not want them can drop one with
/// `#[command(mut_arg("payer_private_key", |a| a.env(None)))]` on its command.
pub mod args {
    #[allow(deprecated, reason = "the old name stays exported for one release")]
    pub use crate::cli::WalletArgs;
    pub use crate::cli::{
        parse_block_id, parse_ether_value, parse_fee_value, CollectArgs, EoaArgs, EvmSpec, FeeArgs,
        PasswordArgs, PayerArgs, RawTxArgs, RpcArgs, SafeArgs, SafeSetupArgs, SafeVersion,
        SendOpts, SignerArgs, SimArgs, SimulateArgs, DEFAULT_BLOCK_TIME, DEFAULT_TIMEOUT,
    };
    /// The HD wallet and sweep flags of `--rotate` (`hd-wallet` feature).
    pub use crate::cli::{parse_hd_key, HdArgs, HdKey, SweepArgs};
}

/// `safe create` and [`create`](create::create) for a CLI that deploys Safes.
pub mod create {
    pub use crate::cli::{FeeArgs, SafeSetupArgs, SafeVersion};
    pub use crate::commands::create::{
        create, run, BoxFuture, CreateArgs, CreateContext, CreateOpts, CreateOutcome, HttpProvider,
        Implementation, ResolvedSetup, SafeDeployment, SafeImplementation, StandardSafe,
    };
    pub use crate::commands::create::{parse_same_as, SameAs};
    pub use crate::error::CreateError;
    pub use crate::output::{OwnerKey, SweptEth};
}

/// Where a `safe` command's progress, questions and result go.
#[derive(Clone)]
pub struct RunConfig {
    pub logger: Arc<dyn Logger>,
    pub prompt: Arc<dyn Prompt>,
    /// Print the result as JSON instead of text. Never asks for
    /// confirmation, as `--no-confirm`.
    pub json: bool,
    /// What every Safe transaction is held to (default: nothing)
    pub policy: Option<Arc<dyn policy::SafePolicy>>,
}

impl RunConfig {
    /// What the `safe` binary uses: progress on stderr (warnings only with
    /// `json`), and questions on the terminal.
    pub fn terminal(json: bool) -> Self {
        let level = if json { Level::Warn } else { Level::Info };
        Self {
            logger: Arc::new(ConsoleLogger::new(level)),
            // The logger already showed what a confirmation is about.
            prompt: Arc::new(TerminalPrompt::new().hide_details()),
            json,
            policy: None,
        }
    }

    /// Checks every Safe transaction with `policy` before it leaves the machine.
    /// rotation unless it allows it.
    #[must_use]
    pub fn with_policy(mut self, policy: impl policy::SafePolicy + 'static) -> Self {
        self.policy = Some(Arc::new(policy));
        self
    }

    pub(crate) fn console(&self) -> Console {
        Console::new(self.logger.clone(), self.prompt.clone()).with_policy(self.policy.clone())
    }
}

/// Runs one `safe` command, then prints its result to stdout: JSON with
/// `config.json`, else text (on stderr when stdout carries `--raw-out -`).
pub async fn run(command: Commands, config: RunConfig) -> Result<()> {
    let reports = Arc::new(Reports::default());
    let console = config.console().with_reports(reports.clone());
    let json = config.json;
    let result = match command {
        Commands::Send(mut args) => {
            args.opts.no_confirm |= json;
            commands::send::run(*args, &console).await
        }
        Commands::Call(args) => commands::call::run(args, &console).await,
        Commands::Info(args) => commands::info::run(args, &console).await,
        Commands::Approvals(args) => commands::approvals::run(args, &console).await,
        Commands::Config(mut args) => {
            args.no_confirm |= json;
            commands::config::run(*args, &console).await
        }
        Commands::Create(args) => commands::create::run_with(*args, &console, json).await,
        Commands::Rotate(mut args) => {
            args.no_confirm |= json;
            commands::rotate::run(*args, &console).await
        }
        Commands::Wallet(args) => run_wallet(args, &console).await,
    };
    reports.print(json);
    result
}

/// `safe wallet`, with its `--rpc-url` and `--safe`. `SAFE_ADDRESS` picks the
/// Safe of `sync` and `sweep` only, so it does not filter `status`.
async fn run_wallet(args: cli::WalletCliArgs, console: &Console) -> Result<()> {
    use wallet::WalletCommand;

    let mut safe = args.safe;
    if safe.is_none()
        && matches!(
            args.command,
            WalletCommand::Sync(_) | WalletCommand::Sweep(_)
        )
    {
        if let Some(value) = std::env::var_os("SAFE_ADDRESS").filter(|v| !v.is_empty()) {
            let value = value.to_string_lossy();
            safe = Some(value.parse().map_err(|_| {
                color_eyre::eyre::eyre!("SAFE_ADDRESS: `{value}` is not an address")
            })?);
        }
    }
    let mut ctx = wallet::WalletContext::new();
    ctx.rpc_url = args.rpc_url;
    ctx.safe = safe;
    ctx.logger = console.logger().clone();
    ctx.prompt = console.prompt().clone();
    wallet::run_in(args.command, &ctx, console).await
}
