//! Another CLI that takes the `safe create` options and the `safe wallet`
//! commands into its own command tree, as a downstream app would.
//!
//! The host has global `--rpc-url`, `--private-key` and `--safe` flags of its
//! own, so the embedded groups must not define them again.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test harness: failures panic"
)]

use clap::{CommandFactory, Parser, Subcommand};
use safe_rs_cli::create::{CreateContext, CreateError, CreateOpts, SafeSetupArgs};
use safe_rs_cli::prompt::NoPrompt;
use safe_rs_cli::safe_rs::Address;
use safe_rs_cli::OptionsError;

#[derive(Parser)]
struct Host {
    #[arg(long, global = true, env = "EMBED_CREATE_RPC_URL")]
    rpc_url: Option<String>,

    #[arg(long, global = true, env = "EMBED_CREATE_PRIVATE_KEY")]
    private_key: Option<String>,

    #[arg(long, global = true)]
    safe: Option<Address>,

    #[command(subcommand)]
    command: HostCommand,
}

#[derive(Subcommand)]
enum HostCommand {
    /// Deploy the account's Safe
    Setup {
        #[command(flatten)]
        create: Box<CreateOpts>,
    },
    /// A command of the host's own
    Balance,
    /// The account's HD wallets
    Wallet {
        #[command(subcommand)]
        command: safe_rs_cli::wallet::WalletCommand,
    },
}

fn parse(args: &[&str]) -> Result<Host, clap::Error> {
    Host::try_parse_from([&["host"], args].concat())
}

#[test]
fn the_host_command_tree_is_valid() {
    Host::command().debug_assert();
}

#[test]
fn create_flags_parse_next_to_the_host_flags() {
    const OWNER: &str = "0x2222222222222222222222222222222222222222";
    let host = parse(&[
        "setup",
        "--private-key",
        "0x01",
        "--owner",
        OWNER,
        "--threshold",
        "1",
        "--compute-only",
        "--max-fee-per-gas",
        "2gwei",
    ])
    .unwrap();
    assert_eq!(host.private_key.as_deref(), Some("0x01"));
    let HostCommand::Setup { create } = host.command else {
        panic!("expected setup");
    };
    assert!(create.compute_only);
    assert_eq!(create.setup.owners, vec![OWNER.parse::<Address>().unwrap()]);
    assert_eq!(create.fees.max_fee_per_gas, Some(2_000_000_000));
    assert!(create.validate(true).is_ok());
}

#[test]
fn create_defaults_match_the_flag_defaults() {
    let HostCommand::Setup { create } = parse(&["setup"]).unwrap().command else {
        panic!("expected setup");
    };
    let defaults = CreateOpts::default();
    assert_eq!(create.setup, SafeSetupArgs::default());
    assert_eq!(create.setup, defaults.setup);
    assert_eq!(create.fees, defaults.fees);
    assert_eq!(create.compute_only, defaults.compute_only);
    assert!(defaults.validate(true).is_ok());
}

#[test]
fn wallet_commands_mount_under_the_host() {
    let host = parse(&[
        "wallet",
        "status",
        "--mnemonic",
        "demo",
        "--safe",
        "0x1111111111111111111111111111111111111111",
    ])
    .unwrap();
    assert!(host.safe.is_some());
    let HostCommand::Wallet { command } = host.command else {
        panic!("expected wallet");
    };
    assert!(matches!(
        command,
        safe_rs_cli::wallet::WalletCommand::Status(_)
    ));
}

/// Options built in code are checked before the chain is reached: the RPC
/// URL points at port 9 (discard).
#[tokio::test]
async fn options_built_in_code_are_checked_like_flags() {
    let ctx = || CreateContext::new("http://127.0.0.1:9".parse().unwrap()).with_prompt(NoPrompt);

    let mut opts = CreateOpts::default();
    opts.sweep.no_sweep = true;
    let error = safe_rs_cli::create::create(ctx(), opts).await.unwrap_err();
    assert!(
        matches!(
            error,
            CreateError::Options(OptionsError::HdOnly { flag: "--no-sweep" })
        ),
        "{error:?}"
    );

    let mut opts = CreateOpts {
        rotate: true,
        ..CreateOpts::default()
    };
    opts.hd.ledger = true;
    let with_signer = ctx().with_signer(safe_rs_cli::PrivateKeySigner::random());
    let error = safe_rs_cli::create::create(with_signer, opts)
        .await
        .unwrap_err();
    assert!(
        matches!(error, CreateError::Options(OptionsError::SignerWithHd)),
        "{error:?}"
    );

    let opts = CreateOpts {
        rotate: true,
        ..CreateOpts::default()
    };
    let error = safe_rs_cli::create::create(ctx(), opts).await.unwrap_err();
    assert!(
        matches!(error, CreateError::Options(OptionsError::RotateWithoutKeys)),
        "{error:?}"
    );

    let mut opts = CreateOpts::default();
    opts.hd.mnemonic = Some("demo".into());
    let error = safe_rs_cli::create::create(ctx(), opts).await.unwrap_err();
    assert!(
        matches!(
            error,
            CreateError::Options(OptionsError::CreateHdWithoutRotate)
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_plain_create_needs_a_signer() {
    let ctx = CreateContext::new("http://127.0.0.1:9".parse().unwrap()).with_prompt(NoPrompt);
    let error = safe_rs_cli::create::create(ctx, CreateOpts::default())
        .await
        .unwrap_err();
    assert!(matches!(error, CreateError::NoSigner), "{error:?}");
    assert!(!error.may_be_pending());
}
