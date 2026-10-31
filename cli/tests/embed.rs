//! Another CLI that takes the `safe send` options by flattening `SendOpts`
//! into its own command, as a downstream app would.
//!
//! The host is shaped like polymarket-cli: global `--rpc-url` and
//! `--private-key` flags of its own, with its own environment variables.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test harness: failures panic"
)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use clap::{CommandFactory, Parser, Subcommand};
use safe_rs_cli::args::{SendOpts, DEFAULT_BLOCK_TIME, DEFAULT_TIMEOUT};
use safe_rs_cli::safe_rs::{Address, Bytes, Call, U256};
use safe_rs_cli::{Output, SendContext};

#[derive(Parser)]
struct Host {
    #[arg(short, long, global = true, default_value = "table")]
    output: String,

    #[arg(long, global = true, env = "EMBED_TEST_PRIVATE_KEY")]
    private_key: Option<String>,

    #[arg(long, global = true, env = "EMBED_TEST_RPC_URL")]
    rpc_url: Option<String>,

    #[command(subcommand)]
    cmd: HostCommand,
}

#[derive(Subcommand)]
enum HostCommand {
    Approve {
        #[command(subcommand)]
        cmd: Approve,
    },
}

#[derive(Subcommand)]
enum Approve {
    /// An app-specific transaction sent through a Safe
    Set {
        #[arg(long)]
        amount: Option<U256>,

        #[command(flatten)]
        send: SendOpts,
    },
}

/// Parses `args` after the binary name, failing the test on a panic.
fn parse(args: &[&str]) -> Result<(Host, Option<U256>, SendOpts), clap::Error> {
    let argv: Vec<&str> = std::iter::once("pm").chain(args.iter().copied()).collect();
    let parsed = catch_unwind(AssertUnwindSafe(|| Host::try_parse_from(&argv)))
        .unwrap_or_else(|_| panic!("parsing {args:?} panicked"))?;
    let HostCommand::Approve {
        cmd: Approve::Set { amount, send },
    } = &parsed.cmd;
    let (amount, send) = (*amount, send.clone());
    Ok((parsed, amount, send))
}

#[test]
fn the_host_keeps_its_own_rpc_url_and_private_key() {
    Host::command().debug_assert();

    let (host, _, send) = parse(&["approve", "set"]).unwrap();
    assert_eq!(host.rpc_url, None);
    assert_eq!(send.timeout, DEFAULT_TIMEOUT);

    // Before and after the subcommand: either way the flag is the host's.
    for args in [
        &["--rpc-url", "http://x", "approve", "set"][..],
        &["approve", "set", "--rpc-url", "http://x"],
    ] {
        let (host, ..) = parse(args).unwrap();
        assert_eq!(host.rpc_url.as_deref(), Some("http://x"), "{args:?}");
    }

    let (host, amount, send) = parse(&[
        "--private-key",
        "0x01",
        "approve",
        "set",
        "--amount",
        "5",
        "--sign-only",
        "--gas-limit",
        "100000",
    ])
    .unwrap();
    assert_eq!(host.private_key.as_deref(), Some("0x01"));
    assert_eq!(amount, Some(U256::from(5)));
    assert!(send.sign_only);
    assert_eq!(send.gas_limit, Some(100_000));
}

#[test]
fn the_conflicts_survive_flattening() {
    for conflicting in [
        &["--rotate", "--nonce", "3"][..],
        &["--rotate", "--skip-simulation"],
        &["--sign-only", "--approve-hash"],
        &["--simulate-only", "--skip-simulation"],
        &["--no-sweep", "--sweep-reserve", "1"],
    ] {
        let mut args = vec!["approve", "set"];
        args.extend_from_slice(conflicting);
        assert!(parse(&args).is_err(), "{conflicting:?} must conflict");
    }
}

#[test]
fn defaults_match_the_flag_defaults() {
    let defaults = SendOpts::default();
    let (_, _, parsed) = parse(&["approve", "set"]).unwrap();
    assert_eq!(defaults.timeout, parsed.timeout);
    assert_eq!(defaults.sim.block_time, parsed.sim.block_time);
    assert_eq!(defaults.sim.block_time, DEFAULT_BLOCK_TIME);
    assert!(defaults.validate().is_ok());
}

#[test]
fn debug_output_hides_secrets() {
    let mut opts = SendOpts::default();
    opts.password.password = Some("hunter2".into());
    opts.payer.payer_private_key = Some("0xdeadbeef".into());
    let debug = format!("{opts:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
    assert!(!debug.contains("deadbeef"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

fn context() -> SendContext {
    // Port 9 (discard): any attempt to reach the chain fails, so each error
    // below comes from a check that runs first.
    SendContext::new(
        "http://127.0.0.1:9".parse().unwrap(),
        Address::repeat_byte(0x11),
    )
    .with_output(Output::Quiet)
}

fn call() -> Vec<Call> {
    vec![Call::new(Address::ZERO, U256::ZERO, Bytes::new())]
}

#[tokio::test]
async fn options_built_in_code_are_checked_like_flags() {
    let cases: [(fn(&mut SendOpts), &str); 4] = [
        (
            |o| {
                o.rotate = true;
                o.nonce = Some(U256::from(3));
            },
            "--rotate cannot be used with --nonce",
        ),
        (
            |o| {
                o.simulate_only = true;
                o.skip_simulation = true;
            },
            "--skip-simulation cannot be used with --simulate-only",
        ),
        (|o| o.sweep.no_sweep = true, "only apply with --rotate"),
        (|o| o.hd.ledger = true, "needs --rotate"),
    ];
    for (set, expected) in cases {
        let mut opts = SendOpts::default();
        set(&mut opts);
        let error = safe_rs_cli::send(context(), call(), opts)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[tokio::test]
async fn rotation_takes_no_signer_from_the_host() {
    let opts = SendOpts {
        rotate: true,
        ..SendOpts::default()
    };
    let ctx = context().with_signer(safe_rs_cli::PrivateKeySigner::random());
    let error = safe_rs_cli::send(ctx, call(), opts).await.unwrap_err();
    assert!(
        error.to_string().contains("send without a signer"),
        "{error}"
    );
}
