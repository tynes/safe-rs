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
use safe_rs_cli::{OptionsError, Output, SendContext, SendError};

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

/// Options to set, the error they give and part of its message.
type OptionsCase = (fn(&mut SendOpts), OptionsError, &'static str);

#[tokio::test]
async fn options_built_in_code_are_checked_like_flags() {
    #[cfg_attr(
        not(feature = "hd-wallet"),
        allow(unused_mut, reason = "the rotation cases need hd-wallet")
    )]
    let mut cases: Vec<OptionsCase> = vec![(
        |o| {
            o.simulate_only = true;
            o.skip_simulation = true;
        },
        OptionsError::Conflict {
            flag: "--skip-simulation",
            with: "--simulate-only",
        },
        "--skip-simulation cannot be used with --simulate-only",
    )];
    #[cfg(feature = "hd-wallet")]
    cases.extend::<[OptionsCase; 3]>([
        (
            |o| {
                o.rotate = true;
                o.nonce = Some(U256::from(3));
            },
            OptionsError::Conflict {
                flag: "--rotate",
                with: "--nonce",
            },
            "--rotate cannot be used with --nonce",
        ),
        (
            |o| o.sweep.no_sweep = true,
            OptionsError::SweepWithoutRotate,
            "only apply with --rotate",
        ),
        (
            |o| o.hd.ledger = true,
            OptionsError::HdWithoutRotate,
            "needs --rotate",
        ),
    ]);
    for (set, expected, message) in cases {
        let mut opts = SendOpts::default();
        set(&mut opts);
        if let OptionsError::Conflict { .. } = expected {
            assert_eq!(opts.validate(), Err(expected.clone()));
        }
        let error = safe_rs_cli::send(context(), call(), opts)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
        match error {
            SendError::Options(found) => assert_eq!(found, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_send_needs_a_signer_and_calls() {
    // Both fail before the chain is reached.
    let error = safe_rs_cli::send(context(), call(), SendOpts::default())
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::NoSigner), "{error:?}");
    assert!(!error.may_be_pending());

    let ctx = context().with_signer(safe_rs_cli::PrivateKeySigner::random());
    let error = safe_rs_cli::send(ctx, Vec::new(), SendOpts::default())
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::NoCalls), "{error:?}");
}

#[test]
fn send_errors_convert_to_eyre_reports() {
    fn host() -> eyre::Result<()> {
        Err(SendError::NoSigner)?;
        Ok(())
    }
    let report = host().unwrap_err();
    assert!(report.downcast_ref::<SendError>().is_some());
}

#[cfg(feature = "hd-wallet")]
#[tokio::test]
async fn rotation_takes_no_signer_from_the_host() {
    let opts = SendOpts {
        rotate: true,
        ..SendOpts::default()
    };
    let ctx = context().with_signer(safe_rs_cli::PrivateKeySigner::random());
    let error = safe_rs_cli::send(ctx, call(), opts).await.unwrap_err();
    assert!(
        matches!(error, SendError::Options(OptionsError::RotateWithSigner)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("send without a signer"),
        "{error}"
    );
}

fn eoa_context() -> SendContext {
    // Port 9 (discard), as in `context`: every error below comes from a check
    // that runs before the chain is reached.
    SendContext::eoa("http://127.0.0.1:9".parse().unwrap())
        .with_signer(safe_rs_cli::PrivateKeySigner::random())
        .with_output(Output::Quiet)
}

#[tokio::test]
async fn an_eoa_send_refuses_the_options_only_a_safe_has() {
    type Case = (fn(&mut SendOpts), &'static str);
    #[cfg_attr(
        not(feature = "hd-wallet"),
        allow(unused_mut, reason = "the rotation cases need hd-wallet")
    )]
    let mut cases: Vec<Case> = vec![
        (|o| o.bundle = Some("tx.json".into()), "--bundle"),
        (|o| o.sign_only = true, "--sign-only"),
        (|o| o.approve_hash = true, "--approve-hash"),
        (|o| o.nonce = Some(U256::from(1)), "--nonce"),
        (|o| o.no_submit = true, "--no-submit"),
        (
            |o| o.payer.payer_private_key = Some("0x01".into()),
            "--payer-private-key",
        ),
    ];
    #[cfg(feature = "hd-wallet")]
    cases.extend::<[Case; 2]>([
        (|o| o.rotate = true, "--rotate"),
        (|o| o.hd.ledger = true, "--ledger"),
    ]);
    for (set, flag) in cases {
        let mut opts = SendOpts::default();
        set(&mut opts);
        let error = safe_rs_cli::send(eoa_context(), call(), opts)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                SendError::Options(OptionsError::SafeOnly { flag: found }) if *found == flag
            ),
            "{flag}: {error:?}"
        );
        assert!(error.to_string().contains("not from an EOA"), "{error}");
    }
}

#[tokio::test]
async fn an_eoa_send_takes_a_gas_limit_for_one_call_only() {
    let opts = SendOpts {
        gas_limit: Some(100_000),
        ..SendOpts::default()
    };
    let two = vec![call().remove(0), call().remove(0)];
    let error = safe_rs_cli::send(eoa_context(), two, opts)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SendError::Options(OptionsError::GasLimitForBatch { calls: 2 })
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_eoa_send_needs_a_signer_calls_and_plain_calls() {
    let no_signer = SendContext::eoa("http://127.0.0.1:9".parse().unwrap());
    let error = safe_rs_cli::send(no_signer, call(), SendOpts::default())
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::NoSigner), "{error:?}");

    let error = safe_rs_cli::send(eoa_context(), Vec::new(), SendOpts::default())
        .await
        .unwrap_err();
    assert!(
        matches!(error, SendError::Safe(safe_rs_cli::safe_rs::Error::NoCalls)),
        "{error:?}"
    );

    let delegate = vec![Call::delegate_call(Address::ZERO, Bytes::new())];
    let error = safe_rs_cli::send(eoa_context(), delegate, SendOpts::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SendError::Safe(safe_rs_cli::safe_rs::Error::UnsupportedEoaOperation { .. })
        ),
        "{error:?}"
    );
}
