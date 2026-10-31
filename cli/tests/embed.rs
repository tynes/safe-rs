//! Another CLI that takes the `safe send` flags by flattening `SendOpts` into
//! its own command, as a downstream app would.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test harness: failures panic"
)]

use clap::{CommandFactory, Parser, Subcommand};
use safe_rs_cli::args::SendOpts;
use safe_rs_cli::safe_rs::{Address, Bytes, Call, U256};

#[derive(Parser)]
struct App {
    #[command(subcommand)]
    command: AppCommand,
}

#[derive(Subcommand)]
enum AppCommand {
    /// An app-specific transaction sent through a Safe
    Deposit(Deposit),
}

#[derive(clap::Args)]
struct Deposit {
    /// App-specific flag next to the Safe ones
    #[arg(long)]
    amount: U256,

    #[command(flatten)]
    safe: SendOpts,
}

const SAFE: &str = "0x1111111111111111111111111111111111111111";

fn deposit(extra: &[&str]) -> Result<Deposit, clap::Error> {
    let mut args = vec![
        "app",
        "deposit",
        "--amount",
        "5",
        "--rpc-url",
        "http://localhost:8545",
        "--safe",
        SAFE,
    ];
    args.extend_from_slice(extra);
    let AppCommand::Deposit(deposit) = App::try_parse_from(args)?.command;
    Ok(deposit)
}

#[test]
fn the_flags_flatten_into_another_command() {
    App::command().debug_assert();

    let parsed = deposit(&["--sign-only", "--gas-limit", "100000"]).unwrap();
    assert_eq!(parsed.amount, U256::from(5));
    assert_eq!(parsed.safe.safe.safe, Some(SAFE.parse().unwrap()));
    assert_eq!(parsed.safe.rpc.rpc_url.as_str(), "http://localhost:8545/");
    assert!(parsed.safe.sign_only);
    assert_eq!(parsed.safe.gas_limit, Some(100_000));
}

#[test]
fn the_conflicts_survive_flattening() {
    for conflicting in [
        &["--rotate", "--nonce", "3"][..],
        &["--rotate", "--skip-simulation"],
        &["--sign-only", "--approve-hash"],
        &["--no-sweep", "--sweep-reserve", "1"],
    ] {
        assert!(
            deposit(conflicting).is_err(),
            "{conflicting:?} must conflict"
        );
    }
}

#[tokio::test]
async fn send_keeps_the_send_guards() {
    let opts = deposit(&["--no-sweep"]).unwrap().safe;
    let call = Call::new(Address::ZERO, U256::ZERO, Bytes::new());
    let error = safe_rs_cli::send(vec![call], opts, false)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("only apply with --rotate"),
        "{error}"
    );
}
