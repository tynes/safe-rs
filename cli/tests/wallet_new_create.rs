//! `safe wallet new --create`, and the funding check of `safe create`: a new
//! wallet and its Safe in one command, against a local Anvil chain with Safe
//! v1.4.1 deployed from the vendored artifacts.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test harness: setup panics are intended"
)]

#[allow(dead_code, reason = "the harness is shared with the library's tests")]
#[path = "../../tests/local/common.rs"]
mod common;

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use common::LocalHarness;
use safe_rs::MnemonicWallet;
use serde_json::Value;

struct Env<'a> {
    h: &'a LocalHarness,
    home: PathBuf,
    password_file: PathBuf,
}

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Output {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}):\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

impl<'a> Env<'a> {
    fn new(h: &'a LocalHarness, dir: &Path) -> Self {
        let password_file = dir.join("password");
        std::fs::write(&password_file, "correct horse battery staple\n").unwrap();
        Self {
            h,
            home: dir.join("home"),
            password_file,
        }
    }

    /// `safe <args> --json` with the RPC and the local Safe contracts.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = self.human(args);
        command.arg("--json");
        command
    }

    /// `safe <args>` with the RPC and the local Safe contracts.
    fn human(&self, args: &[&str]) -> Command {
        let mut command = self.bare(args);
        command.args(["--rpc-url", self.h.url().as_str()]).args([
            "--singleton",
            &self.h.addresses.safe_singleton.to_string(),
            "--factory",
            &self.h.addresses.proxy_factory.to_string(),
            "--fallback-handler",
            &self.h.addresses.fallback_handler.to_string(),
        ]);
        command
    }

    /// `safe <args>` with the password file, a private data directory, and
    /// none of the ambient environment variables the CLI reads.
    fn bare(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safe"));
        command
            .args(args)
            .args(["--password-file", self.password_file.to_str().unwrap()])
            .env("SAFE_RS_HOME", &self.home);
        for name in [
            "PRIVATE_KEY",
            "SAFE_ADDRESS",
            "ETH_RPC_URL",
            "ETH_PASSWORD",
            "ETH_KEYSTORE",
            "ETH_KEYSTORE_ACCOUNT",
            "ETH_FROM",
            "GAS_PAYER_PRIVATE_KEY",
        ] {
            command.env_remove(name);
        }
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        let output = self.command(args).output().expect("run safe");
        Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// The wallet the JSON document's phrase derives.
fn wallet_of(doc: &Value) -> MnemonicWallet {
    MnemonicWallet::from_phrase(doc["phrase"].as_str().expect("the phrase")).unwrap()
}

fn address(value: &Value) -> Address {
    value.as_str().expect("an address").parse().unwrap()
}

fn eth(amount: u64) -> U256 {
    U256::from(amount) * U256::from(10).pow(U256::from(18))
}

async fn balance(h: &LocalHarness, address: Address) -> U256 {
    h.provider.get_balance(address).await.unwrap()
}

/// Without funds, `--create` keeps the wallet, says what to send, and uses no
/// key: once funded, `safe create --rotate` makes the Safe with key 1.
#[tokio::test(flavor = "multi_thread")]
async fn an_unfunded_wallet_keeps_its_first_owner_key_for_later() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new(&h, dir.path());

    let failed = env.run(&["wallet", "new", "demo", "--create"]);
    assert!(!failed.ok, "an empty funding address cannot deploy");
    let doc = failed.json();
    assert_eq!(doc["name"], "demo");
    assert!(doc.get("safe").is_none());
    let error = doc["error"].as_str().unwrap();
    assert!(error.contains("holds 0 ETH"), "{error}");
    assert!(
        failed.stderr.contains("safe create --rotate --wallet demo"),
        "the error says how to finish: {}",
        failed.stderr
    );
    let wallet = wallet_of(&doc);
    assert_eq!(address(&doc["funding_address"]), wallet.id());
    assert!(env.home.join("wallets/demo.json").exists());

    h.fund(wallet.id(), eth(1)).await;
    let created = env.run(&["create", "--rotate", "--wallet", "demo"]).json();
    assert_eq!(created["owner"]["index"], 1, "key 1 was not used up");
    let safe = address(&created["safe_address"]);
    assert_eq!(h.owners(safe).await, vec![wallet.owner_address(1).unwrap()]);
}

/// `--wait-for-funds` waits for the funding address, then deploys and moves
/// what is left to the owner key.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_new_create_waits_for_funds_then_deploys() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new(&h, dir.path());

    let mut child = env
        .command(&["wallet", "new", "demo", "--create", "--wait-for-funds=120"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run safe");
    // Under --json the wait is announced as a warning naming the address.
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut seen = String::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if let Some(rest) = line.split("waiting for ").nth(1) {
                let funding: Address = rest.split_whitespace().next().unwrap().parse().unwrap();
                tx.send(funding).unwrap();
            }
            seen.push_str(&line);
            seen.push('\n');
        }
        seen
    });
    let funding = rx
        .recv_timeout(std::time::Duration::from_mins(2))
        .expect("the command announces the wait");
    h.fund(funding, eth(1)).await;

    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let status = child.wait().unwrap();
    let stderr = reader.join().unwrap();
    assert!(status.success(), "{stdout}\n{stderr}");
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let wallet = wallet_of(&doc);
    assert_eq!(wallet.id(), funding);
    let owner = wallet.owner_address(1).unwrap();
    let safe = address(&doc["safe"]["safe_address"]);
    assert_eq!(doc["safe"]["owner"]["index"], 1);
    assert_eq!(address(&doc["safe"]["payer"]), funding);
    assert_eq!(h.owners(safe).await, vec![owner]);
    assert_eq!(balance(&h, funding).await, U256::ZERO, "swept to the owner");
    assert!(balance(&h, owner).await > U256::ZERO);
    assert_eq!(
        h.provider.get_transaction_count(owner).await.unwrap(),
        0,
        "deploying did not publish the owner key"
    );
}

/// Without --create, `--json` does not count as a Safe option.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_new_json_without_create_still_works() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new(&h, dir.path());

    let output = env
        .bare(&["wallet", "new", "demo", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(address(&doc["funding_address"]), wallet_of(&doc).id());
}

/// In text mode the wallet and its phrase go out as progress before the
/// wait, once, and the result is the Safe and the next step.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_new_create_shows_the_phrase_once_before_waiting() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new(&h, dir.path());

    let mut child = env
        .human(&[
            "wallet",
            "new",
            "demo",
            "--create",
            "--no-confirm",
            "--wait-for-funds=120",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run safe");
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut seen = String::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if line.starts_with("Send at least") {
                let funding: Address = line.split("(").nth(1).unwrap()[..42].parse().unwrap();
                tx.send(funding).unwrap();
            }
            seen.push_str(&line);
            seen.push('\n');
        }
        seen
    });
    let funding = rx
        .recv_timeout(std::time::Duration::from_mins(2))
        .expect("the command says what to send");
    h.fund(funding, eth(1)).await;

    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let status = child.wait().unwrap();
    let stderr = reader.join().unwrap();
    assert!(status.success(), "{stdout}\n{stderr}");

    let phrase = stderr
        .lines()
        .skip_while(|line| !line.starts_with("Recovery phrase"))
        .find(|line| line.starts_with("  "))
        .expect("the phrase is shown before the wait")
        .trim();
    assert_eq!(phrase.split(' ').count(), 24);
    assert_eq!(stderr.matches(phrase).count(), 1, "{stderr}");
    assert!(stderr.contains("Recommended:"), "{stderr}");
    assert!(
        stderr.contains("safe create --rotate --wallet demo"),
        "{stderr}"
    );
    assert!(!stdout.contains(phrase), "{stdout}");
    assert!(stdout.contains("Next: safe send"), "{stdout}");

    let wallet = MnemonicWallet::from_phrase(phrase).unwrap();
    assert_eq!(wallet.id(), funding);
    let safe: Address = stdout.split("Safe Address: ").nth(1).unwrap()[..42]
        .parse()
        .unwrap();
    assert_eq!(h.owners(safe).await, vec![wallet.owner_address(1).unwrap()]);
}

/// A gas payer deploys at once, with no wait and nothing to sweep.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_new_create_with_a_gas_payer_deploys_at_once() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new(&h, dir.path());
    let payer = alloy::hex::encode_prefixed(h.deployer.to_bytes());

    let out = env.run(&[
        "wallet",
        "new",
        "demo",
        "--create",
        "--threshold",
        "2",
        "--owner",
        &h.owner.address().to_string(),
        "--gas-payer-private-key",
        &payer,
    ]);
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    let doc = out.json();
    let wallet = wallet_of(&doc);
    let safe = address(&doc["safe"]["safe_address"]);
    assert_eq!(address(&doc["safe"]["payer"]), h.deployer.address());
    assert!(doc["safe"].get("sweep").is_none());
    assert_eq!(doc["safe"]["threshold"], 2);
    assert_eq!(
        h.owners(safe).await,
        vec![wallet.owner_address(1).unwrap(), h.owner.address()]
    );
    assert_eq!(balance(&h, wallet.id()).await, U256::ZERO);
}

/// A plain `safe create` from an empty key says how much to send.
#[tokio::test(flavor = "multi_thread")]
async fn create_from_an_empty_key_says_what_to_send() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new(&h, dir.path());
    let key = alloy::signers::local::PrivateKeySigner::random();

    let out = env.run(&[
        "create",
        "--private-key",
        &alloy::hex::encode_prefixed(key.to_bytes()),
    ]);
    assert!(!out.ok);
    assert!(
        out.stderr
            .contains(&format!("{} holds 0 ETH", key.address())),
        "{}",
        out.stderr
    );
}
