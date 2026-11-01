//! The `safe` binary end to end: an HD wallet, a Safe created with it, sends
//! that rotate the owner, and recovery of lost state.
//!
//! Runs against a fresh local Anvil chain with Safe v1.4.1 deployed from the
//! vendored artifacts, so no RPC URL is needed.
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

use std::path::{Path, PathBuf};
use std::process::Command;

use alloy::primitives::{Address, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::Provider;
use common::LocalHarness;
use safe_rs::rotation::{binding_key, OwnerRef, RotationState, StateFile};
use safe_rs::{ChainAddresses, HdWallet};
use serde_json::Value;

/// A BIP-39 test vector, deliberately not Anvil's own phrase.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

struct Cli<'a> {
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
    /// Progress (stderr) followed by the result (stdout).
    fn all(&self) -> String {
        format!("{}\n{}", self.stderr, self.stdout)
    }

    fn json(&self) -> Value {
        assert!(self.ok, "command failed:\n{}\n{}", self.stdout, self.stderr);
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}):\n{}", self.stdout))
    }
}

impl Cli<'_> {
    /// Runs `safe` with a private data directory and none of the ambient
    /// environment variables the CLI reads.
    fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safe"));
        command.args(args).env("SAFE_RS_HOME", &self.home);
        for name in [
            "PRIVATE_KEY",
            "SAFE_ADDRESS",
            "ETH_RPC_URL",
            "SAFE_HD_WALLET",
            "SAFE_PASSWORD_FILE",
            "SAFE_PAYER_PRIVATE_KEY",
        ] {
            command.env_remove(name);
        }
        command.envs(env.iter().copied());
        let output = command.output().expect("run safe");
        Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_env(args, &[])
    }

    /// `args` plus the wallet, its password, the RPC URL and `--json`.
    fn wallet_command(&self, args: &[&str]) -> Output {
        let url = self.h.url().to_string();
        let password = self.password_file.to_str().unwrap();
        let mut all = args.to_vec();
        // A rotating Safe is created with `create --rotate`.
        if all.first() == Some(&"create") {
            all.push("--rotate");
        }
        all.extend([
            "--hd-wallet",
            "demo",
            "--password-file",
            password,
            "--rpc-url",
            &url,
            "--json",
        ]);
        self.run(&all)
    }
}

fn eth(amount: u64) -> U256 {
    U256::from(amount) * U256::from(10).pow(U256::from(18))
}

fn key(index: u32) -> Address {
    HdWallet::from_phrase(PHRASE)
        .unwrap()
        .owner_address(index)
        .unwrap()
}

fn address(value: &Value) -> Address {
    value.as_str().expect("an address").parse().unwrap()
}

/// A wei amount as the CLI prints it in JSON (a hex quantity).
fn wei(value: &Value) -> U256 {
    value.as_str().expect("a quantity").parse().unwrap()
}

async fn balance(h: &LocalHarness, address: Address) -> U256 {
    h.provider.get_balance(address).await.unwrap()
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
}

/// A cheap test keystore: password handling is covered by the lifecycle test.
fn discovery_wallet<'a>(h: &'a LocalHarness, dir: &Path) -> Cli<'a> {
    use safe_rs::keystore::{encrypt_mnemonic_keystore, ScryptParams};

    let cli = Cli {
        h,
        home: dir.join("home"),
        password_file: dir.join("password"),
    };
    write(&cli.password_file, "pw");
    std::fs::create_dir_all(cli.home.join("wallets")).unwrap();
    let json = encrypt_mnemonic_keystore(
        PHRASE,
        b"pw",
        ScryptParams {
            log_n: 4,
            r: 8,
            p: 1,
        },
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    write(&cli.home.join("wallets/demo.json"), &json);
    cli
}

#[tokio::test(flavor = "multi_thread")]
async fn rotate_discovers_only_an_unambiguous_recorded_safe() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = discovery_wallet(&h, dir.path());
    let wallet = HdWallet::from_phrase(PHRASE).unwrap();
    let path = cli
        .home
        .join("state")
        .join(format!("{}.json", wallet.id().to_string().to_lowercase()));
    let safe = h.deploy_safe_with(&[key(1)], 1, 600).await;
    let other = h.deploy_safe_with(&[key(2)], 1, 601).await;
    let mut store = StateFile::open(&path, wallet.id()).unwrap();
    let owner = |index| OwnerRef::Derived {
        index,
        address: key(index),
    };
    // A Safe on another chain must not be selected, even at the same address.
    store
        .state
        .bind(&binding_key(h.chain_id + 1, safe), owner(1))
        .unwrap();
    store.save().unwrap();
    drop(store);
    let before = std::fs::read(&path).unwrap();
    let missing = cli.wallet_command(&["rotate"]);
    assert!(!missing.ok);
    assert!(
        missing.stderr.contains("No Safe recorded"),
        "{}",
        missing.stderr
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let mut store = StateFile::open(&path, wallet.id()).unwrap();
    store
        .state
        .bind(&binding_key(h.chain_id, safe), owner(1))
        .unwrap();
    store
        .state
        .bind(&binding_key(h.chain_id, other), owner(2))
        .unwrap();
    store.save().unwrap();
    drop(store);
    let before = std::fs::read(&path).unwrap();
    let ambiguous = cli.wallet_command(&["rotate"]);
    assert!(!ambiguous.ok);
    assert!(
        ambiguous.stderr.contains("Multiple Safes"),
        "{}",
        ambiguous.stderr
    );
    assert!(ambiguous.stderr.contains(&safe.to_string()));
    assert!(ambiguous.stderr.contains(&other.to_string()));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(h.owners(safe).await, vec![key(1)]);
    assert_eq!(h.owners(other).await, vec![key(2)]);
    assert_eq!(h.provider.get_transaction_count(key(1)).await.unwrap(), 0);

    // An explicit address overrides ambiguity and ignores SAFE_ADDRESS.
    h.fund(key(1), eth(1)).await;
    let msco = h.addresses.multi_send_call_only.to_string();
    let explicit = cli
        .run_with_env(
            &[
                "rotate",
                &safe.to_string(),
                "--hd-wallet",
                "demo",
                "--password-file",
                cli.password_file.to_str().unwrap(),
                "--rpc-url",
                h.url().as_str(),
                "--multi-send-call-only",
                &msco,
                "--json",
            ],
            &[("SAFE_ADDRESS", &other.to_string())],
        )
        .json();
    assert_eq!(explicit["status"], "rotated");
    assert_eq!(h.owners(other).await, vec![key(2)]);

    // With only one binding on this chain, subsequent rotations need no address.
    let mut store = StateFile::open(&path, wallet.id()).unwrap();
    store.state.safes.remove(&binding_key(h.chain_id, other));
    store.save().unwrap();
    drop(store);
    let rotated = cli
        .wallet_command(&["rotate", "--multi-send-call-only", &msco])
        .json();
    assert_eq!(rotated["status"], "rotated");
    assert_eq!(
        h.owners(safe).await,
        vec![address(&rotated["owner"]["address"])]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rotate_and_info_share_legacy_default_discovery() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = discovery_wallet(&h, dir.path());
    let legacy = alloy::signers::local::PrivateKeySigner::random();
    let legacy_key = alloy::primitives::hex::encode_prefixed(legacy.to_bytes());
    h.fund(legacy.address(), eth(2)).await;
    let wallet = HdWallet::from_phrase(PHRASE).unwrap();
    let path = cli
        .home
        .join("state")
        .join(format!("{}.json", wallet.id().to_string().to_lowercase()));
    // Legacy discovery takes precedence even when the HD wallet tracks a Safe.
    let unrelated = h.deploy_safe_with(&[key(1)], 1, 602).await;
    let mut store = StateFile::open(&path, wallet.id()).unwrap();
    store
        .state
        .bind(
            &binding_key(h.chain_id, unrelated),
            OwnerRef::Derived {
                index: 1,
                address: key(1),
            },
        )
        .unwrap();
    store.save().unwrap();
    drop(store);
    let before = std::fs::read(&path).unwrap();
    let discover = |extra: &[&str]| {
        let mut args = vec!["rotate", "--from-private-key", &legacy_key, "--no-sweep"];
        args.extend_from_slice(extra);
        cli.wallet_command(&args)
    };
    let missing = discover(&[]);
    assert!(!missing.ok);
    assert!(
        missing.stderr.contains("no known Safe proxy factory"),
        "{}",
        missing.stderr
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);

    // Install canonical contracts using local fixture code. v1.5.0's singleton
    // reports that version; the fixture otherwise implements v1.4.1 behavior.
    let newer_singleton = h.deploy_singleton_reporting("1.5.0").await;
    for (addresses, singleton) in [
        (ChainAddresses::v1_4_1(), h.addresses.safe_singleton),
        (ChainAddresses::v1_5_0(), newer_singleton),
    ] {
        for (target, source) in [
            (addresses.proxy_factory, h.addresses.proxy_factory),
            (addresses.safe_singleton, singleton),
            (addresses.fallback_handler, h.addresses.fallback_handler),
            (
                addresses.multi_send_call_only,
                h.addresses.multi_send_call_only,
            ),
        ] {
            let code = h.provider.get_code_at(source).await.unwrap();
            h.provider.anvil_set_code(target, code).await.unwrap();
        }
    }
    let missing = discover(&[]);
    assert!(!missing.ok);
    assert!(
        missing.stderr.contains("nothing is deployed"),
        "{}",
        missing.stderr
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        h.provider
            .get_transaction_count(legacy.address())
            .await
            .unwrap(),
        0
    );

    let create = |version: &str| {
        cli.run(&[
            "create",
            "--private-key",
            &legacy_key,
            "--safe-version",
            version,
            "--rpc-url",
            h.url().as_str(),
            "--no-confirm",
            "--json",
        ])
        .json()
    };
    let info = || {
        cli.run(&[
            "info",
            "--private-key",
            &legacy_key,
            "--rpc-url",
            h.url().as_str(),
            "--json",
        ])
        .json()
    };
    let old = address(&create("1.4.1")["safe_address"]);
    assert_eq!(address(&info()["address"]), old);
    let preview = discover(&["--simulate-only"]).json();
    assert_eq!(
        address(&preview["rotation"]["old_owner"]["address"]),
        legacy.address()
    );
    let state: RotationState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(state.safes.contains_key(&binding_key(h.chain_id, old)));
    assert_eq!(h.owners(old).await, vec![legacy.address()]);

    let new = address(&create("1.5.0")["safe_address"]);
    assert_eq!(address(&info()["address"]), new);
    let moved = discover(&[]).json();
    assert_eq!(moved["status"], "rotated");
    assert_eq!(
        h.owners(new).await,
        vec![address(&moved["owner"]["address"])]
    );
    assert_eq!(h.owners(old).await, vec![legacy.address()]);
    assert_eq!(h.owners(unrelated).await, vec![key(1)]);
    let state: RotationState = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(state.safes.contains_key(&binding_key(h.chain_id, new)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_safe_lives_on_one_time_keys_from_creation_to_recovery() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli {
        h: &h,
        home: dir.path().join("home"),
        password_file: dir.path().join("password"),
    };
    write(&cli.password_file, "correct horse battery staple\n");
    let phrase_file = dir.path().join("phrase");
    write(&phrase_file, &format!("{PHRASE}\n"));
    let funding = HdWallet::from_phrase(PHRASE).unwrap().id();
    let password = cli.password_file.to_str().unwrap().to_string();
    let singleton = h.addresses.safe_singleton.to_string();
    let factory = h.addresses.proxy_factory.to_string();
    let handler = h.addresses.fallback_handler.to_string();
    let msco = h.addresses.multi_send_call_only.to_string();

    // --- The wallet: an encrypted phrase on disk. ---
    let imported = cli
        .run(&[
            "wallet",
            "import",
            "demo",
            "--phrase-file",
            phrase_file.to_str().unwrap(),
            "--password-file",
            &password,
            "--json",
        ])
        .json();
    assert_eq!(address(&imported["funding_address"]), funding);
    assert!(
        imported.get("phrase").is_none(),
        "an imported phrase is not echoed"
    );
    let keystore = std::fs::read_to_string(cli.home.join("wallets/demo.json")).unwrap();
    assert!(
        !keystore.contains("winner"),
        "the phrase is not stored in the clear"
    );

    let listed = cli.run(&["wallet", "list", "--json"]).json();
    assert_eq!(listed["wallets"][0]["name"], "demo");
    // The funding address needs no password; an owner key does.
    let shown = cli.run(&["wallet", "address", "--hd-wallet", "demo"]);
    assert_eq!(shown.stdout.trim(), funding.to_string());
    let first = cli
        .run(&[
            "wallet",
            "address",
            "--hd-wallet",
            "demo",
            "--index",
            "1",
            "--password-file",
            &password,
            "--json",
        ])
        .json();
    assert_eq!(address(&first["address"]), key(1));
    assert_eq!(first["path"], "m/44'/60'/0'/0/1");
    let wrong = dir.path().join("wrong");
    write(&wrong, "not the password");
    let refused = cli.run(&[
        "wallet",
        "address",
        "--hd-wallet",
        "demo",
        "--index",
        "1",
        "--password-file",
        wrong.to_str().unwrap(),
    ]);
    assert!(!refused.ok);
    assert!(
        refused.stderr.contains("Wrong keystore password"),
        "{}",
        refused.stderr
    );

    // --- A Safe owned by a key that has never signed. ---
    h.fund(funding, eth(1)).await;
    let created = cli
        .wallet_command(&[
            "create",
            "--singleton",
            &singleton,
            "--factory",
            &factory,
            "--fallback-handler",
            &handler,
        ])
        .json();
    let safe = address(&created["safe_address"]);
    let safe_arg = safe.to_string();
    assert_eq!(created["owner"]["index"], 1);
    assert_eq!(address(&created["payer"]), funding);
    assert_eq!(h.owners(safe).await, vec![key(1)]);
    assert_eq!(balance(&h, funding).await, U256::ZERO, "swept to the owner");
    assert_eq!(balance(&h, key(1)).await, wei(&created["sweep"]["amount"]));
    assert_eq!(
        h.provider.get_transaction_count(key(1)).await.unwrap(),
        0,
        "deploying did not publish the owner key"
    );
    h.fund(safe, U256::from(1_000)).await;

    // --- Every send rotates the owner and moves the gas money along. ---
    let recipient = Address::repeat_byte(0x42).to_string();
    let send = |extra: &[&str]| {
        let mut args = vec![
            "send",
            recipient.as_str(),
            "--value",
            "5",
            "--safe",
            safe_arg.as_str(),
            "--multi-send-call-only",
            msco.as_str(),
            "--rotate",
        ];
        args.extend_from_slice(extra);
        cli.wallet_command(&args)
    };
    let sent = send(&[]).json();
    assert_eq!(sent["status"], "rotated");
    assert_eq!(sent["success"], true);
    assert_eq!(sent["old_owner"]["index"], 1);
    assert_eq!(sent["owner"]["index"], 2);
    assert_eq!(h.owners(safe).await, vec![key(2)]);
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);
    assert!(balance(&h, key(2)).await > U256::ZERO);
    assert_eq!(balance(&h, Address::repeat_byte(0x42)).await, U256::from(5));

    let status = cli
        .run(&["wallet", "status", "--hd-wallet", "demo", "--json"])
        .json();
    assert_eq!(status["next_index"], 3);
    assert_eq!(status["safes"][0]["owner"]["index"], 2);
    assert_eq!(
        status["safes"][0]["retired_keys"].as_array().unwrap().len(),
        1
    );
    assert!(status["safes"][0].get("exposed").is_none());

    // --- Without the sweep the next owner cannot pay, until it is swept. ---
    let unswept = send(&["--no-sweep"]).json();
    assert_eq!(unswept["owner"]["index"], 3);
    assert!(unswept.get("sweep").is_none());
    assert!(balance(&h, key(2)).await > U256::ZERO);
    assert_eq!(balance(&h, key(3)).await, U256::ZERO);
    let unfunded = send(&[]);
    assert!(!unfunded.ok);
    assert!(
        unfunded.stderr.contains("cannot pay"),
        "{}",
        unfunded.stderr
    );
    assert_eq!(h.owners(safe).await, vec![key(3)], "nothing was sent");

    let swept = cli
        .wallet_command(&["wallet", "sweep", "--safe", &safe_arg])
        .json();
    assert_eq!(swept["sweeps"].as_array().unwrap().len(), 1);
    assert_eq!(address(&swept["sweeps"][0]["from"]), key(2));
    assert_eq!(address(&swept["sweeps"][0]["to"]), key(3));
    assert!(swept.get("still_owed").is_none());
    assert_eq!(balance(&h, key(2)).await, U256::ZERO);

    // --- A rotation with no other calls. ---
    let rotated = cli
        .wallet_command(&["rotate", &safe_arg, "--multi-send-call-only", &msco])
        .json();
    assert_eq!(rotated["status"], "rotated");
    assert_eq!(rotated["owner"]["index"], 4);
    assert_eq!(h.owners(safe).await, vec![key(4)]);

    // --- The same Safe for another chain reuses the first owner and salt. ---
    let chain_id = h.chain_id.to_string();
    let twin = cli
        .wallet_command(&[
            "create",
            "--same-as",
            &format!("{chain_id}:{safe_arg}"),
            "--compute-only",
        ])
        .json();
    assert_eq!(address(&twin["safe_address"]), safe);
    assert_eq!(twin["owner"]["index"], 1);
    // A preview of a new Safe does not use up a key.
    let preview = cli
        .wallet_command(&[
            "create",
            "--singleton",
            &singleton,
            "--factory",
            &factory,
            "--fallback-handler",
            &handler,
            "--compute-only",
        ])
        .json();
    assert_eq!(preview["owner"]["index"], 5);
    assert_ne!(address(&preview["safe_address"]), safe);
    let status = cli
        .run(&["wallet", "status", "--hd-wallet", "demo", "--json"])
        .json();
    assert_eq!(status["next_index"], 5);

    // --- Lost state is rebuilt from the chain. ---
    std::fs::remove_dir_all(cli.home.join("state")).unwrap();
    let synced = cli
        .wallet_command(&[
            "wallet",
            "sync",
            "--safe",
            &safe_arg,
            "--scan-limit",
            "40",
            "--from-block",
            "0",
        ])
        .json();
    assert_eq!(synced["owner"]["index"], 4);
    assert_eq!(synced["used"], serde_json::json!([1, 2, 3, 4]));
    assert!(synced["next_index"].as_u64().unwrap() > 5);
    let status = cli
        .run(&["wallet", "status", "--hd-wallet", "demo", "--json"])
        .json();
    assert_eq!(status["safes"][0]["exposed"], "rebuilt");
    assert_eq!(
        status["safes"][0]["retired_keys"].as_array().unwrap().len(),
        3
    );

    // --- The flags that would defeat the scheme are refused. ---
    let no_rotate = cli.wallet_command(&["send", &recipient, "--value", "1", "--safe", &safe_arg]);
    assert!(!no_rotate.ok);
    assert!(
        no_rotate.stderr.contains("needs --rotate"),
        "{}",
        no_rotate.stderr
    );
    let stray_key = cli.run_with_env(
        &[
            "send",
            &recipient,
            "--value",
            "1",
            "--safe",
            &safe_arg,
            "--rotate",
            "--hd-wallet",
            "demo",
            "--password-file",
            &password,
            "--rpc-url",
            h.url().as_str(),
        ],
        &[(
            "PRIVATE_KEY",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )],
    );
    assert!(!stray_key.ok);
    assert!(
        stray_key.stderr.contains("unset PRIVATE_KEY"),
        "{}",
        stray_key.stderr
    );
    assert_eq!(h.owners(safe).await, vec![key(4)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_existing_safe_moves_onto_the_wallet() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli {
        h: &h,
        home: dir.path().join("home"),
        password_file: dir.path().join("password"),
    };
    write(&cli.password_file, "pw");
    let phrase_file = dir.path().join("phrase");
    write(&phrase_file, PHRASE);
    let password = cli.password_file.to_str().unwrap().to_string();
    cli.run(&[
        "wallet",
        "import",
        "demo",
        "--phrase-file",
        phrase_file.to_str().unwrap(),
        "--start-index",
        "7",
        "--password-file",
        &password,
        "--json",
    ])
    .json();

    // A Safe owned by an ordinary key, as safe-rs has always used them.
    let legacy = alloy::signers::local::PrivateKeySigner::random();
    let legacy_key = alloy::primitives::hex::encode_prefixed(legacy.to_bytes());
    h.fund(legacy.address(), eth(2)).await;
    let safe = h.deploy_safe_with(&[legacy.address()], 1, 500).await;
    let safe_arg = safe.to_string();
    let msco = h.addresses.multi_send_call_only.to_string();
    let onboard = |extra: &[&str]| {
        let mut args = vec![
            "rotate",
            safe_arg.as_str(),
            "--multi-send-call-only",
            msco.as_str(),
            "--from-private-key",
            legacy_key.as_str(),
        ];
        args.extend_from_slice(extra);
        cli.wallet_command(&args)
    };

    // With no prompt to show the amount, sweeping the legacy key needs a decision.
    let undecided = onboard(&[]);
    assert!(!undecided.ok);
    assert!(
        undecided.stderr.contains("--sweep-legacy"),
        "{}",
        undecided.stderr
    );
    assert_eq!(h.owners(safe).await, vec![legacy.address()]);

    let moved = onboard(&["--sweep-legacy"]).json();
    assert_eq!(moved["status"], "rotated");
    assert!(
        moved["old_owner"].get("index").is_none(),
        "not a wallet key"
    );
    assert_eq!(moved["owner"]["index"], 7, "--start-index is honoured");
    assert_eq!(h.owners(safe).await, vec![key(7)]);
    assert_eq!(balance(&h, legacy.address()).await, U256::ZERO);
    assert!(balance(&h, key(7)).await > eth(1));

    // Once the wallet owns the Safe, a --from-* key is a mistake.
    let again = onboard(&["--no-sweep"]);
    assert!(!again.ok);
    assert!(
        again.stderr.contains("already owned by wallet key 7"),
        "{}",
        again.stderr
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_but_unsent_transaction_is_tracked_until_it_lands() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli {
        h: &h,
        home: dir.path().join("home"),
        password_file: dir.path().join("password"),
    };
    write(&cli.password_file, "pw");
    let phrase_file = dir.path().join("phrase");
    write(&phrase_file, PHRASE);
    let password = cli.password_file.to_str().unwrap().to_string();
    cli.run(&[
        "wallet",
        "import",
        "demo",
        "--phrase-file",
        phrase_file.to_str().unwrap(),
        "--password-file",
        &password,
        "--json",
    ])
    .json();

    // A Safe owned by wallet key 1, adopted on first use.
    let safe = h.deploy_safe_with(&[key(1)], 1, 501).await;
    h.fund(key(1), eth(1)).await;
    h.fund(safe, U256::from(1_000)).await;
    let safe_arg = safe.to_string();
    let msco = h.addresses.multi_send_call_only.to_string();
    let url = h.url().to_string();
    let recipient = Address::repeat_byte(0x42).to_string();
    let send = |extra: &[&str]| {
        let mut args = vec![
            "send",
            recipient.as_str(),
            "--value",
            "5",
            "--safe",
            safe_arg.as_str(),
            "--multi-send-call-only",
            msco.as_str(),
            "--rotate",
            "--hd-wallet",
            "demo",
            "--password-file",
            password.as_str(),
            "--rpc-url",
            url.as_str(),
        ];
        args.extend_from_slice(extra);
        cli.run(&args)
    };
    let status = || {
        cli.run(&["wallet", "status", "--hd-wallet", "demo", "--json"])
            .json()["safes"][0]
            .clone()
    };

    // A dry run shows the whole transaction, including the swap and the sweep,
    // and leaves the key unused.
    let dry = send(&["--simulate-only"]);
    assert!(dry.ok, "{}", dry.stderr);
    println!("{}", dry.stdout);
    // The summary is progress, on stderr; the simulation result is on stdout.
    let shown = dry.all();
    for expected in [
        "Owner: key 1",
        "Next owner: key ",
        "(the owner)",
        "swapOwner:",
        "Sweep: about",
        "Success: true",
    ] {
        assert!(shown.contains(expected), "missing {expected:?}:\n{shown}");
    }
    assert_eq!(h.owners(safe).await, vec![key(1)]);
    let reserved = status();
    let next = reserved["next_owner"]["index"]
        .as_u64()
        .expect("a reserved key");
    assert_eq!(
        reserved["exposed"], "rebuilt",
        "adopted from chain, not signed off"
    );
    assert!(reserved.get("pending_tx").is_none());

    // As JSON the dry run names the swap too.
    let dry_json = send(&["--simulate-only", "--json"]).json();
    assert_eq!(dry_json["success"], true);
    assert_eq!(dry_json["rotation"]["old_owner"]["index"], 1);
    assert_eq!(dry_json["rotation"]["new_owner"]["index"], next);
    assert_eq!(address(&dry_json["rotation"]["planned_sweep"]["to"]), {
        key(u32::try_from(next).unwrap())
    });

    // Signing without sending writes the transaction out and records the key as used.
    let raw_out = dir.path().join("signed.json");
    let unsent = send(&["--no-submit", "--raw-out", raw_out.to_str().unwrap()]);
    assert!(unsent.ok, "{}", unsent.stderr);
    let document: Value =
        serde_json::from_str(&std::fs::read_to_string(&raw_out).unwrap()).unwrap();
    assert_eq!(document["rotation"]["old_owner"]["index"], 1);
    assert_eq!(document["rotation"]["new_owner"]["index"], next);
    assert_eq!(address(&document["rotation"]["payer"]), key(1));
    assert_eq!(address(&document["signer"]), key(1));
    let armed = status();
    assert_eq!(armed["pending_tx"], document["tx_hash"]);
    assert_eq!(
        armed["next_owner"]["index"], next,
        "the reservation is unchanged"
    );
    assert_eq!(h.owners(safe).await, vec![key(1)], "not broadcast");

    // Someone broadcasts the signed bytes later.
    let raw: alloy::primitives::Bytes = document["raw"].as_str().unwrap().parse().unwrap();
    let tx_hash: alloy::primitives::B256 = document["tx_hash"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        safe_rs::broadcast_raw(&h.provider, &raw, tx_hash).await,
        safe_rs::BroadcastOutcome::Accepted(tx_hash)
    );
    let next_key = key(u32::try_from(next).unwrap());
    assert_eq!(h.owners(safe).await, vec![next_key]);
    assert!(balance(&h, key(1)).await > U256::ZERO, "not yet swept");

    // The next command finds the rotation, moves the owed ETH, and carries on.
    let resumed = send(&["--no-confirm"]);
    assert!(resumed.ok, "{}\n{}", resumed.stdout, resumed.stderr);
    println!("{}", resumed.stdout);
    assert!(resumed.stderr.contains("owed from"), "{}", resumed.stderr);
    assert!(
        resumed.stdout.contains("Rotation: rotated"),
        "{}",
        resumed.stdout
    );
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);
    assert_eq!(balance(&h, next_key).await, U256::ZERO);
    assert_eq!(
        balance(&h, Address::repeat_byte(0x42)).await,
        U256::from(10),
        "both sends executed"
    );
    let done = status();
    assert!(done.get("pending_tx").is_none());
    assert!(done.get("exposed").is_none());
    assert_eq!(done["retired_keys"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotating_send_defaults_to_the_multisend_of_the_safe_version() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli {
        h: &h,
        home: dir.path().join("home"),
        password_file: dir.path().join("password"),
    };
    write(&cli.password_file, "pw");
    let phrase_file = dir.path().join("phrase");
    write(&phrase_file, PHRASE);
    cli.run(&[
        "wallet",
        "import",
        "demo",
        "--phrase-file",
        phrase_file.to_str().unwrap(),
        "--password-file",
        cli.password_file.to_str().unwrap(),
        "--json",
    ])
    .json();

    // A chain that has the v1.5.0 MultiSendCallOnly and not the v1.4.1 one,
    // and a Safe reporting v1.5.0 that wallet key 1 owns.
    let v1_4_1 = ChainAddresses::v1_4_1().multi_send_call_only;
    assert!(h.provider.get_code_at(v1_4_1).await.unwrap().is_empty());
    h.set_multi_send_call_only(ChainAddresses::v1_5_0().multi_send_call_only)
        .await;
    let singleton = h.deploy_singleton_reporting("1.5.0").await;
    let safe = h.deploy_safe_on(singleton, &[key(1)], 1, 502).await;
    h.fund(key(1), eth(1)).await;
    h.fund(safe, U256::from(1_000)).await;
    let recipient = Address::repeat_byte(0x42);

    // Without --multi-send-call-only, the call and the swap go through the
    // v1.5.0 contract.
    let sent = cli
        .wallet_command(&[
            "send",
            &recipient.to_string(),
            "--value",
            "5",
            "--safe",
            &safe.to_string(),
            "--rotate",
        ])
        .json();
    assert_eq!(sent["status"], "rotated");
    assert_eq!(sent["old_owner"]["index"], 1);
    let owner = address(&sent["owner"]["address"]);
    assert_ne!(owner, key(1));
    assert_eq!(h.owners(safe).await, vec![owner]);
    assert_eq!(balance(&h, recipient).await, U256::from(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotating_send_names_a_multisend_that_has_no_code() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli {
        h: &h,
        home: dir.path().join("home"),
        password_file: dir.path().join("password"),
    };
    write(&cli.password_file, "pw");
    let phrase_file = dir.path().join("phrase");
    write(&phrase_file, PHRASE);
    cli.run(&[
        "wallet",
        "import",
        "demo",
        "--phrase-file",
        phrase_file.to_str().unwrap(),
        "--password-file",
        cli.password_file.to_str().unwrap(),
        "--json",
    ])
    .json();

    // The harness deploys the Safe contracts through another CREATE2 deployer,
    // so the canonical MultiSendCallOnly the CLI defaults to is empty here.
    let canonical = ChainAddresses::v1_4_1().multi_send_call_only;
    assert!(h.provider.get_code_at(canonical).await.unwrap().is_empty());
    let safe = h.deploy_safe_with(&[key(1)], 1, 503).await;
    h.fund(key(1), eth(1)).await;
    h.fund(safe, U256::from(1_000)).await;
    let safe_arg = safe.to_string();
    let recipient = Address::repeat_byte(0x42);

    // The call and the swap are a batch: refused before anything is signed,
    // naming the address and the option that sets it.
    let refused = cli.wallet_command(&[
        "send",
        &recipient.to_string(),
        "--value",
        "5",
        "--safe",
        &safe_arg,
        "--rotate",
    ]);
    assert!(!refused.ok, "expected a refusal:\n{}", refused.stdout);
    let refusal = format!("MultiSend contract not deployed at {canonical}");
    assert!(refused.stderr.contains(&refusal), "{}", refused.stderr);
    assert!(
        refused.stderr.contains("--multi-send-call-only"),
        "{}",
        refused.stderr
    );
    assert!(refused.stdout.is_empty(), "{}", refused.stdout);
    assert_eq!(h.owners(safe).await, vec![key(1)]);
    assert_eq!(balance(&h, recipient).await, U256::ZERO);

    // A rotation with no other calls is a direct self-call and needs no batch
    // contract.
    let rotated = cli.wallet_command(&["rotate", &safe_arg]).json();
    assert_eq!(rotated["status"], "rotated");
    assert_eq!(rotated["old_owner"]["index"], 1);
    let owner = address(&rotated["owner"]["address"]);
    assert_ne!(owner, key(1));
    assert_eq!(h.owners(safe).await, vec![owner]);
    assert_eq!(balance(&h, recipient).await, U256::ZERO);
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_owner_hd_wallet_creation_and_rotation_via_bundle_and_approve_hash() {
    use alloy::signers::local::PrivateKeySigner;

    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let cli = discovery_wallet(&h, dir.path());
    let funding = HdWallet::from_phrase(PHRASE).unwrap().id();
    let co_owner = PrivateKeySigner::random();
    let co_owner_key = alloy::primitives::hex::encode_prefixed(co_owner.to_bytes());
    h.fund(funding, eth(1)).await;
    h.fund(co_owner.address(), eth(1)).await;

    let singleton = h.addresses.safe_singleton.to_string();
    let factory = h.addresses.proxy_factory.to_string();
    let handler = h.addresses.fallback_handler.to_string();
    let msco = h.addresses.multi_send_call_only.to_string();

    // 1. Create a 2-of-2 Safe with `safe create --rotate --hd-wallet demo --owner <co_owner> --threshold 2`
    let created = cli
        .wallet_command(&[
            "create",
            "--owner",
            &co_owner.address().to_string(),
            "--threshold",
            "2",
            "--singleton",
            &singleton,
            "--factory",
            &factory,
            "--fallback-handler",
            &handler,
        ])
        .json();
    let safe = address(&created["safe_address"]);
    let safe_arg = safe.to_string();
    assert_eq!(created["owner"]["index"], 1);
    assert_eq!(created["threshold"], 2);
    assert_eq!(h.owners(safe).await, vec![key(1), co_owner.address()]);
    h.fund(safe, U256::from(1_000)).await;

    // 2. Offchain bundle rotation:
    //    Step A: HD wallet runs `safe send --rotate --bundle rot.json` (1/2 signatures collected)
    let recipient = Address::repeat_byte(0x61);
    let bundle_path = dir.path().join("rot.json");
    let bundle_arg = bundle_path.to_str().unwrap();
    let saved = cli
        .wallet_command(&[
            "send",
            &recipient.to_string(),
            "--value",
            "25",
            "--safe",
            &safe_arg,
            "--multi-send-call-only",
            &msco,
            "--rotate",
            "--bundle",
            bundle_arg,
        ])
        .json();
    assert_eq!(saved["signatures_collected"], 1);
    assert_eq!(saved["threshold"], 2);
    assert_eq!(h.owners(safe).await, vec![key(1), co_owner.address()]);
    assert_eq!(balance(&h, recipient).await, U256::ZERO);

    //    Step B: Co-owner signs the prepared bundle (with swapOwner included in tx.data) using `--sign-only`
    let co_signed = cli
        .run(&[
            "send",
            "--bundle",
            bundle_arg,
            "--sign-only",
            "--safe",
            &safe_arg,
            "--multi-send-call-only",
            &msco,
            "--private-key",
            &co_owner_key,
            "--rpc-url",
            h.url().as_str(),
            "--json",
        ])
        .json();
    assert_eq!(co_signed["signatures_collected"], 2);
    assert_eq!(co_signed["threshold"], 2);

    //    Step C: HD wallet runs `safe send --rotate --bundle rot.json`: sees 2/2 signatures, executes,
    //            rotates key(1) -> key(2), and sweeps ETH from key(1) -> key(2)!
    let executed = cli
        .wallet_command(&[
            "send",
            "--bundle",
            bundle_arg,
            "--safe",
            &safe_arg,
            "--multi-send-call-only",
            &msco,
            "--rotate",
        ])
        .json();
    assert_eq!(executed["status"], "rotated");
    assert_eq!(executed["old_owner"]["index"], 1);
    assert_eq!(executed["owner"]["index"], 2);
    assert_eq!(h.owners(safe).await, vec![key(2), co_owner.address()]);
    assert_eq!(balance(&h, recipient).await, U256::from(25));
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);
    assert!(balance(&h, key(2)).await > U256::ZERO);

    // 3. On-chain --approve-hash rotation via `safe rotate`:
    //    Step A: HD wallet runs `safe rotate <SAFE> --approve-hash --bundle rot2.json`
    let bundle2_path = dir.path().join("rot2.json");
    let bundle2_arg = bundle2_path.to_str().unwrap();
    let approved = cli
        .wallet_command(&[
            "rotate",
            &safe_arg,
            "--approve-hash",
            "--bundle",
            bundle2_arg,
        ])
        .json();
    assert_eq!(approved["success"], true);
    assert_eq!(address(&approved["approver"]), key(2));
    assert_eq!(h.owners(safe).await, vec![key(2), co_owner.address()]);

    //    Step B: Co-owner signs the bundle `--sign-only`, then HD wallet executes `safe rotate`
    cli.run(&[
        "send",
        "--bundle",
        bundle2_arg,
        "--sign-only",
        "--safe",
        &safe_arg,
        "--private-key",
        &co_owner_key,
        "--rpc-url",
        h.url().as_str(),
        "--json",
    ])
    .json();

    let rotated = cli
        .wallet_command(&["rotate", &safe_arg, "--bundle", bundle2_arg])
        .json();
    assert_eq!(rotated["status"], "rotated");
    assert_eq!(rotated["old_owner"]["index"], 2);
    assert_eq!(rotated["owner"]["index"], 3);
    assert_eq!(h.owners(safe).await, vec![key(3), co_owner.address()]);
    assert_eq!(balance(&h, key(2)).await, U256::ZERO);
    assert!(balance(&h, key(3)).await > U256::ZERO);
}
