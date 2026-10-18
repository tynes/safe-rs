//! `safe config`: owner, threshold, module, guard and fallback handler changes
//! planned into one Safe transaction.
//!
//! Runs against a fresh local Anvil chain with Safe v1.4.1 (or v1.5.0)
//! deployed from the vendored artifacts, so no RPC URL is needed.
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

use std::path::Path;
use std::process::Command;

use alloy::primitives::{hex, Address, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use common::LocalHarness;
use safe_rs::ISafe;
use serde_json::Value;

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Output {
    fn json(&self) -> Value {
        assert!(self.ok, "command failed:\n{}\n{}", self.stdout, self.stderr);
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}):\n{}", self.stdout))
    }

    /// Asserts the command was refused with `reason` on stderr.
    fn assert_refused(&self, reason: &str) {
        assert!(!self.ok, "expected a refusal:\n{}", self.stdout);
        assert!(self.stderr.contains(reason), "{}", self.stderr);
    }
}

/// Runs `safe <args> --json` against the harness chain, with none of the
/// ambient environment variables the CLI reads.
fn safe_cli(h: &LocalHarness, home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_safe"));
    command
        .args(args)
        .args(["--rpc-url", h.url().as_str()])
        .arg("--json")
        .env("SAFE_RS_HOME", home);
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
    let output = command.output().expect("run safe");
    Output {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Runs `safe config --json` on `safe`, signed by `signer`. Several changes
/// batch through the harness's MultiSendCallOnly.
fn config(
    h: &LocalHarness,
    home: &Path,
    safe: Address,
    signer: &PrivateKeySigner,
    args: &[&str],
) -> Output {
    let key = hex::encode_prefixed(signer.to_bytes());
    let safe = safe.to_string();
    let msco = h.addresses.multi_send_call_only.to_string();
    let mut all = vec![
        "config",
        "--safe",
        &safe,
        "--private-key",
        &key,
        "--multi-send-call-only",
        &msco,
    ];
    all.extend_from_slice(args);
    safe_cli(h, home, &all)
}

fn info(h: &LocalHarness, home: &Path, safe: Address) -> Value {
    safe_cli(h, home, &["info", &safe.to_string()]).json()
}

async fn threshold(h: &LocalHarness, safe: Address) -> U256 {
    ISafe::new(safe, &h.provider)
        .getThreshold()
        .call()
        .await
        .unwrap()
}

fn addresses(value: &Value) -> Vec<Address> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().parse().unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn owners_and_threshold_change() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let owner = h.owner.address();
    let safe = h.deploy_safe(800).await;
    let [alice, bob, carol, dave] = [0xa1, 0xb1, 0xc1, 0xd1].map(Address::repeat_byte);
    let s = |address: Address| address.to_string();

    // Two additions in one transaction: new owners go to the head.
    let out = config(
        &h,
        home,
        safe,
        &h.owner,
        &["--add-owner", &s(alice), "--add-owner", &s(bob)],
    )
    .json();
    assert_eq!(out["outcome"], "success");
    assert_eq!(h.owners(safe).await, [bob, alice, owner]);
    assert_eq!(threshold(&h, safe).await, U256::from(1));

    // A middle owner.
    config(&h, home, safe, &h.owner, &["--remove-owner", &s(alice)]).json();
    assert_eq!(h.owners(safe).await, [bob, owner]);

    // A swap keeps the owner's place.
    config(
        &h,
        home,
        safe,
        &h.owner,
        &["--swap-owner", &format!("{bob}:{carol}")],
    )
    .json();
    assert_eq!(h.owners(safe).await, [carol, owner]);

    // Removing the head after an addition in the same transaction: the
    // removal points at the owner just added.
    config(
        &h,
        home,
        safe,
        &h.owner,
        &["--add-owner", &s(dave), "--remove-owner", &s(carol)],
    )
    .json();
    assert_eq!(h.owners(safe).await, [dave, owner]);

    // The threshold alone. After this the owner cannot act alone.
    config(&h, home, safe, &h.owner, &["--threshold", "2"]).json();
    assert_eq!(threshold(&h, safe).await, U256::from(2));
    assert_eq!(h.safe_nonce(safe).await, U256::from(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn modules_guard_and_fallback_handler_change() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let safe = h.deploy_safe(801).await;
    let [m1, m2] = [0xe1, 0xe2].map(Address::repeat_byte);
    let guard = h.guard.to_string();

    config(
        &h,
        home,
        safe,
        &h.owner,
        &[
            "--enable-module",
            &m1.to_string(),
            "--enable-module",
            &m2.to_string(),
        ],
    )
    .json();
    assert_eq!(addresses(&info(&h, home, safe)["modules"]), [m2, m1]);

    // Disable the tail, set the guard and clear the fallback handler at once.
    config(
        &h,
        home,
        safe,
        &h.owner,
        &[
            "--disable-module",
            &m1.to_string(),
            "--guard",
            &guard,
            "--fallback-handler",
            &Address::ZERO.to_string(),
        ],
    )
    .json();
    let state = info(&h, home, safe);
    assert_eq!(addresses(&state["modules"]), [m2]);
    assert_eq!(
        state["guard"].as_str().unwrap().parse::<Address>().unwrap(),
        h.guard
    );
    assert_eq!(
        state["fallback_handler"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap(),
        Address::ZERO
    );

    // Clearing the guard runs through the guard itself.
    config(
        &h,
        home,
        safe,
        &h.owner,
        &["--guard", &Address::ZERO.to_string()],
    )
    .json();
    let state = info(&h, home, safe);
    assert_eq!(
        state["guard"].as_str().unwrap().parse::<Address>().unwrap(),
        Address::ZERO
    );
    assert!(
        state.get("module_guard").is_none(),
        "v1.4.1 has no module guard"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn co_owners_sign_the_planned_change_from_the_bundle() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let owners: Vec<PrivateKeySigner> = (0..3).map(|_| PrivateKeySigner::random()).collect();
    for owner in &owners {
        h.fund(owner.address(), U256::from(10u128.pow(18))).await;
    }
    let addrs: Vec<Address> = owners.iter().map(|o| o.address()).collect();
    let safe = h.deploy_safe_with(&addrs, 2, 802).await;
    let new_owner = Address::repeat_byte(0xa2);
    let bundle_path = dir.path().join("config.json");
    let bundle = bundle_path.to_str().unwrap();

    // Owner 1 plans and signs: 1 of 2 signatures, saved, nothing broadcast.
    let first = config(
        &h,
        &home,
        safe,
        &owners[0],
        &[
            "--add-owner",
            &new_owner.to_string(),
            "--threshold",
            "3",
            "--bundle",
            bundle,
        ],
    )
    .json();
    assert_eq!(first["signatures_collected"], 1);
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);

    // Owner 2 signs what is in the bundle, without the change flags or --safe,
    // and executes.
    let key = hex::encode_prefixed(owners[1].to_bytes());
    let second = safe_cli(
        &h,
        &home,
        &["config", "--bundle", bundle, "--private-key", &key],
    )
    .json();
    assert_eq!(second["outcome"], "success");
    assert_eq!(
        h.owners(safe).await,
        [new_owner, addrs[0], addrs[1], addrs[2]]
    );
    assert_eq!(threshold(&h, safe).await, U256::from(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_changes_are_refused_before_signing() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let owner = h.owner.address();
    let other = Address::repeat_byte(0xa3);
    let safe = h.deploy_safe(803).await;
    let two_of_two = h.deploy_safe_with(&[owner, other], 2, 804).await;
    let s = |address: Address| address.to_string();

    config(&h, home, safe, &h.owner, &["--threshold", "2"])
        .assert_refused("threshold 2 is more than the 1 owners");
    config(&h, home, safe, &h.owner, &["--remove-owner", &s(other)])
        .assert_refused("is not an owner");
    config(&h, home, safe, &h.owner, &["--add-owner", &s(owner)])
        .assert_refused("already an owner");
    config(
        &h,
        home,
        safe,
        &h.owner,
        &["--add-owner", &s(other), "--remove-owner", &s(other)],
    )
    .assert_refused("more than one owner change");
    config(&h, home, safe, &h.owner, &["--module-guard", &s(h.guard)])
        .assert_refused("needs Safe v1.5.0");
    config(&h, home, safe, &h.owner, &[]).assert_refused("nothing to change");
    config(&h, home, safe, &h.owner, &["--guard", &s(Address::ZERO)])
        .assert_refused("the guard is already none");
    config(
        &h,
        home,
        two_of_two,
        &h.owner,
        &["--remove-owner", &s(other)],
    )
    .assert_refused("pass --threshold to lower it");

    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);
    assert_eq!(
        h.provider.get_transaction_count(owner).await.unwrap(),
        0,
        "nothing was broadcast"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn module_guard_changes_on_v1_5_0() {
    let h = LocalHarness::with_version("1.5.0").await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let safe = h.deploy_safe(805).await;
    let guard = h.guard;

    let state = info(&h, home, safe);
    assert_eq!(state["version"], "1.5.0");
    assert_eq!(
        state["module_guard"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap(),
        Address::ZERO
    );

    // The module guard and the transaction guard together: v1.5.0's
    // DebugTransactionGuard is both.
    let out = config(
        &h,
        home,
        safe,
        &h.owner,
        &[
            "--module-guard",
            &guard.to_string(),
            "--guard",
            &guard.to_string(),
        ],
    )
    .json();
    assert_eq!(out["outcome"], "success");
    let state = info(&h, home, safe);
    let read = |key: &str| state[key].as_str().unwrap().parse::<Address>().unwrap();
    assert_eq!(read("module_guard"), guard);
    assert_eq!(read("guard"), guard);

    // A module guard must implement the interface (GS301): simulation stops it.
    config(
        &h,
        home,
        safe,
        &h.owner,
        &["--module-guard", &Address::repeat_byte(0xa4).to_string()],
    )
    .assert_refused("simulation failed");

    // Cleared again.
    config(
        &h,
        home,
        safe,
        &h.owner,
        &["--module-guard", &Address::ZERO.to_string()],
    )
    .json();
    let state = info(&h, home, safe);
    assert_eq!(
        state["module_guard"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap(),
        Address::ZERO
    );
}
