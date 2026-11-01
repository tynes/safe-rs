//! `safe send` without `--rotate`: batches and the MultiSend contract they go
//! through.
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

use std::path::Path;
use std::process::Command;

use alloy::primitives::{hex, Address, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::Provider;
use common::LocalHarness;
use safe_rs::ChainAddresses;
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

    /// Asserts the batch was refused because `target` has no code, naming
    /// `flag` as the way out, and that nothing was written to stdout.
    fn assert_missing_batch_target(&self, target: Address, flag: &str) {
        assert!(!self.ok, "expected a refusal:\n{}", self.stdout);
        let refusal = format!("MultiSend contract not deployed at {target}");
        assert!(self.stderr.contains(&refusal), "{}", self.stderr);
        assert!(self.stderr.contains(flag), "{}", self.stderr);
        assert!(self.stdout.is_empty(), "{}", self.stdout);
    }
}

/// Runs `safe send --json` for `safe`, signed and paid for by the harness
/// owner, with none of the ambient environment variables the CLI reads.
fn send(h: &LocalHarness, home: &Path, safe: Address, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_safe"));
    command
        .arg("send")
        .args(args)
        .args(["--safe", &safe.to_string()])
        .args(["--rpc-url", h.url().as_str()])
        .args(["--private-key", &hex::encode_prefixed(h.owner.to_bytes())])
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

/// Writes a bundle of two transfers to `recipient`, 15 wei in total.
fn write_transfers(path: &Path, recipient: Address) {
    let bundle = serde_json::json!({
        "calls": [
            { "to": recipient.to_string(), "value": "10" },
            { "to": recipient.to_string(), "value": "5" },
        ]
    });
    std::fs::write(path, bundle.to_string()).unwrap();
}

/// Runs `safe send --json` for `safe` signed by an arbitrary `signer`.
fn send_as(
    h: &LocalHarness,
    home: &Path,
    safe: Address,
    signer: &alloy::signers::local::PrivateKeySigner,
    args: &[&str],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_safe"));
    command
        .arg("send")
        .args(args)
        .args(["--safe", &safe.to_string()])
        .args(["--rpc-url", h.url().as_str()])
        .args(["--private-key", &hex::encode_prefixed(signer.to_bytes())])
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

/// Runs `safe send --json` for `safe` with no owner wallet, only `--payer-private-key`.
fn send_with_payer_only(
    h: &LocalHarness,
    home: &Path,
    safe: Address,
    payer: &alloy::signers::local::PrivateKeySigner,
    args: &[&str],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_safe"));
    command
        .arg("send")
        .args(args)
        .args(["--safe", &safe.to_string()])
        .args(["--rpc-url", h.url().as_str()])
        .args([
            "--payer-private-key",
            &hex::encode_prefixed(payer.to_bytes()),
        ])
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

async fn balance(h: &LocalHarness, address: Address) -> U256 {
    h.provider.get_balance(address).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_is_refused_when_its_multisend_has_no_code() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let safe = h.deploy_safe(600).await;
    h.fund(safe, U256::from(1_000)).await;
    let recipient = Address::repeat_byte(0x47);
    let bundle = dir.path().join("bundle.json");
    write_transfers(&bundle, recipient);
    let bundle = bundle.to_str().unwrap();

    // The harness deploys the Safe contracts through another CREATE2 deployer,
    // so the canonical MultiSend addresses the CLI defaults to are empty here.
    let canonical = ChainAddresses::v1_4_1();
    for target in [canonical.multi_send, canonical.multi_send_call_only] {
        assert!(h.provider.get_code_at(target).await.unwrap().is_empty());
    }

    // Refused before anything is signed, however far the command would go.
    for mode in [
        &[][..],
        &["--simulate-only"],
        &["--skip-simulation"],
        &["--no-submit"],
    ] {
        let mut args = vec!["--bundle", bundle, "--call-only"];
        args.extend_from_slice(mode);
        send(&h, &home, safe, &args)
            .assert_missing_batch_target(canonical.multi_send_call_only, "--multi-send-call-only");
    }
    send(&h, &home, safe, &["--bundle", bundle])
        .assert_missing_batch_target(canonical.multi_send, "--multi-send");
    let owner_nonce = h
        .provider
        .get_transaction_count(h.owner.address())
        .await
        .unwrap();
    assert_eq!(owner_nonce, 0, "nothing was broadcast");
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);
    assert_eq!(balance(&h, recipient).await, U256::ZERO);

    // A single call has no batch target and is unaffected.
    let single = send(&h, &home, safe, &[&recipient.to_string(), "--value", "1"]).json();
    assert_eq!(single["success"], true);
    assert_eq!(balance(&h, recipient).await, U256::from(1));

    // Pointed at the deployed MultiSendCallOnly, the batch goes through.
    let msco = h.addresses.multi_send_call_only.to_string();
    let sent = send(
        &h,
        &home,
        safe,
        &[
            "--bundle",
            bundle,
            "--call-only",
            "--multi-send-call-only",
            &msco,
        ],
    )
    .json();
    assert_eq!(sent["success"], true);
    assert_eq!(sent["outcome"], "success");
    assert_eq!(balance(&h, recipient).await, U256::from(16));
    assert_eq!(h.safe_nonce(safe).await, U256::from(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_batch_target_must_exist_at_the_simulated_block() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let safe = h.deploy_safe(601).await;
    h.fund(safe, U256::from(1_000)).await;
    let bundle = dir.path().join("bundle.json");
    write_transfers(&bundle, Address::repeat_byte(0x48));
    let bundle = bundle.to_str().unwrap();

    // A MultiSendCallOnly deployed after `before`.
    let before = h.provider.get_block_number().await.unwrap().to_string();
    let late = h.deploy_multi_send_call_only(B256::repeat_byte(2)).await;
    let late_arg = late.to_string();
    let simulate = |extra: &[&str]| {
        let mut args = vec![
            "--bundle",
            bundle,
            "--call-only",
            "--multi-send-call-only",
            &late_arg,
            "--simulate-only",
        ];
        args.extend_from_slice(extra);
        send(&h, &home, safe, &args)
    };

    // Forked from `before`, the batch would run against no code and the
    // simulation would report a success that did nothing.
    simulate(&["--block", &before]).assert_missing_batch_target(late, "--multi-send-call-only");
    assert_eq!(simulate(&[]).json()["success"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_default_multisend_follows_the_safe_version() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let recipient = Address::repeat_byte(0x49);
    let bundle = dir.path().join("bundle.json");
    write_transfers(&bundle, recipient);
    let bundle = bundle.to_str().unwrap();
    let v1_4_1 = ChainAddresses::v1_4_1();
    let v1_5_0 = ChainAddresses::v1_5_0();

    // A chain that has the v1.5.0 MultiSendCallOnly and not the v1.4.1 one.
    h.set_multi_send_call_only(v1_5_0.multi_send_call_only)
        .await;
    let singleton = h.deploy_singleton_reporting("1.5.0").await;
    let new_safe = h
        .deploy_safe_on(singleton, &[h.owner.address()], 1, 602)
        .await;
    let old_safe = h.deploy_safe(602).await;
    h.fund(new_safe, U256::from(1_000)).await;
    h.fund(old_safe, U256::from(1_000)).await;
    let batch_target = |safe, extra: &[&str]| {
        let mut args = vec!["--bundle", bundle, "--call-only", "--no-submit"];
        args.extend_from_slice(extra);
        let signed = send(&h, &home, safe, &args).json();
        let to: Address = signed["safe_tx"]["to"].as_str().unwrap().parse().unwrap();
        to
    };

    // The v1.5.0 Safe batches through the v1.5.0 contract without being told to.
    assert_eq!(batch_target(new_safe, &[]), v1_5_0.multi_send_call_only);
    let sent = send(&h, &home, new_safe, &["--bundle", bundle, "--call-only"]).json();
    assert_eq!(sent["outcome"], "success");
    assert_eq!(balance(&h, recipient).await, U256::from(15));

    // The v1.4.1 Safe keeps the v1.4.1 one, which this chain does not have.
    send(&h, &home, old_safe, &["--bundle", bundle, "--call-only"])
        .assert_missing_batch_target(v1_4_1.multi_send_call_only, "--multi-send-call-only");

    // An override wins over the version, for either Safe.
    for (safe, target) in [
        (new_safe, h.addresses.multi_send_call_only),
        (old_safe, h.addresses.multi_send_call_only),
        (old_safe, v1_5_0.multi_send_call_only),
    ] {
        let chosen = batch_target(safe, &["--multi-send-call-only", &target.to_string()]);
        assert_eq!(chosen, target);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_owner_offchain_bundle_collection_and_execution() {
    use alloy::signers::local::PrivateKeySigner;

    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");

    let owner1 = PrivateKeySigner::random();
    let owner2 = PrivateKeySigner::random();
    let owner3 = PrivateKeySigner::random();
    h.fund(owner1.address(), U256::from(10u128.pow(18))).await;
    h.fund(owner2.address(), U256::from(10u128.pow(18))).await;
    h.fund(owner3.address(), U256::from(10u128.pow(18))).await;

    let safe = h
        .deploy_safe_with(
            &[owner1.address(), owner2.address(), owner3.address()],
            2,
            700,
        )
        .await;
    h.fund(safe, U256::from(1_000)).await;

    let recipient = Address::repeat_byte(0x51);
    let bundle_path = dir.path().join("tx.json");
    let bundle = bundle_path.to_str().unwrap();

    // Without --bundle or --approve-hash on a 2-of-3 Safe, `safe send` refuses with a clear error.
    let missing_bundle = send_as(
        &h,
        &home,
        safe,
        &owner1,
        &[&recipient.to_string(), "--value", "100"],
    );
    assert!(!missing_bundle.ok);
    assert!(
        missing_bundle
            .stderr
            .contains("Safe threshold is 2 (have 1/2 signatures)"),
        "{}",
        missing_bundle.stderr
    );

    // Owner 1 initializes and signs the bundle (1/2 signatures): simulates, does not broadcast.
    let first = send_as(
        &h,
        &home,
        safe,
        &owner1,
        &[&recipient.to_string(), "--value", "100", "--bundle", bundle],
    )
    .json();
    assert_eq!(first["signatures_collected"], 1);
    assert_eq!(first["threshold"], 2);
    assert_eq!(balance(&h, recipient).await, U256::ZERO);
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);

    // `safe approvals --bundle` counts the offchain signature; no --safe needed.
    let pending = safe_cli(&h, &home, &["approvals", "--bundle", bundle]).json();
    assert_eq!(pending["approvals"], 1);
    assert_eq!(pending["executable"], false);
    assert_eq!(pending["nonce_used"], false);
    assert_eq!(pending["signed_offchain"].as_array().unwrap().len(), 1);
    assert_eq!(pending["pending"].as_array().unwrap().len(), 2);
    assert_eq!(
        h.provider
            .get_transaction_count(owner1.address())
            .await
            .unwrap(),
        0,
        "nothing was broadcast"
    );

    // Owner 2 loads tx.json, appends signature (2/2), and executes execTransaction on-chain.
    // No --safe: the prepared bundle names its Safe, not owner 2's default one.
    let owner2_key = hex::encode_prefixed(owner2.to_bytes());
    let second = safe_cli(
        &h,
        &home,
        &["send", "--bundle", bundle, "--private-key", &owner2_key],
    )
    .json();
    assert_eq!(second["success"], true);
    assert_eq!(second["outcome"], "success");
    assert_eq!(balance(&h, recipient).await, U256::from(100));
    assert_eq!(h.safe_nonce(safe).await, U256::from(1));

    let executed = safe_cli(&h, &home, &["approvals", "--bundle", bundle]).json();
    assert_eq!(executed["approvals"], 2);
    assert_eq!(executed["nonce_used"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_owner_offline_parallel_signing_and_merge_bundle_with_payer() {
    use alloy::signers::local::PrivateKeySigner;

    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");

    let owner1 = PrivateKeySigner::random();
    let owner2 = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    // Owners have 0 ETH; only payer has ETH!
    h.fund(payer.address(), U256::from(10u128.pow(18))).await;

    let safe = h
        .deploy_safe_with(&[owner1.address(), owner2.address()], 2, 701)
        .await;
    h.fund(safe, U256::from(1_000)).await;

    let recipient = Address::repeat_byte(0x52);
    let b1_path = dir.path().join("tx_owner1.json");
    let b2_path = dir.path().join("tx_owner2.json");
    let b1 = b1_path.to_str().unwrap();
    let b2 = b2_path.to_str().unwrap();
    let payer_key = hex::encode_prefixed(payer.to_bytes());

    // Owner 1 signs into tx_owner1.json
    let s1 = send_as(
        &h,
        &home,
        safe,
        &owner1,
        &[
            &recipient.to_string(),
            "--value",
            "75",
            "--bundle",
            b1,
            "--payer-private-key",
            &payer_key,
        ],
    )
    .json();
    assert_eq!(s1["signatures_collected"], 1);

    // Owner 2 signs independently into tx_owner2.json with --sign-only
    let s2 = send_as(
        &h,
        &home,
        safe,
        &owner2,
        &[
            &recipient.to_string(),
            "--value",
            "75",
            "--bundle",
            b2,
            "--sign-only",
            "--payer-private-key",
            &payer_key,
        ],
    )
    .json();
    assert_eq!(s2["signatures_collected"], 1);
    assert_eq!(balance(&h, recipient).await, U256::ZERO);

    // Non-owner payer merges both bundles and executes on-chain!
    let executed = send_with_payer_only(
        &h,
        &home,
        safe,
        &payer,
        &["--bundle", b1, "--merge-bundle", b2],
    )
    .json();
    assert_eq!(executed["success"], true);
    assert_eq!(executed["outcome"], "success");
    assert_eq!(balance(&h, recipient).await, U256::from(75));
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_owner_onchain_approve_hash_flow() {
    use alloy::signers::local::PrivateKeySigner;
    use safe_rs::contracts::ISafe;

    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");

    let owner1 = PrivateKeySigner::random();
    let owner2 = PrivateKeySigner::random();
    h.fund(owner1.address(), U256::from(10u128.pow(18))).await;
    h.fund(owner2.address(), U256::from(10u128.pow(18))).await;

    let safe = h
        .deploy_safe_with(&[owner1.address(), owner2.address()], 2, 702)
        .await;
    h.fund(safe, U256::from(1_000)).await;

    let recipient = Address::repeat_byte(0x53);

    // Owner 1 approves the hash on-chain with --approve-hash
    let approved = send_as(
        &h,
        &home,
        safe,
        &owner1,
        &[&recipient.to_string(), "--value", "50", "--approve-hash"],
    )
    .json();
    assert_eq!(approved["success"], true);
    let approver: Address = approved["approver"].as_str().unwrap().parse().unwrap();
    assert_eq!(approver, owner1.address());
    assert_eq!(approved["signatures_collected"], 1);
    assert_eq!(approved["threshold"], 2);
    let safe_tx_hash: B256 = approved["safe_tx_hash"].as_str().unwrap().parse().unwrap();

    let onchain_flag = ISafe::new(safe, &h.provider)
        .approvedHashes(owner1.address(), safe_tx_hash)
        .call()
        .await
        .unwrap();
    assert_eq!(onchain_flag, U256::from(1));
    assert_eq!(balance(&h, recipient).await, U256::ZERO);

    let info = safe_cli(&h, &home, &["info", &safe.to_string()]).json();
    assert_eq!(info["balance"], "0x3e8"); // 1000 wei

    // `safe approvals <hash>` reads approvedHashes per owner, with no log scan.
    let hash = safe_tx_hash.to_string();
    let approvals = safe_cli(
        &h,
        &home,
        &["approvals", &hash, "--safe", &safe.to_string()],
    )
    .json();
    assert_eq!(approvals["approvals"], 1);
    assert_eq!(approvals["threshold"], 2);
    assert_eq!(approvals["executable"], false);
    let approved_onchain: Vec<Address> =
        serde_json::from_value(approvals["approved_onchain"].clone()).unwrap();
    assert_eq!(approved_onchain, vec![owner1.address()]);
    let pending: Vec<Address> = serde_json::from_value(approvals["pending"].clone()).unwrap();
    assert_eq!(pending, vec![owner2.address()]);
    assert!(approvals.get("nonce_used").is_none());

    // Owner 2 runs the same `safe send` without a bundle file: automatically discovers
    // owner 1's on-chain approval, combines v=1 + ECDSA signature, and executes!
    let executed = send_as(
        &h,
        &home,
        safe,
        &owner2,
        &[&recipient.to_string(), "--value", "50"],
    )
    .json();
    assert_eq!(executed["success"], true);
    assert_eq!(executed["outcome"], "success");
    assert_eq!(balance(&h, recipient).await, U256::from(50));
}

/// Runs `safe <args> --json` against the harness chain, with none of the
/// ambient environment variables the CLI reads.
fn safe_cli(h: &LocalHarness, home: &Path, args: &[&str]) -> Output {
    safe_cli_with_env(h, home, args, &[])
}

/// [`safe_cli`] with `env` set on top of the cleared environment.
fn safe_cli_with_env(h: &LocalHarness, home: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
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
    command.envs(env.iter().copied());
    let output = command.output().expect("run safe");
    Output {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn send_and_call_default_to_the_signers_one_of_one_safe() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let key = hex::encode_prefixed(h.owner.to_bytes());
    let recipient = Address::repeat_byte(0x77);

    // The default Safe lives at the canonical v1.4.1 addresses.
    let canonical = ChainAddresses::v1_4_1();
    for (target, source) in [
        (canonical.proxy_factory, h.addresses.proxy_factory),
        (canonical.safe_singleton, h.addresses.safe_singleton),
        (canonical.fallback_handler, h.addresses.fallback_handler),
    ] {
        let code = h.provider.get_code_at(source).await.unwrap();
        h.provider.anvil_set_code(target, code).await.unwrap();
    }

    // Before it is deployed, nothing is guessed.
    let missing = safe_cli(
        &h,
        home,
        &["send", &recipient.to_string(), "--private-key", &key],
    );
    assert!(!missing.ok);
    assert!(
        missing.stderr.contains("nothing is deployed"),
        "{}",
        missing.stderr
    );
    let anonymous = safe_cli(&h, home, &["call", &recipient.to_string(), "owner()"]);
    assert!(!anonymous.ok);
    assert!(
        anonymous.stderr.contains("No Safe specified"),
        "{}",
        anonymous.stderr
    );

    let created = safe_cli(
        &h,
        home,
        &[
            "create",
            "--private-key",
            &key,
            "--safe-version",
            "1.4.1",
            "--no-confirm",
        ],
    )
    .json();
    let safe: Address = created["safe_address"].as_str().unwrap().parse().unwrap();
    let ether = U256::from(10).pow(U256::from(18));
    h.fund(safe, ether).await;

    let sent = safe_cli(
        &h,
        home,
        &[
            "send",
            &recipient.to_string(),
            "--value",
            "0.5ether",
            "--private-key",
            &key,
            "--no-confirm",
        ],
    );
    assert!(sent.stderr.contains(&safe.to_string()), "{}", sent.stderr);
    assert_eq!(sent.json()["success"], true);
    assert_eq!(balance(&h, recipient).await, ether / U256::from(2));
    assert_eq!(balance(&h, safe).await, ether / U256::from(2));

    let called = safe_cli(
        &h,
        home,
        &[
            "call",
            &safe.to_string(),
            "getThreshold()",
            "--private-key",
            &key,
        ],
    )
    .json();
    assert_eq!(called["success"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn send_eoa_sends_each_call_from_the_signers_own_account() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let key = hex::encode_prefixed(h.owner.to_bytes());
    let from = h.owner.address();
    let recipient = Address::repeat_byte(0x73);
    let nonce = h.provider.get_transaction_count(from).await.unwrap();

    // A transfer: one transaction from the signer, no Safe involved.
    let sent = safe_cli(
        &h,
        home,
        &[
            "send",
            &recipient.to_string(),
            "--value",
            "7",
            "--send-eoa",
            "--private-key",
            &key,
            "--no-confirm",
        ],
    )
    .json();
    assert_eq!(
        sent["from"].as_str().unwrap().parse::<Address>().unwrap(),
        from
    );
    assert_eq!(sent["txs"].as_array().unwrap().len(), 1, "{sent}");
    assert_eq!(balance(&h, recipient).await, U256::from(7));
    assert_eq!(
        h.provider.get_transaction_count(from).await.unwrap(),
        nonce + 1
    );

    // Each --call is its own transaction.
    let call = format!("{}:getThreshold()", h.addresses.safe_singleton);
    let batch = safe_cli(
        &h,
        home,
        &[
            "send",
            "--send-eoa",
            "--call",
            &call,
            "--call",
            &call,
            "--private-key",
            &key,
            "--no-confirm",
        ],
    )
    .json();
    assert_eq!(batch["txs"].as_array().unwrap().len(), 2, "{batch}");
    assert_eq!(
        h.provider.get_transaction_count(from).await.unwrap(),
        nonce + 3
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn send_eoa_refuses_a_safe_and_its_options() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let key = hex::encode_prefixed(h.owner.to_bytes());
    let recipient = Address::repeat_byte(0x74).to_string();
    let safe = Address::repeat_byte(0x11).to_string();
    let base = ["send", &recipient, "--send-eoa", "--private-key", &key];
    fn with<'a>(base: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
        [base, extra].concat()
    }

    for (refused, env, message) in [
        (
            with(&base, &["--safe", &safe]),
            &[][..],
            "remove --safe and unset SAFE_ADDRESS",
        ),
        (
            with(&base, &[]),
            &[("SAFE_ADDRESS", safe.as_str())][..],
            "remove --safe and unset SAFE_ADDRESS",
        ),
        (
            with(&base, &["--nonce", "1"]),
            &[],
            "--nonce only applies to a send through a Safe",
        ),
        (
            with(&base, &["--bundle", "tx.json"]),
            &[],
            "--bundle only applies to a send through a Safe",
        ),
    ] {
        let output = safe_cli_with_env(&h, home, &refused, env);
        assert!(!output.ok, "{refused:?} must be refused");
        assert!(output.stderr.contains(message), "{}", output.stderr);
    }
    assert_eq!(balance(&h, recipient.parse().unwrap()).await, U256::ZERO);
}
