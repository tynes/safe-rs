//! `$SAFE_RS_HOME/config.toml` as the `safe` binary reads it, and HD wallet
//! keys as signers. Nothing here reaches a chain: the RPC URL points at port 9
//! (discard), and the signer is resolved before any request.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness: failures panic"
)]

use std::path::Path;
use std::process::{Command, Output};

const DEAD_RPC: &str = "http://127.0.0.1:9";
const TARGET: &str = "0x1111111111111111111111111111111111111111";
const KEY: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";

/// `safe send --send-eoa` to `TARGET`, which resolves the signer before it
/// touches the RPC.
fn send_eoa(home: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_safe"));
    command
        .args([
            "send",
            "--send-eoa",
            TARGET,
            "--rpc-url",
            DEAD_RPC,
            "--no-confirm",
        ])
        .args(args)
        .env("SAFE_RS_HOME", home);
    for name in [
        "PRIVATE_KEY",
        "SAFE_ADDRESS",
        "ETH_PASSWORD",
        "ETH_KEYSTORE",
        "ETH_KEYSTORE_ACCOUNT",
        "ETH_FROM",
        "GAS_PAYER_PRIVATE_KEY",
        "ETH_RPC_URL",
    ] {
        command.env_remove(name);
    }
    command.envs(envs.iter().copied());
    command.output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_configured_keystore_signs_unless_another_signer_is_given() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "keystore = \"/nonexistent/me.json\"\n",
    )
    .unwrap();

    let configured = send_eoa(home.path(), &[], &["--password", "x"]);
    assert!(!configured.status.success());
    assert!(
        stderr(&configured).contains("/nonexistent/me.json"),
        "the configured keystore was not used:\n{}",
        stderr(&configured)
    );

    for (envs, args) in [
        (&[("PRIVATE_KEY", KEY)][..], &[][..]),
        (&[][..], &["--private-key", KEY][..]),
    ] {
        let overridden = send_eoa(home.path(), envs, args);
        assert!(!overridden.status.success(), "the RPC is dead");
        assert!(
            !stderr(&overridden).contains("/nonexistent/me.json"),
            "{envs:?} {args:?} should win over the configured keystore:\n{}",
            stderr(&overridden)
        );
    }
}

#[test]
fn an_invalid_config_file_is_refused_by_name() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), "rpc = 1\n").unwrap();
    let output = send_eoa(home.path(), &[("PRIVATE_KEY", KEY)], &[]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("config.toml"),
        "{}",
        stderr(&output)
    );
}

#[tokio::test]
async fn every_hd_wallet_key_is_usable_as_a_signer() {
    use safe_rs_cli::args::{HdArgs, PasswordArgs};
    use safe_rs_cli::prompt::NoPrompt;
    use safe_rs_cli::wallet::{self, WalletContext};

    let home = tempfile::tempdir().unwrap();
    let ctx = WalletContext::new()
        .with_home(home.path().to_path_buf())
        .with_prompt(NoPrompt);
    let created = wallet::new_wallet(&ctx, "trader", "correct horse").unwrap();
    let password = PasswordArgs {
        password: Some("correct horse".into()),
        ..PasswordArgs::default()
    };
    let hd = HdArgs {
        mnemonic: Some("trader".into()),
        password: password.clone(),
        ..HdArgs::default()
    };

    let funding = wallet::signer(&ctx, "trader", 0, &password).unwrap();
    assert_eq!(funding.address(), created.funding_address);
    for index in [1, 3] {
        let signer = wallet::signer(&ctx, "trader", index, &password).unwrap();
        let expected = wallet::wallet_address(&ctx, &hd, Some(index))
            .await
            .unwrap();
        assert_eq!(signer.address(), expected.address, "key {index}");
    }

    // The same key through `--mnemonic <wallet file> --mnemonic-index 3`.
    let wallet_file = home.path().join("wallets/trader.json");
    let args = safe_rs_cli::args::SignerArgs {
        mnemonic: Some(wallet_file.to_string_lossy().into_owned()),
        mnemonic_index: 3,
        password: password.clone(),
        ..Default::default()
    };
    let signer = args.resolve(std::sync::Arc::new(NoPrompt)).await.unwrap();
    let expected = wallet::wallet_address(&ctx, &hd, Some(3)).await.unwrap();
    assert_eq!(signer.address(), expected.address);

    let wrong = PasswordArgs {
        password: Some("wrong".into()),
        ..PasswordArgs::default()
    };
    assert!(wallet::signer(&ctx, "trader", 1, &wrong).is_err());
}
