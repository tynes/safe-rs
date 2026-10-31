//! `safe_rs_cli::send` as a downstream CLI calls it: each way a send can end
//! comes back as a `SendOutcome`.
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

use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use common::LocalHarness;
use safe_rs_cli::args::SendOpts;
use safe_rs_cli::safe_rs::Call;
use safe_rs_cli::{Output, SendContext, SendError, SendOutcome};

const RECIPIENT: Address = Address::repeat_byte(0x42);

fn transfer() -> Vec<Call> {
    vec![Call::new(RECIPIENT, U256::from(7), Bytes::new())]
}

fn context(h: &LocalHarness, safe: Address) -> SendContext {
    SendContext::new(h.url(), safe)
        .with_signer(h.owner.clone())
        .with_output(Output::Quiet)
}

fn opts() -> SendOpts {
    SendOpts {
        no_confirm: true,
        ..SendOpts::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn each_way_a_send_ends_is_returned() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(0).await;
    h.fund(safe, U256::from(1_000)).await;

    // Simulated: nothing signed or sent.
    let simulated = safe_rs_cli::send(
        context(&h, safe),
        transfer(),
        SendOpts {
            simulate_only: true,
            ..opts()
        },
    )
    .await
    .unwrap();
    let SendOutcome::Simulated { gas_used, .. } = simulated else {
        panic!("expected Simulated, got {simulated:?}");
    };
    assert!(gas_used > 0);
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);

    // Signed into a bundle, not executed.
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("tx.json");
    let signed = safe_rs_cli::send(
        context(&h, safe),
        transfer(),
        SendOpts {
            sign_only: true,
            bundle: Some(bundle.clone()),
            ..opts()
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(
            &signed,
            SendOutcome::Signed { signatures: 1, threshold: 1, bundle: path, .. } if *path == bundle
        ),
        "{signed:?}"
    );
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);

    // Signed but not broadcast: the raw bytes come back, stdout is left alone.
    let not_submitted = safe_rs_cli::send(
        context(&h, safe),
        transfer(),
        SendOpts {
            no_submit: true,
            ..opts()
        },
    )
    .await
    .unwrap();
    let SendOutcome::NotSubmitted { raw, .. } = not_submitted else {
        panic!("expected NotSubmitted, got {not_submitted:?}");
    };
    assert!(!raw.is_empty());
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);

    // Executed.
    let executed = safe_rs_cli::send(context(&h, safe), transfer(), opts())
        .await
        .unwrap();
    let SendOutcome::Executed {
        tx_hash,
        gas_used,
        block,
        ..
    } = executed
    else {
        panic!("expected Executed, got {executed:?}");
    };
    assert!(gas_used > 0);
    assert!(block.is_some());
    let receipt = h
        .provider
        .get_transaction_receipt(tx_hash)
        .await
        .unwrap()
        .expect("mined");
    assert_eq!(receipt.block_number, block);
    assert_eq!(h.safe_nonce(safe).await, U256::from(1));
    assert_eq!(
        h.provider.get_balance(RECIPIENT).await.unwrap(),
        U256::from(7)
    );

    // An outcome serializes for a host's own JSON output.
    let json = serde_json::to_value(&simulated).unwrap();
    assert_eq!(json["outcome"], "simulated");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_simulation_is_returned_as_its_own_error() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(0).await;

    // The Safe holds no ETH, so the transfer reverts in simulation.
    let error = safe_rs_cli::send(context(&h, safe), transfer(), opts())
        .await
        .unwrap_err();
    assert!(
        matches!(error, SendError::SimulationFailed { .. }),
        "{error:?}"
    );
    assert!(!error.may_be_pending());
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);
}
