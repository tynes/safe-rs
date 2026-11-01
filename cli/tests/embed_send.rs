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

use alloy::network::ReceiptResponse as _;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use common::LocalHarness;
use safe_rs_cli::args::{CollectArgs, RawTxArgs, SendOpts, SimulateArgs};
use safe_rs_cli::prompt::NoPrompt;
use safe_rs_cli::safe_rs::Call;
use safe_rs_cli::{SendContext, SendError, SendOutcome};

const RECIPIENT: Address = Address::repeat_byte(0x42);

fn transfer() -> Vec<Call> {
    vec![Call::new(RECIPIENT, U256::from(7), Bytes::new())]
}

fn context(h: &LocalHarness, safe: Address) -> SendContext {
    SendContext::new(h.url(), safe)
        .with_signer(h.owner.clone())
        .with_prompt(NoPrompt)
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
            simulate: SimulateArgs {
                simulate_only: true,
                ..SimulateArgs::default()
            },
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
            collect: CollectArgs {
                sign_only: true,
                bundle: Some(bundle.clone()),
                ..CollectArgs::default()
            },
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
            raw: RawTxArgs {
                no_submit: true,
                ..RawTxArgs::default()
            },
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

fn eoa_context(h: &LocalHarness) -> SendContext {
    SendContext::eoa(h.url())
        .with_signer(h.owner.clone())
        .with_prompt(NoPrompt)
}

async fn owner_nonce(h: &LocalHarness) -> u64 {
    h.provider
        .get_transaction_count(h.owner.address())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_eoa_sends_each_call_as_its_own_transaction() {
    let h = LocalHarness::new().await;
    let other = Address::repeat_byte(0x43);
    let calls = vec![
        Call::new(RECIPIENT, U256::from(7), Bytes::new()),
        Call::new(other, U256::from(9), Bytes::new()),
    ];
    let start = owner_nonce(&h).await;

    // Simulated: nothing signed or sent.
    let simulated = safe_rs_cli::send(
        eoa_context(&h),
        calls.clone(),
        SendOpts {
            simulate: SimulateArgs {
                simulate_only: true,
                ..SimulateArgs::default()
            },
            ..opts()
        },
    )
    .await
    .unwrap();
    let SendOutcome::EoaSimulated { gas_used } = simulated else {
        panic!("expected EoaSimulated, got {simulated:?}");
    };
    assert!(gas_used >= 2 * 21_000, "{gas_used}");
    assert_eq!(owner_nonce(&h).await, start);

    // Executed: two transactions, in order.
    let executed = safe_rs_cli::send(eoa_context(&h), calls, opts())
        .await
        .unwrap();
    let SendOutcome::EoaExecuted { txs } = &executed else {
        panic!("expected EoaExecuted, got {executed:?}");
    };
    assert_eq!(txs.len(), 2);
    for tx in txs {
        let receipt = h
            .provider
            .get_transaction_receipt(tx.tx_hash)
            .await
            .unwrap()
            .expect("mined");
        assert!(receipt.status());
        assert_eq!(receipt.block_number, tx.block);
    }
    assert_eq!(owner_nonce(&h).await, start + 2);
    assert_eq!(
        h.provider.get_balance(RECIPIENT).await.unwrap(),
        U256::from(7)
    );
    assert_eq!(h.provider.get_balance(other).await.unwrap(), U256::from(9));

    let json = serde_json::to_value(&executed).unwrap();
    assert_eq!(json["outcome"], "eoa_executed");
    assert_eq!(json["txs"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_eoa_send_with_a_reverting_call_sends_nothing() {
    let h = LocalHarness::new().await;
    let reverter = h.create2(common::reverter_initcode()).await;
    let start = owner_nonce(&h).await;
    let calls = vec![
        Call::new(RECIPIENT, U256::from(7), Bytes::new()),
        Call::new(reverter, U256::ZERO, Bytes::new()),
    ];

    let error = safe_rs_cli::send(eoa_context(&h), calls, opts())
        .await
        .unwrap_err();
    let SendError::SimulationFailed { reason } = &error else {
        panic!("expected SimulationFailed, got {error:?}");
    };
    assert!(reason.starts_with("call 1:"), "{reason}");
    assert!(!error.may_be_pending());
    assert_eq!(owner_nonce(&h).await, start);
    assert_eq!(h.provider.get_balance(RECIPIENT).await.unwrap(), U256::ZERO);
}
