//! Tests against a fresh local Anvil chain with Safe v1.4.1 deployed from the
//! vendored artifacts. No RPC URL is needed.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test harness: setup panics are intended"
)]

#[path = "local/common.rs"]
mod common;

use std::time::Duration;

use alloy::eips::eip1559::BaseFeeParams;
use alloy::eips::{BlockId, RpcBlockHash};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::Provider;
use alloy::sol_types::SolValue;
use common::{enable_module_call, reverter_initcode, set_guard_call, LocalHarness};
use safe_rs::inspect::{enumerate_modules, read_safe_state, ReadSafeStateOptions};
use safe_rs::{
    broadcast_raw, decode_safe_outcome, wait_for_receipt, Account, BroadcastOutcome, Call,
    CallBuilder, Error, ForkSession, ISafe, ParentHeader, ReceiptWait, SafeExecutionOutcome,
    SafeTxGasPolicy, SimBlockEnv, SimTx, SpecId, TxChecks, WalletBuilder, WalletConfig,
};

/// Gas limit used for outer transactions in these tests (fixed so that failing
/// transactions can still be mined).
const OUTER_GAS: u64 = 600_000;

fn logs(receipt: &alloy::network::AnyTransactionReceipt) -> Vec<alloy::primitives::Log> {
    safe_rs::submit::receipt_logs(receipt)
}

async fn session_at_latest(h: &LocalHarness) -> ForkSession {
    let parent = ParentHeader::fetch(&h.provider, BlockId::latest())
        .await
        .unwrap();
    let env = SimBlockEnv::next_after(&parent, 12, BaseFeeParams::ethereum());
    ForkSession::new(
        h.provider.clone(),
        h.chain_id,
        BlockId::Hash(RpcBlockHash::from_hash(parent.hash, Some(true))),
        env,
        SpecId::OSAKA,
    )
}

fn strict_tx(h: &LocalHarness, outer: &safe_rs::SignedOuterTx) -> SimTx {
    SimTx {
        from: h.owner.address(),
        to: outer.params.to,
        value: outer.params.value,
        input: outer.params.input.clone(),
        gas_limit: outer.params.gas_limit,
        max_fee_per_gas: outer.params.max_fee_per_gas,
        max_priority_fee_per_gas: Some(outer.params.max_priority_fee_per_gas),
        nonce: Some(outer.params.nonce),
        checks: TxChecks::STRICT,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn envelope_hash_matches_onchain_get_transaction_hash() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(1).await;
    let calls = [
        Call::new(h.deployer.address(), U256::from(1), Bytes::new()),
        Call::call(safe, Bytes::new()),
    ];
    let prepared = h.prepare(safe, &calls, SafeTxGasPolicy::Zero).await;
    let p = &prepared.params;
    let onchain = ISafe::new(safe, &h.provider)
        .getTransactionHash(
            p.to,
            p.value,
            p.data.clone(),
            p.operation.as_u8(),
            p.safe_tx_gas,
            p.base_gas,
            p.gas_price,
            p.gas_token,
            p.refund_receiver,
            p.nonce,
        )
        .call()
        .await
        .unwrap();
    assert_eq!(onchain, prepared.safe_tx_hash);
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_outer_tx_hash_matches_node_hash_and_executes() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(2).await;
    h.fund(safe, U256::from(10_000)).await;
    let recipient = Address::repeat_byte(0x42);
    let calls = [
        Call::new(recipient, U256::from(100), Bytes::new()),
        Call::new(recipient, U256::from(23), Bytes::new()),
    ];
    let prepared = h.prepare(safe, &calls, SafeTxGasPolicy::Zero).await;
    let outer = h.sign_exec(&prepared, OUTER_GAS).await;
    let receipt = h.send(&outer).await;
    assert_eq!(receipt.transaction_hash, outer.tx_hash);
    assert!(receipt.inner.inner.status());
    assert!(decode_safe_outcome(&logs(&receipt), safe, prepared.safe_tx_hash).is_success());
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(123)
    );
    assert_eq!(h.safe_nonce(safe).await, U256::from(1));

    // Rebroadcasting the exact same bytes is idempotent, never a second execution.
    let again = broadcast_raw(&h.provider, &outer.raw, outer.tx_hash).await;
    assert!(
        matches!(
            again,
            BroadcastOutcome::AlreadyKnown(_) | BroadcastOutcome::Rejected { .. }
        ),
        "unexpected rebroadcast outcome {again:?}"
    );
    assert_eq!(h.safe_nonce(safe).await, U256::from(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn session_block_env_matches_pinned_header() {
    let h = LocalHarness::new().await;
    let probe = h.create2(common::block_probe_initcode()).await;
    let mut session = session_at_latest(&h).await;
    let out = session
        .call(h.deployer.address(), probe, Bytes::new())
        .unwrap();
    let (timestamp, number, basefee, prevrandao) =
        <(U256, U256, U256, B256)>::abi_decode(&out).unwrap();
    let env = session.block_env().clone();
    assert_eq!(timestamp, U256::from(env.timestamp));
    assert_eq!(number, U256::from(env.number));
    assert_eq!(basefee, U256::from(env.basefee));
    assert_eq!(prevrandao, env.prevrandao);
    let latest = ParentHeader::fetch(&h.provider, BlockId::latest())
        .await
        .unwrap();
    assert_eq!(env.number, latest.number + 1);
    assert!(env.timestamp > latest.timestamp);
    assert_ne!(
        timestamp,
        U256::from(1),
        "revm default timestamp must not leak"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_is_stateful_across_commits() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(3).await;
    h.fund(safe, U256::from(1_000)).await;
    let recipient = Address::repeat_byte(0x43);
    let mut session = session_at_latest(&h).await;

    // Safe nonce 0 and nonce 1, signed in sequence and applied in one session.
    for (i, nonce) in [0u64, 1].into_iter().enumerate() {
        let prepared = safe_rs::PreparedSafeTx::single_call(
            h.chain_id,
            safe,
            &Call::new(recipient, U256::from(10), Bytes::new()),
            U256::from(nonce),
            SafeTxGasPolicy::Zero,
        )
        .unwrap();
        let signed = prepared.sign(&h.owner).await.unwrap();
        let result = session
            .transact_commit(SimTx::relaxed(
                h.owner.address(),
                safe,
                U256::ZERO,
                signed.exec_calldata(),
                OUTER_GAS,
            ))
            .unwrap();
        assert!(result.success, "tx {i} failed: {:?}", result.revert_reason);
        assert!(decode_safe_outcome(&result.logs, safe, prepared.safe_tx_hash).is_success());
    }
    assert_eq!(session.balance(recipient).unwrap(), U256::from(20));

    // A checkpoint diverges independently.
    let mut fork = session.checkpoint();
    fork.transact_commit(SimTx::relaxed(
        h.deployer.address(),
        recipient,
        U256::from(5),
        Bytes::new(),
        21_000,
    ))
    .unwrap();
    assert_eq!(fork.balance(recipient).unwrap(), U256::from(25));
    assert_eq!(session.balance(recipient).unwrap(), U256::from(20));

    // Nothing was broadcast.
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_rejects_gas_above_osaka_cap() {
    let h = LocalHarness::new().await;
    let mut session = session_at_latest(&h).await.with_tx_gas_cap(1 << 24);
    let err = session
        .transact(SimTx::relaxed(
            h.deployer.address(),
            Address::ZERO,
            U256::ZERO,
            Bytes::new(),
            30_000_000,
        ))
        .unwrap_err();
    assert!(matches!(err, Error::GasLimitAboveCap { .. }), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_session_simulates_exact_signed_outer_tx() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(4).await;
    h.fund(safe, U256::from(1_000)).await;
    let prepared = h
        .prepare(
            safe,
            &[Call::new(
                Address::repeat_byte(9),
                U256::from(1),
                Bytes::new(),
            )],
            SafeTxGasPolicy::Zero,
        )
        .await;
    let outer = h.sign_exec(&prepared, OUTER_GAS).await;
    let mut session = session_at_latest(&h).await;
    let simulated = session.transact_commit(strict_tx(&h, &outer)).unwrap();
    assert!(simulated.success);
    let receipt = h.send(&outer).await;
    let mined_logs = logs(&receipt);
    assert_eq!(
        simulated.logs, mined_logs,
        "simulated logs must match the mined transaction"
    );
    assert_eq!(
        simulated.gas_used, receipt.gas_used,
        "simulated gas must match the receipt"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_safe_tx_gas_inner_failure_reverts_gs013() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(5).await;
    let reverter = h.create2(reverter_initcode()).await;
    let calls = [
        Call::call(reverter, Bytes::new()),
        Call::call(safe, Bytes::new()),
    ];
    let prepared = h.prepare(safe, &calls, SafeTxGasPolicy::Zero).await;
    let outer = h.sign_exec(&prepared, OUTER_GAS).await;

    let mut session = session_at_latest(&h).await.with_tracing(true);
    let simulated = session.transact(strict_tx(&h, &outer)).unwrap();
    assert!(
        !simulated.success,
        "a failing inner call must fail the simulation"
    );
    assert_eq!(
        simulated.revert_reason.as_deref(),
        Some("nope"),
        "inner reason recovered from trace"
    );

    // Mined anyway (fixed gas limit): the outer transaction reverts, Safe nonce unchanged.
    let receipt = h.send(&outer).await;
    assert!(!receipt.inner.inner.status());
    assert_eq!(h.safe_nonce(safe).await, U256::ZERO);
}

#[tokio::test(flavor = "multi_thread")]
async fn nonzero_safe_tx_gas_inner_failure_emits_execution_failure_and_bumps_nonce() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(6).await;
    let reverter = h.create2(reverter_initcode()).await;
    let prepared = h
        .prepare(
            safe,
            &[Call::call(reverter, Bytes::new())],
            SafeTxGasPolicy::Explicit(U256::from(100_000)),
        )
        .await;
    let outer = h.sign_exec(&prepared, OUTER_GAS).await;
    let receipt = h.send(&outer).await;
    assert!(receipt.inner.inner.status(), "outer transaction succeeds");
    assert_eq!(
        decode_safe_outcome(&logs(&receipt), safe, prepared.safe_tx_hash),
        SafeExecutionOutcome::Failure {
            payment: U256::ZERO
        }
    );
    assert_eq!(
        h.safe_nonce(safe).await,
        U256::from(1),
        "Safe nonce is consumed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn builder_reports_failures_that_used_to_look_successful() {
    let h = LocalHarness::new().await;
    let safe_address = h.deploy_safe(7).await;
    let reverter = h.create2(reverter_initcode()).await;
    let safe = h.safe_client(safe_address);

    // Batch simulation of a failing call now fails (it used to report success).
    let builder = safe
        .batch()
        .call_only()
        .add(Call::call(reverter, Bytes::new()))
        .add(Call::call(safe_address, Bytes::new()))
        .simulate()
        .await
        .unwrap();
    let sim = builder.simulation_result().unwrap();
    assert!(!sim.success);
    assert!(
        sim.revert_reason.as_deref().unwrap().contains("nope"),
        "{:?}",
        sim.revert_reason
    );

    // A single call is simulated through execTransaction too.
    let builder = safe
        .batch()
        .add(Call::call(reverter, Bytes::new()))
        .simulate()
        .await
        .unwrap();
    assert!(!builder.simulation_result().unwrap().success);

    // With an explicit non-zero safeTxGas the failure is mined; execute() reports it.
    let result = safe
        .batch()
        .add(Call::call(reverter, Bytes::new()))
        .with_safe_tx_gas(U256::from(100_000))
        .execute()
        .await
        .unwrap();
    assert!(
        !result.success,
        "ExecutionFailure must not be reported as success"
    );

    // call_only rejects delegatecall even for a single call.
    let err = safe
        .batch()
        .call_only()
        .add(Call::delegate_call(reverter, Bytes::new()))
        .simulate()
        .await;
    assert!(matches!(
        err,
        Err(Error::DelegateCallNotAllowed { index: 0 })
    ));

    // A fixed nonce that is stale is rejected rather than silently replaced.
    let stale = safe.nonce().await.unwrap() + U256::from(5);
    let err = safe
        .batch()
        .add(Call::call(safe_address, Bytes::new()))
        .with_nonce(stale)
        .execute()
        .await;
    assert!(matches!(err, Err(Error::NonceMismatch { .. })));
}

#[tokio::test(flavor = "multi_thread")]
async fn safe_state_reports_owners_modules_guard_and_handler() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(8).await;
    let state = read_safe_state(
        &h.provider,
        safe,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await
    .unwrap();
    assert!(state.is_sole_owner(h.owner.address()));
    assert_eq!(state.singleton, h.addresses.safe_singleton);
    assert_eq!(state.version.as_deref(), Some("1.4.1"));
    assert_eq!(state.fallback_handler, h.addresses.fallback_handler);
    assert_eq!(state.guard, Address::ZERO);
    assert!(state.modules.complete && state.modules.modules.is_empty());

    let modules = [
        Address::repeat_byte(0xa1),
        Address::repeat_byte(0xa2),
        Address::repeat_byte(0xa3),
    ];
    for module in modules {
        h.exec_self(safe, enable_module_call(module)).await;
    }
    h.exec_self(safe, set_guard_call(h.guard)).await;

    let paged = enumerate_modules(&h.provider, safe, BlockId::latest(), 2, 10)
        .await
        .unwrap();
    assert!(paged.complete);
    assert_eq!(paged.modules.len(), 3);
    let truncated = enumerate_modules(&h.provider, safe, BlockId::latest(), 2, 1)
        .await
        .unwrap();
    assert!(
        !truncated.complete,
        "a truncated enumeration must not look complete"
    );

    let state = read_safe_state(
        &h.provider,
        safe,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(state.guard, h.guard);
    assert_eq!(state.modules.modules.len(), 3);
    assert_eq!(state.nonce, U256::from(4));
}

#[tokio::test(flavor = "multi_thread")]
async fn modules_read_errors_on_uninitialized_proxy() {
    let h = LocalHarness::new().await;
    // A proxy created with an empty initializer is never set up.
    let data = safe_rs::encode_create_proxy_with_nonce(
        h.addresses.safe_singleton,
        Bytes::new(),
        U256::from(99),
    );
    let factory = safe_rs::ISafeProxyFactory::new(h.addresses.proxy_factory, &h.provider);
    let creation_code = factory.proxyCreationCode().call().await.unwrap();
    let proxy = safe_rs::compute_create2_address(
        h.addresses.proxy_factory,
        h.addresses.safe_singleton,
        &Bytes::new(),
        U256::from(99),
        &creation_code,
    );
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(h.addresses.proxy_factory)
        .input(data.into());
    h.deployer_provider
        .send_transaction(tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(!h.provider.get_code_at(proxy).await.unwrap().is_empty());
    let err = read_safe_state(
        &h.provider,
        proxy,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await;
    assert!(
        err.is_err(),
        "reading an uninitialized proxy must fail, got {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_owner_and_threshold_are_not_sole_owner() {
    let h = LocalHarness::new().await;
    let other = h.deployer.address();
    let safe = h.deploy_safe_with(&[h.owner.address(), other], 1, 11).await;
    let state = read_safe_state(
        &h.provider,
        safe,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await
    .unwrap();
    assert!(!state.is_sole_owner(h.owner.address()));
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_builder_address_override_predicts_and_deploys() {
    let h = LocalHarness::new().await;
    let builder = WalletBuilder::new(h.provider.clone(), h.owner.clone());
    let config = WalletConfig::new()
        .with_salt_nonce(U256::from(1234))
        .with_addresses(h.addresses.clone());
    let predicted = builder.compute_address(&config).await.unwrap();
    let deployed = builder.deploy(h.url(), config.clone()).await.unwrap();
    assert_eq!(predicted, deployed);
    // Idempotent: deploying again returns the same address without a transaction.
    assert_eq!(builder.deploy(h.url(), config).await.unwrap(), deployed);
    let state = read_safe_state(
        &h.provider,
        deployed,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await
    .unwrap();
    assert!(state.is_sole_owner(h.owner.address()));
    assert_eq!(state.singleton, h.addresses.safe_singleton);
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_then_timeout_returns_hash_then_mined() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(12).await;
    let prepared = h
        .prepare(
            safe,
            &[Call::call(safe, Bytes::new())],
            SafeTxGasPolicy::Zero,
        )
        .await;
    let outer = h.sign_exec(&prepared, OUTER_GAS).await;

    h.provider.anvil_set_auto_mine(false).await.unwrap();
    let outcome = broadcast_raw(&h.provider, &outer.raw, outer.tx_hash).await;
    assert_eq!(outcome, BroadcastOutcome::Accepted(outer.tx_hash));
    let waited = wait_for_receipt(
        &h.provider,
        outer.tx_hash,
        Duration::from_millis(300),
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    assert!(matches!(waited, ReceiptWait::TimedOut { tx_hash } if tx_hash == outer.tx_hash));

    h.provider.anvil_mine(Some(1), None).await.unwrap();
    let waited = wait_for_receipt(
        &h.provider,
        outer.tx_hash,
        Duration::from_secs(5),
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    let ReceiptWait::Mined(receipt) = waited else {
        panic!("expected a receipt")
    };
    assert!(decode_safe_outcome(&logs(&receipt), safe, prepared.safe_tx_hash).is_success());
}

#[tokio::test(flavor = "multi_thread")]
async fn measure_checks_skip_only_the_sender_balance() {
    let h = LocalHarness::new().await;
    let poor = Address::repeat_byte(0x77);
    h.provider
        .anvil_set_balance(poor, U256::from(1_000))
        .await
        .unwrap();
    let mut session = session_at_latest(&h).await.with_tx_gas_cap(1 << 24);
    let fee = session.block_env().basefee * 2 + 1_000_000_000;
    let tx = |checks, nonce| SimTx {
        from: poor,
        to: Address::repeat_byte(9),
        value: U256::ZERO,
        input: Bytes::new(),
        gas_limit: 1 << 24,
        max_fee_per_gas: u128::from(fee),
        max_priority_fee_per_gas: Some(1_000_000_000),
        nonce: Some(nonce),
        checks,
    };
    // The sender cannot afford gas_limit * max_fee: invalid as sent...
    assert!(session.transact(tx(TxChecks::STRICT, 0)).is_err());
    // ...but measurable, while the nonce is still enforced.
    assert!(session.transact(tx(TxChecks::MEASURE, 0)).unwrap().success);
    assert!(session.transact(tx(TxChecks::MEASURE, 5)).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn halted_frames_are_named_in_revert_reasons() {
    let h = LocalHarness::new().await;
    // Runtime `JUMPDEST PUSH1 0 JUMP`: loops until out of gas.
    let looper = h
        .create2("0x635b6000566000526004601cf3".parse().unwrap())
        .await;
    let mut session = session_at_latest(&h).await.with_tracing(true);
    let result = session
        .transact(SimTx::relaxed(
            h.deployer.address(),
            looper,
            U256::ZERO,
            Bytes::new(),
            100_000,
        ))
        .unwrap();
    assert!(!result.success);
    let reason = result.revert_reason.unwrap_or_default();
    assert!(reason.contains("OutOfGas"), "{reason}");
}

#[tokio::test(flavor = "multi_thread")]
async fn builder_executes_exactly_the_simulated_safe_tx() {
    let h = LocalHarness::new().await;
    let safe_address = h.deploy_safe(9).await;
    h.fund(safe_address, U256::from(1_000)).await;
    let safe = h.safe_client(safe_address);
    let recipient = Address::repeat_byte(0x43);

    let builder = safe
        .batch()
        .call_only()
        .add(Call::new(recipient, U256::from(10), Bytes::new()))
        .add(Call::new(recipient, U256::from(5), Bytes::new()));
    let prepared = builder.prepare().await.unwrap();
    assert!(prepared.is_fail_closed());
    let builder = builder
        .simulate()
        .await
        .unwrap()
        .simulation_success()
        .unwrap();
    let result = builder.execute().await.unwrap();
    assert!(result.success);

    // The mined Safe transaction is the prepared (and simulated) one, safeTxGas 0.
    let receipt = h
        .provider
        .get_transaction_receipt(result.tx_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(decode_safe_outcome(&logs(&receipt), safe_address, prepared.safe_tx_hash).is_success());
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(15)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn builder_execute_after_simulate_stays_fail_closed() {
    let h = LocalHarness::new().await;
    let safe_address = h.deploy_safe(10).await;
    let reverter = h.create2(reverter_initcode()).await;
    let safe = h.safe_client(safe_address);

    // A failing inner call after simulate() used to be signed with
    // safeTxGas = gas_used * 1.1 and mined as ExecutionFailure. It now reverts
    // before broadcast and the nonce is not consumed.
    let builder = safe
        .batch()
        .add(Call::call(reverter, Bytes::new()))
        .simulate()
        .await
        .unwrap();
    assert!(!builder.simulation_result().unwrap().success);
    let err = builder.execute().await;
    assert!(
        matches!(err, Err(Error::InnerTransactionReverted { .. })),
        "{err:?}"
    );
    assert_eq!(h.safe_nonce(safe_address).await, U256::ZERO);

    // Calls added after simulate() are refused rather than executed unsimulated.
    let err = safe
        .batch()
        .add(Call::call(safe_address, Bytes::new()))
        .simulate()
        .await
        .unwrap()
        .add(Call::call(safe_address, Bytes::new()))
        .execute()
        .await;
    assert!(matches!(err, Err(Error::InvalidConfig(_))), "{err:?}");

    // A simulated transaction whose nonce was used in the meantime is refused.
    let stale = safe
        .batch()
        .add(Call::call(safe_address, Bytes::new()))
        .simulate()
        .await
        .unwrap();
    safe.batch()
        .add(Call::call(safe_address, Bytes::new()))
        .execute()
        .await
        .unwrap();
    assert!(matches!(
        stale.execute().await,
        Err(Error::NonceMismatch { .. })
    ));
}
