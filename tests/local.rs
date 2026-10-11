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
use alloy::eips::BlockId;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use common::{
    enable_module_call, one_shot_initcode, reverter_initcode, set_guard_call, LocalHarness,
};
use safe_rs::inspect::{enumerate_modules, read_safe_state, ReadSafeStateOptions};
use safe_rs::rotation::{check_post_state, plan_rotation};
use safe_rs::{
    broadcast_raw, decode_safe_outcome, sign_outer_tx, simulate_exec, submit_and_wait,
    wait_for_receipt, Account, BroadcastOutcome, Call, CallBuilder, ChainAddresses, ChainConfig,
    Eoa, Error, ForkSession, ISafe, OuterTxParams, ParentHeader, PreparedSafeTx, ReceiptWait, Safe,
    SafeExecutionOutcome, SafeTxGasPolicy, SimTx, SpecId, Submission, TxChecks, WalletBuilder,
    WalletConfig,
};

/// Gas limit used for outer transactions in these tests (fixed so that failing
/// transactions can still be mined).
const OUTER_GAS: u64 = 600_000;

fn logs(receipt: &alloy::network::AnyTransactionReceipt) -> Vec<alloy::primitives::Log> {
    safe_rs::receipt_logs(receipt)
}

async fn session_at_latest(h: &LocalHarness) -> ForkSession {
    ForkSession::fork_next_block(
        h.provider.clone(),
        h.chain_id,
        BlockId::latest(),
        12,
        BaseFeeParams::ethereum(),
        SpecId::OSAKA,
    )
    .await
    .unwrap()
}

fn strict_tx(outer: &safe_rs::SignedOuterTx) -> SimTx {
    SimTx::from_outer(&outer.params, TxChecks::STRICT)
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
        let prepared = PreparedSafeTx::single_call(
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
    let simulated = session.transact_commit(strict_tx(&outer)).unwrap();
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
    let simulated = session.transact(strict_tx(&outer)).unwrap();
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
async fn connect_with_config_batches_through_the_config_addresses() {
    let h = LocalHarness::new().await;
    let builder = WalletBuilder::new(h.owner_provider(), h.owner.clone());
    let config = WalletConfig::new()
        .with_salt_nonce(U256::from(4321))
        .with_addresses(h.addresses.clone());
    let safe_address = builder.deploy(h.url(), config.clone()).await.unwrap();
    h.fund(safe_address, U256::from(1_000)).await;
    let recipient = Address::repeat_byte(0x4a);
    let canonical = ChainAddresses::v1_4_1();

    // connect(address) has no config to take addresses from: it picks the
    // canonical contracts for the Safe's version, which this chain lacks.
    let detected = WalletBuilder::new(h.owner_provider(), h.owner.clone())
        .connect(safe_address)
        .await
        .unwrap();
    assert_eq!(
        detected.config().addresses.multi_send_call_only,
        canonical.multi_send_call_only
    );

    // The config's deployment is the one the wallet batches through.
    let wallet = builder.connect_with_config(config).await.unwrap();
    assert_eq!(wallet.address(), safe_address);
    assert_eq!(wallet.config().chain_id, h.chain_id);
    let addresses = &wallet.config().addresses;
    assert_eq!(addresses.safe_singleton, h.addresses.safe_singleton);
    assert_eq!(addresses.multi_send, h.addresses.multi_send);
    assert_eq!(
        addresses.multi_send_call_only,
        h.addresses.multi_send_call_only
    );
    assert_ne!(
        addresses.multi_send_call_only,
        canonical.multi_send_call_only
    );

    let result = wallet
        .batch()
        .call_only()
        .add(Call::new(recipient, U256::from(10), Bytes::new()))
        .add(Call::new(recipient, U256::from(5), Bytes::new()))
        .simulate()
        .await
        .unwrap()
        .simulation_success()
        .unwrap()
        .execute()
        .await
        .unwrap();
    assert!(result.success);
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(15)
    );
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

/// Whether `result` is the refusal to batch through `target`, which has no code.
fn refused<T>(result: &safe_rs::Result<T>, target: Address) -> bool {
    matches!(result, Err(Error::MultiSendNotDeployed(missing)) if *missing == target)
}

#[tokio::test(flavor = "multi_thread")]
async fn builder_refuses_a_batch_whose_target_has_no_code() {
    let h = LocalHarness::new().await;
    let safe_address = h.deploy_safe(13).await;
    h.fund(safe_address, U256::from(1_000)).await;
    let recipient = Address::repeat_byte(0x45);
    let transfers = [
        Call::new(recipient, U256::from(10), Bytes::new()),
        Call::new(recipient, U256::from(5), Bytes::new()),
    ];
    let codeless = Address::repeat_byte(0x99);
    let safe = h.safe_client_with(
        safe_address,
        ChainAddresses {
            multi_send_call_only: codeless,
            ..h.addresses.clone()
        },
    );

    // prepare(), simulate() and execute() all stop before the owner signs.
    let call_only = || {
        safe.batch()
            .call_only()
            .add(transfers[0].clone())
            .add(transfers[1].clone())
    };
    assert!(refused(&call_only().prepare().await, codeless));
    assert!(refused(&call_only().simulate().await, codeless));
    assert!(refused(&call_only().execute().await, codeless));

    // The same goes for MultiSend, which the harness does not deploy.
    let multi_send = || {
        safe.batch()
            .add(transfers[0].clone())
            .add(transfers[1].clone())
    };
    assert_eq!(h.addresses.multi_send, Address::ZERO);
    assert!(refused(&multi_send().prepare().await, Address::ZERO));
    assert!(refused(&multi_send().simulate().await, Address::ZERO));
    assert!(refused(&multi_send().execute().await, Address::ZERO));

    // Nothing was broadcast.
    let owner_nonce = || async {
        h.provider
            .get_transaction_count(h.owner.address())
            .await
            .unwrap()
    };
    assert_eq!(owner_nonce().await, 0);
    assert_eq!(h.safe_nonce(safe_address).await, U256::ZERO);
    assert_eq!(h.provider.get_balance(recipient).await.unwrap(), U256::ZERO);

    // A single call has no batch target and is unaffected.
    let result = safe
        .batch()
        .call_only()
        .add(transfers[0].clone())
        .simulate()
        .await
        .unwrap()
        .simulation_success()
        .unwrap()
        .execute()
        .await
        .unwrap();
    assert!(result.success);
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(10)
    );

    // With the deployed MultiSendCallOnly the batch goes through.
    let deployed = h.safe_client(safe_address);
    let result = deployed
        .batch()
        .call_only()
        .add(transfers[0].clone())
        .add(transfers[1].clone())
        .simulate()
        .await
        .unwrap()
        .simulation_success()
        .unwrap()
        .execute()
        .await
        .unwrap();
    assert!(result.success);
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(25)
    );

    // What the refusal prevents: signed anyway, the batch to the codeless
    // target is mined with ExecutionSuccess and none of its calls ran.
    let prepared = PreparedSafeTx::call_only_batch(
        h.chain_id,
        safe_address,
        codeless,
        &transfers,
        h.safe_nonce(safe_address).await,
        SafeTxGasPolicy::Zero,
    )
    .unwrap();
    let outer = h.sign_exec(&prepared, OUTER_GAS).await;
    let receipt = h.send(&outer).await;
    assert!(decode_safe_outcome(&logs(&receipt), safe_address, prepared.safe_tx_hash).is_success());
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(25)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn builder_checks_the_batch_target_at_the_requested_block() {
    let h = LocalHarness::new().await;
    let safe_address = h.deploy_safe(14).await;
    h.fund(safe_address, U256::from(1_000)).await;
    let recipient = Address::repeat_byte(0x46);

    // A second MultiSendCallOnly that does not exist yet at `before`.
    let before = h.provider.get_block_number().await.unwrap();
    let late = h.deploy_multi_send_call_only(B256::repeat_byte(1)).await;
    let safe = h.safe_client_with(
        safe_address,
        ChainAddresses {
            multi_send_call_only: late,
            ..h.addresses.clone()
        },
    );
    let batch = || {
        safe.batch()
            .call_only()
            .add(Call::new(recipient, U256::from(10), Bytes::new()))
            .add(Call::new(recipient, U256::from(5), Bytes::new()))
    };

    // A simulation forked from `before` would run the batch against no code.
    let pinned = batch().with_batch_target_block(BlockId::number(before));
    assert!(refused(&pinned.prepare().await, late));

    // At the latest block, the default, the batch goes through it.
    let prepared = batch().prepare().await.unwrap();
    assert_eq!(prepared.params.to, late);
    let result = batch().execute().await.unwrap();
    assert!(result.success);
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(15)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_batches_through_the_contracts_of_the_safe_version() {
    let h = LocalHarness::new().await;
    let v1_4_1 = ChainAddresses::v1_4_1();
    let v1_5_0 = ChainAddresses::v1_5_0();
    let recipient = Address::repeat_byte(0x49);

    // A chain that has the v1.5.0 MultiSendCallOnly and not the v1.4.1 one.
    h.set_multi_send_call_only(v1_5_0.multi_send_call_only)
        .await;
    let singleton = h.deploy_singleton_reporting("1.5.0").await;
    let new_safe = h
        .deploy_safe_on(singleton, &[h.owner.address()], 1, 15)
        .await;
    let old_safe = h.deploy_safe(15).await;
    h.fund(new_safe, U256::from(1_000)).await;
    h.fund(old_safe, U256::from(1_000)).await;
    let connect = |safe| Safe::connect(h.owner_provider(), h.owner.clone(), safe);
    let batch = |safe| {
        Safe::batch(safe)
            .call_only()
            .add(Call::new(recipient, U256::from(10), Bytes::new()))
            .add(Call::new(recipient, U256::from(5), Bytes::new()))
    };

    // The v1.5.0 Safe batches through the v1.5.0 contract.
    let safe = connect(new_safe).await.unwrap();
    assert_eq!(safe.addresses().multi_send, v1_5_0.multi_send);
    let prepared = batch(&safe).prepare().await.unwrap();
    assert_eq!(prepared.params.to, v1_5_0.multi_send_call_only);
    assert!(batch(&safe).execute().await.unwrap().success);
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(15)
    );

    // The v1.4.1 Safe keeps the v1.4.1 one, which this chain does not have.
    let safe = connect(old_safe).await.unwrap();
    assert_eq!(safe.addresses().multi_send, v1_4_1.multi_send);
    assert!(refused(
        &batch(&safe).prepare().await,
        v1_4_1.multi_send_call_only
    ));

    // So does an address whose version cannot be read.
    let safe = connect(Address::repeat_byte(0x77)).await.unwrap();
    assert_eq!(safe.addresses().multi_send, v1_4_1.multi_send);
    assert_eq!(
        safe.addresses().multi_send_call_only,
        v1_4_1.multi_send_call_only
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn eoa_batch_simulation_is_stateful() {
    let h = LocalHarness::new().await;
    let one_shot = h.create2(one_shot_initcode()).await;
    let eoa = Eoa::new(
        h.provider.clone(),
        h.owner.clone(),
        ChainConfig::with_addresses(h.chain_id, h.addresses.clone()),
        h.url(),
    );
    let builder = eoa
        .batch()
        .add(Call::call(one_shot, Bytes::new()))
        .add(Call::call(one_shot, Bytes::new()))
        .simulate()
        .await
        .unwrap();
    let results = builder.simulation_results().unwrap();
    // The second call sees the first call's storage write and reverts.
    assert!(results[0].success);
    assert!(!results[1].success);
    assert!(builder.simulation_success().is_err());
}

async fn safe_state(h: &LocalHarness, safe: Address) -> safe_rs::SafeState {
    read_safe_state(
        &h.provider,
        safe,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn rotation_swaps_the_sole_owner_after_the_user_calls() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(40).await;
    h.fund(safe, U256::from(1_000)).await;
    let recipient = Address::repeat_byte(0x42);
    let next = Address::repeat_byte(0x51);

    let user = [Call::new(recipient, U256::from(5), Bytes::new())];
    let plan = plan_rotation(
        &safe_state(&h, safe).await,
        h.chain_id,
        h.addresses.multi_send_call_only,
        &user,
        &[(h.owner.address(), next)],
    )
    .unwrap();
    let outer = h.sign_exec(&plan.prepared, OUTER_GAS).await;

    // The simulated post-state is what the plan promised.
    let mut post = session_at_latest(&h).await;
    let mut simulated = post.transact_commit(strict_tx(&outer)).unwrap();
    simulated.require_safe_success(safe, plan.prepared.safe_tx_hash);
    assert!(simulated.success, "{:?}", simulated.revert_reason);
    check_post_state(&mut post, &plan).unwrap();

    let receipt = h.send(&outer).await;
    assert!(decode_safe_outcome(&logs(&receipt), safe, plan.prepared.safe_tx_hash).is_success());
    assert_eq!(h.owners(safe).await, vec![next]);
    assert_eq!(
        h.provider.get_balance(recipient).await.unwrap(),
        U256::from(5)
    );

    // The rotated-out key no longer authorizes anything.
    let stale = h
        .prepare(
            safe,
            &[Call::call(safe, Bytes::new())],
            SafeTxGasPolicy::Zero,
        )
        .await;
    let stale_outer = h.sign_exec(&stale, OUTER_GAS).await;
    let rejected = session_at_latest(&h)
        .await
        .transact(strict_tx(&stale_outer))
        .unwrap();
    assert!(!rejected.success);
    assert!(
        rejected
            .revert_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("GS026")),
        "unexpected reason {:?}",
        rejected.revert_reason
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rotation_of_the_middle_owner_keeps_list_order() {
    let h = LocalHarness::new().await;
    let first = Address::repeat_byte(0x61);
    let last = Address::repeat_byte(0x62);
    let next = Address::repeat_byte(0x63);
    let safe = h
        .deploy_safe_with(&[first, h.owner.address(), last], 1, 41)
        .await;

    let plan = plan_rotation(
        &safe_state(&h, safe).await,
        h.chain_id,
        h.addresses.multi_send_call_only,
        &[],
        &[(h.owner.address(), next)],
    )
    .unwrap();
    assert_eq!(plan.swaps[0].prev_owner, first);
    assert_eq!(plan.prepared.params.to, safe, "rotation only: a direct self-call");

    let outer = h.sign_exec(&plan.prepared, OUTER_GAS).await;
    let receipt = h.send(&outer).await;
    assert!(receipt.inner.inner.status());
    assert_eq!(h.owners(safe).await, vec![first, next, last]);
}

#[tokio::test(flavor = "multi_thread")]
async fn post_state_check_catches_a_batch_target_without_code() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(42).await;
    let next = Address::repeat_byte(0x71);
    let codeless = Address::repeat_byte(0x99);

    // A DELEGATECALL to an address with no code succeeds and does nothing, so
    // the Safe reports success while the owner is unchanged.
    let user = [Call::call(safe, Bytes::new())];
    let plan = plan_rotation(
        &safe_state(&h, safe).await,
        h.chain_id,
        codeless,
        &user,
        &[(h.owner.address(), next)],
    )
    .unwrap();
    let outer = h.sign_exec(&plan.prepared, OUTER_GAS).await;

    let mut post = session_at_latest(&h).await;
    let mut simulated = post.transact_commit(strict_tx(&outer)).unwrap();
    simulated.require_safe_success(safe, plan.prepared.safe_tx_hash);
    assert!(simulated.success, "the Safe itself reports success");
    assert!(matches!(
        check_post_state(&mut post, &plan),
        Err(Error::Rotation(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_separate_payer_sends_what_the_owner_signed() {
    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(43).await;
    let payer = PrivateKeySigner::random();
    h.fund(payer.address(), U256::from(10).pow(U256::from(18)))
        .await;

    let prepared = h
        .prepare(
            safe,
            &[Call::call(safe, Bytes::new())],
            SafeTxGasPolicy::Zero,
        )
        .await;
    let signed = prepared.sign(&h.owner).await.unwrap();
    let fees = h.fees().await;

    let session = session_at_latest(&h).await;
    let simulated = simulate_exec(&session, &signed, payer.address(), fees, None).unwrap();
    assert!(
        simulated.result.success,
        "{:?}",
        simulated.result.revert_reason
    );
    assert!(simulated.post.is_some());
    assert_eq!(simulated.payer_nonce, 0);

    let outer = sign_outer_tx(
        &payer,
        OuterTxParams::exec_transaction(
            &signed,
            payer.address(),
            simulated.payer_nonce,
            simulated.gas_limit,
            fees,
        ),
    )
    .await
    .unwrap();
    let submission = submit_and_wait(
        &h.provider,
        &outer,
        Duration::from_secs(10),
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    let Submission::Mined(receipt) = submission else {
        panic!("expected a receipt, got {submission:?}")
    };
    assert_eq!(receipt.from, payer.address());
    assert!(decode_safe_outcome(&logs(&receipt), safe, prepared.safe_tx_hash).is_success());
    assert_eq!(
        h.provider
            .get_transaction_count(h.owner.address())
            .await
            .unwrap(),
        0,
        "the owner key never sent a transaction"
    );

    // A payer that cannot afford the transaction fails the strict simulation.
    let poor = PrivateKeySigner::random();
    let next = h
        .prepare(
            safe,
            &[Call::call(safe, Bytes::new())],
            SafeTxGasPolicy::Zero,
        )
        .await
        .sign(&h.owner)
        .await
        .unwrap();
    let session = session_at_latest(&h).await;
    assert!(simulate_exec(&session, &next, poor.address(), fees, None).is_err());
}
