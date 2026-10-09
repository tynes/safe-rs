//! One-time owner keys end to end, against a fresh local Anvil chain.
//!
//! Every test deploys Safe v1.4.1 from the vendored artifacts, so no RPC URL
//! is needed. Owner keys come from a fixed BIP-39 test phrase.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test harness: setup panics are intended"
)]

#[allow(dead_code, reason = "the harness is shared with tests/local.rs")]
#[path = "local/common.rs"]
mod common;

use std::path::Path;
use std::time::Duration;

use alloy::network::{AnyNetwork, EthereumWallet};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use common::{one_shot_initcode, LocalHarness};
use safe_rs::rotation::{
    binding_key, ExecOptions, Exposure, OwnerRef, RotatingSafe, RotationConfig, RotationStatus,
    StateFile,
};
use safe_rs::{
    broadcast_raw, sign_outer_tx, wait_for_receipt, BroadcastOutcome, Call, Error, HdWallet,
    OuterTxParams, ReceiptWait,
};

/// A BIP-39 test vector, deliberately not Anvil's own phrase.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

type Rotating = RotatingSafe<DynProvider<AnyNetwork>>;

fn wallet() -> HdWallet {
    HdWallet::from_phrase(PHRASE).unwrap()
}

fn eth(amount: u64) -> U256 {
    U256::from(amount) * U256::from(10).pow(U256::from(18))
}

fn config(h: &LocalHarness) -> RotationConfig {
    RotationConfig {
        addresses: h.addresses.clone(),
        timeout: Duration::from_secs(10),
        poll_interval: Duration::from_millis(50),
        scan_limit: 24,
        ..RotationConfig::default()
    }
}

/// Deploys a 1/1 Safe owned by wallet key 1, gives that key 1 ETH for gas and
/// the Safe a little to spend, and records the binding in `state`.
async fn setup(h: &LocalHarness, salt: u64, state: &Path) -> Address {
    let owner = wallet().owner_address(1).unwrap();
    let safe = h.deploy_safe_with(&[owner], 1, salt).await;
    h.fund(owner, eth(1)).await;
    h.fund(safe, U256::from(1_000)).await;
    let mut store = StateFile::open(state, wallet().id()).unwrap();
    store
        .state
        .bind(
            &binding_key(h.chain_id, safe),
            OwnerRef::Derived {
                index: 1,
                address: owner,
            },
        )
        .unwrap();
    store.save().unwrap();
    safe
}

async fn open_with(
    h: &LocalHarness,
    safe: Address,
    state: &Path,
    config: RotationConfig,
) -> Rotating {
    let store = StateFile::open(state, wallet().id()).unwrap();
    RotatingSafe::open_with(h.provider.clone(), safe, wallet(), store, config)
        .await
        .unwrap()
}

async fn open(h: &LocalHarness, safe: Address, state: &Path) -> Rotating {
    open_with(h, safe, state, config(h)).await
}

async fn balance(h: &LocalHarness, address: Address) -> U256 {
    h.provider.get_balance(address).await.unwrap()
}

async fn eoa_nonce(h: &LocalHarness, address: Address) -> u64 {
    h.provider.get_transaction_count(address).await.unwrap()
}

async fn sender_of(h: &LocalHarness, tx_hash: alloy::primitives::B256) -> Address {
    h.provider
        .get_transaction_receipt(tx_hash)
        .await
        .unwrap()
        .unwrap()
        .from
}

fn pay(to: Address, wei: u64) -> Call {
    Call::new(to, U256::from(wei), Bytes::new())
}

fn key(index: u32) -> Address {
    wallet().owner_address(index).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_transaction_moves_ownership_and_gas_to_the_next_key() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 100, &state).await;
    let recipient = Address::repeat_byte(0x42);
    let mut rotating = open(&h, safe, &state).await;

    for round in 1..=5u32 {
        let old = key(round);
        let new = key(round + 1);
        let before = balance(&h, old).await;

        let outcome = rotating.execute(&[pay(recipient, 1)]).await.unwrap();
        assert_eq!(outcome.status, RotationStatus::Rotated, "round {round}");
        assert!(outcome.safe_outcome.is_success());
        assert_eq!(h.owners(safe).await, vec![new]);
        assert_eq!(sender_of(&h, outcome.tx_hash).await, old, "the owner paid");

        // All of the old key's ETH is on the new key, less the two fees.
        let sweep = outcome.sweep.expect("a sweep");
        assert_eq!((sweep.from, sweep.to), (old, new));
        assert_eq!(balance(&h, old).await, U256::ZERO, "round {round}");
        assert_eq!(balance(&h, new).await, sweep.amount);
        assert!(sweep.amount < before && sweep.amount > before - eth(1) / U256::from(100));
        assert_eq!(eoa_nonce(&h, new).await, 0, "the new key has not signed");
        assert!(rotating.warnings().is_empty(), "{:?}", rotating.warnings());
    }

    assert_eq!(balance(&h, recipient).await, U256::from(5));
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.current.index(), Some(6));
    assert_eq!(binding.exposed, None);
    assert_eq!(binding.reserved, None);
    assert_eq!(binding.pending, None);
    assert_eq!(binding.sweep_due, None);
    assert_eq!(binding.history.len(), 5);
    assert!(binding
        .history
        .iter()
        .all(|retired| retired.swept.is_some()));
    assert_eq!(rotating.state().next_index, 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_middle_owner_of_three_rotates_in_place() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let first = Address::repeat_byte(0x61);
    let last = Address::repeat_byte(0x62);
    let safe = h.deploy_safe_with(&[first, key(1), last], 1, 101).await;
    h.fund(key(1), eth(1)).await;

    // No state yet: the Safe is adopted because key 1 is among its owners.
    let mut rotating = open(&h, safe, &state).await;
    assert_eq!(rotating.binding().unwrap().current.index(), Some(1));
    assert_eq!(
        rotating.binding().unwrap().exposed,
        Some(Exposure::Rebuilt),
        "a binding rebuilt from chain may have signatures it cannot see"
    );

    let outcome = rotating.rotate().await.unwrap();
    assert_eq!(outcome.status, RotationStatus::Rotated);
    let new = rotating.binding().unwrap().current.address();
    assert_eq!(h.owners(safe).await, vec![first, new, last]);
    assert_eq!(rotating.binding().unwrap().exposed, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reverted_rotation_exposes_the_key_and_recovers_at_the_same_nonce() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 102, &state).await;
    let one_shot = h.create2(one_shot_initcode()).await;
    let mut rotating = open(&h, safe, &state).await;

    // Simulated while the call still succeeds...
    let tx = rotating
        .prepare(
            &[Call::call(one_shot, Bytes::new())],
            ExecOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        rotating.binding().unwrap().exposed,
        None,
        "nothing left the process yet"
    );
    // ...then someone else uses up the one shot, so on chain it reverts.
    h.deployer_provider
        .send_transaction(TransactionRequest::default().to(one_shot).into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let reserved = tx.to;
    let stale = tx.signed.clone();
    let outcome = rotating.submit(tx).await.unwrap();
    assert_eq!(outcome.status, RotationStatus::NotRotated);
    assert_eq!(outcome.sweep, None);
    assert_eq!(h.owners(safe).await, vec![key(1)]);
    assert_eq!(
        h.safe_nonce(safe).await,
        U256::ZERO,
        "GS013 does not use the nonce"
    );
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.exposed, Some(Exposure::Signed));
    assert_eq!(binding.reserved, Some(reserved), "the reservation is kept");
    assert_eq!(binding.pending, None, "a mined transaction is not pending");

    // Recovery: a rotation-only transaction at the same Safe nonce, to the
    // same next key. It retires the exposed key and voids the stale signature.
    let recovery = rotating.rotate().await.unwrap();
    assert_eq!(recovery.status, RotationStatus::Rotated);
    assert_eq!(h.owners(safe).await, vec![reserved.address]);
    assert_eq!(h.safe_nonce(safe).await, U256::from(1));
    assert_eq!(rotating.binding().unwrap().exposed, None);
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);

    // The stale Safe transaction can no longer execute.
    let fees = h.fees().await;
    let replay = sign_outer_tx(
        &h.deployer,
        OuterTxParams::exec_transaction(
            &stale,
            h.deployer.address(),
            eoa_nonce(&h, h.deployer.address()).await,
            600_000,
            fees,
        ),
    )
    .await
    .unwrap();
    assert!(!h.send(&replay).await.inner.inner.status());
    assert_eq!(h.owners(safe).await, vec![reserved.address]);
}

/// A third party executes the signed Safe transaction itself.
async fn front_run(h: &LocalHarness, signed: &safe_rs::SignedSafeTx) {
    let runner = alloy::signers::local::PrivateKeySigner::random();
    h.fund(runner.address(), eth(1)).await;
    let outer = sign_outer_tx(
        &runner,
        OuterTxParams::exec_transaction(signed, runner.address(), 0, 600_000, h.fees().await),
    )
    .await
    .unwrap();
    assert!(h.send(&outer).await.inner.inner.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_front_run_copy_still_counts_as_the_rotation() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 103, &state).await;
    let mut rotating = open(&h, safe, &state).await;

    let tx = rotating
        .prepare(
            &[pay(Address::repeat_byte(0x42), 1)],
            ExecOptions::default(),
        )
        .await
        .unwrap();
    rotating.arm(&tx).unwrap();
    front_run(&h, &tx.signed).await;

    // Our own outer transaction now reverts, but the owner list has moved on.
    let outcome = rotating.submit(tx).await.unwrap();
    assert_eq!(outcome.status, RotationStatus::RotatedElsewhere);
    assert!(!outcome.safe_outcome.is_success());
    assert_eq!(h.owners(safe).await, vec![key(2)]);
    assert_eq!(rotating.binding().unwrap().current.index(), Some(2));
    assert_eq!(rotating.binding().unwrap().exposed, None);
    assert_eq!(balance(&h, key(1)).await, U256::ZERO, "swept all the same");
    assert_eq!(balance(&h, Address::repeat_byte(0x42)).await, U256::from(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_completed_while_away_is_picked_up_on_reopen() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 104, &state).await;

    let mut rotating = open(&h, safe, &state).await;
    let tx = rotating.prepare(&[], ExecOptions::default()).await.unwrap();
    rotating.arm(&tx).unwrap();
    assert_eq!(
        rotating.binding().unwrap().exposed,
        Some(Exposure::Signed),
        "armed: the signature may leave the process"
    );
    // The process dies here; the signed transaction is executed by someone else.
    drop(rotating);
    front_run(&h, &tx.signed).await;

    let rotating = open(&h, safe, &state).await;
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.current.index(), Some(2));
    assert_eq!(binding.pending, None);
    assert_eq!(binding.exposed, None);
    assert_eq!(binding.sweep_due, None, "the owed sweep ran on open");
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);
    assert!(balance(&h, key(2)).await > U256::ZERO);
    assert!(rotating.warnings().is_empty(), "{:?}", rotating.warnings());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crash_after_broadcast_is_reconciled_from_the_chain() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 105, &state).await;

    let mut rotating = open(&h, safe, &state).await;
    let tx = rotating
        .prepare(
            &[pay(Address::repeat_byte(0x42), 1)],
            ExecOptions::default(),
        )
        .await
        .unwrap();
    rotating.arm(&tx).unwrap();
    h.provider.anvil_set_auto_mine(false).await.unwrap();
    assert_eq!(
        broadcast_raw(&h.provider, &tx.outer.raw, tx.outer.tx_hash).await,
        BroadcastOutcome::Accepted(tx.outer.tx_hash)
    );
    drop(rotating); // crash before any receipt

    // Reopened while the transaction is still in the mempool.
    let mut short = config(&h);
    short.timeout = Duration::from_millis(300);
    let mut rotating = open_with(&h, safe, &state, short).await;
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.current.index(), Some(1));
    assert!(binding.pending.is_some());
    assert_eq!(binding.exposed, Some(Exposure::Signed));
    // New user calls must not compete with the pending ones.
    let refused = rotating
        .prepare(
            &[pay(Address::repeat_byte(0x43), 1)],
            ExecOptions::default(),
        )
        .await;
    assert!(matches!(refused, Err(Error::Rotation(_))), "{refused:?}");
    drop(rotating);

    h.provider.anvil_mine(Some(1), None).await.unwrap();
    h.provider.anvil_set_auto_mine(true).await.unwrap();
    let rotating = open(&h, safe, &state).await;
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.current.index(), Some(2));
    assert_eq!(binding.pending, None);
    assert_eq!(binding.exposed, None);
    assert_eq!(h.owners(safe).await, vec![key(2)]);
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);
    assert_eq!(balance(&h, Address::repeat_byte(0x42)).await, U256::from(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sweep_interrupted_after_broadcast_lands_exactly_once() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 106, &state).await;
    let mut short = config(&h);
    short.timeout = Duration::from_millis(300);

    // Rotate by hand so that the sweep is the first thing left to do.
    let mut rotating = open_with(&h, safe, &state, short.clone()).await;
    let tx = rotating.prepare(&[], ExecOptions::default()).await.unwrap();
    rotating.arm(&tx).unwrap();
    broadcast_raw(&h.provider, &tx.outer.raw, tx.outer.tx_hash).await;
    let mined = wait_for_receipt(
        &h.provider,
        tx.outer.tx_hash,
        Duration::from_secs(10),
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    assert!(matches!(mined, ReceiptWait::Mined(_)));

    // The sweep is broadcast but not mined before the process stops.
    h.provider.anvil_set_auto_mine(false).await.unwrap();
    rotating.reconcile().await.unwrap();
    assert_eq!(rotating.binding().unwrap().current.index(), Some(2));
    let due = rotating.binding().unwrap().sweep_due.clone().expect("owed");
    let stored = due
        .signed
        .expect("the signed transfer is saved before broadcast");
    assert_eq!(rotating.warnings().len(), 1, "{:?}", rotating.warnings());
    drop(rotating);

    // Reopening rebroadcasts the same bytes instead of signing a second transfer.
    let rotating = open_with(&h, safe, &state, short).await;
    let again = rotating
        .binding()
        .unwrap()
        .sweep_due
        .clone()
        .expect("still owed");
    assert_eq!(again.signed, Some(stored.clone()));
    drop(rotating);

    h.provider.anvil_mine(Some(1), None).await.unwrap();
    h.provider.anvil_set_auto_mine(true).await.unwrap();
    let rotating = open(&h, safe, &state).await;
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.sweep_due, None);
    let swept = binding.history[0].swept.expect("recorded");
    assert_eq!(swept.tx_hash, stored.tx_hash);
    assert_eq!(swept.amount, stored.amount);
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);
    assert_eq!(balance(&h, key(2)).await, stored.amount);
    assert_eq!(
        eoa_nonce(&h, key(1)).await,
        2,
        "one rotation and exactly one transfer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_sweep_the_next_owner_has_no_gas_until_swept() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 107, &state).await;
    let mut no_sweep = config(&h);
    no_sweep.sweep = false;

    let mut rotating = open_with(&h, safe, &state, no_sweep).await;
    let outcome = rotating.rotate().await.unwrap();
    assert_eq!(outcome.status, RotationStatus::Rotated);
    assert_eq!(outcome.sweep, None);
    assert!(balance(&h, key(1)).await > U256::ZERO, "the ETH stayed put");
    assert_eq!(balance(&h, key(2)).await, U256::ZERO);
    assert_eq!(rotating.binding().unwrap().sweep_due, None);

    // The new owner cannot pay: the failure is found before anything is signed off.
    let unfunded = rotating.prepare(&[], ExecOptions::default()).await;
    let Err(Error::Rotation(message)) = unfunded else {
        panic!("expected a funding error, got {unfunded:?}")
    };
    assert!(message.contains("cannot pay"), "{message}");
    assert_eq!(rotating.binding().unwrap().exposed, None);

    // Sweeping on request moves the retired key's ETH after all.
    let swept = rotating.sweep_retired().await.unwrap().expect("a sweep");
    assert_eq!((swept.from, swept.to), (key(1), key(2)));
    assert_eq!(balance(&h, key(1)).await, U256::ZERO);
    assert_eq!(
        rotating.rotate().await.unwrap().status,
        RotationStatus::Rotated
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_separate_payer_keeps_owner_keys_off_chain() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = h.deploy_safe_with(&[key(1)], 1, 108).await;
    let payer = alloy::signers::local::PrivateKeySigner::random();
    h.fund(payer.address(), eth(1)).await;
    let mut paid = config(&h);
    paid.payer = Some(payer.clone());

    let mut rotating = open_with(&h, safe, &state, paid).await;
    for round in 1..=2u32 {
        let outcome = rotating.rotate().await.unwrap();
        assert_eq!(outcome.status, RotationStatus::Rotated);
        assert_eq!(sender_of(&h, outcome.tx_hash).await, payer.address());
        assert_eq!(outcome.sweep, None, "owner keys hold nothing to sweep");
        assert_eq!(rotating.binding().unwrap().sweep_due, None);
        assert_eq!(rotating.binding().unwrap().history.len(), round as usize);
    }
    for retired in &rotating.binding().unwrap().history {
        assert_eq!(retired.swept, None);
        assert_eq!(
            eoa_nonce(&h, retired.owner.address()).await,
            0,
            "an owner key never sent a transaction"
        );
    }
    assert!(rotating.warnings().is_empty(), "{:?}", rotating.warnings());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_owner_hands_the_safe_and_its_gas_to_the_wallet() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    // A Safe owned by an ordinary key the wallet cannot derive.
    let legacy = alloy::signers::local::PrivateKeySigner::random();
    h.fund(legacy.address(), eth(2)).await;
    let safe = h.deploy_safe_with(&[legacy.address()], 1, 109).await;

    // Without the legacy key there is nothing to adopt.
    let store = StateFile::open(&state, wallet().id()).unwrap();
    let refused =
        RotatingSafe::open_with(h.provider.clone(), safe, wallet(), store, config(&h)).await;
    assert!(matches!(refused, Err(Error::Rotation(_))));

    let mut onboarding = config(&h);
    onboarding.legacy_owner = Some(legacy.clone());
    let mut rotating = open_with(&h, safe, &state, onboarding).await;
    assert_eq!(
        rotating.binding().unwrap().current,
        OwnerRef::External {
            address: legacy.address()
        }
    );
    let outcome = rotating.rotate().await.unwrap();
    assert_eq!(outcome.status, RotationStatus::Rotated);
    assert_eq!(h.owners(safe).await, vec![key(1)]);
    assert_eq!(balance(&h, legacy.address()).await, U256::ZERO);
    assert_eq!(balance(&h, key(1)).await, outcome.sweep.unwrap().amount);
    drop(rotating);

    // From here on the wallet alone is enough.
    let mut rotating = open(&h, safe, &state).await;
    assert_eq!(
        rotating.rotate().await.unwrap().status,
        RotationStatus::Rotated
    );
    assert_eq!(h.owners(safe).await, vec![key(2)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owed_sweep_that_cannot_run_is_a_warning_not_a_failure() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 110, &state).await;

    // A sweep is owed from a key the wallet does not have.
    let stranger = Address::repeat_byte(0x77);
    let mut store = StateFile::open(&state, wallet().id()).unwrap();
    store
        .state
        .schedule_sweep(
            &binding_key(h.chain_id, safe),
            OwnerRef::External { address: stranger },
        )
        .unwrap();
    store.save().unwrap();
    drop(store);

    let mut rotating = open(&h, safe, &state).await;
    assert_eq!(rotating.warnings().len(), 1, "{:?}", rotating.warnings());
    assert!(
        rotating.binding().unwrap().sweep_due.is_some(),
        "still owed"
    );
    let outcome = rotating.rotate().await.unwrap();
    assert_eq!(outcome.status, RotationStatus::Rotated);
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_state_is_rebuilt_from_the_owner_list() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 111, &state).await;

    let mut rotating = open(&h, safe, &state).await;
    for _ in 0..3 {
        rotating.rotate().await.unwrap();
    }
    let before = rotating.state().clone();
    assert_eq!(before.next_index, 5);
    drop(rotating);
    std::fs::remove_file(&state).unwrap();

    let mut rotating = open(&h, safe, &state).await;
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.current.index(), Some(4), "found among the owners");
    assert_eq!(binding.exposed, Some(Exposure::Rebuilt));
    assert!(
        binding.history.is_empty(),
        "the owner list holds no history"
    );
    assert!(
        rotating.state().next_index > before.next_index,
        "the counter never moves back, and leaves a margin"
    );
    // The rebuilt state is enough to carry on.
    let next = rotating.state().next_index;
    assert_eq!(
        rotating.rotate().await.unwrap().status,
        RotationStatus::Rotated
    );
    assert_eq!(h.owners(safe).await, vec![key(next)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_that_already_sent_a_transaction_is_never_made_owner() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 112, &state).await;

    // Key 2 was used outside this tool: its public key is on chain.
    h.fund(key(2), eth(1)).await;
    let used = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .wallet(EthereumWallet::from(wallet().owner(2).unwrap()))
        .connect_http(h.url())
        .erased();
    used.send_transaction(
        TransactionRequest::default()
            .to(Address::repeat_byte(0x55))
            .value(U256::from(1))
            .into(),
    )
    .await
    .unwrap()
    .get_receipt()
    .await
    .unwrap();

    let mut rotating = open(&h, safe, &state).await;
    let outcome = rotating.rotate().await.unwrap();
    assert_eq!(outcome.status, RotationStatus::Rotated);
    assert_eq!(h.owners(safe).await, vec![key(3)], "key 2 was skipped");
    assert!(
        rotating
            .warnings()
            .iter()
            .any(|warning| warning.contains("skipping key 2")),
        "{:?}",
        rotating.warnings()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_simulation_signs_nothing_off() {
    let h = LocalHarness::new().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let safe = setup(&h, 113, &state).await;
    let reverter = h.create2(common::reverter_initcode()).await;

    let mut rotating = open(&h, safe, &state).await;
    let failed = rotating
        .prepare(
            &[Call::call(reverter, Bytes::new())],
            ExecOptions::default(),
        )
        .await;
    assert!(
        matches!(&failed, Err(Error::SimulationReverted { reason }) if reason.contains("nope")),
        "{failed:?}"
    );
    let binding = rotating.binding().unwrap();
    assert_eq!(binding.exposed, None, "no signature left the process");
    assert_eq!(binding.pending, None);
    let reserved = binding.reserved.expect("the reservation survives");

    // The next attempt rotates to the same reserved key.
    let outcome = rotating.rotate().await.unwrap();
    assert_eq!(outcome.status, RotationStatus::Rotated);
    assert_eq!(h.owners(safe).await, vec![reserved.address]);
}
