//! Signing with a real Ledger. Ignored by default: run with a Ledger plugged
//! in, unlocked, with the Ethereum app open (blind signing enabled) and
//! confirm each prompt on the device:
//!
//! ```text
//! cargo test --features ledger --test ledger -- --ignored --nocapture
//! ```
//!
//! Nothing is broadcast; the signatures are only checked.
#![allow(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test harness: setup panics are intended"
)]

use alloy::eips::eip1559::Eip1559Estimation;
use alloy::primitives::{Address, Bytes, U256};
use safe_rs::rotation::KeySource;
use safe_rs::{
    decode_signed_outer_tx, Call, LedgerKeys, OuterTxParams, PreparedSafeTx, SafeTxGasPolicy,
};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Ledger with the Ethereum app open"]
async fn a_ledger_derives_keys_and_signs_safe_and_outer_transactions() {
    let keys = LedgerKeys::connect().await.unwrap();
    let mut addresses = Vec::new();
    for index in 0..3 {
        let address = keys.address(index).await.unwrap();
        println!("key {index}: {address}");
        addresses.push(address);
    }
    assert_ne!(addresses[0], addresses[1]);
    assert_eq!(keys.address(1).await.unwrap(), addresses[1], "stable");

    // A Safe transaction, signed as EIP-712 typed data (confirm on the device).
    let safe = Address::repeat_byte(0x5A);
    let tx = PreparedSafeTx::single_call(
        1,
        safe,
        &Call::new(Address::repeat_byte(0x42), U256::from(1), Bytes::new()),
        U256::from(7),
        SafeTxGasPolicy::Zero,
    )
    .unwrap();
    println!("Safe tx hash: {}", tx.safe_tx_hash);
    let signed = keys.sign_safe_tx(1, &tx).await.unwrap();
    assert_eq!(signed.owner, addresses[1]);
    signed.verify().unwrap();

    // The outer transaction that would submit it (confirm on the device).
    let params = OuterTxParams::exec_transaction(
        &signed,
        addresses[1],
        0,
        200_000,
        Eip1559Estimation {
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        },
    );
    let outer = keys.sign_outer_tx(1, params).await.unwrap();
    assert_eq!(
        decode_signed_outer_tx(&outer.raw).unwrap().params.from,
        addresses[1]
    );
}
