//! Safe transaction E2E tests

use alloy::primitives::{Bytes, U256};

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::{Account, CallBuilder, Operation};

/// Test executing a single ETH transfer from the Safe
#[tokio::test(flavor = "multi_thread")]
async fn test_execute_single_eth_transfer() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(5001))
        .await
        .expect("Failed to deploy Safe");

    // Fund the Safe with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(safe_address, fund_amount)
        .await
        .expect("Failed to fund Safe");

    // Verify Safe balance
    let safe_balance = harness.get_balance(safe_address).await.unwrap();
    assert_eq!(safe_balance, fund_amount, "Safe should have 10 ETH");

    // Create Safe client
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Recipient address
    let recipient = alloy::primitives::address!("0x4444444444444444444444444444444444444444");
    let transfer_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    // Get recipient balance before
    let recipient_balance_before = harness.get_balance(recipient).await.unwrap();

    // Execute ETH transfer
    let result = safe
        .execute_single(recipient, transfer_amount, Bytes::new(), Operation::Call)
        .await
        .expect("Failed to execute transfer");

    assert!(result.success, "Transaction should succeed");

    // Verify recipient received ETH
    let recipient_balance_after = harness.get_balance(recipient).await.unwrap();
    assert_eq!(
        recipient_balance_after,
        recipient_balance_before + transfer_amount,
        "Recipient should have received 1 ETH"
    );
}

/// Test executing multiple ETH transfers via multicall
#[tokio::test(flavor = "multi_thread")]
async fn test_multicall_multiple_transfers() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(5002))
        .await
        .expect("Failed to deploy Safe");

    // Fund the Safe with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(safe_address, fund_amount)
        .await
        .expect("Failed to fund Safe");

    // Create Safe client
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Recipients
    let recipient1 = alloy::primitives::address!("0x5555555555555555555555555555555555555555");
    let recipient2 = alloy::primitives::address!("0x6666666666666666666666666666666666666666");
    let transfer_amount = U256::from(500_000_000_000_000_000u128); // 0.5 ETH each

    // Get balances before
    let balance1_before = harness.get_balance(recipient1).await.unwrap();
    let balance2_before = harness.get_balance(recipient2).await.unwrap();

    // Execute multicall with two ETH transfers
    let result = safe
        .batch()
        .add_raw(recipient1, transfer_amount, Bytes::new())
        .add_raw(recipient2, transfer_amount, Bytes::new())
        .simulate()
        .await
        .expect("Simulation should succeed")
        .execute()
        .await
        .expect("Failed to execute multicall");

    assert!(result.success, "Transaction should succeed");

    // Verify both recipients received ETH
    let balance1_after = harness.get_balance(recipient1).await.unwrap();
    let balance2_after = harness.get_balance(recipient2).await.unwrap();

    assert_eq!(
        balance1_after,
        balance1_before + transfer_amount,
        "Recipient 1 should have received 0.5 ETH"
    );
    assert_eq!(
        balance2_after,
        balance2_before + transfer_amount,
        "Recipient 2 should have received 0.5 ETH"
    );
}

/// Test simulate then execute workflow
#[tokio::test(flavor = "multi_thread")]
async fn test_simulate_then_execute() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(5003))
        .await
        .expect("Failed to deploy Safe");

    // Fund the Safe with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(safe_address, fund_amount)
        .await
        .expect("Failed to fund Safe");

    // Create Safe client
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let recipient = alloy::primitives::address!("0x7777777777777777777777777777777777777777");
    let transfer_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    // Get recipient's initial balance (may be non-zero in forked state)
    let initial_recipient_balance = harness.get_balance(recipient).await.unwrap();

    // Build multicall and simulate first
    let builder = safe
        .batch()
        .add_raw(recipient, transfer_amount, Bytes::new())
        .simulate()
        .await
        .expect("Simulation should succeed");

    // Inspect simulation result
    let sim_result = builder.simulation_result().expect("Should have simulation result");
    assert!(sim_result.success, "Simulation should succeed");
    assert!(sim_result.gas_used > 0, "Should use some gas");

    // Now execute
    let result = builder.execute().await.expect("Execution should succeed");
    assert!(result.success, "Transaction should succeed");

    // Verify transfer happened by checking balance increase
    let final_recipient_balance = harness.get_balance(recipient).await.unwrap();
    assert_eq!(
        final_recipient_balance,
        initial_recipient_balance + transfer_amount,
        "Recipient should have received 1 ETH"
    );
}

/// Test that nonce increments after each transaction
#[tokio::test(flavor = "multi_thread")]
async fn test_nonce_increments() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(5004))
        .await
        .expect("Failed to deploy Safe");

    // Fund the Safe
    harness
        .mint_eth(safe_address, U256::from(10_000_000_000_000_000_000u128))
        .await
        .expect("Failed to fund Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Get initial nonce
    let nonce_before = safe.nonce().await.expect("Failed to get nonce");
    assert_eq!(nonce_before, U256::ZERO, "Initial nonce should be 0");

    // Execute a transaction
    let recipient = alloy::primitives::address!("0x8888888888888888888888888888888888888888");
    safe.execute_single(
        recipient,
        U256::from(100_000_000_000_000_000u128), // 0.1 ETH
        Bytes::new(),
        Operation::Call,
    )
    .await
    .expect("First transaction should succeed");

    // Check nonce incremented
    let nonce_after_first = safe.nonce().await.expect("Failed to get nonce");
    assert_eq!(nonce_after_first, U256::from(1), "Nonce should be 1 after first tx");

    // Execute another transaction
    safe.execute_single(
        recipient,
        U256::from(100_000_000_000_000_000u128),
        Bytes::new(),
        Operation::Call,
    )
    .await
    .expect("Second transaction should succeed");

    // Check nonce incremented again
    let nonce_after_second = safe.nonce().await.expect("Failed to get nonce");
    assert_eq!(nonce_after_second, U256::from(2), "Nonce should be 2 after second tx");
}
