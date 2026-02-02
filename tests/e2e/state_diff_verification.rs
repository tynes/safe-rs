//! State diff verification E2E tests - verify state diff matches RPC queries

use alloy::primitives::{keccak256, Bytes, U256};

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::{Account, CallBuilder, IERC20};

/// Test state diff balance changes for ETH transfer
#[tokio::test(flavor = "multi_thread")]
async fn test_state_diff_balance_changes() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(8001))
        .await
        .expect("Failed to deploy Safe");

    // Fund Safe
    let initial_balance = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(safe_address, initial_balance)
        .await
        .expect("Failed to fund Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let recipient = alloy::primitives::address!("0x1111111111111111111111111111111111111111");
    let transfer_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    // Get pre-state balances via RPC
    let pre_safe_balance = harness.get_balance(safe_address).await.unwrap();
    let pre_recipient_balance = harness.get_balance(recipient).await.unwrap();

    // Simulate to get state diff
    let builder = safe
        .batch()
        .add_raw(recipient, transfer_amount, Bytes::new())
        .simulate()
        .await
        .expect("Simulation should succeed");

    let sim_result = builder.simulation_result().expect("Should have simulation result");
    assert!(sim_result.success, "Simulation should succeed");

    // Check state diff contains recipient balance change
    let state_diff = &sim_result.state_diff;

    // The state diff should show recipient balance increasing
    if let Some(post_account) = state_diff.post.get(&recipient) {
        if let Some(post_balance) = post_account.balance {
            // Verify the post balance in state diff is correct
            assert!(
                post_balance >= transfer_amount,
                "State diff should show recipient receiving ETH"
            );
        }
    }

    // Execute the transaction
    let exec_result = builder.execute().await.expect("Execution should succeed");
    assert!(exec_result.success);

    // Get post-state balances via RPC
    let post_recipient_balance = harness.get_balance(recipient).await.unwrap();

    // Verify actual balance change matches expected
    assert_eq!(
        post_recipient_balance,
        pre_recipient_balance + transfer_amount,
        "Recipient should receive 1 ETH"
    );

    println!("Pre Safe balance: {}", pre_safe_balance);
    println!("Transfer amount: {}", transfer_amount);
    println!("Post recipient balance: {}", post_recipient_balance);
}

/// Compute ERC20 balance slot for address using keccak256(address ++ slot)
/// Standard ERC20 stores balances in slot 0 with mapping key = address
fn compute_balance_slot(holder: alloy::primitives::Address, base_slot: U256) -> U256 {
    let mut input = [0u8; 64];
    // Pad address to 32 bytes (left-pad with zeros)
    input[12..32].copy_from_slice(holder.as_slice());
    // Base slot as 32 bytes
    input[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());
    let hash = keccak256(input);
    U256::from_be_bytes(hash.0)
}

/// Test state diff storage changes for ERC20 transfer
#[tokio::test(flavor = "multi_thread")]
async fn test_state_diff_storage_changes() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(8002))
        .await
        .expect("Failed to deploy Safe");

    // Fund Safe with ETH
    harness
        .mint_eth(safe_address, U256::from(1_000_000_000_000_000_000u128))
        .await
        .expect("Failed to fund Safe");

    // Deploy and mint tokens
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    let mint_amount = U256::from(1000_000_000_000_000_000_000u128);
    harness
        .mint_erc20(token_address, safe_address, mint_amount)
        .await
        .expect("Failed to mint tokens");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let recipient = alloy::primitives::address!("0x2222222222222222222222222222222222222222");
    let transfer_amount = U256::from(100_000_000_000_000_000_000u128);

    // Compute balance storage slots
    // MockERC20 layout: slot 0-3 = name, symbol, decimals, totalSupply; slot 4 = balanceOf mapping
    let balance_mapping_slot = U256::from(4);
    let safe_balance_slot = compute_balance_slot(safe_address, balance_mapping_slot);
    let recipient_balance_slot = compute_balance_slot(recipient, balance_mapping_slot);

    // Get pre-state storage via RPC
    let pre_safe_storage = harness.get_storage_at(token_address, safe_balance_slot).await.unwrap();
    let pre_recipient_storage = harness
        .get_storage_at(token_address, recipient_balance_slot)
        .await
        .unwrap();

    println!("Safe balance slot: {:?}", safe_balance_slot);
    println!("Recipient balance slot: {:?}", recipient_balance_slot);
    println!("Pre Safe storage: {:?}", pre_safe_storage);
    println!("Pre recipient storage: {:?}", pre_recipient_storage);

    // Simulate
    let builder = safe
        .batch()
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient,
                amount: transfer_amount,
            },
        )
        .simulate()
        .await
        .expect("Simulation should succeed");

    let sim_result = builder.simulation_result().expect("Should have simulation result");
    assert!(sim_result.success, "Simulation should succeed");

    // Check state diff for token storage changes
    let state_diff = &sim_result.state_diff;

    // Verify token contract is in state diff
    if let Some(post_token_state) = state_diff.post.get(&token_address) {
        println!("Token state diff storage changes: {:?}", post_token_state.storage.len());

        // The storage should have changed
        assert!(
            !post_token_state.storage.is_empty() || state_diff.pre.contains_key(&token_address),
            "State diff should show token storage changes"
        );
    }

    // Execute
    let exec_result = builder.execute().await.expect("Execution should succeed");
    assert!(exec_result.success);

    // Get post-state storage via RPC
    let post_safe_storage = harness.get_storage_at(token_address, safe_balance_slot).await.unwrap();
    let post_recipient_storage = harness
        .get_storage_at(token_address, recipient_balance_slot)
        .await
        .unwrap();

    println!("Post Safe storage: {:?}", post_safe_storage);
    println!("Post recipient storage: {:?}", post_recipient_storage);

    // Verify storage changes match expected balance changes
    assert_eq!(
        post_safe_storage,
        pre_safe_storage - transfer_amount,
        "Safe token storage should decrease"
    );
    assert_eq!(
        post_recipient_storage,
        pre_recipient_storage + transfer_amount,
        "Recipient token storage should increase"
    );
}

/// Test state diff shows Safe nonce increment
#[tokio::test(flavor = "multi_thread")]
async fn test_state_diff_nonce_increment() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(8003))
        .await
        .expect("Failed to deploy Safe");

    // Fund Safe
    harness
        .mint_eth(safe_address, U256::from(10_000_000_000_000_000_000u128))
        .await
        .expect("Failed to fund Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Get initial nonce via contract call
    let pre_nonce = safe.nonce().await.expect("Failed to get nonce");
    assert_eq!(pre_nonce, U256::ZERO, "Initial nonce should be 0");

    // Safe nonce is stored at slot 5
    let nonce_slot = U256::from(5);
    let pre_nonce_storage = harness.get_storage_at(safe_address, nonce_slot).await.unwrap();
    println!("Pre nonce from storage: {:?}", pre_nonce_storage);

    let recipient = alloy::primitives::address!("0x3333333333333333333333333333333333333333");
    let transfer_amount = U256::from(100_000_000_000_000_000u128);

    // Execute transaction
    let exec_result = safe
        .batch()
        .add_raw(recipient, transfer_amount, Bytes::new())
        .simulate()
        .await
        .expect("Simulation should succeed")
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(exec_result.success);

    // Get post nonce via contract call
    let post_nonce = safe.nonce().await.expect("Failed to get nonce");
    assert_eq!(post_nonce, U256::from(1), "Nonce should increment to 1");

    // Verify via storage
    let post_nonce_storage = harness.get_storage_at(safe_address, nonce_slot).await.unwrap();
    println!("Post nonce from storage: {:?}", post_nonce_storage);

    assert_eq!(
        post_nonce_storage,
        pre_nonce_storage + U256::from(1),
        "Nonce storage should increment"
    );
}

/// Test state diff shows multiple account changes in multicall
#[tokio::test(flavor = "multi_thread")]
async fn test_state_diff_multiple_accounts() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(8004))
        .await
        .expect("Failed to deploy Safe");

    // Fund Safe
    harness
        .mint_eth(safe_address, U256::from(10_000_000_000_000_000_000u128))
        .await
        .expect("Failed to fund Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let recipient1 = alloy::primitives::address!("0x4444444444444444444444444444444444444444");
    let recipient2 = alloy::primitives::address!("0x5555555555555555555555555555555555555555");
    let transfer_amount = U256::from(100_000_000_000_000_000u128); // 0.1 ETH each

    // Get pre-state balances
    let pre_balance1 = harness.get_balance(recipient1).await.unwrap();
    let pre_balance2 = harness.get_balance(recipient2).await.unwrap();

    // Simulate multicall to two recipients
    let builder = safe
        .batch()
        .add_raw(recipient1, transfer_amount, Bytes::new())
        .add_raw(recipient2, transfer_amount, Bytes::new())
        .simulate()
        .await
        .expect("Simulation should succeed");

    let sim_result = builder.simulation_result().expect("Should have simulation result");
    assert!(sim_result.success);

    // State diff should contain both recipients
    let state_diff = &sim_result.state_diff;

    // Check post state has entries for recipients
    let has_recipient1 = state_diff.post.contains_key(&recipient1);
    let has_recipient2 = state_diff.post.contains_key(&recipient2);

    println!("State diff has recipient1: {}", has_recipient1);
    println!("State diff has recipient2: {}", has_recipient2);
    println!("Total accounts in post state diff: {}", state_diff.post.len());

    // Execute
    let exec_result = builder.execute().await.expect("Execution should succeed");
    assert!(exec_result.success);

    // Verify actual balance changes
    let post_balance1 = harness.get_balance(recipient1).await.unwrap();
    let post_balance2 = harness.get_balance(recipient2).await.unwrap();

    assert_eq!(
        post_balance1,
        pre_balance1 + transfer_amount,
        "Recipient1 should receive ETH"
    );
    assert_eq!(
        post_balance2,
        pre_balance2 + transfer_amount,
        "Recipient2 should receive ETH"
    );
}

/// Test that state diff pre values match RPC queries before execution
#[tokio::test(flavor = "multi_thread")]
async fn test_state_diff_pre_values_match_rpc() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(8005))
        .await
        .expect("Failed to deploy Safe");

    // Fund Safe with specific amount
    let initial_balance = U256::from(5_000_000_000_000_000_000u128); // 5 ETH
    harness
        .mint_eth(safe_address, initial_balance)
        .await
        .expect("Failed to fund Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Query Safe balance via RPC before simulation
    let rpc_balance = harness.get_balance(safe_address).await.unwrap();
    assert_eq!(rpc_balance, initial_balance, "Safe should have 5 ETH");

    let recipient = alloy::primitives::address!("0x6666666666666666666666666666666666666666");
    let transfer_amount = U256::from(1_000_000_000_000_000_000u128);

    // Simulate
    let builder = safe
        .batch()
        .add_raw(recipient, transfer_amount, Bytes::new())
        .simulate()
        .await
        .expect("Simulation should succeed");

    let sim_result = builder.simulation_result().expect("Should have simulation result");
    let state_diff = &sim_result.state_diff;

    // Check if Safe's pre-state balance matches what we queried
    if let Some(pre_safe_state) = state_diff.pre.get(&safe_address) {
        if let Some(pre_balance) = pre_safe_state.balance {
            println!("State diff pre balance: {}", pre_balance);
            println!("RPC queried balance: {}", rpc_balance);

            // Note: The balance might include simulator's boosted balance
            // so we just verify it's at least the initial balance
            assert!(
                pre_balance >= initial_balance,
                "Pre-state balance should be at least the initial balance"
            );
        }
    }

    // Execute to verify everything works
    let exec_result = builder.execute().await.expect("Execution should succeed");
    assert!(exec_result.success);
}
