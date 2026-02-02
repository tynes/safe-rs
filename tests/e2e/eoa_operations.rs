//! EOA operations E2E tests

use alloy::primitives::{address, U256};
use alloy::providers::Provider;
use std::collections::HashSet;

use crate::common::{MockERC20, TestHarness};
use crate::skip_if_no_rpc;
use safe_rs::{Account, Call, CallBuilder, ChainConfig, Eoa, Error, IERC20};

// ============================================================================
// Eoa Client Construction Tests
// ============================================================================

/// Test Eoa::new() with explicit ChainConfig
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_new_with_explicit_config() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let config = ChainConfig::new(1); // Mainnet

    let eoa = Eoa::new(harness.provider.clone(), harness.signer.clone(), config);

    assert_eq!(eoa.address(), harness.signer_address());
    assert_eq!(eoa.config().chain_id, 1);
}

/// Test Eoa::connect() auto-detects chain ID
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_connect_auto_detects_chain() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Should detect mainnet chain ID (1) from forked Anvil
    assert_eq!(eoa.address(), harness.signer_address());
    assert_eq!(eoa.config().chain_id, 1);
}

/// Test nonce() returns correct value
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_nonce_returns_current_nonce() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Get nonce from the provider directly
    let expected_nonce = harness
        .provider
        .get_transaction_count(harness.signer_address())
        .await
        .expect("Failed to get nonce");

    let actual_nonce = eoa.nonce().await.expect("Failed to get EOA nonce");

    assert_eq!(actual_nonce, expected_nonce);
}

// ============================================================================
// Builder Methods Tests
// ============================================================================

/// Test call_count() increments correctly
#[tokio::test(flavor = "multi_thread")]
async fn test_builder_call_count() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    let recipient = address!("0x9999999999999999999999999999999999999999");

    let builder = eoa.batch();
    assert_eq!(builder.call_count(), 0);

    let builder = builder.add_raw(recipient, U256::from(1000), vec![]);
    assert_eq!(builder.call_count(), 1);

    let builder = builder.add_raw(recipient, U256::from(2000), vec![]);
    assert_eq!(builder.call_count(), 2);

    let builder = builder.add_raw(recipient, U256::from(3000), vec![]);
    assert_eq!(builder.call_count(), 3);
}

/// Test add_typed() adds call correctly
#[tokio::test(flavor = "multi_thread")]
async fn test_builder_add_typed() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    let token_address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
    let recipient = address!("0x9999999999999999999999999999999999999999");

    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: U256::from(1000),
    };

    let builder = eoa.batch().add_typed(token_address, transfer_call);

    assert_eq!(builder.call_count(), 1);
}

/// Test simulation_results() is None before simulate()
#[tokio::test(flavor = "multi_thread")]
async fn test_builder_simulation_results_none_before_simulate() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    let recipient = address!("0x9999999999999999999999999999999999999999");

    let builder = eoa.batch().add_raw(recipient, U256::from(1000), vec![]);

    assert!(builder.simulation_results().is_none());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

/// Test simulate() returns Error::NoCalls for empty batch
#[tokio::test(flavor = "multi_thread")]
async fn test_simulate_empty_batch_returns_error() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    let result = eoa.batch().simulate().await;

    assert!(matches!(result, Err(Error::NoCalls)));
}

/// Test execute() returns Error::NoCalls for empty batch
#[tokio::test(flavor = "multi_thread")]
async fn test_execute_empty_batch_returns_error() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    let result = eoa.batch().execute().await;

    assert!(matches!(result, Err(Error::NoCalls)));
}

/// Test simulate() rejects DelegateCall operations
#[tokio::test(flavor = "multi_thread")]
async fn test_simulate_rejects_delegatecall() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    let target = address!("0x1234567890123456789012345678901234567890");
    let delegate_call = Call::delegate_call(target, vec![0x12, 0x34]);

    let result = eoa.batch().add(delegate_call).simulate().await;

    assert!(matches!(result, Err(Error::UnsupportedEoaOperation { .. })));
}

/// Test execute() rejects DelegateCall operations
#[tokio::test(flavor = "multi_thread")]
async fn test_execute_rejects_delegatecall() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    let target = address!("0x1234567890123456789012345678901234567890");
    let delegate_call = Call::delegate_call(target, vec![0x12, 0x34]);

    let result = eoa.batch().add(delegate_call).execute().await;

    assert!(matches!(result, Err(Error::UnsupportedEoaOperation { .. })));
}

// ============================================================================
// Single Transaction Execution Tests
// ============================================================================

/// Test executing a single ETH transfer and verify balance change
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_single_eth_transfer() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let transfer_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    // Get initial balance
    let initial_balance = harness
        .get_balance(recipient)
        .await
        .expect("Failed to get initial balance");

    // Execute ETH transfer
    let result = eoa
        .batch()
        .add_raw(recipient, transfer_amount, vec![])
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.all_succeeded());
    assert_eq!(result.results.len(), 1);
    assert!(result.results[0].success);

    // Verify balance change
    let final_balance = harness
        .get_balance(recipient)
        .await
        .expect("Failed to get final balance");

    assert_eq!(final_balance, initial_balance + transfer_amount);
}

/// Test executing a single ERC20 transfer via add_typed()
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_single_erc20_transfer() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Deploy MockERC20
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    // Mint tokens to EOA
    let mint_amount = U256::from(1000_000_000_000_000_000_000u128); // 1000 tokens
    harness
        .mint_erc20(token_address, eoa.address(), mint_amount)
        .await
        .expect("Failed to mint tokens");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let transfer_amount = U256::from(100_000_000_000_000_000_000u128); // 100 tokens

    // Execute ERC20 transfer
    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };

    let result = eoa
        .batch()
        .add_typed(token_address, transfer_call)
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.all_succeeded());

    // Verify balance change
    let token = MockERC20::new(token_address, &harness.provider);
    let recipient_balance = token
        .balanceOf(recipient)
        .call()
        .await
        .expect("Failed to get balance");

    assert_eq!(recipient_balance, transfer_amount);
}

// ============================================================================
// CRITICAL: Nonce Handling Tests
// ============================================================================

/// Test that nonce increments by N after N transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_nonce_increments_per_transaction() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let initial_nonce = eoa.nonce().await.expect("Failed to get initial nonce");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let transfer_amount = U256::from(1000); // Small amount

    // Execute batch of 3 transactions
    let result = eoa
        .batch()
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.all_succeeded());
    assert_eq!(result.results.len(), 3);

    // Verify nonce incremented by 3
    let final_nonce = eoa.nonce().await.expect("Failed to get final nonce");
    assert_eq!(final_nonce, initial_nonce + U256::from(3));
}

/// Test that all tx hashes are unique (proves no nonce collision)
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_batch_unique_tx_hashes() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let transfer_amount = U256::from(1000); // Small amount

    // Execute batch of 5 transactions
    let result = eoa
        .batch()
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.all_succeeded());
    assert_eq!(result.results.len(), 5);

    // Verify all tx hashes are unique
    let hashes = result.tx_hashes();
    let unique_hashes: HashSet<_> = hashes.iter().collect();
    assert_eq!(
        unique_hashes.len(),
        hashes.len(),
        "All transaction hashes should be unique"
    );
}

/// Test that nonce continues correctly across multiple batches
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_consecutive_batches_nonce_continuity() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let initial_nonce = eoa.nonce().await.expect("Failed to get initial nonce");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let transfer_amount = U256::from(1000);

    // First batch: 2 transactions
    let result1 = eoa
        .batch()
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .execute()
        .await
        .expect("First batch should succeed");
    assert!(result1.all_succeeded());

    let nonce_after_first = eoa.nonce().await.expect("Failed to get nonce");
    assert_eq!(nonce_after_first, initial_nonce + U256::from(2));

    // Second batch: 3 transactions
    let result2 = eoa
        .batch()
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .add_raw(recipient, transfer_amount, vec![])
        .execute()
        .await
        .expect("Second batch should succeed");
    assert!(result2.all_succeeded());

    let nonce_after_second = eoa.nonce().await.expect("Failed to get nonce");
    assert_eq!(nonce_after_second, initial_nonce + U256::from(5));

    // All hashes from both batches should be unique
    let mut all_hashes: HashSet<_> = result1.tx_hashes().into_iter().collect();
    for hash in result2.tx_hashes() {
        assert!(
            all_hashes.insert(hash),
            "Transaction hash collision across batches"
        );
    }
}

// ============================================================================
// continue_on_failure Behavior Tests
// ============================================================================

/// Test default behavior stops after first failure
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_stops_on_first_failure_by_default() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA with some ETH (but not enough for all transfers)
    let fund_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    // First call should succeed, second should fail (impossible transfer to a contract that will revert)
    let recipient = address!("0x9999999999999999999999999999999999999999");
    let good_transfer = U256::from(1000); // Small amount that should succeed

    // Deploy a token without giving EOA any balance - transfer will fail
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    // Create a transfer call that will revert (no token balance)
    let failing_transfer_call = IERC20::transferCall {
        to: recipient,
        amount: U256::from(1000),
    };

    let result = eoa
        .batch()
        .add_raw(recipient, good_transfer, vec![]) // Should succeed
        .add_typed(token_address, failing_transfer_call) // Should fail
        .with_gas_limit(100_000) // Skip gas estimation for reverting call
        .add_raw(recipient, good_transfer, vec![]) // Would succeed, but shouldn't execute
        .execute()
        .await
        .expect("Execution should return results");

    assert!(!result.all_succeeded());
    assert_eq!(result.first_failure, Some(1));
    // With stop_on_failure (default), only 2 transactions should be attempted
    assert_eq!(result.results.len(), 2);
}

/// Test continue_on_failure() flag works
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_continue_on_failure_executes_all() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let good_transfer = U256::from(1000);

    // Deploy a token without giving EOA any balance - transfer will fail
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    let failing_transfer_call = IERC20::transferCall {
        to: recipient,
        amount: U256::from(1000),
    };

    let result = eoa
        .batch()
        .add_raw(recipient, good_transfer, vec![]) // Should succeed
        .add_typed(token_address, failing_transfer_call) // Should fail
        .with_gas_limit(100_000) // Skip gas estimation for reverting call
        .add_raw(recipient, good_transfer, vec![]) // Should succeed
        .continue_on_failure()
        .execute()
        .await
        .expect("Execution should return results");

    assert!(!result.all_succeeded());
    assert_eq!(result.first_failure, Some(1));
    // With continue_on_failure, all 3 transactions should be attempted
    assert_eq!(result.results.len(), 3);
    assert!(result.results[0].success);
    assert!(!result.results[1].success);
    assert!(result.results[2].success);
}

// ============================================================================
// Simulation Tests
// ============================================================================

/// Test simulate() populates simulation_results
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_simulate_populates_results() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let recipient = address!("0x9999999999999999999999999999999999999999");

    let builder = eoa
        .batch()
        .add_raw(recipient, U256::from(1000), vec![])
        .add_raw(recipient, U256::from(2000), vec![])
        .simulate()
        .await
        .expect("Simulation should succeed");

    let sim_results = builder.simulation_results();
    assert!(sim_results.is_some());

    let results = sim_results.unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].success);
    assert!(results[1].success);
    assert!(results[0].gas_used > 0);
    assert!(results[1].gas_used > 0);
}

/// Test total_gas_used() sums all simulation results
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_total_gas_used() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let recipient = address!("0x9999999999999999999999999999999999999999");

    // Before simulation, total_gas_used should be None
    let builder = eoa
        .batch()
        .add_raw(recipient, U256::from(1000), vec![])
        .add_raw(recipient, U256::from(2000), vec![]);

    assert!(builder.total_gas_used().is_none());

    // After simulation, total_gas_used should be the sum
    let builder = builder.simulate().await.expect("Simulation should succeed");

    let total_gas = builder.total_gas_used();
    assert!(total_gas.is_some());

    let results = builder.simulation_results().unwrap();
    let expected_total: u64 = results.iter().map(|r| r.gas_used).sum();
    assert_eq!(total_gas.unwrap(), expected_total);
}

/// Test full simulate-then-execute workflow
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_simulate_then_execute() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let transfer_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    let initial_balance = harness
        .get_balance(recipient)
        .await
        .expect("Failed to get initial balance");

    // Simulate first
    let builder = eoa
        .batch()
        .add_raw(recipient, transfer_amount, vec![])
        .simulate()
        .await
        .expect("Simulation should succeed");

    assert!(builder.simulation_results().is_some());
    assert!(builder.total_gas_used().is_some());

    // Then execute
    let result = builder.execute().await.expect("Execution should succeed");

    assert!(result.all_succeeded());

    let final_balance = harness
        .get_balance(recipient)
        .await
        .expect("Failed to get final balance");

    assert_eq!(final_balance, initial_balance + transfer_amount);
}

/// Test failed simulation returns revert info
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_simulate_failure_returns_revert_reason() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Deploy a token without giving EOA any balance
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let failing_transfer_call = IERC20::transferCall {
        to: recipient,
        amount: U256::from(1000), // EOA has no tokens, should revert
    };

    let result = eoa
        .batch()
        .add_typed(token_address, failing_transfer_call)
        .simulate()
        .await;

    assert!(result.is_err());
    match result {
        Err(Error::SimulationReverted { reason }) => {
            assert!(!reason.is_empty(), "Should include revert reason");
        }
        Ok(_) => panic!("Expected SimulationReverted error, got Ok"),
        Err(e) => panic!("Expected SimulationReverted, got different error: {}", e),
    }
}

// ============================================================================
// Mixed Operations Tests
// ============================================================================

/// Test batch with both ETH and ERC20 transfers
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_mixed_eth_and_erc20_batch() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa = Eoa::connect(harness.provider.clone(), harness.signer.clone())
        .await
        .expect("Failed to connect");

    // Fund the EOA with ETH
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
    harness
        .mint_eth(eoa.address(), fund_amount)
        .await
        .expect("Failed to fund EOA");

    // Deploy MockERC20 and mint to EOA
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    let token_mint_amount = U256::from(1000_000_000_000_000_000_000u128); // 1000 tokens
    harness
        .mint_erc20(token_address, eoa.address(), token_mint_amount)
        .await
        .expect("Failed to mint tokens");

    let eth_recipient = address!("0x8888888888888888888888888888888888888888");
    let token_recipient = address!("0x9999999999999999999999999999999999999999");
    let eth_transfer_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let token_transfer_amount = U256::from(100_000_000_000_000_000_000u128); // 100 tokens

    // Get initial balances
    let initial_eth_balance = harness
        .get_balance(eth_recipient)
        .await
        .expect("Failed to get ETH balance");

    let token = MockERC20::new(token_address, &harness.provider);
    let initial_token_balance = token
        .balanceOf(token_recipient)
        .call()
        .await
        .expect("Failed to get token balance");

    // Execute mixed batch
    let transfer_call = IERC20::transferCall {
        to: token_recipient,
        amount: token_transfer_amount,
    };

    let result = eoa
        .batch()
        .add_raw(eth_recipient, eth_transfer_amount, vec![]) // ETH transfer
        .add_typed(token_address, transfer_call) // ERC20 transfer
        .simulate()
        .await
        .expect("Simulation should succeed")
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.all_succeeded());
    assert_eq!(result.results.len(), 2);

    // Verify ETH transfer
    let final_eth_balance = harness
        .get_balance(eth_recipient)
        .await
        .expect("Failed to get final ETH balance");
    assert_eq!(
        final_eth_balance,
        initial_eth_balance + eth_transfer_amount
    );

    // Verify token transfer
    let final_token_balance = token
        .balanceOf(token_recipient)
        .call()
        .await
        .expect("Failed to get final token balance");
    assert_eq!(
        final_token_balance,
        initial_token_balance + token_transfer_amount
    );
}
