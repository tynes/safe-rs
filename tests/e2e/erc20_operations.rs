//! ERC20 operations E2E tests

use alloy::primitives::U256;

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::{Account, IERC20};

/// Test deploying a MockERC20 token and minting to Safe
#[tokio::test(flavor = "multi_thread")]
async fn test_deploy_mock_erc20() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(6001))
        .await
        .expect("Failed to deploy Safe");

    // Deploy MockERC20 and mint using the helper
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    // Mint tokens to Safe
    let mint_amount = U256::from(1_000_000_000_000_000_000_000u128); // 1000 tokens
    harness
        .mint_erc20(token_address, safe_address, mint_amount)
        .await
        .expect("Failed to mint tokens");

    // Verify Safe balance using IERC20 interface
    let token = IERC20::new(token_address, &harness.provider);
    let balance = token.balanceOf(safe_address).call().await.expect("Failed to get balance");

    assert_eq!(balance, mint_amount, "Safe should have 1000 tokens");
}

/// Test ERC20 transfer via Safe
#[tokio::test(flavor = "multi_thread")]
async fn test_erc20_transfer_via_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(6002))
        .await
        .expect("Failed to deploy Safe");

    // Fund Safe with ETH for gas
    harness
        .mint_eth(safe_address, U256::from(1_000_000_000_000_000_000u128))
        .await
        .expect("Failed to fund Safe");

    // Deploy and mint tokens
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    let mint_amount = U256::from(1000_000_000_000_000_000_000u128); // 1000 tokens
    harness
        .mint_erc20(token_address, safe_address, mint_amount)
        .await
        .expect("Failed to mint tokens");

    // Create Safe client
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Transfer tokens from Safe to recipient
    let recipient = alloy::primitives::address!("0x9999999999999999999999999999999999999999");
    let transfer_amount = U256::from(100_000_000_000_000_000_000u128); // 100 tokens

    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };

    let result = safe
        .batch()
        .add_typed(token_address, transfer_call)
        .simulate()
        .await
        .expect("Simulation should succeed")
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.success, "Transaction should succeed");

    // Verify balances
    let token = IERC20::new(token_address, &harness.provider);
    let safe_balance = token.balanceOf(safe_address).call().await.expect("Failed to get Safe balance");
    let recipient_balance = token.balanceOf(recipient).call().await.expect("Failed to get recipient balance");

    assert_eq!(
        safe_balance,
        mint_amount - transfer_amount,
        "Safe should have 900 tokens"
    );
    assert_eq!(
        recipient_balance, transfer_amount,
        "Recipient should have 100 tokens"
    );
}

/// Test ERC20 approve via Safe
#[tokio::test(flavor = "multi_thread")]
async fn test_erc20_approve() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(6003))
        .await
        .expect("Failed to deploy Safe");

    // Fund Safe with ETH for gas
    harness
        .mint_eth(safe_address, U256::from(1_000_000_000_000_000_000u128))
        .await
        .expect("Failed to fund Safe");

    // Deploy token
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    // Create Safe client
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Approve spender
    let spender = alloy::primitives::address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let approve_amount = U256::from(500_000_000_000_000_000_000u128); // 500 tokens

    let approve_call = IERC20::approveCall {
        spender,
        amount: approve_amount,
    };

    let result = safe
        .batch()
        .add_typed(token_address, approve_call)
        .simulate()
        .await
        .expect("Simulation should succeed")
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.success, "Transaction should succeed");

    // Verify allowance
    let token = IERC20::new(token_address, &harness.provider);
    let allowance = token.allowance(safe_address, spender).call().await.expect("Failed to get allowance");

    assert_eq!(allowance, approve_amount, "Allowance should be 500 tokens");
}

/// Test batch ERC20 operations in one multicall
#[tokio::test(flavor = "multi_thread")]
async fn test_batch_erc20_operations() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(6004))
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

    let mint_amount = U256::from(1000_000_000_000_000_000_000u128); // 1000 tokens
    harness
        .mint_erc20(token_address, safe_address, mint_amount)
        .await
        .expect("Failed to mint tokens");

    // Create Safe client
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Multiple recipients
    let recipient1 = alloy::primitives::address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    let recipient2 = alloy::primitives::address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    let spender = alloy::primitives::address!("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");

    let transfer_amount = U256::from(50_000_000_000_000_000_000u128); // 50 tokens each
    let approve_amount = U256::MAX;

    // Execute batch: transfer to recipient1, transfer to recipient2, approve spender
    let result = safe
        .batch()
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient1,
                amount: transfer_amount,
            },
        )
        .add_typed(
            token_address,
            IERC20::transferCall {
                to: recipient2,
                amount: transfer_amount,
            },
        )
        .add_typed(
            token_address,
            IERC20::approveCall {
                spender,
                amount: approve_amount,
            },
        )
        .simulate()
        .await
        .expect("Simulation should succeed")
        .execute()
        .await
        .expect("Execution should succeed");

    assert!(result.success, "Transaction should succeed");

    // Verify all operations
    let token = IERC20::new(token_address, &harness.provider);
    let safe_balance = token.balanceOf(safe_address).call().await.unwrap();
    let balance1 = token.balanceOf(recipient1).call().await.unwrap();
    let balance2 = token.balanceOf(recipient2).call().await.unwrap();
    let allowance = token.allowance(safe_address, spender).call().await.unwrap();

    assert_eq!(
        safe_balance,
        mint_amount - transfer_amount - transfer_amount,
        "Safe should have 900 tokens"
    );
    assert_eq!(balance1, transfer_amount, "Recipient1 should have 50 tokens");
    assert_eq!(balance2, transfer_amount, "Recipient2 should have 50 tokens");
    assert_eq!(allowance, approve_amount, "Spender should have max allowance");
}
