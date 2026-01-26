//! is_safe E2E tests

use alloy::primitives::U256;

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::is_safe;

/// Test that is_safe returns true for a deployed Safe v1.4.1
#[tokio::test]
async fn test_is_safe_returns_true_for_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a new Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(5001))
        .await
        .expect("Failed to deploy Safe");

    // Verify is_safe returns true
    let result = is_safe(&harness.provider, safe_address)
        .await
        .expect("is_safe call failed");

    assert!(result, "is_safe should return true for a deployed Safe");
}

/// Test that is_safe returns false for a non-Safe contract (ERC20)
#[tokio::test]
async fn test_is_safe_returns_false_for_erc20() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Deploy a MockERC20 token
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    // Verify is_safe returns false
    let result = is_safe(&harness.provider, token_address)
        .await
        .expect("is_safe call failed");

    assert!(!result, "is_safe should return false for an ERC20 contract");
}

/// Test that is_safe returns false for an EOA (no code)
#[tokio::test]
async fn test_is_safe_returns_false_for_eoa() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa_address = harness.signer_address();

    // Verify is_safe returns false for EOA
    let result = is_safe(&harness.provider, eoa_address)
        .await
        .expect("is_safe call failed");

    assert!(!result, "is_safe should return false for an EOA");
}

/// Test that is_safe returns false for an address with no code
#[tokio::test]
async fn test_is_safe_returns_false_for_empty_address() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    // Random address with no code deployed
    let empty_address = alloy::primitives::address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    // Verify is_safe returns false
    let result = is_safe(&harness.provider, empty_address)
        .await
        .expect("is_safe call failed");

    assert!(!result, "is_safe should return false for an empty address");
}
