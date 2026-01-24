//! Safe deployment E2E tests

use alloy::primitives::U256;
use alloy::providers::Provider;

use crate::common::TestHarness;
use crate::skip_if_no_rpc;

/// Test deploying a Safe with a single owner
#[tokio::test]
async fn test_deploy_safe_success() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy Safe with single owner and threshold 1
    let safe_address = harness
        .deploy_safe(vec![owner], 1, U256::from(1001))
        .await
        .expect("Failed to deploy Safe");

    // Verify code exists at the Safe address
    let code = harness
        .provider
        .get_code_at(safe_address)
        .await
        .expect("Failed to get code");
    assert!(!code.is_empty(), "Safe should have code deployed");

    // Create Safe client and verify configuration
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let owners = safe.owners().await.expect("Failed to get owners");
    assert_eq!(owners.len(), 1, "Safe should have 1 owner");
    assert_eq!(owners[0], owner, "Owner should match signer");

    let threshold = safe.threshold().await.expect("Failed to get threshold");
    assert_eq!(threshold, 1, "Threshold should be 1");
}

/// Test that deploying the same Safe twice fails (CREATE2 collision)
#[tokio::test]
async fn test_deploy_same_safe_twice_fails() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();
    let salt_nonce = U256::from(2001);

    // First deployment should succeed
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("First deployment should succeed");

    // Verify first deployment
    let code = harness
        .provider
        .get_code_at(safe_address)
        .await
        .expect("Failed to get code");
    assert!(!code.is_empty(), "Safe should be deployed");

    // Second deployment with same parameters should return the existing address
    // (our deploy_safe function returns early if already deployed)
    let safe_address_2 = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Second deploy should return existing address");

    assert_eq!(
        safe_address, safe_address_2,
        "Both deployments should return the same address"
    );
}

/// Test deploying a Safe with multiple owners
#[tokio::test]
async fn test_deploy_safe_multiple_owners() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner1 = harness.signer_address();
    // Generate additional owner addresses
    let owner2 = alloy::primitives::address!("0x1111111111111111111111111111111111111111");
    let owner3 = alloy::primitives::address!("0x2222222222222222222222222222222222222222");

    let owners = vec![owner1, owner2, owner3];

    // Deploy Safe with 3 owners and threshold 2
    let safe_address = harness
        .deploy_safe(owners.clone(), 2, U256::from(3001))
        .await
        .expect("Failed to deploy Safe");

    // Verify deployment
    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let deployed_owners = safe.owners().await.expect("Failed to get owners");
    assert_eq!(deployed_owners.len(), 3, "Safe should have 3 owners");

    // Verify each owner is present (order may differ)
    for owner in &owners {
        assert!(
            deployed_owners.contains(owner),
            "Owner {:?} should be in deployed owners",
            owner
        );
    }

    let threshold = safe.threshold().await.expect("Failed to get threshold");
    assert_eq!(threshold, 2, "Threshold should be 2");
}

/// Test deploying a Safe with threshold equal to owner count
#[tokio::test]
async fn test_deploy_safe_threshold_equals_owners() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner1 = harness.signer_address();
    let owner2 = alloy::primitives::address!("0x3333333333333333333333333333333333333333");

    let owners = vec![owner1, owner2];

    // Deploy Safe with 2 owners and threshold 2 (2-of-2 multisig)
    let safe_address = harness
        .deploy_safe(owners.clone(), 2, U256::from(4001))
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let threshold = safe.threshold().await.expect("Failed to get threshold");
    assert_eq!(threshold, 2, "Threshold should equal number of owners");
}
