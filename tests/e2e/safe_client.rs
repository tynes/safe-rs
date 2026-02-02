//! Safe client construction and query method tests

use alloy::primitives::{address, U256};

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::{Account, ChainConfig, Safe};

// ============================================================================
// Safe Client Construction Tests
// ============================================================================

/// Test Safe::new() with explicit ChainConfig
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_new_with_explicit_config() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // First deploy a Safe
    let salt_nonce = U256::from(3001);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let config = ChainConfig::new(1); // Mainnet

    let safe = Safe::new(
        harness.provider.clone(),
        harness.signer.clone(),
        safe_address,
        config,
    );

    assert_eq!(safe.address(), safe_address);
    assert_eq!(safe.config().chain_id, 1);
}

/// Test Safe::connect() auto-detects chain ID
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_connect_auto_detects_chain() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe
    let salt_nonce = U256::from(3002);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = Safe::connect(harness.provider.clone(), harness.signer.clone(), safe_address)
        .await
        .expect("Failed to connect");

    // Should detect mainnet chain ID (1) from forked Anvil
    assert_eq!(safe.address(), safe_address);
    assert_eq!(safe.config().chain_id, 1);
}

/// Test Safe with debug output directory
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_with_debug_output_dir() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe
    let salt_nonce = U256::from(3003);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

    let safe = Safe::connect(harness.provider.clone(), harness.signer.clone(), safe_address)
        .await
        .expect("Failed to connect")
        .with_debug_output_dir(temp_dir.path());

    // Verify debug output dir is set
    assert_eq!(safe.debug_output_dir(), Some(temp_dir.path()));
}

// ============================================================================
// Safe Query Tests
// ============================================================================

/// Test threshold() returns correct value
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_threshold_returns_correct_value() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe with threshold 1
    let salt_nonce = U256::from(3004);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let threshold = safe.threshold().await.expect("Failed to get threshold");
    assert_eq!(threshold, 1);
}

/// Test owners() returns all owners
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_owners_returns_all_owners() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe with single owner
    let salt_nonce = U256::from(3005);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let owners = safe.owners().await.expect("Failed to get owners");
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0], owner);
}

/// Test owners() with multiple owners
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_owners_returns_multiple_owners() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner1 = harness.signer_address();
    let owner2 = address!("0x1111111111111111111111111111111111111111");

    // Deploy a Safe with two owners
    let salt_nonce = U256::from(3006);
    let safe_address = harness
        .deploy_safe(vec![owner1, owner2], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let owners = safe.owners().await.expect("Failed to get owners");
    assert_eq!(owners.len(), 2);
    assert!(owners.contains(&owner1));
    assert!(owners.contains(&owner2));
}

/// Test is_owner() returns true for owner
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_is_owner_true_for_owner() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe
    let salt_nonce = U256::from(3007);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let is_owner = safe.is_owner(owner).await.expect("Failed to check is_owner");
    assert!(is_owner);
}

/// Test is_owner() returns false for non-owner
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_is_owner_false_for_non_owner() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();
    let non_owner = address!("0x9999999999999999999999999999999999999999");

    // Deploy a Safe with just one owner
    let salt_nonce = U256::from(3008);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let is_owner = safe
        .is_owner(non_owner)
        .await
        .expect("Failed to check is_owner");
    assert!(!is_owner);
}

/// Test verify_single_owner() succeeds when signer is owner and threshold is 1
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_verify_single_owner_succeeds() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe with threshold 1
    let salt_nonce = U256::from(3009);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Should succeed when signer is owner and threshold is 1
    safe.verify_single_owner()
        .await
        .expect("verify_single_owner should succeed");
}

/// Test verify_single_owner() fails when threshold > 1
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_verify_single_owner_fails_high_threshold() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner1 = harness.signer_address();
    let owner2 = address!("0x2222222222222222222222222222222222222222");

    // Deploy a Safe with threshold 2
    let salt_nonce = U256::from(3010);
    let safe_address = harness
        .deploy_safe(vec![owner1, owner2], 2, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Should fail because threshold is 2
    let result = safe.verify_single_owner().await;
    assert!(result.is_err());
    match result {
        Err(safe_rs::Error::InvalidThreshold { threshold }) => {
            assert_eq!(threshold, 2);
        }
        other => panic!("Expected InvalidThreshold error, got: {:?}", other),
    }
}

/// Test verify_single_owner() fails when signer is not owner
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_verify_single_owner_fails_not_owner() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let different_owner = address!("0x3333333333333333333333333333333333333333");

    // Deploy a Safe with a different owner (not the signer)
    let salt_nonce = U256::from(3011);
    let safe_address = harness
        .deploy_safe(vec![different_owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    // Should fail because signer is not an owner
    let result = safe.verify_single_owner().await;
    assert!(result.is_err());
    match result {
        Err(safe_rs::Error::NotOwner { signer, safe: safe_addr }) => {
            assert_eq!(signer, harness.signer_address());
            assert_eq!(safe_addr, safe_address);
        }
        other => panic!("Expected NotOwner error, got: {:?}", other),
    }
}

// ============================================================================
// is_safe() Function Tests
// ============================================================================

/// Test is_safe() returns true for deployed Safe
#[tokio::test(flavor = "multi_thread")]
async fn test_is_safe_returns_true_for_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe
    let salt_nonce = U256::from(3012);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let is_safe = safe_rs::is_safe(&harness.provider, safe_address)
        .await
        .expect("Failed to check is_safe");
    assert!(is_safe);
}

/// Test is_safe() returns false for EOA
#[tokio::test(flavor = "multi_thread")]
async fn test_is_safe_returns_false_for_eoa() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let eoa_address = harness.signer_address();

    let is_safe = safe_rs::is_safe(&harness.provider, eoa_address)
        .await
        .expect("Failed to check is_safe");
    assert!(!is_safe);
}

/// Test is_safe() returns false for random address with no code
#[tokio::test(flavor = "multi_thread")]
async fn test_is_safe_returns_false_for_empty_address() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let random_address = address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    let is_safe = safe_rs::is_safe(&harness.provider, random_address)
        .await
        .expect("Failed to check is_safe");
    assert!(!is_safe);
}

// ============================================================================
// Safe Nonce Tests
// ============================================================================

/// Test nonce() returns 0 for fresh Safe
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_nonce_returns_zero_for_fresh_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a fresh Safe
    let salt_nonce = U256::from(3013);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    let safe = harness
        .safe_client(safe_address)
        .await
        .expect("Failed to create Safe client");

    let nonce = safe.nonce().await.expect("Failed to get nonce");
    assert_eq!(nonce, U256::ZERO);
}
