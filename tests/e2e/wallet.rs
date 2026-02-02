//! Wallet E2E tests

use alloy::primitives::U256;

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::{WalletBuilder, WalletConfig};

/// Test connecting to an existing Safe
#[tokio::test]
async fn test_wallet_connect_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // First deploy a Safe manually
    let salt_nonce = U256::from(10001);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    // Now connect to it using the fluent builder API
    let wallet = WalletBuilder::new(harness.provider.clone(), harness.signer.clone())
        .connect(safe_address)
        .await
        .expect("Failed to connect to Safe");

    assert!(wallet.is_safe(), "Wallet should be Safe");
    assert!(!wallet.is_eoa(), "Wallet should not be EOA");
    assert_eq!(
        wallet.address(),
        safe_address,
        "Safe wallet address should match deployed Safe address"
    );
    assert_eq!(
        wallet.signer_address(),
        harness.signer_address(),
        "Signer address should match"
    );
}

/// Test connecting to a Safe with config
#[tokio::test]
async fn test_wallet_connect_safe_with_config() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // First deploy a Safe manually
    let salt_nonce = U256::from(10002);
    let _safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    // Now connect with the same salt nonce - should detect the Safe
    let config = WalletConfig::new().with_salt_nonce(salt_nonce);

    let wallet = WalletBuilder::new(harness.provider.clone(), harness.signer.clone())
        .connect_with_config(config)
        .await
        .expect("Failed to connect wallet");

    assert!(wallet.is_safe(), "Wallet should be Safe when deployed");
    assert!(!wallet.is_eoa(), "Wallet should not be EOA when Safe is deployed");
    assert_eq!(
        wallet.signer_address(),
        harness.signer_address(),
        "Signer address should match"
    );
}

/// Test that connect_with_config fails when no Safe exists
#[tokio::test]
async fn test_wallet_connect_with_config_fails_when_no_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Use a unique salt nonce to ensure no Safe exists at the computed address
    let config = WalletConfig::new().with_salt_nonce(U256::from(999999));

    let result = WalletBuilder::new(harness.provider.clone(), harness.signer.clone())
        .connect_with_config(config)
        .await;

    assert!(result.is_err(), "Should fail when no Safe is deployed");
}

/// Test connecting to an EOA
#[tokio::test]
async fn test_wallet_connect_eoa() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    let wallet = WalletBuilder::new(harness.provider.clone(), harness.signer.clone())
        .connect_eoa()
        .await
        .expect("Failed to connect EOA wallet");

    assert!(wallet.is_eoa(), "Wallet should be EOA");
    assert!(!wallet.is_safe(), "Wallet should not be Safe");
    assert_eq!(
        wallet.address(),
        harness.signer_address(),
        "EOA wallet address should match signer address"
    );
    assert_eq!(
        wallet.signer_address(),
        harness.signer_address(),
        "Signer address should match"
    );
}

/// Test that deploy creates a Safe if not exists
#[tokio::test]
async fn test_wallet_deploy_creates_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Use a unique salt nonce to ensure no Safe exists
    let config = WalletConfig::new().with_salt_nonce(U256::from(20001));

    // Deploy then connect using the fluent builder API
    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());
    let address = builder
        .deploy(harness._anvil.endpoint_url(), config)
        .await
        .expect("Failed to deploy Safe");

    let wallet = builder.connect(address).await.expect("Failed to connect to Safe");

    assert!(wallet.is_safe(), "Wallet should be Safe after deployment");
    assert!(!wallet.is_eoa(), "Wallet should not be EOA");
    assert_eq!(
        wallet.signer_address(),
        harness.signer_address(),
        "Signer address should match"
    );

    // Verify the Safe is actually deployed by checking is_safe
    assert!(
        safe_rs::is_safe(&harness.provider, wallet.address())
            .await
            .expect("is_safe check failed"),
        "Deployed wallet should be a valid Safe"
    );
}

/// Test that deploy is idempotent and returns existing Safe address
#[tokio::test]
async fn test_wallet_deploy_uses_existing_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // First deploy a Safe manually
    let salt_nonce = U256::from(30001);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    // Now call deploy with the same salt nonce - should return existing address
    let config = WalletConfig::new().with_salt_nonce(salt_nonce);

    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());
    let deployed_address = builder
        .deploy(harness._anvil.endpoint_url(), config)
        .await
        .expect("Failed to deploy Safe");

    assert_eq!(
        deployed_address, safe_address,
        "Should return existing Safe address"
    );

    let wallet = builder.connect(deployed_address).await.expect("Failed to connect");
    assert!(wallet.is_safe(), "Wallet should be Safe");
}

/// Test that compute_address matches the actual deployed address
#[tokio::test]
async fn test_wallet_compute_address() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    let salt_nonce = U256::from(40001);
    let config = WalletConfig::new().with_salt_nonce(salt_nonce);

    // Compute the address first using the builder
    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());
    let computed_address = builder
        .compute_address(&config)
        .await
        .expect("Failed to compute Safe address");

    // Deploy the Safe
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    assert_eq!(
        computed_address, safe_address,
        "Computed address should match deployed address"
    );
}

/// Test WalletConfig with custom salt nonce
#[tokio::test]
async fn test_wallet_config_salt_nonce() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Two different salt nonces should produce different addresses
    let config1 = WalletConfig::new().with_salt_nonce(U256::from(50001));
    let config2 = WalletConfig::new().with_salt_nonce(U256::from(50002));

    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());

    let addr1 = builder
        .compute_address(&config1)
        .await
        .expect("Failed to compute address 1");

    let addr2 = builder
        .compute_address(&config2)
        .await
        .expect("Failed to compute address 2");

    assert_ne!(addr1, addr2, "Different salt nonces should produce different addresses");
}

/// Test WalletConfig with additional owners
#[tokio::test]
async fn test_wallet_config_additional_owners() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner2 = alloy::primitives::address!("0x1111111111111111111111111111111111111111");

    // Config with single owner (default)
    let config1 = WalletConfig::new().with_salt_nonce(U256::from(60001));

    // Config with additional owner
    let config2 = WalletConfig::new()
        .with_salt_nonce(U256::from(60001))
        .with_additional_owners(vec![owner2]);

    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());

    let addr1 = builder
        .compute_address(&config1)
        .await
        .expect("Failed to compute address 1");

    let addr2 = builder
        .compute_address(&config2)
        .await
        .expect("Failed to compute address 2");

    // Different owners should produce different addresses (even with same salt)
    assert_ne!(addr1, addr2, "Different owners should produce different addresses");
}

/// Test WalletConfig with different threshold
#[tokio::test]
async fn test_wallet_deploy_with_threshold() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner2 = alloy::primitives::address!("0x2222222222222222222222222222222222222222");

    let config = WalletConfig::new()
        .with_salt_nonce(U256::from(70001))
        .with_additional_owners(vec![owner2])
        .with_threshold(2);

    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());
    let address = builder
        .deploy(harness._anvil.endpoint_url(), config)
        .await
        .expect("Failed to deploy Safe");

    let wallet = builder.connect(address).await.expect("Failed to connect");

    assert!(wallet.is_safe(), "Wallet should be Safe");

    // Verify the Safe has correct configuration using .safe() accessor
    let safe = wallet.safe();
    let threshold = safe.threshold().await.expect("Failed to get threshold");
    assert_eq!(threshold, 2, "Threshold should be 2");

    let owners = safe.owners().await.expect("Failed to get owners");
    assert_eq!(owners.len(), 2, "Should have 2 owners");
}

/// Test that invalid threshold returns error
#[tokio::test]
async fn test_wallet_config_invalid_threshold() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Threshold of 2 with only 1 owner (signer) should fail
    let config = WalletConfig::new()
        .with_salt_nonce(U256::from(80001))
        .with_threshold(2);

    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());
    let result = builder.deploy(harness._anvil.endpoint_url(), config).await;

    match result {
        Err(err) => {
            assert!(
                err.to_string().contains("Invalid threshold"),
                "Error should mention invalid threshold: {}",
                err
            );
        }
        Ok(_) => panic!("Should fail with invalid threshold"),
    }
}

/// Test that threshold 0 returns error
#[tokio::test]
async fn test_wallet_config_zero_threshold() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    let config = WalletConfig::new()
        .with_salt_nonce(U256::from(90001))
        .with_threshold(0);

    let builder = WalletBuilder::new(harness.provider.clone(), harness.signer.clone());
    let result = builder.deploy(harness._anvil.endpoint_url(), config).await;

    assert!(result.is_err(), "Should fail with zero threshold");
}
