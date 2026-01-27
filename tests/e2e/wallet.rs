//! Wallet auto-detection E2E tests

use alloy::primitives::U256;

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::{Wallet, WalletConfig};

/// Test that Wallet::connect returns Wallet::Eoa when no Safe is deployed
#[tokio::test]
async fn test_wallet_connect_returns_eoa_when_no_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Use a unique salt nonce to ensure no Safe exists at the computed address
    let config = WalletConfig::new().with_salt_nonce(U256::from(999999));

    let wallet = Wallet::connect_with_config(
        harness.provider.clone(),
        harness.signer.clone(),
        config,
    )
    .await
    .expect("Failed to connect wallet");

    assert!(wallet.is_eoa(), "Wallet should be EOA when Safe not deployed");
    assert!(!wallet.is_safe(), "Wallet should not be Safe when not deployed");
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

/// Test that Wallet::connect returns Wallet::Safe when Safe is deployed
#[tokio::test]
async fn test_wallet_connect_returns_safe_when_deployed() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // First deploy a Safe manually
    let salt_nonce = U256::from(10001);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    // Now connect with the same salt nonce - should detect the Safe
    let config = WalletConfig::new().with_salt_nonce(salt_nonce);

    let wallet = Wallet::connect_with_config(
        harness.provider.clone(),
        harness.signer.clone(),
        config,
    )
    .await
    .expect("Failed to connect wallet");

    assert!(wallet.is_safe(), "Wallet should be Safe when deployed");
    assert!(!wallet.is_eoa(), "Wallet should not be EOA when Safe is deployed");
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

/// Test that Wallet::connect_and_deploy deploys a Safe if not exists
#[tokio::test]
async fn test_wallet_connect_and_deploy_creates_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Use a unique salt nonce to ensure no Safe exists
    let config = WalletConfig::new().with_salt_nonce(U256::from(20001));

    let wallet = Wallet::connect_and_deploy_with_rpc_and_config(
        harness.provider.clone(),
        harness.signer.clone(),
        harness._anvil.endpoint_url(),
        config,
    )
    .await
    .expect("Failed to connect and deploy wallet");

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

/// Test that Wallet::connect_and_deploy returns existing Safe without re-deploying
#[tokio::test]
async fn test_wallet_connect_and_deploy_uses_existing_safe() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // First deploy a Safe manually
    let salt_nonce = U256::from(30001);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    // Now call connect_and_deploy with the same salt nonce
    let config = WalletConfig::new().with_salt_nonce(salt_nonce);

    let wallet = Wallet::connect_and_deploy_with_rpc_and_config(
        harness.provider.clone(),
        harness.signer.clone(),
        harness._anvil.endpoint_url(),
        config,
    )
    .await
    .expect("Failed to connect and deploy wallet");

    assert!(wallet.is_safe(), "Wallet should be Safe");
    assert_eq!(
        wallet.address(),
        safe_address,
        "Should use existing Safe address"
    );
}

/// Test that computed_safe_address matches the actual deployed address
#[tokio::test]
async fn test_wallet_computed_safe_address() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    let salt_nonce = U256::from(40001);
    let config = WalletConfig::new().with_salt_nonce(salt_nonce);

    // Compute the address first
    let computed_address = Wallet::<_>::computed_safe_address(
        &harness.provider,
        &harness.signer,
        &config,
    )
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

    let addr1 = Wallet::<_>::computed_safe_address(
        &harness.provider,
        &harness.signer,
        &config1,
    )
    .await
    .expect("Failed to compute address 1");

    let addr2 = Wallet::<_>::computed_safe_address(
        &harness.provider,
        &harness.signer,
        &config2,
    )
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

    let addr1 = Wallet::<_>::computed_safe_address(
        &harness.provider,
        &harness.signer,
        &config1,
    )
    .await
    .expect("Failed to compute address 1");

    let addr2 = Wallet::<_>::computed_safe_address(
        &harness.provider,
        &harness.signer,
        &config2,
    )
    .await
    .expect("Failed to compute address 2");

    // Different owners should produce different addresses (even with same salt)
    assert_ne!(addr1, addr2, "Different owners should produce different addresses");
}

/// Test WalletConfig with different threshold
#[tokio::test]
async fn test_wallet_connect_and_deploy_with_threshold() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner2 = alloy::primitives::address!("0x2222222222222222222222222222222222222222");

    let config = WalletConfig::new()
        .with_salt_nonce(U256::from(70001))
        .with_additional_owners(vec![owner2])
        .with_threshold(2);

    let wallet = Wallet::connect_and_deploy_with_rpc_and_config(
        harness.provider.clone(),
        harness.signer.clone(),
        harness._anvil.endpoint_url(),
        config,
    )
    .await
    .expect("Failed to connect and deploy wallet");

    assert!(wallet.is_safe(), "Wallet should be Safe");

    // Verify the Safe has correct configuration
    if let Wallet::Safe(safe) = &wallet {
        let threshold = safe.threshold().await.expect("Failed to get threshold");
        assert_eq!(threshold, 2, "Threshold should be 2");

        let owners = safe.owners().await.expect("Failed to get owners");
        assert_eq!(owners.len(), 2, "Should have 2 owners");
    }
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

    let result = Wallet::connect_and_deploy_with_rpc_and_config(
        harness.provider.clone(),
        harness.signer.clone(),
        harness._anvil.endpoint_url(),
        config,
    )
    .await;

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

    let result = Wallet::connect_and_deploy_with_rpc_and_config(
        harness.provider.clone(),
        harness.signer.clone(),
        harness._anvil.endpoint_url(),
        config,
    )
    .await;

    assert!(result.is_err(), "Should fail with zero threshold");
}
