//! Generic Wallet type for Safe and EOA accounts
//!
//! This module provides a `Wallet<A>` type that wraps any account implementing
//! the `Account` trait, enabling generic code that works with both Safe and EOA.
//!
//! # Example
//!
//! ```rust,ignore
//! use safe_rs::{Wallet, WalletConfig, Account};
//!
//! // Connect to a Safe wallet
//! let safe_wallet = Wallet::connect_safe(provider, signer, safe_address).await?;
//!
//! // Connect to an EOA wallet
//! let eoa_wallet = Wallet::connect_eoa(provider, signer).await?;
//!
//! // Generic function that works with any account type
//! async fn do_something<A: Account>(wallet: &Wallet<A>) -> Result<()> {
//!     wallet.batch()
//!         .add_typed(token, IERC20::transferCall { to: recipient, amount })
//!         .simulate().await?
//!         .execute().await?;
//!     Ok(())
//! }
//! ```

use alloy::network::{AnyNetwork, EthereumWallet};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use url::Url;

use crate::account::Account;
use crate::chain::{ChainAddresses, ChainConfig};
use crate::create2::{compute_create2_address, encode_setup_call};
use crate::eoa::Eoa;
use crate::error::{Error, Result};
use crate::safe::{is_safe, ExecutionResult, Safe};
use crate::types::Operation;
use crate::ISafeProxyFactory;

/// Configuration for Safe address computation and deployment
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// Salt nonce for CREATE2 address computation (default: 0)
    pub salt_nonce: U256,
    /// Additional owners beyond the signer (default: empty)
    pub additional_owners: Vec<Address>,
    /// Threshold for the Safe (default: 1)
    pub threshold: u64,
    /// Fallback handler address (default: v1.4.1 fallback handler)
    pub fallback_handler: Option<Address>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            salt_nonce: U256::ZERO,
            additional_owners: Vec::new(),
            threshold: 1,
            fallback_handler: None,
        }
    }
}

impl WalletConfig {
    /// Creates a new WalletConfig with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the salt nonce for CREATE2 address computation
    pub fn with_salt_nonce(mut self, salt_nonce: U256) -> Self {
        self.salt_nonce = salt_nonce;
        self
    }

    /// Sets additional owners beyond the signer
    pub fn with_additional_owners(mut self, owners: Vec<Address>) -> Self {
        self.additional_owners = owners;
        self
    }

    /// Sets the threshold for the Safe
    pub fn with_threshold(mut self, threshold: u64) -> Self {
        self.threshold = threshold;
        self
    }

    /// Sets a custom fallback handler
    pub fn with_fallback_handler(mut self, handler: Address) -> Self {
        self.fallback_handler = Some(handler);
        self
    }

    /// Builds the owners array (signer + additional owners)
    fn build_owners(&self, signer_address: Address) -> Vec<Address> {
        let mut owners = vec![signer_address];
        for owner in &self.additional_owners {
            if !owners.contains(owner) {
                owners.push(*owner);
            }
        }
        owners
    }

    /// Gets the fallback handler, using the v1.4.1 default if not specified
    fn get_fallback_handler(&self) -> Address {
        self.fallback_handler
            .unwrap_or_else(|| ChainAddresses::v1_4_1().fallback_handler)
    }
}

/// A wallet that wraps any account type implementing the `Account` trait.
///
/// This provides a unified interface for both Safe and EOA wallets with
/// compile-time polymorphism.
///
/// # Type Parameters
///
/// * `A` - The account type (e.g., `Safe<P>` or `Eoa<P>`)
///
/// # Example
///
/// ```rust,ignore
/// // Connect to a Safe
/// let wallet = Wallet::connect_safe(provider, signer, safe_address).await?;
///
/// // Use the unified batch API
/// wallet.batch()
///     .add_typed(token, call)
///     .execute().await?;
/// ```
pub struct Wallet<A: Account> {
    account: A,
}

impl<A: Account> Wallet<A> {
    /// Creates a new wallet wrapping the given account.
    pub fn new(account: A) -> Self {
        Self { account }
    }

    /// Returns the wallet's address.
    ///
    /// For Safe wallets, returns the Safe contract address.
    /// For EOA wallets, returns the signer address.
    pub fn address(&self) -> Address {
        self.account.address()
    }

    /// Returns the underlying signer address.
    ///
    /// For Safe wallets, this is the owner/signer address.
    /// For EOA wallets, this is the same as `address()`.
    pub fn signer_address(&self) -> Address {
        self.account.signer_address()
    }

    /// Returns a reference to the provider.
    pub fn provider(&self) -> &A::Provider {
        self.account.provider()
    }

    /// Returns the chain configuration.
    pub fn config(&self) -> &ChainConfig {
        self.account.config()
    }

    /// Gets the current nonce for the account.
    ///
    /// For Safe wallets, this is the Safe's internal nonce.
    /// For EOA wallets, this is the account's transaction count.
    pub async fn nonce(&self) -> Result<U256> {
        self.account.nonce().await
    }

    /// Creates a new builder for batching transactions.
    ///
    /// Returns `A::Builder<'_>` which implements `CallBuilder`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// wallet.batch()
    ///     .add_typed(token, IERC20::transferCall { to: recipient, amount })
    ///     .simulate().await?
    ///     .execute().await?;
    /// ```
    pub fn batch(&self) -> A::Builder<'_> {
        self.account.batch()
    }

    /// Executes a single transaction.
    ///
    /// This is a convenience method for executing a single call without
    /// the batch builder. For multiple calls, use `batch()` instead.
    ///
    /// # Errors
    /// Returns `Error::UnsupportedEoaOperation` if `operation` is `DelegateCall`
    /// and the wallet is an EOA.
    pub async fn execute_single(
        &self,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
    ) -> Result<ExecutionResult> {
        self.account.execute_single(to, value, data, operation).await
    }

    /// Returns a reference to the underlying account.
    pub fn inner(&self) -> &A {
        &self.account
    }

    /// Consumes the wallet and returns the underlying account.
    pub fn into_inner(self) -> A {
        self.account
    }
}

// =============================================================================
// Safe-specific implementation
// =============================================================================

impl<P> Wallet<Safe<P>>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Connects to an existing Safe at the given address.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer (must be an owner of the Safe)
    /// * `address` - The Safe contract address
    pub async fn connect_safe(
        provider: P,
        signer: PrivateKeySigner,
        address: Address,
    ) -> Result<Self> {
        let safe = Safe::connect(provider, signer, address).await?;
        Ok(Self::new(safe))
    }

    /// Connects to a Safe at the computed CREATE2 address for the given config.
    ///
    /// This computes the deterministic Safe address based on the signer and config,
    /// then connects to it. Returns an error if no Safe is deployed at that address.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer
    /// * `config` - Configuration for Safe address computation
    pub async fn connect_safe_with_config(
        provider: P,
        signer: PrivateKeySigner,
        config: WalletConfig,
    ) -> Result<Self> {
        let safe_address = Self::compute_safe_address(&provider, &signer, &config).await?;

        // Check if Safe is deployed
        if !is_safe(&provider, safe_address).await? {
            return Err(Error::InvalidConfig(format!(
                "No Safe deployed at computed address {}",
                safe_address
            )));
        }

        let safe = Safe::connect(provider, signer, safe_address).await?;
        Ok(Self::new(safe))
    }

    /// Connects to a Safe or deploys one if it doesn't exist.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer
    /// * `rpc_url` - The RPC URL for sending deployment transaction
    pub async fn connect_or_deploy_safe_with_rpc(
        provider: P,
        signer: PrivateKeySigner,
        rpc_url: Url,
    ) -> Result<Self> {
        Self::connect_or_deploy_safe_with_rpc_and_config(
            provider,
            signer,
            rpc_url,
            WalletConfig::default(),
        )
        .await
    }

    /// Connects to a Safe or deploys one with custom configuration.
    ///
    /// If a Safe already exists at the computed address, connects to it.
    /// Otherwise, deploys a new Safe with the specified configuration.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer
    /// * `rpc_url` - The RPC URL for sending deployment transaction
    /// * `config` - Configuration for Safe address computation and deployment
    pub async fn connect_or_deploy_safe_with_rpc_and_config(
        provider: P,
        signer: PrivateKeySigner,
        rpc_url: Url,
        config: WalletConfig,
    ) -> Result<Self> {
        let addresses = ChainAddresses::v1_4_1();
        let signer_address = signer.address();

        // Build owners array
        let owners = config.build_owners(signer_address);

        // Validate threshold
        if config.threshold == 0 || config.threshold as usize > owners.len() {
            return Err(Error::InvalidConfig(format!(
                "Invalid threshold: {} (must be 1-{})",
                config.threshold,
                owners.len()
            )));
        }

        // Get fallback handler
        let fallback_handler = config.get_fallback_handler();

        // Encode initializer
        let initializer = encode_setup_call(&owners, config.threshold, fallback_handler);

        // Get proxy creation code
        let factory = ISafeProxyFactory::new(addresses.proxy_factory, &provider);
        let creation_code = factory
            .proxyCreationCode()
            .call()
            .await
            .map_err(|e| Error::Fetch {
                what: "proxy creation code",
                reason: e.to_string(),
            })?;

        // Compute deterministic address
        let safe_address = compute_create2_address(
            addresses.proxy_factory,
            addresses.safe_singleton,
            &initializer,
            config.salt_nonce,
            &creation_code,
        );

        // Check if Safe is already deployed
        if is_safe(&provider, safe_address).await? {
            let safe = Safe::connect(provider, signer, safe_address).await?;
            return Ok(Self::new(safe));
        }

        // Deploy the Safe
        let wallet_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(rpc_url);

        let factory_with_wallet = ISafeProxyFactory::new(addresses.proxy_factory, &wallet_provider);

        let pending_tx = factory_with_wallet
            .createProxyWithNonce(addresses.safe_singleton, initializer, config.salt_nonce)
            .send()
            .await
            .map_err(|e| Error::ExecutionFailed {
                reason: format!("Failed to send deployment transaction: {}", e),
            })?;

        let _receipt = pending_tx.get_receipt().await.map_err(|e| Error::ExecutionFailed {
            reason: format!("Failed to get deployment receipt: {}", e),
        })?;

        // Verify deployment
        if !is_safe(&provider, safe_address).await? {
            return Err(Error::ExecutionFailed {
                reason: format!("Deployment failed: no Safe at expected address {}", safe_address),
            });
        }

        let safe = Safe::connect(provider, signer, safe_address).await?;
        Ok(Self::new(safe))
    }

    /// Computes the Safe address that would be used for the given signer and config.
    ///
    /// This is useful for checking what Safe address would be computed without
    /// actually connecting or deploying.
    pub async fn compute_safe_address(
        provider: &P,
        signer: &PrivateKeySigner,
        config: &WalletConfig,
    ) -> Result<Address> {
        let addresses = ChainAddresses::v1_4_1();
        let signer_address = signer.address();

        // Build owners array
        let owners = config.build_owners(signer_address);

        // Get fallback handler
        let fallback_handler = config.get_fallback_handler();

        // Encode initializer
        let initializer = encode_setup_call(&owners, config.threshold, fallback_handler);

        // Get proxy creation code
        let factory = ISafeProxyFactory::new(addresses.proxy_factory, provider);
        let creation_code = factory
            .proxyCreationCode()
            .call()
            .await
            .map_err(|e| Error::Fetch {
                what: "proxy creation code",
                reason: e.to_string(),
            })?;

        // Compute deterministic address
        let safe_address = compute_create2_address(
            addresses.proxy_factory,
            addresses.safe_singleton,
            &initializer,
            config.salt_nonce,
            &creation_code,
        );

        Ok(safe_address)
    }

    /// Returns true (this is a Safe wallet).
    pub fn is_safe(&self) -> bool {
        true
    }

    /// Returns false (this is not an EOA wallet).
    pub fn is_eoa(&self) -> bool {
        false
    }

    /// Returns a reference to the underlying Safe.
    pub fn safe(&self) -> &Safe<P> {
        self.inner()
    }
}

// =============================================================================
// EOA-specific implementation
// =============================================================================

impl<P> Wallet<Eoa<P>>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Connects to an EOA wallet.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer
    pub async fn connect_eoa(provider: P, signer: PrivateKeySigner) -> Result<Self> {
        let eoa = Eoa::connect(provider, signer).await?;
        Ok(Self::new(eoa))
    }

    /// Returns false (this is not a Safe wallet).
    pub fn is_safe(&self) -> bool {
        false
    }

    /// Returns true (this is an EOA wallet).
    pub fn is_eoa(&self) -> bool {
        true
    }

    /// Returns a reference to the underlying Eoa.
    pub fn eoa(&self) -> &Eoa<P> {
        self.inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_config_default() {
        let config = WalletConfig::default();
        assert_eq!(config.salt_nonce, U256::ZERO);
        assert!(config.additional_owners.is_empty());
        assert_eq!(config.threshold, 1);
        assert!(config.fallback_handler.is_none());
    }

    #[test]
    fn test_wallet_config_builder() {
        use alloy::primitives::address;

        let owner2 = address!("2222222222222222222222222222222222222222");
        let handler = address!("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99");

        let config = WalletConfig::new()
            .with_salt_nonce(U256::from(42))
            .with_additional_owners(vec![owner2])
            .with_threshold(2)
            .with_fallback_handler(handler);

        assert_eq!(config.salt_nonce, U256::from(42));
        assert_eq!(config.additional_owners, vec![owner2]);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.fallback_handler, Some(handler));
    }

    #[test]
    fn test_wallet_config_build_owners() {
        use alloy::primitives::address;

        let signer = address!("1111111111111111111111111111111111111111");
        let owner2 = address!("2222222222222222222222222222222222222222");
        let owner3 = address!("3333333333333333333333333333333333333333");

        let config = WalletConfig::new().with_additional_owners(vec![owner2, owner3]);
        let owners = config.build_owners(signer);

        assert_eq!(owners.len(), 3);
        assert_eq!(owners[0], signer);
        assert_eq!(owners[1], owner2);
        assert_eq!(owners[2], owner3);
    }

    #[test]
    fn test_wallet_config_build_owners_no_duplicates() {
        use alloy::primitives::address;

        let signer = address!("1111111111111111111111111111111111111111");
        // Include signer in additional owners (should not duplicate)
        let config = WalletConfig::new().with_additional_owners(vec![signer]);
        let owners = config.build_owners(signer);

        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0], signer);
    }

    #[test]
    fn test_wallet_config_get_fallback_handler_default() {
        let config = WalletConfig::default();
        let handler = config.get_fallback_handler();
        assert_eq!(handler, ChainAddresses::v1_4_1().fallback_handler);
    }

    #[test]
    fn test_wallet_config_get_fallback_handler_custom() {
        use alloy::primitives::address;

        let custom_handler = address!("dead000000000000000000000000000000000000");
        let config = WalletConfig::new().with_fallback_handler(custom_handler);
        let handler = config.get_fallback_handler();
        assert_eq!(handler, custom_handler);
    }
}
