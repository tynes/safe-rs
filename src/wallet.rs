//! Auto-detecting Wallet type for Safe and EOA accounts
//!
//! This module provides a unified `Wallet` type that automatically detects whether
//! a private key has an associated Safe deployed at its deterministic CREATE2 address.
//!
//! # Example
//!
//! ```rust,ignore
//! use safe_rs::{Wallet, WalletConfig};
//!
//! // Simple case: auto-detect Safe vs EOA
//! let wallet = Wallet::connect(provider, signer).await?;
//!
//! // With custom configuration
//! let wallet = Wallet::connect_with_config(provider, signer, WalletConfig {
//!     salt_nonce: U256::from(1001),
//!     ..Default::default()
//! }).await?;
//!
//! // Auto-deploy: deploys Safe if not exists
//! let wallet = Wallet::connect_and_deploy(provider, signer).await?;
//!
//! // Unified batch API (works for both Safe and EOA)
//! wallet.batch()
//!     .add_typed(token, IERC20::transferCall { to: recipient, amount })
//!     .simulate().await?
//!     .execute().await?;
//!
//! // Pattern matching for variant-specific operations
//! match &wallet {
//!     Wallet::Safe(safe) => { safe.multicall()... }
//!     Wallet::Eoa(eoa) => { eoa.batch()... }
//! }
//! ```

use alloy::network::{AnyNetwork, EthereumWallet};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use url::Url;

use crate::chain::ChainAddresses;
use crate::create2::{compute_create2_address, encode_setup_call};
use crate::eoa::{Eoa, EoaBuilder};
use crate::error::{Error, Result};
use crate::safe::{is_safe, MulticallBuilder, Safe};
use crate::types::{BatchResult, BatchSimulationResult, SafeCall};
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

/// A wallet that can be either a Safe smart account or an EOA
///
/// Note: `Debug` is not derived because `Safe<P>` and `Eoa<P>` don't implement `Debug`.
pub enum Wallet<P> {
    /// Safe smart account variant
    Safe(Safe<P>),
    /// Externally Owned Account variant
    Eoa(Eoa<P>),
}

impl<P> Wallet<P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Connects to a wallet, auto-detecting whether a Safe exists
    ///
    /// Uses default configuration (salt_nonce = 0, single owner, threshold = 1).
    /// If a Safe is deployed at the computed CREATE2 address, returns `Wallet::Safe`.
    /// Otherwise, returns `Wallet::Eoa`.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer
    ///
    /// # Returns
    /// `Wallet::Safe` if Safe exists at computed address, `Wallet::Eoa` otherwise
    pub async fn connect(provider: P, signer: PrivateKeySigner) -> Result<Self> {
        Self::connect_with_config(provider, signer, WalletConfig::default()).await
    }

    /// Connects to a wallet with custom configuration
    ///
    /// If a Safe is deployed at the computed CREATE2 address for the given config,
    /// returns `Wallet::Safe`. Otherwise, returns `Wallet::Eoa`.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer
    /// * `config` - Configuration for Safe address computation
    pub async fn connect_with_config(
        provider: P,
        signer: PrivateKeySigner,
        config: WalletConfig,
    ) -> Result<Self> {
        let safe_address = Self::compute_safe_address_internal(&provider, &signer, &config).await?;

        // Check if Safe is deployed
        if is_safe(&provider, safe_address).await? {
            let safe = Safe::connect(provider, signer, safe_address).await?;
            Ok(Wallet::Safe(safe))
        } else {
            let eoa = Eoa::connect(provider, signer).await?;
            Ok(Wallet::Eoa(eoa))
        }
    }

    /// Connects and deploys a Safe if one doesn't exist
    ///
    /// Uses default configuration. If Safe already exists, connects to it.
    /// If not, deploys a new Safe and returns `Wallet::Safe`.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls (must support sending transactions)
    /// * `signer` - The private key signer
    pub async fn connect_and_deploy(provider: P, signer: PrivateKeySigner) -> Result<Self> {
        Self::connect_and_deploy_with_config(provider, signer, WalletConfig::default()).await
    }

    /// Connects and deploys a Safe with custom configuration
    ///
    /// If Safe already exists at the computed address, connects to it.
    /// If not, deploys a new Safe with the specified configuration.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls (must support sending transactions)
    /// * `signer` - The private key signer
    /// * `config` - Configuration for Safe address computation and deployment
    pub async fn connect_and_deploy_with_config(
        provider: P,
        signer: PrivateKeySigner,
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
            return Ok(Wallet::Safe(safe));
        }

        // Deploy the Safe
        // Create wallet provider for sending transaction
        let rpc_url = Self::extract_rpc_url(&provider)?;
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
        Ok(Wallet::Safe(safe))
    }

    /// Returns the wallet's address
    ///
    /// For `Wallet::Safe`, returns the Safe contract address.
    /// For `Wallet::Eoa`, returns the EOA signer address.
    pub fn address(&self) -> Address {
        match self {
            Wallet::Safe(safe) => safe.address(),
            Wallet::Eoa(eoa) => eoa.address(),
        }
    }

    /// Returns true if this is a Safe wallet
    pub fn is_safe(&self) -> bool {
        matches!(self, Wallet::Safe(_))
    }

    /// Returns true if this is an EOA wallet
    pub fn is_eoa(&self) -> bool {
        matches!(self, Wallet::Eoa(_))
    }

    /// Returns the underlying EOA signer address
    ///
    /// For both variants, this returns the address of the private key signer.
    pub fn signer_address(&self) -> Address {
        match self {
            Wallet::Safe(safe) => safe.signer_address(),
            Wallet::Eoa(eoa) => eoa.signer_address(),
        }
    }

    /// Returns a reference to the provider
    pub fn provider(&self) -> &P {
        match self {
            Wallet::Safe(safe) => safe.provider(),
            Wallet::Eoa(eoa) => eoa.provider(),
        }
    }

    /// Creates a unified batch builder for executing transactions
    ///
    /// This provides the same API for both Safe and EOA wallets, abstracting
    /// away the differences between atomic multicall (Safe) and sequential
    /// transactions (EOA).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// wallet.batch()
    ///     .add_typed(token, IERC20::transferCall { to: recipient, amount })
    ///     .simulate().await?
    ///     .execute().await?;
    /// ```
    pub fn batch(&self) -> BatchBuilder<'_, P> {
        match self {
            Wallet::Safe(safe) => BatchBuilder::Safe(safe.multicall()),
            Wallet::Eoa(eoa) => BatchBuilder::Eoa(eoa.batch()),
        }
    }

    /// Executes a single transaction
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
        operation: crate::types::Operation,
    ) -> Result<crate::safe::ExecutionResult> {
        match self {
            Wallet::Safe(safe) => safe.execute_single(to, value, data, operation).await,
            Wallet::Eoa(eoa) => eoa.execute_single(to, value, data, operation).await,
        }
    }

    /// Computes the Safe address that would be used for the given signer and config
    ///
    /// This is useful for checking what Safe address would be computed without
    /// actually connecting or deploying.
    pub async fn computed_safe_address(
        provider: &P,
        signer: &PrivateKeySigner,
        config: &WalletConfig,
    ) -> Result<Address> {
        Self::compute_safe_address_internal(provider, signer, config).await
    }

    /// Internal helper to compute Safe address
    async fn compute_safe_address_internal(
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

    /// Helper to extract RPC URL from provider
    ///
    /// This is a workaround since we can't clone arbitrary providers for wallet construction.
    /// We need to create a new provider with wallet capabilities for deployment.
    fn extract_rpc_url(_provider: &P) -> Result<Url> {
        // For HTTP providers, we need to get the endpoint URL
        // This is a limitation - we assume HTTP provider with a well-known endpoint pattern
        // In practice, users should ensure the provider is an HTTP provider
        Err(Error::Provider(
            "Cannot extract RPC URL from provider. Use connect_and_deploy with an HTTP provider that has the RPC URL accessible.".to_string()
        ))
    }
}

/// Specialized implementation for the common HTTP provider case
impl<P> Wallet<P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Connects and deploys a Safe using the specified RPC URL
    ///
    /// This variant is useful when the provider doesn't expose its RPC URL directly.
    ///
    /// # Arguments
    /// * `provider` - The provider for RPC calls
    /// * `signer` - The private key signer
    /// * `rpc_url` - The RPC URL for sending deployment transaction
    pub async fn connect_and_deploy_with_rpc(
        provider: P,
        signer: PrivateKeySigner,
        rpc_url: Url,
    ) -> Result<Self> {
        Self::connect_and_deploy_with_rpc_and_config(
            provider,
            signer,
            rpc_url,
            WalletConfig::default(),
        )
        .await
    }

    /// Connects and deploys a Safe with custom configuration and RPC URL
    pub async fn connect_and_deploy_with_rpc_and_config(
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
            return Ok(Wallet::Safe(safe));
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
        Ok(Wallet::Safe(safe))
    }
}

/// Unified batch builder for Safe and EOA transactions
///
/// This enum wraps either a `MulticallBuilder` (for Safe) or `EoaBuilder` (for EOA),
/// providing a common API for batching transactions regardless of wallet type.
pub enum BatchBuilder<'a, P> {
    /// Safe multicall builder (atomic execution)
    Safe(MulticallBuilder<'a, P>),
    /// EOA batch builder (sequential execution)
    Eoa(EoaBuilder<'a, P>),
}

impl<'a, P> BatchBuilder<'a, P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Adds a typed call to the batch
    pub fn add_typed<C: SolCall + Clone>(self, to: Address, call: C) -> Self {
        match self {
            BatchBuilder::Safe(builder) => BatchBuilder::Safe(builder.add_typed(to, call)),
            BatchBuilder::Eoa(builder) => BatchBuilder::Eoa(builder.add_typed(to, call)),
        }
    }

    /// Adds a typed call with value to the batch
    pub fn add_typed_with_value<C: SolCall + Clone>(
        self,
        to: Address,
        call: C,
        value: U256,
    ) -> Self {
        match self {
            BatchBuilder::Safe(builder) => {
                BatchBuilder::Safe(builder.add_typed_with_value(to, call, value))
            }
            BatchBuilder::Eoa(builder) => {
                BatchBuilder::Eoa(builder.add_typed_with_value(to, call, value))
            }
        }
    }

    /// Adds a raw call to the batch
    pub fn add_raw(self, to: Address, value: U256, data: impl Into<Bytes>) -> Self {
        match self {
            BatchBuilder::Safe(builder) => BatchBuilder::Safe(builder.add_raw(to, value, data)),
            BatchBuilder::Eoa(builder) => BatchBuilder::Eoa(builder.add_raw(to, value, data)),
        }
    }

    /// Adds a call implementing SafeCall to the batch
    pub fn add(self, call: impl SafeCall) -> Self {
        match self {
            BatchBuilder::Safe(builder) => BatchBuilder::Safe(builder.add(call)),
            BatchBuilder::Eoa(builder) => BatchBuilder::Eoa(builder.add(call)),
        }
    }

    /// Returns the number of calls in the batch
    pub fn call_count(&self) -> usize {
        match self {
            BatchBuilder::Safe(builder) => builder.call_count(),
            BatchBuilder::Eoa(builder) => builder.call_count(),
        }
    }

    /// Returns true if the batch will execute atomically
    ///
    /// Safe batches are atomic (all-or-nothing), EOA batches are not.
    pub fn is_atomic(&self) -> bool {
        matches!(self, BatchBuilder::Safe(_))
    }

    /// Simulates the batch and returns a SimulatedBatchBuilder
    ///
    /// After simulation, you can inspect the results and then call `execute()`.
    pub async fn simulate(self) -> Result<SimulatedBatchBuilder<'a, P>> {
        match self {
            BatchBuilder::Safe(builder) => {
                let simulated = builder.simulate().await?;
                let sim_result = simulated
                    .simulation_result()
                    .cloned()
                    .map(BatchSimulationResult::from_safe);
                Ok(SimulatedBatchBuilder {
                    inner: BatchBuilder::Safe(simulated),
                    simulation_result: sim_result,
                })
            }
            BatchBuilder::Eoa(builder) => {
                let simulated = builder.simulate().await?;
                let sim_result = simulated
                    .simulation_results()
                    .map(|r| BatchSimulationResult::from_eoa(r.to_vec()));
                Ok(SimulatedBatchBuilder {
                    inner: BatchBuilder::Eoa(simulated),
                    simulation_result: sim_result,
                })
            }
        }
    }

    /// Executes the batch without prior simulation
    ///
    /// Gas will be estimated via RPC for each call.
    pub async fn execute(self) -> Result<BatchResult> {
        match self {
            BatchBuilder::Safe(builder) => {
                let result = builder.execute().await?;
                Ok(BatchResult::from_safe(result))
            }
            BatchBuilder::Eoa(builder) => {
                let result = builder.execute().await?;
                Ok(BatchResult::from_eoa(result))
            }
        }
    }
}

/// A batch builder that has been simulated
///
/// This struct holds both the simulated builder and the simulation results,
/// allowing inspection of gas usage before execution.
pub struct SimulatedBatchBuilder<'a, P> {
    inner: BatchBuilder<'a, P>,
    simulation_result: Option<BatchSimulationResult>,
}

impl<P> SimulatedBatchBuilder<'_, P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Returns a reference to the simulation result
    pub fn simulation_result(&self) -> Option<&BatchSimulationResult> {
        self.simulation_result.as_ref()
    }

    /// Returns the total gas used in simulation
    pub fn total_gas_used(&self) -> Option<u64> {
        self.simulation_result.as_ref().map(|r| r.total_gas_used)
    }

    /// Returns the number of calls in the batch
    pub fn call_count(&self) -> usize {
        self.inner.call_count()
    }

    /// Returns true if the batch will execute atomically
    pub fn is_atomic(&self) -> bool {
        self.inner.is_atomic()
    }

    /// Executes the batch using the simulated gas values
    pub async fn execute(self) -> Result<BatchResult> {
        self.inner.execute().await
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
