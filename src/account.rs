//! Shared account trait for Safe and EOA wallets

use std::future::Future;
use std::path::Path;

use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;

use crate::chain::ChainConfig;
use crate::error::Result;
use crate::safe::ExecutionResult;
use crate::types::{CallBuilder, Operation};

/// Trait for account types that can sign and execute transactions.
///
/// This provides a unified interface for both Safe smart accounts
/// and EOA (Externally Owned Account) wallets.
pub trait Account {
    /// The provider type for RPC calls.
    type Provider: Provider<AnyNetwork> + Clone + 'static;

    /// The builder type for constructing batched transactions.
    type Builder<'a>: CallBuilder
    where
        Self: 'a;

    /// Returns the account's transaction-sending address.
    ///
    /// For Safe accounts, this is the Safe contract address.
    /// For EOA accounts, this is the signer address.
    fn address(&self) -> Address;

    /// Returns the underlying signer address.
    ///
    /// For Safe accounts, this is the owner/signer address.
    /// For EOA accounts, this is the same as `address()`.
    fn signer_address(&self) -> Address;

    /// Returns the chain configuration.
    fn config(&self) -> &ChainConfig;

    /// Returns a reference to the provider.
    fn provider(&self) -> &Self::Provider;

    /// Returns the debug output directory for simulation failures, if configured.
    fn debug_output_dir(&self) -> Option<&Path>;

    /// Gets the current nonce for the account.
    ///
    /// For Safe accounts, this is the Safe's internal nonce.
    /// For EOA accounts, this is the account's transaction count.
    fn nonce(&self) -> impl Future<Output = Result<U256>> + Send;

    /// Creates a new builder for batching transactions.
    fn batch(&self) -> Self::Builder<'_>;

    /// Executes a single transaction.
    ///
    /// # Arguments
    /// * `to` - Target address
    /// * `value` - ETH value to send
    /// * `data` - Calldata
    /// * `operation` - Call or DelegateCall
    ///
    /// # Errors
    /// Returns an error if the transaction fails to execute.
    /// For EOA accounts, `DelegateCall` operation returns `Error::UnsupportedEoaOperation`.
    fn execute_single(
        &self,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
    ) -> impl Future<Output = Result<ExecutionResult>> + Send;
}
