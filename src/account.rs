//! Shared account trait for Safe and EOA wallets

use std::future::Future;
use std::path::Path;

use alloy::network::{AnyNetwork, TxSigner};
use alloy::primitives::{Address, Bytes, Signature, U256};
use alloy::providers::Provider;
use alloy::signers::Signer;

use crate::chain::ChainConfig;
use crate::error::Result;
use crate::safe::ExecutionResult;
use crate::types::{CallBuilder, Operation};

/// The key a [`Safe`](crate::Safe) or [`Eoa`](crate::Eoa) client signs with:
/// any alloy signer that signs EIP-712 typed data (the Safe transaction) and
/// transactions, and is cheap to clone. A local key, a hardware wallet or a
/// remote signer behind an `Arc` all qualify.
///
/// It needs no raw-hash signing: hardware wallets refuse `sign_hash`, so the
/// clients only call `sign_typed_data` and `sign_transaction`.
pub trait AccountSigner: Signer + TxSigner<Signature> + Clone + Send + Sync + 'static {}

impl<T> AccountSigner for T where T: Signer + TxSigner<Signature> + Clone + Send + Sync + 'static {}

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
    /// With the `simulation` feature (on by default) the call is simulated
    /// first, and a revert fails with `Error::SimulationReverted`. Without it a
    /// revert fails when gas is estimated. Either way nothing is broadcast.
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
