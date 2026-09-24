//! Safe client and SafeBuilder implementation

use std::path::{Path, PathBuf};

use alloy::network::primitives::ReceiptResponse;
use alloy::network::{AnyNetwork, Network, TransactionBuilder};
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;

use crate::account::Account;
use crate::chain::{ChainAddresses, ChainConfig};
use crate::contracts::ISafe;
use crate::envelope::{batch_params, BatchTarget, PreparedSafeTx, SafeTxGasPolicy};
use crate::error::{Error, Result};
use crate::simulation::{ForkSimulator, SimulationResult};
use crate::submit::{decode_safe_outcome, receipt_logs};
use crate::types::{Call, CallBuilder, Operation};

/// Safe proxy singleton storage slot (slot 0)
/// Safe proxies store the implementation/singleton address at storage slot 0,
/// as the first declared variable in the proxy contract.
pub const SAFE_SINGLETON_SLOT: U256 = U256::ZERO;

/// Checks if an address is a Safe contract by reading the singleton storage slot
/// and matching against known Safe singleton addresses.
///
/// Safe proxies store the implementation address at storage slot 0 (not ERC1967).
///
/// # Arguments
/// * `provider` - The provider for RPC calls
/// * `address` - The address to check
///
/// # Returns
/// `true` if the address is a Safe proxy pointing to a known Safe singleton,
/// `false` otherwise (including if the address has no code or no implementation slot).
pub async fn is_safe<P: Provider<N>, N: Network>(
    provider: &P,
    address: Address,
) -> Result<bool> {
    // Read the Safe singleton slot (slot 0)
    let storage_value = provider
        .get_storage_at(address, SAFE_SINGLETON_SLOT)
        .await
        .map_err(|e| Error::Fetch {
            what: "singleton slot",
            reason: e.to_string(),
        })?;

    // Parse storage value as an address (last 20 bytes of the 32-byte slot)
    let impl_address = Address::from_slice(&storage_value.to_be_bytes::<32>()[12..]);

    // Check against known Safe singletons
    let v1_4_1 = ChainAddresses::v1_4_1();
    let v1_3_0 = ChainAddresses::v1_3_0();

    Ok(impl_address == v1_4_1.safe_singleton || impl_address == v1_3_0.safe_singleton)
}

/// Result of executing a Safe transaction
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Transaction hash
    pub tx_hash: TxHash,
    /// Whether the Safe transaction succeeded (not just inclusion)
    pub success: bool,
}

/// Safe client for interacting with Safe v1.4.1 smart accounts
pub struct Safe<P> {
    /// The provider for RPC calls
    provider: P,
    /// The signer for transactions
    signer: PrivateKeySigner,
    /// The Safe contract address
    address: Address,
    /// Chain configuration
    config: ChainConfig,
    /// Debug output directory for simulation failures
    debug_output_dir: Option<PathBuf>,
}

impl<P> Safe<P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Creates a new Safe client
    pub fn new(provider: P, signer: PrivateKeySigner, address: Address, config: ChainConfig) -> Self {
        Self {
            provider,
            signer,
            address,
            config,
            debug_output_dir: None,
        }
    }

    /// Configures a directory for writing debug output on simulation failures.
    ///
    /// When a simulation fails and this is set, a JSON file will be written
    /// to the configured directory with the simulation details.
    pub fn with_debug_output_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.debug_output_dir = Some(path.into());
        self
    }

    /// Creates a Safe client with auto-detected chain configuration
    pub async fn connect(provider: P, signer: PrivateKeySigner, address: Address) -> Result<Self> {
        let chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| Error::Provider(e.to_string()))?;

        let config = ChainConfig::new(chain_id);
        Ok(Self::new(provider, signer, address, config))
    }

    /// Returns the chain addresses
    pub fn addresses(&self) -> &ChainAddresses {
        &self.config.addresses
    }

    /// Gets the threshold of the Safe
    pub async fn threshold(&self) -> Result<u64> {
        let safe = ISafe::new(self.address, &self.provider);
        let threshold = safe
            .getThreshold()
            .call()
            .await
            .map_err(|e| Error::Fetch {
                what: "threshold",
                reason: e.to_string(),
            })?;
        Ok(threshold.to::<u64>())
    }

    /// Gets the owners of the Safe
    pub async fn owners(&self) -> Result<Vec<Address>> {
        let safe = ISafe::new(self.address, &self.provider);
        let owners = safe
            .getOwners()
            .call()
            .await
            .map_err(|e| Error::Fetch {
                what: "owners",
                reason: e.to_string(),
            })?;
        Ok(owners)
    }

    /// Checks if an address is an owner of the Safe
    pub async fn is_owner(&self, address: Address) -> Result<bool> {
        let safe = ISafe::new(self.address, &self.provider);
        let is_owner = safe
            .isOwner(address)
            .call()
            .await
            .map_err(|e| Error::Fetch {
                what: "is_owner",
                reason: e.to_string(),
            })?;
        Ok(is_owner)
    }

    /// Verifies that the Safe is a strict 1-of-1 owned by `expected`: exactly one
    /// owner, equal to `expected`, and threshold 1.
    pub async fn verify_sole_owner(&self, expected: Address) -> Result<()> {
        let threshold = self.threshold().await?;
        if threshold != 1 {
            return Err(Error::InvalidThreshold { threshold });
        }
        let owners = self.owners().await?;
        if owners != [expected] {
            return Err(Error::InvalidConfig(format!(
                "Safe {} must have exactly one owner {expected}, found {owners:?}",
                self.address
            )));
        }
        Ok(())
    }

    /// Verifies that the signer is an owner and threshold is 1.
    ///
    /// This does not check the owner count: a Safe with several owners and
    /// threshold 1 passes. Use [`Safe::verify_sole_owner`] for a strict 1-of-1 check.
    pub async fn verify_single_owner(&self) -> Result<()> {
        let threshold = self.threshold().await?;
        if threshold != 1 {
            return Err(Error::InvalidThreshold { threshold });
        }

        let is_owner = self.is_owner(self.signer.address()).await?;
        if !is_owner {
            return Err(Error::NotOwner {
                signer: self.signer.address(),
                safe: self.address,
            });
        }

        Ok(())
    }
}

/// Builder for constructing multicall transactions
pub struct SafeBuilder<'a, P> {
    safe: &'a Safe<P>,
    calls: Vec<Call>,
    use_call_only: bool,
    gas: SafeTxGasPolicy,
    nonce: Option<U256>,
    /// The Safe transaction `simulate()` ran, which `execute()` must match
    simulated: Option<PreparedSafeTx>,
    simulation_result: Option<SimulationResult>,
}

impl<'a, P> SafeBuilder<'a, P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    fn new(safe: &'a Safe<P>) -> Self {
        SafeBuilder {
            safe,
            calls: Vec::new(),
            use_call_only: false,
            gas: SafeTxGasPolicy::Zero,
            nonce: None,
            simulated: None,
            simulation_result: None,
        }
    }

    /// Uses a fixed Safe nonce instead of reading the current one.
    ///
    /// Execution fails if the on-chain nonce differs, rather than silently
    /// signing a different Safe transaction.
    pub fn with_nonce(mut self, nonce: U256) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Resolves the nonce to sign for: `expected` (checked against the chain)
    /// or the current on-chain nonce.
    async fn resolve_nonce(&self, expected: Option<U256>) -> Result<U256> {
        let current = self.safe.nonce().await?;
        match expected {
            Some(expected) if expected != current => Err(Error::NonceMismatch {
                expected,
                actual: current,
            }),
            Some(expected) => Ok(expected),
            None => Ok(current),
        }
    }

    /// Use MultiSendCallOnly instead of MultiSend and reject any DelegateCall.
    ///
    /// With `call_only()`, a DelegateCall entry (including a single DelegateCall)
    /// makes `simulate()` and `execute()` fail with [`Error::DelegateCallNotAllowed`].
    pub fn call_only(mut self) -> Self {
        self.use_call_only = true;
        self
    }

    /// Sets an explicit `safeTxGas` instead of the fail-closed default of 0.
    ///
    /// With a non-zero value a failing inner call does not revert: the Safe emits
    /// `ExecutionFailure` and consumes the nonce (see [`SafeTxGasPolicy`]).
    pub fn with_safe_tx_gas(mut self, gas: U256) -> Self {
        self.gas = SafeTxGasPolicy::Explicit(gas);
        self
    }

    /// Sets the top-level `safe_tx_gas` for the entire Safe transaction.
    ///
    /// This is equivalent to `with_safe_tx_gas(U256::from(gas_limit))`.
    pub fn with_gas_limit(self, gas_limit: u64) -> Self {
        self.with_safe_tx_gas(U256::from(gas_limit))
    }

    fn batch_target(&self) -> BatchTarget {
        let addresses = self.safe.addresses();
        if self.use_call_only {
            BatchTarget::CallOnly(addresses.multi_send_call_only)
        } else {
            BatchTarget::MultiSend(addresses.multi_send)
        }
    }

    /// Freezes the batch into the Safe transaction that `simulate()` and
    /// `execute()` sign.
    ///
    /// The nonce is the one set with [`SafeBuilder::with_nonce`] (checked against
    /// the chain) or the current on-chain nonce. `safeTxGas` is the explicit value
    /// or 0, and no gas refund is paid.
    pub async fn prepare(&self) -> Result<PreparedSafeTx> {
        self.prepare_at(self.nonce).await
    }

    async fn prepare_at(&self, nonce: Option<U256>) -> Result<PreparedSafeTx> {
        let params = batch_params(&self.calls, self.batch_target())?;
        let nonce = self.resolve_nonce(nonce).await?;
        Ok(PreparedSafeTx::from_params(
            self.safe.config.chain_id,
            self.safe.address,
            params.with_safe_tx_gas(self.gas.value()).with_nonce(nonce),
        ))
    }

    /// A simulator for this Safe's chain, without debug output.
    fn simulator(&self) -> ForkSimulator<P> {
        ForkSimulator::new(self.safe.provider.clone(), self.safe.config.chain_id)
    }

    /// Simulates the multicall and stores the result
    ///
    /// The simulation is the real path: the owner calling `Safe.execTransaction`
    /// with a signed Safe transaction. That checks the signature, nonce and Safe
    /// configuration, and gives DelegateCall targets (like MultiSend) their
    /// delegatecall context.
    ///
    /// This method does not return an error if the simulation reverts. Instead,
    /// the result (success or failure) is stored internally. Use `simulation_success()`
    /// to check if the simulation succeeded before calling `execute()`, which
    /// executes exactly the simulated Safe transaction.
    pub async fn simulate(mut self) -> Result<Self> {
        let prepared = self.prepare().await?;
        let signed = prepared.sign(&self.safe.signer).await?;
        let exec_data = signed.exec_calldata();
        let owner = self.safe.signer.address();

        let mut simulator = self.simulator();
        if let Some(dir) = &self.safe.debug_output_dir {
            simulator = simulator.with_debug_output_dir(dir.clone(), self.safe.address);
        }
        let mut result = simulator
            .simulate_call(
                owner,
                self.safe.address,
                U256::ZERO,
                exec_data.clone(),
                Operation::Call,
            )
            .await?;

        // A non-zero safeTxGas makes the Safe emit ExecutionFailure instead of
        // reverting; treat that as a failed simulation too.
        result.require_safe_success(self.safe.address, prepared.safe_tx_hash);

        // GS013 hides the inner revert reason; replay with tracing to recover it.
        if !result.success
            && result
                .revert_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("GS013"))
        {
            let traced = self
                .simulator()
                .with_tracing(true)
                .simulate_call(owner, self.safe.address, U256::ZERO, exec_data, Operation::Call)
                .await?;
            if let Some(inner) = traced
                .traces
                .as_ref()
                .and_then(crate::simulation::innermost_revert_reason)
            {
                result.revert_reason = Some(format!("GS013: inner call reverted: {inner}"));
            }
        }

        // Store the result regardless of success/failure
        self.simulated = Some(prepared);
        self.simulation_result = Some(result);
        Ok(self)
    }

    /// Checks that simulation was performed and succeeded.
    ///
    /// Returns `Ok(self)` if simulation was performed and all calls succeeded.
    /// Returns `Err(Error::SimulationNotPerformed)` if `simulate()` was not called.
    /// Returns `Err(Error::SimulationReverted { reason })` if simulation failed.
    ///
    /// This is useful for chaining to ensure reverting transactions are not submitted:
    /// ```ignore
    /// safe.batch()
    ///     .add_typed(target, call)
    ///     .simulate().await?
    ///     .simulation_success()?
    ///     .execute().await?
    /// ```
    pub fn simulation_success(self) -> Result<Self> {
        match &self.simulation_result {
            None => Err(Error::SimulationNotPerformed),
            Some(result) if !result.success => Err(Error::SimulationReverted {
                reason: result
                    .revert_reason
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
            }),
            Some(_) => Ok(self),
        }
    }

    /// Returns the simulation result if simulation was performed
    pub fn simulation_result(&self) -> Option<&SimulationResult> {
        self.simulation_result.as_ref()
    }

    /// Executes the multicall transaction
    ///
    /// The Safe transaction is the one [`SafeBuilder::prepare`] builds. After
    /// `simulate()` it is exactly the simulated transaction: the same fields and
    /// the same nonce. If the on-chain nonce moved since the simulation this fails
    /// with [`Error::NonceMismatch`], and if calls were added after the simulation
    /// it fails with [`Error::InvalidConfig`].
    ///
    /// # `safeTxGas`
    ///
    /// `safeTxGas` is the explicit value from `with_safe_tx_gas()` /
    /// `with_gas_limit()`, or `0`. It is never estimated. With `gasPrice == 0`
    /// (this library never pays refunds) the Safe forwards all remaining gas to
    /// the inner call, so `safeTxGas` does not cap it; the outer `execTransaction`
    /// gas is estimated by the provider when sending.
    ///
    /// # Consequence for failing transactions
    ///
    /// With `safeTxGas == 0` a failing inner transaction reverts the whole outer
    /// `execTransaction` with `GS013` rather than mining a successful receipt
    /// carrying an `ExecutionFailure` event. This usually surfaces before
    /// broadcast, as [`Error::InnerTransactionReverted`], when the provider
    /// estimates gas. The on-chain revert does not carry the inner reason, so use
    /// `simulate()` to find out why a transaction fails.
    ///
    /// `success` in the result requires both a successful receipt and the Safe's
    /// `ExecutionSuccess` event for this Safe transaction.
    pub async fn execute(self) -> Result<ExecutionResult> {
        let expected_nonce = self
            .nonce
            .or_else(|| self.simulated.as_ref().map(|p| p.params.nonce));
        let prepared = self.prepare_at(expected_nonce).await?;
        if let Some(simulated) = &self.simulated {
            if simulated != &prepared {
                return Err(Error::InvalidConfig(
                    "the batch changed after simulate(); simulate it again".to_string(),
                ));
            }
        }

        let signed = prepared.sign(&self.safe.signer).await?;
        let tx = <AnyNetwork as Network>::TransactionRequest::default()
            .with_from(self.safe.signer.address())
            .with_to(self.safe.address)
            .with_input(signed.exec_calldata());

        // The GS013 revert normally surfaces here: the provider estimates gas on
        // send, so the failing `execTransaction` is caught before broadcast.
        let pending_tx = self
            .safe
            .provider
            .send_transaction(tx)
            .await
            .map_err(|e| map_execution_error(e.to_string()))?;

        let receipt = pending_tx
            .get_receipt()
            .await
            .map_err(|e| map_execution_error(e.to_string()))?;

        // With a non-zero safeTxGas a failed inner call is mined successfully but
        // emits ExecutionFailure, so the receipt status alone is not enough.
        let outcome = decode_safe_outcome(
            &receipt_logs(&receipt),
            self.safe.address,
            prepared.safe_tx_hash,
        );
        let success = receipt.status() && outcome.is_success();

        Ok(ExecutionResult {
            tx_hash: receipt.transaction_hash,
            success,
        })
    }
}

impl<P> CallBuilder for SafeBuilder<'_, P>
where
    P: Provider<AnyNetwork> + Clone + Send + Sync + 'static,
{
    fn calls_mut(&mut self) -> &mut Vec<Call> {
        &mut self.calls
    }

    fn calls(&self) -> &Vec<Call> {
        &self.calls
    }

    fn with_gas_limit(self, gas_limit: u64) -> Self {
        SafeBuilder::with_gas_limit(self, gas_limit)
    }

    async fn simulate(self) -> Result<Self> {
        SafeBuilder::simulate(self).await
    }

    fn simulation_result(&self) -> Option<&SimulationResult> {
        self.simulation_result.as_ref()
    }

    fn simulation_success(self) -> Result<Self> {
        SafeBuilder::simulation_success(self)
    }
}

impl<P> crate::account::Account for Safe<P>
where
    P: Provider<AnyNetwork> + Clone + Send + Sync + 'static,
{
    type Provider = P;
    type Builder<'a> = SafeBuilder<'a, P> where Self: 'a;

    fn address(&self) -> Address {
        self.address
    }

    fn signer_address(&self) -> Address {
        self.signer.address()
    }

    fn config(&self) -> &ChainConfig {
        &self.config
    }

    fn provider(&self) -> &P {
        &self.provider
    }

    fn debug_output_dir(&self) -> Option<&Path> {
        self.debug_output_dir.as_deref()
    }

    async fn nonce(&self) -> Result<U256> {
        let safe = ISafe::new(self.address, &self.provider);
        let nonce = safe
            .nonce()
            .call()
            .await
            .map_err(|e| Error::Fetch {
                what: "nonce",
                reason: e.to_string(),
            })?;
        Ok(nonce)
    }

    fn batch(&self) -> SafeBuilder<'_, P> {
        SafeBuilder::new(self)
    }

    async fn execute_single(
        &self,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
    ) -> Result<ExecutionResult> {
        self.batch()
            .add(Call::new(to, value, data).with_operation(operation))
            .simulate()
            .await?
            .simulation_success()?
            .execute()
            .await
    }
}

/// `GS013` as the hex bytes it takes inside an ABI-encoded `Error(string)`
/// payload (`0x08c379a0...`), which is how most providers report the revert.
const GS013_ERROR_STRING_HEX: &str = "4753303133";

/// Whether a provider error describes Safe's `GS013` revert.
///
/// `execTransaction` reverts with `GS013` when the inner transaction fails while
/// `safeTxGas == 0` and `gasPrice == 0` - a deliberate fail-closed path that
/// discards the inner revert reason. Providers report it either as plain text
/// (`execution reverted: GS013`) or as the ABI-encoded `Error(string)` data blob,
/// so both forms are matched.
fn is_gs013_revert(reason: &str) -> bool {
    // Plain-text form. Safe emits the code uppercase, so match it exactly rather
    // than case-insensitively, which would misfire on ordinary prose.
    if reason.contains("GS013") {
        return true;
    }

    // ABI-encoded form. Providers differ on hex casing, so normalise first.
    reason.to_ascii_lowercase().contains(GS013_ERROR_STRING_HEX)
}

/// Map a failure from the outer `execTransaction` send onto an [`Error`],
/// promoting Safe's opaque `GS013` revert to [`Error::InnerTransactionReverted`]
/// so callers can match on it instead of string-matching. The original provider
/// message is preserved either way.
fn map_execution_error(reason: String) -> Error {
    if is_gs013_revert(&reason) {
        Error::InnerTransactionReverted { reason }
    } else {
        Error::ExecutionFailed { reason }
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports, reason = "glob import shared by tests that use varying subsets")]
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_call_params_single() {
        // This would need a mock provider to test fully
        // For now, just test that types compile correctly
        let _addr = address!("0x1234567890123456789012345678901234567890");
    }

    #[test]
    fn test_safe_singleton_slot_is_zero() {
        assert_eq!(SAFE_SINGLETON_SLOT, U256::ZERO);
    }

    #[test]
    fn detects_gs013_in_plain_text_revert() {
        // The message an RPC returns for a batch whose inner call reverts.
        assert!(is_gs013_revert(
            "server returned an error response: error code 3: execution reverted: GS013"
        ));
    }

    #[test]
    fn detects_gs013_in_abi_encoded_data() {
        // `Error(string)` selector + offset + length + "GS013" padded to 32 bytes.
        let data = "0x08c379a0\
                    0000000000000000000000000000000000000000000000000000000000000020\
                    0000000000000000000000000000000000000000000000000000000000000005\
                    4753303133000000000000000000000000000000000000000000000000000000";
        assert!(is_gs013_revert(&format!(
            "server returned an error response: error code 3: execution reverted, data: \"{data}\""
        )));
    }

    #[test]
    fn detects_gs013_regardless_of_hex_casing() {
        let payload = "0x08C379A000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000005475330313300000000000000000000000000000000000000000000000000000000";
        assert!(is_gs013_revert(payload));
        assert!(is_gs013_revert(&payload.to_ascii_lowercase()));
    }

    #[test]
    fn unrelated_provider_errors_are_not_gs013() {
        assert!(!is_gs013_revert(
            "insufficient funds for gas * price + value"
        ));
        assert!(!is_gs013_revert("nonce too low"));
        // A different Safe error code must not be swallowed by the GS013 branch.
        assert!(!is_gs013_revert("execution reverted: GS020"));
        // An unrelated ABI-encoded revert reason ("Insufficient balance").
        let insufficient_balance = "0x08c379a0\
            0000000000000000000000000000000000000000000000000000000000000020\
            0000000000000000000000000000000000000000000000000000000000000014\
            496e73756666696369656e742062616c616e6365000000000000000000000000";
        assert!(!is_gs013_revert(insufficient_balance));
    }

    #[test]
    fn map_execution_error_routes_by_revert_kind() {
        // GS013 gets the dedicated variant, with the provider message retained.
        assert!(matches!(
            map_execution_error("execution reverted: GS013".to_string()),
            Error::InnerTransactionReverted { reason } if reason == "execution reverted: GS013"
        ));

        // Everything else keeps the existing behaviour.
        assert!(matches!(
            map_execution_error("nonce too low".to_string()),
            Error::ExecutionFailed { reason } if reason == "nonce too low"
        ));
    }
}
