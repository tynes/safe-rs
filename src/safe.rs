//! Safe client and SafeBuilder implementation

use std::path::{Path, PathBuf};

use alloy::network::primitives::ReceiptResponse;
use alloy::network::{AnyNetwork, Network};
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;

use crate::account::Account;
use crate::chain::{ChainAddresses, ChainConfig};
use crate::contracts::{IMultiSend, IMultiSendCallOnly, ISafe};
use crate::encoding::{compute_safe_transaction_hash, encode_multisend_data, SafeTxParams};
use crate::error::{Error, Result};
use crate::signing::sign_hash;
use crate::simulation::{ForkSimulator, SimulationResult};
use crate::types::{Call, CallBuilder, Operation};

/// Safe proxy singleton storage slot (slot 0)
/// Safe proxies store the implementation/singleton address at storage slot 0,
/// as the first declared variable in the proxy contract.
pub const SAFE_SINGLETON_SLOT: U256 = U256::ZERO;

/// Gas price used for every `execTransaction` built by this crate: zero, i.e. the
/// Safe pays no gas refund and the executing EOA bears the whole cost.
///
/// This is load-bearing, not cosmetic. `Safe.execTransaction` forwards
///
/// ```solidity
/// success = execute(to, value, data, operation, gasPrice == 0 ? (gasleft() - 2500) : safeTxGas);
/// ```
///
/// so while `gasPrice == 0` the inner call gets all remaining gas and `safeTxGas`
/// only feeds the GS010 pre-check and the GS013 branch. That is what makes
/// `safe_tx_gas = 0` viable for MultiSend delegatecall batches (see
/// `SafeBuilder::execute`). Supporting refunds (a non-zero gas price, `gas_token`
/// or `refund_receiver`) means `safeTxGas` starts gating the inner call, so every
/// site that leaves `safe_tx_gas` at zero must be revisited at the same time.
const NO_REFUND_GAS_PRICE: U256 = U256::ZERO;

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

    /// Verifies that the signer is an owner and threshold is 1
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
    safe_tx_gas: Option<U256>,
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
            safe_tx_gas: None,
            simulation_result: None,
        }
    }

    /// Use MultiSendCallOnly instead of MultiSend (no delegatecall allowed)
    pub fn call_only(mut self) -> Self {
        self.use_call_only = true;
        self
    }

    /// Manually sets the safeTxGas instead of auto-estimating
    pub fn with_safe_tx_gas(mut self, gas: U256) -> Self {
        self.safe_tx_gas = Some(gas);
        self
    }

    /// Sets the top-level `safe_tx_gas` for the entire Safe transaction.
    ///
    /// This is equivalent to `with_safe_tx_gas(U256::from(gas_limit))`.
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.safe_tx_gas = Some(U256::from(gas_limit));
        self
    }

    /// Simulates the multicall and stores the result
    ///
    /// This method does not return an error if the simulation reverts. Instead,
    /// the result (success or failure) is stored internally. Use `simulation_success()`
    /// to check if the simulation succeeded before calling `execute()`.
    ///
    /// After simulation, you can inspect the results via `simulation_result()`
    /// and then call `execute()` which will use the simulation gas.
    pub async fn simulate(mut self) -> Result<Self> {
        if self.calls.is_empty() {
            return Err(Error::NoCalls);
        }

        let (to, value, data, operation) = self.build_call_params()?;

        let mut simulator = ForkSimulator::new(self.safe.provider.clone(), self.safe.config.chain_id);

        // Configure debug output if the Safe has a debug output directory
        if let Some(dir) = &self.safe.debug_output_dir {
            simulator = simulator.with_debug_output_dir(dir.clone(), self.safe.address);
        }

        // For DelegateCall operations (like MultiSend), we need to simulate through
        // Safe's execTransaction because the target contract expects delegatecall context.
        // For regular Call operations, we can simulate the inner call directly.
        let result = match operation {
            Operation::DelegateCall => {
                // Simulate through Safe.execTransaction
                self.simulate_via_exec_transaction(&simulator, to, value, data, operation)
                    .await?
            }
            Operation::Call => {
                simulator
                    .simulate_call(self.safe.address, to, value, data, operation)
                    .await?
            }
        };

        // Store the result regardless of success/failure
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

    /// Simulates by calling Safe.execTransaction
    ///
    /// This is needed for DelegateCall operations because the target contract
    /// (like MultiSend) expects to be called via delegatecall.
    async fn simulate_via_exec_transaction(
        &self,
        simulator: &ForkSimulator<P>,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
    ) -> Result<SimulationResult> {
        // Get nonce
        let nonce = self.safe.nonce().await?;

        // Use a high gas estimate for simulation - we'll refine it after
        let safe_tx_gas = U256::from(10_000_000);

        // No gas refunds: the executing EOA pays. Same invariant as
        // `SafeBuilder::execute` - keep both sites in sync if refunds are added.
        let gas_price = NO_REFUND_GAS_PRICE;

        // Build SafeTxParams
        let params = SafeTxParams {
            to,
            value,
            data: data.clone(),
            operation,
            safe_tx_gas,
            base_gas: U256::ZERO,
            gas_price,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce,
        };

        // Compute transaction hash
        let tx_hash = compute_safe_transaction_hash(
            self.safe.config.chain_id,
            self.safe.address,
            &params,
        );

        // Sign the hash
        let signature = sign_hash(&self.safe.signer, tx_hash).await?;

        // Build the execTransaction call
        let exec_call = ISafe::execTransactionCall {
            to: params.to,
            value: params.value,
            data: params.data,
            operation: params.operation.as_u8(),
            safeTxGas: params.safe_tx_gas,
            baseGas: params.base_gas,
            gasPrice: params.gas_price,
            gasToken: params.gas_token,
            refundReceiver: params.refund_receiver,
            signatures: signature,
        };

        let exec_data = Bytes::from(exec_call.abi_encode());

        // Simulate the execTransaction call
        simulator
            .simulate_call(
                self.safe.signer.address(), // EOA calls Safe
                self.safe.address,           // Safe address
                U256::ZERO,                  // No ETH value for outer call
                exec_data,
                Operation::Call,             // Regular call to Safe
            )
            .await
    }

    /// Returns the simulation result if simulation was performed
    pub fn simulation_result(&self) -> Option<&SimulationResult> {
        self.simulation_result.as_ref()
    }

    /// Executes the multicall transaction
    ///
    /// # How `safeTxGas` is chosen
    ///
    /// The first rule that applies wins:
    ///
    /// 1. **Explicit** — `with_safe_tx_gas()` or `with_gas_limit()` was called:
    ///    that value is used verbatim, no estimation happens.
    /// 2. **Simulated** — `simulate()` was performed: the simulated `gas_used`
    ///    plus a 10% buffer.
    /// 3. **`DelegateCall` batch** — the transaction is a `DelegateCall` into
    ///    `MultiSend`, which is how any batch of more than one call is sent: `0`.
    ///    A raw `eth_estimateGas` on the inner `(to, data)` would model a direct
    ///    `CALL` into the `MultiSend` singleton and revert its
    ///    `address(this) != _self` guard, so the estimate is skipped entirely.
    ///    The outer `execTransaction` send still does its own,
    ///    operation-correct estimate.
    /// 4. **Single plain `Call`** — `eth_estimateGas` on the inner call plus a
    ///    10% buffer.
    ///
    /// # Why `0` is safe
    ///
    /// The Safe forwards `gasPrice == 0 ? gasleft() - 2500 : safeTxGas` to the
    /// inner call, and this library always submits with `gasPrice == 0`. So
    /// `safeTxGas` never caps the inner call's gas; it only feeds the `GS010`
    /// pre-check (trivially satisfied at `0`) and the `GS013`
    /// "internal transaction must succeed" branch.
    ///
    /// # Consequence for failing transactions
    ///
    /// That `GS013` branch is user-visible: with `safeTxGas == 0` and
    /// `gasPrice == 0`, a failing inner transaction reverts the whole outer
    /// `execTransaction` call rather than mining a successful receipt carrying
    /// an `ExecutionFailure` event. The on-chain revert does not carry the inner
    /// reason, so use `simulate()` to find out why a transaction fails.
    pub async fn execute(self) -> Result<ExecutionResult> {
        if self.calls.is_empty() {
            return Err(Error::NoCalls);
        }

        let (to, value, data, operation) = self.build_call_params()?;

        // Get nonce
        let nonce = self.safe.nonce().await?;

        // No gas refunds: the executing EOA pays. This is what makes
        // `safe_tx_gas = 0` safe below - see the delegatecall arm.
        let gas_price = NO_REFUND_GAS_PRICE;

        // Determine safe_tx_gas: explicit > simulation > estimate
        let safe_tx_gas = match (&self.simulation_result, self.safe_tx_gas) {
            (_, Some(gas)) => gas, // User provided explicit gas
            (Some(sim), None) => {
                // Use simulation result + 10% buffer
                let gas_used = sim.gas_used;
                U256::from(gas_used + gas_used / 10)
            }
            // A raw `eth_estimateGas` against the inner `(to, data)` only models the
            // call correctly for a plain Call. For a DelegateCall (MultiSend batch)
            // it models a direct CALL into the MultiSend singleton, which reverts its
            // `address(this) != _self` guard ("MultiSend should only be called via
            // delegatecall"). The inner safe_tx_gas may be 0 (forward all available
            // gas); the outer execTransaction send does its own operation-correct
            // eth_estimateGas. So skip the broken estimate.
            //
            // "Forward all available gas" holds only while `gas_price == 0`: the
            // Safe passes `gasleft() - 2500` to the inner call when the gas price
            // is zero, and exactly `safeTxGas` otherwise. See NO_REFUND_GAS_PRICE.
            (None, None) if operation == Operation::DelegateCall => {
                debug_assert!(
                    gas_price.is_zero(),
                    "safe_tx_gas = 0 only forwards all available gas while gas_price == 0; \
                     with a non-zero gas_price the Safe would forward zero gas to the inner call"
                );
                U256::ZERO
            }
            (None, None) => {
                // Estimate gas via RPC (valid for a plain Call to `to`).
                use alloy::network::TransactionBuilder;
                let tx_request = <AnyNetwork as alloy::network::Network>::TransactionRequest::default()
                    .with_from(self.safe.address)
                    .with_to(to)
                    .with_value(value)
                    .with_input(data.clone());

                let estimated = self
                    .safe
                    .provider
                    .estimate_gas(tx_request)
                    .await
                    .map_err(|e| Error::Provider(format!("gas estimation failed: {}", e)))?;

                // Add 10% buffer
                U256::from(estimated + estimated / 10)
            }
        };

        // Build SafeTxParams
        let params = SafeTxParams {
            to,
            value,
            data: data.clone(),
            operation,
            safe_tx_gas,
            base_gas: U256::ZERO,
            gas_price,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce,
        };

        // Compute transaction hash
        let tx_hash = compute_safe_transaction_hash(
            self.safe.config.chain_id,
            self.safe.address,
            &params,
        );

        // Sign the hash
        let signature = sign_hash(&self.safe.signer, tx_hash).await?;

        // Build the execTransaction call
        let exec_call = ISafe::execTransactionCall {
            to: params.to,
            value: params.value,
            data: params.data,
            operation: params.operation.as_u8(),
            safeTxGas: params.safe_tx_gas,
            baseGas: params.base_gas,
            gasPrice: params.gas_price,
            gasToken: params.gas_token,
            refundReceiver: params.refund_receiver,
            signatures: signature,
        };

        // Execute the transaction through the provider
        let safe_contract = ISafe::new(self.safe.address, &self.safe.provider);

        let builder = safe_contract.execTransaction(
            exec_call.to,
            exec_call.value,
            exec_call.data,
            exec_call.operation,
            exec_call.safeTxGas,
            exec_call.baseGas,
            exec_call.gasPrice,
            exec_call.gasToken,
            exec_call.refundReceiver,
            exec_call.signatures,
        );

        // The GS013 revert normally surfaces here: alloy pre-estimates gas on
        // `send()`, so the failing `execTransaction` is caught before broadcast.
        let pending_tx = builder
            .send()
            .await
            .map_err(|e| map_execution_error(e.to_string()))?;

        let receipt = pending_tx
            .get_receipt()
            .await
            .map_err(|e| map_execution_error(e.to_string()))?;

        // Check if Safe execution succeeded
        let success = receipt.status();

        Ok(ExecutionResult {
            tx_hash: receipt.transaction_hash,
            success,
        })
    }

    fn build_call_params(&self) -> Result<(Address, U256, Bytes, Operation)> {
        if self.calls.len() == 1 {
            // Single call - execute directly, honoring the call's own operation
            let call = &self.calls[0];
            Ok((call.to, call.value, call.data.clone(), call.operation))
        } else {
            // Multiple calls - use MultiSend
            let multisend_data = encode_multisend_data(&self.calls);

            let (multisend_address, calldata) = if self.use_call_only {
                let call = IMultiSendCallOnly::multiSendCall {
                    transactions: multisend_data,
                };
                (
                    self.safe.addresses().multi_send_call_only,
                    Bytes::from(call.abi_encode()),
                )
            } else {
                let call = IMultiSend::multiSendCall {
                    transactions: multisend_data,
                };
                (
                    self.safe.addresses().multi_send,
                    Bytes::from(call.abi_encode()),
                )
            };

            // MultiSend is called with zero value; individual call values are encoded in the data
            Ok((multisend_address, U256::ZERO, calldata, Operation::DelegateCall))
        }
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
    #[allow(unused_imports)]
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
    fn no_refund_gas_price_is_zero() {
        // `SafeBuilder::execute` sends DelegateCall (MultiSend) batches with
        // safe_tx_gas = 0, which forwards all remaining gas only while the Safe
        // sees gasPrice == 0. A non-zero gas price makes safeTxGas gate the inner
        // call, so a zero safe_tx_gas would forward zero gas and every batch would
        // emit ExecutionFailure. If this assertion has to change, the safe_tx_gas
        // arms in `execute()` must change with it.
        assert!(NO_REFUND_GAS_PRICE.is_zero());
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
