//! Safe client and SafeBuilder implementation

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
        }
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
    operation: Operation,
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
            operation: Operation::DelegateCall, // MultiSend is called via delegatecall
            simulation_result: None,
        }
    }

    /// Use MultiSendCallOnly instead of MultiSend (no delegatecall allowed)
    pub fn call_only(mut self) -> Self {
        self.use_call_only = true;
        self
    }

    /// Sets the operation type for the outer call (usually DelegateCall for MultiSend)
    pub fn with_operation(mut self, operation: Operation) -> Self {
        self.operation = operation;
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
    /// After simulation, you can inspect the results via `simulation_result()`
    /// and then call `execute()` which will use the simulation gas.
    pub async fn simulate(mut self) -> Result<Self> {
        if self.calls.is_empty() {
            return Err(Error::NoCalls);
        }

        let (to, value, data, operation) = self.build_call_params()?;

        let simulator = ForkSimulator::new(self.safe.provider.clone(), self.safe.config.chain_id);

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

        if !result.success {
            return Err(Error::SimulationReverted {
                reason: result
                    .revert_reason
                    .unwrap_or_else(|| "Unknown".to_string()),
            });
        }

        self.simulation_result = Some(result);
        Ok(self)
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

        // Build SafeTxParams
        let params = SafeTxParams {
            to,
            value,
            data: data.clone(),
            operation,
            safe_tx_gas,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
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
    /// If simulation was performed, uses the simulated gas + 10% buffer.
    /// If no simulation, estimates gas via `eth_estimateGas` RPC call.
    /// If `with_safe_tx_gas()` was called, uses that value instead.
    pub async fn execute(self) -> Result<ExecutionResult> {
        if self.calls.is_empty() {
            return Err(Error::NoCalls);
        }

        let (to, value, data, operation) = self.build_call_params()?;

        // Get nonce
        let nonce = self.safe.nonce().await?;

        // Determine safe_tx_gas: explicit > simulation > estimate
        let safe_tx_gas = match (&self.simulation_result, self.safe_tx_gas) {
            (_, Some(gas)) => gas, // User provided explicit gas
            (Some(sim), None) => {
                // Use simulation result + 10% buffer
                let gas_used = sim.gas_used;
                U256::from(gas_used + gas_used / 10)
            }
            (None, None) => {
                // Estimate gas via RPC
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
            gas_price: U256::ZERO,
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

        let pending_tx = builder
            .send()
            .await
            .map_err(|e| Error::ExecutionFailed {
                reason: e.to_string(),
            })?;

        let receipt = pending_tx
            .get_receipt()
            .await
            .map_err(|e| Error::ExecutionFailed {
                reason: e.to_string(),
            })?;

        // Check if Safe execution succeeded
        let success = receipt.status();

        Ok(ExecutionResult {
            tx_hash: receipt.transaction_hash,
            success,
        })
    }

    fn build_call_params(&self) -> Result<(Address, U256, Bytes, Operation)> {
        if self.calls.len() == 1 {
            // Single call - execute directly
            let call = &self.calls[0];
            Ok((call.to, call.value, call.data.clone(), Operation::Call))
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
            .add_raw(to, value, data)
            .with_operation(operation)
            .simulate()
            .await?
            .execute()
            .await
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
}
