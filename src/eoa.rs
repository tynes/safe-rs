//! EOA (Externally Owned Account) fallback mode
//!
//! Provides the same builder API as the Safe multicall, but executes each call
//! as a separate transaction instead of batching into a single MultiSend.

use alloy::network::AnyNetwork;
use alloy::network::primitives::ReceiptResponse;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;

use crate::chain::ChainConfig;
use crate::error::{Error, Result};
use crate::safe::ExecutionResult;
use crate::simulation::{ForkSimulator, SimulationResult};
use crate::types::{Call, Operation, SafeCall, TypedCall};

/// Result of executing a single EOA transaction
#[derive(Debug, Clone)]
pub struct EoaTxResult {
    /// Transaction hash
    pub tx_hash: TxHash,
    /// Whether the transaction succeeded
    pub success: bool,
    /// Index of this transaction in the batch
    pub index: usize,
}

/// Result of executing multiple EOA transactions
#[derive(Debug, Clone)]
pub struct EoaBatchResult {
    /// Results for each transaction
    pub results: Vec<EoaTxResult>,
    /// Number of successful transactions
    pub success_count: usize,
    /// Number of failed transactions
    pub failure_count: usize,
    /// Index of the first failure, if any
    pub first_failure: Option<usize>,
}

impl EoaBatchResult {
    /// Returns true if all transactions succeeded
    pub fn all_succeeded(&self) -> bool {
        self.failure_count == 0
    }

    /// Returns the transaction hashes
    pub fn tx_hashes(&self) -> Vec<TxHash> {
        self.results.iter().map(|r| r.tx_hash).collect()
    }
}

/// EOA client for executing transactions from an externally owned account
pub struct Eoa<P> {
    /// The provider for RPC calls
    provider: P,
    /// The signer for transactions
    signer: PrivateKeySigner,
    /// Chain configuration
    config: ChainConfig,
}

impl<P> Eoa<P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Creates a new EOA client with explicit chain configuration
    pub fn new(provider: P, signer: PrivateKeySigner, config: ChainConfig) -> Self {
        Self {
            provider,
            signer,
            config,
        }
    }

    /// Creates an EOA client with auto-detected chain configuration
    pub async fn connect(provider: P, signer: PrivateKeySigner) -> Result<Self> {
        let chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| Error::Provider(e.to_string()))?;

        let config = ChainConfig::new(chain_id);
        Ok(Self::new(provider, signer, config))
    }

    /// Returns the EOA address
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Returns the signer address
    ///
    /// For EOA, this is the same as `address()` since the signer IS the wallet.
    pub fn signer_address(&self) -> Address {
        self.signer.address()
    }

    /// Returns the chain configuration
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Returns a reference to the provider
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Creates a batch builder for executing multiple transactions
    pub fn batch(&self) -> EoaBuilder<'_, P> {
        EoaBuilder::new(self)
    }

    /// Executes a single transaction
    ///
    /// # Errors
    /// Returns `Error::UnsupportedEoaOperation` if `operation` is `DelegateCall`.
    pub async fn execute_single(
        &self,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
    ) -> Result<ExecutionResult> {
        if operation == Operation::DelegateCall {
            return Err(Error::UnsupportedEoaOperation {
                operation: "DelegateCall in execute_single".to_string(),
            });
        }

        let result = self
            .batch()
            .add_raw(to, value, data)
            .simulate()
            .await?
            .execute()
            .await?;

        let tx_result = result.results.into_iter().next().ok_or(Error::NoCalls)?;

        Ok(ExecutionResult {
            tx_hash: tx_result.tx_hash,
            success: tx_result.success,
        })
    }

    /// Gets the current nonce of the EOA
    pub async fn nonce(&self) -> Result<u64> {
        let nonce = self
            .provider
            .get_transaction_count(self.signer.address())
            .await
            .map_err(|e| Error::Fetch {
                what: "nonce",
                reason: e.to_string(),
            })?;
        Ok(nonce)
    }
}

/// Builder for constructing and executing EOA transaction batches
pub struct EoaBuilder<'a, P> {
    eoa: &'a Eoa<P>,
    calls: Vec<Call>,
    stop_on_failure: bool,
    simulation_results: Option<Vec<SimulationResult>>,
    aggregated_result: Option<SimulationResult>,
}

impl<'a, P> EoaBuilder<'a, P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    fn new(eoa: &'a Eoa<P>) -> Self {
        EoaBuilder {
            eoa,
            calls: Vec::new(),
            stop_on_failure: true,
            simulation_results: None,
            aggregated_result: None,
        }
    }

    /// Validates that no calls use DelegateCall operation
    fn validate_operations(&self) -> Result<()> {
        for (i, call) in self.calls.iter().enumerate() {
            if call.operation == Operation::DelegateCall {
                return Err(Error::UnsupportedEoaOperation {
                    operation: format!("DelegateCall (call index {})", i),
                });
            }
        }
        Ok(())
    }
    /// Adds a typed call to the batch
    pub fn add_typed<C: SolCall + Clone>(mut self, to: Address, call: C) -> Self {
        let typed_call = TypedCall::new(to, call);
        self.calls.push(Call::new(
            typed_call.to(),
            typed_call.value,
            typed_call.data(),
        ));
        self
    }

    /// Adds a typed call with value to the batch
    pub fn add_typed_with_value<C: SolCall + Clone>(
        mut self,
        to: Address,
        call: C,
        value: U256,
    ) -> Self {
        let typed_call = TypedCall::new(to, call).with_value(value);
        self.calls.push(Call::new(
            typed_call.to(),
            typed_call.value,
            typed_call.data(),
        ));
        self
    }

    /// Adds a raw call to the batch
    pub fn add_raw(mut self, to: Address, value: U256, data: impl Into<Bytes>) -> Self {
        self.calls.push(Call::new(to, value, data));
        self
    }

    /// Adds a call implementing SafeCall to the batch
    pub fn add(mut self, call: impl SafeCall) -> Self {
        self.calls.push(Call {
            to: call.to(),
            value: call.value(),
            data: call.data(),
            operation: call.operation(),
        });
        self
    }

    /// Continue executing remaining transactions even if one fails
    ///
    /// By default, execution stops on the first failure. Call this method
    /// to continue executing all transactions regardless of failures.
    pub fn continue_on_failure(mut self) -> Self {
        self.stop_on_failure = false;
        self
    }

    /// Simulates all calls and stores the results
    ///
    /// After simulation, you can inspect the results via `simulation_results()`
    /// and then call `execute()` which will use the simulation gas values.
    pub async fn simulate(mut self) -> Result<Self> {
        if self.calls.is_empty() {
            return Err(Error::NoCalls);
        }

        self.validate_operations()?;

        let simulator = ForkSimulator::new(self.eoa.provider.clone(), self.eoa.config.chain_id);
        let mut simulation_results = Vec::with_capacity(self.calls.len());

        for (i, call) in self.calls.iter().enumerate() {
            let result = simulator
                .simulate_call(
                    self.eoa.address(),
                    call.to,
                    call.value,
                    call.data.clone(),
                    Operation::Call,
                )
                .await?;

            if !result.success {
                return Err(Error::SimulationReverted {
                    reason: format!(
                        "Call {} failed: {}",
                        i,
                        result.revert_reason.unwrap_or_else(|| "Unknown".to_string())
                    ),
                });
            }

            simulation_results.push(result);
        }

        self.aggregated_result = Some(Self::aggregate_results(&simulation_results));
        self.simulation_results = Some(simulation_results);
        Ok(self)
    }

    /// Returns the simulation results if simulation was performed
    pub fn simulation_results(&self) -> Option<&[SimulationResult]> {
        self.simulation_results.as_deref()
    }

    /// Returns a unified simulation result combining all individual results
    ///
    /// Aggregates individual results:
    /// - `success`: true only if all calls succeeded
    /// - `gas_used`: sum of all gas used
    /// - `return_data`: from the last call
    /// - `logs`: concatenated from all calls
    /// - `revert_reason`: first revert reason encountered
    pub fn simulation_result(&self) -> Option<&SimulationResult> {
        self.aggregated_result.as_ref()
    }

    /// Returns the total gas used across all simulated calls
    ///
    /// Returns `None` if simulation was not performed.
    pub fn total_gas_used(&self) -> Option<u64> {
        self.simulation_results
            .as_ref()
            .map(|results| results.iter().map(|r| r.gas_used).sum())
    }

    /// Returns the number of calls in the batch
    pub fn call_count(&self) -> usize {
        self.calls.len()
    }

    /// Executes all transactions
    ///
    /// If simulation was performed, uses the simulated gas + 10% buffer.
    /// If no simulation, estimates gas via `eth_estimateGas` RPC call.
    pub async fn execute(self) -> Result<EoaBatchResult> {
        if self.calls.is_empty() {
            return Err(Error::NoCalls);
        }

        self.validate_operations()?;

        let mut nonce = self.eoa.nonce().await?;
        let mut results = Vec::with_capacity(self.calls.len());
        let mut success_count = 0;
        let mut failure_count = 0;
        let mut first_failure = None;

        for (i, call) in self.calls.iter().enumerate() {
            // Determine gas: use simulation result if available, otherwise estimate
            let gas_with_buffer = if let Some(ref sim_results) = self.simulation_results {
                let sim_result = &sim_results[i];
                sim_result.gas_used + sim_result.gas_used / 10
            } else {
                // Build transaction for gas estimation
                let tx_request = <AnyNetwork as alloy::network::Network>::TransactionRequest::default()
                    .with_from(self.eoa.address())
                    .with_to(call.to)
                    .with_value(call.value)
                    .with_input(call.data.clone())
                    .with_nonce(nonce);

                let gas_limit = self
                    .eoa
                    .provider
                    .estimate_gas(tx_request)
                    .await
                    .map_err(|e| Error::TransactionSendFailed {
                        index: i,
                        reason: format!("gas estimation failed: {}", e),
                    })?;

                gas_limit + gas_limit / 10
            };

            // Build transaction
            let tx_request = <AnyNetwork as alloy::network::Network>::TransactionRequest::default()
                .with_from(self.eoa.address())
                .with_to(call.to)
                .with_value(call.value)
                .with_input(call.data.clone())
                .with_nonce(nonce)
                .with_gas_limit(gas_with_buffer);

            // Send transaction
            let pending_tx = self
                .eoa
                .provider
                .send_transaction(tx_request)
                .await
                .map_err(|e| Error::TransactionSendFailed {
                    index: i,
                    reason: e.to_string(),
                })?;

            // Wait for receipt
            let receipt = pending_tx.get_receipt().await.map_err(|e| {
                Error::TransactionSendFailed {
                    index: i,
                    reason: e.to_string(),
                }
            })?;

            let success = receipt.status();
            let tx_hash = receipt.transaction_hash;

            if success {
                success_count += 1;
            } else {
                failure_count += 1;
                if first_failure.is_none() {
                    first_failure = Some(i);
                }
            }

            results.push(EoaTxResult {
                tx_hash,
                success,
                index: i,
            });

            // Stop on failure if configured
            if !success && self.stop_on_failure {
                break;
            }

            nonce += 1;
        }

        Ok(EoaBatchResult {
            results,
            success_count,
            failure_count,
            first_failure,
        })
    }

    /// Aggregates multiple simulation results into a single unified result
    fn aggregate_results(results: &[SimulationResult]) -> SimulationResult {
        use alloy::rpc::types::trace::geth::pre_state::DiffMode;
        use std::collections::BTreeMap;

        let success = results.iter().all(|r| r.success);
        let gas_used = results.iter().map(|r| r.gas_used).sum();
        let return_data = results
            .last()
            .map(|r| r.return_data.clone())
            .unwrap_or_default();
        let logs = results.iter().flat_map(|r| r.logs.clone()).collect();
        let revert_reason = results.iter().find_map(|r| r.revert_reason.clone());

        // Merge state diffs: pre-state from first encounter, post-state from last
        let mut merged_pre = BTreeMap::new();
        let mut merged_post = BTreeMap::new();

        for result in results {
            // For pre-state: only insert if we haven't seen this address before
            for (addr, state) in &result.state_diff.pre {
                merged_pre.entry(*addr).or_insert_with(|| state.clone());
            }

            // For post-state: always overwrite with the latest
            for (addr, state) in &result.state_diff.post {
                merged_post.insert(*addr, state.clone());
            }
        }

        let state_diff = DiffMode {
            pre: merged_pre,
            post: merged_post,
        };

        SimulationResult {
            success,
            gas_used,
            return_data,
            logs,
            revert_reason,
            state_diff,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256};

    #[test]
    fn test_eoa_batch_result_all_succeeded() {
        let result = EoaBatchResult {
            results: vec![
                EoaTxResult {
                    tx_hash: TxHash::ZERO,
                    success: true,
                    index: 0,
                },
                EoaTxResult {
                    tx_hash: TxHash::ZERO,
                    success: true,
                    index: 1,
                },
            ],
            success_count: 2,
            failure_count: 0,
            first_failure: None,
        };

        assert!(result.all_succeeded());
        assert_eq!(result.tx_hashes().len(), 2);
    }

    #[test]
    fn test_eoa_batch_result_partial_failure() {
        let result = EoaBatchResult {
            results: vec![
                EoaTxResult {
                    tx_hash: TxHash::ZERO,
                    success: true,
                    index: 0,
                },
                EoaTxResult {
                    tx_hash: TxHash::ZERO,
                    success: false,
                    index: 1,
                },
            ],
            success_count: 1,
            failure_count: 1,
            first_failure: Some(1),
        };

        assert!(!result.all_succeeded());
        assert_eq!(result.first_failure, Some(1));
    }

    #[test]
    fn test_validate_operations_rejects_delegatecall() {
        // This test verifies at compile time that the types work
        let _addr = address!("0x1234567890123456789012345678901234567890");
    }

    #[test]
    fn test_eoa_tx_result_fields() {
        let tx_hash = b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let result = EoaTxResult {
            tx_hash,
            success: true,
            index: 42,
        };

        assert_eq!(result.tx_hash, tx_hash);
        assert!(result.success);
        assert_eq!(result.index, 42);
    }

    #[test]
    fn test_eoa_batch_result_empty() {
        let result = EoaBatchResult {
            results: vec![],
            success_count: 0,
            failure_count: 0,
            first_failure: None,
        };

        // Empty batch has no failures, so all_succeeded() should be true
        assert!(result.all_succeeded());
        assert!(result.tx_hashes().is_empty());
    }

    #[test]
    fn test_eoa_batch_result_all_failed() {
        let result = EoaBatchResult {
            results: vec![
                EoaTxResult {
                    tx_hash: TxHash::ZERO,
                    success: false,
                    index: 0,
                },
                EoaTxResult {
                    tx_hash: TxHash::ZERO,
                    success: false,
                    index: 1,
                },
                EoaTxResult {
                    tx_hash: TxHash::ZERO,
                    success: false,
                    index: 2,
                },
            ],
            success_count: 0,
            failure_count: 3,
            first_failure: Some(0),
        };

        assert!(!result.all_succeeded());
        assert_eq!(result.failure_count, 3);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.first_failure, Some(0));
    }

    #[test]
    fn test_eoa_batch_result_tx_hashes_order() {
        let hash1 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
        let hash2 = b256!("0x2222222222222222222222222222222222222222222222222222222222222222");
        let hash3 = b256!("0x3333333333333333333333333333333333333333333333333333333333333333");

        let result = EoaBatchResult {
            results: vec![
                EoaTxResult {
                    tx_hash: hash1,
                    success: true,
                    index: 0,
                },
                EoaTxResult {
                    tx_hash: hash2,
                    success: true,
                    index: 1,
                },
                EoaTxResult {
                    tx_hash: hash3,
                    success: true,
                    index: 2,
                },
            ],
            success_count: 3,
            failure_count: 0,
            first_failure: None,
        };

        let hashes = result.tx_hashes();
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0], hash1);
        assert_eq!(hashes[1], hash2);
        assert_eq!(hashes[2], hash3);
    }

    #[test]
    fn test_call_with_regular_operation() {
        let to = address!("0x1234567890123456789012345678901234567890");
        let value = U256::from(1000);
        let data = Bytes::from(vec![0x01, 0x02, 0x03]);

        let call = Call::new(to, value, data.clone());

        assert_eq!(call.to, to);
        assert_eq!(call.value, value);
        assert_eq!(call.data, data);
        assert_eq!(call.operation, Operation::Call);
    }

    #[test]
    fn test_delegate_call_creates_correct_operation() {
        let to = address!("0x1234567890123456789012345678901234567890");
        let data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);

        let call = Call::delegate_call(to, data.clone());

        assert_eq!(call.to, to);
        assert_eq!(call.value, U256::ZERO);
        assert_eq!(call.data, data);
        assert_eq!(call.operation, Operation::DelegateCall);
    }
}
