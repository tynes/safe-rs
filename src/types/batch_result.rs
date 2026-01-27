//! Unified batch result types for Safe and EOA transactions

use alloy::primitives::TxHash;

use crate::eoa::EoaBatchResult;
use crate::safe::ExecutionResult;
use crate::simulation::SimulationResult;

/// Unified result of executing a batch of transactions
///
/// This provides a common interface for both Safe (atomic multicall) and
/// EOA (sequential transactions) execution results.
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Transaction hashes (Safe has 1, EOA has N)
    pub tx_hashes: Vec<TxHash>,
    /// Whether all transactions succeeded
    pub success: bool,
    /// Number of successful transactions
    pub success_count: usize,
    /// Number of failed transactions
    pub failure_count: usize,
    /// Whether the batch was executed atomically (Safe=true, EOA=false)
    pub atomic: bool,
}

impl BatchResult {
    /// Creates a BatchResult from a Safe execution result
    pub fn from_safe(result: ExecutionResult) -> Self {
        BatchResult {
            tx_hashes: vec![result.tx_hash],
            success: result.success,
            success_count: usize::from(result.success),
            failure_count: usize::from(!result.success),
            atomic: true,
        }
    }

    /// Creates a BatchResult from an EOA batch result
    pub fn from_eoa(result: EoaBatchResult) -> Self {
        BatchResult {
            tx_hashes: result.tx_hashes(),
            success: result.all_succeeded(),
            success_count: result.success_count,
            failure_count: result.failure_count,
            atomic: false,
        }
    }

    /// Returns true if all transactions succeeded
    pub fn all_succeeded(&self) -> bool {
        self.success
    }
}

/// Unified result of simulating a batch of transactions
///
/// This provides a common interface for simulation results from both
/// Safe (single multicall simulation) and EOA (multiple individual simulations).
#[derive(Debug, Clone)]
pub struct BatchSimulationResult {
    /// Individual simulation results for each call
    pub results: Vec<SimulationResult>,
    /// Total gas used across all simulated calls
    pub total_gas_used: u64,
    /// Whether the batch will execute atomically (Safe=true, EOA=false)
    pub atomic: bool,
}

impl BatchSimulationResult {
    /// Creates a BatchSimulationResult from a Safe simulation result
    pub fn from_safe(result: SimulationResult) -> Self {
        let gas_used = result.gas_used;
        BatchSimulationResult {
            results: vec![result],
            total_gas_used: gas_used,
            atomic: true,
        }
    }

    /// Creates a BatchSimulationResult from EOA simulation results
    pub fn from_eoa(results: Vec<SimulationResult>) -> Self {
        let total_gas_used = results.iter().map(|r| r.gas_used).sum();
        BatchSimulationResult {
            results,
            total_gas_used,
            atomic: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eoa::EoaTxResult;

    #[test]
    fn test_batch_result_from_safe_success() {
        let safe_result = ExecutionResult {
            tx_hash: TxHash::ZERO,
            success: true,
        };

        let result = BatchResult::from_safe(safe_result);

        assert_eq!(result.tx_hashes.len(), 1);
        assert!(result.success);
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 0);
        assert!(result.atomic);
    }

    #[test]
    fn test_batch_result_from_safe_failure() {
        let safe_result = ExecutionResult {
            tx_hash: TxHash::ZERO,
            success: false,
        };

        let result = BatchResult::from_safe(safe_result);

        assert!(!result.success);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 1);
        assert!(result.atomic);
    }

    #[test]
    fn test_batch_result_from_eoa() {
        let eoa_result = EoaBatchResult {
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

        let result = BatchResult::from_eoa(eoa_result);

        assert_eq!(result.tx_hashes.len(), 2);
        assert!(result.success);
        assert_eq!(result.success_count, 2);
        assert_eq!(result.failure_count, 0);
        assert!(!result.atomic);
    }

    #[test]
    fn test_batch_simulation_result_from_safe() {
        let sim_result = SimulationResult {
            success: true,
            gas_used: 50000,
            return_data: Default::default(),
            revert_reason: None,
            logs: vec![],
            state_diff: Default::default(),
        };

        let result = BatchSimulationResult::from_safe(sim_result);

        assert_eq!(result.results.len(), 1);
        assert_eq!(result.total_gas_used, 50000);
        assert!(result.atomic);
    }

    #[test]
    fn test_batch_simulation_result_from_eoa() {
        let sim_results = vec![
            SimulationResult {
                success: true,
                gas_used: 21000,
                return_data: Default::default(),
                revert_reason: None,
                logs: vec![],
                state_diff: Default::default(),
            },
            SimulationResult {
                success: true,
                gas_used: 30000,
                return_data: Default::default(),
                revert_reason: None,
                logs: vec![],
                state_diff: Default::default(),
            },
        ];

        let result = BatchSimulationResult::from_eoa(sim_results);

        assert_eq!(result.results.len(), 2);
        assert_eq!(result.total_gas_used, 51000);
        assert!(!result.atomic);
    }
}
