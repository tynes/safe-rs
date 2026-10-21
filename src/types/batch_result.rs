//! Unified batch result types for Safe and EOA transactions

use alloy::primitives::TxHash;
use serde::{Deserialize, Serialize};

use crate::eoa::EoaBatchResult;
use crate::safe::ExecutionResult;
#[cfg(feature = "simulation")]
use crate::simulation::SimulationResult;

/// Unified result of executing a batch of transactions
///
/// This provides a common interface for both Safe (atomic multicall) and
/// EOA (sequential transactions) execution results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[cfg(feature = "simulation")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSimulationResult {
    /// Individual simulation results for each call
    pub results: Vec<SimulationResult>,
    /// Total gas used across all simulated calls
    pub total_gas_used: u64,
    /// Whether the batch will execute atomically (Safe=true, EOA=false)
    pub atomic: bool,
}

#[cfg(feature = "simulation")]
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

    /// Writes the result to `path` as pretty-printed JSON, replacing the file.
    pub fn write_json(&self, path: impl AsRef<std::path::Path>) -> crate::error::Result<()> {
        crate::json::write_file(path.as_ref(), self)
    }

    /// Reads a result written by [`BatchSimulationResult::write_json`].
    pub fn read_json(path: impl AsRef<std::path::Path>) -> crate::error::Result<Self> {
        crate::json::read_file(path.as_ref())
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

    #[cfg(feature = "simulation")]
    #[test]
    fn test_batch_simulation_result_from_safe() {
        let sim_result = SimulationResult {
            success: true,
            gas_used: 50000,
            gas_spent: 50000,
            return_data: Default::default(),
            revert_reason: None,
            logs: vec![],
            state_diff: Default::default(),
            traces: None,
        };

        let result = BatchSimulationResult::from_safe(sim_result);

        assert_eq!(result.results.len(), 1);
        assert_eq!(result.total_gas_used, 50000);
        assert!(result.atomic);
    }

    #[cfg(feature = "simulation")]
    #[test]
    fn test_batch_simulation_result_from_eoa() {
        let sim_results = vec![
            SimulationResult {
                success: true,
                gas_used: 21000,
                gas_spent: 21000,
                return_data: Default::default(),
                revert_reason: None,
                logs: vec![],
                state_diff: Default::default(),
                traces: None,
            },
            SimulationResult {
                success: true,
                gas_used: 30000,
                gas_spent: 30000,
                return_data: Default::default(),
                revert_reason: None,
                logs: vec![],
                state_diff: Default::default(),
                traces: None,
            },
        ];

        let result = BatchSimulationResult::from_eoa(sim_results);

        assert_eq!(result.results.len(), 2);
        assert_eq!(result.total_gas_used, 51000);
        assert!(!result.atomic);
    }

    #[test]
    fn a_batch_simulation_round_trips_through_a_file() {
        let sim = |gas_used| SimulationResult {
            success: true,
            gas_used,
            gas_spent: gas_used,
            return_data: Default::default(),
            revert_reason: None,
            logs: vec![],
            state_diff: Default::default(),
            traces: None,
        };
        let result = BatchSimulationResult::from_eoa(vec![sim(21_000), sim(30_000)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("batch.json");
        result.write_json(&path).unwrap();
        let back = BatchSimulationResult::read_json(&path).unwrap();
        assert_eq!(back.results.len(), 2);
        assert_eq!(back.total_gas_used, 51_000);
        assert!(!back.atomic);
    }

    #[test]
    fn a_batch_result_round_trips_through_json() {
        let result = BatchResult {
            tx_hashes: vec![TxHash::repeat_byte(1), TxHash::repeat_byte(2)],
            success: false,
            success_count: 1,
            failure_count: 1,
            atomic: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(serde_json::from_str::<BatchResult>(&json).unwrap(), result);
    }
}
