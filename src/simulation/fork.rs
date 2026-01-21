//! Fork database and revm simulation

use std::sync::Arc;

use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Bytes, Log, TxKind, U256};
use alloy::providers::Provider;
use foundry_fork_db::{cache::BlockchainDbMeta, BlockchainDb, SharedBackend};
use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::primitives::hardfork::SpecId;
use revm::state::AccountInfo;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

use crate::error::{Error, Result};
use crate::types::Operation;

/// Result of a simulated transaction
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// Whether the simulation succeeded
    pub success: bool,
    /// Gas used during simulation
    pub gas_used: u64,
    /// Return data from the call
    pub return_data: Bytes,
    /// Logs emitted during simulation
    pub logs: Vec<Log>,
    /// Revert reason if the call reverted
    pub revert_reason: Option<String>,
}

impl SimulationResult {
    /// Returns true if the simulation was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Returns the revert reason if available
    pub fn error_message(&self) -> Option<&str> {
        self.revert_reason.as_deref()
    }
}

/// Fork simulator for executing transactions against a forked state
pub struct ForkSimulator<P> {
    provider: P,
    chain_id: u64,
    block_number: Option<u64>,
}

impl<P> ForkSimulator<P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Creates a new fork simulator
    pub fn new(provider: P, chain_id: u64) -> Self {
        Self {
            provider,
            chain_id,
            block_number: None,
        }
    }

    /// Sets the block number to fork from
    pub fn at_block(mut self, block: u64) -> Self {
        self.block_number = Some(block);
        self
    }

    /// Creates a forked database from the current provider state
    pub async fn create_fork_db(&self) -> Result<CacheDB<SharedBackend>> {
        let block = match self.block_number {
            Some(b) => b,
            None => self
                .provider
                .get_block_number()
                .await
                .map_err(|e| Error::ForkDb(e.to_string()))?,
        };

        let meta = BlockchainDbMeta::new(
            Default::default(), // empty known contracts
            format!("fork-{}", self.chain_id),
        );

        let db = BlockchainDb::new(meta, None);
        let backend = SharedBackend::spawn_backend_thread(
            Arc::new(self.provider.clone()),
            db,
            Some(block.into()),
        );

        Ok(CacheDB::new(backend))
    }

    /// Simulates a call from the Safe
    pub async fn simulate_call(
        &self,
        from: Address,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
    ) -> Result<SimulationResult> {
        let mut db = self.create_fork_db().await?;

        // Set a high balance for the caller to ensure the call can proceed
        let caller_info = AccountInfo::default();
        db.insert_account_info(from, caller_info);

        // Update the balance separately
        if let Some(account) = db.cache.accounts.get_mut(&from) {
            account.info.balance = U256::from(1_000_000_000_000_000_000_000u128); // 1000 ETH
        }

        // Determine the actual call target and calldata
        let (call_to, call_data) = match operation {
            Operation::Call => (to, data.to_vec()),
            Operation::DelegateCall => {
                // For delegatecall simulation, we execute directly from the Safe
                // This is a simplification - in reality the Safe would delegatecall
                (to, data.to_vec())
            }
        };

        let tx = TxEnv {
            caller: from,
            gas_limit: 30_000_000,
            gas_price: 0,
            kind: TxKind::Call(call_to),
            value,
            data: call_data.into(),
            nonce: 0,
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        // Build the EVM context
        let ctx = Context::mainnet()
            .with_db(db)
            .modify_cfg_chained(|cfg| {
                cfg.spec = SpecId::CANCUN;
            })
            .modify_block_chained(|block| {
                block.basefee = 0;
            })
            .with_tx(tx.clone());

        // Create and run the EVM
        let mut evm = ctx.build_mainnet();
        let result = evm.transact(tx).map_err(|e| Error::Revm(format!("{:?}", e)))?;

        Ok(self.process_result(result))
    }

    /// Estimates gas for a Safe internal call
    ///
    /// Runs the simulation and returns gas used + 10% buffer
    pub async fn estimate_safe_tx_gas(
        &self,
        from: Address,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
    ) -> Result<U256> {
        let result = self.simulate_call(from, to, value, data, operation).await?;

        if !result.success {
            return Err(Error::GasEstimation(format!(
                "Simulation failed: {}",
                result.revert_reason.unwrap_or_else(|| "unknown".to_string())
            )));
        }

        // Add 10% buffer to the gas used
        let gas_with_buffer = result.gas_used + (result.gas_used / 10);
        Ok(U256::from(gas_with_buffer))
    }

    fn process_result<H>(
        &self,
        result: revm::context::result::ExecResultAndState<revm::context::result::ExecutionResult<H>>,
    ) -> SimulationResult
    where
        H: std::fmt::Debug,
    {
        use revm::context::result::{ExecutionResult, Output};

        match result.result {
            ExecutionResult::Success {
                gas_used,
                output,
                logs,
                ..
            } => {
                let return_data = match output {
                    Output::Call(data) => Bytes::from(data.to_vec()),
                    Output::Create(_, _) => Bytes::new(),
                };

                let logs = logs
                    .into_iter()
                    .filter_map(|log| {
                        Log::new(log.address, log.topics().to_vec(), log.data.data.clone())
                    })
                    .collect();

                SimulationResult {
                    success: true,
                    gas_used,
                    return_data,
                    logs,
                    revert_reason: None,
                }
            }
            ExecutionResult::Revert { gas_used, output } => {
                let revert_reason = Self::decode_revert_reason(&output);
                SimulationResult {
                    success: false,
                    gas_used,
                    return_data: Bytes::from(output.to_vec()),
                    logs: vec![],
                    revert_reason: Some(revert_reason),
                }
            }
            ExecutionResult::Halt { gas_used, reason } => SimulationResult {
                success: false,
                gas_used,
                return_data: Bytes::new(),
                logs: vec![],
                revert_reason: Some(format!("Halted: {:?}", reason)),
            },
        }
    }

    fn decode_revert_reason(output: &revm::primitives::Bytes) -> String {
        if output.len() < 4 {
            return "Unknown revert".to_string();
        }

        // Check for Error(string) selector: 0x08c379a0
        if output[0..4] == [0x08, 0xc3, 0x79, 0xa0] && output.len() >= 68 {
            // Skip selector (4) + offset (32) + length position
            let offset = 4 + 32;
            if output.len() > offset + 32 {
                let len = u32::from_be_bytes([
                    output[offset + 28],
                    output[offset + 29],
                    output[offset + 30],
                    output[offset + 31],
                ]) as usize;

                let str_start = offset + 32;
                if output.len() >= str_start + len {
                    if let Ok(s) = String::from_utf8(output[str_start..str_start + len].to_vec()) {
                        return s;
                    }
                }
            }
        }

        // Check for Panic(uint256) selector: 0x4e487b71
        if output[0..4] == [0x4e, 0x48, 0x7b, 0x71] && output.len() >= 36 {
            let panic_code =
                u32::from_be_bytes([output[32], output[33], output[34], output[35]]) as usize;
            return match panic_code {
                0x00 => "Panic: generic/compiler panic",
                0x01 => "Panic: assertion failed",
                0x11 => "Panic: arithmetic overflow/underflow",
                0x12 => "Panic: division by zero",
                0x21 => "Panic: invalid enum value",
                0x22 => "Panic: access to incorrectly encoded storage",
                0x31 => "Panic: pop on empty array",
                0x32 => "Panic: array out of bounds",
                0x41 => "Panic: memory overflow",
                0x51 => "Panic: call to zero-initialized function",
                _ => "Panic: unknown code",
            }
            .to_string();
        }

        format!("Revert: 0x{}", alloy::primitives::hex::encode(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_result() {
        let result = SimulationResult {
            success: true,
            gas_used: 21000,
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: None,
        };

        assert!(result.is_success());
        assert!(result.error_message().is_none());
    }

    #[test]
    fn test_simulation_result_revert() {
        let result = SimulationResult {
            success: false,
            gas_used: 21000,
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: Some("ERC20: insufficient balance".to_string()),
        };

        assert!(!result.is_success());
        assert_eq!(result.error_message(), Some("ERC20: insufficient balance"));
    }
}
