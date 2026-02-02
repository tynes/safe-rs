//! Fork database and revm simulation

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Bytes, Log, TxKind, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::trace::geth::pre_state::{AccountState, DiffMode};
use serde::Serialize;
use foundry_fork_db::{cache::BlockchainDbMeta, BlockchainDb, SharedBackend};
use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::primitives::hardfork::SpecId;
use revm::state::{AccountInfo, EvmState};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
use revm_inspectors::tracing::{TracingInspector, TracingInspectorConfig};

pub use revm_inspectors::tracing::CallTraceArena;

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
    /// State changes from simulation (pre/post state for touched accounts)
    pub state_diff: DiffMode,
    /// Call trace arena (if tracing was enabled)
    pub traces: Option<CallTraceArena>,
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

    /// Format traces as human-readable text (cast run style)
    ///
    /// Returns `None` if tracing was not enabled for this simulation.
    pub fn format_traces(&self) -> Option<String> {
        use revm_inspectors::tracing::TraceWriter;

        let traces = self.traces.as_ref()?;
        let mut writer = TraceWriter::new(Vec::<u8>::new());
        writer.write_arena(traces).ok()?;
        String::from_utf8(writer.into_writer()).ok()
    }
}

/// Debug output for a failed simulation, written to disk as JSON
#[derive(Debug, Serialize)]
pub struct SimulationDebugOutput {
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Chain ID
    pub chain_id: u64,
    /// The account address (Safe or EOA)
    pub account_address: Address,
    /// The call that was attempted
    pub call: CallDebugInfo,
    /// The simulation result
    pub result: SimulationResultDebug,
}

/// Debug information about a call
#[derive(Debug, Serialize)]
pub struct CallDebugInfo {
    /// Target address
    pub to: Address,
    /// ETH value sent
    pub value: String,
    /// Calldata (hex encoded)
    pub data: String,
    /// Operation type (Call or DelegateCall)
    pub operation: String,
}

/// Debug information about a simulation result (serializable version)
#[derive(Debug, Serialize)]
pub struct SimulationResultDebug {
    /// Whether the simulation succeeded
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Revert reason if the call reverted
    pub revert_reason: Option<String>,
    /// Return data (hex encoded)
    pub return_data: String,
    /// Logs emitted during simulation
    pub logs: Vec<LogDebug>,
    /// State diff
    pub state_diff: StateDiffDebug,
    /// Formatted traces if available
    pub traces: Option<String>,
}

/// Debug information about a log entry
#[derive(Debug, Serialize)]
pub struct LogDebug {
    /// Address that emitted the log
    pub address: Address,
    /// Topics
    pub topics: Vec<String>,
    /// Data (hex encoded)
    pub data: String,
}

/// Debug information about state diff
#[derive(Debug, Serialize)]
pub struct StateDiffDebug {
    /// Pre-state of affected accounts
    pub pre: BTreeMap<Address, AccountStateDebug>,
    /// Post-state of affected accounts
    pub post: BTreeMap<Address, AccountStateDebug>,
}

/// Debug information about account state
#[derive(Debug, Serialize)]
pub struct AccountStateDebug {
    /// Account balance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,
    /// Account nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// Storage slots (key -> value, both hex encoded)
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub storage: BTreeMap<String, String>,
}

impl SimulationDebugOutput {
    /// Creates a new debug output from a simulation result and context
    pub fn new(
        chain_id: u64,
        account_address: Address,
        to: Address,
        value: U256,
        data: &Bytes,
        operation: &crate::types::Operation,
        result: &SimulationResult,
    ) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();

        let call = CallDebugInfo {
            to,
            value: value.to_string(),
            data: format!("0x{}", alloy::primitives::hex::encode(data)),
            operation: format!("{:?}", operation),
        };

        let logs = result
            .logs
            .iter()
            .map(|log| LogDebug {
                address: log.address,
                topics: log
                    .topics()
                    .iter()
                    .map(|t| format!("0x{}", alloy::primitives::hex::encode(t)))
                    .collect(),
                data: format!("0x{}", alloy::primitives::hex::encode(log.data.data.as_ref())),
            })
            .collect();

        let state_diff = StateDiffDebug {
            pre: result
                .state_diff
                .pre
                .iter()
                .map(|(addr, state)| (*addr, AccountStateDebug::from(state)))
                .collect(),
            post: result
                .state_diff
                .post
                .iter()
                .map(|(addr, state)| (*addr, AccountStateDebug::from(state)))
                .collect(),
        };

        let result_debug = SimulationResultDebug {
            success: result.success,
            gas_used: result.gas_used,
            revert_reason: result.revert_reason.clone(),
            return_data: format!("0x{}", alloy::primitives::hex::encode(&result.return_data)),
            logs,
            state_diff,
            traces: result.format_traces(),
        };

        Self {
            timestamp,
            chain_id,
            account_address,
            call,
            result: result_debug,
        }
    }

    /// Writes the debug output to a file in the given directory.
    ///
    /// The filename format is: `{chain_id}-{address}-{timestamp}.json`
    ///
    /// Creates the directory if it doesn't exist.
    pub fn write_to_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
        // Create directory if it doesn't exist
        std::fs::create_dir_all(dir)?;

        // Generate filename: {chain_id}-{address}-{timestamp}.json
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let filename = format!(
            "{}-{}-{}.json",
            self.chain_id,
            self.account_address.to_string().to_lowercase(),
            timestamp
        );
        let path = dir.join(filename);

        // Write JSON to file
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;

        Ok(path)
    }
}

impl From<&AccountState> for AccountStateDebug {
    fn from(state: &AccountState) -> Self {
        Self {
            balance: state.balance.map(|b| b.to_string()),
            nonce: state.nonce,
            storage: state
                .storage
                .iter()
                .map(|(k, v)| {
                    (
                        format!("0x{}", alloy::primitives::hex::encode(k)),
                        format!("0x{}", alloy::primitives::hex::encode(v)),
                    )
                })
                .collect(),
        }
    }
}

/// Builds a state diff from REVM's execution state
///
/// REVM tracks original values in `Account.original_info` and `EvmStorageSlot.original_value`,
/// so we can reconstruct both pre and post state from the final state.
fn build_state_diff(state: &EvmState) -> DiffMode {
    let mut pre = BTreeMap::new();
    let mut post = BTreeMap::new();

    for (address, account) in state.iter() {
        // Skip if account wasn't touched
        if !account.is_touched() {
            continue;
        }

        // Build storage diffs - only include changed slots
        let mut pre_storage = BTreeMap::new();
        let mut post_storage = BTreeMap::new();

        for (key, slot) in account.storage.iter() {
            if slot.is_changed() {
                pre_storage.insert(B256::from(*key), B256::from(slot.original_value));
                post_storage.insert(B256::from(*key), B256::from(slot.present_value));
            }
        }

        // Build pre-state from original_info
        let pre_state = AccountState {
            balance: Some(account.original_info.balance),
            nonce: Some(account.original_info.nonce),
            code: account
                .original_info
                .code
                .as_ref()
                .map(|c| Bytes::from(c.original_bytes().to_vec())),
            storage: pre_storage,
        };

        // Build post-state from current info
        let post_state = AccountState {
            balance: Some(account.info.balance),
            nonce: Some(account.info.nonce),
            code: account
                .info
                .code
                .as_ref()
                .map(|c| Bytes::from(c.original_bytes().to_vec())),
            storage: post_storage,
        };

        pre.insert(*address, pre_state);
        post.insert(*address, post_state);
    }

    DiffMode { pre, post }
}

/// Fork simulator for executing transactions against a forked state
pub struct ForkSimulator<P> {
    provider: P,
    chain_id: u64,
    block_number: Option<u64>,
    tracing: bool,
    caller_balance: Option<U256>,
    debug_output_dir: Option<PathBuf>,
    /// Account address for debug output (the Safe or EOA address)
    debug_account_address: Option<Address>,
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
            tracing: false,
            caller_balance: None,
            debug_output_dir: None,
            debug_account_address: None,
        }
    }

    /// Configures a directory for writing debug output on simulation failures.
    ///
    /// When a simulation fails and this is set, a JSON file will be written
    /// to the configured directory with the simulation details.
    ///
    /// The `account_address` is the Safe or EOA address that will be recorded
    /// in the debug output.
    pub fn with_debug_output_dir(mut self, dir: impl Into<PathBuf>, account_address: Address) -> Self {
        self.debug_output_dir = Some(dir.into());
        self.debug_account_address = Some(account_address);
        self
    }

    /// Sets the block number to fork from
    pub fn at_block(mut self, block: u64) -> Self {
        self.block_number = Some(block);
        self
    }

    /// Enables transaction tracing (cast run style)
    ///
    /// When enabled, `simulate_call()` will capture detailed call traces
    /// showing the nested call hierarchy, gas per call, and call/return data.
    /// Access traces via `SimulationResult::format_traces()`.
    pub fn with_tracing(mut self, enable: bool) -> Self {
        self.tracing = enable;
        self
    }

    /// Sets a custom balance for the caller during simulation.
    ///
    /// If not set, the caller's on-chain balance is used.
    pub fn with_caller_balance(mut self, balance: U256) -> Self {
        self.caller_balance = Some(balance);
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

        // Only override caller balance if configured
        if let Some(balance) = self.caller_balance {
            let caller_info = AccountInfo::default();
            db.insert_account_info(from, caller_info);

            if let Some(account) = db.cache.accounts.get_mut(&from) {
                account.info.balance = balance;
            }
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
                cfg.chain_id = self.chain_id;
            })
            .modify_block_chained(|block| {
                block.basefee = 0;
            })
            .with_tx(tx.clone());

        let sim_result = if self.tracing {
            // Create inspector for tracing
            let config = TracingInspectorConfig::default_parity();
            let mut inspector = TracingInspector::new(config);

            // Build EVM with inspector attached and execute
            let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
            let result = evm.transact(tx).map_err(|e| Error::Revm(format!("{:?}", e)))?;

            // Extract traces from the inspector
            let traces = Some(inspector.into_traces());

            let mut sim_result = self.process_result(result);
            sim_result.traces = traces;
            sim_result
        } else {
            // Create and run the EVM without tracing
            let mut evm = ctx.build_mainnet();
            let result = evm.transact(tx).map_err(|e| Error::Revm(format!("{:?}", e)))?;

            self.process_result(result)
        };

        // Write debug output if simulation failed and debug output is configured
        if !sim_result.success {
            if let (Some(dir), Some(account_address)) =
                (&self.debug_output_dir, self.debug_account_address)
            {
                let debug_output = SimulationDebugOutput::new(
                    self.chain_id,
                    account_address,
                    to,
                    value,
                    &data,
                    &operation,
                    &sim_result,
                );
                // Best-effort write - don't fail the simulation if we can't write debug output
                let _ = debug_output.write_to_dir(dir);
            }
        }

        Ok(sim_result)
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

        // Build state diff from the execution state
        let state_diff = build_state_diff(&result.state);

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
                    state_diff,
                    traces: None,
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
                    state_diff,
                    traces: None,
                }
            }
            ExecutionResult::Halt { gas_used, reason } => SimulationResult {
                success: false,
                gas_used,
                return_data: Bytes::new(),
                logs: vec![],
                revert_reason: Some(format!("Halted: {:?}", reason)),
                state_diff,
                traces: None,
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
            state_diff: DiffMode::default(),
            traces: None,
        };

        assert!(result.is_success());
        assert!(result.error_message().is_none());
        assert!(result.format_traces().is_none());
    }

    #[test]
    fn test_simulation_result_revert() {
        let result = SimulationResult {
            success: false,
            gas_used: 21000,
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: Some("ERC20: insufficient balance".to_string()),
            state_diff: DiffMode::default(),
            traces: None,
        };

        assert!(!result.is_success());
        assert_eq!(result.error_message(), Some("ERC20: insufficient balance"));
    }

    #[test]
    fn test_state_diff_with_balance_change() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();

        let addr = Address::ZERO;

        pre.insert(
            addr,
            AccountState {
                balance: Some(U256::from(1000)),
                nonce: Some(0),
                code: None,
                storage: BTreeMap::new(),
            },
        );

        post.insert(
            addr,
            AccountState {
                balance: Some(U256::from(500)),
                nonce: Some(1),
                code: None,
                storage: BTreeMap::new(),
            },
        );

        let state_diff = DiffMode { pre, post };

        let result = SimulationResult {
            success: true,
            gas_used: 21000,
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: None,
            state_diff,
            traces: None,
        };

        assert!(result.is_success());
        assert_eq!(result.state_diff.pre.len(), 1);
        assert_eq!(result.state_diff.post.len(), 1);

        let pre_account = result.state_diff.pre.get(&addr).unwrap();
        let post_account = result.state_diff.post.get(&addr).unwrap();

        assert_eq!(pre_account.balance, Some(U256::from(1000)));
        assert_eq!(post_account.balance, Some(U256::from(500)));
        assert_eq!(pre_account.nonce, Some(0));
        assert_eq!(post_account.nonce, Some(1));
    }

    #[test]
    fn test_state_diff_with_storage_change() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();

        let addr = Address::ZERO;
        let storage_key = B256::ZERO;

        // Storage values in AccountState are B256, not U256
        let pre_value = B256::from(U256::from(100));
        let post_value = B256::from(U256::from(200));

        let mut pre_storage = BTreeMap::new();
        pre_storage.insert(storage_key, pre_value);

        let mut post_storage = BTreeMap::new();
        post_storage.insert(storage_key, post_value);

        pre.insert(
            addr,
            AccountState {
                balance: Some(U256::ZERO),
                nonce: Some(0),
                code: None,
                storage: pre_storage,
            },
        );

        post.insert(
            addr,
            AccountState {
                balance: Some(U256::ZERO),
                nonce: Some(0),
                code: None,
                storage: post_storage,
            },
        );

        let state_diff = DiffMode { pre, post };

        let result = SimulationResult {
            success: true,
            gas_used: 50000,
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: None,
            state_diff,
            traces: None,
        };

        let pre_account = result.state_diff.pre.get(&addr).unwrap();
        let post_account = result.state_diff.post.get(&addr).unwrap();

        assert_eq!(pre_account.storage.get(&storage_key), Some(&pre_value));
        assert_eq!(post_account.storage.get(&storage_key), Some(&post_value));
    }
}
