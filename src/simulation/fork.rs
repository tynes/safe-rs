//! Fork database and revm simulation

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::eips::BlockId;
use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Bytes, Log, TxKind, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::trace::geth::pre_state::{AccountState, DiffMode};
use foundry_fork_db::SharedBackend;
use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::primitives::hardfork::SpecId;
use revm::state::EvmState;
use revm::Database;
use serde::Serialize;

pub use revm_inspectors::tracing::CallTraceArena;

use crate::error::{Error, Result};
use crate::simulation::evm::{self, canonical_hash, EvmSettings};
use crate::simulation::session::{SimBlockEnv, TxChecks};
use crate::types::{Call, Operation};

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

    /// Replaces the revert reason of a failed, traced result with the reason of
    /// the innermost failed call (see [`innermost_revert_reason`]).
    pub fn apply_inner_revert_reason(&mut self) {
        if self.success {
            return;
        }
        if let Some(inner) = self.traces.as_ref().and_then(innermost_revert_reason) {
            self.revert_reason = Some(inner);
        }
    }

    /// Marks a successful `execTransaction` simulation as failed unless `safe`
    /// emitted exactly one `ExecutionSuccess` for `safe_tx_hash`.
    ///
    /// With a non-zero `safeTxGas` the Safe emits `ExecutionFailure` instead of
    /// reverting when the inner call fails, so a successful top-level call is not
    /// enough to know the Safe transaction succeeded.
    pub fn require_safe_success(&mut self, safe: Address, safe_tx_hash: B256) {
        if !self.success {
            return;
        }
        let outcome = crate::submit::decode_safe_outcome(&self.logs, safe, safe_tx_hash);
        if !outcome.is_success() {
            self.success = false;
            self.revert_reason = Some(format!(
                "Safe did not report ExecutionSuccess for {safe_tx_hash} ({})",
                outcome.label()
            ));
        }
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
pub(crate) fn build_state_diff(state: &EvmState) -> DiffMode {
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
        let original_info = account.original_info();
        let pre_state = AccountState {
            balance: Some(original_info.balance),
            nonce: Some(original_info.nonce),
            code: original_info
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
    block_hash: Option<B256>,
    block_env: Option<SimBlockEnv>,
    spec: SpecId,
    tx_gas_limit: u64,
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
            block_hash: None,
            block_env: None,
            spec: SpecId::CANCUN,
            tx_gas_limit: 30_000_000,
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

    /// Pins the fork to a block hash (takes precedence over [`ForkSimulator::at_block`])
    pub fn at_block_hash(mut self, hash: B256) -> Self {
        self.block_hash = Some(hash);
        self
    }

    /// Sets the block environment used for execution.
    ///
    /// Without it the simulator uses revm defaults (block number 0, timestamp 1,
    /// base fee 0), which makes deadline and expiry checks meaningless. Callers
    /// that care about time-dependent logic should always set it; see
    /// [`SimBlockEnv::next_after`].
    pub fn with_block_env(mut self, env: SimBlockEnv) -> Self {
        self.block_env = Some(env);
        self
    }

    /// Sets the EVM specification (default: CANCUN)
    pub fn with_spec(mut self, spec: SpecId) -> Self {
        self.spec = spec;
        self
    }

    /// Sets the transaction gas limit used for simulated calls (default: 30M)
    pub fn with_tx_gas_limit(mut self, gas_limit: u64) -> Self {
        self.tx_gas_limit = gas_limit;
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
        let block: BlockId = match (self.block_hash, self.block_number) {
            (Some(hash), _) => canonical_hash(hash),
            (None, Some(b)) => b.into(),
            (None, None) => self
                .provider
                .get_block_number()
                .await
                .map_err(|e| Error::ForkDb(e.to_string()))?
                .into(),
        };
        Ok(evm::fork_db(self.provider.clone(), self.chain_id, block))
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
        let mut db = self.fork_for(from).await?;
        self.run_call(&mut db, from, to, value, data, operation, false)
    }

    /// Simulates `calls` in order from `from` on a single fork, so every call
    /// sees the state changes of the calls before it.
    ///
    /// All calls are simulated, including those after a failure; a failed call
    /// still consumes the sender nonce, as it would on chain.
    pub async fn simulate_calls(&self, from: Address, calls: &[Call]) -> Result<Vec<SimulationResult>> {
        let mut db = self.fork_for(from).await?;
        calls
            .iter()
            .map(|call| {
                self.run_call(
                    &mut db,
                    from,
                    call.to,
                    call.value,
                    call.data.clone(),
                    call.operation,
                    true,
                )
            })
            .collect()
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

    /// Creates the fork and applies the caller balance override, if any.
    async fn fork_for(&self, from: Address) -> Result<CacheDB<SharedBackend>> {
        let mut db = self.create_fork_db().await?;
        // Use load_account to preserve existing account info (code, nonce, code_hash)
        if let Some(balance) = self.caller_balance {
            let existing_account = db
                .load_account(from)
                .map_err(|e| Error::ForkDb(format!("Failed to load caller account: {:?}", e)))?;
            existing_account.info.balance = balance;
        }
        Ok(db)
    }

    /// Runs one gas-price-zero call against `db`.
    ///
    /// DelegateCall operations are executed as a direct call from `from`; this
    /// is a simplification, since a real Safe would delegatecall the target.
    fn run_call(
        &self,
        db: &mut CacheDB<SharedBackend>,
        from: Address,
        to: Address,
        value: U256,
        data: Bytes,
        operation: Operation,
        commit: bool,
    ) -> Result<SimulationResult> {
        // Fetch the caller's actual nonce from the forked database
        let caller_nonce = db
            .basic(from)
            .map_err(|e| Error::ForkDb(format!("Failed to fetch caller info: {:?}", e)))?
            .map_or(0, |info| info.nonce);

        let tx = TxEnv {
            caller: from,
            gas_limit: self.tx_gas_limit,
            gas_price: 0,
            kind: TxKind::Call(to),
            value,
            data: data.clone(),
            nonce: caller_nonce,
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        let settings = EvmSettings {
            chain_id: self.chain_id,
            spec: self.spec,
            // Gas price is zero for these simulations
            checks: TxChecks {
                base_fee: false,
                nonce: true,
                balance: true,
            },
            tx_gas_cap: None,
            block_env: self.block_env.clone(),
            zero_basefee: true,
        };
        let result = evm::execute(db, &settings, tx, self.tracing, commit)?;

        if !result.success {
            self.write_debug_output(to, value, &data, operation, &result);
        }
        Ok(result)
    }

    /// Writes debug output for a failed simulation if a directory is configured.
    fn write_debug_output(
        &self,
        to: Address,
        value: U256,
        data: &Bytes,
        operation: Operation,
        result: &SimulationResult,
    ) {
        if let (Some(dir), Some(account_address)) = (&self.debug_output_dir, self.debug_account_address) {
            let debug_output = SimulationDebugOutput::new(
                self.chain_id,
                account_address,
                to,
                value,
                data,
                &operation,
                result,
            );
            // Best-effort write - don't fail the simulation if we can't write debug output
            let _ = debug_output.write_to_dir(dir);
        }
    }
}

/// Decodes `Error(string)` and `Panic(uint256)` revert payloads; falls back to hex.
pub fn decode_revert_reason(output: &[u8]) -> String {
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

/// Returns the decoded revert reason of the deepest reverted call in a trace.
///
/// Safe reports a failed inner call with its own opaque `GS013`; the trace still
/// holds the inner frame that actually reverted.
pub fn innermost_revert_reason(traces: &CallTraceArena) -> Option<String> {
    let failed: Vec<_> = traces
        .nodes()
        .iter()
        .filter(|node| !node.trace.success)
        .collect();
    let deepest = failed.iter().max_by_key(|node| node.trace.depth)?;
    // A frame that halted (out of gas, invalid opcode, ...) returns no data;
    // name the halt so it is not reported as an unknown revert.
    let halt = match deepest.trace.status {
        Some(status) if !status.is_revert() && deepest.trace.output.is_empty() => {
            Some(format!("{status:?}"))
        }
        _ => None,
    };
    let reverted = failed
        .iter()
        .filter(|node| !node.trace.output.is_empty())
        .max_by_key(|node| node.trace.depth);
    match (reverted, halt) {
        (Some(node), Some(halt)) if node.trace.depth < deepest.trace.depth => Some(format!(
            "{} (inner call halted: {halt})",
            decode_revert_reason(&node.trace.output)
        )),
        (Some(node), _) => Some(decode_revert_reason(&node.trace.output)),
        (None, Some(halt)) => Some(format!("halted: {halt}")),
        (None, None) => None,
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
