//! Shared revm plumbing for [`ForkSimulator`](super::ForkSimulator) and
//! [`ForkSession`](super::ForkSession): forked database creation and a single
//! transaction executor.

use std::sync::Arc;

use alloy::eips::{BlockId, RpcBlockHash};
use alloy::network::AnyNetwork;
use alloy::primitives::{Bytes, Log, B256};
use alloy::providers::Provider;
use foundry_fork_db::{cache::BlockchainDbMeta, BlockchainDb, SharedBackend};
use revm::context::result::{ExecResultAndState, ExecutionResult, Output};
use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::primitives::hardfork::SpecId;
use revm::state::EvmState;
use revm::{Context, DatabaseCommit, ExecuteEvm, InspectEvm, MainBuilder, MainContext};
use revm_inspectors::tracing::{TracingInspector, TracingInspectorConfig};

use crate::error::{Error, Result};
use crate::simulation::fork::{build_state_diff, decode_revert_reason, SimulationResult};
use crate::simulation::session::{SimBlockEnv, TxChecks};

/// A block id that pins `hash` and requires it to be canonical.
pub(crate) fn canonical_hash(hash: B256) -> BlockId {
    BlockId::Hash(RpcBlockHash::from_hash(hash, Some(true)))
}

/// Forked database backed by `provider`, pinned at `pin`.
pub(crate) fn fork_db<P>(provider: P, chain_id: u64, pin: BlockId) -> CacheDB<SharedBackend>
where
    P: Provider<AnyNetwork> + 'static,
{
    let meta = BlockchainDbMeta::new(Default::default(), format!("fork-{chain_id}"));
    let db = BlockchainDb::new(meta, None);
    let backend = SharedBackend::spawn_backend_thread(Arc::new(provider), db, Some(pin));
    CacheDB::new(backend)
}

/// EVM configuration for one executed transaction.
#[derive(Debug, Clone)]
pub(crate) struct EvmSettings {
    pub chain_id: u64,
    pub spec: SpecId,
    pub checks: TxChecks,
    pub tx_gas_cap: Option<u64>,
    /// Block environment; `None` keeps revm defaults
    pub block_env: Option<SimBlockEnv>,
    /// Force the block base fee to zero (for gas-price-zero simulations)
    pub zero_basefee: bool,
}

/// Executes `tx` against `db`, optionally recording call traces and committing
/// the resulting state.
pub(crate) fn execute(
    db: &mut CacheDB<SharedBackend>,
    settings: &EvmSettings,
    tx: TxEnv,
    tracing: bool,
    commit: bool,
) -> Result<SimulationResult> {
    let ctx = Context::mainnet()
        .with_db(&mut *db)
        .modify_cfg_chained(|cfg| {
            cfg.set_spec_and_mainnet_gas_params(settings.spec);
            cfg.chain_id = settings.chain_id;
            // Allow simulation from contract addresses (e.g., Safe contracts)
            cfg.disable_eip3607 = true;
            cfg.disable_base_fee = !settings.checks.base_fee;
            cfg.disable_nonce_check = !settings.checks.nonce;
            cfg.disable_balance_check = !settings.checks.balance;
            cfg.tx_gas_limit_cap = settings.tx_gas_cap;
        })
        .modify_block_chained(|block| {
            if let Some(env) = &settings.block_env {
                env.apply(block);
            }
            if settings.zero_basefee {
                block.basefee = 0;
            }
        });

    let (output, traces) = if tracing {
        // Record logs so traces show emitted events, as `cast run` does
        let config = TracingInspectorConfig::default_parity().record_logs();
        let mut inspector = TracingInspector::new(config);
        let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);
        let output = evm
            .inspect_tx(tx)
            .map_err(|e| Error::Revm(format!("{e:?}")))?;
        drop(evm);
        (output, Some(inspector.into_traces()))
    } else {
        let mut evm = ctx.build_mainnet();
        let output = evm
            .transact(tx)
            .map_err(|e| Error::Revm(format!("{e:?}")))?;
        (output, None)
    };

    let ExecResultAndState { result, state } = output;
    let mut sim = to_simulation_result(result, &state);
    sim.traces = traces;
    if commit {
        db.commit(state);
    }
    Ok(sim)
}

/// Converts a revm execution result into a [`SimulationResult`].
fn to_simulation_result<H>(result: ExecutionResult<H>, state: &EvmState) -> SimulationResult
where
    H: std::fmt::Debug,
{
    let state_diff = build_state_diff(state);

    match result {
        ExecutionResult::Success {
            gas, output, logs, ..
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
                gas_used: gas.tx_gas_used(),
                return_data,
                logs,
                revert_reason: None,
                state_diff,
                traces: None,
            }
        }
        ExecutionResult::Revert { gas, output, .. } => SimulationResult {
            success: false,
            gas_used: gas.tx_gas_used(),
            revert_reason: Some(decode_revert_reason(&output)),
            return_data: Bytes::from(output.to_vec()),
            logs: vec![],
            state_diff,
            traces: None,
        },
        ExecutionResult::Halt { gas, reason, .. } => SimulationResult {
            success: false,
            gas_used: gas.tx_gas_used(),
            return_data: Bytes::new(),
            logs: vec![],
            revert_reason: Some(format!("Halted: {:?}", reason)),
            state_diff,
            traces: None,
        },
    }
}
