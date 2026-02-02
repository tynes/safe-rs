//! Transaction simulation using fork database and revm

mod fork;

pub use alloy::rpc::types::trace::geth::pre_state::{AccountState, DiffMode};
pub use fork::{
    AccountStateDebug, CallDebugInfo, CallTraceArena, ForkSimulator, LogDebug,
    SimulationDebugOutput, SimulationResult, SimulationResultDebug, StateDiffDebug,
};
