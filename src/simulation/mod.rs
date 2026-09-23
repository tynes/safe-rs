//! Transaction simulation using fork database and revm

mod fork;
pub mod session;

pub use alloy::rpc::types::trace::geth::pre_state::{AccountState, DiffMode};
pub use fork::{
    decode_revert_reason, innermost_revert_reason, AccountStateDebug, CallDebugInfo,
    CallTraceArena, ForkSimulator, LogDebug, SimulationDebugOutput, SimulationResult,
    SimulationResultDebug, StateDiffDebug,
};
pub use session::{ForkSession, ParentHeader, SimBlockEnv, SimTx, SpecId, TxChecks};
