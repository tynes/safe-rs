//! Transaction simulation using fork database and revm

mod fork;

pub use alloy::rpc::types::trace::geth::pre_state::{AccountState, DiffMode};
pub use fork::{CallTraceArena, ForkSimulator, SimulationResult};
