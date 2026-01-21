//! # safe-rs
//!
//! A Rust library for interacting with Safe v1.4.1 smart accounts.
//!
//! ## Features
//!
//! - Fluent builder API for multicall transactions
//! - Local fork simulation using foundry-fork-db + revm
//! - Seamless integration with alloy's `sol!` macro ecosystem
//! - Single-owner (1/1 threshold) Safe support
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use safe_rs::{Safe, contracts::IERC20};
//! use alloy::primitives::{address, U256};
//!
//! // Connect to a Safe
//! let safe = Safe::connect(provider, signer, safe_address).await?;
//!
//! // Execute a multicall with typed calls
//! safe.multicall()
//!     .add_typed(usdc, IERC20::transferCall { to: recipient, amount: U256::from(1000) })
//!     .add_typed(usdc, IERC20::approveCall { spender, amount: U256::MAX })
//!     .simulate().await?
//!     .execute().await?;
//! ```
//!
//! ## Type-State Builder
//!
//! The library uses a type-state pattern to enforce simulation before execution:
//!
//! ```rust,ignore
//! // NotSimulated state - can add calls, cannot execute
//! let builder = safe.multicall()
//!     .add_typed(token, call);
//!
//! // Simulated state - can inspect results, can execute
//! let simulated = builder.simulate().await?;
//! println!("Gas used: {}", simulated.gas_used());
//!
//! // Execute the transaction
//! let result = simulated.execute().await?;
//! ```

pub mod chain;
pub mod contracts;
pub mod encoding;
pub mod error;
pub mod safe;
pub mod signing;
pub mod simulation;
pub mod types;

// Re-export main types at crate root
pub use chain::{ChainAddresses, ChainConfig};
pub use contracts::{IERC20, IMultiSend, IMultiSendCallOnly, ISafe};
pub use encoding::SafeTxParams;
pub use error::{Error, Result};
pub use safe::{ExecutionResult, MulticallBuilder, NotSimulated, Safe, Simulated};
pub use simulation::{ForkSimulator, SimulationResult};
pub use types::{Call, Operation, SafeCall, TypedCall};

// Re-export alloy types that are commonly used
pub use alloy::network::AnyNetwork;
pub use alloy::primitives::{Address, Bytes, U256};
pub use alloy::providers::Provider;
