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
//! // Execute a multicall with typed calls (with simulation)
//! safe.multicall()
//!     .add_typed(usdc, IERC20::transferCall { to: recipient, amount: U256::from(1000) })
//!     .add_typed(usdc, IERC20::approveCall { spender, amount: U256::MAX })
//!     .simulate().await?
//!     .execute().await?;
//!
//! // Or execute without simulation (gas estimated via RPC)
//! safe.multicall()
//!     .add_typed(usdc, IERC20::transferCall { to: recipient, amount: U256::from(1000) })
//!     .execute().await?;
//! ```
//!
//! ## Builder API
//!
//! The `SafeBuilder` provides a fluent API for constructing transactions:
//!
//! ```rust,ignore
//! // Build and simulate
//! let builder = safe.multicall()
//!     .add_typed(token, call)
//!     .simulate().await?;
//!
//! // Inspect simulation results
//! if let Some(result) = builder.simulation_result() {
//!     println!("Gas used: {}", result.gas_used);
//! }
//!
//! // Execute the transaction
//! let result = builder.execute().await?;
//! ```

pub mod account;
pub mod chain;
pub mod contracts;
pub mod create2;
pub mod encoding;
pub mod eoa;
pub mod error;
pub mod safe;
pub mod signing;
pub mod simulation;
pub mod types;
pub mod wallet;

// Re-export main types at crate root
pub use account::Account;
pub use chain::{ChainAddresses, ChainConfig};
pub use contracts::{IERC20, IMultiSend, IMultiSendCallOnly, ISafe, ISafeProxyFactory, ISafeSetup};
pub use create2::{compute_create2_address, encode_setup_call};
pub use encoding::SafeTxParams;
pub use eoa::{Eoa, EoaBatchResult, EoaBuilder, EoaTxResult};
pub use error::{Error, Result};
pub use safe::{is_safe, ExecutionResult, SafeBuilder, Safe, SAFE_SINGLETON_SLOT};
pub use simulation::{AccountState, CallTraceArena, DiffMode, ForkSimulator, SimulationResult};
pub use types::{BatchResult, BatchSimulationResult, Call, CallBuilder, Operation, SafeCall, TypedCall};
pub use wallet::{BatchBuilder, SimulatedBatchBuilder, Wallet, WalletConfig};

// Re-export alloy types that are commonly used
pub use alloy::network::AnyNetwork;
pub use alloy::primitives::{Address, Bytes, U256};
pub use alloy::providers::Provider;
