//! # safe-rs
//!
//! A Rust library for interacting with Safe v1.4.1 smart accounts.
//!
//! ## Features
//!
//! - Fluent builder API for multicall transactions
//! - Local fork simulation using foundry-fork-db + revm
//! - Seamless integration with alloy's `sol!` macro ecosystem
//! - Multi-owner Safes: owners' signatures and on-chain `approveHash`
//!   approvals ([`read_approved_owners`]) combine in a [`SignedSafeTx`]; the
//!   builder's `execute()` signs with one key, so it needs threshold 1
//! - One-time owner keys: every transaction swaps the signing owner for a
//!   fresh key ([`rotation`]; the `hd-wallet` feature adds the encrypted
//!   phrase and `rotation::RotatingSafe`)
//!
//! ## Cargo features
//!
//! - `simulation` (default): fork simulation with foundry-fork-db and revm,
//!   meaning `simulate()` on the builders, `ForkSession` and the
//!   `simulate_exec*` functions. With `default-features = false` the builders
//!   still execute, with gas estimated over RPC, and revm is not compiled.
//! - `hd-wallet`: encrypted mnemonic keystores, HD keys and
//!   `rotation::RotatingSafe` (implies `simulation`).
//! - `ledger`: owner keys on a Ledger device (implies `hd-wallet`).
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
//! safe.batch()
//!     .add_typed(usdc, IERC20::transferCall { to: recipient, amount: U256::from(1000) })
//!     .add_typed(usdc, IERC20::approveCall { spender, amount: U256::MAX })
//!     .simulate().await?
//!     .execute().await?;
//!
//! // Or execute without simulation (gas estimated via RPC)
//! safe.batch()
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
//! let builder = safe.batch()
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
pub mod config;
pub mod contracts;
pub mod create2;
pub mod encoding;
pub mod envelope;
pub mod eoa;
pub mod error;
pub mod exec;
#[cfg(feature = "hd-wallet")]
pub mod hd;
pub mod inspect;
#[cfg(feature = "hd-wallet")]
pub mod keystore;
#[cfg(feature = "ledger")]
pub mod ledger;
pub mod outer;
pub mod rotation;
pub mod safe;
pub mod signing;
#[cfg(feature = "simulation")]
pub mod simulation;
pub mod submit;
pub mod types;
pub mod wallet;

// Re-export main types at crate root
pub use account::Account;
pub use chain::{ChainAddresses, ChainConfig};
#[cfg(feature = "simulation")]
pub use config::check_config_post_state;
pub use config::{plan_config, ConfigChanges, ConfigOp, ConfigPlan, ExpectedConfig};
pub use contracts::{IERC20, IMultiSend, IMultiSendCallOnly, ISafe, ISafeProxyFactory, ISafeSetup};
pub use create2::{
    compute_create2_address, encode_create_proxy_with_nonce, encode_setup_call,
    fetch_proxy_creation_code, predict_safe_address,
};
pub use encoding::SafeTxParams;
pub use eoa::{Eoa, EoaBatchResult, EoaBuilder, EoaTxResult};
pub use error::{Error, Result};
#[cfg(feature = "simulation")]
pub use exec::{simulate_approve_hash, simulate_exec, simulate_exec_with_threshold, ExecSimulation};
pub use exec::{submit_and_wait, Submission};
#[cfg(feature = "hd-wallet")]
pub use hd::HdWallet;
#[cfg(feature = "ledger")]
pub use ledger::LedgerKeys;
pub use safe::{
    detect_addresses, is_gs013_revert, is_safe, ExecutionResult, Safe, SafeBuilder,
    SAFE_SINGLETON_SLOT,
};
pub use envelope::{
    batch_params, decode_exec_calldata, recover_signer, BatchTarget, DecodedExecTransaction,
    PreparedSafeTx, SafeTxGasPolicy, SignedSafeTx,
};
pub use inspect::{
    has_module_guard, is_safe_with, prev_in_list, read_approved_owners, read_safe_state,
    require_batch_target, ModuleList, ReadSafeStateOptions, SafeState,
};
pub use outer::{
    decode_signed_outer_tx, sign_outer_tx, sweep_value, OuterTxParams, SignedOuterTx,
};
pub use rotation::{OwnerSwap, RotationPlan};
#[cfg(feature = "simulation")]
pub use simulation::{
    AccountState, CallTraceArena, DiffMode, ForkSession, ForkSimulator, ParentHeader, SimBlockEnv,
    SimTx, SimulationResult, SpecId, TxChecks,
};
pub use submit::{
    broadcast_raw, decode_safe_outcome, receipt_logs, safe_outcome_for_receipt, wait_for_receipt,
    BroadcastOutcome, ReceiptWait, RejectClass, SafeExecutionOutcome,
};
#[cfg(feature = "simulation")]
pub use types::BatchSimulationResult;
pub use types::{BatchResult, Call, CallBuilder, Operation, SafeCall, TypedCall};
pub use wallet::{SafeDeployment, Wallet, WalletBuilder, WalletConfig};

/// Type alias for a Safe wallet
pub type SafeWallet<P> = Wallet<Safe<P>>;

/// Type alias for an EOA wallet
pub type EoaWallet<P> = Wallet<Eoa<P>>;

// Re-export alloy types that are commonly used
pub use alloy::network::AnyNetwork;
pub use alloy::primitives::{Address, Bytes, U256};
pub use alloy::providers::Provider;
