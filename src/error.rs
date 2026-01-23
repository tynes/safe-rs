//! Error types for safe-rs

use alloy::primitives::Address;
use thiserror::Error;

/// Result type alias for safe-rs operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when interacting with Safe smart accounts
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to connect to the RPC provider
    #[error("Provider error: {0}")]
    Provider(String),

    /// Failed to fetch data from the blockchain
    #[error("Failed to fetch {what}: {reason}")]
    Fetch { what: &'static str, reason: String },

    /// Invalid chain ID
    #[error("Unsupported chain ID: {0}")]
    UnsupportedChain(u64),

    /// Safe contract not deployed at the given address
    #[error("Safe not deployed at {0}")]
    SafeNotDeployed(Address),

    /// MultiSend contract not deployed
    #[error("MultiSend contract not deployed at {0}")]
    MultiSendNotDeployed(Address),

    /// The signer is not an owner of the Safe
    #[error("Signer {signer} is not an owner of Safe {safe}")]
    NotOwner { signer: Address, safe: Address },

    /// Invalid Safe configuration for single-owner operations
    #[error("Safe threshold is {threshold}, expected 1 for single-owner operations")]
    InvalidThreshold { threshold: u64 },

    /// Transaction simulation failed
    #[error("Simulation failed: {reason}")]
    SimulationFailed { reason: String },

    /// Transaction reverted during simulation
    #[error("Transaction reverted during simulation: {reason}")]
    SimulationReverted { reason: String },

    /// Transaction execution failed
    #[error("Execution failed: {reason}")]
    ExecutionFailed { reason: String },

    /// Transaction was rejected by the Safe
    #[error("Safe rejected transaction: {reason}")]
    SafeRejected { reason: String },

    /// Signature generation failed
    #[error("Failed to sign: {0}")]
    Signing(String),

    /// Encoding error
    #[error("Encoding error: {0}")]
    Encoding(String),

    /// No calls added to multicall builder
    #[error("No calls added to multicall builder")]
    NoCalls,

    /// Gas estimation failed
    #[error("Gas estimation failed: {0}")]
    GasEstimation(String),

    /// ABI encoding/decoding error
    #[error("ABI error: {0}")]
    Abi(String),

    /// EIP-712 signing error
    #[error("EIP-712 error: {0}")]
    Eip712(String),

    /// Fork database error
    #[error("Fork database error: {0}")]
    ForkDb(String),

    /// Revm execution error
    #[error("Revm execution error: {0}")]
    Revm(String),

    /// Transaction send failed
    #[error("Failed to send transaction {index}: {reason}")]
    TransactionSendFailed { index: usize, reason: String },

    /// EOA operation not supported (e.g., DelegateCall)
    #[error("EOA does not support {operation} operation")]
    UnsupportedEoaOperation { operation: String },
}

impl From<alloy::transports::RpcError<alloy::transports::TransportErrorKind>> for Error {
    fn from(err: alloy::transports::RpcError<alloy::transports::TransportErrorKind>) -> Self {
        Error::Provider(err.to_string())
    }
}

impl From<alloy::contract::Error> for Error {
    fn from(err: alloy::contract::Error) -> Self {
        Error::Provider(err.to_string())
    }
}

impl From<alloy::signers::Error> for Error {
    fn from(err: alloy::signers::Error) -> Self {
        Error::Signing(err.to_string())
    }
}
