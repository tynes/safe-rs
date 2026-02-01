#[path = "e2e/common.rs"]
mod common;

#[path = "e2e/eoa_operations.rs"]
mod eoa_operations;

#[path = "e2e/erc20_operations.rs"]
mod erc20_operations;

#[path = "e2e/is_safe.rs"]
mod is_safe;

#[path = "e2e/safe_deployment.rs"]
mod safe_deployment;

#[path = "e2e/safe_transactions.rs"]
mod safe_transactions;

#[path = "e2e/simulation_verification.rs"]
mod simulation_verification;

#[path = "e2e/state_diff_verification.rs"]
mod state_diff_verification;

#[path = "e2e/tracing.rs"]
mod tracing;

#[path = "e2e/wallet.rs"]
mod wallet;
