//! Simulation debug output tests

use alloy::primitives::{address, Bytes, U256};
use alloy::rpc::types::trace::geth::pre_state::DiffMode;
use std::fs;

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::simulation::{SimulationDebugOutput, SimulationResult};
use safe_rs::{Account, CallBuilder, Eoa, IERC20, Operation, Safe};

// ============================================================================
// SimulationDebugOutput Unit Tests
// ============================================================================

/// Test SimulationDebugOutput::new() creates valid output
#[test]
fn test_simulation_debug_output_new() {
    let chain_id = 1u64;
    let account_address = address!("0x1111111111111111111111111111111111111111");
    let to = address!("0x2222222222222222222222222222222222222222");
    let value = U256::from(1000);
    let data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
    let operation = Operation::Call;

    let result = SimulationResult {
        success: false,
        gas_used: 21000,
        return_data: Bytes::from(vec![0x08, 0xc3, 0x79, 0xa0]),
        logs: vec![],
        revert_reason: Some("ERC20: transfer amount exceeds balance".to_string()),
        state_diff: DiffMode::default(),
        traces: None,
    };

    let debug_output =
        SimulationDebugOutput::new(chain_id, account_address, to, value, &data, &operation, &result);

    assert_eq!(debug_output.chain_id, chain_id);
    assert_eq!(debug_output.account_address, account_address);
    assert_eq!(debug_output.call.to, to);
    assert_eq!(debug_output.call.value, "1000");
    assert_eq!(debug_output.call.operation, "Call");
    assert!(!debug_output.result.success);
    assert_eq!(debug_output.result.gas_used, 21000);
    assert_eq!(
        debug_output.result.revert_reason,
        Some("ERC20: transfer amount exceeds balance".to_string())
    );
}

/// Test SimulationDebugOutput::write_to_dir() creates valid JSON file
#[test]
fn test_simulation_debug_output_write_to_dir() {
    let chain_id = 1u64;
    let account_address = address!("0x1111111111111111111111111111111111111111");
    let to = address!("0x2222222222222222222222222222222222222222");
    let value = U256::ZERO;
    let data = Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]); // transfer selector
    let operation = Operation::Call;

    let result = SimulationResult {
        success: false,
        gas_used: 50000,
        return_data: Bytes::new(),
        logs: vec![],
        revert_reason: Some("Insufficient balance".to_string()),
        state_diff: DiffMode::default(),
        traces: None,
    };

    let debug_output =
        SimulationDebugOutput::new(chain_id, account_address, to, value, &data, &operation, &result);

    // Write to temp directory
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = debug_output
        .write_to_dir(temp_dir.path())
        .expect("Failed to write debug output");

    // Verify file exists
    assert!(file_path.exists());

    // Verify file contains valid JSON
    let content = fs::read_to_string(&file_path).expect("Failed to read file");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("Invalid JSON");

    // Check structure
    assert_eq!(parsed["chain_id"], 1);
    assert!(!parsed["result"]["success"].as_bool().unwrap());
    assert_eq!(parsed["result"]["gas_used"], 50000);
    assert!(parsed["timestamp"].is_string());
}

/// Test SimulationDebugOutput with DelegateCall operation
#[test]
fn test_simulation_debug_output_delegatecall_operation() {
    let chain_id = 1u64;
    let account_address = address!("0x1111111111111111111111111111111111111111");
    let to = address!("0x2222222222222222222222222222222222222222");
    let value = U256::ZERO;
    let data = Bytes::new();
    let operation = Operation::DelegateCall;

    let result = SimulationResult {
        success: true,
        gas_used: 100000,
        return_data: Bytes::new(),
        logs: vec![],
        revert_reason: None,
        state_diff: DiffMode::default(),
        traces: None,
    };

    let debug_output =
        SimulationDebugOutput::new(chain_id, account_address, to, value, &data, &operation, &result);

    assert_eq!(debug_output.call.operation, "DelegateCall");
}

// ============================================================================
// Integration Tests: Safe with Debug Output
// ============================================================================

/// Test Safe debug output on simulation failure
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_debug_output_on_simulation_failure() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let owner = harness.signer_address();

    // Deploy a Safe
    let salt_nonce = U256::from(4001);
    let safe_address = harness
        .deploy_safe(vec![owner], 1, salt_nonce)
        .await
        .expect("Failed to deploy Safe");

    // Create temp directory for debug output
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Configure Safe with debug output directory
    let safe = Safe::connect(harness.provider.clone(), harness.signer.clone(), safe_address)
        .await
        .expect("Failed to connect")
        .with_debug_output_dir(temp_dir.path());

    // Deploy a token without giving Safe any balance
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let failing_transfer_call = IERC20::transferCall {
        to: recipient,
        amount: U256::from(1000), // Safe has no tokens, should revert
    };

    // Simulate - this will fail and should write debug output
    let result = safe
        .batch()
        .add_typed(token_address, failing_transfer_call)
        .simulate()
        .await;

    // The simulation itself should succeed (we get a result), but the result shows failure
    assert!(result.is_ok());
    let builder = result.unwrap();
    let sim_result = builder.simulation_result();
    assert!(sim_result.is_some());

    // Check that debug output file was created (if simulation actually failed internally)
    // Note: The simulate() method stores result without erroring, so debug output
    // would be written by the ForkSimulator when the inner call fails
    let files: Vec<_> = fs::read_dir(temp_dir.path())
        .expect("Failed to read dir")
        .filter_map(|e| e.ok())
        .collect();

    // Debug output is written when simulation fails
    // The file should exist if the simulation reverted
    if let Some(sim) = sim_result {
        if !sim.success {
            assert!(
                !files.is_empty(),
                "Debug output should be created on simulation failure"
            );

            // Verify file content
            let file_path = &files[0].path();
            let content = fs::read_to_string(file_path).expect("Failed to read debug file");
            let parsed: serde_json::Value =
                serde_json::from_str(&content).expect("Invalid JSON in debug file");
            assert_eq!(parsed["chain_id"], 1);
            assert!(!parsed["result"]["success"].as_bool().unwrap());
        }
    }
}

/// Test EOA debug output on simulation failure
#[tokio::test(flavor = "multi_thread")]
async fn test_eoa_debug_output_on_simulation_failure() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;

    // Create temp directory for debug output
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Configure EOA with debug output directory
    let eoa = Eoa::connect(
        harness.provider.clone(),
        harness.signer.clone(),
        harness._anvil.endpoint_url(),
    )
    .await
    .expect("Failed to connect")
    .with_debug_output_dir(temp_dir.path());

    // Deploy a token without giving EOA any balance
    let token_address = harness
        .deploy_mock_erc20()
        .await
        .expect("Failed to deploy MockERC20");

    let recipient = address!("0x9999999999999999999999999999999999999999");
    let failing_transfer_call = IERC20::transferCall {
        to: recipient,
        amount: U256::from(1000), // EOA has no tokens, should revert
    };

    // Simulate - this will detect the failure
    let result = eoa
        .batch()
        .add_typed(token_address, failing_transfer_call)
        .simulate()
        .await;

    assert!(result.is_ok());
    let builder = result.unwrap();
    let sim_results = builder.simulation_results();
    assert!(sim_results.is_some());

    // Check that debug output file was created
    let files: Vec<_> = fs::read_dir(temp_dir.path())
        .expect("Failed to read dir")
        .filter_map(|e| e.ok())
        .collect();

    if let Some(results) = sim_results {
        if !results.is_empty() && !results[0].success {
            assert!(
                !files.is_empty(),
                "Debug output should be created on simulation failure"
            );
        }
    }
}

// ============================================================================
// format_traces() Tests
// ============================================================================

/// Test format_traces() returns None when tracing is disabled
#[test]
fn test_format_traces_returns_none_without_tracing() {
    let result = SimulationResult {
        success: true,
        gas_used: 21000,
        return_data: Bytes::new(),
        logs: vec![],
        revert_reason: None,
        state_diff: DiffMode::default(),
        traces: None,
    };

    assert!(result.format_traces().is_none());
}

/// Test SimulationResult accessors
#[test]
fn test_simulation_result_accessors() {
    let result = SimulationResult {
        success: true,
        gas_used: 50000,
        return_data: Bytes::new(),
        logs: vec![],
        revert_reason: None,
        state_diff: DiffMode::default(),
        traces: None,
    };

    assert!(result.is_success());
    assert!(result.error_message().is_none());

    let failed_result = SimulationResult {
        success: false,
        gas_used: 21000,
        return_data: Bytes::new(),
        logs: vec![],
        revert_reason: Some("Transfer failed".to_string()),
        state_diff: DiffMode::default(),
        traces: None,
    };

    assert!(!failed_result.is_success());
    assert_eq!(failed_result.error_message(), Some("Transfer failed"));
}
