//! Tracing E2E tests - verify CallTraceArena capture during simulation

use alloy::primitives::{address, keccak256, Address, Bytes, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;

use crate::common::TestHarness;
use crate::skip_if_no_rpc;
use safe_rs::{ForkSimulator, IERC20, Operation};

/// USDC contract address on Ethereum mainnet
const USDC_ADDRESS: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

/// ERC20 transfer function selector: transfer(address,uint256)
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Computes the storage slot for a USDC balance
///
/// USDC uses slot 9 for the balance mapping: balanceOf[address] = slot(keccak256(address, 9))
fn compute_usdc_balance_slot(holder: Address) -> U256 {
    let mut input = [0u8; 64];
    input[12..32].copy_from_slice(holder.as_slice());
    input[32..64].copy_from_slice(&U256::from(9).to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(input).0)
}

/// Sets USDC balance for a holder using anvil_setStorageAt
async fn set_usdc_balance(
    harness: &TestHarness,
    holder: Address,
    amount: U256,
) -> Result<(), Box<dyn std::error::Error>> {
    let slot = compute_usdc_balance_slot(holder);

    // Convert slot and amount to hex strings for the RPC call
    let params = serde_json::json!([
        format!("{:?}", USDC_ADDRESS),
        format!("0x{:064x}", slot),
        format!("0x{:064x}", amount)
    ]);

    harness
        .provider
        .client()
        .request::<_, bool>("anvil_setStorageAt", params)
        .await?;

    Ok(())
}

/// Test tracing captures USDC transfer call trace
#[tokio::test(flavor = "multi_thread")]
async fn test_tracing_usdc_transfer() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let sender = harness.signer_address();
    let recipient = address!("0xdead000000000000000000000000000000000000");
    let transfer_amount = U256::from(1_000_000u64); // 1 USDC (6 decimals)

    // Set sender's USDC balance
    set_usdc_balance(&harness, sender, U256::from(10_000_000u64))
        .await
        .expect("Failed to set USDC balance");

    // Build transfer calldata
    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };
    let calldata = Bytes::from(transfer_call.abi_encode());

    // Get chain ID
    let chain_id = harness
        .provider
        .get_chain_id()
        .await
        .expect("Failed to get chain ID");

    // Simulate with tracing enabled
    let simulator = ForkSimulator::new(harness.provider.clone(), chain_id).with_tracing(true);

    let result = simulator
        .simulate_call(sender, USDC_ADDRESS, U256::ZERO, calldata, Operation::Call)
        .await
        .expect("Simulation should succeed");

    // Assert traces are captured
    assert!(result.traces.is_some(), "Traces should be captured");

    let traces = result.traces.as_ref().unwrap();
    let nodes = traces.nodes();
    assert!(!nodes.is_empty(), "Should have at least one trace node");

    // Get root node (first node at depth 0)
    let root = &nodes[0];

    // Assert root node properties
    assert_eq!(
        root.trace.caller, sender,
        "Root caller should be the sender"
    );
    assert_eq!(
        root.trace.address, USDC_ADDRESS,
        "Root address should be USDC"
    );

    // Check selector matches transfer
    let selector = root.selector();
    assert!(selector.is_some(), "Root should have a selector");
    assert_eq!(
        selector.unwrap(),
        TRANSFER_SELECTOR,
        "Selector should be transfer(address,uint256)"
    );

    assert!(root.trace.success, "Transfer should succeed");
    assert!(root.trace.gas_used > 0, "Gas used should be non-zero");
}

/// Test tracing captures Transfer event in logs
#[tokio::test(flavor = "multi_thread")]
async fn test_tracing_captures_transfer_event() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let sender = harness.signer_address();
    let recipient = address!("0xbeef000000000000000000000000000000000000");
    let transfer_amount = U256::from(500_000u64); // 0.5 USDC

    // Set sender's USDC balance
    set_usdc_balance(&harness, sender, U256::from(10_000_000u64))
        .await
        .expect("Failed to set USDC balance");

    // Build transfer calldata
    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };
    let calldata = Bytes::from(transfer_call.abi_encode());

    let chain_id = harness
        .provider
        .get_chain_id()
        .await
        .expect("Failed to get chain ID");

    let simulator = ForkSimulator::new(harness.provider.clone(), chain_id).with_tracing(true);

    let result = simulator
        .simulate_call(sender, USDC_ADDRESS, U256::ZERO, calldata, Operation::Call)
        .await
        .expect("Simulation should succeed");

    let traces = result.traces.as_ref().expect("Traces should be captured");
    let root = &traces.nodes()[0];

    // Check for Transfer event in logs
    let transfer_topic = keccak256("Transfer(address,address,uint256)");
    let has_transfer_event = root
        .logs
        .iter()
        .any(|log| log.raw_log.topics().first() == Some(&transfer_topic));

    assert!(
        has_transfer_event,
        "Root node logs should contain Transfer event"
    );
}

/// Test tracing captures traces even on revert
#[tokio::test(flavor = "multi_thread")]
async fn test_tracing_on_revert() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let sender = harness.signer_address();
    let recipient = address!("0xcafe000000000000000000000000000000000000");
    let transfer_amount = U256::from(1_000_000_000u64); // 1000 USDC - more than we have

    // Do NOT set USDC balance - transfer should fail

    // Build transfer calldata
    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };
    let calldata = Bytes::from(transfer_call.abi_encode());

    let chain_id = harness
        .provider
        .get_chain_id()
        .await
        .expect("Failed to get chain ID");

    let simulator = ForkSimulator::new(harness.provider.clone(), chain_id).with_tracing(true);

    let result = simulator
        .simulate_call(sender, USDC_ADDRESS, U256::ZERO, calldata, Operation::Call)
        .await
        .expect("Simulation should complete (even if reverted)");

    // Traces should still be captured on revert
    assert!(
        result.traces.is_some(),
        "Traces should be captured even on revert"
    );

    let traces = result.traces.as_ref().unwrap();
    let root = &traces.nodes()[0];

    // The call should have failed
    assert!(!root.trace.success, "Transfer should have failed");
}

/// Test tracing disabled returns None
#[tokio::test(flavor = "multi_thread")]
async fn test_tracing_disabled_returns_none() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let sender = harness.signer_address();
    let recipient = address!("0xaaaa000000000000000000000000000000000000");
    let transfer_amount = U256::from(100_000u64);

    // Set sender's USDC balance
    set_usdc_balance(&harness, sender, U256::from(10_000_000u64))
        .await
        .expect("Failed to set USDC balance");

    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };
    let calldata = Bytes::from(transfer_call.abi_encode());

    let chain_id = harness
        .provider
        .get_chain_id()
        .await
        .expect("Failed to get chain ID");

    // Simulate WITHOUT tracing enabled (default)
    let simulator = ForkSimulator::new(harness.provider.clone(), chain_id);

    let result = simulator
        .simulate_call(sender, USDC_ADDRESS, U256::ZERO, calldata, Operation::Call)
        .await
        .expect("Simulation should succeed");

    // Traces should be None when tracing is disabled
    assert!(result.traces.is_none(), "Traces should be None");
    assert!(
        result.format_traces().is_none(),
        "format_traces() should return None"
    );
}

/// Test format_traces returns human-readable output
#[tokio::test(flavor = "multi_thread")]
async fn test_format_traces_output() {
    skip_if_no_rpc!();

    let harness = TestHarness::new().await;
    let sender = harness.signer_address();
    let recipient = address!("0xbbbb000000000000000000000000000000000000");
    let transfer_amount = U256::from(250_000u64);

    // Set sender's USDC balance
    set_usdc_balance(&harness, sender, U256::from(10_000_000u64))
        .await
        .expect("Failed to set USDC balance");

    let transfer_call = IERC20::transferCall {
        to: recipient,
        amount: transfer_amount,
    };
    let calldata = Bytes::from(transfer_call.abi_encode());

    let chain_id = harness
        .provider
        .get_chain_id()
        .await
        .expect("Failed to get chain ID");

    let simulator = ForkSimulator::new(harness.provider.clone(), chain_id).with_tracing(true);

    let result = simulator
        .simulate_call(sender, USDC_ADDRESS, U256::ZERO, calldata, Operation::Call)
        .await
        .expect("Simulation should succeed");

    // format_traces should return non-empty string
    let formatted = result.format_traces();
    assert!(formatted.is_some(), "format_traces() should return Some");

    let trace_output = formatted.unwrap();
    assert!(!trace_output.is_empty(), "Trace output should not be empty");

    // The output should contain the USDC address
    let usdc_str = format!("{:?}", USDC_ADDRESS).to_lowercase();
    assert!(
        trace_output.to_lowercase().contains(&usdc_str),
        "Trace output should contain USDC address. Output:\n{}",
        trace_output
    );

    // Print for debugging
    println!("Formatted traces:\n{}", trace_output);
}
