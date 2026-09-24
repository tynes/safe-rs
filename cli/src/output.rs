use std::fmt::{Display, Write as _};

use alloy::primitives::{Address, Bytes, TxHash, B256, U256};
use safe_rs::{Operation, SafeState, SignedOuterTx, SignedSafeTx};
use serde::Serialize;

/// A command result that prints either as JSON or as human-readable text.
pub trait Report: Serialize {
    /// Human-readable rendering (may span several lines).
    fn human(&self) -> String;

    fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(self).unwrap());
        } else {
            println!("{}", self.human());
        }
    }
}

/// Destination for human-readable progress text.
///
/// Progress is suppressed in `--json` mode and goes to stderr when stdout
/// carries a JSON document (for example `--raw-out -`).
#[derive(Clone, Copy)]
pub struct Console {
    quiet: bool,
    stderr: bool,
}

impl Console {
    pub fn new(json: bool, stdout_is_data: bool) -> Self {
        Self {
            quiet: json,
            stderr: stdout_is_data,
        }
    }

    pub fn line(&self, text: impl Display) {
        if self.quiet {
            return;
        }
        if self.stderr {
            eprintln!("{text}");
        } else {
            println!("{text}");
        }
    }
}

#[derive(Serialize)]
pub struct SafeInfoOutput {
    pub address: Address,
    pub nonce: U256,
    pub threshold: u64,
    pub owners: Vec<Address>,
    pub singleton: Address,
    pub version: Option<String>,
    pub code_hash: B256,
    pub modules: Vec<Address>,
    /// False if module enumeration stopped before the end of the list
    pub modules_complete: bool,
    pub guard: Address,
    pub fallback_handler: Address,
    pub block_number: u64,
    pub block_hash: B256,
}

impl SafeInfoOutput {
    pub fn new(state: SafeState, block_number: u64, block_hash: B256) -> Self {
        Self {
            address: state.address,
            nonce: state.nonce,
            threshold: state.threshold.saturating_to(),
            owners: state.owners,
            singleton: state.singleton,
            version: state.version,
            code_hash: state.code_hash,
            modules: state.modules.modules,
            modules_complete: state.modules.complete,
            guard: state.guard,
            fallback_handler: state.fallback_handler,
            block_number,
            block_hash,
        }
    }
}

impl Report for SafeInfoOutput {
    fn human(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "Safe: {}", self.address);
        let _ = writeln!(s, "Block: {} ({})", self.block_number, self.block_hash);
        let _ = writeln!(
            s,
            "Version: {}",
            self.version.as_deref().unwrap_or("unknown")
        );
        let _ = writeln!(s, "Singleton: {}", self.singleton);
        let _ = writeln!(s, "Nonce: {}", self.nonce);
        let _ = writeln!(s, "Threshold: {}", self.threshold);
        let _ = writeln!(s, "Owners:");
        for (i, owner) in self.owners.iter().enumerate() {
            let _ = writeln!(s, "  {}: {}", i + 1, owner);
        }
        let _ = writeln!(
            s,
            "Modules:{}",
            if self.modules.is_empty() { " none" } else { "" }
        );
        for (i, module) in self.modules.iter().enumerate() {
            let _ = writeln!(s, "  {}: {}", i + 1, module);
        }
        if !self.modules_complete {
            let _ = writeln!(s, "  WARNING: module list is incomplete");
        }
        let _ = writeln!(s, "Guard: {}", optional_address(self.guard));
        let _ = write!(
            s,
            "Fallback Handler: {}",
            optional_address(self.fallback_handler)
        );
        s
    }
}

fn optional_address(address: Address) -> String {
    if address == Address::ZERO {
        "none".to_string()
    } else {
        address.to_string()
    }
}

#[derive(Serialize)]
pub struct SimulationOutput {
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_tx_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traces: Option<String>,
}

impl Report for SimulationOutput {
    fn human(&self) -> String {
        let mut s = String::from("Simulation Result:");
        let _ = write!(s, "\n  Success: {}", self.success);
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        if let Some(reason) = &self.revert_reason {
            let _ = write!(s, "\n  Revert Reason: {}", reason);
        }
        if let Some(traces) = &self.traces {
            let _ = write!(s, "\nTraces:\n{}", traces);
        }
        s
    }
}

#[derive(Serialize)]
pub struct ExecutionOutput {
    pub tx_hash: TxHash,
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_tx_hash: Option<B256>,
    /// Safe outcome: `success`, `failure`, `not_found` or `conflicting`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
}

impl Report for ExecutionOutput {
    fn human(&self) -> String {
        let mut s = String::from("Transaction Executed:");
        let _ = write!(s, "\n  Tx Hash: {}", self.tx_hash);
        if let Some(safe_tx_hash) = &self.safe_tx_hash {
            let _ = write!(s, "\n  Safe Tx Hash: {}", safe_tx_hash);
        }
        let _ = write!(s, "\n  Success: {}", self.success);
        if let Some(outcome) = self.outcome {
            let _ = write!(s, "\n  Outcome: {}", outcome);
        }
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        s
    }
}

/// A Safe transaction and the outer transaction that submits it, as written by
/// `send --raw-out`.
#[derive(Serialize)]
pub struct SignedTxOutput {
    pub chain_id: u64,
    pub safe: Address,
    pub safe_nonce: U256,
    pub safe_tx_hash: B256,
    pub safe_tx: SafeTxOutput,
    /// Owner whose signature is included
    pub signer: Address,
    pub signature: Bytes,
    pub outer: OuterTxOutput,
    /// EIP-2718 encoded outer transaction, for `eth_sendRawTransaction`
    pub raw: Bytes,
    pub tx_hash: B256,
}

#[derive(Serialize)]
pub struct SafeTxOutput {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    /// 0 = CALL, 1 = DELEGATECALL
    pub operation: u8,
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: Address,
    pub refund_receiver: Address,
}

#[derive(Serialize)]
pub struct OuterTxOutput {
    pub from: Address,
    pub to: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub value: U256,
    pub input: Bytes,
}

impl SignedTxOutput {
    pub fn new(signed: &SignedSafeTx, outer: &SignedOuterTx) -> Self {
        let prepared = &signed.prepared;
        let p = &prepared.params;
        let o = &outer.params;
        Self {
            chain_id: prepared.chain_id,
            safe: prepared.safe,
            safe_nonce: p.nonce,
            safe_tx_hash: prepared.safe_tx_hash,
            safe_tx: SafeTxOutput {
                to: p.to,
                value: p.value,
                data: p.data.clone(),
                operation: p.operation.as_u8(),
                safe_tx_gas: p.safe_tx_gas,
                base_gas: p.base_gas,
                gas_price: p.gas_price,
                gas_token: p.gas_token,
                refund_receiver: p.refund_receiver,
            },
            signer: signed.owner,
            signature: signed.signature.clone(),
            outer: OuterTxOutput {
                from: o.from,
                to: o.to,
                nonce: o.nonce,
                gas_limit: o.gas_limit,
                max_fee_per_gas: U256::from(o.max_fee_per_gas),
                max_priority_fee_per_gas: U256::from(o.max_priority_fee_per_gas),
                value: o.value,
                input: o.input.clone(),
            },
            raw: outer.raw.clone(),
            tx_hash: outer.tx_hash,
        }
    }

    /// Writes the document to `dest`, a file path or `-` for stdout.
    pub fn write_to(&self, dest: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        if dest == "-" {
            println!("{json}");
            Ok(())
        } else {
            std::fs::write(dest, json + "\n")
        }
    }
}

impl Report for SignedTxOutput {
    fn human(&self) -> String {
        let mut s = String::from("Signed Transaction:");
        let _ = write!(s, "\n  Safe Tx Hash: {}", self.safe_tx_hash);
        let _ = write!(s, "\n  Safe Nonce: {}", self.safe_nonce);
        let _ = write!(s, "\n  Tx Hash: {}", self.tx_hash);
        let _ = write!(
            s,
            "\n  From: {} (nonce {})",
            self.outer.from, self.outer.nonce
        );
        let _ = write!(s, "\n  Gas Limit: {}", self.outer.gas_limit);
        s
    }
}

#[derive(Serialize)]
pub struct CreateOutput {
    pub safe_address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<TxHash>,
    pub owners: Vec<Address>,
    pub threshold: u64,
    pub already_deployed: bool,
}

impl Report for CreateOutput {
    fn human(&self) -> String {
        let mut s = String::new();
        let _ = write!(s, "Safe Address: {}", self.safe_address);
        if self.already_deployed {
            let _ = write!(s, "\n  Status: Already deployed");
        } else if let Some(tx_hash) = self.tx_hash {
            let _ = write!(s, "\n  Tx Hash: {}", tx_hash);
        }
        let _ = write!(s, "\n  Threshold: {}", self.threshold);
        let _ = write!(s, "\n  Owners:");
        for (i, owner) in self.owners.iter().enumerate() {
            let _ = write!(s, "\n    {}: {}", i + 1, owner);
        }
        s
    }
}

#[derive(Serialize)]
pub struct CallOutput {
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traces: Option<String>,
}

impl Report for CallOutput {
    fn human(&self) -> String {
        let mut s = String::from("Call Result:");
        let _ = write!(s, "\n  Success: {}", self.success);
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        if let Some(data) = &self.return_data {
            let _ = write!(s, "\n  Return Data: {}", data);
        }
        if let Some(reason) = &self.revert_reason {
            let _ = write!(s, "\n  Revert Reason: {}", reason);
        }
        if let Some(traces) = &self.traces {
            let _ = write!(s, "\nTraces:\n{}", traces);
        }
        s
    }
}

pub fn calls_summary(calls: &[safe_rs::Call]) -> String {
    let mut s = format!("Calls ({}):", calls.len());
    for (i, call) in calls.iter().enumerate() {
        let _ = write!(s, "\n  {}. To: {}", i + 1, call.to);
        if call.operation == Operation::DelegateCall {
            let _ = write!(s, " (delegatecall)");
        }
        if !call.value.is_zero() {
            let _ = write!(s, "\n     Value: {} wei", call.value);
        }
        let _ = write!(s, "\n     Data: {} bytes", call.data.len());
    }
    s
}

pub fn confirm_prompt(message: &str) -> bool {
    use dialoguer::Confirm;

    Confirm::new()
        .with_prompt(message)
        .default(false)
        .interact()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256};

    fn to_json(value: &impl Serialize) -> serde_json::Value {
        serde_json::from_str(&serde_json::to_string_pretty(value).unwrap()).unwrap()
    }

    fn info(owners: Vec<Address>) -> SafeInfoOutput {
        SafeInfoOutput {
            address: address!("0x1234567890123456789012345678901234567890"),
            nonce: U256::from(42),
            threshold: 2,
            owners,
            singleton: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
            version: Some("1.4.1".to_string()),
            code_hash: B256::ZERO,
            modules: vec![],
            modules_complete: true,
            guard: Address::ZERO,
            fallback_handler: Address::ZERO,
            block_number: 7,
            block_hash: B256::ZERO,
        }
    }

    #[test]
    fn test_safe_info_output_json_format() {
        let parsed = to_json(&info(vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
        ]));

        assert_eq!(
            parsed["address"],
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(parsed["nonce"], "0x2a"); // 42 in hex
        assert_eq!(parsed["threshold"], 2);
        assert_eq!(parsed["owners"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["version"], "1.4.1");
        assert_eq!(parsed["modules_complete"], true);
        assert_eq!(parsed["block_number"], 7);
    }

    #[test]
    fn test_safe_info_output_empty_owners() {
        let parsed = to_json(&info(vec![]));
        assert!(parsed["owners"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_safe_info_human_flags_incomplete_modules() {
        let mut output = info(vec![]);
        output.modules_complete = false;
        assert!(output.human().contains("incomplete"));
    }

    #[test]
    fn test_simulation_output_json_format_success() {
        let parsed = to_json(&SimulationOutput {
            success: true,
            gas_used: 50_000,
            revert_reason: None,
            safe_tx_hash: None,
            traces: None,
        });

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 50_000);
        // optional fields should be absent (skip_serializing_if)
        assert!(parsed.get("revert_reason").is_none());
        assert!(parsed.get("traces").is_none());
    }

    #[test]
    fn test_simulation_output_json_format_failure() {
        let parsed = to_json(&SimulationOutput {
            success: false,
            gas_used: 21_000,
            revert_reason: Some("ERC20: transfer amount exceeds balance".to_string()),
            safe_tx_hash: None,
            traces: None,
        });

        assert_eq!(parsed["success"], false);
        assert_eq!(parsed["gas_used"], 21_000);
        assert_eq!(
            parsed["revert_reason"],
            "ERC20: transfer amount exceeds balance"
        );
    }

    #[test]
    fn test_execution_output_json_format() {
        let tx_hash = b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let parsed = to_json(&ExecutionOutput {
            tx_hash,
            success: true,
            gas_used: 100_000,
            safe_tx_hash: Some(B256::ZERO),
            outcome: Some("success"),
        });

        assert_eq!(
            parsed["tx_hash"],
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 100_000);
        assert_eq!(parsed["outcome"], "success");
    }

    #[test]
    fn test_create_output_json_format_new_deployment() {
        let tx_hash = b256!("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        let parsed = to_json(&CreateOutput {
            safe_address: address!("0x1234567890123456789012345678901234567890"),
            tx_hash: Some(tx_hash),
            owners: vec![address!("0x1111111111111111111111111111111111111111")],
            threshold: 1,
            already_deployed: false,
        });

        assert_eq!(
            parsed["safe_address"],
            "0x1234567890123456789012345678901234567890"
        );
        assert!(parsed["tx_hash"].is_string());
        assert_eq!(parsed["threshold"], 1);
        assert_eq!(parsed["already_deployed"], false);
    }

    #[test]
    fn test_create_output_json_format_already_deployed() {
        let parsed = to_json(&CreateOutput {
            safe_address: address!("0x1234567890123456789012345678901234567890"),
            tx_hash: None,
            owners: vec![
                address!("0x1111111111111111111111111111111111111111"),
                address!("0x2222222222222222222222222222222222222222"),
            ],
            threshold: 2,
            already_deployed: true,
        });

        assert_eq!(parsed["already_deployed"], true);
        // tx_hash should be absent (skip_serializing_if)
        assert!(parsed.get("tx_hash").is_none());
        assert_eq!(parsed["threshold"], 2);
        assert_eq!(parsed["owners"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_call_output_json_format_success() {
        let parsed = to_json(&CallOutput {
            success: true,
            gas_used: 25_000,
            return_data: Some(Bytes::from(vec![0u8; 32])),
            revert_reason: None,
            traces: None,
        });

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 25_000);
        assert!(parsed["return_data"].as_str().unwrap().starts_with("0x"));
        assert!(parsed.get("revert_reason").is_none());
    }

    #[test]
    fn test_call_output_json_format_failure() {
        let parsed = to_json(&CallOutput {
            success: false,
            gas_used: 21_000,
            return_data: None,
            revert_reason: Some("Insufficient balance".to_string()),
            traces: None,
        });

        assert_eq!(parsed["success"], false);
        assert!(parsed.get("return_data").is_none());
        assert_eq!(parsed["revert_reason"], "Insufficient balance");
    }

    #[tokio::test]
    async fn test_signed_tx_output_matches_signed_transactions() {
        use alloy::eips::eip1559::Eip1559Estimation;
        use alloy::primitives::keccak256;
        use alloy::signers::local::PrivateKeySigner;
        use safe_rs::{sign_outer_tx, Call, OuterTxParams, PreparedSafeTx, SafeTxGasPolicy};

        let owner = PrivateKeySigner::random();
        let safe = address!("0x1000000000000000000000000000000000000001");
        let prepared = PreparedSafeTx::single_call(
            1,
            safe,
            &Call::new(safe, U256::from(5), Bytes::new()),
            U256::from(3),
            SafeTxGasPolicy::Zero,
        )
        .unwrap();
        let signed = prepared.sign(&owner).await.unwrap();
        let fees = Eip1559Estimation {
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        };
        let params = OuterTxParams::exec_transaction(&signed, owner.address(), 4, 90_000, fees);
        let outer = sign_outer_tx(&owner, params).await.unwrap();

        let parsed = to_json(&SignedTxOutput::new(&signed, &outer));
        assert_eq!(parsed["chain_id"], 1);
        assert_eq!(parsed["safe_nonce"], "0x3");
        assert_eq!(parsed["safe_tx_hash"], prepared.safe_tx_hash.to_string());
        assert_eq!(parsed["safe_tx"]["operation"], 0);
        assert_eq!(parsed["safe_tx"]["safe_tx_gas"], "0x0");
        assert_eq!(parsed["outer"]["nonce"], 4);
        assert_eq!(parsed["outer"]["gas_limit"], 90_000);
        assert_eq!(parsed["outer"]["to"], safe.to_string());
        let raw: Bytes = parsed["raw"].as_str().unwrap().parse().unwrap();
        assert_eq!(parsed["tx_hash"], keccak256(&raw).to_string());
    }

    #[test]
    fn test_calls_summary_marks_delegatecalls() {
        let calls = [
            safe_rs::Call::new(
                address!("0x1111111111111111111111111111111111111111"),
                U256::from(1000),
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
            safe_rs::Call::delegate_call(
                address!("0x2222222222222222222222222222222222222222"),
                vec![0xa9, 0x05, 0x9c, 0xbb],
            ),
        ];
        let summary = calls_summary(&calls);
        assert!(summary.starts_with("Calls (2):"));
        assert!(summary.contains("Value: 1000 wei"));
        assert_eq!(summary.matches("(delegatecall)").count(), 1);
    }
}
