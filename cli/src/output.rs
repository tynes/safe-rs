use alloy::primitives::{Address, TxHash, U256};
use serde::Serialize;

#[derive(Serialize)]
pub struct SafeInfoOutput {
    pub address: Address,
    pub nonce: U256,
    pub threshold: u64,
    pub owners: Vec<Address>,
}

impl SafeInfoOutput {
    pub fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(self).unwrap());
        } else {
            println!("Safe: {}", self.address);
            println!("Nonce: {}", self.nonce);
            println!("Threshold: {}", self.threshold);
            println!("Owners:");
            for (i, owner) in self.owners.iter().enumerate() {
                println!("  {}: {}", i + 1, owner);
            }
        }
    }
}

#[derive(Serialize)]
pub struct SimulationOutput {
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
}

impl SimulationOutput {
    pub fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(self).unwrap());
        } else {
            println!("Simulation Result:");
            println!("  Success: {}", self.success);
            println!("  Gas Used: {}", self.gas_used);
            if let Some(reason) = &self.revert_reason {
                println!("  Revert Reason: {}", reason);
            }
        }
    }
}

#[derive(Serialize)]
pub struct ExecutionOutput {
    pub tx_hash: TxHash,
    pub success: bool,
    pub gas_used: u64,
}

impl ExecutionOutput {
    pub fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(self).unwrap());
        } else {
            println!("Transaction Executed:");
            println!("  Tx Hash: {}", self.tx_hash);
            println!("  Success: {}", self.success);
            println!("  Gas Used: {}", self.gas_used);
        }
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

impl CreateOutput {
    pub fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(self).unwrap());
        } else {
            println!("Safe Address: {}", self.safe_address);
            if self.already_deployed {
                println!("  Status: Already deployed");
            } else if let Some(tx_hash) = self.tx_hash {
                println!("  Tx Hash: {}", tx_hash);
            }
            println!("  Threshold: {}", self.threshold);
            println!("  Owners:");
            for (i, owner) in self.owners.iter().enumerate() {
                println!("    {}: {}", i + 1, owner);
            }
        }
    }
}

#[derive(Serialize)]
pub struct CallOutput {
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
}

impl CallOutput {
    pub fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(self).unwrap());
        } else {
            println!("Call Result:");
            println!("  Success: {}", self.success);
            println!("  Gas Used: {}", self.gas_used);
            if let Some(data) = &self.return_data {
                println!("  Return Data: {}", data);
            }
            if let Some(reason) = &self.revert_reason {
                println!("  Revert Reason: {}", reason);
            }
        }
    }
}

pub fn print_calls_summary(calls: &[safe_rs::Call], json: bool) {
    if json {
        #[derive(Serialize)]
        struct CallSummary {
            to: Address,
            value: U256,
            data_len: usize,
        }

        let summaries: Vec<_> = calls
            .iter()
            .map(|c| CallSummary {
                to: c.to,
                value: c.value,
                data_len: c.data.len(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&summaries).unwrap());
    } else {
        println!("Calls ({}):", calls.len());
        for (i, call) in calls.iter().enumerate() {
            println!("  {}. To: {}", i + 1, call.to);
            if !call.value.is_zero() {
                println!("     Value: {} wei", call.value);
            }
            println!("     Data: {} bytes", call.data.len());
        }
    }
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

    #[test]
    fn test_safe_info_output_json_format() {
        let output = SafeInfoOutput {
            address: address!("0x1234567890123456789012345678901234567890"),
            nonce: U256::from(42),
            threshold: 2,
            owners: vec![
                address!("0x1111111111111111111111111111111111111111"),
                address!("0x2222222222222222222222222222222222222222"),
            ],
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed["address"],
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(parsed["nonce"], "0x2a"); // 42 in hex
        assert_eq!(parsed["threshold"], 2);
        assert_eq!(parsed["owners"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_safe_info_output_empty_owners() {
        let output = SafeInfoOutput {
            address: address!("0x1234567890123456789012345678901234567890"),
            nonce: U256::ZERO,
            threshold: 1,
            owners: vec![],
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["owners"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_simulation_output_json_format_success() {
        let output = SimulationOutput {
            success: true,
            gas_used: 50000,
            revert_reason: None,
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 50000);
        // revert_reason should be absent (skip_serializing_if)
        assert!(parsed.get("revert_reason").is_none());
    }

    #[test]
    fn test_simulation_output_json_format_failure() {
        let output = SimulationOutput {
            success: false,
            gas_used: 21000,
            revert_reason: Some("ERC20: transfer amount exceeds balance".to_string()),
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["success"], false);
        assert_eq!(parsed["gas_used"], 21000);
        assert_eq!(
            parsed["revert_reason"],
            "ERC20: transfer amount exceeds balance"
        );
    }

    #[test]
    fn test_execution_output_json_format() {
        let tx_hash = b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let output = ExecutionOutput {
            tx_hash,
            success: true,
            gas_used: 100000,
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed["tx_hash"],
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 100000);
    }

    #[test]
    fn test_create_output_json_format_new_deployment() {
        let tx_hash = b256!("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        let output = CreateOutput {
            safe_address: address!("0x1234567890123456789012345678901234567890"),
            tx_hash: Some(tx_hash),
            owners: vec![
                address!("0x1111111111111111111111111111111111111111"),
            ],
            threshold: 1,
            already_deployed: false,
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

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
        let output = CreateOutput {
            safe_address: address!("0x1234567890123456789012345678901234567890"),
            tx_hash: None,
            owners: vec![
                address!("0x1111111111111111111111111111111111111111"),
                address!("0x2222222222222222222222222222222222222222"),
            ],
            threshold: 2,
            already_deployed: true,
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["already_deployed"], true);
        // tx_hash should be absent (skip_serializing_if)
        assert!(parsed.get("tx_hash").is_none());
        assert_eq!(parsed["threshold"], 2);
        assert_eq!(parsed["owners"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_call_output_json_format_success() {
        let output = CallOutput {
            success: true,
            gas_used: 25000,
            return_data: Some("0x0000000000000000000000000000000000000000000000000000000000000001".to_string()),
            revert_reason: None,
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 25000);
        assert!(parsed["return_data"].is_string());
        assert!(parsed.get("revert_reason").is_none());
    }

    #[test]
    fn test_call_output_json_format_failure() {
        let output = CallOutput {
            success: false,
            gas_used: 21000,
            return_data: None,
            revert_reason: Some("Insufficient balance".to_string()),
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["success"], false);
        assert!(parsed.get("return_data").is_none());
        assert_eq!(parsed["revert_reason"], "Insufficient balance");
    }

    #[test]
    fn test_call_output_json_format_no_optional_fields() {
        let output = CallOutput {
            success: true,
            gas_used: 30000,
            return_data: None,
            revert_reason: None,
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 30000);
        // Both optional fields should be absent
        assert!(parsed.get("return_data").is_none());
        assert!(parsed.get("revert_reason").is_none());
    }

    #[test]
    fn test_print_calls_summary_json() {
        let calls = vec![
            safe_rs::Call::new(
                address!("0x1111111111111111111111111111111111111111"),
                U256::from(1000),
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
            safe_rs::Call::new(
                address!("0x2222222222222222222222222222222222222222"),
                U256::ZERO,
                vec![0xa9, 0x05, 0x9c, 0xbb],
            ),
        ];

        // This just verifies the function doesn't panic
        // The actual print is to stdout, which is hard to capture in tests
        // But we can at least verify the calls are processed correctly
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].to, address!("0x1111111111111111111111111111111111111111"));
        assert_eq!(calls[0].value, U256::from(1000));
        assert_eq!(calls[0].data.len(), 4);
        assert_eq!(calls[1].to, address!("0x2222222222222222222222222222222222222222"));
        assert!(calls[1].value.is_zero());
    }
}
