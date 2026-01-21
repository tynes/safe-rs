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
