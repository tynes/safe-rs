use alloy::primitives::{Address, Bytes, U256};
use color_eyre::eyre::{eyre, Result};
use safe_rs::{Call, Operation};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Safe TX Bundler JSON format
#[derive(Debug, Deserialize)]
pub struct BundleTransaction {
    pub to: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub operation: u8,
}

/// Loads a bundle file and converts to Vec<Call>
pub fn load_bundle(path: &str) -> Result<Vec<Call>> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(eyre!("Bundle file not found: {}", path.display()));
    }

    let content = fs::read_to_string(path)?;
    parse_bundle(&content)
}

/// Parses bundle JSON content
pub fn parse_bundle(content: &str) -> Result<Vec<Call>> {
    let transactions: Vec<BundleTransaction> =
        serde_json::from_str(content).map_err(|e| eyre!("Invalid bundle JSON: {}", e))?;

    transactions.into_iter().map(convert_transaction).collect()
}

fn convert_transaction(tx: BundleTransaction) -> Result<Call> {
    let to: Address = tx
        .to
        .parse()
        .map_err(|e| eyre!("Invalid address '{}': {}", tx.to, e))?;

    let value = if tx.value.is_empty() || tx.value == "0" {
        U256::ZERO
    } else {
        parse_value(&tx.value)?
    };

    let data = if tx.data.is_empty() || tx.data == "0x" {
        Bytes::new()
    } else {
        parse_hex_data(&tx.data)?
    };

    let operation = Operation::from_u8(tx.operation)
        .ok_or_else(|| eyre!("Invalid operation: {}", tx.operation))?;

    Ok(Call {
        to,
        value,
        data,
        operation,
    })
}

fn parse_value(s: &str) -> Result<U256> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        U256::from_str_radix(&s[2..], 16).map_err(|e| eyre!("Invalid hex value: {}", e))
    } else {
        s.parse::<U256>().map_err(|e| eyre!("Invalid value: {}", e))
    }
}

fn parse_hex_data(s: &str) -> Result<Bytes> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| eyre!("Invalid hex data: {}", e))?;
    Ok(Bytes::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bundle() {
        let json = r#"[
            {
                "to": "0x1234567890123456789012345678901234567890",
                "value": "1000",
                "data": "0xa9059cbb",
                "operation": 0
            },
            {
                "to": "0xabcdef1234567890abcdef1234567890abcdef12",
                "value": "0",
                "data": "0x",
                "operation": 0
            }
        ]"#;

        let calls = parse_bundle(json).unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].value, U256::from(1000));
        assert_eq!(calls[1].data, Bytes::new());
    }

    #[test]
    fn test_parse_bundle_minimal() {
        let json = r#"[
            {
                "to": "0x1234567890123456789012345678901234567890"
            }
        ]"#;

        let calls = parse_bundle(json).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].value, U256::ZERO);
        assert!(calls[0].data.is_empty());
    }
}
