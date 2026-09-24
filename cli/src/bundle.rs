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
pub fn load_bundle(path: &Path) -> Result<Vec<Call>> {
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

    // Decimal or 0x-prefixed hex; empty means zero
    let value = match tx.value.trim() {
        "" => U256::ZERO,
        value => value
            .parse()
            .map_err(|e| eyre!("Invalid value '{}': {}", value, e))?,
    };

    // Hex with or without 0x; empty means no calldata
    let data: Bytes = tx
        .data
        .trim()
        .parse()
        .map_err(|e| eyre!("Invalid hex data: {}", e))?;

    let operation = Operation::from_u8(tx.operation)
        .ok_or_else(|| eyre!("Invalid operation: {}", tx.operation))?;

    Ok(Call::new(to, value, data).with_operation(operation))
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
    fn test_parse_bundle_hex_values_and_operations() {
        let json = r#"[
            {
                "to": "0x1234567890123456789012345678901234567890",
                "value": "0x3e8",
                "data": "a9059cbb",
                "operation": 1
            }
        ]"#;

        let calls = parse_bundle(json).unwrap();
        assert_eq!(calls[0].value, U256::from(1000));
        assert_eq!(calls[0].data, Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]));
        assert_eq!(calls[0].operation, Operation::DelegateCall);
    }

    #[test]
    fn test_parse_bundle_rejects_bad_input() {
        let bad_value = r#"[{"to": "0x1234567890123456789012345678901234567890", "value": "ten"}]"#;
        assert!(parse_bundle(bad_value).is_err());
        let bad_data = r#"[{"to": "0x1234567890123456789012345678901234567890", "data": "0xzz"}]"#;
        assert!(parse_bundle(bad_data).is_err());
        let bad_op = r#"[{"to": "0x1234567890123456789012345678901234567890", "operation": 2}]"#;
        assert!(parse_bundle(bad_op).is_err());
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
