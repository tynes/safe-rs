use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use color_eyre::eyre::{eyre, Result};

/// Parses a function signature and encodes it with arguments
/// e.g., "transfer(address,uint256)" with args ["0x...", "1000"]
pub fn encode_function_call(sig: &str, args: &[String]) -> Result<Bytes> {
    let selector = compute_selector(sig)?;
    let param_types = parse_param_types(sig)?;

    if param_types.len() != args.len() {
        return Err(eyre!(
            "Expected {} arguments, got {}",
            param_types.len(),
            args.len()
        ));
    }

    let values = parse_args(&param_types, args)?;
    let encoded_args = encode_values(&values)?;

    let mut calldata = selector.to_vec();
    calldata.extend(encoded_args);

    Ok(Bytes::from(calldata))
}

/// Computes the 4-byte function selector from signature
fn compute_selector(sig: &str) -> Result<[u8; 4]> {
    // Normalize the signature (remove spaces)
    let sig = sig.replace(' ', "");
    let hash = keccak256(sig.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    Ok(selector)
}

/// Extracts parameter types from a function signature
/// e.g., "transfer(address,uint256)" -> ["address", "uint256"]
fn parse_param_types(sig: &str) -> Result<Vec<String>> {
    let sig = sig.trim();

    // Find the opening paren
    let open_paren = sig.find('(').ok_or_else(|| eyre!("Invalid signature: missing '('"))?;
    let close_paren = sig.rfind(')').ok_or_else(|| eyre!("Invalid signature: missing ')'"))?;

    if close_paren <= open_paren {
        return Err(eyre!("Invalid signature format"));
    }

    let params_str = &sig[open_paren + 1..close_paren];

    if params_str.is_empty() {
        return Ok(Vec::new());
    }

    // Parse parameters, handling nested types like tuples and arrays
    let params = split_params(params_str)?;
    Ok(params)
}

/// Splits parameter string handling nested parentheses
fn split_params(params_str: &str) -> Result<Vec<String>> {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut depth = 0;

    for c in params_str.chars() {
        match c {
            '(' => {
                depth += 1;
                current.push(c);
            }
            ')' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                let param = current.trim().to_string();
                if !param.is_empty() {
                    params.push(param);
                }
                current = String::new();
            }
            _ => {
                current.push(c);
            }
        }
    }

    let param = current.trim().to_string();
    if !param.is_empty() {
        params.push(param);
    }

    Ok(params)
}

/// Parses string arguments into DynSolValue based on their types
fn parse_args(types: &[String], args: &[String]) -> Result<Vec<DynSolValue>> {
    types
        .iter()
        .zip(args.iter())
        .map(|(ty, arg)| parse_arg(ty, arg))
        .collect()
}

/// Parses a single argument
fn parse_arg(ty: &str, arg: &str) -> Result<DynSolValue> {
    let sol_type: DynSolType = ty.parse().map_err(|e| eyre!("Invalid type '{}': {}", ty, e))?;
    parse_value(&sol_type, arg)
}

/// Parses a value according to its type
fn parse_value(sol_type: &DynSolType, arg: &str) -> Result<DynSolValue> {
    match sol_type {
        DynSolType::Address => {
            let addr: Address = arg.parse().map_err(|e| eyre!("Invalid address '{}': {}", arg, e))?;
            Ok(DynSolValue::Address(addr))
        }
        DynSolType::Bool => {
            let b = match arg.to_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => return Err(eyre!("Invalid bool value: {}", arg)),
            };
            Ok(DynSolValue::Bool(b))
        }
        DynSolType::Int(bits) => {
            let value = parse_int(arg, *bits)?;
            Ok(DynSolValue::Int(value, *bits))
        }
        DynSolType::Uint(bits) => {
            let value = parse_uint(arg)?;
            Ok(DynSolValue::Uint(value, *bits))
        }
        DynSolType::Bytes => {
            let bytes = parse_bytes(arg)?;
            Ok(DynSolValue::Bytes(bytes))
        }
        DynSolType::FixedBytes(len) => {
            let bytes = parse_bytes(arg)?;
            if bytes.len() != *len {
                return Err(eyre!(
                    "Expected {} bytes, got {}",
                    len,
                    bytes.len()
                ));
            }
            // Pad to 32 bytes (right-padded with zeros)
            let mut padded = [0u8; 32];
            padded[..*len].copy_from_slice(&bytes);
            Ok(DynSolValue::FixedBytes(
                alloy::primitives::FixedBytes::from_slice(&padded),
                *len,
            ))
        }
        DynSolType::String => Ok(DynSolValue::String(arg.to_string())),
        DynSolType::Array(inner) => {
            let elements = parse_array_arg(arg)?;
            let values: Result<Vec<_>> = elements
                .iter()
                .map(|el| parse_value(inner, el))
                .collect();
            Ok(DynSolValue::Array(values?))
        }
        DynSolType::FixedArray(inner, len) => {
            let elements = parse_array_arg(arg)?;
            if elements.len() != *len {
                return Err(eyre!(
                    "Expected {} elements, got {}",
                    len,
                    elements.len()
                ));
            }
            let values: Result<Vec<_>> = elements
                .iter()
                .map(|el| parse_value(inner, el))
                .collect();
            Ok(DynSolValue::FixedArray(values?))
        }
        DynSolType::Tuple(types) => {
            let elements = parse_tuple_arg(arg)?;
            if elements.len() != types.len() {
                return Err(eyre!(
                    "Expected {} tuple elements, got {}",
                    types.len(),
                    elements.len()
                ));
            }
            let values: Result<Vec<_>> = types
                .iter()
                .zip(elements.iter())
                .map(|(ty, el)| parse_value(ty, el))
                .collect();
            Ok(DynSolValue::Tuple(values?))
        }
        _ => Err(eyre!("Unsupported type: {:?}", sol_type)),
    }
}

/// Parses a uint value (supports decimal and hex)
fn parse_uint(s: &str) -> Result<U256> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        U256::from_str_radix(&s[2..], 16).map_err(|e| eyre!("Invalid hex uint: {}", e))
    } else {
        s.parse::<U256>().map_err(|e| eyre!("Invalid uint: {}", e))
    }
}

/// Parses a signed int value
fn parse_int(s: &str, bits: usize) -> Result<alloy::primitives::I256> {
    let s = s.trim();
    let negative = s.starts_with('-');
    let abs_str = if negative { &s[1..] } else { s };

    let abs_value = parse_uint(abs_str)?;

    if negative {
        // Check that the absolute value fits in the signed range
        let max_neg = U256::from(1u64) << (bits - 1);
        if abs_value > max_neg {
            return Err(eyre!("Value out of range for int{}", bits));
        }
        Ok(-alloy::primitives::I256::try_from(abs_value).map_err(|e| eyre!("Int conversion error: {}", e))?)
    } else {
        alloy::primitives::I256::try_from(abs_value).map_err(|e| eyre!("Int conversion error: {}", e))
    }
}

/// Parses bytes (hex string)
fn parse_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| eyre!("Invalid hex bytes: {}", e))
}

/// Parses an array argument like "[1,2,3]" or "1,2,3"
fn parse_array_arg(s: &str) -> Result<Vec<String>> {
    let s = s.trim();
    let s = s.strip_prefix('[').unwrap_or(s);
    let s = s.strip_suffix(']').unwrap_or(s);

    if s.is_empty() {
        return Ok(Vec::new());
    }

    split_params(s)
}

/// Parses a tuple argument like "(val1,val2)"
fn parse_tuple_arg(s: &str) -> Result<Vec<String>> {
    let s = s.trim();
    let s = s.strip_prefix('(').ok_or_else(|| eyre!("Tuple must start with '('"))?;
    let s = s.strip_suffix(')').ok_or_else(|| eyre!("Tuple must end with ')'"))?;

    if s.is_empty() {
        return Ok(Vec::new());
    }

    split_params(s)
}

/// Encodes DynSolValues into ABI-encoded bytes
fn encode_values(values: &[DynSolValue]) -> Result<Vec<u8>> {
    if values.is_empty() {
        return Ok(Vec::new());
    }

    let tuple = DynSolValue::Tuple(values.to_vec());
    Ok(tuple.abi_encode_params())
}

/// Parses a multicall specification like "0xAddr:sig(types):arg1,arg2"
pub fn parse_call_spec(spec: &str) -> Result<(Address, Bytes)> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err(eyre!(
            "Invalid call spec format. Expected '0xAddr:sig(types)' or '0xAddr:sig(types):args'"
        ));
    }

    let to: Address = parts[0]
        .parse()
        .map_err(|e| eyre!("Invalid address '{}': {}", parts[0], e))?;

    let sig = parts[1];
    let args: Vec<String> = if parts.len() > 2 && !parts[2].is_empty() {
        parts[2].split(',').map(|s| s.trim().to_string()).collect()
    } else {
        Vec::new()
    };

    let data = encode_function_call(sig, &args)?;
    Ok((to, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_selector() {
        let selector = compute_selector("transfer(address,uint256)").unwrap();
        // keccak256("transfer(address,uint256)")[0:4] = 0xa9059cbb
        assert_eq!(selector, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_parse_param_types() {
        let types = parse_param_types("transfer(address,uint256)").unwrap();
        assert_eq!(types, vec!["address", "uint256"]);

        let empty = parse_param_types("noArgs()").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_encode_simple_call() {
        let data = encode_function_call(
            "transfer(address,uint256)",
            &[
                "0x1234567890123456789012345678901234567890".to_string(),
                "1000".to_string(),
            ],
        )
        .unwrap();

        // Should start with transfer selector
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_parse_call_spec() {
        let (to, data) = parse_call_spec(
            "0x1234567890123456789012345678901234567890:transfer(address,uint256):0xabcdef1234567890abcdef1234567890abcdef12,1000",
        )
        .unwrap();

        assert_eq!(
            to,
            "0x1234567890123456789012345678901234567890".parse::<Address>().unwrap()
        );
        assert!(!data.is_empty());
    }

    // =========================================================================
    // Bool Type Tests
    // =========================================================================

    #[test]
    fn test_parse_value_bool_true() {
        let sol_type: DynSolType = "bool".parse().unwrap();

        // Test various true representations
        let result = parse_value(&sol_type, "true").unwrap();
        assert_eq!(result, DynSolValue::Bool(true));

        let result = parse_value(&sol_type, "1").unwrap();
        assert_eq!(result, DynSolValue::Bool(true));

        let result = parse_value(&sol_type, "TRUE").unwrap();
        assert_eq!(result, DynSolValue::Bool(true));
    }

    #[test]
    fn test_parse_value_bool_false() {
        let sol_type: DynSolType = "bool".parse().unwrap();

        // Test various false representations
        let result = parse_value(&sol_type, "false").unwrap();
        assert_eq!(result, DynSolValue::Bool(false));

        let result = parse_value(&sol_type, "0").unwrap();
        assert_eq!(result, DynSolValue::Bool(false));

        let result = parse_value(&sol_type, "FALSE").unwrap();
        assert_eq!(result, DynSolValue::Bool(false));
    }

    #[test]
    fn test_parse_value_bool_invalid() {
        let sol_type: DynSolType = "bool".parse().unwrap();
        let result = parse_value(&sol_type, "maybe");
        assert!(result.is_err());
    }

    // =========================================================================
    // Uint Type Tests
    // =========================================================================

    #[test]
    fn test_parse_value_uint_decimal() {
        let sol_type: DynSolType = "uint256".parse().unwrap();
        let result = parse_value(&sol_type, "1000").unwrap();
        assert_eq!(result, DynSolValue::Uint(U256::from(1000), 256));
    }

    #[test]
    fn test_parse_value_uint_hex() {
        let sol_type: DynSolType = "uint256".parse().unwrap();
        let result = parse_value(&sol_type, "0x3e8").unwrap();
        assert_eq!(result, DynSolValue::Uint(U256::from(1000), 256));

        // Test uppercase 0X prefix
        let result = parse_value(&sol_type, "0X3E8").unwrap();
        assert_eq!(result, DynSolValue::Uint(U256::from(1000), 256));
    }

    #[test]
    fn test_parse_value_uint_large() {
        let sol_type: DynSolType = "uint256".parse().unwrap();
        // 1 ETH in wei
        let result = parse_value(&sol_type, "1000000000000000000").unwrap();
        assert_eq!(
            result,
            DynSolValue::Uint(U256::from(1_000_000_000_000_000_000u128), 256)
        );
    }

    #[test]
    fn test_parse_value_uint_smaller_sizes() {
        let sol_type: DynSolType = "uint8".parse().unwrap();
        let result = parse_value(&sol_type, "255").unwrap();
        assert_eq!(result, DynSolValue::Uint(U256::from(255), 8));

        let sol_type: DynSolType = "uint128".parse().unwrap();
        let result = parse_value(&sol_type, "12345").unwrap();
        assert_eq!(result, DynSolValue::Uint(U256::from(12345), 128));
    }

    // =========================================================================
    // Int Type Tests
    // =========================================================================

    #[test]
    fn test_parse_value_int_positive() {
        let sol_type: DynSolType = "int256".parse().unwrap();
        let result = parse_value(&sol_type, "1000").unwrap();
        if let DynSolValue::Int(value, bits) = result {
            assert_eq!(bits, 256);
            assert!(value.is_positive());
        } else {
            panic!("Expected Int variant");
        }
    }

    #[test]
    fn test_parse_value_int_negative() {
        let sol_type: DynSolType = "int256".parse().unwrap();
        let result = parse_value(&sol_type, "-1000").unwrap();
        if let DynSolValue::Int(value, bits) = result {
            assert_eq!(bits, 256);
            assert!(value.is_negative());
        } else {
            panic!("Expected Int variant");
        }
    }

    #[test]
    fn test_parse_value_int_zero() {
        let sol_type: DynSolType = "int256".parse().unwrap();
        let result = parse_value(&sol_type, "0").unwrap();
        if let DynSolValue::Int(value, bits) = result {
            assert_eq!(bits, 256);
            assert!(value.is_zero());
        } else {
            panic!("Expected Int variant");
        }
    }

    // =========================================================================
    // Bytes Type Tests
    // =========================================================================

    #[test]
    fn test_parse_value_bytes_dynamic() {
        let sol_type: DynSolType = "bytes".parse().unwrap();
        let result = parse_value(&sol_type, "0xdeadbeef").unwrap();
        assert_eq!(result, DynSolValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));

        // Without 0x prefix
        let result = parse_value(&sol_type, "deadbeef").unwrap();
        assert_eq!(result, DynSolValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn test_parse_value_bytes_empty() {
        let sol_type: DynSolType = "bytes".parse().unwrap();
        let result = parse_value(&sol_type, "0x").unwrap();
        assert_eq!(result, DynSolValue::Bytes(vec![]));
    }

    #[test]
    fn test_parse_value_fixed_bytes() {
        let sol_type: DynSolType = "bytes4".parse().unwrap();
        let result = parse_value(&sol_type, "0xdeadbeef").unwrap();
        if let DynSolValue::FixedBytes(fb, size) = result {
            assert_eq!(size, 4);
            // FixedBytes internally stores as bytes32 with right-padding
            // The actual bytes are at the beginning
            assert_eq!(fb[0], 0xde);
            assert_eq!(fb[1], 0xad);
            assert_eq!(fb[2], 0xbe);
            assert_eq!(fb[3], 0xef);
        } else {
            panic!("Expected FixedBytes variant");
        }
    }

    #[test]
    fn test_parse_value_bytes32() {
        let sol_type: DynSolType = "bytes32".parse().unwrap();
        let hash = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let result = parse_value(&sol_type, hash).unwrap();
        if let DynSolValue::FixedBytes(fb, size) = result {
            assert_eq!(size, 32);
            assert_eq!(fb[0], 0x12);
            assert_eq!(fb[31], 0x34);
        } else {
            panic!("Expected FixedBytes variant");
        }
    }

    #[test]
    fn test_parse_value_fixed_bytes_wrong_length() {
        let sol_type: DynSolType = "bytes4".parse().unwrap();
        // Too many bytes
        let result = parse_value(&sol_type, "0xdeadbeefcafe");
        assert!(result.is_err());
    }

    // =========================================================================
    // String Type Tests
    // =========================================================================

    #[test]
    fn test_parse_value_string() {
        let sol_type: DynSolType = "string".parse().unwrap();
        let result = parse_value(&sol_type, "hello world").unwrap();
        assert_eq!(result, DynSolValue::String("hello world".to_string()));
    }

    #[test]
    fn test_parse_value_string_empty() {
        let sol_type: DynSolType = "string".parse().unwrap();
        let result = parse_value(&sol_type, "").unwrap();
        assert_eq!(result, DynSolValue::String("".to_string()));
    }

    #[test]
    fn test_parse_value_string_special_chars() {
        let sol_type: DynSolType = "string".parse().unwrap();
        let result = parse_value(&sol_type, "hello, world! 🎉").unwrap();
        assert_eq!(result, DynSolValue::String("hello, world! 🎉".to_string()));
    }

    // =========================================================================
    // Array Type Tests
    // =========================================================================

    #[test]
    fn test_parse_value_array_uint() {
        let sol_type: DynSolType = "uint256[]".parse().unwrap();
        let result = parse_value(&sol_type, "[1,2,3]").unwrap();
        if let DynSolValue::Array(values) = result {
            assert_eq!(values.len(), 3);
            assert_eq!(values[0], DynSolValue::Uint(U256::from(1), 256));
            assert_eq!(values[1], DynSolValue::Uint(U256::from(2), 256));
            assert_eq!(values[2], DynSolValue::Uint(U256::from(3), 256));
        } else {
            panic!("Expected Array variant");
        }
    }

    #[test]
    fn test_parse_value_array_without_brackets() {
        let sol_type: DynSolType = "uint256[]".parse().unwrap();
        let result = parse_value(&sol_type, "1,2,3").unwrap();
        if let DynSolValue::Array(values) = result {
            assert_eq!(values.len(), 3);
        } else {
            panic!("Expected Array variant");
        }
    }

    #[test]
    fn test_parse_value_array_empty() {
        let sol_type: DynSolType = "uint256[]".parse().unwrap();
        let result = parse_value(&sol_type, "[]").unwrap();
        if let DynSolValue::Array(values) = result {
            assert!(values.is_empty());
        } else {
            panic!("Expected Array variant");
        }
    }

    #[test]
    fn test_parse_value_array_addresses() {
        let sol_type: DynSolType = "address[]".parse().unwrap();
        let result = parse_value(
            &sol_type,
            "[0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222]",
        )
        .unwrap();
        if let DynSolValue::Array(values) = result {
            assert_eq!(values.len(), 2);
        } else {
            panic!("Expected Array variant");
        }
    }

    // =========================================================================
    // Tuple Type Tests
    // =========================================================================

    #[test]
    fn test_parse_value_tuple() {
        let sol_type: DynSolType = "(address,uint256)".parse().unwrap();
        let result = parse_value(
            &sol_type,
            "(0x1234567890123456789012345678901234567890,1000)",
        )
        .unwrap();
        if let DynSolValue::Tuple(values) = result {
            assert_eq!(values.len(), 2);
            if let DynSolValue::Address(addr) = &values[0] {
                assert_eq!(
                    *addr,
                    "0x1234567890123456789012345678901234567890"
                        .parse::<Address>()
                        .unwrap()
                );
            } else {
                panic!("Expected Address");
            }
            if let DynSolValue::Uint(val, _) = &values[1] {
                assert_eq!(*val, U256::from(1000));
            } else {
                panic!("Expected Uint");
            }
        } else {
            panic!("Expected Tuple variant");
        }
    }

    #[test]
    fn test_parse_value_tuple_missing_parens() {
        let sol_type: DynSolType = "(uint256,uint256)".parse().unwrap();
        // Missing opening paren should fail
        let result = parse_value(&sol_type, "1,2)");
        assert!(result.is_err());
    }

    // =========================================================================
    // Call Spec Tests
    // =========================================================================

    #[test]
    fn test_parse_call_spec_no_args() {
        let (to, data) = parse_call_spec(
            "0x1234567890123456789012345678901234567890:totalSupply()",
        )
        .unwrap();

        assert_eq!(
            to,
            "0x1234567890123456789012345678901234567890"
                .parse::<Address>()
                .unwrap()
        );
        // Should only have the 4-byte selector
        assert_eq!(data.len(), 4);
    }

    #[test]
    fn test_parse_call_spec_with_empty_args() {
        let (to, data) = parse_call_spec(
            "0x1234567890123456789012345678901234567890:totalSupply():",
        )
        .unwrap();

        assert_eq!(
            to,
            "0x1234567890123456789012345678901234567890"
                .parse::<Address>()
                .unwrap()
        );
        // Should only have the 4-byte selector (empty args)
        assert_eq!(data.len(), 4);
    }

    #[test]
    fn test_parse_call_spec_invalid_format_no_colon() {
        let result = parse_call_spec("0x1234567890123456789012345678901234567890");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_call_spec_invalid_address() {
        let result = parse_call_spec("invalid:transfer(address,uint256):0x1111111111111111111111111111111111111111,100");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_call_spec_invalid_signature() {
        let result = parse_call_spec("0x1234567890123456789012345678901234567890:invalid");
        assert!(result.is_err());
    }

    // =========================================================================
    // Argument Count Mismatch Tests
    // =========================================================================

    #[test]
    fn test_encode_function_call_wrong_arg_count() {
        // Too few args
        let result = encode_function_call(
            "transfer(address,uint256)",
            &["0x1234567890123456789012345678901234567890".to_string()],
        );
        assert!(result.is_err());

        // Too many args
        let result = encode_function_call(
            "transfer(address,uint256)",
            &[
                "0x1234567890123456789012345678901234567890".to_string(),
                "1000".to_string(),
                "extra".to_string(),
            ],
        );
        assert!(result.is_err());
    }

    // =========================================================================
    // Nested Type Tests
    // =========================================================================

    #[test]
    fn test_parse_param_types_nested_tuple() {
        let types = parse_param_types("foo((address,uint256),bytes)").unwrap();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], "(address,uint256)");
        assert_eq!(types[1], "bytes");
    }

    #[test]
    fn test_parse_param_types_array_of_tuples() {
        let types = parse_param_types("foo((address,uint256)[])").unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], "(address,uint256)[]");
    }
}
