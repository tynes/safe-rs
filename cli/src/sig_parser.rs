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
            Ok(DynSolValue::FixedBytes(
                alloy::primitives::FixedBytes::from_slice(&bytes),
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
}
