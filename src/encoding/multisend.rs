//! MultiSend transaction encoding
//!
//! The MultiSend contract expects transactions to be encoded in a packed format:
//! - operation: 1 byte (0 = Call, 1 = DelegateCall)
//! - to: 20 bytes
//! - value: 32 bytes
//! - data length: 32 bytes
//! - data: variable length

use alloy::primitives::Bytes;

use crate::types::SafeCall;

/// Encodes a single transaction for MultiSend packed format
///
/// Format: operation (1 byte) | to (20 bytes) | value (32 bytes) | data length (32 bytes) | data
pub fn encode_transaction(call: &impl SafeCall) -> Vec<u8> {
    let data = call.data();
    let data_len = data.len();

    // Calculate total size: 1 + 20 + 32 + 32 + data_len
    let mut encoded = Vec::with_capacity(85 + data_len);

    // Operation (1 byte)
    encoded.push(call.operation().as_u8());

    // To address (20 bytes)
    encoded.extend_from_slice(call.to().as_slice());

    // Value (32 bytes, big-endian)
    encoded.extend_from_slice(&call.value().to_be_bytes::<32>());

    // Data length (32 bytes, big-endian)
    let mut data_len_bytes = [0u8; 32];
    data_len_bytes[24..].copy_from_slice(&(data_len as u64).to_be_bytes());
    encoded.extend_from_slice(&data_len_bytes);

    // Data
    encoded.extend_from_slice(&data);

    encoded
}

/// Encodes multiple transactions for MultiSend
pub fn encode_multisend_data(calls: &[impl SafeCall]) -> Bytes {
    let mut encoded = Vec::new();

    for call in calls {
        encoded.extend(encode_transaction(call));
    }

    Bytes::from(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Call;
    use alloy::primitives::{address, U256};

    #[test]
    fn test_encode_single_transaction() {
        let call = Call::new(
            address!("0x1234567890123456789012345678901234567890"),
            U256::from(1000),
            vec![0xa9, 0x05, 0x9c, 0xbb], // transfer selector
        );

        let encoded = encode_transaction(&call);

        // Check operation byte
        assert_eq!(encoded[0], 0); // Call

        // Check address (bytes 1-20)
        assert_eq!(
            &encoded[1..21],
            address!("0x1234567890123456789012345678901234567890").as_slice()
        );

        // Check value (bytes 21-52)
        let value_bytes = &encoded[21..53];
        assert_eq!(value_bytes[31], 0xe8); // 1000 = 0x3e8
        assert_eq!(value_bytes[30], 0x03);

        // Check data length (bytes 53-84)
        let len_bytes = &encoded[53..85];
        assert_eq!(len_bytes[31], 4); // 4 bytes of data

        // Check data (bytes 85+)
        assert_eq!(&encoded[85..], &[0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_encode_delegate_call() {
        let call = Call::delegate_call(
            address!("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
            vec![0x01, 0x02],
        );

        let encoded = encode_transaction(&call);
        assert_eq!(encoded[0], 1); // DelegateCall
    }

    #[test]
    fn test_encode_multisend_data() {
        let calls = vec![
            Call::call(
                address!("0x1111111111111111111111111111111111111111"),
                vec![0x01],
            ),
            Call::call(
                address!("0x2222222222222222222222222222222222222222"),
                vec![0x02],
            ),
        ];

        let encoded = encode_multisend_data(&calls);

        // First transaction: 1 + 20 + 32 + 32 + 1 = 86 bytes
        // Second transaction: 1 + 20 + 32 + 32 + 1 = 86 bytes
        assert_eq!(encoded.len(), 172);
    }

    #[test]
    fn test_encode_empty_data() {
        let call = Call::call(
            address!("0x1234567890123456789012345678901234567890"),
            vec![],
        );

        let encoded = encode_transaction(&call);

        // 1 + 20 + 32 + 32 + 0 = 85 bytes
        assert_eq!(encoded.len(), 85);

        // Check data length is 0
        let len_bytes = &encoded[53..85];
        assert!(len_bytes.iter().all(|&b| b == 0));
    }
}
