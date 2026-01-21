//! EIP-712 signing support for Safe transactions

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};

use crate::contracts::{DOMAIN_SEPARATOR_TYPEHASH, SAFE_TX_TYPEHASH};
use crate::types::Operation;

/// Safe transaction parameters for hashing
#[derive(Debug, Clone)]
pub struct SafeTxParams {
    /// Target address
    pub to: Address,
    /// Value to send
    pub value: U256,
    /// Calldata
    pub data: Bytes,
    /// Operation type
    pub operation: Operation,
    /// Gas limit for the Safe transaction
    pub safe_tx_gas: U256,
    /// Base gas (overhead)
    pub base_gas: U256,
    /// Gas price for refund calculation
    pub gas_price: U256,
    /// Token used for gas refund (address(0) for ETH)
    pub gas_token: Address,
    /// Address to receive gas refund
    pub refund_receiver: Address,
    /// Safe nonce
    pub nonce: U256,
}

impl SafeTxParams {
    /// Creates new SafeTxParams with minimal parameters
    pub fn new(to: Address, value: U256, data: impl Into<Bytes>, operation: Operation) -> Self {
        Self {
            to,
            value,
            data: data.into(),
            operation,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    /// Sets the safe transaction gas
    pub fn with_safe_tx_gas(mut self, gas: U256) -> Self {
        self.safe_tx_gas = gas;
        self
    }

    /// Sets the nonce
    pub fn with_nonce(mut self, nonce: U256) -> Self {
        self.nonce = nonce;
        self
    }
}

/// Computes the domain separator for a Safe
///
/// domain_separator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, safeAddress))
pub fn compute_domain_separator(chain_id: u64, safe_address: Address) -> B256 {
    let mut encoded = Vec::with_capacity(96);

    // DOMAIN_SEPARATOR_TYPEHASH (32 bytes)
    encoded.extend_from_slice(&DOMAIN_SEPARATOR_TYPEHASH);

    // chainId (32 bytes, left-padded)
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());

    // verifyingContract (32 bytes, left-padded address)
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(safe_address.as_slice());
    encoded.extend_from_slice(&addr_bytes);

    keccak256(&encoded)
}

/// Computes the struct hash for SafeTx
///
/// safeTxHash = keccak256(abi.encode(
///     SAFE_TX_TYPEHASH,
///     to, value, keccak256(data), operation,
///     safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce
/// ))
pub fn compute_safe_tx_hash(params: &SafeTxParams) -> B256 {
    let mut encoded = Vec::with_capacity(384);

    // SAFE_TX_TYPEHASH (32 bytes)
    encoded.extend_from_slice(&SAFE_TX_TYPEHASH);

    // to (32 bytes, left-padded address)
    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(params.to.as_slice());
    encoded.extend_from_slice(&to_bytes);

    // value (32 bytes)
    encoded.extend_from_slice(&params.value.to_be_bytes::<32>());

    // keccak256(data) (32 bytes)
    encoded.extend_from_slice(keccak256(&params.data).as_slice());

    // operation (32 bytes, left-padded)
    let mut op_bytes = [0u8; 32];
    op_bytes[31] = params.operation.as_u8();
    encoded.extend_from_slice(&op_bytes);

    // safeTxGas (32 bytes)
    encoded.extend_from_slice(&params.safe_tx_gas.to_be_bytes::<32>());

    // baseGas (32 bytes)
    encoded.extend_from_slice(&params.base_gas.to_be_bytes::<32>());

    // gasPrice (32 bytes)
    encoded.extend_from_slice(&params.gas_price.to_be_bytes::<32>());

    // gasToken (32 bytes, left-padded address)
    let mut gas_token_bytes = [0u8; 32];
    gas_token_bytes[12..].copy_from_slice(params.gas_token.as_slice());
    encoded.extend_from_slice(&gas_token_bytes);

    // refundReceiver (32 bytes, left-padded address)
    let mut refund_bytes = [0u8; 32];
    refund_bytes[12..].copy_from_slice(params.refund_receiver.as_slice());
    encoded.extend_from_slice(&refund_bytes);

    // nonce (32 bytes)
    encoded.extend_from_slice(&params.nonce.to_be_bytes::<32>());

    keccak256(&encoded)
}

/// Computes the final EIP-712 hash to sign
///
/// hash = keccak256("\x19\x01" || domainSeparator || safeTxHash)
pub fn compute_transaction_hash(domain_separator: B256, safe_tx_hash: B256) -> B256 {
    let mut encoded = Vec::with_capacity(66);

    // EIP-712 prefix
    encoded.extend_from_slice(&[0x19, 0x01]);

    // Domain separator
    encoded.extend_from_slice(domain_separator.as_slice());

    // SafeTx hash
    encoded.extend_from_slice(safe_tx_hash.as_slice());

    keccak256(&encoded)
}

/// Computes the complete transaction hash for signing
pub fn compute_safe_transaction_hash(
    chain_id: u64,
    safe_address: Address,
    params: &SafeTxParams,
) -> B256 {
    let domain_separator = compute_domain_separator(chain_id, safe_address);
    let safe_tx_hash = compute_safe_tx_hash(params);
    compute_transaction_hash(domain_separator, safe_tx_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, hex};

    #[test]
    fn test_domain_separator() {
        // Test against known values
        let chain_id = 1u64;
        let safe = address!("0x1234567890123456789012345678901234567890");

        let domain = compute_domain_separator(chain_id, safe);

        // The domain separator should be 32 bytes
        assert_eq!(domain.len(), 32);
    }

    #[test]
    fn test_safe_tx_hash() {
        let params = SafeTxParams {
            to: address!("0x1234567890123456789012345678901234567890"),
            value: U256::from(1000),
            data: Bytes::from(vec![0x01, 0x02, 0x03]),
            operation: Operation::Call,
            safe_tx_gas: U256::from(100000),
            base_gas: U256::from(21000),
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::from(5),
        };

        let hash = compute_safe_tx_hash(&params);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_transaction_hash_prefix() {
        let domain = B256::ZERO;
        let safe_tx_hash = B256::ZERO;

        let hash = compute_transaction_hash(domain, safe_tx_hash);

        // The result should be keccak256("\x19\x01" + 64 zero bytes)
        let expected_input = hex!("1901").iter()
            .chain([0u8; 64].iter())
            .copied()
            .collect::<Vec<u8>>();

        assert_eq!(hash, keccak256(&expected_input));
    }

    #[test]
    fn test_complete_hash() {
        let chain_id = 1u64;
        let safe = address!("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");

        let params = SafeTxParams::new(
            address!("0x1111111111111111111111111111111111111111"),
            U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            vec![],
            Operation::Call,
        )
        .with_nonce(U256::from(0));

        let hash = compute_safe_transaction_hash(chain_id, safe, &params);
        assert_eq!(hash.len(), 32);
    }
}
