//! CREATE2 address computation for Safe proxy deployment
//!
//! This module provides utilities for computing deterministic Safe proxy addresses
//! using CREATE2. The Safe proxy factory deploys proxies at deterministic addresses
//! based on the singleton address, initializer data, and salt nonce.

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::sol_types::SolCall;

use crate::contracts::ISafeSetup;

/// Encodes the Safe.setup() call for proxy initialization
///
/// # Arguments
/// * `owners` - Array of owner addresses for the Safe
/// * `threshold` - Number of required confirmations for transactions
/// * `fallback_handler` - Address of the fallback handler contract
///
/// # Returns
/// ABI-encoded setup call data
pub fn encode_setup_call(owners: &[Address], threshold: u64, fallback_handler: Address) -> Bytes {
    let setup_call = ISafeSetup::setupCall {
        _owners: owners.to_vec(),
        _threshold: U256::from(threshold),
        to: Address::ZERO,
        data: Bytes::new(),
        fallbackHandler: fallback_handler,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    };

    Bytes::from(setup_call.abi_encode())
}

/// Computes the CREATE2 address for a Safe proxy
///
/// The Safe proxy factory uses a specific CREATE2 formula:
/// ```text
/// salt = keccak256(keccak256(initializer) ++ saltNonce)
/// init_code = proxyCreationCode ++ singleton_address_padded
/// address = keccak256(0xff ++ factory ++ salt ++ keccak256(init_code))[12:]
/// ```
///
/// # Arguments
/// * `factory` - Address of the SafeProxyFactory contract
/// * `singleton` - Address of the Safe singleton (implementation) contract
/// * `initializer` - ABI-encoded Safe.setup() call data
/// * `salt_nonce` - User-provided nonce for address derivation
/// * `creation_code` - Proxy creation bytecode from SafeProxyFactory.proxyCreationCode()
///
/// # Returns
/// The deterministic address where the Safe proxy will be deployed
pub fn compute_create2_address(
    factory: Address,
    singleton: Address,
    initializer: &Bytes,
    salt_nonce: U256,
    creation_code: &Bytes,
) -> Address {
    // Compute salt: keccak256(keccak256(initializer) ++ saltNonce)
    let initializer_hash = keccak256(initializer);

    let mut salt_input = [0u8; 64];
    salt_input[..32].copy_from_slice(initializer_hash.as_slice());
    salt_input[32..64].copy_from_slice(&salt_nonce.to_be_bytes::<32>());

    let salt = keccak256(salt_input);

    // Compute init_code_hash: keccak256(creation_code ++ singleton_padded)
    let mut init_code = creation_code.to_vec();
    // Append singleton address as 32-byte padded value
    let mut singleton_padded = [0u8; 32];
    singleton_padded[12..].copy_from_slice(singleton.as_slice());
    init_code.extend_from_slice(&singleton_padded);

    let init_code_hash = keccak256(&init_code);

    // Compute CREATE2 address
    let mut create2_input = Vec::with_capacity(1 + 20 + 32 + 32);
    create2_input.push(0xff);
    create2_input.extend_from_slice(factory.as_slice());
    create2_input.extend_from_slice(salt.as_slice());
    create2_input.extend_from_slice(init_code_hash.as_slice());

    let hash = keccak256(&create2_input);

    Address::from_slice(&hash[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_encode_setup_call() {
        let owners = vec![address!("1234567890123456789012345678901234567890")];
        let threshold = 1;
        let fallback_handler = address!("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99");

        let data = encode_setup_call(&owners, threshold, fallback_handler);

        // Should not be empty and should start with setup selector
        assert!(!data.is_empty());
        // setup() selector is 0xb63e800d
        assert_eq!(&data[0..4], &[0xb6, 0x3e, 0x80, 0x0d]);
    }

    #[test]
    fn test_encode_setup_call_multiple_owners() {
        let owners = vec![
            address!("1111111111111111111111111111111111111111"),
            address!("2222222222222222222222222222222222222222"),
            address!("3333333333333333333333333333333333333333"),
        ];
        let threshold = 2;
        let fallback_handler = address!("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99");

        let data = encode_setup_call(&owners, threshold, fallback_handler);

        // Should not be empty
        assert!(!data.is_empty());
        // setup() selector is 0xb63e800d
        assert_eq!(&data[0..4], &[0xb6, 0x3e, 0x80, 0x0d]);
    }

    #[test]
    fn test_compute_create2_address_deterministic() {
        // Test that the same inputs always produce the same output
        let factory = address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");
        let singleton = address!("41675C099F32341bf84BFc5382aF534df5C7461a");
        let initializer = Bytes::from(vec![0x01, 0x02, 0x03]);
        let salt_nonce = U256::from(42);
        let creation_code = Bytes::from(vec![0x60, 0x80, 0x60, 0x40]);

        let addr1 = compute_create2_address(
            factory,
            singleton,
            &initializer,
            salt_nonce,
            &creation_code,
        );

        let addr2 = compute_create2_address(
            factory,
            singleton,
            &initializer,
            salt_nonce,
            &creation_code,
        );

        assert_eq!(addr1, addr2, "CREATE2 address should be deterministic");
    }

    #[test]
    fn test_compute_create2_address_different_nonce() {
        // Test that different salt nonces produce different addresses
        let factory = address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");
        let singleton = address!("41675C099F32341bf84BFc5382aF534df5C7461a");
        let initializer = Bytes::from(vec![0x01, 0x02, 0x03]);
        let creation_code = Bytes::from(vec![0x60, 0x80, 0x60, 0x40]);

        let addr1 = compute_create2_address(
            factory,
            singleton,
            &initializer,
            U256::from(1),
            &creation_code,
        );

        let addr2 = compute_create2_address(
            factory,
            singleton,
            &initializer,
            U256::from(2),
            &creation_code,
        );

        assert_ne!(addr1, addr2, "Different salt nonces should produce different addresses");
    }
}
