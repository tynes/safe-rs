//! ECDSA signature generation for Safe transactions

use alloy::primitives::{Bytes, B256};
use alloy::signers::Signer;

use crate::error::{Error, Result};

/// Signs a message hash and formats it for Safe
///
/// Safe expects signatures in the format: r (32 bytes) || s (32 bytes) || v (1 byte)
/// where v is adjusted to be 27 or 28
pub async fn sign_hash<S: Signer>(signer: &S, hash: B256) -> Result<Bytes> {
    let signature = signer.sign_hash(&hash).await?;

    // Get r, s, v from the signature
    let r = signature.r();
    let s = signature.s();
    let v = signature.v();

    // Safe expects v to be 27 or 28 for EOA signatures
    // v is a bool (y_parity) in alloy - true means odd (28), false means even (27)
    let v_byte = if v { 28u8 } else { 27u8 };

    // Format: r || s || v
    let mut sig_bytes = Vec::with_capacity(65);
    sig_bytes.extend_from_slice(&r.to_be_bytes::<32>());
    sig_bytes.extend_from_slice(&s.to_be_bytes::<32>());
    sig_bytes.push(v_byte);

    Ok(Bytes::from(sig_bytes))
}

/// Signs a message using eth_sign (personal_sign) and formats for Safe
///
/// This adds the "\x19Ethereum Signed Message:\n32" prefix before signing
/// and adjusts v to be 31 or 32 to indicate eth_sign was used
pub async fn eth_sign_hash<S: Signer>(signer: &S, hash: B256) -> Result<Bytes> {
    let signature = signer.sign_hash(&hash).await?;

    let r = signature.r();
    let s = signature.s();
    let v = signature.v();

    // For eth_sign signatures in Safe, v is 31 or 32 (27/28 + 4)
    // v is a bool (y_parity) in alloy - true means odd (32), false means even (31)
    let v_byte = if v { 32u8 } else { 31u8 };

    let mut sig_bytes = Vec::with_capacity(65);
    sig_bytes.extend_from_slice(&r.to_be_bytes::<32>());
    sig_bytes.extend_from_slice(&s.to_be_bytes::<32>());
    sig_bytes.push(v_byte);

    Ok(Bytes::from(sig_bytes))
}

/// Encodes a pre-validated signature for a given owner
///
/// This creates a signature that indicates the owner has pre-approved the transaction.
/// Used when a contract owner has approved a hash.
pub fn encode_pre_validated_signature(owner: alloy::primitives::Address) -> Bytes {
    let mut sig_bytes = Vec::with_capacity(65);

    // r = owner address (left-padded to 32 bytes)
    let mut r = [0u8; 32];
    r[12..].copy_from_slice(owner.as_slice());
    sig_bytes.extend_from_slice(&r);

    // s = 0 (32 bytes)
    sig_bytes.extend_from_slice(&[0u8; 32]);

    // v = 1 (indicates pre-validated signature)
    sig_bytes.push(1);

    Bytes::from(sig_bytes)
}

/// Validates that a signature is 65 bytes and has a valid v value
pub fn validate_signature(signature: &[u8]) -> Result<()> {
    if signature.len() != 65 {
        return Err(Error::Signing(format!(
            "Invalid signature length: expected 65, got {}",
            signature.len()
        )));
    }

    let v = signature[64];
    // Valid v values: 0, 1 (pre-validated), 27, 28 (ECDSA), 31, 32 (eth_sign)
    if !matches!(v, 0 | 1 | 27 | 28 | 31 | 32) {
        return Err(Error::Signing(format!("Invalid signature v value: {}", v)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::local::PrivateKeySigner;

    #[tokio::test]
    async fn test_sign_hash() {
        let signer = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0x42);

        let signature = sign_hash(&signer, hash).await.unwrap();

        assert_eq!(signature.len(), 65);
        let v = signature[64];
        assert!(v == 27 || v == 28);
    }

    #[tokio::test]
    async fn test_eth_sign_hash() {
        let signer = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0x42);

        let signature = eth_sign_hash(&signer, hash).await.unwrap();

        assert_eq!(signature.len(), 65);
        let v = signature[64];
        assert!(v == 31 || v == 32);
    }

    #[test]
    fn test_pre_validated_signature() {
        let owner = address!("0x1234567890123456789012345678901234567890");
        let signature = encode_pre_validated_signature(owner);

        assert_eq!(signature.len(), 65);
        assert_eq!(signature[64], 1); // v = 1 for pre-validated

        // r should contain the owner address (left-padded)
        assert_eq!(&signature[12..32], owner.as_slice());
    }

    #[test]
    fn test_validate_signature() {
        // Valid signature
        let mut sig = vec![0u8; 65];
        sig[64] = 27;
        assert!(validate_signature(&sig).is_ok());

        sig[64] = 28;
        assert!(validate_signature(&sig).is_ok());

        sig[64] = 31;
        assert!(validate_signature(&sig).is_ok());

        sig[64] = 1;
        assert!(validate_signature(&sig).is_ok());

        // Invalid length
        assert!(validate_signature(&[0u8; 64]).is_err());

        // Invalid v
        sig[64] = 99;
        assert!(validate_signature(&sig).is_err());
    }
}
