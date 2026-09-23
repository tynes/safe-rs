//! Signed outer (EOA) transactions.
//!
//! A Safe transaction reaches the chain inside an ordinary EOA transaction that
//! calls `execTransaction` (or, for Safe creation, the proxy factory). This
//! module signs that outer transaction locally so the caller can persist the raw
//! bytes and hash *before* the first broadcast, and rebroadcast the exact same
//! bytes later if needed.

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::{Decodable2718, Encodable2718};
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::Signer;

use crate::error::{Error, Result};

/// Fields of an EIP-1559 outer transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterTxParams {
    /// Chain ID (EIP-155)
    pub chain_id: u64,
    /// Sender, which must be the signer's address
    pub from: Address,
    /// Sender account nonce
    pub nonce: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// `maxFeePerGas`
    pub max_fee_per_gas: u128,
    /// `maxPriorityFeePerGas`
    pub max_priority_fee_per_gas: u128,
    /// Recipient
    pub to: Address,
    /// Value in wei sent by the EOA
    pub value: U256,
    /// Calldata
    pub input: Bytes,
}

impl OuterTxParams {
    fn to_tx(&self) -> TxEip1559 {
        TxEip1559 {
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            to: TxKind::Call(self.to),
            value: self.value,
            access_list: Default::default(),
            input: self.input.clone(),
        }
    }

    /// Worst-case wei the sender needs: `gas_limit * max_fee_per_gas + value`.
    pub fn max_cost(&self) -> U256 {
        U256::from(self.gas_limit) * U256::from(self.max_fee_per_gas) + self.value
    }
}

/// A signed, EIP-2718 encoded outer transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOuterTx {
    /// The signed fields
    pub params: OuterTxParams,
    /// EIP-2718 encoded bytes for `eth_sendRawTransaction`
    pub raw: Bytes,
    /// Transaction hash
    pub tx_hash: B256,
}

/// Signs an EIP-1559 outer transaction.
///
/// Fails if `params.from` is not the signer's address.
pub async fn sign_outer_tx<S: Signer + Sync>(
    signer: &S,
    params: OuterTxParams,
) -> Result<SignedOuterTx> {
    if signer.address() != params.from {
        return Err(Error::SignatureMismatch {
            expected: params.from,
            recovered: signer.address(),
        });
    }
    let tx = params.to_tx();
    let signature = signer.sign_hash(&tx.signature_hash()).await?;
    let signed = tx.into_signed(signature);
    let tx_hash = *signed.hash();
    let envelope = TxEnvelope::Eip1559(signed);
    let raw = Bytes::from(envelope.encoded_2718());
    Ok(SignedOuterTx {
        params,
        raw,
        tx_hash,
    })
}

/// Decodes and verifies a raw outer transaction produced by [`sign_outer_tx`].
///
/// Returns the recovered parameters and hash. Only EIP-1559 transactions are
/// accepted.
pub fn decode_signed_outer_tx(raw: &[u8]) -> Result<SignedOuterTx> {
    let envelope = TxEnvelope::decode_2718(&mut &raw[..])
        .map_err(|e| Error::Encoding(format!("invalid raw transaction: {e}")))?;
    let TxEnvelope::Eip1559(signed) = &envelope else {
        return Err(Error::Encoding(
            "expected an EIP-1559 transaction".to_string(),
        ));
    };
    let from = signed
        .recover_signer()
        .map_err(|e| Error::Signing(format!("cannot recover sender: {e}")))?;
    let tx = signed.tx();
    let TxKind::Call(to) = tx.to else {
        return Err(Error::Encoding(
            "contract creation is not supported".to_string(),
        ));
    };
    Ok(SignedOuterTx {
        params: OuterTxParams {
            chain_id: tx.chain_id,
            from,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            to,
            value: tx.value,
            input: tx.input.clone(),
        },
        raw: Bytes::copy_from_slice(raw),
        tx_hash: *signed.hash(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::local::PrivateKeySigner;

    fn params(from: Address) -> OuterTxParams {
        OuterTxParams {
            chain_id: 31337,
            from,
            nonce: 4,
            gas_limit: 210_000,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: address!("0x2000000000000000000000000000000000000002"),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }
    }

    #[tokio::test]
    async fn sign_then_decode_roundtrip() {
        let signer = PrivateKeySigner::random();
        let signed = sign_outer_tx(&signer, params(signer.address()))
            .await
            .unwrap();
        let decoded = decode_signed_outer_tx(&signed.raw).unwrap();
        assert_eq!(decoded, signed);
        assert_eq!(decoded.params.from, signer.address());
    }

    #[tokio::test]
    async fn wrong_sender_is_rejected() {
        let signer = PrivateKeySigner::random();
        let other = address!("0x3000000000000000000000000000000000000003");
        assert!(matches!(
            sign_outer_tx(&signer, params(other)).await,
            Err(Error::SignatureMismatch { .. })
        ));
    }

    #[test]
    fn max_cost_includes_value() {
        let mut p = params(Address::ZERO);
        p.value = U256::from(5);
        assert_eq!(p.max_cost(), U256::from(210_000u64 * 3_000_000_000u64 + 5));
    }
}
