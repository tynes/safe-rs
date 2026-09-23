//! Frozen Safe transaction envelopes.
//!
//! The [`SafeBuilder`](crate::SafeBuilder) resolves the Safe nonce and `safeTxGas`
//! at execution time. Callers that must review, simulate, sign and broadcast the
//! *exact same* Safe transaction (for example a CLI that writes an inspectable
//! plan) need those parameters fixed up front. [`PreparedSafeTx`] captures every
//! field of the Safe transaction together with its EIP-712 hash, and
//! [`SignedSafeTx`] adds the owner signature and the `execTransaction` calldata.
//!
//! Nothing in this module talks to the network.

use alloy::primitives::{Address, Bytes, Signature, B256, U256};
use alloy::signers::Signer;
use alloy::sol_types::SolCall;

use crate::contracts::{IMultiSendCallOnly, ISafe};
use crate::encoding::{compute_safe_transaction_hash, encode_multisend_data, SafeTxParams};
use crate::error::{Error, Result};
use crate::signing::{encode_pre_validated_signature, sign_hash};
use crate::types::{Call, Operation};

/// How `safeTxGas` is set on a prepared Safe transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeTxGasPolicy {
    /// `safeTxGas = 0` with `gasPrice = 0`.
    ///
    /// The inner call receives all remaining gas and any inner failure reverts
    /// the outer `execTransaction` with `GS013`, so a mined transaction always
    /// means the inner call succeeded. This is the fail-closed production policy.
    Zero,
    /// An explicit `safeTxGas`.
    ///
    /// With a non-zero value the Safe does not revert when the inner call
    /// fails: it emits `ExecutionFailure` and still consumes the nonce. Only use
    /// this to reproduce that behaviour (for example in tests).
    Explicit(U256),
}

impl SafeTxGasPolicy {
    fn value(self) -> U256 {
        match self {
            Self::Zero => U256::ZERO,
            Self::Explicit(gas) => gas,
        }
    }
}

/// A Safe transaction whose every field, including the nonce, is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSafeTx {
    /// Chain ID used in the EIP-712 domain
    pub chain_id: u64,
    /// The Safe that will execute the transaction
    pub safe: Address,
    /// The Safe transaction fields
    pub params: SafeTxParams,
    /// The EIP-712 digest the owner signs (equals the Safe's `getTransactionHash`)
    pub safe_tx_hash: B256,
}

impl PreparedSafeTx {
    /// Builds a prepared transaction from explicit parameters.
    ///
    /// Refund fields are taken verbatim; callers that want the fail-closed policy
    /// should use [`PreparedSafeTx::single_call`] or
    /// [`PreparedSafeTx::call_only_batch`] instead.
    pub fn from_params(chain_id: u64, safe: Address, params: SafeTxParams) -> Self {
        let safe_tx_hash = compute_safe_transaction_hash(chain_id, safe, &params);
        Self {
            chain_id,
            safe,
            params,
            safe_tx_hash,
        }
    }

    /// Prepares a single CALL executed directly by the Safe.
    ///
    /// Returns [`Error::DelegateCallNotAllowed`] if the call is a DelegateCall.
    pub fn single_call(
        chain_id: u64,
        safe: Address,
        call: &Call,
        nonce: U256,
        gas: SafeTxGasPolicy,
    ) -> Result<Self> {
        if call.operation != Operation::Call {
            return Err(Error::DelegateCallNotAllowed { index: 0 });
        }
        let params = SafeTxParams {
            to: call.to,
            value: call.value,
            data: call.data.clone(),
            operation: Operation::Call,
            safe_tx_gas: gas.value(),
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce,
        };
        Ok(Self::from_params(chain_id, safe, params))
    }

    /// Prepares a batch of CALLs.
    ///
    /// One call is executed directly. Two or more calls are packed into
    /// `MultiSendCallOnly.multiSend` and executed through a single outer
    /// DELEGATECALL to `multi_send_call_only`, which is the only DELEGATECALL
    /// this function ever emits. Every inner entry must be a CALL.
    pub fn call_only_batch(
        chain_id: u64,
        safe: Address,
        multi_send_call_only: Address,
        calls: &[Call],
        nonce: U256,
        gas: SafeTxGasPolicy,
    ) -> Result<Self> {
        if calls.is_empty() {
            return Err(Error::NoCalls);
        }
        if let Some(index) = calls.iter().position(|c| c.operation != Operation::Call) {
            return Err(Error::DelegateCallNotAllowed { index });
        }
        if let [call] = calls {
            return Self::single_call(chain_id, safe, call, nonce, gas);
        }
        let data = IMultiSendCallOnly::multiSendCall {
            transactions: encode_multisend_data(calls),
        }
        .abi_encode();
        let params = SafeTxParams {
            to: multi_send_call_only,
            value: U256::ZERO,
            data: Bytes::from(data),
            operation: Operation::DelegateCall,
            safe_tx_gas: gas.value(),
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce,
        };
        Ok(Self::from_params(chain_id, safe, params))
    }

    /// Returns true when the refund fields follow the fail-closed policy
    /// (`safeTxGas`, `baseGas` and `gasPrice` zero; no gas token or refund receiver).
    pub fn is_fail_closed(&self) -> bool {
        self.params.safe_tx_gas.is_zero()
            && self.params.base_gas.is_zero()
            && self.params.gas_price.is_zero()
            && self.params.gas_token == Address::ZERO
            && self.params.refund_receiver == Address::ZERO
    }

    /// Signs the Safe transaction hash with an owner key.
    pub async fn sign<S: Signer + Sync>(&self, signer: &S) -> Result<SignedSafeTx> {
        let signature = sign_hash(signer, self.safe_tx_hash).await?;
        Ok(SignedSafeTx {
            prepared: self.clone(),
            owner: signer.address(),
            signature,
        })
    }

    /// Builds a pre-validated (`v = 1`) signature for `owner`.
    ///
    /// Safe accepts it only when `msg.sender == owner` (or the owner approved the
    /// hash on-chain). It lets a caller simulate the full `execTransaction` path
    /// without the owner key, with the owner EOA as the transaction sender. It is
    /// not proof that the owner authorized anything.
    pub fn prevalidated(&self, owner: Address) -> SignedSafeTx {
        SignedSafeTx {
            prepared: self.clone(),
            owner,
            signature: encode_pre_validated_signature(owner),
        }
    }
}

/// A prepared Safe transaction plus an owner signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSafeTx {
    /// The frozen Safe transaction
    pub prepared: PreparedSafeTx,
    /// The owner the signature is attributed to
    pub owner: Address,
    /// 65-byte Safe signature (`r || s || v`)
    pub signature: Bytes,
}

impl SignedSafeTx {
    /// Returns true for a pre-validated (`v = 1`) signature.
    pub fn is_prevalidated(&self) -> bool {
        self.signature.len() == 65 && self.signature[64] == 1
    }

    /// ABI-encoded `execTransaction` calldata for the outer transaction.
    pub fn exec_calldata(&self) -> Bytes {
        let p = &self.prepared.params;
        let call = ISafe::execTransactionCall {
            to: p.to,
            value: p.value,
            data: p.data.clone(),
            operation: p.operation.as_u8(),
            safeTxGas: p.safe_tx_gas,
            baseGas: p.base_gas,
            gasPrice: p.gas_price,
            gasToken: p.gas_token,
            refundReceiver: p.refund_receiver,
            signatures: self.signature.clone(),
        };
        Bytes::from(call.abi_encode())
    }

    /// Recovers the address that produced the signature.
    ///
    /// For an ECDSA signature (`v` 27/28) this is `ecrecover(safe_tx_hash)`. A
    /// pre-validated signature carries the owner in `r` and is returned as is.
    pub fn recover_owner(&self) -> Result<Address> {
        if self.signature.len() != 65 {
            return Err(Error::Signing(format!(
                "invalid signature length {}",
                self.signature.len()
            )));
        }
        if self.is_prevalidated() {
            return Ok(Address::from_slice(&self.signature[12..32]));
        }
        let signature = Signature::from_raw(&self.signature)
            .map_err(|e| Error::Signing(format!("invalid signature: {e}")))?;
        signature
            .recover_address_from_prehash(&self.prepared.safe_tx_hash)
            .map_err(|e| Error::Signing(format!("signature recovery failed: {e}")))
    }

    /// Checks that the signature recovers to [`SignedSafeTx::owner`].
    pub fn verify(&self) -> Result<()> {
        let recovered = self.recover_owner()?;
        if recovered != self.owner {
            return Err(Error::SignatureMismatch {
                expected: self.owner,
                recovered,
            });
        }
        Ok(())
    }
}

/// Fields decoded from `execTransaction` calldata.
///
/// The Safe nonce is not part of the calldata, so it is not included here; use
/// [`DecodedExecTransaction::into_params`] with the nonce the transaction was
/// signed for to recompute the Safe transaction hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedExecTransaction {
    /// Target of the Safe transaction
    pub to: Address,
    /// Value sent by the Safe
    pub value: U256,
    /// Inner calldata
    pub data: Bytes,
    /// Operation (0 = CALL, 1 = DELEGATECALL)
    pub operation: Operation,
    /// `safeTxGas`
    pub safe_tx_gas: U256,
    /// `baseGas`
    pub base_gas: U256,
    /// `gasPrice`
    pub gas_price: U256,
    /// `gasToken`
    pub gas_token: Address,
    /// `refundReceiver`
    pub refund_receiver: Address,
    /// Packed signatures
    pub signatures: Bytes,
}

impl DecodedExecTransaction {
    /// Converts to [`SafeTxParams`] for the given nonce.
    pub fn into_params(self, nonce: U256) -> SafeTxParams {
        SafeTxParams {
            to: self.to,
            value: self.value,
            data: self.data,
            operation: self.operation,
            safe_tx_gas: self.safe_tx_gas,
            base_gas: self.base_gas,
            gas_price: self.gas_price,
            gas_token: self.gas_token,
            refund_receiver: self.refund_receiver,
            nonce,
        }
    }
}

/// Decodes `execTransaction` calldata (for example from a mined transaction).
pub fn decode_exec_calldata(data: &[u8]) -> Result<DecodedExecTransaction> {
    let call = ISafe::execTransactionCall::abi_decode(data)
        .map_err(|e| Error::Abi(format!("not execTransaction calldata: {e}")))?;
    let operation = Operation::from_u8(call.operation)
        .ok_or_else(|| Error::Abi(format!("invalid operation {}", call.operation)))?;
    Ok(DecodedExecTransaction {
        to: call.to,
        value: call.value,
        data: call.data,
        operation,
        safe_tx_gas: call.safeTxGas,
        base_gas: call.baseGas,
        gas_price: call.gasPrice,
        gas_token: call.gasToken,
        refund_receiver: call.refundReceiver,
        signatures: call.signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::local::PrivateKeySigner;

    const SAFE: Address = address!("0x1000000000000000000000000000000000000001");
    const MSCO: Address = address!("0x9641d764fc13c8B624c04430C7356C1C7C8102e2");

    fn call(to: Address) -> Call {
        Call::call(to, Bytes::from(vec![0xde, 0xad]))
    }

    #[test]
    fn single_call_rejects_delegatecall() {
        let dc = Call::delegate_call(SAFE, Bytes::new());
        let err = PreparedSafeTx::single_call(1, SAFE, &dc, U256::ZERO, SafeTxGasPolicy::Zero);
        assert!(matches!(
            err,
            Err(Error::DelegateCallNotAllowed { index: 0 })
        ));
    }

    #[test]
    fn batch_rejects_inner_delegatecall() {
        let calls = vec![call(SAFE), Call::delegate_call(SAFE, Bytes::new())];
        let err = PreparedSafeTx::call_only_batch(
            1,
            SAFE,
            MSCO,
            &calls,
            U256::ZERO,
            SafeTxGasPolicy::Zero,
        );
        assert!(matches!(
            err,
            Err(Error::DelegateCallNotAllowed { index: 1 })
        ));
    }

    #[test]
    fn batch_of_one_is_a_direct_call() {
        let p = PreparedSafeTx::call_only_batch(
            1,
            SAFE,
            MSCO,
            &[call(MSCO)],
            U256::from(3),
            SafeTxGasPolicy::Zero,
        )
        .unwrap();
        assert_eq!(p.params.operation, Operation::Call);
        assert_eq!(p.params.to, MSCO);
        assert_eq!(p.params.nonce, U256::from(3));
        assert!(p.is_fail_closed());
    }

    #[test]
    fn batch_of_two_delegatecalls_multisend_call_only() {
        let p = PreparedSafeTx::call_only_batch(
            1,
            SAFE,
            MSCO,
            &[call(SAFE), call(MSCO)],
            U256::ZERO,
            SafeTxGasPolicy::Zero,
        )
        .unwrap();
        assert_eq!(p.params.operation, Operation::DelegateCall);
        assert_eq!(p.params.to, MSCO);
        assert_eq!(p.params.value, U256::ZERO);
    }

    #[test]
    fn empty_batch_is_rejected() {
        let err =
            PreparedSafeTx::call_only_batch(1, SAFE, MSCO, &[], U256::ZERO, SafeTxGasPolicy::Zero);
        assert!(matches!(err, Err(Error::NoCalls)));
    }

    #[tokio::test]
    async fn sign_recover_and_roundtrip_calldata() {
        let signer = PrivateKeySigner::random();
        let p = PreparedSafeTx::call_only_batch(
            10,
            SAFE,
            MSCO,
            &[call(SAFE), call(MSCO)],
            U256::from(7),
            SafeTxGasPolicy::Zero,
        )
        .unwrap();
        let signed = p.sign(&signer).await.unwrap();
        assert_eq!(signed.recover_owner().unwrap(), signer.address());
        signed.verify().unwrap();

        let decoded = decode_exec_calldata(&signed.exec_calldata()).unwrap();
        assert_eq!(decoded.signatures, signed.signature);
        let params = decoded.into_params(U256::from(7));
        assert_eq!(params, p.params);
        assert_eq!(
            compute_safe_transaction_hash(10, SAFE, &params),
            p.safe_tx_hash
        );
    }

    #[test]
    fn prevalidated_signature_recovers_owner() {
        let owner = address!("0x00000000000000000000000000000000000000aa");
        let p =
            PreparedSafeTx::single_call(1, SAFE, &call(MSCO), U256::ZERO, SafeTxGasPolicy::Zero)
                .unwrap();
        let signed = p.prevalidated(owner);
        assert!(signed.is_prevalidated());
        assert_eq!(signed.recover_owner().unwrap(), owner);
    }

    #[test]
    fn explicit_gas_is_not_fail_closed() {
        let p = PreparedSafeTx::single_call(
            1,
            SAFE,
            &call(MSCO),
            U256::ZERO,
            SafeTxGasPolicy::Explicit(U256::from(100_000)),
        )
        .unwrap();
        assert!(!p.is_fail_closed());
    }
}
