use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use alloy::primitives::{Address, Bytes, B256, U256};
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::encoding::compute_safe_transaction_hash;
use safe_rs::{recover_signer, Call, Operation, PreparedSafeTx, SafeTxParams};
use serde::{Deserialize, Serialize};

/// Unified Safe transaction bundle file for calls, prepared Safe transaction,
/// offchain owner signatures, and optional HD/Ledger rotation swaps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFile {
    /// Ordered user calls (excluding any automatically appended rotation `swapOwner` calls,
    /// which are tracked in `rotations` and reconstructed/verified deterministically)
    pub calls: Vec<BundleCall>,
    /// Prepared Safe transaction, populated once prepared/signed against a Safe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx: Option<BundleSafeTx>,
    /// Offchain owner signatures keyed by checksummed/hex Owner Address -> 65-byte 0x-hex signature
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signatures: BTreeMap<Address, Bytes>,
    /// Optional rotation swaps included in `tx.data`, keyed by old_owner -> BundleRotationSwap
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotations: Vec<BundleRotationSwap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleCall {
    pub to: Address,
    #[serde(default)]
    pub value: U256,
    #[serde(default)]
    pub data: Bytes,
    #[serde(default)]
    pub operation: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSafeTx {
    pub chain_id: u64,
    pub safe: Address,
    pub nonce: U256,
    pub safe_tx_hash: B256,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub operation: u8,
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: Address,
    pub refund_receiver: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleRotationSwap {
    pub old_owner: Address,
    pub new_owner: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_owner_index: Option<u32>,
}

impl From<&Call> for BundleCall {
    fn from(call: &Call) -> Self {
        Self {
            to: call.to,
            value: call.value,
            data: call.data.clone(),
            operation: call.operation.as_u8(),
        }
    }
}

impl BundleCall {
    pub fn to_call(&self) -> Result<Call> {
        let operation = Operation::from_u8(self.operation)
            .ok_or_else(|| eyre!("Invalid operation: {}", self.operation))?;
        Ok(Call::new(self.to, self.value, self.data.clone()).with_operation(operation))
    }
}

impl From<&PreparedSafeTx> for BundleSafeTx {
    fn from(prepared: &PreparedSafeTx) -> Self {
        let p = &prepared.params;
        Self {
            chain_id: prepared.chain_id,
            safe: prepared.safe,
            nonce: p.nonce,
            safe_tx_hash: prepared.safe_tx_hash,
            to: p.to,
            value: p.value,
            data: p.data.clone(),
            operation: p.operation.as_u8(),
            safe_tx_gas: p.safe_tx_gas,
            base_gas: p.base_gas,
            gas_price: p.gas_price,
            gas_token: p.gas_token,
            refund_receiver: p.refund_receiver,
        }
    }
}

impl BundleFile {
    /// Loads a `BundleFile` from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("Bundle file not found: {}", path.display());
        }
        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parses a `BundleFile` from JSON content.
    pub fn parse(content: &str) -> Result<Self> {
        let bundle: Self =
            serde_json::from_str(content).map_err(|e| eyre!("Invalid bundle JSON: {e}"))?;
        // Validate calls and any prepared tx/signatures upfront
        let _ = bundle.calls()?;
        if let Some(prepared) = bundle.prepared_tx()? {
            for (&owner, sig) in &bundle.signatures {
                let recovered = recover_signer(prepared.safe_tx_hash, sig)
                    .map_err(|e| eyre!("Invalid signature for {owner} in bundle: {e}"))?;
                if recovered != owner {
                    bail!(
                        "Signature mismatch in bundle: key is {owner}, but signature recovered to {recovered}"
                    );
                }
            }
        }
        Ok(bundle)
    }

    /// Writes the bundle as pretty-printed JSON with a trailing newline.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, format!("{json}\n"))?;
        Ok(())
    }

    /// Builds a new `BundleFile` from a slice of `Call`s.
    pub fn from_calls(calls: &[Call]) -> Self {
        Self {
            calls: calls.iter().map(BundleCall::from).collect(),
            tx: None,
            signatures: BTreeMap::new(),
            rotations: Vec::new(),
        }
    }

    /// Converts `self.calls` into `Vec<Call>`.
    pub fn calls(&self) -> Result<Vec<Call>> {
        self.calls.iter().map(BundleCall::to_call).collect()
    }

    /// Reconstructs `PreparedSafeTx` from `self.tx` and verifies `safe_tx_hash`.
    pub fn prepared_tx(&self) -> Result<Option<PreparedSafeTx>> {
        let Some(tx) = &self.tx else {
            return Ok(None);
        };
        let operation = Operation::from_u8(tx.operation)
            .ok_or_else(|| eyre!("Invalid operation in bundle tx: {}", tx.operation))?;
        let params = SafeTxParams {
            to: tx.to,
            value: tx.value,
            data: tx.data.clone(),
            operation,
            safe_tx_gas: tx.safe_tx_gas,
            base_gas: tx.base_gas,
            gas_price: tx.gas_price,
            gas_token: tx.gas_token,
            refund_receiver: tx.refund_receiver,
            nonce: tx.nonce,
        };
        let recomputed = compute_safe_transaction_hash(tx.chain_id, tx.safe, &params);
        if recomputed != tx.safe_tx_hash {
            bail!(
                "Bundle tx safe_tx_hash mismatch: recorded {}, recomputed {recomputed}",
                tx.safe_tx_hash
            );
        }
        Ok(Some(PreparedSafeTx {
            chain_id: tx.chain_id,
            safe: tx.safe,
            params,
            safe_tx_hash: recomputed,
        }))
    }

    /// Merges a prepared Safe transaction, new offchain signatures, and rotation swaps into this bundle.
    pub fn merge(
        &mut self,
        prepared: &PreparedSafeTx,
        new_sigs: &BTreeMap<Address, Bytes>,
        rotations: &[BundleRotationSwap],
    ) -> Result<()> {
        if let Some(existing) = &self.tx {
            if existing.safe_tx_hash != prepared.safe_tx_hash {
                bail!(
                    "Bundle file already contains a different Safe transaction (existing hash {} at nonce {}, new hash {} at nonce {})",
                    existing.safe_tx_hash,
                    existing.nonce,
                    prepared.safe_tx_hash,
                    prepared.params.nonce
                );
            }
        }
        self.tx = Some(BundleSafeTx::from(prepared));
        for swap in rotations {
            if let Some(existing_swap) = self
                .rotations
                .iter_mut()
                .find(|s| s.old_owner == swap.old_owner)
            {
                if existing_swap.new_owner != swap.new_owner {
                    bail!(
                        "Conflicting rotation swap for owner {}: {} vs {}",
                        swap.old_owner,
                        existing_swap.new_owner,
                        swap.new_owner
                    );
                }
                if existing_swap.new_owner_index.is_none() {
                    existing_swap.new_owner_index = swap.new_owner_index;
                }
            } else {
                self.rotations.push(swap.clone());
            }
        }

        // Validate existing signatures against prepared.safe_tx_hash
        for (&owner, sig) in &self.signatures {
            let recovered = recover_signer(prepared.safe_tx_hash, sig)
                .map_err(|e| eyre!("Invalid existing signature for {owner}: {e}"))?;
            if recovered != owner {
                bail!(
                    "Existing signature in bundle for {owner} recovered to {recovered} for hash {}",
                    prepared.safe_tx_hash
                );
            }
        }

        // Validate and insert new signatures
        for (&owner, sig) in new_sigs {
            let recovered = recover_signer(prepared.safe_tx_hash, sig)
                .map_err(|e| eyre!("Invalid signature for {owner}: {e}"))?;
            if recovered != owner {
                bail!(
                    "Signature for {owner} recovered to {recovered} for hash {}",
                    prepared.safe_tx_hash
                );
            }
            self.signatures.insert(owner, sig.clone());
        }

        Ok(())
    }

    /// Merges signatures (and rotation entries) from another `BundleFile` that shares the same `calls` and `tx`.
    pub fn merge_from_file(&mut self, other: &BundleFile) -> Result<()> {
        if self.calls != other.calls {
            bail!("Cannot merge bundles with different call lists");
        }
        match (&self.tx, &other.tx) {
            (Some(a), Some(b)) if a.safe_tx_hash != b.safe_tx_hash => {
                bail!(
                    "Cannot merge bundles with different safe_tx_hash: {} vs {}",
                    a.safe_tx_hash,
                    b.safe_tx_hash
                );
            }
            (None, Some(_)) => {
                if let Some(prepared) = other.prepared_tx()? {
                    self.merge(&prepared, &other.signatures, &other.rotations)?;
                }
            }
            (Some(_), _) => {
                let prepared = self.prepared_tx()?.expect("tx is Some");
                self.merge(&prepared, &other.signatures, &other.rotations)?;
            }
            (None, None) => {
                if !other.signatures.is_empty() {
                    bail!("Cannot merge signatures from a bundle without a prepared tx");
                }
                for swap in &other.rotations {
                    if !self.rotations.iter().any(|s| s.old_owner == swap.old_owner) {
                        self.rotations.push(swap.clone());
                    }
                }
            }
        }
        Ok(())
    }
}


/// Parses bundle JSON content and returns its `Vec<Call>`
#[cfg(test)]
pub fn parse_bundle(content: &str) -> Result<Vec<Call>> {
    BundleFile::parse(content)?.calls()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::local::PrivateKeySigner;
    use safe_rs::SafeTxGasPolicy;

    const SAFE: Address = address!("0x1000000000000000000000000000000000000001");

    #[test]
    fn test_parse_bundle() {
        let json = r#"{
            "calls": [
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
            ]
        }"#;

        let calls = parse_bundle(json).unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].value, U256::from(1000));
        assert_eq!(calls[1].data, Bytes::new());
    }

    #[test]
    fn test_parse_bundle_hex_values_and_operations() {
        let json = r#"{
            "calls": [
                {
                    "to": "0x1234567890123456789012345678901234567890",
                    "value": "0x3e8",
                    "data": "0xa9059cbb",
                    "operation": 1
                }
            ]
        }"#;

        let calls = parse_bundle(json).unwrap();
        assert_eq!(calls[0].value, U256::from(1000));
        assert_eq!(calls[0].data, Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]));
        assert_eq!(calls[0].operation, Operation::DelegateCall);
    }

    #[test]
    fn test_parse_bundle_rejects_bad_input() {
        let bad_value =
            r#"{"calls": [{"to": "0x1234567890123456789012345678901234567890", "value": "ten"}]}"#;
        assert!(parse_bundle(bad_value).is_err());
        let bad_data =
            r#"{"calls": [{"to": "0x1234567890123456789012345678901234567890", "data": "0xzz"}]}"#;
        assert!(parse_bundle(bad_data).is_err());
        let bad_op =
            r#"{"calls": [{"to": "0x1234567890123456789012345678901234567890", "operation": 2}]}"#;
        assert!(parse_bundle(bad_op).is_err());
        let bare_array = r#"[{"to": "0x1234567890123456789012345678901234567890"}]"#;
        assert!(parse_bundle(bare_array).is_err());
    }

    #[test]
    fn test_parse_bundle_minimal() {
        let json = r#"{
            "calls": [
                {
                    "to": "0x1234567890123456789012345678901234567890"
                }
            ]
        }"#;

        let calls = parse_bundle(json).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].value, U256::ZERO);
        assert!(calls[0].data.is_empty());
    }

    #[tokio::test]
    async fn test_bundle_merge_and_hash_verification() {
        let s1 = PrivateKeySigner::random();
        let s2 = PrivateKeySigner::random();
        let recipient = address!("0x1234567890123456789012345678901234567890");
        let call = Call::new(recipient, U256::from(100), Bytes::new());

        let prepared =
            PreparedSafeTx::single_call(1, SAFE, &call, U256::from(3), SafeTxGasPolicy::Zero)
                .unwrap();
        let signed1 = prepared.sign(&s1).await.unwrap();
        let signed2 = prepared.sign(&s2).await.unwrap();

        let mut b1 = BundleFile::from_calls(std::slice::from_ref(&call));
        b1.merge(&prepared, &signed1.signatures, &[]).unwrap();

        let mut b2 = BundleFile::from_calls(std::slice::from_ref(&call));
        let swap = BundleRotationSwap {
            old_owner: s2.address(),
            new_owner: address!("0x2222222222222222222222222222222222222222"),
            new_owner_index: Some(4),
        };
        b2.merge(&prepared, &signed2.signatures, std::slice::from_ref(&swap))
            .unwrap();

        b1.merge_from_file(&b2).unwrap();
        assert_eq!(b1.signatures.len(), 2);
        assert!(b1.signatures.contains_key(&s1.address()));
        assert!(b1.signatures.contains_key(&s2.address()));
        assert_eq!(b1.rotations, vec![swap]);

        // Roundtrip through JSON
        let json = serde_json::to_string_pretty(&b1).unwrap();
        let parsed = BundleFile::parse(&json).unwrap();
        assert_eq!(parsed, b1);
        assert_eq!(parsed.prepared_tx().unwrap().unwrap(), prepared);

        // Conflicting nonce/hash fails to merge
        let other_prepared =
            PreparedSafeTx::single_call(1, SAFE, &call, U256::from(4), SafeTxGasPolicy::Zero)
                .unwrap();
        assert!(b1.merge(&other_prepared, &BTreeMap::new(), &[]).is_err());
    }
}
