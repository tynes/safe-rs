//! [`AnySigner`]: the key a command signs with, any backend `cast` supports.

use std::fmt;
use std::sync::Arc;

use alloy::consensus::SignableTransaction;
use alloy::dyn_abi::TypedData;
use alloy::network::TxSigner;
use alloy::primitives::{Address, ChainId, Signature, B256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::{Eip712Domain, SolStruct};
use async_trait::async_trait;
use foundry_wallets::WalletSigner;

/// The key a command signs with: any signer `cast` and `forge` support, as
/// foundry's [`WalletSigner`]. A local key (`--private-key`, `--keystore`,
/// `--account`, `--mnemonic`, `--interactive`), a hardware wallet
/// (`--ledger`, `--trezor`) or a remote one (`--aws`, `--gcp`, `--turnkey`).
///
/// It is an alloy [`Signer`] and [`TxSigner`], and cheap to clone. Hardware
/// wallets sign EIP-712 typed data and transactions, but not bare hashes:
/// `sign_hash` fails on them (see [`can_sign_hash`](Self::can_sign_hash)), so
/// sign typed data with [`Signer::sign_typed_data`].
#[derive(Clone)]
pub struct AnySigner(Arc<WalletSigner>);

impl AnySigner {
    /// The key's address.
    pub fn address(&self) -> Address {
        Signer::address(self.0.as_ref())
    }

    /// The foundry signer inside.
    pub fn inner(&self) -> &WalletSigner {
        &self.0
    }

    /// Whether the key signs a bare 32-byte hash. Hardware wallets (Ledger,
    /// Trezor) refuse to; local and remote (KMS, Turnkey) keys do.
    pub fn can_sign_hash(&self) -> bool {
        !self.kind().is_hardware()
    }

    /// Which backend holds the key. Lets a host branch on the signer (say,
    /// to warn before a Trezor prompt) without depending on foundry-wallets.
    pub fn kind(&self) -> SignerKind {
        match self.0.as_ref() {
            WalletSigner::Local(_) => SignerKind::Local,
            WalletSigner::Ledger(_) => SignerKind::Ledger,
            WalletSigner::Trezor(_) => SignerKind::Trezor,
            #[cfg(feature = "aws-kms")]
            WalletSigner::Aws(_) => SignerKind::Aws,
            #[cfg(feature = "gcp-kms")]
            WalletSigner::Gcp(_) => SignerKind::Gcp,
            #[cfg(feature = "turnkey")]
            WalletSigner::Turnkey(_) => SignerKind::Turnkey,
        }
    }
}

/// The backend an [`AnySigner`]'s key lives in, from [`AnySigner::kind`].
///
/// Every variant exists whatever features the crate is built with; `Aws`,
/// `Gcp` and `Turnkey` are only returned when their feature is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignerKind {
    /// A key in memory: `--private-key`, `--keystore`, `--account`,
    /// `--mnemonic` or `--interactive`.
    Local,
    /// A Ledger hardware wallet (`--ledger`).
    Ledger,
    /// A Trezor hardware wallet (`--trezor`).
    Trezor,
    /// An AWS KMS key (`--aws`).
    Aws,
    /// A GCP KMS key (`--gcp`).
    Gcp,
    /// A Turnkey key (`--turnkey`).
    Turnkey,
}

impl SignerKind {
    /// Whether the key is on a hardware wallet (Ledger or Trezor), which
    /// asks for confirmation on the device and will not sign a bare hash.
    pub fn is_hardware(self) -> bool {
        matches!(self, Self::Ledger | Self::Trezor)
    }

    /// A short name: "local", "Ledger", "Trezor", "AWS KMS", "GCP KMS" or
    /// "Turnkey".
    pub fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ledger => "Ledger",
            Self::Trezor => "Trezor",
            Self::Aws => "AWS KMS",
            Self::Gcp => "GCP KMS",
            Self::Turnkey => "Turnkey",
        }
    }
}

impl fmt::Display for SignerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<WalletSigner> for AnySigner {
    fn from(signer: WalletSigner) -> Self {
        Self(Arc::new(signer))
    }
}

impl From<PrivateKeySigner> for AnySigner {
    fn from(key: PrivateKeySigner) -> Self {
        WalletSigner::Local(key).into()
    }
}

impl fmt::Debug for AnySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnySigner")
            .field("kind", &self.kind().name())
            .field("address", &self.address())
            .finish()
    }
}

#[async_trait]
impl Signer for AnySigner {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<Signature> {
        self.0.sign_hash(hash).await
    }

    async fn sign_message(&self, message: &[u8]) -> alloy::signers::Result<Signature> {
        self.0.sign_message(message).await
    }

    async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> alloy::signers::Result<Signature>
    where
        Self: Sized,
    {
        self.0.sign_typed_data(payload, domain).await
    }

    async fn sign_dynamic_typed_data(
        &self,
        payload: &TypedData,
    ) -> alloy::signers::Result<Signature> {
        self.0.sign_dynamic_typed_data(payload).await
    }

    fn address(&self) -> Address {
        AnySigner::address(self)
    }

    fn chain_id(&self) -> Option<ChainId> {
        self.0.chain_id()
    }

    /// Sets the chain ID only while this is the sole handle on the key: on
    /// an [`AnySigner`] that has been cloned (the key is shared) it does
    /// nothing.
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        if let Some(signer) = Arc::get_mut(&mut self.0) {
            signer.set_chain_id(chain_id);
        }
    }
}

#[async_trait]
impl TxSigner<Signature> for AnySigner {
    fn address(&self) -> Address {
        AnySigner::address(self)
    }

    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> alloy::signers::Result<Signature> {
        TxSigner::sign_transaction(self.0.as_ref(), tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_key_keeps_its_address() {
        let key = PrivateKeySigner::random();
        let any = AnySigner::from(key.clone());
        assert_eq!(any.address(), key.address());
        assert_eq!(any.kind(), SignerKind::Local);
        assert!(any.can_sign_hash());
        assert!(format!("{any:?}").contains("local"));
    }

    #[test]
    fn only_hardware_kinds_are_hardware() {
        assert!(SignerKind::Ledger.is_hardware());
        assert!(SignerKind::Trezor.is_hardware());
        for kind in [
            SignerKind::Local,
            SignerKind::Aws,
            SignerKind::Gcp,
            SignerKind::Turnkey,
        ] {
            assert!(!kind.is_hardware(), "{kind}");
        }
    }

    #[tokio::test]
    async fn signatures_match_the_key_inside() {
        let key = PrivateKeySigner::random();
        let any = AnySigner::from(key.clone());
        let hash = B256::repeat_byte(7);
        assert_eq!(
            any.sign_hash(&hash).await.unwrap(),
            key.sign_hash(&hash).await.unwrap()
        );
    }
}
