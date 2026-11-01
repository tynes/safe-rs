//! [`AnySigner`]: the key a command signs with, local or on a Ledger.

use std::fmt;
#[cfg(feature = "ledger")]
use std::sync::Arc;

use alloy::consensus::SignableTransaction;
use alloy::dyn_abi::TypedData;
use alloy::network::TxSigner;
use alloy::primitives::{Address, ChainId, Signature, B256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::{Eip712Domain, SolStruct};
#[cfg(feature = "ledger")]
use alloy_signer_ledger::LedgerSigner;
use async_trait::async_trait;

/// The key a command signs with: a local key (`--private-key`, `--keystore`,
/// `--hd-key`, `--interactive`) or one on a Ledger (`--ledger`).
///
/// It is an alloy [`Signer`] and [`TxSigner`]. A Ledger signs EIP-712 typed
/// data and transactions, but not bare hashes: `sign_hash` fails on it, so
/// sign typed data with [`Signer::sign_typed_data`].
#[derive(Clone)]
#[non_exhaustive]
pub enum AnySigner {
    Local(PrivateKeySigner),
    #[cfg(feature = "ledger")]
    Ledger(Arc<LedgerSigner>),
}

impl AnySigner {
    /// The key's address.
    pub fn address(&self) -> Address {
        match self {
            Self::Local(key) => key.address(),
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => Signer::address(key.as_ref()),
        }
    }

    /// The local key, if it is one.
    pub fn as_local(&self) -> Option<&PrivateKeySigner> {
        match self {
            Self::Local(key) => Some(key),
            #[cfg(feature = "ledger")]
            Self::Ledger(_) => None,
        }
    }

    /// Whether the key is on a device, which asks before each signature.
    pub fn is_device(&self) -> bool {
        self.as_local().is_none()
    }
}

impl From<PrivateKeySigner> for AnySigner {
    fn from(key: PrivateKeySigner) -> Self {
        Self::Local(key)
    }
}

#[cfg(feature = "ledger")]
impl From<LedgerSigner> for AnySigner {
    fn from(key: LedgerSigner) -> Self {
        Self::Ledger(Arc::new(key))
    }
}

impl fmt::Debug for AnySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_device() { "Ledger" } else { "Local" };
        f.debug_struct("AnySigner")
            .field("kind", &kind)
            .field("address", &self.address())
            .finish()
    }
}

#[async_trait]
impl Signer for AnySigner {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<Signature> {
        match self {
            Self::Local(key) => key.sign_hash(hash).await,
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => key.sign_hash(hash).await,
        }
    }

    async fn sign_message(&self, message: &[u8]) -> alloy::signers::Result<Signature> {
        match self {
            Self::Local(key) => key.sign_message(message).await,
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => key.sign_message(message).await,
        }
    }

    async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> alloy::signers::Result<Signature>
    where
        Self: Sized,
    {
        match self {
            Self::Local(key) => key.sign_typed_data(payload, domain).await,
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => key.sign_typed_data(payload, domain).await,
        }
    }

    async fn sign_dynamic_typed_data(
        &self,
        payload: &TypedData,
    ) -> alloy::signers::Result<Signature> {
        match self {
            Self::Local(key) => key.sign_dynamic_typed_data(payload).await,
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => key.sign_dynamic_typed_data(payload).await,
        }
    }

    fn address(&self) -> Address {
        AnySigner::address(self)
    }

    fn chain_id(&self) -> Option<ChainId> {
        match self {
            Self::Local(key) => key.chain_id(),
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => key.chain_id(),
        }
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        match self {
            Self::Local(key) => key.set_chain_id(chain_id),
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => {
                if let Some(key) = Arc::get_mut(key) {
                    key.set_chain_id(chain_id);
                }
            }
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
        match self {
            Self::Local(key) => TxSigner::sign_transaction(key, tx).await,
            #[cfg(feature = "ledger")]
            Self::Ledger(key) => TxSigner::sign_transaction(key.as_ref(), tx).await,
        }
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
        assert!(!any.is_device());
        assert!(format!("{any:?}").contains("Local"));
    }
}
