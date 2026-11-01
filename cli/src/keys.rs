//! The wallet owner keys come from: a phrase on disk or a Ledger.

use alloy::primitives::Address;
use safe_rs::rotation::KeySource;
use safe_rs::LedgerKeys;
use safe_rs::{HdWallet, OuterTxParams, PreparedSafeTx, SignedOuterTx, SignedSafeTx};

/// Owner keys from `--hd-wallet` or `--ledger`.
pub enum CliKeys {
    /// A phrase decrypted from its keystore
    Phrase(Box<HdWallet>),
    /// A connected Ledger
    Ledger(LedgerKeys),
}

impl CliKeys {
    /// True for a hardware wallet, where each signature is confirmed on the device.
    pub fn is_device(&self) -> bool {
        !matches!(self, Self::Phrase(_))
    }
}

impl KeySource for CliKeys {
    async fn address(&self, index: u32) -> safe_rs::Result<Address> {
        match self {
            Self::Phrase(keys) => keys.address(index).await,
            Self::Ledger(keys) => keys.address(index).await,
        }
    }

    fn scan_limit(&self) -> u32 {
        match self {
            Self::Phrase(keys) => keys.scan_limit(),
            Self::Ledger(keys) => keys.scan_limit(),
        }
    }

    async fn sign_safe_tx(&self, index: u32, tx: &PreparedSafeTx) -> safe_rs::Result<SignedSafeTx> {
        match self {
            Self::Phrase(keys) => keys.sign_safe_tx(index, tx).await,
            Self::Ledger(keys) => keys.sign_safe_tx(index, tx).await,
        }
    }

    async fn sign_outer_tx(
        &self,
        index: u32,
        params: OuterTxParams,
    ) -> safe_rs::Result<SignedOuterTx> {
        match self {
            Self::Phrase(keys) => keys.sign_outer_tx(index, params).await,
            Self::Ledger(keys) => keys.sign_outer_tx(index, params).await,
        }
    }
}
