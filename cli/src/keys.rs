//! The wallet owner keys come from: a phrase on disk or a Ledger.

use alloy::primitives::Address;
use safe_rs::rotation::KeySource;
#[cfg(feature = "ledger")]
use safe_rs::rotation::{REBUILD_MARGIN, SETUP_LOOKAHEAD};
#[cfg(feature = "ledger")]
use safe_rs::LedgerKeys;
use safe_rs::{HdWallet, OuterTxParams, PreparedSafeTx, SignedOuterTx, SignedSafeTx};

/// How far to search for a Safe's owner among a phrase's keys. Derivation is
/// local and fast.
const PHRASE_SCAN_LIMIT: u32 = 1_000;

/// How far to search on a Ledger, which answers one address at a time: the
/// keys a set-up Safe has on record, and a margin past them.
#[cfg(feature = "ledger")]
const LEDGER_SCAN_LIMIT: u32 = SETUP_LOOKAHEAD + 2 * REBUILD_MARGIN;

/// Owner keys from `--hd-wallet` or `--ledger`.
pub enum CliKeys {
    /// A phrase decrypted from its keystore
    Phrase(Box<HdWallet>),
    /// A connected Ledger
    #[cfg(feature = "ledger")]
    Ledger(LedgerKeys),
}

impl CliKeys {
    /// How many keys to search when looking for a Safe's owner.
    pub fn scan_limit(&self) -> u32 {
        match self {
            Self::Phrase(_) => PHRASE_SCAN_LIMIT,
            #[cfg(feature = "ledger")]
            Self::Ledger(_) => LEDGER_SCAN_LIMIT,
        }
    }

    /// True for a hardware wallet, where each signature is confirmed on the device.
    pub fn is_device(&self) -> bool {
        !matches!(self, Self::Phrase(_))
    }
}

impl KeySource for CliKeys {
    async fn address(&self, index: u32) -> safe_rs::Result<Address> {
        match self {
            Self::Phrase(keys) => keys.address(index).await,
            #[cfg(feature = "ledger")]
            Self::Ledger(keys) => keys.address(index).await,
        }
    }

    async fn sign_safe_tx(&self, index: u32, tx: &PreparedSafeTx) -> safe_rs::Result<SignedSafeTx> {
        match self {
            Self::Phrase(keys) => keys.sign_safe_tx(index, tx).await,
            #[cfg(feature = "ledger")]
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
            #[cfg(feature = "ledger")]
            Self::Ledger(keys) => keys.sign_outer_tx(index, params).await,
        }
    }
}
