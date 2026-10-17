//! Owner keys on a Ledger device.
//!
//! [`LedgerKeys`] is a [`KeySource`] backed by the Ethereum app of a connected
//! Ledger, at the same path every key source uses, `m/44'/60'/0'/0/i`. A
//! Ledger seeded with a phrase therefore derives the same keys as that phrase
//! in [`HdWallet`](crate::HdWallet), and shares its rotation state.
//!
//! The device is asked for each address once: the [`Keyring`] records them
//! and looks ahead (see [`SETUP_LOOKAHEAD`] and [`SEND_LOOKAHEAD`]). Before a
//! key signs, its address is asked again and must match the record.
//!
//! What the device has to allow:
//!
//! - Safe transactions are signed as EIP-712 typed data, which the Ethereum
//!   app supports from version 1.6.0 in its "hashed" mode: the device shows the
//!   domain hash and the message hash, not the decoded transaction.
//! - Outer transactions call `execTransaction` with calldata the app cannot
//!   decode, so "blind signing" has to be enabled in the app's settings.
//!
//! [`Keyring`]: crate::rotation::Keyring
//! [`SETUP_LOOKAHEAD`]: crate::rotation::SETUP_LOOKAHEAD
//! [`SEND_LOOKAHEAD`]: crate::rotation::SEND_LOOKAHEAD

use std::sync::Arc;

use alloy::primitives::Address;
use alloy::signers::Signer;
use alloy_signer_ledger::coins_ledger::transports::{Ledger, LedgerAsync};
use alloy_signer_ledger::{HDPath, LedgerSigner};
use futures_util::lock::Mutex;

use crate::envelope::{PreparedSafeTx, SignedSafeTx};
use crate::error::{Error, Result};
use crate::hd::key_path;
use crate::outer::{sign_outer_tx, OuterTxParams, SignedOuterTx};
use crate::rotation::{KeySource, REBUILD_MARGIN, SETUP_LOOKAHEAD};

fn device_error(e: impl std::fmt::Display) -> Error {
    Error::Device(format!(
        "Ledger: {e} (is it connected and unlocked, with the Ethereum app open?)"
    ))
}

/// The keys of a connected Ledger.
///
/// One connection is opened and shared by every key, so the device is never
/// opened twice by the same process.
#[derive(Debug, Clone)]
pub struct LedgerKeys {
    transport: Arc<Mutex<Ledger>>,
}

impl LedgerKeys {
    /// Connects to the Ledger. It must be unlocked with the Ethereum app open,
    /// and not in use by another program.
    pub async fn connect() -> Result<Self> {
        let transport = Ledger::init().await.map_err(device_error)?;
        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
        })
    }

    /// The device's signer for key `index`. Creating it asks the device for
    /// the key's address, without a confirmation on the device.
    pub async fn signer(&self, index: u32) -> Result<LedgerSigner> {
        LedgerSigner::new_with_transport(
            HDPath::Other(key_path(index)),
            None,
            self.transport.clone(),
        )
        .await
        .map_err(device_error)
    }
}

/// How far a Ledger is searched for an owner that is not on record: the keys
/// a set-up Safe has recorded, and a margin past them. The device answers one
/// address at a time.
pub const LEDGER_SCAN_LIMIT: u32 = SETUP_LOOKAHEAD + 2 * REBUILD_MARGIN;

impl KeySource for LedgerKeys {
    async fn address(&self, index: u32) -> Result<Address> {
        Ok(Signer::address(&self.signer(index).await?))
    }

    fn scan_limit(&self) -> u32 {
        LEDGER_SCAN_LIMIT
    }

    async fn sign_safe_tx(&self, index: u32, tx: &PreparedSafeTx) -> Result<SignedSafeTx> {
        tx.sign(&self.signer(index).await?).await
    }

    async fn sign_outer_tx(&self, index: u32, params: OuterTxParams) -> Result<SignedOuterTx> {
        sign_outer_tx(&self.signer(index).await?, params).await
    }
}
