//! Errors of the library API: [`send`](crate::send) and
//! [`SendOpts::validate`](crate::args::SendOpts::validate).
//!
//! The `safe` binary and its other commands report errors with `eyre`; a
//! [`SendError`] converts into an `eyre::Report` with `?`.

use std::error::Error as StdError;
use std::fmt;

use alloy::primitives::{Address, B256};
use alloy::transports::TransportError;
use safe_rs::RejectClass;

/// Options that cannot be used together, found before any key or the chain is
/// touched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OptionsError {
    /// Two flags that clap would refuse together
    #[error("{flag} cannot be used with {with}")]
    Conflict {
        flag: &'static str,
        with: &'static str,
    },
    /// `--rotate` with a signer from the host: the owner key comes from the HD
    /// wallet or Ledger
    #[error(
        "with --rotate the owner key comes from the HD wallet or Ledger (--hd-wallet or \
         --ledger): send without a signer"
    )]
    RotateWithSigner,
    /// `--no-sweep` or `--sweep-reserve` without `--rotate`
    #[error("--no-sweep and --sweep-reserve only apply with --rotate")]
    SweepWithoutRotate,
    /// `--hd-wallet` or `--ledger` without `--rotate`, which would publish an
    /// owner key and leave it in charge of the Safe
    #[error(
        "--hd-wallet or --ledger needs --rotate: sending without rotating would publish \
         an owner key and leave it in charge of the Safe"
    )]
    HdWithoutRotate,
    /// An option that only applies to a send through a Safe, given for an EOA
    /// send
    #[error("{flag} only applies to a send through a Safe, not from an EOA")]
    SafeOnly { flag: &'static str },
    /// `--gas-limit` for an EOA send of more than one call, which is more than
    /// one transaction
    #[error("--gas-limit applies to one transaction, but an EOA sends each of the {calls} calls as its own")]
    GasLimitForBatch { calls: usize },
}

/// Why a send failed.
///
/// [`may_be_pending`](Self::may_be_pending) tells apart the failures after
/// which a transaction may still be mined.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// The options conflict; nothing was signed or sent
    #[error(transparent)]
    Options(#[from] OptionsError),
    /// Neither a signer nor a payer to send with
    #[error("No wallet specified. Use --private-key, --keystore or --interactive")]
    NoSigner,
    /// No calls were given and the bundle holds none
    #[error("No calls specified")]
    NoCalls,
    /// The Safe transaction reverts in simulation; nothing was signed or sent
    #[error("simulation failed: {reason}")]
    SimulationFailed { reason: String },
    /// The `approveHash` transaction reverts in simulation; nothing was sent
    #[error("approveHash simulation failed: {reason}")]
    ApproveHashSimulationFailed { reason: String },
    /// Fewer signatures than the threshold, and no `--bundle` to save them to
    #[error(
        "Safe threshold is {need} (have {have}/{need} signatures). Pass --bundle <FILE> to save \
         and collect signatures offchain, or --approve-hash to approve on-chain"
    )]
    BelowThreshold { have: usize, need: usize },
    /// The node refused the signed transaction, so it was not sent
    #[error("node rejected {tx_hash}: {reason} ({class:?})")]
    Rejected {
        tx_hash: B256,
        reason: String,
        class: RejectClass,
    },
    /// The broadcast failed in a way that leaves the transaction possibly
    /// pending
    #[error("broadcast of {tx_hash} is ambiguous and it may still be pending: {reason}")]
    BroadcastAmbiguous { tx_hash: B256, reason: String },
    /// The transaction was sent but no receipt arrived within the timeout
    #[error("no receipt for {tx_hash} after {timeout_secs}s; it may still be pending")]
    ReceiptTimeout { tx_hash: B256, timeout_secs: u64 },
    /// The rotating transaction was sent, or may have been, and is not
    /// confirmed. Its signature is public, so the old owner key counts as used.
    #[error(
        "transaction {tx_hash} is not confirmed: {reason}\nIts signature is public, so {} \
         counts as used. Run `safe rotate` (or any rotating command) to pick up where this \
         left off.",
        owner_label(*old_owner, *old_owner_index)
    )]
    RotationUnconfirmed {
        tx_hash: B256,
        reason: String,
        /// The owner that signed and is now retired
        old_owner: Address,
        /// Its HD wallet index, when the wallet derives it
        old_owner_index: Option<u32>,
    },
    /// The `approveHash` transaction was mined and reverted
    #[error("approveHash transaction reverted")]
    ApproveHashReverted { tx_hash: B256 },
    /// `execTransaction` was mined but the Safe transaction did not succeed
    #[error("Safe transaction did not succeed ({outcome})")]
    SafeTxFailed {
        tx_hash: B256,
        /// The outcome's label, such as `"failure"` or `"not_found"`
        outcome: &'static str,
    },
    /// The rotating transaction reverted, but the owner was rotated by another
    /// transaction carrying the same signed Safe transaction
    #[error(
        "the owner was rotated, but by another transaction carrying the same signed Safe \
         transaction; this one reverted"
    )]
    RotatedElsewhere { tx_hash: B256 },
    /// The rotating transaction reverted and the owner was not rotated. Its
    /// signature is public: run `safe rotate` to retire the old key.
    #[error(
        "the transaction reverted and the owner was NOT rotated. Its signature is public and \
         the signed calls stay executable until the Safe nonce is used: run `safe rotate` now \
         to retire {}. If its ETH was swept with this transaction (see the warnings), fund it \
         first or pass --payer-private-key",
        owner_label(*old_owner, *old_owner_index)
    )]
    NotRotated {
        tx_hash: B256,
        /// The owner that signed and is still an owner
        old_owner: Address,
        /// Its HD wallet index, when the wallet derives it
        old_owner_index: Option<u32>,
    },
    /// An EOA transaction was mined and reverted
    #[error("transaction {tx_hash} (call {index}) reverted")]
    EoaTxReverted { tx_hash: B256, index: usize },
    /// An EOA send stopped part way: the transactions in `mined` are on chain,
    /// the one at `failed_index` failed and the rest were not sent
    #[error(
        "the EOA send stopped at call {failed_index} after {} transaction(s) were mined ({}): {source}",
        mined.len(),
        tx_list(mined)
    )]
    EoaBatchFailed {
        mined: Vec<B256>,
        failed_index: usize,
        #[source]
        source: Box<SendError>,
    },
    /// An error from the Safe library, such as the signer not being an owner
    /// or a nonce mismatch
    #[error(transparent)]
    Safe(#[from] safe_rs::Error),
    /// An RPC request failed
    #[error(transparent)]
    Rpc(#[from] TransportError),
    /// Any other failure: a bad bundle file, a wallet that cannot be opened,
    /// a gas estimate that fails
    #[error(transparent)]
    Other(Box<dyn StdError + Send + Sync + 'static>),
}

impl SendError {
    /// Whether a transaction may have been broadcast and still be mined, so a
    /// retry could send it twice.
    pub fn may_be_pending(&self) -> bool {
        if let Self::EoaBatchFailed { source, .. } = self {
            return source.may_be_pending();
        }
        matches!(
            self,
            Self::BroadcastAmbiguous { .. }
                | Self::ReceiptTimeout { .. }
                | Self::RotationUnconfirmed { .. }
                | Self::Safe(safe_rs::Error::Unconfirmed { .. })
        )
    }

    /// An [`Other`](Self::Other) error with `message`.
    pub(crate) fn other(message: impl fmt::Display) -> Self {
        Self::Other(message.to_string().into())
    }
}

/// Transaction hashes, comma separated.
fn tx_list(hashes: &[B256]) -> String {
    hashes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// An owner key as the rotation output names it.
fn owner_label(address: Address, index: Option<u32>) -> String {
    match index {
        Some(index) => format!("key {index} ({address})"),
        None => format!("{address} (not a wallet key)"),
    }
}

/// The internal helpers report with `eyre`; keep their message and causes.
impl From<eyre::Report> for SendError {
    fn from(report: eyre::Report) -> Self {
        Self::Other(report.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfirmed_transactions_may_be_pending() {
        let tx_hash = B256::repeat_byte(1);
        let pending = [
            SendError::BroadcastAmbiguous {
                tx_hash,
                reason: "connection reset".into(),
            },
            SendError::ReceiptTimeout {
                tx_hash,
                timeout_secs: 60,
            },
            SendError::RotationUnconfirmed {
                tx_hash,
                reason: "no receipt".into(),
                old_owner: Address::ZERO,
                old_owner_index: Some(3),
            },
            SendError::Safe(safe_rs::Error::Unconfirmed {
                tx_hash,
                reason: "no receipt".into(),
            }),
            SendError::EoaBatchFailed {
                mined: vec![B256::repeat_byte(2)],
                failed_index: 1,
                source: Box::new(SendError::ReceiptTimeout {
                    tx_hash,
                    timeout_secs: 60,
                }),
            },
        ];
        for error in pending {
            assert!(error.may_be_pending(), "{error:?}");
        }

        let settled = [
            SendError::NoSigner,
            SendError::SimulationFailed {
                reason: "GS013".into(),
            },
            SendError::Rejected {
                tx_hash,
                reason: "nonce too low".into(),
                class: RejectClass::NonceTooLow,
            },
            SendError::Safe(safe_rs::Error::NoCalls),
            SendError::EoaBatchFailed {
                mined: vec![B256::repeat_byte(2)],
                failed_index: 1,
                source: Box::new(SendError::EoaTxReverted { tx_hash, index: 1 }),
            },
        ];
        for error in settled {
            assert!(!error.may_be_pending(), "{error:?}");
        }
    }

    #[test]
    fn rotation_errors_name_the_old_owner_key() {
        let error = SendError::RotationUnconfirmed {
            tx_hash: B256::ZERO,
            reason: "no receipt".into(),
            old_owner: Address::ZERO,
            old_owner_index: Some(3),
        };
        assert!(
            error
                .to_string()
                .contains(&format!("so key 3 ({}) counts", Address::ZERO)),
            "{error}"
        );
    }
}
