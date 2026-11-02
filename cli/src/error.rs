//! Errors of the library API: [`send`](crate::send),
//! [`create`](crate::create::create), the [`wallet`](crate::wallet)
//! functions, and the checks on their options.
//!
//! The `safe` binary and its other commands report errors with `eyre`; every
//! error here converts into an `eyre::Report` with `?`.

use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

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
        "with --rotate the owner key comes from the HD wallet or Ledger (--mnemonic or \
         --ledger): send without a signer"
    )]
    RotateWithSigner,
    /// `--no-sweep` or `--sweep-reserve` without `--rotate`
    #[error("--no-sweep and --sweep-reserve only apply with --rotate")]
    SweepWithoutRotate,
    /// Rotating owner keys ([`SendOpts::hd`](crate::args::SendOpts::hd))
    /// without `--rotate`, which would publish an owner key and leave it in
    /// charge of the Safe
    #[error(
        "the rotating owner keys need --rotate: sending without rotating would publish \
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
    /// A signer with `create --rotate`, where the owner key comes from the
    /// wallet
    #[error(
        "with --rotate the owner key comes from the HD wallet or Ledger (--mnemonic or \
         --ledger): remove the other wallet options, and unset PRIVATE_KEY, ETH_KEYSTORE \
         and ETH_KEYSTORE_ACCOUNT"
    )]
    SignerWithHd,
    /// Rotating owner keys for `create` without `--rotate`
    #[error(
        "the rotating owner keys need --rotate: `create --rotate` makes a Safe whose owner \
         key rotates"
    )]
    CreateHdWithoutRotate,
    /// `create --rotate` with no HD wallet or Ledger to take the owner keys from
    #[error("--rotate needs --mnemonic or --ledger to take the owner keys from")]
    RotateWithoutKeys,
    /// An option of `create` that only applies with `--rotate`
    #[error("{flag} needs --rotate")]
    HdOnly { flag: &'static str },
}

/// A broadcast transaction that did not land: refused by the node, possibly
/// sent, or sent without a receipt in time.
///
/// Shared by every command that broadcasts.
/// [`may_be_pending`](Self::may_be_pending) tells apart the failures after
/// which the transaction may still be mined.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BroadcastError {
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
    Ambiguous { tx_hash: B256, reason: String },
    /// The transaction was sent but no receipt arrived within the timeout
    #[error("no receipt for {tx_hash} after {timeout_secs}s; it may still be pending")]
    ReceiptTimeout { tx_hash: B256, timeout_secs: u64 },
}

impl BroadcastError {
    /// Whether the transaction may still be mined, so a retry could send it
    /// twice.
    pub fn may_be_pending(&self) -> bool {
        matches!(self, Self::Ambiguous { .. } | Self::ReceiptTimeout { .. })
    }

    /// The transaction this is about.
    pub fn tx_hash(&self) -> B256 {
        match self {
            Self::Rejected { tx_hash, .. }
            | Self::Ambiguous { tx_hash, .. }
            | Self::ReceiptTimeout { tx_hash, .. } => *tx_hash,
        }
    }
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
    #[error("No wallet specified. Use {}", crate::signers::SIGNER_FLAGS_HELP)]
    NoSigner,
    /// No calls were given and the bundle holds none
    #[error("No calls specified")]
    NoCalls,
    /// The Safe transaction reverts in simulation; nothing was signed or sent
    #[error("simulation failed: {reason}")]
    SimulationFailed { reason: String },
    /// The host's [`SafePolicy`](crate::policy::SafePolicy) refuses the Safe
    /// transaction; nothing was sent
    #[error("the {policy} policy refuses this Safe transaction")]
    PolicyRefused { policy: String },
    /// The `approveHash` transaction reverts in simulation; nothing was sent
    #[error("approveHash simulation failed: {reason}")]
    ApproveHashSimulationFailed { reason: String },
    /// Fewer signatures than the threshold, and no `--bundle` to save them to
    #[error(
        "Safe threshold is {need} (have {have}/{need} signatures). Pass --bundle <FILE> to save \
         and collect signatures offchain, or --approve-hash to approve on-chain"
    )]
    BelowThreshold { have: usize, need: usize },
    /// The transaction was refused, may still be pending, or got no receipt
    /// in time
    #[error(transparent)]
    Broadcast(#[from] BroadcastError),
    /// The rotating transaction was sent, or may have been, and is not
    /// confirmed. Its signature is public, so the old owner key counts as used.
    #[error(
        "transaction {tx_hash} is not confirmed: {reason}\nIts signature is public, so {} \
         counts as used. Run `safe send --rotate` (or any rotating command) to pick up where this \
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
    /// signature is public: run `safe send --rotate` to retire the old key.
    #[error(
        "the transaction reverted and the owner was NOT rotated. Its signature is public and \
         the signed calls stay executable until the Safe nonce is used: run \
         `safe send --rotate` now to retire {}. If its ETH was swept with this transaction \
         (see the warnings), fund it first or pass a --gas-payer-* key",
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
        if let Self::Broadcast(error) = self {
            return error.may_be_pending();
        }
        matches!(
            self,
            Self::RotationUnconfirmed { .. } | Self::Safe(safe_rs::Error::Unconfirmed { .. })
        )
    }

    /// An [`Other`](Self::Other) error with `message`.
    pub(crate) fn other(message: impl fmt::Display) -> Self {
        Self::Other(message.to_string().into())
    }
}

/// Why [`create`](crate::create::create) failed.
///
/// Every error after the deployment was signed carries the predicted `safe`,
/// so a host can tell the user what to `safe wallet sync --safe` once it is
/// mined.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CreateError {
    /// The options conflict; nothing was signed or sent
    #[error(transparent)]
    Options(#[from] OptionsError),
    /// No signer, and no `--rotate` keys to take the owner from
    #[error("No wallet specified. Use {}", crate::signers::SIGNER_FLAGS_HELP)]
    NoSigner,
    /// A zero-address owner, or a threshold outside 1..=owners
    #[error("{0}")]
    InvalidSetup(String),
    /// The predicted owner key turned out to be used on chain between the
    /// preview and the reservation; nothing was sent. Running again picks the
    /// next unused key.
    #[error(
        "the owner key changed while the deployment was prepared (key {previewed} was used on \
         chain in the meantime); nothing was sent, run again"
    )]
    OwnerChanged { previewed: u32 },
    /// The deployment was refused, may still be pending, or got no receipt
    #[error("deploying Safe {safe}: {error}")]
    Broadcast {
        safe: Address,
        #[source]
        error: BroadcastError,
    },
    /// The deployment was mined and reverted
    #[error("deployment transaction {tx_hash} of Safe {safe} reverted")]
    Reverted { safe: Address, tx_hash: B256 },
    /// The deployment was mined but there is no Safe at the predicted address
    #[error("the deployment {tx_hash} was mined but there is no Safe at {safe}")]
    NotDeployed { safe: Address, tx_hash: B256 },
    /// An error from the Safe library
    #[error(transparent)]
    Safe(#[from] safe_rs::Error),
    /// An RPC request failed
    #[error(transparent)]
    Rpc(#[from] TransportError),
    /// Any other failure: the wallet file, its password, the state lock
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

impl CreateError {
    /// Whether the deployment may have been broadcast and still be mined, so
    /// a retry could send it twice.
    pub fn may_be_pending(&self) -> bool {
        match self {
            Self::Broadcast { error, .. } => error.may_be_pending(),
            Self::Safe(safe_rs::Error::Unconfirmed { .. }) => true,
            _ => false,
        }
    }

    /// The Safe the failed deployment was for, once it was signed.
    pub fn safe(&self) -> Option<Address> {
        match self {
            Self::Broadcast { safe, .. }
            | Self::Reverted { safe, .. }
            | Self::NotDeployed { safe, .. } => Some(*safe),
            _ => None,
        }
    }
}

/// Why a [`wallet`](crate::wallet) function failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WalletError {
    /// No HD wallet file by this name
    #[error("no HD wallet at {path} (create one with `safe wallet new`)")]
    NotFound { path: PathBuf },
    /// A wallet file is already there
    #[error("{} already exists", path.display())]
    AlreadyExists { path: PathBuf },
    /// The password does not open the wallet
    #[error("Wrong keystore password (or corrupt keystore)")]
    WrongPassword,
    /// Another process holds the wallet's state
    #[error("another safe command is using this HD wallet ({} is locked); wait for it to finish", path.display())]
    Locked { path: PathBuf },
    /// Not a valid BIP-39 phrase
    #[error("invalid recovery phrase: {0}")]
    InvalidPhrase(String),
    /// `sync` and `sweep` read the chain
    #[error("this needs --rpc-url (or ETH_RPC_URL)")]
    NoRpcUrl,
    /// Some sweeps could not be sent; the ones that were are in `swept`
    #[error("{} sweep(s) could not be completed", still_owed.len())]
    Sweep {
        swept: Vec<crate::wallet::SweptEth>,
        still_owed: Vec<crate::wallet::OwedSweep>,
    },
    /// Any other failure
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

impl From<safe_rs::Error> for WalletError {
    fn from(error: safe_rs::Error) -> Self {
        match error {
            safe_rs::Error::StateLocked(path) => Self::Locked { path: path.into() },
            other => Self::Other(other.into()),
        }
    }
}

impl From<std::io::Error> for WalletError {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.into())
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
            SendError::Broadcast(BroadcastError::Ambiguous {
                tx_hash,
                reason: "connection reset".into(),
            }),
            SendError::Broadcast(BroadcastError::ReceiptTimeout {
                tx_hash,
                timeout_secs: 60,
            }),
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
                source: Box::new(SendError::Broadcast(BroadcastError::ReceiptTimeout {
                    tx_hash,
                    timeout_secs: 60,
                })),
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
            SendError::Broadcast(BroadcastError::Rejected {
                tx_hash,
                reason: "nonce too low".into(),
                class: RejectClass::NonceTooLow,
            }),
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
    fn create_errors_after_signing_name_the_safe() {
        let safe = Address::repeat_byte(5);
        let tx_hash = B256::repeat_byte(1);
        let timeout = CreateError::Broadcast {
            safe,
            error: BroadcastError::ReceiptTimeout {
                tx_hash,
                timeout_secs: 120,
            },
        };
        assert!(timeout.may_be_pending());
        assert_eq!(timeout.safe(), Some(safe));
        let reverted = CreateError::Reverted { safe, tx_hash };
        assert!(!reverted.may_be_pending());
        assert_eq!(reverted.safe(), Some(safe));
        assert_eq!(CreateError::NoSigner.safe(), None);
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
