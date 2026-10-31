//! Broadcasting raw transactions and classifying Safe outcomes.
//!
//! These helpers never hide pending state: a broadcast whose result is unclear
//! is reported as [`BroadcastOutcome::Ambiguous`], and a receipt that does not
//! arrive in time is reported as [`ReceiptWait::TimedOut`] with the hash, so the
//! caller can persist it and reconcile later.

use std::time::Duration;

use alloy::network::AnyNetwork;
use alloy::network::AnyTransactionReceipt;
use alloy::primitives::{Address, Bytes, Log, B256, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolEvent;
use alloy::transports::{RpcError, TransportErrorKind};

use crate::contracts::{ISafe, ISafeV130};
use crate::error::{Error, Result};

/// Why a node rejected a transaction before inclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectClass {
    /// The sender nonce was already used
    NonceTooLow,
    /// The fee is too low (including replacement underpricing)
    Underpriced,
    /// The sender cannot pay for gas and value
    InsufficientFunds,
    /// Any other explicit rejection
    Other,
}

/// Result of submitting a raw transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// The node accepted the transaction
    Accepted(B256),
    /// The node already knew the transaction (idempotent rebroadcast)
    AlreadyKnown(B256),
    /// The node explicitly rejected the transaction
    Rejected {
        /// Node error message
        reason: String,
        /// Classification of the reason
        class: RejectClass,
    },
    /// The outcome is unknown (transport failure or unexpected response); the
    /// transaction may or may not have reached the network
    Ambiguous {
        /// Error description
        reason: String,
    },
}

fn classify_rejection(message: &str) -> BroadcastRejection {
    let m = message.to_ascii_lowercase();
    if m.contains("already known")
        || m.contains("known transaction")
        || m.contains("already imported")
    {
        return BroadcastRejection::AlreadyKnown;
    }
    let class = if m.contains("nonce too low") || m.contains("nonce is too low") {
        RejectClass::NonceTooLow
    } else if m.contains("underpriced")
        || m.contains("fee too low")
        || m.contains("max fee per gas less than block base fee")
    {
        RejectClass::Underpriced
    } else if m.contains("insufficient funds") {
        RejectClass::InsufficientFunds
    } else {
        RejectClass::Other
    };
    BroadcastRejection::Rejected(class)
}

enum BroadcastRejection {
    AlreadyKnown,
    Rejected(RejectClass),
}

/// Sends raw transaction bytes with `eth_sendRawTransaction`.
///
/// `expected_hash` is the locally computed hash; a node response with a
/// different hash is reported as [`BroadcastOutcome::Ambiguous`].
pub async fn broadcast_raw<P: Provider<AnyNetwork>>(
    provider: &P,
    raw: &Bytes,
    expected_hash: B256,
) -> BroadcastOutcome {
    let response: std::result::Result<B256, RpcError<TransportErrorKind>> = provider
        .client()
        .request("eth_sendRawTransaction", (raw.clone(),))
        .await;
    match response {
        Ok(hash) if hash == expected_hash => BroadcastOutcome::Accepted(hash),
        Ok(hash) => BroadcastOutcome::Ambiguous {
            reason: format!("node returned hash {hash}, expected {expected_hash}"),
        },
        Err(RpcError::ErrorResp(payload)) => match classify_rejection(&payload.message) {
            BroadcastRejection::AlreadyKnown => BroadcastOutcome::AlreadyKnown(expected_hash),
            BroadcastRejection::Rejected(class) => BroadcastOutcome::Rejected {
                reason: payload.message.to_string(),
                class,
            },
        },
        Err(e) => BroadcastOutcome::Ambiguous {
            reason: e.to_string(),
        },
    }
}

/// Result of waiting for a receipt.
#[derive(Debug, Clone)]
pub enum ReceiptWait {
    /// The transaction was mined
    Mined(Box<AnyTransactionReceipt>),
    /// No receipt arrived before the deadline; the transaction may still be pending
    TimedOut {
        /// The transaction hash that was polled
        tx_hash: B256,
    },
}

/// Polls `eth_getTransactionReceipt` until the receipt appears or `timeout` elapses.
///
/// Transport errors while polling are retried until the deadline; they never
/// turn into a "failed" result.
pub async fn wait_for_receipt<P: Provider<AnyNetwork>>(
    provider: &P,
    tx_hash: B256,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<ReceiptWait> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
            return Ok(ReceiptWait::Mined(Box::new(receipt)));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(ReceiptWait::TimedOut { tx_hash });
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// How a Safe transaction ended, judged only from logs emitted by the Safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeExecutionOutcome {
    /// Exactly one `ExecutionSuccess(safe_tx_hash)` from the Safe
    Success {
        /// Refund payment reported by the Safe
        payment: U256,
    },
    /// Exactly one `ExecutionFailure(safe_tx_hash)` from the Safe: the inner call
    /// failed but the transaction was mined and the Safe nonce was consumed
    Failure {
        /// Refund payment reported by the Safe
        payment: U256,
    },
    /// No execution event for this Safe transaction hash
    NotFound,
    /// Several or contradictory execution events for this hash
    Conflicting,
}

impl SafeExecutionOutcome {
    /// Returns true for [`SafeExecutionOutcome::Success`].
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Stable machine-readable name: `success`, `failure`, `not_found` or `conflicting`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Success { .. } => "success",
            Self::Failure { .. } => "failure",
            Self::NotFound => "not_found",
            Self::Conflicting => "conflicting",
        }
    }
}

/// Whether an execution event reported success or failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionEvent {
    Success,
    Failure,
}

/// Decodes an `ExecutionSuccess` or `ExecutionFailure` log into its kind,
/// `txHash` and `payment`, in either layout:
///
/// - v1.4.1 and later: `txHash` indexed, so two topics and 32 bytes of data
/// - v1.3.0: nothing indexed, so one topic and 64 bytes of data
///
/// Both layouts share topic0, so the layout is chosen from the topic count.
/// A log of any other shape is not an execution event.
fn decode_execution_event(log: &Log) -> Option<(ExecutionEvent, B256, U256)> {
    let topic0 = *log.topics().first()?;
    let kind = if topic0 == ISafe::ExecutionSuccess::SIGNATURE_HASH {
        ExecutionEvent::Success
    } else if topic0 == ISafe::ExecutionFailure::SIGNATURE_HASH {
        ExecutionEvent::Failure
    } else {
        return None;
    };
    let (tx_hash, payment) = match (kind, log.topics().len()) {
        (ExecutionEvent::Success, 2) => ISafe::ExecutionSuccess::decode_log(log)
            .ok()
            .map(|e| (e.txHash, e.payment))?,
        (ExecutionEvent::Failure, 2) => ISafe::ExecutionFailure::decode_log(log)
            .ok()
            .map(|e| (e.txHash, e.payment))?,
        (ExecutionEvent::Success, 1) => ISafeV130::ExecutionSuccess::decode_log(log)
            .ok()
            .map(|e| (e.txHash, e.payment))?,
        (ExecutionEvent::Failure, 1) => ISafeV130::ExecutionFailure::decode_log(log)
            .ok()
            .map(|e| (e.txHash, e.payment))?,
        _ => return None,
    };
    Some((kind, tx_hash, payment))
}

/// Classifies the outcome of `safe_tx_hash` from a list of logs.
///
/// Only logs emitted by `safe` whose `txHash` equals `safe_tx_hash` count;
/// events from other contracts or other Safe transactions are ignored. Both
/// event layouts are accepted: v1.4.1 and later index `txHash`, v1.3.0 does not.
pub fn decode_safe_outcome<'a>(
    logs: impl IntoIterator<Item = &'a Log>,
    safe: Address,
    safe_tx_hash: B256,
) -> SafeExecutionOutcome {
    let mut successes = Vec::new();
    let mut failures = Vec::new();
    for log in logs {
        if log.address != safe {
            continue;
        }
        match decode_execution_event(log) {
            Some((ExecutionEvent::Success, hash, payment)) if hash == safe_tx_hash => {
                successes.push(payment);
            }
            Some((ExecutionEvent::Failure, hash, payment)) if hash == safe_tx_hash => {
                failures.push(payment);
            }
            _ => {}
        }
    }
    match (successes.as_slice(), failures.as_slice()) {
        ([payment], []) => SafeExecutionOutcome::Success { payment: *payment },
        ([], [payment]) => SafeExecutionOutcome::Failure { payment: *payment },
        ([], []) => SafeExecutionOutcome::NotFound,
        _ => SafeExecutionOutcome::Conflicting,
    }
}

/// Extracts consensus logs from an RPC receipt.
pub fn receipt_logs(receipt: &AnyTransactionReceipt) -> Vec<Log> {
    receipt
        .inner
        .inner
        .logs()
        .iter()
        .map(|l| l.inner.clone())
        .collect()
}

/// Classifies the Safe outcome of a mined outer transaction.
///
/// Returns [`Error::ExecutionFailed`] if the outer transaction itself reverted
/// (for example with `GS013`); otherwise the outcome decoded from its logs.
pub fn safe_outcome_for_receipt(
    receipt: &AnyTransactionReceipt,
    safe: Address,
    safe_tx_hash: B256,
) -> Result<SafeExecutionOutcome> {
    if !receipt.inner.inner.status() {
        return Err(Error::ExecutionFailed {
            reason: format!("outer transaction {} reverted", receipt.transaction_hash),
        });
    }
    Ok(decode_safe_outcome(
        &receipt_logs(receipt),
        safe,
        safe_tx_hash,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256, bytes, LogData};

    const SAFE: Address = address!("0x1000000000000000000000000000000000000001");
    const HASH: B256 = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const OTHER: B256 = b256!("0x2222222222222222222222222222222222222222222222222222222222222222");

    fn success(address: Address, hash: B256) -> Log {
        let event = ISafe::ExecutionSuccess {
            txHash: hash,
            payment: U256::ZERO,
        };
        Log {
            address,
            data: event.encode_log_data(),
        }
    }

    fn failure(address: Address, hash: B256) -> Log {
        let event = ISafe::ExecutionFailure {
            txHash: hash,
            payment: U256::ZERO,
        };
        Log {
            address,
            data: event.encode_log_data(),
        }
    }

    #[test]
    fn success_is_detected() {
        let logs = [success(SAFE, HASH)];
        assert!(decode_safe_outcome(&logs, SAFE, HASH).is_success());
    }

    #[test]
    fn failure_is_detected() {
        let logs = [failure(SAFE, HASH)];
        assert_eq!(
            decode_safe_outcome(&logs, SAFE, HASH),
            SafeExecutionOutcome::Failure {
                payment: U256::ZERO
            }
        );
    }

    #[test]
    fn other_safe_and_other_hash_are_ignored() {
        let other_safe = address!("0x9999999999999999999999999999999999999999");
        let logs = [success(other_safe, HASH), success(SAFE, OTHER)];
        assert_eq!(
            decode_safe_outcome(&logs, SAFE, HASH),
            SafeExecutionOutcome::NotFound
        );
    }

    #[test]
    fn duplicate_events_conflict() {
        let logs = [success(SAFE, HASH), failure(SAFE, HASH)];
        assert_eq!(
            decode_safe_outcome(&logs, SAFE, HASH),
            SafeExecutionOutcome::Conflicting
        );
    }

    #[test]
    fn unrelated_logs_are_ignored() {
        let logs = [Log {
            address: SAFE,
            data: LogData::new_unchecked(vec![OTHER], Bytes::new()),
        }];
        assert_eq!(
            decode_safe_outcome(&logs, SAFE, HASH),
            SafeExecutionOutcome::NotFound
        );
    }

    fn v130_success(address: Address, hash: B256, payment: U256) -> Log {
        let event = ISafeV130::ExecutionSuccess {
            txHash: hash,
            payment,
        };
        Log {
            address,
            data: event.encode_log_data(),
        }
    }

    fn v130_failure(address: Address, hash: B256, payment: U256) -> Log {
        let event = ISafeV130::ExecutionFailure {
            txHash: hash,
            payment,
        };
        Log {
            address,
            data: event.encode_log_data(),
        }
    }

    #[test]
    fn v130_layout_is_one_topic_with_hash_in_data() {
        let log = v130_success(SAFE, HASH, U256::ZERO);
        assert_eq!(log.topics(), [ISafe::ExecutionSuccess::SIGNATURE_HASH]);
        assert_eq!(log.data.data.len(), 64);
    }

    #[test]
    fn v130_success_and_failure_are_detected() {
        let payment = U256::from(7);
        assert_eq!(
            decode_safe_outcome(&[v130_success(SAFE, HASH, payment)], SAFE, HASH),
            SafeExecutionOutcome::Success { payment }
        );
        assert_eq!(
            decode_safe_outcome(&[v130_failure(SAFE, HASH, payment)], SAFE, HASH),
            SafeExecutionOutcome::Failure { payment }
        );
    }

    #[test]
    fn v130_other_safe_and_other_hash_are_ignored() {
        let other_safe = address!("0x9999999999999999999999999999999999999999");
        let logs = [
            v130_success(other_safe, HASH, U256::ZERO),
            v130_success(SAFE, OTHER, U256::ZERO),
        ];
        assert_eq!(
            decode_safe_outcome(&logs, SAFE, HASH),
            SafeExecutionOutcome::NotFound
        );
    }

    #[test]
    fn v130_and_v141_events_for_one_hash_conflict() {
        let logs = [success(SAFE, HASH), v130_failure(SAFE, HASH, U256::ZERO)];
        assert_eq!(
            decode_safe_outcome(&logs, SAFE, HASH),
            SafeExecutionOutcome::Conflicting
        );
    }

    #[test]
    fn malformed_execution_logs_are_ignored() {
        let topic0 = ISafe::ExecutionSuccess::SIGNATURE_HASH;
        let word = Bytes::from(HASH.to_vec());
        let malformed = [
            // One topic, but only 32 bytes of data: not a v1.3.0 event.
            LogData::new_unchecked(vec![topic0], word.clone()),
            // Two topics, but no data.
            LogData::new_unchecked(vec![topic0, HASH], Bytes::new()),
            // Three topics.
            LogData::new_unchecked(vec![topic0, HASH, HASH], word),
        ];
        for data in malformed {
            let logs = [Log {
                address: SAFE,
                data,
            }];
            assert_eq!(
                decode_safe_outcome(&logs, SAFE, HASH),
                SafeExecutionOutcome::NotFound
            );
        }
    }

    /// The `ExecutionSuccess` log of Polygon transaction
    /// 0x25e854a351977048cc5520dc1a51042a55df973ac99334a77196006153fe087b,
    /// emitted by a Polymarket Safe: VERSION() 1.3.0, implementation
    /// 0xE51abdf814f8854941b9Fe8e3A4F65CAB4e7A4a8.
    #[test]
    fn polymarket_safe_log_is_success() {
        let safe = address!("0x82b3ba993f1b7def7d8c3673092fa0f4ab97b3ed");
        let safe_tx_hash =
            b256!("0x4cd26d2174f4b2cf48915d476365605dd1ba22de06f2ab8485afb9be4db21cd3");
        let log = Log {
            address: safe,
            data: LogData::new_unchecked(
                vec![b256!(
                    "0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e"
                )],
                bytes!(
                    "4cd26d2174f4b2cf48915d476365605dd1ba22de06f2ab8485afb9be4db21cd3"
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ),
            ),
        };
        assert_eq!(
            decode_safe_outcome(std::slice::from_ref(&log), safe, safe_tx_hash),
            SafeExecutionOutcome::Success {
                payment: U256::ZERO
            }
        );
        // The payment word is not mistaken for the hash, nor the hash for it.
        assert_eq!(
            decode_safe_outcome(&[log], safe, B256::ZERO),
            SafeExecutionOutcome::NotFound
        );
    }

    #[test]
    fn rejection_classes() {
        assert!(matches!(
            classify_rejection("nonce too low"),
            BroadcastRejection::Rejected(RejectClass::NonceTooLow)
        ));
        assert!(matches!(
            classify_rejection("replacement transaction underpriced"),
            BroadcastRejection::Rejected(RejectClass::Underpriced)
        ));
        assert!(matches!(
            classify_rejection("insufficient funds for gas * price + value"),
            BroadcastRejection::Rejected(RejectClass::InsufficientFunds)
        ));
        assert!(matches!(
            classify_rejection("already known"),
            BroadcastRejection::AlreadyKnown
        ));
    }
}
