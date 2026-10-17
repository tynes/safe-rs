//! Simulating and submitting the outer transaction that carries a signed Safe
//! transaction.
//!
//! The Safe signature and the outer transaction are signed by two roles that
//! may or may not be the same key: the *owner* authorizes the Safe transaction
//! and the *payer* sends `execTransaction` and pays for gas. Everything here
//! takes the payer explicitly.
//!
//! The `simulate_*` functions need the `simulation` feature (on by default).

use std::time::Duration;

#[cfg(feature = "simulation")]
use alloy::eips::eip1559::Eip1559Estimation;
use alloy::network::{AnyNetwork, AnyTransactionReceipt};
use alloy::primitives::B256;
#[cfg(feature = "simulation")]
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;

#[cfg(feature = "simulation")]
use crate::envelope::SignedSafeTx;
use crate::error::Result;
#[cfg(feature = "simulation")]
use crate::outer::OuterTxParams;
use crate::outer::SignedOuterTx;
#[cfg(feature = "simulation")]
use crate::simulation::{ForkSession, SimTx, SimulationResult, TxChecks, READ_CALL_GAS};
use crate::submit::{broadcast_raw, wait_for_receipt, BroadcastOutcome, ReceiptWait, RejectClass};

/// The strict simulation of the outer transaction that would be signed.
#[cfg(feature = "simulation")]
#[derive(Debug, Clone)]
pub struct ExecSimulation {
    /// Result of the strict run (or of the gas measurement, if that failed)
    pub result: SimulationResult,
    /// The payer's account nonce in the forked state
    pub payer_nonce: u64,
    /// The gas limit the strict run used
    pub gas_limit: u64,
    /// The session with the transaction applied; `None` unless it succeeded
    pub post: Option<ForkSession>,
}

/// Simulates the exact outer `execTransaction` for `signed`, sent by `payer`,
/// in `session`'s block with all validity checks (nonce, fees, balance).
///
/// Without `gas_limit`, gas is first measured at the largest limit the session
/// accepts (without requiring the payer to afford it) and the limit is that
/// plus 20%.
///
/// `session` itself is left untouched: the runs happen on checkpoints, and the
/// one the transaction was committed to is returned in
/// [`ExecSimulation::post`] so the caller can inspect the resulting state.
#[cfg(feature = "simulation")]
pub fn simulate_exec(
    session: &ForkSession,
    signed: &SignedSafeTx,
    payer: Address,
    fees: Eip1559Estimation,
    gas_limit: Option<u64>,
) -> Result<ExecSimulation> {
    let mut scratch = session.checkpoint();
    let payer_nonce = scratch.nonce(payer)?;
    let outer =
        |gas_limit| OuterTxParams::exec_transaction(signed, payer, payer_nonce, gas_limit, fees);

    let gas_limit = if let Some(gas) = gas_limit {
        gas
    } else {
        let max = session.max_tx_gas();
        let measured = scratch.transact(SimTx::from_outer(&outer(max), TxChecks::MEASURE))?;
        if !measured.success {
            return Ok(ExecSimulation {
                result: measured,
                payer_nonce,
                gas_limit: max,
                post: None,
            });
        }
        (measured.gas_used + measured.gas_used / 5).min(max)
    };

    let mut post = session.checkpoint();
    let mut result =
        post.transact_commit(SimTx::from_outer(&outer(gas_limit), TxChecks::STRICT))?;
    result.require_safe_success(signed.prepared.safe, signed.prepared.safe_tx_hash);
    let post = result.success.then_some(post);
    Ok(ExecSimulation {
        result,
        payer_nonce,
        gas_limit,
        post,
    })
}

/// Simulates `execTransaction` for `signed` on a Safe with `owners` and `threshold`.
///
/// - If `signed.signatures.len() >= threshold`, trims `signed` to exact `threshold` signatures
///   in ascending owner order and runs [`simulate_exec`] directly.
/// - If `signed.signatures.len() < threshold`, creates a checkpoint of `session`, commits
///   `ISafe::approveHash(safe_tx_hash)` via `SimTx::relaxed` for each missing co-owner up to
///   `threshold`, builds `signed.with_simulated_co_owners(owners, threshold)`, and runs
///   [`simulate_exec`] against that checkpoint so inner call reverts and Safe checks are
///   exercised even before all co-owners have signed.
#[cfg(feature = "simulation")]
pub fn simulate_exec_with_threshold(
    session: &ForkSession,
    signed: &SignedSafeTx,
    owners: &[Address],
    threshold: usize,
    payer: Address,
    fees: Eip1559Estimation,
    gas_limit: Option<u64>,
) -> Result<ExecSimulation> {
    if signed.signatures.len() >= threshold {
        let mut trimmed = signed.clone();
        trimmed.signatures = signed
            .signatures
            .iter()
            .take(threshold)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        return simulate_exec(session, &trimmed, payer, fees, gas_limit);
    }

    let mut pre_approved = session.checkpoint();
    let approve_calldata = SignedSafeTx::approve_hash_calldata(signed.prepared.safe_tx_hash);
    let gas = pre_approved.max_tx_gas().min(READ_CALL_GAS);
    let mut needed = threshold.saturating_sub(signed.signatures.len());
    for &owner in owners {
        if needed == 0 {
            break;
        }
        if !signed.signatures.contains_key(&owner) {
            pre_approved.transact_commit(SimTx::relaxed(
                owner,
                signed.prepared.safe,
                U256::ZERO,
                approve_calldata.clone(),
                gas,
            ))?;
            needed -= 1;
        }
    }
    let sim_signed = signed.with_simulated_co_owners(owners, threshold);
    simulate_exec(&pre_approved, &sim_signed, payer, fees, gas_limit)
}

/// Simulates an on-chain `ISafe::approveHash(safe_tx_hash)` outer transaction sent by `owner`.
#[cfg(feature = "simulation")]
pub fn simulate_approve_hash(
    session: &ForkSession,
    chain_id: u64,
    safe: Address,
    safe_tx_hash: B256,
    owner: Address,
    fees: Eip1559Estimation,
    gas_limit: Option<u64>,
) -> Result<ExecSimulation> {
    let mut scratch = session.checkpoint();
    let payer_nonce = scratch.nonce(owner)?;
    let outer = |gas_limit| {
        OuterTxParams::approve_hash(
            chain_id,
            safe,
            safe_tx_hash,
            owner,
            payer_nonce,
            gas_limit,
            fees,
        )
    };

    let gas_limit = if let Some(gas) = gas_limit {
        gas
    } else {
        let max = session.max_tx_gas();
        let measured = scratch.transact(SimTx::from_outer(&outer(max), TxChecks::MEASURE))?;
        if !measured.success {
            return Ok(ExecSimulation {
                result: measured,
                payer_nonce,
                gas_limit: max,
                post: None,
            });
        }
        (measured.gas_used + measured.gas_used / 5).min(max)
    };

    let mut post = session.checkpoint();
    let result = post.transact_commit(SimTx::from_outer(&outer(gas_limit), TxChecks::STRICT))?;
    let post = result.success.then_some(post);
    Ok(ExecSimulation {
        result,
        payer_nonce,
        gas_limit,
        post,
    })
}

/// How a broadcast ended.
#[derive(Debug, Clone)]
pub enum Submission {
    /// The transaction was mined (check the receipt status and logs)
    Mined(Box<AnyTransactionReceipt>),
    /// The node took the transaction but no receipt arrived in time; it may
    /// still be pending
    TimedOut {
        /// The transaction hash that was polled
        tx_hash: B256,
    },
    /// The node explicitly rejected the transaction
    Rejected {
        /// Node error message
        reason: String,
        /// Classification of the reason
        class: RejectClass,
    },
    /// The outcome of the broadcast is unknown; the transaction may or may not
    /// have reached the network
    Ambiguous {
        /// Error description
        reason: String,
    },
}

/// Broadcasts a signed outer transaction and waits for its receipt.
///
/// A node that already knows the transaction counts as accepted, so
/// rebroadcasting stored bytes is safe.
pub async fn submit_and_wait<P: Provider<AnyNetwork>>(
    provider: &P,
    outer: &SignedOuterTx,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<Submission> {
    match broadcast_raw(provider, &outer.raw, outer.tx_hash).await {
        BroadcastOutcome::Accepted(_) | BroadcastOutcome::AlreadyKnown(_) => {}
        BroadcastOutcome::Rejected { reason, class } => {
            return Ok(Submission::Rejected { reason, class })
        }
        BroadcastOutcome::Ambiguous { reason } => return Ok(Submission::Ambiguous { reason }),
    }
    Ok(
        match wait_for_receipt(provider, outer.tx_hash, timeout, poll_interval).await? {
            ReceiptWait::Mined(receipt) => Submission::Mined(receipt),
            ReceiptWait::TimedOut { tx_hash } => Submission::TimedOut { tx_hash },
        },
    )
}
