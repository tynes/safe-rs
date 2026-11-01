//! What `--rotate`, `safe rotate`, `safe create --hd-wallet` and `safe wallet`
//! report.

use std::fmt::{Display, Write as _};

use alloy::primitives::utils::format_ether;
use alloy::primitives::{Address, TxHash, B256, U256};
use safe_rs::rotation::{
    OwnerRef, Reserved, RotationOutcome, RotationStatus, RotationTx, SweepOutcome,
};
use serde::Serialize;

use super::{calls_summary, Report};

/// An owner key: a wallet key index, or an address the wallet cannot derive.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    pub address: Address,
}

impl From<OwnerRef> for OwnerOutput {
    fn from(owner: OwnerRef) -> Self {
        Self {
            index: owner.index(),
            address: owner.address(),
        }
    }
}

impl From<Reserved> for OwnerOutput {
    fn from(reserved: Reserved) -> Self {
        Self {
            index: Some(reserved.index),
            address: reserved.address,
        }
    }
}

impl Display for OwnerOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.index {
            Some(index) => write!(f, "key {index} ({})", self.address),
            None => write!(f, "{} (not a wallet key)", self.address),
        }
    }
}

/// A sweep that is expected to follow a rotation.
#[derive(Serialize, Clone, Copy)]
pub struct PlannedSweepOutput {
    pub from: Address,
    pub to: Address,
    /// Approximate wei; the exact amount depends on the gas the rotation pays
    pub estimated: U256,
}

/// What a rotating transaction does besides the user's calls.
#[derive(Serialize, Clone, Copy)]
pub struct RotationPlanOutput {
    /// The owner that signs and is swapped out
    pub old_owner: OwnerOutput,
    /// The owner the Safe has afterwards
    pub new_owner: OwnerOutput,
    /// Sender of the outer transaction
    pub payer: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planned_sweep: Option<PlannedSweepOutput>,
}

impl RotationPlanOutput {
    pub fn new(tx: &RotationTx) -> Self {
        Self {
            old_owner: tx.from.into(),
            new_owner: tx.to.into(),
            payer: tx.payer,
            planned_sweep: tx.planned_sweep.map(|sweep| PlannedSweepOutput {
                from: sweep.from,
                to: sweep.to,
                estimated: sweep.estimated,
            }),
        }
    }
}

/// Everything a rotating transaction will do, for review before it is sent:
/// the user's calls, the owner swap appended to them, who pays, and the sweep.
pub fn rotation_summary(
    tx: &RotationTx,
    user_calls: &[safe_rs::Call],
    sweep_enabled: bool,
) -> String {
    let plan = RotationPlanOutput::new(tx);
    let prepared = &tx.plan.prepared;
    let mut s = format!("Safe: {}", prepared.safe);
    let _ = write!(s, "\nOwner: {}", plan.old_owner);
    let _ = write!(s, "\nNext owner: {}", plan.new_owner);
    let _ = write!(s, "\nPayer: {}", plan.payer);
    if plan.payer == plan.old_owner.address {
        let _ = write!(s, " (the owner)");
    }
    let _ = write!(s, "\nNonce: {}", prepared.params.nonce);
    let _ = write!(s, "\nSafe Tx Hash: {}", prepared.safe_tx_hash);

    let total = user_calls.len() + tx.plan.swaps.len();
    let _ = write!(s, "\n\nCalls ({total}):");
    if !user_calls.is_empty() {
        // Skip the "Calls (n):" header of the plain summary.
        let listed = calls_summary(user_calls);
        if let Some((_, rest)) = listed.split_once('\n') {
            let _ = write!(s, "\n{rest}");
        }
    }
    for (offset, swap) in tx.plan.swaps.iter().enumerate() {
        let _ = write!(
            s,
            "\n  {}. To: {} (the Safe)",
            user_calls.len() + offset + 1,
            prepared.safe
        );
        if (swap.old_owner, swap.new_owner) == (plan.old_owner.address, plan.new_owner.address) {
            let _ = write!(
                s,
                "\n     swapOwner: {} -> {}",
                plan.old_owner, plan.new_owner
            );
        } else {
            let _ = write!(
                s,
                "\n     swapOwner: {} -> {}",
                swap.old_owner, swap.new_owner
            );
        }
    }

    match (plan.planned_sweep, sweep_enabled) {
        (Some(sweep), _) => {
            let _ = write!(
                s,
                "\n\nSweep: about {} ETH from {} to {}, sent with the rotation",
                format_ether(sweep.estimated),
                sweep.from,
                sweep.to
            );
        }
        (None, true) => {
            let _ = write!(
                s,
                "\n\nSweep: nothing to move ({} holds no spare ETH)",
                plan.old_owner.address
            );
        }
        (None, false) => {
            let _ = write!(
                s,
                "\n\nSweep: off. {} stays unfunded: fund it or use --payer-private-key for the next transaction",
                plan.new_owner.address
            );
        }
    }
    s
}

/// A completed sweep.
#[derive(Serialize, Clone, Copy)]
pub struct SweepOutput {
    pub tx_hash: TxHash,
    /// Wei moved
    pub amount: U256,
    pub from: Address,
    pub to: Address,
}

impl From<SweepOutcome> for SweepOutput {
    fn from(sweep: SweepOutcome) -> Self {
        Self {
            tx_hash: sweep.tx_hash,
            amount: sweep.amount,
            from: sweep.from,
            to: sweep.to,
        }
    }
}

impl Report for SweepOutput {
    fn human(&self) -> String {
        format!(
            "Swept {} ETH from {} to {}\n  Tx Hash: {}",
            format_ether(self.amount),
            self.from,
            self.to,
            self.tx_hash
        )
    }
}

/// The result of a mined rotating transaction.
#[derive(Serialize)]
pub struct RotationOutput {
    pub tx_hash: TxHash,
    pub safe_tx_hash: B256,
    /// True only if the Safe transaction succeeded and the owner was rotated by it
    pub success: bool,
    /// Safe outcome: `success`, `failure`, `not_found` or `conflicting`
    pub outcome: &'static str,
    /// Owner list outcome: `rotated`, `rotated_elsewhere` or `not_rotated`
    pub status: &'static str,
    pub gas_used: u64,
    pub old_owner: OwnerOutput,
    /// The owner the Safe has now
    pub owner: OwnerOutput,
    pub payer: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sweep: Option<SweepOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl RotationOutput {
    pub fn new(
        plan: RotationPlanOutput,
        outcome: &RotationOutcome,
        owner: OwnerOutput,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            tx_hash: outcome.tx_hash,
            safe_tx_hash: outcome.safe_tx_hash,
            success: outcome.status == RotationStatus::Rotated,
            outcome: outcome.safe_outcome.label(),
            status: match outcome.status {
                RotationStatus::Rotated => "rotated",
                RotationStatus::RotatedElsewhere => "rotated_elsewhere",
                RotationStatus::NotRotated => "not_rotated",
            },
            gas_used: outcome.gas_used,
            old_owner: plan.old_owner,
            owner,
            payer: plan.payer,
            sweep: outcome.sweep.map(Into::into),
            warnings,
        }
    }
}

impl Report for RotationOutput {
    fn human(&self) -> String {
        let mut s = String::from("Transaction Executed:");
        let _ = write!(s, "\n  Tx Hash: {}", self.tx_hash);
        let _ = write!(s, "\n  Safe Tx Hash: {}", self.safe_tx_hash);
        let _ = write!(s, "\n  Success: {}", self.success);
        let _ = write!(s, "\n  Outcome: {}", self.outcome);
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        let _ = write!(s, "\n  Rotation: {}", self.status);
        let _ = write!(s, "\n  Owner: {}", self.owner);
        match &self.sweep {
            Some(sweep) => {
                let _ = write!(
                    s,
                    "\n  Swept: {} ETH from {} (tx {})",
                    format_ether(sweep.amount),
                    sweep.from,
                    sweep.tx_hash
                );
            }
            None => {
                let _ = write!(s, "\n  Swept: nothing");
            }
        }
        for warning in &self.warnings {
            let _ = write!(s, "\n  Warning: {warning}");
        }
        s
    }
}
