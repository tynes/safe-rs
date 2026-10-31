use std::fmt::{Display, Write as _};

use alloy::primitives::utils::format_ether;
use alloy::primitives::{Address, Bytes, TxHash, B256, U256};
#[cfg(feature = "hd-wallet")]
use safe_rs::rotation::RotationTx;
use safe_rs::{Operation, SafeState, SignedOuterTx, SignedSafeTx};
use serde::Serialize;

#[cfg(feature = "hd-wallet")]
mod rotation;
#[cfg(feature = "hd-wallet")]
pub use rotation::*;

/// A command result that prints either as JSON or as human-readable text.
pub trait Report: Serialize {
    /// Human-readable rendering (may span several lines).
    fn human(&self) -> String;

    fn print(&self, json: bool) {
        if json {
            println!("{}", serde_json::to_string_pretty(self).unwrap());
        } else {
            println!("{}", self.human());
        }
    }
}

/// Destination for human-readable progress text.
///
/// Progress is suppressed in `--json` mode and goes to stderr when stdout
/// carries a JSON document (for example `--raw-out -`).
#[derive(Clone, Copy)]
pub struct Console {
    quiet: bool,
    stderr: bool,
}

/// Prints a command result: as JSON on stdout, as text through the console,
/// or not at all in [`Output::Quiet`].
pub fn emit(report: &impl Report, output: Output, console: Console) {
    match output {
        Output::Json => report.print(true),
        Output::Human => console.line(report.human()),
        Output::Quiet => {}
    }
}

/// How a send ended. Failures (a reverted transaction, a failed simulation, a
/// receipt that never came) are errors instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SendOutcome {
    /// The confirmation prompt was declined; nothing was broadcast
    Aborted { safe_tx_hash: B256 },
    /// `--simulate-only`: the simulation passed; nothing was signed or broadcast
    Simulated { safe_tx_hash: B256, gas_used: u64 },
    /// The signatures were saved to the bundle for other owners to add to:
    /// `--sign-only`, or fewer signatures than the threshold
    Signed {
        safe_tx_hash: B256,
        safe_nonce: U256,
        signatures: usize,
        threshold: usize,
        bundle: std::path::PathBuf,
    },
    /// `--approve-hash`: the approveHash transaction was mined
    HashApproved {
        tx_hash: B256,
        safe_tx_hash: B256,
        gas_used: u64,
        block: Option<u64>,
    },
    /// `--no-submit`: the transaction was signed but not broadcast
    NotSubmitted {
        tx_hash: B256,
        safe_tx_hash: B256,
        /// EIP-2718 bytes for `eth_sendRawTransaction`
        raw: Bytes,
    },
    /// The Safe transaction was executed and succeeded
    Executed {
        tx_hash: B256,
        safe_tx_hash: B256,
        gas_used: u64,
        /// Block it was mined in, when the receipt names it
        block: Option<u64>,
    },
    /// A send from an EOA declined at the confirmation prompt; nothing was
    /// broadcast
    EoaAborted,
    /// A send from an EOA with `--simulate-only`: every transaction passed in
    /// simulation; nothing was signed or broadcast
    EoaSimulated {
        /// Gas used by all the transactions together
        gas_used: u64,
    },
    /// A send from an EOA: every call was mined, one transaction each, and
    /// succeeded
    EoaExecuted { txs: Vec<EoaTx> },
}

/// One mined transaction of a send from an EOA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EoaTx {
    pub tx_hash: B256,
    pub gas_used: u64,
    /// Block it was mined in, when the receipt names it
    pub block: Option<u64>,
}

/// The transactions of a send from an EOA, once all were mined.
#[derive(Serialize)]
pub struct EoaExecutionOutput {
    pub from: Address,
    pub txs: Vec<EoaTx>,
}

impl Report for EoaExecutionOutput {
    fn human(&self) -> String {
        let mut s = format!("Transactions Executed from {}:", self.from);
        for (i, tx) in self.txs.iter().enumerate() {
            let _ = write!(
                s,
                "\n  {}. {} (gas used {})",
                i + 1,
                tx.tx_hash,
                tx.gas_used
            );
        }
        s
    }
}

/// What a send prints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Output {
    /// Progress, the confirmation prompt and the result as text, as `safe send`
    #[default]
    Human,
    /// The result as one JSON document on stdout, and nothing else; never
    /// prompts (`safe send --json`)
    Json,
    /// Progress and the confirmation prompt as text on stderr, and no result:
    /// for a CLI that prints its own from the returned
    /// [`SendOutcome`](crate::SendOutcome). Stdout stays untouched unless
    /// `--raw-out -` asks for it.
    Quiet,
}

impl Output {
    pub fn from_json(json: bool) -> Self {
        if json {
            Self::Json
        } else {
            Self::Human
        }
    }

    /// Whether the confirmation prompt may be shown.
    pub fn prompts(self) -> bool {
        self != Self::Json
    }
}

impl Console {
    pub fn new(json: bool, stdout_is_data: bool) -> Self {
        Self {
            quiet: json,
            stderr: stdout_is_data,
        }
    }

    pub fn for_output(output: Output, stdout_is_data: bool) -> Self {
        Self {
            quiet: output == Output::Json,
            stderr: stdout_is_data || output == Output::Quiet,
        }
    }

    pub fn line(&self, text: impl Display) {
        if self.quiet {
            return;
        }
        if self.stderr {
            eprintln!("{text}");
        } else {
            println!("{text}");
        }
    }
}

#[derive(Serialize)]
pub struct SafeInfoOutput {
    pub address: Address,
    /// Native balance in wei
    pub balance: U256,
    pub nonce: U256,
    pub threshold: u64,
    pub owners: Vec<Address>,
    pub singleton: Address,
    pub version: Option<String>,
    pub code_hash: B256,
    pub modules: Vec<Address>,
    /// False if module enumeration stopped before the end of the list
    pub modules_complete: bool,
    pub guard: Address,
    pub fallback_handler: Address,
    /// Module guard; absent for Safe versions without one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_guard: Option<Address>,
    pub block_number: u64,
    pub block_hash: B256,
}

impl SafeInfoOutput {
    pub fn new(state: SafeState, balance: U256, block_number: u64, block_hash: B256) -> Self {
        Self {
            address: state.address,
            balance,
            nonce: state.nonce,
            threshold: state.threshold.saturating_to(),
            owners: state.owners,
            singleton: state.singleton,
            version: state.version,
            code_hash: state.code_hash,
            modules: state.modules.modules,
            modules_complete: state.modules.complete,
            guard: state.guard,
            fallback_handler: state.fallback_handler,
            module_guard: state.module_guard,
            block_number,
            block_hash,
        }
    }
}

impl Report for SafeInfoOutput {
    fn human(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "Safe: {}", self.address);
        let _ = writeln!(s, "Block: {} ({})", self.block_number, self.block_hash);
        let _ = writeln!(
            s,
            "Version: {}",
            self.version.as_deref().unwrap_or("unknown")
        );
        let _ = writeln!(s, "Singleton: {}", self.singleton);
        let _ = writeln!(s, "Balance: {} ETH", format_ether(self.balance));
        let _ = writeln!(s, "Nonce: {}", self.nonce);
        let _ = writeln!(s, "Threshold: {}", self.threshold);
        let _ = writeln!(s, "Owners:");
        for (i, owner) in self.owners.iter().enumerate() {
            let _ = writeln!(s, "  {}: {}", i + 1, owner);
        }
        let _ = writeln!(
            s,
            "Modules:{}",
            if self.modules.is_empty() { " none" } else { "" }
        );
        for (i, module) in self.modules.iter().enumerate() {
            let _ = writeln!(s, "  {}: {}", i + 1, module);
        }
        if !self.modules_complete {
            let _ = writeln!(s, "  WARNING: module list is incomplete");
        }
        let _ = writeln!(s, "Guard: {}", optional_address(self.guard));
        if let Some(module_guard) = self.module_guard {
            let _ = writeln!(s, "Module Guard: {}", optional_address(module_guard));
        }
        let _ = write!(
            s,
            "Fallback Handler: {}",
            optional_address(self.fallback_handler)
        );
        s
    }
}

/// How far a Safe transaction is from execution, read at one block.
#[derive(Serialize)]
pub struct SafeApprovalsOutput {
    pub safe: Address,
    pub safe_tx_hash: B256,
    pub threshold: u64,
    /// Owners that approved on-chain or signed offchain
    pub approvals: u64,
    /// Current owners with `approvedHashes(owner, safe_tx_hash) != 0`
    pub approved_onchain: Vec<Address>,
    /// Current owners with a valid signature in the bundle and no on-chain approval
    pub signed_offchain: Vec<Address>,
    /// Current owners that have neither approved nor signed
    pub pending: Vec<Address>,
    /// Enough approvals for anyone to execute
    pub executable: bool,
    /// The Safe's current nonce
    pub safe_nonce: U256,
    /// The transaction's nonce; known only from a bundle
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_nonce: Option<U256>,
    /// True when the Safe's nonce is past the transaction's (executed or
    /// replaced); known only from a bundle
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_used: Option<bool>,
    pub block_number: u64,
    pub block_hash: B256,
}

impl SafeApprovalsOutput {
    pub fn new(
        state: &SafeState,
        safe_tx_hash: B256,
        approved_onchain: Vec<Address>,
        signed_offchain: Vec<Address>,
        tx_nonce: Option<U256>,
        block_number: u64,
        block_hash: B256,
    ) -> Self {
        let pending = state
            .owners
            .iter()
            .filter(|owner| !approved_onchain.contains(owner) && !signed_offchain.contains(owner))
            .copied()
            .collect();
        let approvals = (approved_onchain.len() + signed_offchain.len()) as u64;
        let threshold: u64 = state.threshold.saturating_to();
        Self {
            safe: state.address,
            safe_tx_hash,
            threshold,
            approvals,
            approved_onchain,
            signed_offchain,
            pending,
            executable: approvals >= threshold,
            safe_nonce: state.nonce,
            tx_nonce,
            nonce_used: tx_nonce.map(|nonce| nonce < state.nonce),
            block_number,
            block_hash,
        }
    }
}

impl Report for SafeApprovalsOutput {
    fn human(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "Safe: {}", self.safe);
        let _ = writeln!(s, "Block: {} ({})", self.block_number, self.block_hash);
        let _ = writeln!(s, "SafeTxHash: {}", self.safe_tx_hash);
        match (self.tx_nonce, self.nonce_used) {
            (Some(nonce), Some(true)) => {
                let _ = writeln!(
                    s,
                    "Nonce: {nonce} (already used, Safe nonce is {}: executed or replaced)",
                    self.safe_nonce
                );
            }
            (Some(nonce), _) => {
                let _ = writeln!(s, "Nonce: {nonce} (Safe nonce is {})", self.safe_nonce);
            }
            (None, _) => {
                let _ = writeln!(s, "Safe nonce: {}", self.safe_nonce);
            }
        }
        let _ = writeln!(
            s,
            "Approvals: {} / {} threshold",
            self.approvals, self.threshold
        );
        for (label, owners) in [
            ("Approved on-chain", &self.approved_onchain),
            ("Signed offchain", &self.signed_offchain),
            ("Pending", &self.pending),
        ] {
            if owners.is_empty() {
                continue;
            }
            let _ = writeln!(s, "{label}:");
            for owner in owners {
                let _ = writeln!(s, "  {owner}");
            }
        }
        let status = if self.nonce_used == Some(true) {
            "Status: nonce already used"
        } else if self.executable {
            "Status: ready to execute"
        } else if self.approvals + 1 == self.threshold {
            "Status: one approval short (a pending owner can execute it directly)"
        } else {
            "Status: waiting for approvals"
        };
        let _ = write!(s, "{status}");
        if self.tx_nonce.is_none() {
            let _ = write!(
                s,
                "\nNote: on-chain approvals stay after execution; pass --bundle to check the nonce"
            );
        }
        s
    }
}

fn optional_address(address: Address) -> String {
    if address == Address::ZERO {
        "none".to_string()
    } else {
        address.to_string()
    }
}

#[derive(Serialize, Default)]
pub struct SimulationOutput {
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_tx_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traces: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures_collected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_to_execute: Option<bool>,
}
impl Report for SimulationOutput {
    fn human(&self) -> String {
        let mut s = String::from("Simulation Result:");
        let _ = write!(s, "\n  Success: {}", self.success);
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        if let Some(reason) = &self.revert_reason {
            let _ = write!(s, "\n  Revert Reason: {}", reason);
        }
        if let Some(traces) = &self.traces {
            let _ = write!(s, "\nTraces:\n{}", traces);
        }
        s
    }
}

#[derive(Serialize)]
pub struct ExecutionOutput {
    pub tx_hash: TxHash,
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_tx_hash: Option<B256>,
    /// Safe outcome: `success`, `failure`, `not_found` or `conflicting`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
}

impl Report for ExecutionOutput {
    fn human(&self) -> String {
        let mut s = String::from("Transaction Executed:");
        let _ = write!(s, "\n  Tx Hash: {}", self.tx_hash);
        if let Some(safe_tx_hash) = &self.safe_tx_hash {
            let _ = write!(s, "\n  Safe Tx Hash: {}", safe_tx_hash);
        }
        let _ = write!(s, "\n  Success: {}", self.success);
        if let Some(outcome) = self.outcome {
            let _ = write!(s, "\n  Outcome: {}", outcome);
        }
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        s
    }
}

#[derive(Serialize)]
pub struct ApproveHashOutput {
    pub tx_hash: TxHash,
    pub success: bool,
    pub gas_used: u64,
    pub safe_tx_hash: B256,
    pub safe_nonce: U256,
    pub approver: Address,
    pub signatures_collected: usize,
    pub threshold: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<String>,
}

impl Report for ApproveHashOutput {
    fn human(&self) -> String {
        let mut s = String::from("Safe Hash Approved On-Chain:");
        let _ = write!(s, "\n  Tx Hash: {}", self.tx_hash);
        let _ = write!(s, "\n  Safe Tx Hash: {}", self.safe_tx_hash);
        let _ = write!(s, "\n  Safe Nonce: {}", self.safe_nonce);
        let _ = write!(s, "\n  Approver: {}", self.approver);
        let _ = write!(
            s,
            "\n  Approvals: {}/{}",
            self.signatures_collected, self.threshold
        );
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        if let Some(path) = &self.bundle_path {
            let _ = write!(s, "\n  Bundle Saved: {path}");
        }
        s
    }
}

#[derive(Serialize)]
pub struct BundleSavedOutput {
    pub safe_tx_hash: B256,
    pub safe_nonce: U256,
    pub signatures_collected: usize,
    pub threshold: usize,
    pub signers: Vec<Address>,
    pub remaining_owners: Vec<Address>,
    pub bundle_path: String,
}

impl Report for BundleSavedOutput {
    fn human(&self) -> String {
        let mut s = format!("Bundle Saved to {}:", self.bundle_path);
        let _ = write!(s, "\n  Safe Tx Hash: {}", self.safe_tx_hash);
        let _ = write!(s, "\n  Safe Nonce: {}", self.safe_nonce);
        let _ = write!(
            s,
            "\n  Signatures: {}/{}",
            self.signatures_collected, self.threshold
        );
        if !self.signers.is_empty() {
            let _ = write!(
                s,
                "\n  Signed by: {}",
                self.signers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !self.remaining_owners.is_empty() {
            let _ = write!(
                s,
                "\n  Remaining owners: {}",
                self.remaining_owners
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        s
    }
}

/// A Safe transaction and the outer transaction that submits it, as written by
/// `send --raw-out`.
#[derive(Serialize)]
pub struct SignedTxOutput {
    pub chain_id: u64,
    pub safe: Address,
    pub safe_nonce: U256,
    pub safe_tx_hash: B256,
    pub safe_tx: SafeTxOutput,
    /// Owner whose signature is included
    pub signer: Address,
    pub signature: Bytes,
    pub outer: OuterTxOutput,
    /// EIP-2718 encoded outer transaction, for `eth_sendRawTransaction`
    pub raw: Bytes,
    pub tx_hash: B256,
    /// The owner swap the Safe transaction ends with, for `send --rotate`
    #[cfg(feature = "hd-wallet")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<RotationPlanOutput>,
}

#[derive(Serialize)]
pub struct SafeTxOutput {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    /// 0 = CALL, 1 = DELEGATECALL
    pub operation: u8,
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: Address,
    pub refund_receiver: Address,
}

#[derive(Serialize)]
pub struct OuterTxOutput {
    pub from: Address,
    pub to: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub value: U256,
    pub input: Bytes,
}

impl SignedTxOutput {
    pub fn new(signed: &SignedSafeTx, outer: &SignedOuterTx) -> Self {
        let prepared = &signed.prepared;
        let p = &prepared.params;
        let o = &outer.params;
        Self {
            chain_id: prepared.chain_id,
            safe: prepared.safe,
            safe_nonce: p.nonce,
            safe_tx_hash: prepared.safe_tx_hash,
            safe_tx: SafeTxOutput {
                to: p.to,
                value: p.value,
                data: p.data.clone(),
                operation: p.operation.as_u8(),
                safe_tx_gas: p.safe_tx_gas,
                base_gas: p.base_gas,
                gas_price: p.gas_price,
                gas_token: p.gas_token,
                refund_receiver: p.refund_receiver,
            },
            signer: signed.owner().unwrap_or(o.from),
            signature: signed.packed_signatures(),
            outer: OuterTxOutput {
                from: o.from,
                to: o.to,
                nonce: o.nonce,
                gas_limit: o.gas_limit,
                max_fee_per_gas: U256::from(o.max_fee_per_gas),
                max_priority_fee_per_gas: U256::from(o.max_priority_fee_per_gas),
                value: o.value,
                input: o.input.clone(),
            },
            raw: outer.raw.clone(),
            tx_hash: outer.tx_hash,
            #[cfg(feature = "hd-wallet")]
            rotation: None,
        }
    }

    /// The document for a rotating transaction, including the owner swap.
    #[cfg(feature = "hd-wallet")]
    pub fn for_rotation(tx: &RotationTx) -> Self {
        Self {
            rotation: Some(RotationPlanOutput::new(tx)),
            ..Self::new(&tx.signed, &tx.outer)
        }
    }

    /// Writes the document to `dest`, a file path or `-` for stdout.
    pub fn write_to(&self, dest: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        if dest == "-" {
            println!("{json}");
            Ok(())
        } else {
            std::fs::write(dest, json + "\n")
        }
    }
}

impl Report for SignedTxOutput {
    fn human(&self) -> String {
        let mut s = String::from("Signed Transaction:");
        let _ = write!(s, "\n  Safe Tx Hash: {}", self.safe_tx_hash);
        let _ = write!(s, "\n  Safe Nonce: {}", self.safe_nonce);
        let _ = write!(s, "\n  Tx Hash: {}", self.tx_hash);
        let _ = write!(
            s,
            "\n  From: {} (nonce {})",
            self.outer.from, self.outer.nonce
        );
        let _ = write!(s, "\n  Gas Limit: {}", self.outer.gas_limit);
        s
    }
}

#[derive(Serialize)]
pub struct CreateOutput {
    pub safe_address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<TxHash>,
    pub owners: Vec<Address>,
    pub threshold: u64,
    pub already_deployed: bool,
}

impl Report for CreateOutput {
    fn human(&self) -> String {
        let mut s = String::new();
        let _ = write!(s, "Safe Address: {}", self.safe_address);
        if self.already_deployed {
            let _ = write!(s, "\n  Status: Already deployed");
        } else if let Some(tx_hash) = self.tx_hash {
            let _ = write!(s, "\n  Tx Hash: {}", tx_hash);
        }
        let _ = write!(s, "\n  Threshold: {}", self.threshold);
        let _ = write!(s, "\n  Owners:");
        for (i, owner) in self.owners.iter().enumerate() {
            let _ = write!(s, "\n    {}: {}", i + 1, owner);
        }
        s
    }
}

#[derive(Serialize)]
pub struct CallOutput {
    pub success: bool,
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traces: Option<String>,
}

impl Report for CallOutput {
    fn human(&self) -> String {
        let mut s = String::from("Call Result:");
        let _ = write!(s, "\n  Success: {}", self.success);
        let _ = write!(s, "\n  Gas Used: {}", self.gas_used);
        if let Some(data) = &self.return_data {
            let _ = write!(s, "\n  Return Data: {}", data);
        }
        if let Some(reason) = &self.revert_reason {
            let _ = write!(s, "\n  Revert Reason: {}", reason);
        }
        if let Some(traces) = &self.traces {
            let _ = write!(s, "\nTraces:\n{}", traces);
        }
        s
    }
}

pub fn calls_summary(calls: &[safe_rs::Call]) -> String {
    let mut s = format!("Calls ({}):", calls.len());
    for (i, call) in calls.iter().enumerate() {
        let _ = write!(s, "\n  {}. To: {}", i + 1, call.to);
        if call.operation == Operation::DelegateCall {
            let _ = write!(s, " (delegatecall)");
        }
        if !call.value.is_zero() {
            let _ = write!(s, "\n     Value: {} wei", call.value);
        }
        let _ = write!(s, "\n     Data: {} bytes", call.data.len());
    }
    s
}

pub fn confirm_prompt(message: &str) -> bool {
    use dialoguer::Confirm;

    Confirm::new()
        .with_prompt(message)
        .default(false)
        .interact()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::eips::BlockId;
    use alloy::primitives::{address, b256};
    use safe_rs::ModuleList;

    fn to_json(value: &impl Serialize) -> serde_json::Value {
        serde_json::from_str(&serde_json::to_string_pretty(value).unwrap()).unwrap()
    }

    fn info(owners: Vec<Address>) -> SafeInfoOutput {
        SafeInfoOutput {
            address: address!("0x1234567890123456789012345678901234567890"),
            balance: U256::from(1_500_000_000_000_000_000u128),
            nonce: U256::from(42),
            threshold: 2,
            owners,
            singleton: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
            version: Some("1.4.1".to_string()),
            code_hash: B256::ZERO,
            modules: vec![],
            modules_complete: true,
            guard: Address::ZERO,
            fallback_handler: Address::ZERO,
            module_guard: None,
            block_number: 7,
            block_hash: B256::ZERO,
        }
    }

    #[test]
    fn test_safe_info_output_json_format() {
        let parsed = to_json(&info(vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
        ]));

        assert_eq!(
            parsed["address"],
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(parsed["nonce"], "0x2a"); // 42 in hex
        assert_eq!(parsed["threshold"], 2);
        assert_eq!(parsed["owners"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["version"], "1.4.1");
        assert_eq!(parsed["modules_complete"], true);
        assert_eq!(parsed["block_number"], 7);
        assert_eq!(parsed["balance"], "0x14d1120d7b160000"); // 1.5 ether in wei
    }

    fn approvals(
        approved: Vec<Address>,
        offchain: Vec<Address>,
        tx_nonce: Option<U256>,
    ) -> SafeApprovalsOutput {
        let state = SafeState {
            address: address!("0x1234567890123456789012345678901234567890"),
            code_hash: B256::ZERO,
            singleton: Address::ZERO,
            version: None,
            owners: vec![
                address!("0x1111111111111111111111111111111111111111"),
                address!("0x2222222222222222222222222222222222222222"),
                address!("0x3333333333333333333333333333333333333333"),
            ],
            threshold: U256::from(2),
            nonce: U256::from(5),
            modules: ModuleList {
                modules: vec![],
                complete: true,
            },
            guard: Address::ZERO,
            fallback_handler: Address::ZERO,
            module_guard: None,
            block: BlockId::latest(),
        };
        SafeApprovalsOutput::new(
            &state,
            B256::ZERO,
            approved,
            offchain,
            tx_nonce,
            7,
            B256::ZERO,
        )
    }

    #[test]
    fn test_safe_approvals_counts_onchain_and_offchain() {
        let one = address!("0x1111111111111111111111111111111111111111");
        let two = address!("0x2222222222222222222222222222222222222222");
        let output = approvals(vec![one], vec![], None);
        assert_eq!(output.approvals, 1);
        assert!(!output.executable);
        assert_eq!(output.pending.len(), 2);
        assert!(output.human().contains("one approval short"));
        let parsed = to_json(&output);
        assert!(parsed.get("nonce_used").is_none());

        let output = approvals(vec![one], vec![two], Some(U256::from(5)));
        assert_eq!(output.approvals, 2);
        assert!(output.executable);
        assert_eq!(output.nonce_used, Some(false));
        assert!(output.human().contains("ready to execute"));
    }

    #[test]
    fn test_safe_approvals_flags_a_used_nonce() {
        let output = approvals(vec![], vec![], Some(U256::from(4)));
        assert_eq!(output.nonce_used, Some(true));
        assert!(output.human().contains("nonce already used"));
    }

    #[test]
    fn test_safe_info_human_shows_balance_in_ether() {
        assert!(info(vec![])
            .human()
            .contains("Balance: 1.500000000000000000 ETH"));
    }

    #[test]
    fn test_safe_info_output_empty_owners() {
        let parsed = to_json(&info(vec![]));
        assert!(parsed["owners"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_safe_info_human_flags_incomplete_modules() {
        let mut output = info(vec![]);
        output.modules_complete = false;
        assert!(output.human().contains("incomplete"));
    }

    #[test]
    fn test_simulation_output_json_format_success() {
        let parsed = to_json(&SimulationOutput {
            success: true,
            gas_used: 50_000,
            revert_reason: None,
            safe_tx_hash: None,
            traces: None,
            ..Default::default()
        });

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 50_000);
        // optional fields should be absent (skip_serializing_if)
        assert!(parsed.get("revert_reason").is_none());
        assert!(parsed.get("traces").is_none());
    }

    #[test]
    fn test_simulation_output_json_format_failure() {
        let parsed = to_json(&SimulationOutput {
            success: false,
            gas_used: 21_000,
            revert_reason: Some("ERC20: transfer amount exceeds balance".to_string()),
            safe_tx_hash: None,
            traces: None,
            ..Default::default()
        });

        assert_eq!(parsed["success"], false);
        assert_eq!(parsed["gas_used"], 21_000);
        assert_eq!(
            parsed["revert_reason"],
            "ERC20: transfer amount exceeds balance"
        );
    }

    #[test]
    fn test_execution_output_json_format() {
        let tx_hash = b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let parsed = to_json(&ExecutionOutput {
            tx_hash,
            success: true,
            gas_used: 100_000,
            safe_tx_hash: Some(B256::ZERO),
            outcome: Some("success"),
        });

        assert_eq!(
            parsed["tx_hash"],
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 100_000);
        assert_eq!(parsed["outcome"], "success");
    }

    #[test]
    fn test_create_output_json_format_new_deployment() {
        let tx_hash = b256!("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        let parsed = to_json(&CreateOutput {
            safe_address: address!("0x1234567890123456789012345678901234567890"),
            tx_hash: Some(tx_hash),
            owners: vec![address!("0x1111111111111111111111111111111111111111")],
            threshold: 1,
            already_deployed: false,
        });

        assert_eq!(
            parsed["safe_address"],
            "0x1234567890123456789012345678901234567890"
        );
        assert!(parsed["tx_hash"].is_string());
        assert_eq!(parsed["threshold"], 1);
        assert_eq!(parsed["already_deployed"], false);
    }

    #[test]
    fn test_create_output_json_format_already_deployed() {
        let parsed = to_json(&CreateOutput {
            safe_address: address!("0x1234567890123456789012345678901234567890"),
            tx_hash: None,
            owners: vec![
                address!("0x1111111111111111111111111111111111111111"),
                address!("0x2222222222222222222222222222222222222222"),
            ],
            threshold: 2,
            already_deployed: true,
        });

        assert_eq!(parsed["already_deployed"], true);
        // tx_hash should be absent (skip_serializing_if)
        assert!(parsed.get("tx_hash").is_none());
        assert_eq!(parsed["threshold"], 2);
        assert_eq!(parsed["owners"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_call_output_json_format_success() {
        let parsed = to_json(&CallOutput {
            success: true,
            gas_used: 25_000,
            return_data: Some(Bytes::from(vec![0u8; 32])),
            revert_reason: None,
            traces: None,
        });

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["gas_used"], 25_000);
        assert!(parsed["return_data"].as_str().unwrap().starts_with("0x"));
        assert!(parsed.get("revert_reason").is_none());
    }

    #[test]
    fn test_call_output_json_format_failure() {
        let parsed = to_json(&CallOutput {
            success: false,
            gas_used: 21_000,
            return_data: None,
            revert_reason: Some("Insufficient balance".to_string()),
            traces: None,
        });

        assert_eq!(parsed["success"], false);
        assert!(parsed.get("return_data").is_none());
        assert_eq!(parsed["revert_reason"], "Insufficient balance");
    }

    #[tokio::test]
    async fn test_signed_tx_output_matches_signed_transactions() {
        use alloy::eips::eip1559::Eip1559Estimation;
        use alloy::primitives::keccak256;
        use alloy::signers::local::PrivateKeySigner;
        use safe_rs::{sign_outer_tx, Call, OuterTxParams, PreparedSafeTx, SafeTxGasPolicy};

        let owner = PrivateKeySigner::random();
        let safe = address!("0x1000000000000000000000000000000000000001");
        let prepared = PreparedSafeTx::single_call(
            1,
            safe,
            &Call::new(safe, U256::from(5), Bytes::new()),
            U256::from(3),
            SafeTxGasPolicy::Zero,
        )
        .unwrap();
        let signed = prepared.sign(&owner).await.unwrap();
        let fees = Eip1559Estimation {
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        };
        let params = OuterTxParams::exec_transaction(&signed, owner.address(), 4, 90_000, fees);
        let outer = sign_outer_tx(&owner, params).await.unwrap();

        let parsed = to_json(&SignedTxOutput::new(&signed, &outer));
        assert_eq!(parsed["chain_id"], 1);
        assert_eq!(parsed["safe_nonce"], "0x3");
        assert_eq!(parsed["safe_tx_hash"], prepared.safe_tx_hash.to_string());
        assert_eq!(parsed["safe_tx"]["operation"], 0);
        assert_eq!(parsed["safe_tx"]["safe_tx_gas"], "0x0");
        assert_eq!(parsed["outer"]["nonce"], 4);
        assert_eq!(parsed["outer"]["gas_limit"], 90_000);
        assert_eq!(parsed["outer"]["to"], safe.to_string());
        let raw: Bytes = parsed["raw"].as_str().unwrap().parse().unwrap();
        assert_eq!(parsed["tx_hash"], keccak256(&raw).to_string());
    }

    #[test]
    fn test_calls_summary_marks_delegatecalls() {
        let calls = [
            safe_rs::Call::new(
                address!("0x1111111111111111111111111111111111111111"),
                U256::from(1000),
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
            safe_rs::Call::delegate_call(
                address!("0x2222222222222222222222222222222222222222"),
                vec![0xa9, 0x05, 0x9c, 0xbb],
            ),
        ];
        let summary = calls_summary(&calls);
        assert!(summary.starts_with("Calls (2):"));
        assert!(summary.contains("Value: 1000 wei"));
        assert_eq!(summary.matches("(delegatecall)").count(), 1);
    }
}
