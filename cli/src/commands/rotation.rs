//! The rotating send shared by `safe send --rotate` and `safe rotate`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use alloy::network::primitives::ReceiptResponse;
use alloy::primitives::utils::format_ether;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::encoding::compute_domain_separator;
use safe_rs::rotation::{
    ExecOptions, Keyring, OwnerRef, RotatingSafe, RotationConfig, RotationStatus,
};
use safe_rs::{
    broadcast_raw, detect_addresses, wait_for_receipt, BroadcastOutcome, Call, ChainAddresses,
    Error, ReceiptWait, SpecId,
};
use url::Url;

use crate::bundle::{BundleFile, BundleRotationSwap};
use crate::cli::{SimArgs, SweepArgs};
use crate::commands::{http_provider, latest_sim_spec, outer_fees};
use crate::keys::CliKeys;
use crate::output::{
    confirm_prompt, emit, rotation_summary, ApproveHashOutput, BundleSavedOutput, Console, Output,
    Report, RotationOutput, RotationPlanOutput, SendOutcome, SignedTxOutput, SimulationOutput,
};

/// How often to poll for a receipt after broadcasting.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Everything one rotating transaction needs.
pub struct RotationRun<'a> {
    pub rpc_url: &'a Url,
    pub safe: Address,
    /// The wallet's keys and their locked state
    pub ring: Keyring<CliKeys>,
    /// Key of a current owner the wallet cannot derive (`safe rotate --from-*`)
    pub legacy_owner: Option<PrivateKeySigner>,
    /// `--sweep-legacy`: the legacy key's whole balance may move without a prompt
    pub sweep_legacy: bool,
    pub payer: Option<PrivateKeySigner>,
    pub sweep: &'a SweepArgs,
    /// The user's calls; empty for a rotation-only transaction
    pub calls: Vec<Call>,
    pub multi_send_call_only: Option<Address>,
    pub sim: &'a SimArgs,
    pub gas_limit: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub timeout: u64,
    pub trace: bool,
    pub simulate_only: bool,
    pub raw_out: Option<String>,
    pub no_submit: bool,
    pub no_confirm: bool,
    pub bundle: Option<PathBuf>,
    pub merge_bundle: Vec<PathBuf>,
    pub approve_hash: bool,
    pub sign_only: bool,
    pub output: Output,
}

/// The configuration shared by every command that opens a rotating Safe.
pub fn rotation_config(
    multi_send_call_only: Option<Address>,
    spec: SpecId,
    block_time: u64,
    timeout: u64,
) -> RotationConfig {
    let mut addresses = ChainAddresses::v1_4_1();
    if let Some(address) = multi_send_call_only {
        addresses.multi_send_call_only = address;
    }
    RotationConfig {
        addresses,
        spec,
        block_time,
        timeout: Duration::from_secs(timeout),
        poll_interval: RECEIPT_POLL_INTERVAL,
        ..RotationConfig::default()
    }
}

/// Prints warnings the library collected (to stderr, so JSON output stays clean).
pub fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}

/// The `--simulate-only` report: the simulation plus the owner swap it
/// includes, so JSON consumers see everything the transaction would do.
#[derive(serde::Serialize)]
struct RotationSimulation {
    #[serde(flatten)]
    simulation: SimulationOutput,
    rotation: RotationPlanOutput,
}

impl Report for RotationSimulation {
    fn human(&self) -> String {
        self.simulation.human()
    }
}

pub async fn run(run: RotationRun<'_>) -> Result<SendOutcome> {
    let output = run.output;
    let json = output == Output::Json;
    let prompts = !run.no_confirm && output.prompts() && !run.no_submit;
    if run.legacy_owner.is_some() && !run.sweep.no_sweep && !run.sweep_legacy && !prompts {
        bail!(
            "moving a Safe onto the HD wallet also moves the whole ETH balance of the \
             --from-* key to the new owner. Without a prompt to show the amount, pass \
             --sweep-legacy to allow it or --no-sweep to leave the ETH where it is"
        );
    }
    if run.sim.block.is_some() {
        bail!(
            "--block cannot be combined with owner rotation, which always runs at the latest block"
        );
    }

    // `--no-submit` without a destination writes the signed transaction to
    // stdout, unless the caller prints its own output.
    let raw_out = run
        .raw_out
        .clone()
        .or_else(|| (run.no_submit && output != Output::Quiet).then(|| "-".to_string()));
    let console = Console::for_output(output, raw_out.as_deref() == Some("-"));

    let provider = http_provider(run.rpc_url);
    // Unless overridden, batches go through the MultiSendCallOnly of the
    // Safe's own version.
    let multi_send_call_only = match run.multi_send_call_only {
        Some(address) => address,
        None => {
            detect_addresses(&provider, run.safe)
                .await
                .multi_send_call_only
        }
    };
    let chain_id = provider.get_chain_id().await?;
    let spec = latest_sim_spec(&provider, chain_id, run.sim.spec, run.sim.block_time).await?;
    let mut config = rotation_config(
        Some(multi_send_call_only),
        spec,
        run.sim.block_time,
        run.timeout,
    );
    let on_device = run.ring.keys().is_device();
    config.payer = run.payer;
    config.sweep = !run.sweep.no_sweep;
    config.sweep_reserve = run.sweep.sweep_reserve;
    let onboarding = run.legacy_owner.is_some();
    config.legacy_owner = run.legacy_owner;

    let mut rotating =
        RotatingSafe::with_keyring(provider.clone(), run.safe, run.ring, config).await?;
    print_warnings(&rotating.take_warnings());
    if let (true, OwnerRef::Derived { index, .. }) = (onboarding, rotating.binding()?.current) {
        bail!(
            "Safe {} is already owned by wallet key {index}; drop the --from-* option",
            run.safe
        );
    }

    // ETH still owed to the current owner from an earlier rotation: move it
    // first, since it is what pays for this transaction.
    let sweep_owed = !rotating.binding()?.sweep_due.is_empty();
    if sweep_owed && !run.sweep.no_sweep && !run.simulate_only {
        let report = rotating.sweep_all().await?;
        for sweep in &report.swept {
            console.line(format!(
                "Swept {} ETH owed from {} to {} (tx {})\n",
                format_ether(sweep.amount),
                sweep.from,
                sweep.to,
                sweep.tx_hash
            ));
        }
        for (from, error) in &report.failed {
            eprintln!("warning: a sweep from {from} is still owed: {error}");
        }
    }

    let bundle_existed = run.bundle.as_ref().is_some_and(|p| p.exists());
    let mut bundle = if let Some(bundle_path) = &run.bundle {
        if bundle_path.exists() {
            BundleFile::load(bundle_path)?
        } else {
            BundleFile::from_calls(&run.calls)
        }
    } else {
        BundleFile::from_calls(&run.calls)
    };
    for merge_path in &run.merge_bundle {
        let other = BundleFile::load(merge_path)?;
        bundle.merge_from_file(&other)?;
    }

    let extra_swaps: Vec<(Address, Address)> = bundle
        .rotations
        .iter()
        .map(|s| (s.old_owner, s.new_owner))
        .collect();

    let fees = outer_fees(&provider, run.max_fee_per_gas, run.max_priority_fee_per_gas).await?;
    let options = ExecOptions {
        fees: Some(fees),
        gas_limit: run.gas_limit,
        co_signatures: bundle.signatures.clone(),
        extra_swaps,
        approve_hash: run.approve_hash,
    };
    if on_device {
        // The device shows the Safe signature as two hashes; the domain one is
        // known now.
        console.line(format!(
            "Confirm each signature on the Ledger: the Safe transaction (EIP-712; domain hash \
             {}), then the transaction that submits it, then the transfer of the old key's ETH.",
            compute_domain_separator(rotating.chain_id(), run.safe)
        ));
    }
    let tx = match rotating.prepare(&run.calls, options).await {
        Ok(tx) => tx,
        Err(Error::SimulationReverted { reason }) => {
            print_warnings(&rotating.take_warnings());
            let report = SimulationOutput {
                success: false,
                gas_used: 0,
                revert_reason: Some(reason.clone()),
                safe_tx_hash: None,
                traces: None,
                ..Default::default()
            };
            emit(&report, output, console);
            bail!("simulation failed: {reason}");
        }
        Err(e @ Error::MultiSendNotDeployed(_)) => {
            print_warnings(&rotating.take_warnings());
            bail!("{e}; pass the address it has on this chain with --multi-send-call-only");
        }
        Err(e) => return Err(eyre!(e)),
    };
    print_warnings(&rotating.take_warnings());

    let sweep_enabled = !run.sweep.no_sweep;
    console.line(rotation_summary(&tx, &run.calls, sweep_enabled));
    console.line("");
    let have = tx.signatures_collected;
    let need = tx.threshold;
    let simulation = SimulationOutput {
        success: true,
        gas_used: tx.simulation.gas_used,
        revert_reason: None,
        safe_tx_hash: Some(tx.plan.prepared.safe_tx_hash),
        traces: run.trace.then(|| tx.simulation.format_traces()).flatten(),
        signatures_collected: Some(have),
        threshold: Some(need),
        ready_to_execute: Some(have >= need),
    };
    if run.simulate_only {
        let report = RotationSimulation {
            simulation,
            rotation: RotationPlanOutput::new(&tx),
        };
        emit(&report, output, console);
        return Ok(SendOutcome::Simulated {
            safe_tx_hash: tx.plan.prepared.safe_tx_hash,
            gas_used: tx.simulation.gas_used,
        });
    }
    console.line(simulation.human());
    console.line("");

    let mut new_sigs = BTreeMap::new();
    for (&owner_addr, sig) in &tx.signed.signatures {
        if !(sig.len() == 65 && sig[64] == 1) {
            new_sigs.insert(owner_addr, sig.clone());
        }
    }
    let swap_entry = BundleRotationSwap {
        old_owner: tx.from.address(),
        new_owner: tx.to.address,
        new_owner_index: Some(tx.to.index),
    };

    // Branch A: --approve-hash
    if run.approve_hash {
        let bundle_path_str = if let Some(bundle_path) = &run.bundle {
            bundle.merge(
                &tx.plan.prepared,
                &new_sigs,
                std::slice::from_ref(&swap_entry),
            )?;
            bundle.save(bundle_path)?;
            Some(bundle_path.display().to_string())
        } else {
            None
        };
        let prompt =
            format!("Approve Safe transaction hash on-chain ({have}/{need} toward threshold)?");
        if prompts && !confirm_prompt(&prompt) {
            console.line("Aborted");
            return Ok(SendOutcome::Aborted {
                safe_tx_hash: tx.plan.prepared.safe_tx_hash,
            });
        }
        rotating.arm_signed_only(&tx)?;
        match broadcast_raw(&provider, &tx.outer.raw, tx.outer.tx_hash).await {
            BroadcastOutcome::Accepted(_) => {}
            BroadcastOutcome::AlreadyKnown(_) => console.line("Node already knew the transaction"),
            BroadcastOutcome::Rejected { reason, class } => {
                bail!("node rejected {}: {reason} ({class:?})", tx.outer.tx_hash)
            }
            BroadcastOutcome::Ambiguous { reason } => bail!(
                "broadcast of {} is ambiguous and it may still be pending: {reason}",
                tx.outer.tx_hash
            ),
        }
        console.line(format!("Sent {}, waiting for receipt...", tx.outer.tx_hash));
        let timeout = Duration::from_secs(run.timeout);
        let receipt =
            match wait_for_receipt(&provider, tx.outer.tx_hash, timeout, RECEIPT_POLL_INTERVAL)
                .await?
            {
                ReceiptWait::Mined(receipt) => receipt,
                ReceiptWait::TimedOut { tx_hash } => bail!(
                    "no receipt for {tx_hash} after {}s; it may still be pending",
                    run.timeout
                ),
            };
        let success = receipt.status();
        emit(
            &ApproveHashOutput {
                tx_hash: tx.outer.tx_hash,
                success,
                gas_used: receipt.gas_used,
                safe_tx_hash: tx.plan.prepared.safe_tx_hash,
                safe_nonce: tx.plan.prepared.params.nonce,
                approver: tx.from.address(),
                signatures_collected: have,
                threshold: need,
                bundle_path: bundle_path_str,
            },
            output,
            console,
        );
        if !success {
            bail!("approveHash transaction reverted");
        }
        return Ok(SendOutcome::HashApproved {
            tx_hash: tx.outer.tx_hash,
            safe_tx_hash: tx.plan.prepared.safe_tx_hash,
            gas_used: receipt.gas_used,
            block: receipt.block_number(),
        });
    }

    // Branch B: Offchain signature collection (`have < need` or `--sign-only`)
    if have < need || run.sign_only {
        let Some(bundle_path) = &run.bundle else {
            bail!(
                "Safe threshold is {need} (have {have}/{need} signatures). Pass --bundle <FILE> to save and collect signatures offchain, or --approve-hash to approve on-chain"
            );
        };
        rotating.arm_signed_only(&tx)?;
        bundle.merge(
            &tx.plan.prepared,
            &new_sigs,
            std::slice::from_ref(&swap_entry),
        )?;
        bundle.save(bundle_path)?;
        let signers: Vec<Address> = tx.signed.signatures.keys().copied().collect();
        let remaining_owners: Vec<Address> = tx
            .owners
            .iter()
            .copied()
            .filter(|o| !tx.signed.signatures.contains_key(o))
            .collect();
        emit(
            &BundleSavedOutput {
                safe_tx_hash: tx.plan.prepared.safe_tx_hash,
                safe_nonce: tx.plan.prepared.params.nonce,
                signatures_collected: have,
                threshold: need,
                signers,
                remaining_owners,
                bundle_path: bundle_path.display().to_string(),
            },
            output,
            console,
        );
        return Ok(SendOutcome::Signed {
            safe_tx_hash: tx.plan.prepared.safe_tx_hash,
            safe_nonce: tx.plan.prepared.params.nonce,
            signatures: have,
            threshold: need,
            bundle: bundle_path.clone(),
        });
    }

    // Branch C: Threshold met (`have >= need`) -> Execute `execTransaction`
    if !run.no_submit {
        if let Some(bundle_path) = &run.bundle {
            if !bundle_existed || bundle.tx.is_some() {
                bundle.merge(&tx.plan.prepared, &new_sigs, &[swap_entry])?;
                bundle.save(bundle_path)?;
            }
        }
    }

    if onboarding && sweep_enabled {
        let balance = provider.get_balance(tx.from.address()).await?;
        console.line(format!(
            "The --from-* key {} holds {} ETH. All of it moves to the new owner {} after the rotation.",
            tx.from.address(),
            format_ether(balance),
            tx.to.address
        ));
    }
    if prompts && !confirm_prompt("Execute transaction and rotate the owner key?") {
        console.line("Aborted");
        return Ok(SendOutcome::Aborted {
            safe_tx_hash: tx.plan.prepared.safe_tx_hash,
        });
    }

    // From here on the owner's signature may leave this process: record that
    // before writing or sending anything.
    rotating.arm(&tx)?;
    let plan = RotationPlanOutput::new(&tx);
    let document = SignedTxOutput::for_rotation(&tx);
    if let Some(dest) = &raw_out {
        document
            .write_to(dest)
            .map_err(|e| eyre!("cannot write {dest}: {e}"))?;
        if dest != "-" {
            console.line(format!("Signed transaction written to {dest}"));
        }
    }
    if run.no_submit {
        if json && raw_out.as_deref() != Some("-") {
            document.print(true);
        } else if output == Output::Human {
            console.line(document.human());
        }
        console.line(format!(
            "Not broadcast. Key {} is now recorded as used: once this transaction is mined, \
             the next safe command finishes the rotation and the sweep.",
            plan.old_owner
        ));
        return Ok(SendOutcome::NotSubmitted {
            tx_hash: tx.outer.tx_hash,
            safe_tx_hash: tx.plan.prepared.safe_tx_hash,
            raw: tx.outer.raw.clone(),
        });
    }

    console.line(format!(
        "Sending {}, waiting for receipt...",
        tx.outer.tx_hash
    ));
    let outcome = match rotating.submit(tx).await {
        Ok(outcome) => outcome,
        Err(Error::Unconfirmed { tx_hash, reason }) => bail!(
            "transaction {tx_hash} is not confirmed: {reason}\n\
             Its signature is public, so key {} counts as used. Run `safe rotate` \
             (or any rotating command) to pick up where this left off.",
            plan.old_owner
        ),
        Err(e) => return Err(eyre!(e)),
    };

    let owner = rotating.binding()?.current.into();
    let warnings = rotating.take_warnings();
    let status = outcome.status;
    let executed = SendOutcome::Executed {
        tx_hash: outcome.tx_hash,
        safe_tx_hash: outcome.safe_tx_hash,
        gas_used: outcome.gas_used,
        block: None,
    };
    emit(
        &RotationOutput::new(plan, &outcome, owner, warnings),
        output,
        console,
    );
    match status {
        RotationStatus::Rotated => Ok(executed),
        RotationStatus::RotatedElsewhere => bail!(
            "the owner was rotated, but by another transaction carrying the same signed \
             Safe transaction; this one reverted"
        ),
        RotationStatus::NotRotated => bail!(
            "the transaction reverted and the owner was NOT rotated. Its signature is \
             public and the signed calls stay executable until the Safe nonce is used: \
             run `safe rotate` now to retire {}. If its ETH was swept with this transaction \
             (see the warnings), fund it first or pass --payer-private-key",
            plan.old_owner
        ),
    }
}
