//! The rotating send of `safe send --rotate`.

use std::collections::BTreeMap;
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::primitives::utils::format_ether;
use alloy::primitives::Address;
use alloy::providers::Provider;
use safe_rs::encoding::compute_domain_separator;
use safe_rs::rotation::{ExecOptions, Keyring, RotatingSafe, RotationConfig, RotationStatus};
use safe_rs::{
    detect_addresses, read_safe_state, Call, ChainAddresses, Error, ReadSafeStateOptions, SpecId,
};
use url::Url;

use crate::any_signer::AnySigner;
use crate::bundle::{is_pre_validated, BundleFile, BundleRotationSwap};
use crate::cli::SendOpts;
use crate::commands::send::{
    approve_hash_outcome, broadcast_and_wait, bundle_saved, resolve_raw_out, write_signed, Tally,
};
use crate::commands::{http_provider, latest_sim_spec, outer_fees, RECEIPT_POLL_INTERVAL};
use crate::console::Console;
use crate::error::SendError;
use crate::keys::CliKeys;
use crate::output::{
    rotation_summary, Report, RotationOutput, RotationPlanOutput, SendOutcome, SignedTxOutput,
    SimulationOutput,
};
use crate::policy::{self, Plan, SafeSnapshot, SafeTxCheck};

/// Everything one rotating transaction needs.
pub struct RotationRun<'a> {
    pub rpc_url: &'a Url,
    pub safe: Address,
    /// The wallet's keys and their locked state
    pub ring: Keyring<CliKeys>,
    /// The gas payer (`--gas-payer-*`), if not the current owner
    pub payer: Option<AnySigner>,
    /// The user's calls; empty for a rotation-only transaction
    pub calls: Vec<Call>,
    /// The `send` options; `calls` already holds the bundle's
    pub opts: &'a SendOpts,
    pub console: &'a Console,
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

pub async fn run(run: RotationRun<'_>) -> Result<SendOutcome, SendError> {
    let console = run.console;
    let opts = run.opts;
    let sim = &opts.simulate.sim;
    let collect = &opts.collect;
    let no_submit = opts.raw.no_submit;
    // `run` sets `no_confirm` for `--json`, so this is false whenever no one
    // will be asked.
    let prompts = !opts.no_confirm && !no_submit;
    if sim.block.is_some() {
        return Err(SendError::other(
            "--block cannot be combined with owner rotation, which always runs at the latest block",
        ));
    }

    let raw_out = resolve_raw_out(&opts.raw, console);

    let provider = http_provider(run.rpc_url);
    // Unless overridden, batches go through the MultiSendCallOnly of the
    // Safe's own version.
    let multi_send_call_only = match opts.multi_send_call_only {
        Some(address) => address,
        None => {
            detect_addresses(&provider, run.safe)
                .await
                .multi_send_call_only
        }
    };
    let chain_id = provider.get_chain_id().await?;
    let spec = latest_sim_spec(&provider, chain_id, sim.spec, sim.block_time).await?;
    let mut config = rotation_config(
        Some(multi_send_call_only),
        spec,
        sim.block_time,
        opts.fees.timeout,
    );
    let on_device = run.ring.keys().is_device();
    config.payer = run
        .payer
        .map(|payer| std::sync::Arc::new(payer) as safe_rs::rotation::Payer);
    config.sweep = !opts.sweep.no_sweep;
    config.sweep_reserve = opts.sweep.sweep_reserve;

    let mut rotating =
        RotatingSafe::with_keyring(provider.clone(), run.safe, run.ring, config).await?;
    console.warnings(&rotating.take_warnings());

    // ETH still owed to the current owner from an earlier rotation: move it
    // first, since it is what pays for this transaction.
    let sweep_owed = !rotating.binding()?.sweep_due.is_empty();
    if sweep_owed && !opts.sweep.no_sweep && !opts.simulate.simulate_only {
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
            console.warn(format!("a sweep from {from} is still owed: {error}"));
        }
    }

    let bundle_existed = collect.bundle.as_ref().is_some_and(|p| p.exists());
    let mut bundle = if let Some(bundle_path) = &collect.bundle {
        if bundle_path.exists() {
            BundleFile::load(bundle_path)?
        } else {
            BundleFile::from_calls(&run.calls)
        }
    } else {
        BundleFile::from_calls(&run.calls)
    };
    for merge_path in &collect.merge_bundle {
        let other = BundleFile::load(merge_path)?;
        bundle.merge_from_file(&other)?;
    }

    let extra_swaps: Vec<(Address, Address)> = bundle
        .rotations
        .iter()
        .map(|s| (s.old_owner, s.new_owner))
        .collect();

    let fees = outer_fees(
        &provider,
        opts.fees.max_fee_per_gas,
        opts.fees.max_priority_fee_per_gas,
    )
    .await?;
    let options = ExecOptions {
        fees: Some(fees),
        gas_limit: opts.fees.gas_limit,
        co_signatures: bundle.signatures.clone(),
        extra_swaps,
        approve_hash: collect.approve_hash,
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
            console.warnings(&rotating.take_warnings());
            let report = SimulationOutput {
                success: false,
                gas_used: 0,
                revert_reason: Some(reason.clone()),
                safe_tx_hash: None,
                traces: None,
                ..Default::default()
            };
            console.emit(&report);
            return Err(SendError::SimulationFailed { reason });
        }
        Err(e @ Error::MultiSendNotDeployed(_)) => {
            console.warnings(&rotating.take_warnings());
            return Err(SendError::other(format!(
                "{e}; pass the address it has on this chain with --multi-send-call-only"
            )));
        }
        Err(e) => return Err(e.into()),
    };
    console.warnings(&rotating.take_warnings());

    if let Some(policy) = console.policy() {
        let before = read_safe_state(
            &provider,
            run.safe,
            BlockId::latest(),
            ReadSafeStateOptions::default(),
        )
        .await?;
        let after = SafeSnapshot::new(
            run.safe,
            tx.plan.expected_owners.clone(),
            tx.plan.threshold,
            before.singleton,
        );
        let check = SafeTxCheck {
            rpc_url: run.rpc_url,
            chain_id,
            plan: Plan::Rotation(&tx.plan),
            calls: &run.calls,
            prepared: &tx.plan.prepared,
            before: &before,
            after: Some(&after),
        };
        policy::enforce(policy.as_ref(), &check).await?;
    }

    let plan = RotationPlanOutput::new(&tx);
    let sweep_enabled = !opts.sweep.no_sweep;
    let details = rotation_summary(&tx, &plan, &run.calls, sweep_enabled);
    console.line(&details);
    console.line("");
    let have = tx.signatures_collected;
    let need = tx.threshold;
    let simulation = SimulationOutput {
        success: true,
        gas_used: tx.simulation.gas_used,
        revert_reason: None,
        safe_tx_hash: Some(tx.plan.prepared.safe_tx_hash),
        traces: opts
            .simulate
            .trace
            .then(|| tx.simulation.format_traces())
            .flatten(),
        signatures_collected: Some(have),
        threshold: Some(need),
        ready_to_execute: Some(have >= need),
    };
    if opts.simulate.simulate_only {
        let report = RotationSimulation {
            simulation,
            rotation: plan,
        };
        console.emit(&report);
        return Ok(SendOutcome::Simulated {
            safe_tx_hash: tx.plan.prepared.safe_tx_hash,
            gas_used: tx.simulation.gas_used,
        });
    }
    console.line(simulation.human());
    console.line("");

    let new_sigs: BTreeMap<_, _> = tx
        .signed
        .signatures
        .iter()
        .filter(|(_, sig)| !is_pre_validated(sig))
        .map(|(&owner, sig)| (owner, sig.clone()))
        .collect();
    let swap_entry = [BundleRotationSwap {
        old_owner: tx.from.address(),
        new_owner: tx.to.address,
        new_owner_index: Some(tx.to.index),
    }];
    let tally = Tally {
        prepared: &tx.plan.prepared,
        have,
        need,
    };

    // Branch A: --approve-hash
    if collect.approve_hash {
        if let Some(bundle_path) = &collect.bundle {
            bundle.merge_and_save(bundle_path, &tx.plan.prepared, &new_sigs, &swap_entry)?;
        }
        let prompt =
            format!("Approve Safe transaction hash on-chain ({have}/{need} toward threshold)?");
        if prompts && !console.confirm(&prompt, &details) {
            console.line("Aborted");
            return Ok(SendOutcome::Aborted {
                safe_tx_hash: tx.plan.prepared.safe_tx_hash,
            });
        }
        rotating.arm_signed_only(&tx)?;
        let receipt = broadcast_and_wait(&provider, &tx.outer, opts.fees.timeout, console).await?;
        return approve_hash_outcome(
            &tally,
            tx.outer.tx_hash,
            &receipt,
            tx.from.address(),
            collect.bundle.as_deref(),
            console,
        );
    }

    // Branch B: Offchain signature collection (`have < need` or `--sign-only`)
    if have < need || collect.sign_only {
        let Some(bundle_path) = &collect.bundle else {
            return Err(SendError::BelowThreshold { have, need });
        };
        rotating.arm_signed_only(&tx)?;
        bundle.merge_and_save(bundle_path, &tx.plan.prepared, &new_sigs, &swap_entry)?;
        return Ok(bundle_saved(
            &tally,
            &tx.signed.signatures,
            &tx.owners,
            bundle_path,
            console,
        ));
    }

    // Branch C: Threshold met (`have >= need`) -> Execute `execTransaction`
    if !no_submit {
        if let Some(bundle_path) = &collect.bundle {
            if !bundle_existed || bundle.tx.is_some() {
                bundle.merge_and_save(bundle_path, &tx.plan.prepared, &new_sigs, &swap_entry)?;
            }
        }
    }

    if prompts && !console.confirm("Execute transaction and rotate the owner key?", &details) {
        console.line("Aborted");
        return Ok(SendOutcome::Aborted {
            safe_tx_hash: tx.plan.prepared.safe_tx_hash,
        });
    }

    // From here on the owner's signature may leave this process: record that
    // before writing or sending anything.
    rotating.arm(&tx)?;
    let document = SignedTxOutput::for_rotation(&tx, plan);
    write_signed(&document, raw_out.as_deref(), no_submit, console)?;
    if no_submit {
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
        Err(Error::Unconfirmed { tx_hash, reason }) => {
            return Err(SendError::RotationUnconfirmed {
                tx_hash,
                reason,
                old_owner: plan.old_owner.address,
                old_owner_index: plan.old_owner.index,
            })
        }
        Err(e) => return Err(e.into()),
    };

    let owner = rotating.binding()?.current.into();
    let warnings = rotating.take_warnings();
    let status = outcome.status;
    let executed_tx = outcome.tx_hash;
    let old_owner = plan.old_owner;
    let executed = SendOutcome::Executed {
        tx_hash: outcome.tx_hash,
        safe_tx_hash: outcome.safe_tx_hash,
        gas_used: outcome.gas_used,
        block: None,
    };
    console.emit(&RotationOutput::new(plan, &outcome, owner, warnings));
    match status {
        RotationStatus::Rotated => Ok(executed),
        RotationStatus::RotatedElsewhere => Err(SendError::RotatedElsewhere {
            tx_hash: executed_tx,
        }),
        RotationStatus::NotRotated => Err(SendError::NotRotated {
            tx_hash: executed_tx,
            old_owner: old_owner.address,
            old_owner_index: old_owner.index,
        }),
    }
}
