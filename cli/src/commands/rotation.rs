//! The rotating send shared by `safe send --rotate` and `safe rotate`.

use std::time::Duration;

use alloy::primitives::utils::format_ether;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::encoding::compute_domain_separator;
use safe_rs::rotation::{
    ExecOptions, Keyring, OwnerRef, RotatingSafe, RotationConfig, RotationStatus,
};
use safe_rs::{detect_addresses, Call, ChainAddresses, Error, SpecId};
use url::Url;

use crate::cli::{SimArgs, SweepArgs};
use crate::commands::{http_provider, outer_fees};
use crate::keys::CliKeys;
use crate::output::{
    confirm_prompt, rotation_summary, Console, Report, RotationOutput, RotationPlanOutput,
    SignedTxOutput, SimulationOutput,
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
    pub json: bool,
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

fn emit(report: &impl Report, json: bool, console: Console) {
    if json {
        report.print(true);
    } else {
        console.line(report.human());
    }
}

pub async fn run(run: RotationRun<'_>) -> Result<()> {
    let prompts = !run.no_confirm && !run.json && !run.no_submit;
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

    let raw_out = run
        .raw_out
        .clone()
        .or_else(|| run.no_submit.then(|| "-".to_string()));
    let console = Console::new(run.json, raw_out.as_deref() == Some("-"));

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
    let mut config = rotation_config(
        Some(multi_send_call_only),
        SpecId::from(run.sim.spec),
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

    let fees = outer_fees(&provider, run.max_fee_per_gas, run.max_priority_fee_per_gas).await?;
    let options = ExecOptions {
        fees: Some(fees),
        gas_limit: run.gas_limit,
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
            };
            emit(&report, run.json, console);
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
    let simulation = SimulationOutput {
        success: true,
        gas_used: tx.simulation.gas_used,
        revert_reason: None,
        safe_tx_hash: Some(tx.plan.prepared.safe_tx_hash),
        traces: run.trace.then(|| tx.simulation.format_traces()).flatten(),
    };
    if run.simulate_only {
        let report = RotationSimulation {
            simulation,
            rotation: RotationPlanOutput::new(&tx),
        };
        emit(&report, run.json, console);
        return Ok(());
    }
    console.line(simulation.human());
    console.line("");

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
        return Ok(());
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
        if run.json && raw_out.as_deref() != Some("-") {
            document.print(true);
        } else {
            console.line(document.human());
        }
        console.line(format!(
            "Not broadcast. Key {} is now recorded as used: once this transaction is mined, \
             the next safe command finishes the rotation and the sweep.",
            plan.old_owner
        ));
        return Ok(());
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
    emit(
        &RotationOutput::new(plan, &outcome, owner, warnings),
        run.json,
        console,
    );
    match status {
        RotationStatus::Rotated => Ok(()),
        RotationStatus::RotatedElsewhere => bail!(
            "the owner was rotated, but by another transaction carrying the same signed \
             Safe transaction; this one reverted"
        ),
        RotationStatus::NotRotated => bail!(
            "the transaction reverted and the owner was NOT rotated. Its signature is \
             public and the signed calls stay executable until the Safe nonce is used: \
             run `safe rotate` now to retire {}",
            plan.old_owner
        ),
    }
}
