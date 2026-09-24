use std::time::Duration;

use alloy::eips::eip1559::Eip1559Estimation;
use alloy::network::{AnyNetwork, Network, TransactionBuilder};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::{
    broadcast_raw, is_gs013_revert, safe_outcome_for_receipt, sign_outer_tx, wait_for_receipt,
    Account, BroadcastOutcome, Call, CallBuilder, ChainAddresses, ChainConfig, OuterTxParams,
    ReceiptWait, Safe, SignedSafeTx, SimTx, SimulationResult, TxChecks,
};

use crate::bundle::load_bundle;
use crate::cli::SendArgs;
use crate::commands::{fork_session, http_provider, max_tx_gas, HttpProvider};
use crate::output::{
    calls_summary, confirm_prompt, Console, ExecutionOutput, Report, SignedTxOutput,
    SimulationOutput,
};
use crate::sig_parser::{encode_function_call, parse_call_spec};
use crate::wallet::create_signer;

/// How often to poll for the receipt after broadcasting.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Prints a result as JSON on stdout, or as text through the console.
fn emit(report: &impl Report, json: bool, console: Console) {
    if json {
        report.print(true);
    } else {
        console.line(report.human());
    }
}

pub async fn run(args: SendArgs, json: bool) -> Result<()> {
    let calls = build_calls(&args)?;
    if calls.is_empty() {
        return Err(eyre!("No calls specified"));
    }

    // `--no-submit` without a destination writes the signed transaction to stdout.
    let raw_out = args
        .raw_out
        .clone()
        .or_else(|| args.no_submit.then(|| "-".to_string()));
    let console = Console::new(json, raw_out.as_deref() == Some("-"));

    let signer = create_signer(&args.wallet)?;
    let from = signer.address();
    let provider = http_provider(&args.rpc.rpc_url);
    let chain_id = provider.get_chain_id().await?;
    let safe_address = args.safe.safe;
    let config = ChainConfig::with_addresses(chain_id, chain_addresses(&args));
    let safe = Safe::new(provider.clone(), signer.clone(), safe_address, config);

    // Verify ownership
    safe.verify_single_owner().await?;

    // Freeze the Safe transaction: everything below simulates, signs and submits
    // exactly this transaction.
    let mut builder = calls
        .iter()
        .cloned()
        .fold(safe.batch(), |b, call| b.add(call));
    if args.call_only {
        builder = builder.call_only();
    }
    if let Some(nonce) = args.nonce {
        builder = builder.with_nonce(nonce);
    }
    if let Some(gas) = args.safe_tx_gas {
        builder = builder.with_safe_tx_gas(gas);
    }
    let prepared = builder.prepare().await?;
    let signed = prepared.sign(&signer).await?;

    console.line(format!("Safe: {}", safe_address));
    console.line(format!("Signer: {}", from));
    console.line(format!("Nonce: {}", prepared.params.nonce));
    console.line(format!("Safe Tx Hash: {}", prepared.safe_tx_hash));
    console.line("");
    console.line(calls_summary(&calls));
    console.line("");

    let fees = outer_fees(&provider, &args).await?;
    let (eoa_nonce, gas_limit) = if args.skip_simulation {
        console.line("Skipping simulation (--skip-simulation)\n");
        let nonce = provider.get_transaction_count(from).await?;
        let gas_limit = match args.gas_limit {
            Some(gas) => gas,
            None => estimate_outer_gas(&provider, &signed, from).await?,
        };
        (nonce, gas_limit)
    } else {
        let simulated = simulate(&provider, chain_id, &args, &signed, from, fees).await?;
        let result = &simulated.result;
        let report = SimulationOutput {
            success: result.success,
            gas_used: result.gas_used,
            revert_reason: result.revert_reason.clone(),
            safe_tx_hash: Some(prepared.safe_tx_hash),
            traces: args.trace.then(|| result.format_traces()).flatten(),
        };
        if args.simulate_only || !result.success {
            emit(&report, json, console);
        } else {
            console.line(report.human());
            console.line("");
        }
        if !result.success {
            bail!(
                "simulation failed: {}",
                result.revert_reason.as_deref().unwrap_or("unknown reason")
            );
        }
        if args.simulate_only {
            return Ok(());
        }
        (simulated.eoa_nonce, simulated.gas_limit)
    };

    let outer = sign_outer_tx(
        &signer,
        OuterTxParams::exec_transaction(&signed, from, eoa_nonce, gas_limit, fees),
    )
    .await?;

    // Persist the exact bytes before the first broadcast so they can be
    // rebroadcast or reconciled if the outcome is unclear.
    let document = SignedTxOutput::new(&signed, &outer);
    if let Some(dest) = &raw_out {
        document
            .write_to(dest)
            .map_err(|e| eyre!("cannot write {dest}: {e}"))?;
        if dest != "-" {
            console.line(format!("Signed transaction written to {dest}"));
        }
    }

    if args.no_submit {
        if json && raw_out.as_deref() != Some("-") {
            document.print(true);
        } else {
            console.line(document.human());
        }
        return Ok(());
    }

    let prompt = if args.skip_simulation {
        "Execute transaction without simulation?"
    } else {
        "Execute transaction?"
    };
    if !args.no_confirm && !json && !confirm_prompt(prompt) {
        console.line("Aborted");
        return Ok(());
    }

    match broadcast_raw(&provider, &outer.raw, outer.tx_hash).await {
        BroadcastOutcome::Accepted(_) => {}
        BroadcastOutcome::AlreadyKnown(_) => console.line("Node already knew the transaction"),
        BroadcastOutcome::Rejected { reason, class } => {
            bail!("node rejected {}: {reason} ({class:?})", outer.tx_hash)
        }
        BroadcastOutcome::Ambiguous { reason } => bail!(
            "broadcast of {} is ambiguous and it may still be pending: {reason}",
            outer.tx_hash
        ),
    }
    console.line(format!("Sent {}, waiting for receipt...", outer.tx_hash));

    let timeout = Duration::from_secs(args.timeout);
    let receipt =
        match wait_for_receipt(&provider, outer.tx_hash, timeout, RECEIPT_POLL_INTERVAL).await? {
            ReceiptWait::Mined(receipt) => receipt,
            ReceiptWait::TimedOut { tx_hash } => bail!(
                "no receipt for {tx_hash} after {}s; it may still be pending",
                args.timeout
            ),
        };
    let outcome = safe_outcome_for_receipt(&receipt, safe_address, prepared.safe_tx_hash)?;

    emit(
        &ExecutionOutput {
            tx_hash: outer.tx_hash,
            success: outcome.is_success(),
            gas_used: receipt.gas_used,
            safe_tx_hash: Some(prepared.safe_tx_hash),
            outcome: Some(outcome.label()),
        },
        json,
        console,
    );
    if !outcome.is_success() {
        bail!("Safe transaction did not succeed ({})", outcome.label());
    }

    Ok(())
}

/// The strict simulation of the outer transaction that would be signed.
struct Simulated {
    result: SimulationResult,
    eoa_nonce: u64,
    gas_limit: u64,
}

/// Simulates the exact outer `execTransaction` the CLI would sign, in the block
/// after `--block`, with all validity checks (nonce, fees, balance).
///
/// Without `--gas-limit`, gas is first measured at the largest allowed limit
/// (without requiring the sender to afford it) and the limit is that plus 20%.
///
/// Calls are always traced so that a `GS013` failure reports the inner revert
/// reason; the traces are only printed with `--trace`.
async fn simulate(
    provider: &HttpProvider,
    chain_id: u64,
    args: &SendArgs,
    signed: &SignedSafeTx,
    from: Address,
    fees: Eip1559Estimation,
) -> Result<Simulated> {
    let mut session = fork_session(provider.clone(), chain_id, &args.sim, true).await?;
    let eoa_nonce = session.nonce(from)?;
    let outer =
        |gas_limit| OuterTxParams::exec_transaction(signed, from, eoa_nonce, gas_limit, fees);

    let gas_limit = if let Some(gas) = args.gas_limit {
        gas
    } else {
        let max = max_tx_gas(&session);
        let measured = session.transact(SimTx::from_outer(&outer(max), TxChecks::MEASURE))?;
        if !measured.success {
            return Ok(Simulated {
                result: measured,
                eoa_nonce,
                gas_limit: max,
            });
        }
        (measured.gas_used + measured.gas_used / 5).min(max)
    };

    let mut result = session.transact(SimTx::from_outer(&outer(gas_limit), TxChecks::STRICT))?;
    result.require_safe_success(signed.prepared.safe, signed.prepared.safe_tx_hash);
    Ok(Simulated {
        result,
        eoa_nonce,
        gas_limit,
    })
}

/// EIP-1559 fees for the outer transaction: the node estimate, with any
/// `--max-fee-per-gas` / `--max-priority-fee-per-gas` override applied.
async fn outer_fees(provider: &HttpProvider, args: &SendArgs) -> Result<Eip1559Estimation> {
    let mut fees = match (args.max_fee_per_gas, args.max_priority_fee_per_gas) {
        (Some(max_fee_per_gas), Some(max_priority_fee_per_gas)) => Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
        _ => provider.estimate_eip1559_fees().await?,
    };
    if let Some(max_fee) = args.max_fee_per_gas {
        fees.max_fee_per_gas = max_fee;
    }
    if let Some(priority_fee) = args.max_priority_fee_per_gas {
        fees.max_priority_fee_per_gas = priority_fee;
    }
    Ok(fees)
}

/// `eth_estimateGas` for the outer transaction, plus 20%.
async fn estimate_outer_gas(
    provider: &HttpProvider,
    signed: &SignedSafeTx,
    from: Address,
) -> Result<u64> {
    let tx = <AnyNetwork as Network>::TransactionRequest::default()
        .with_from(from)
        .with_to(signed.prepared.safe)
        .with_input(signed.exec_calldata());
    let estimate = provider.estimate_gas(tx).await.map_err(|e| {
        let reason = e.to_string();
        if is_gs013_revert(&reason) {
            eyre!(
                "the inner Safe transaction reverts (GS013); run without --skip-simulation to see why"
            )
        } else {
            eyre!("gas estimation failed: {reason}")
        }
    })?;
    Ok(estimate + estimate / 5)
}

/// Canonical v1.4.1 addresses with the `--multi-send*` overrides applied.
fn chain_addresses(args: &SendArgs) -> ChainAddresses {
    let mut addresses = ChainAddresses::v1_4_1();
    if let Some(multi_send) = args.multi_send {
        addresses.multi_send = multi_send;
    }
    if let Some(multi_send_call_only) = args.multi_send_call_only {
        addresses.multi_send_call_only = multi_send_call_only;
    }
    addresses
}

fn build_calls(args: &SendArgs) -> Result<Vec<Call>> {
    // Mode 1: Bundle file
    if let Some(bundle_path) = &args.bundle {
        return load_bundle(bundle_path);
    }

    // Mode 2: Multicall via --call flags
    if !args.calls.is_empty() {
        return args
            .calls
            .iter()
            .map(|spec| {
                let (to, data) = parse_call_spec(spec)?;
                Ok(Call::new(to, U256::ZERO, data))
            })
            .collect();
    }

    // Mode 3: Single call (cast-style)
    let to = args
        .to
        .ok_or_else(|| eyre!("Target address required for single call mode"))?;

    // Handle simple ETH transfer (no signature) or function call
    let data = match &args.sig {
        Some(sig) if !sig.is_empty() => encode_function_call(sig, &args.args)?,
        _ => Bytes::new(), // Simple ETH transfer
    };

    Ok(vec![Call::new(to, args.value, data)])
}
