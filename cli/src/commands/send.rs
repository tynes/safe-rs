use std::collections::BTreeMap;
use std::time::Duration;

use alloy::eips::eip1559::Eip1559Estimation;
use alloy::eips::BlockId;
use alloy::network::primitives::ReceiptResponse;
use alloy::network::{AnyNetwork, Network, TransactionBuilder};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::{
    broadcast_raw, detect_addresses, is_gs013_revert, read_approved_owners, read_safe_state,
    require_batch_target, safe_outcome_for_receipt, sign_outer_tx, simulate_approve_hash,
    simulate_exec_with_threshold, wait_for_receipt, Account, BatchTarget, BroadcastOutcome, Call,
    CallBuilder, ChainAddresses, ChainConfig, Error, ExecSimulation, ForkSession, OuterTxParams,
    ReadSafeStateOptions, ReceiptWait, Safe, SignedSafeTx,
};

use crate::bundle::{BundleCall, BundleFile};
use crate::cli::{SendArgs, SendOpts};
use crate::commands::default_safe::{recorded_safe, safe_or_default};
use crate::commands::rotation::{self, RotationRun};
use crate::commands::{fork_session, http_provider, outer_fees, HttpProvider};
use crate::output::{
    calls_summary, confirm_prompt, ApproveHashOutput, BundleSavedOutput, Console, ExecutionOutput,
    Report, SignedTxOutput, SimulationOutput,
};
use crate::sig_parser::{encode_function_call, parse_call_spec};
use crate::wallet::{create_payer, create_signer, open_wallet};

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
    let calls = build_cli_calls(&args)?;
    send(calls, args.opts, json).await
}

/// Sends `calls` through the Safe as `safe send` does, with every option in
/// `opts`: `--rotate`, `--bundle` signature collection, simulation, then
/// approveHash, saving to the bundle or execution.
///
/// With `--bundle`, `calls` may be empty when the bundle already holds them.
pub async fn send(calls: Vec<Call>, opts: SendOpts, json: bool) -> Result<()> {
    if opts.rotate {
        return Box::pin(run_rotating(opts, calls, json)).await;
    }
    if opts.sweep.no_sweep || opts.sweep.sweep_reserve.is_some() {
        bail!("--no-sweep and --sweep-reserve only apply with --rotate");
    }
    if opts.hd.is_set() && !opts.wallet.is_set() {
        bail!(
            "--hd-wallet or --ledger needs --rotate: sending without rotating would publish \
             an owner key and leave it in charge of the Safe"
        );
    }
    execute(opts, calls, ExecHooks::default(), json).await
}

/// Checks the Safe in the session the simulated transaction was committed to.
/// An error stops the run before anything is signed or broadcast.
pub type PostCheck<'a> = &'a (dyn Fn(&mut ForkSession) -> safe_rs::Result<()> + Sync);

/// What another command adds to the send pipeline.
#[derive(Default)]
pub struct ExecHooks<'a> {
    /// The signer, when the caller already created it (so a keystore password
    /// is not asked for twice)
    pub signer: Option<PrivateKeySigner>,
    /// Checked against the simulated post-state
    pub post_check: Option<PostCheck<'a>>,
}

/// Runs `cli_calls` (with `--bundle` and the other flags in `args`) through the
/// Safe: signature collection, simulation, then approveHash, saving to the
/// bundle or execution. Ignores `--rotate`: [`send`] handles it.
pub async fn execute(
    args: SendOpts,
    cli_calls: Vec<Call>,
    hooks: ExecHooks<'_>,
    json: bool,
) -> Result<()> {
    // 1. Load/Build Calls & Existing Bundle State
    let bundle_existed = args.bundle.as_ref().is_some_and(|p| p.exists());
    let mut bundle = if let Some(bundle_path) = &args.bundle {
        if bundle_path.exists() {
            let mut loaded = BundleFile::load(bundle_path)?;
            if !cli_calls.is_empty() {
                let cli_bundle_calls: Vec<BundleCall> =
                    cli_calls.iter().map(BundleCall::from).collect();
                if loaded.tx.is_none() {
                    loaded.calls.extend(cli_bundle_calls);
                    loaded.save(bundle_path)?;
                } else if loaded.calls != cli_bundle_calls {
                    bail!(
                        "Bundle file {} already has a prepared Safe transaction whose calls differ from the CLI arguments",
                        bundle_path.display()
                    );
                }
            }
            loaded
        } else {
            if cli_calls.is_empty() {
                bail!(
                    "Bundle file not found: {} (pass calls on the command line to initialize a new bundle)",
                    bundle_path.display()
                );
            }
            BundleFile::from_calls(&cli_calls)
        }
    } else {
        if cli_calls.is_empty() {
            bail!("Target address required for single call mode");
        }
        BundleFile::from_calls(&cli_calls)
    };

    for merge_path in &args.merge_bundle {
        let other = BundleFile::load(merge_path)?;
        bundle.merge_from_file(&other)?;
    }

    let calls = bundle.calls()?;
    if calls.is_empty() && bundle.tx.is_none() && bundle.rotations.is_empty() {
        return Err(eyre!("No calls specified"));
    }

    // `--no-submit` without a destination writes the signed transaction to stdout.
    let raw_out = args
        .raw_out
        .clone()
        .or_else(|| args.no_submit.then(|| "-".to_string()));
    let console = Console::new(json, raw_out.as_deref() == Some("-"));

    // 2. Inspect Safe State & Resolve Signer / Payer
    let signer_opt = match hooks.signer {
        Some(signer) => Some(signer),
        None if args.wallet.is_set() => Some(create_signer(&args.wallet, &args.password)?),
        None => None,
    };
    let payer_opt = create_payer(&args.payer)?;
    let payer = match (&payer_opt, &signer_opt) {
        (Some(p), _) => p.clone(),
        (None, Some(s)) => s.clone(),
        (None, None) => {
            // Force the standard wallet error message
            create_signer(&args.wallet, &args.password)?
        }
    };
    let from = payer.address();

    let provider = http_provider(&args.rpc.rpc_url);
    let chain_id = provider.get_chain_id().await?;
    // A prepared bundle names its Safe, so co-signers need not pass --safe.
    let safe_address = safe_or_default(
        &provider,
        args.safe.safe.or(bundle.tx.as_ref().map(|tx| tx.safe)),
        signer_opt.as_ref(),
        BlockId::latest(),
    )
    .await?;
    let addresses = chain_addresses(&provider, &args, safe_address).await;
    let config = ChainConfig::with_addresses(chain_id, addresses.clone());

    let sim_block = args.sim.block.unwrap_or_else(BlockId::latest);
    let state = read_safe_state(
        &provider,
        safe_address,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await?;
    let need = state.threshold.saturating_to::<usize>();
    if need == 0 {
        bail!("Safe {} returned threshold 0", safe_address);
    }

    let signer_is_owner = signer_opt
        .as_ref()
        .is_some_and(|s| state.owners.contains(&s.address()));

    // 3. Prepare Safe Transaction & Collect Signatures
    let batch_target = if args.call_only {
        BatchTarget::CallOnly(addresses.multi_send_call_only)
    } else {
        BatchTarget::MultiSend(addresses.multi_send)
    };
    let check_block = if args.skip_simulation {
        BlockId::latest()
    } else {
        sim_block
    };
    if let Some(target_addr) = batch_target.address_for(&calls) {
        require_batch_target(&provider, target_addr, check_block)
            .await
            .map_err(|e| {
                let flag = if args.call_only {
                    "--multi-send-call-only"
                } else {
                    "--multi-send"
                };
                eyre!("{e}; pass the address it has on this chain with {flag}")
            })?;
    }

    let prepared = if let Some(existing) = bundle.prepared_tx()? {
        if existing.chain_id != chain_id {
            bail!(
                "Bundle was prepared for chain {}, but connected RPC is chain {chain_id}",
                existing.chain_id
            );
        }
        if existing.safe != safe_address {
            bail!(
                "Bundle was prepared for Safe {}, not {safe_address}",
                existing.safe
            );
        }
        let expected_nonce = args.nonce.unwrap_or(existing.params.nonce);
        if existing.params.nonce != expected_nonce {
            bail!(
                "Bundle was prepared for Safe nonce {}, not {expected_nonce}",
                existing.params.nonce
            );
        }
        if state.nonce != existing.params.nonce {
            return Err(Error::NonceMismatch {
                expected: existing.params.nonce,
                actual: state.nonce,
            }
            .into());
        }
        existing
    } else {
        let safe_for_builder = Safe::new(
            provider.clone(),
            signer_opt.clone().unwrap_or_else(|| payer.clone()),
            safe_address,
            config,
        );
        let mut builder = calls
            .iter()
            .cloned()
            .fold(safe_for_builder.batch(), |b, call| b.add(call));
        if args.call_only {
            builder = builder.call_only();
        }
        if let Some(nonce) = args.nonce {
            builder = builder.with_nonce(nonce);
        }
        if let Some(gas) = args.safe_tx_gas {
            builder = builder.with_safe_tx_gas(gas);
        }
        if let (false, Some(block)) = (args.skip_simulation, args.sim.block) {
            builder = builder.with_batch_target_block(block);
        }
        builder.prepare().await?
    };

    let approved_owners = read_approved_owners(
        &provider,
        safe_address,
        &state.owners,
        prepared.safe_tx_hash,
        sim_block,
    )
    .await?;

    let mut signed = SignedSafeTx::empty(prepared.clone());
    let mut offchain_sigs = BTreeMap::new();
    for (&owner, sig) in &bundle.signatures {
        if state.owners.contains(&owner) {
            signed.insert_signature(owner, sig.clone())?;
            offchain_sigs.insert(owner, sig.clone());
        }
    }
    for &owner in &approved_owners {
        signed
            .signatures
            .entry(owner)
            .or_insert_with(|| safe_rs::signing::encode_pre_validated_signature(owner));
    }

    if let Some(signer) = &signer_opt {
        if signer_is_owner {
            if args.approve_hash {
                // When approving on-chain, the owner authorizes via approveHash (v = 1)
                // unless they also want an offchain signature in --bundle.
                if args.bundle.is_some() && !offchain_sigs.contains_key(&signer.address()) {
                    let sig_tx = prepared.sign(signer).await?;
                    if let Some(sig) = sig_tx.signature() {
                        signed.insert_signature(signer.address(), sig.clone())?;
                        offchain_sigs.insert(signer.address(), sig.clone());
                    }
                } else {
                    signed.add_prevalidated(signer.address());
                }
            } else {
                let needs_ecdsa = match signed.signatures.get(&signer.address()) {
                    None => true,
                    Some(existing_sig) => existing_sig.len() == 65 && existing_sig[64] == 1,
                };
                if needs_ecdsa {
                    let sig_tx = prepared.sign(signer).await?;
                    if let Some(sig) = sig_tx.signature() {
                        signed.insert_signature(signer.address(), sig.clone())?;
                        offchain_sigs.insert(signer.address(), sig.clone());
                    }
                }
            }
        }
    }

    let have = signed.signatures.len();
    if !signer_is_owner && (args.approve_hash || args.sign_only || have < need) {
        let bad_signer = signer_opt.as_ref().map_or(from, |s| s.address());
        return Err(Error::NotOwner {
            signer: bad_signer,
            safe: safe_address,
        }
        .into());
    }

    console.line(format!("Safe: {}", safe_address));
    if let Some(signer) = &signer_opt {
        console.line(format!("Signer: {}", signer.address()));
    }
    if Some(from) != signer_opt.as_ref().map(|s| s.address()) {
        console.line(format!("Payer: {from}"));
    }
    console.line(format!("Threshold: {have}/{need} signatures"));
    console.line(format!("Nonce: {}", prepared.params.nonce));
    console.line(format!("Safe Tx Hash: {}", prepared.safe_tx_hash));
    console.line("");
    console.line(calls_summary(&calls));
    console.line("");

    let fees = outer_fees(
        &provider,
        args.max_fee_per_gas,
        args.max_priority_fee_per_gas,
    )
    .await?;

    // 4. Simulate
    let sim_info = if args.skip_simulation {
        console.line("Skipping simulation (--skip-simulation)\n");
        None
    } else {
        let mut simulated = simulate(
            &provider,
            chain_id,
            &args,
            &signed,
            &state.owners,
            need,
            from,
            fees,
        )
        .await?;
        if let (Some(check), Some(post)) = (hooks.post_check, simulated.post.as_mut()) {
            check(post)?;
        }
        let result = &simulated.result;
        let report = SimulationOutput {
            success: result.success,
            gas_used: result.gas_used,
            revert_reason: result.revert_reason.clone(),
            safe_tx_hash: Some(prepared.safe_tx_hash),
            traces: args.trace.then(|| result.format_traces()).flatten(),
            signatures_collected: Some(have),
            threshold: Some(need),
            ready_to_execute: Some(have >= need),
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
        Some((simulated.payer_nonce, simulated.gas_limit))
    };

    // 5. Smart Action Branching
    // Branch A: --approve-hash
    if args.approve_hash {
        let signer = signer_opt.as_ref().ok_or_else(|| {
            eyre!("--approve-hash requires an owner wallet (--private-key, --keystore, or --interactive)")
        })?;
        let approver = signer.address();
        let bundle_path_str = if let Some(bundle_path) = &args.bundle {
            bundle.merge(&prepared, &offchain_sigs, &[])?;
            bundle.save(bundle_path)?;
            Some(bundle_path.display().to_string())
        } else {
            None
        };

        let (approve_nonce, approve_gas) = if args.skip_simulation {
            let nonce = provider.get_transaction_count(approver).await?;
            let gas = if let Some(g) = args.gas_limit {
                g
            } else {
                let tx = <AnyNetwork as Network>::TransactionRequest::default()
                    .with_from(approver)
                    .with_to(safe_address)
                    .with_input(SignedSafeTx::approve_hash_calldata(prepared.safe_tx_hash));
                let est = provider.estimate_gas(tx).await?;
                est + est / 5
            };
            (nonce, gas)
        } else {
            let session = fork_session(provider.clone(), chain_id, &args.sim, false).await?;
            let sim = simulate_approve_hash(
                &session,
                chain_id,
                safe_address,
                prepared.safe_tx_hash,
                approver,
                fees,
                args.gas_limit,
            )?;
            if !sim.result.success {
                bail!(
                    "approveHash simulation failed: {}",
                    sim.result
                        .revert_reason
                        .as_deref()
                        .unwrap_or("unknown reason")
                );
            }
            let gas = if args.gas_limit.is_some() {
                sim.gas_limit
            } else {
                let tx = <AnyNetwork as Network>::TransactionRequest::default()
                    .with_from(approver)
                    .with_to(safe_address)
                    .with_input(SignedSafeTx::approve_hash_calldata(prepared.safe_tx_hash));
                let est = provider
                    .estimate_gas(tx)
                    .await
                    .map_err(|e| node_estimate_failed(eyre!("{e}"), "approveHash"))?;
                cross_check_gas_limit(sim.gas_limit, est + est / 5)
            };
            (sim.payer_nonce, gas)
        };

        let outer = sign_outer_tx(
            signer,
            OuterTxParams::approve_hash(
                chain_id,
                safe_address,
                prepared.safe_tx_hash,
                approver,
                approve_nonce,
                approve_gas,
                fees,
            ),
        )
        .await?;

        let prompt =
            format!("Approve Safe transaction hash on-chain ({have}/{need} toward threshold)?");
        if !args.no_confirm && !json && !confirm_prompt(&prompt) {
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
            match wait_for_receipt(&provider, outer.tx_hash, timeout, RECEIPT_POLL_INTERVAL).await?
            {
                ReceiptWait::Mined(receipt) => receipt,
                ReceiptWait::TimedOut { tx_hash } => bail!(
                    "no receipt for {tx_hash} after {}s; it may still be pending",
                    args.timeout
                ),
            };

        let success = receipt.status();
        emit(
            &ApproveHashOutput {
                tx_hash: outer.tx_hash,
                success,
                gas_used: receipt.gas_used,
                safe_tx_hash: prepared.safe_tx_hash,
                safe_nonce: prepared.params.nonce,
                approver,
                signatures_collected: have,
                threshold: need,
                bundle_path: bundle_path_str,
            },
            json,
            console,
        );
        if !success {
            bail!("approveHash transaction reverted");
        }
        return Ok(());
    }

    // Branch B: Offchain signature collection (`have < need` or `--sign-only`)
    if have < need || args.sign_only {
        let Some(bundle_path) = &args.bundle else {
            bail!(
                "Safe threshold is {need} (have {have}/{need} signatures). Pass --bundle <FILE> to save and collect signatures offchain, or --approve-hash to approve on-chain"
            );
        };
        bundle.merge(&prepared, &offchain_sigs, &[])?;
        bundle.save(bundle_path)?;
        let signers: Vec<Address> = signed.signatures.keys().copied().collect();
        let remaining_owners: Vec<Address> = state
            .owners
            .iter()
            .copied()
            .filter(|o| !signed.signatures.contains_key(o))
            .collect();
        emit(
            &BundleSavedOutput {
                safe_tx_hash: prepared.safe_tx_hash,
                safe_nonce: prepared.params.nonce,
                signatures_collected: have,
                threshold: need,
                signers,
                remaining_owners,
                bundle_path: bundle_path.display().to_string(),
            },
            json,
            console,
        );
        return Ok(());
    }

    // Branch C: Threshold met (`have >= need`) -> Execute `execTransaction`
    if !args.no_submit {
        if let Some(bundle_path) = &args.bundle {
            if !bundle_existed || bundle.tx.is_some() {
                bundle.merge(&prepared, &offchain_sigs, &[])?;
                bundle.save(bundle_path)?;
            }
        }
    }

    // Trim `signed` to exact `need` signatures in ascending owner address order
    let mut exec_signed = signed.clone();
    exec_signed.signatures = signed
        .signatures
        .iter()
        .take(need)
        .map(|(&k, v)| (k, v.clone()))
        .collect();

    let (eoa_nonce, gas_limit) = if let Some((nonce, simulated)) = sim_info {
        let gas_limit = if args.gas_limit.is_some() {
            simulated
        } else {
            let est = provider
                .estimate_gas(exec_request(&exec_signed, from))
                .await
                .map_err(|e| node_estimate_failed(eyre!("{e}"), "execTransaction"))?;
            cross_check_gas_limit(simulated, est + est / 5)
        };
        (nonce, gas_limit)
    } else {
        let nonce = provider.get_transaction_count(from).await?;
        let gas_limit = if let Some(gas) = args.gas_limit {
            gas
        } else {
            estimate_outer_gas(&provider, &exec_signed, from).await?
        };
        (nonce, gas_limit)
    };

    let outer = sign_outer_tx(
        &payer,
        OuterTxParams::exec_transaction(&exec_signed, from, eoa_nonce, gas_limit, fees),
    )
    .await?;

    // Persist the exact bytes before the first broadcast so they can be
    // rebroadcast or reconciled if the outcome is unclear.
    let document = SignedTxOutput::new(&exec_signed, &outer);
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
        format!("Execute transaction without simulation ({have}/{need} signatures)?")
    } else if need > 1 {
        format!("Execute transaction ({have}/{need} signatures)?")
    } else {
        "Execute transaction?".to_string()
    };
    if !args.no_confirm && !json && !confirm_prompt(&prompt) {
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

/// `send --rotate`: the user's calls followed by a swap of the owner for the HD
/// wallet's next unused key, then a sweep of the old key's ETH.
async fn run_rotating(args: SendOpts, cli_calls: Vec<Call>, json: bool) -> Result<()> {
    if args.wallet.is_set() {
        bail!(
            "with --rotate the owner key comes from --hd-wallet or --ledger: remove --private-key, \
             --keystore and --interactive, and unset PRIVATE_KEY"
        );
    }
    let mut bundle_safe = None;
    let calls = if let Some(bundle_path) = &args.bundle {
        if bundle_path.exists() {
            let loaded = BundleFile::load(bundle_path)?;
            bundle_safe = loaded.tx.as_ref().map(|tx| tx.safe);
            let loaded_calls = loaded.calls()?;
            let cli_bundle_calls: Vec<BundleCall> =
                cli_calls.iter().map(BundleCall::from).collect();
            if !cli_calls.is_empty() && loaded.tx.is_some() && loaded.calls != cli_bundle_calls {
                bail!(
                    "Bundle file {} already has a prepared Safe transaction whose calls differ from the CLI arguments",
                    bundle_path.display()
                );
            }
            if loaded.tx.is_none() && !cli_calls.is_empty() {
                let mut combined = loaded_calls;
                combined.extend(cli_calls);
                combined
            } else {
                loaded_calls
            }
        } else {
            cli_calls
        }
    } else {
        cli_calls
    };
    if calls.is_empty() {
        return Err(eyre!("No calls specified"));
    }
    let payer = create_payer(&args.payer)?;
    let ring = open_wallet(&args.hd, &args.password).await?;
    let safe = if let Some(safe) = args.safe.safe.or(bundle_safe) {
        safe
    } else {
        let chain_id = http_provider(&args.rpc.rpc_url).get_chain_id().await?;
        recorded_safe(ring.state(), chain_id, "--safe")?
    };
    rotation::run(RotationRun {
        rpc_url: &args.rpc.rpc_url,
        safe,
        ring,
        legacy_owner: None,
        sweep_legacy: false,
        payer,
        sweep: &args.sweep,
        calls,
        multi_send_call_only: args.multi_send_call_only,
        sim: &args.sim,
        gas_limit: args.gas_limit,
        max_fee_per_gas: args.max_fee_per_gas,
        max_priority_fee_per_gas: args.max_priority_fee_per_gas,
        timeout: args.timeout,
        trace: args.trace,
        simulate_only: args.simulate_only,
        raw_out: args.raw_out.clone(),
        no_submit: args.no_submit,
        no_confirm: args.no_confirm,
        bundle: args.bundle.clone(),
        merge_bundle: args.merge_bundle.clone(),
        approve_hash: args.approve_hash,
        sign_only: args.sign_only,
        json,
    })
    .await
}

/// Simulates the exact outer `execTransaction` the CLI would sign, in the block
/// after `--block`, with all validity checks (nonce, fees, balance).
///
/// Calls are always traced so that a `GS013` failure reports the inner revert
/// reason; the traces are only printed with `--trace`.
async fn simulate(
    provider: &HttpProvider,
    chain_id: u64,
    args: &SendOpts,
    signed: &SignedSafeTx,
    owners: &[Address],
    threshold: usize,
    from: Address,
    fees: Eip1559Estimation,
) -> Result<ExecSimulation> {
    let session = fork_session(provider.clone(), chain_id, &args.sim, true).await?;
    Ok(simulate_exec_with_threshold(
        &session,
        signed,
        owners,
        threshold,
        from,
        fees,
        args.gas_limit,
    )?)
}

/// `eth_estimateGas` for the outer transaction, plus 20%.
async fn estimate_outer_gas(
    provider: &HttpProvider,
    signed: &SignedSafeTx,
    from: Address,
) -> Result<u64> {
    let estimate = provider.estimate_gas(exec_request(signed, from)).await.map_err(|e| {
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

/// The outer `execTransaction` call for `signed`, sent by `from`.
fn exec_request(
    signed: &SignedSafeTx,
    from: Address,
) -> <AnyNetwork as Network>::TransactionRequest {
    <AnyNetwork as Network>::TransactionRequest::default()
        .with_from(from)
        .with_to(signed.prepared.safe)
        .with_input(signed.exec_calldata())
}

/// How far apart (in percent of the lower) the simulated and node gas limits
/// may be before [`cross_check_gas_limit`] warns.
const GAS_DIVERGENCE_WARN_PERCENT: u64 = 25;

/// The higher of the simulated gas limit and the node's (`eth_estimateGas`
/// plus 20%), warning on stderr when they differ by more than
/// [`GAS_DIVERGENCE_WARN_PERCENT`]: the local EVM may not model the gas
/// schedule of the chain's current fork, and a limit sized by it alone can run
/// out of gas on chain even though the simulation succeeded.
fn cross_check_gas_limit(simulated: u64, node: u64) -> u64 {
    let (gas_limit, warning) = reconcile_gas_limits(simulated, node);
    if let Some(warning) = warning {
        eprintln!("warning: {warning}");
    }
    gas_limit
}

fn reconcile_gas_limits(simulated: u64, node: u64) -> (u64, Option<String>) {
    let (low, high) = (simulated.min(node), simulated.max(node));
    let diverges =
        (high - low).saturating_mul(100) > low.saturating_mul(GAS_DIVERGENCE_WARN_PERCENT);
    let warning = diverges.then(|| {
        if node > simulated {
            format!(
                "the node estimates more gas than the simulation ({node} vs {simulated}); \
                 the local EVM may not match the chain's current fork, using {high}"
            )
        } else {
            format!(
                "the simulation needs more gas than the node estimates ({simulated} vs {node}); \
                 using {high}"
            )
        }
    });
    (high, warning)
}

/// The error for a node gas estimate that fails after the simulation passed.
fn node_estimate_failed(error: color_eyre::eyre::Report, what: &str) -> color_eyre::eyre::Report {
    eyre!(
        "the simulation succeeded but the node's gas estimate for {what} failed, so the \
         transaction would likely revert on chain (the local EVM may not match the chain's \
         current fork); pass --gas-limit to send it anyway: {error}"
    )
}

/// Canonical addresses for the Safe's version with the `--multi-send*`
/// overrides applied.
async fn chain_addresses(
    provider: &HttpProvider,
    args: &SendOpts,
    safe: Address,
) -> ChainAddresses {
    let mut addresses = detect_addresses(provider, safe).await;
    if let Some(multi_send) = args.multi_send {
        addresses.multi_send = multi_send;
    }
    if let Some(multi_send_call_only) = args.multi_send_call_only {
        addresses.multi_send_call_only = multi_send_call_only;
    }
    addresses
}

fn build_cli_calls(args: &SendArgs) -> Result<Vec<Call>> {
    // Multicall via --call flags
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

    // Single call (cast-style) if `TO` is present
    let Some(to) = args.to else {
        return Ok(Vec::new());
    };

    // Handle simple ETH transfer (no signature) or function call
    let data = match &args.sig {
        Some(sig) if !sig.is_empty() => encode_function_call(sig, &args.args)?,
        _ => Bytes::new(), // Simple ETH transfer
    };

    Ok(vec![Call::new(to, args.value, data)])
}

#[cfg(test)]
mod tests {
    use super::reconcile_gas_limits;

    #[test]
    fn close_gas_limits_take_the_higher_without_a_warning() {
        assert_eq!(reconcile_gas_limits(100_000, 110_000), (110_000, None));
        assert_eq!(reconcile_gas_limits(125_000, 100_000), (125_000, None));
    }

    #[test]
    fn divergent_gas_limits_take_the_higher_and_warn() {
        // The Sepolia case: the local EVM measured 74,674 (limit 89,608) while
        // the node estimated 161,826 (limit 194,191).
        let (gas, warning) = reconcile_gas_limits(89_608, 194_191);
        assert_eq!(gas, 194_191);
        assert!(warning.unwrap().contains("node estimates more gas"));

        let (gas, warning) = reconcile_gas_limits(200_000, 100_000);
        assert_eq!(gas, 200_000);
        assert!(warning.unwrap().contains("simulation needs more gas"));
    }
}
