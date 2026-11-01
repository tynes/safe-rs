use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use alloy::eips::eip1559::Eip1559Estimation;
use alloy::eips::BlockId;
use alloy::network::primitives::ReceiptResponse;
use alloy::network::{AnyNetwork, Network, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre;
use safe_rs::{
    broadcast_raw, check_eoa_calls, detect_addresses, is_gs013_revert, read_approved_owners,
    read_safe_state, require_batch_target, safe_outcome_for_receipt, sign_outer_tx,
    simulate_approve_hash, simulate_eoa_calls, simulate_exec_with_threshold, wait_for_receipt,
    Account, BatchTarget, BroadcastOutcome, Call, CallBuilder, ChainAddresses, ChainConfig, Error,
    ExecSimulation, ForkSession, OuterTxParams, ReadSafeStateOptions, ReceiptWait, Safe,
    SignedSafeTx,
};

use crate::bundle::{BundleCall, BundleFile};
use crate::cli::{SendArgs, SendOpts};
#[cfg(feature = "hd-wallet")]
use crate::commands::default_safe::recorded_safe;
use crate::commands::default_safe::safe_or_default;
#[cfg(feature = "hd-wallet")]
use crate::commands::rotation::{self, RotationRun};
use crate::commands::{fork_session, http_provider, outer_fees, HttpProvider};
use crate::console::Console;
#[cfg(feature = "hd-wallet")]
use crate::error::OptionsError;
use crate::error::{BroadcastError, SendError};
use crate::log::{Logger, NoopLogger};
use crate::output::{
    calls_summary, ApproveHashOutput, BundleSavedOutput, EoaExecutionOutput, ExecutionOutput,
    Report, SignedTxOutput, SimulationOutput,
};
pub use crate::output::{EoaTx, SendOutcome};
use crate::prompt::{Prompt, TerminalPrompt};
use crate::sig_parser::{encode_function_call, parse_call_spec};
#[cfg(feature = "hd-wallet")]
use crate::signers::open_wallet;
use crate::signers::{create_payer, create_signer};
#[cfg(feature = "hd-wallet")]
use std::path::PathBuf;
use std::sync::Arc;
use url::Url;

/// How often to poll for the receipt after broadcasting.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(500);

type Result<T, E = SendError> = std::result::Result<T, E>;

/// What sends the calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sender {
    /// The Safe at this address, in one Safe transaction (batched through
    /// MultiSend when there is more than one call)
    Safe(Address),
    /// The signer's own account, one transaction per call
    Eoa,
}

/// Where a send goes and who signs it: what a CLI embedding [`SendOpts`]
/// resolves itself instead of taking `--rpc-url`, `--safe` and the wallet
/// flags.
#[derive(Clone)]
#[non_exhaustive]
pub struct SendContext {
    /// RPC endpoint of the chain to send on
    pub rpc_url: Url,
    /// The Safe to send through, or the signer's own account
    pub sender: Sender,
    /// The owner key that signs the Safe transaction, and pays for gas unless
    /// `--payer-private-key` is given. Leave it out with `--rotate`, where the
    /// owner key comes from the HD wallet or Ledger, or to only add on-chain
    /// approvals collected in `--bundle` while a payer submits.
    ///
    /// For [`Sender::Eoa`], the account that sends and pays; required.
    pub signer: Option<PrivateKeySigner>,
    /// Where progress and warnings go (default: nowhere)
    pub logger: Arc<dyn Logger>,
    /// What asks for confirmation and passwords (default: the terminal)
    pub prompt: Arc<dyn Prompt>,
    /// Where HD wallets and their state live, for `--rotate` (default:
    /// `$SAFE_RS_HOME` or `~/.safe-rs`)
    #[cfg(feature = "hd-wallet")]
    pub home: Option<PathBuf>,
}

impl SendContext {
    /// A send through `safe` over `rpc_url`, with no signer, a silent
    /// [`NoopLogger`] and a [`TerminalPrompt`].
    pub fn new(rpc_url: Url, safe: Address) -> Self {
        Self {
            rpc_url,
            sender: Sender::Safe(safe),
            signer: None,
            logger: Arc::new(NoopLogger),
            prompt: Arc::new(TerminalPrompt::new()),
            #[cfg(feature = "hd-wallet")]
            home: None,
        }
    }

    /// A send from the signer's own account over `rpc_url`, one transaction
    /// per call, with the same defaults as [`new`](Self::new). Give it a signer with
    /// [`with_signer`](Self::with_signer).
    ///
    /// The options that only apply to a Safe (`--bundle`, `--nonce`,
    /// `--rotate` and the others) are refused with
    /// [`OptionsError::SafeOnly`].
    pub fn eoa(rpc_url: Url) -> Self {
        Self {
            rpc_url,
            sender: Sender::Eoa,
            signer: None,
            logger: Arc::new(NoopLogger),
            prompt: Arc::new(TerminalPrompt::new()),
            #[cfg(feature = "hd-wallet")]
            home: None,
        }
    }

    pub fn with_signer(mut self, signer: PrivateKeySigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Sends progress and warnings to `logger`. An `Arc<dyn Logger>` is a
    /// logger too, so one can be shared between contexts.
    pub fn with_logger(mut self, logger: impl Logger + 'static) -> Self {
        self.logger = Arc::new(logger);
        self
    }

    /// Asks `prompt` for confirmations and secrets.
    /// [`NoPrompt`](crate::prompt::NoPrompt) declines every confirmation:
    /// set `no_confirm` on the options to send unattended.
    pub fn with_prompt(mut self, prompt: impl Prompt + 'static) -> Self {
        self.prompt = Arc::new(prompt);
        self
    }

    /// Looks for HD wallets and their state under `home` instead of
    /// `$SAFE_RS_HOME` or `~/.safe-rs`.
    #[cfg(feature = "hd-wallet")]
    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home = Some(home);
        self
    }

    fn console(&self) -> Console {
        Console::new(self.logger.clone(), self.prompt.clone())
    }
}

impl fmt::Debug for SendContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendContext")
            .field("rpc_url", &self.rpc_url.as_str())
            .field("sender", &self.sender)
            .field("signer", &self.signer.as_ref().map(|s| s.address()))
            .finish_non_exhaustive()
    }
}

/// The resolved RPC, Safe and signer of one send. The Safe is optional for
/// `safe send`, which falls back to the bundle's, the HD wallet's or the
/// signer's default Safe.
pub struct Target {
    pub rpc_url: Url,
    pub safe: Option<Address>,
    pub signer: Option<PrivateKeySigner>,
    /// The HD wallet directory, for `--rotate`
    #[cfg(feature = "hd-wallet")]
    pub home: Option<PathBuf>,
}

/// `safe send`.
pub async fn run(args: SendArgs, console: &Console) -> eyre::Result<()> {
    let calls = build_cli_calls(&args)?;
    if args.send_eoa {
        return run_eoa(args, calls, console).await;
    }
    // Checked before any key or password prompt.
    let checked = args.opts.validate_safe(args.signer.is_set());
    #[cfg(feature = "hd-wallet")]
    if checked == Err(OptionsError::RotateWithSigner) {
        eyre::bail!(
            "with --rotate the owner key comes from --hd-wallet or --ledger: remove --private-key, \
             --keystore and --interactive, and unset PRIVATE_KEY"
        );
    }
    checked?;
    if calls.is_empty() && args.opts.collect.bundle.is_none() && !args.opts.rotates() {
        eyre::bail!("Target address required for single call mode");
    }
    let signer = if args.signer.is_set() {
        Some(create_signer(&args.signer, &args.opts.password, console)?)
    } else {
        None
    };
    let target = Target {
        rpc_url: args.rpc.rpc_url,
        safe: args.safe.safe,
        signer,
        #[cfg(feature = "hd-wallet")]
        home: None,
    };
    dispatch(target, calls, args.opts, console).await?;
    Ok(())
}

/// `safe send --send-eoa`: the calls go from the signer's own account, one
/// transaction each, through the same path as [`SendContext::eoa`].
async fn run_eoa(args: SendArgs, calls: Vec<Call>, console: &Console) -> eyre::Result<()> {
    // `--safe` and SAFE_ADDRESS look the same here; refuse both rather than
    // send from the EOA when a Safe was asked for.
    if args.safe.safe.is_some() {
        eyre::bail!(
            "--send-eoa sends from the signer's own account, not a Safe: remove --safe and \
             unset SAFE_ADDRESS"
        );
    }
    // Checked before any key or password prompt.
    args.opts.validate_eoa(calls.len())?;
    if calls.is_empty() {
        eyre::bail!("nothing to send: pass a target address or --call");
    }
    if !args.signer.is_set() {
        return Err(SendError::NoSigner.into());
    }
    let signer = create_signer(&args.signer, &args.opts.password, console)?;
    execute_eoa(&args.rpc.rpc_url, &signer, calls, &args.opts, console).await?;
    Ok(())
}

/// Sends `calls` through the Safe as `safe send` does, with every option in
/// `opts`: `--rotate`, `--bundle` signature collection, simulation, then
/// approveHash, saving to the bundle or execution.
///
/// With `--bundle`, `calls` may be empty when the bundle already holds them.
/// Options built in code are checked for the same conflicts clap enforces on
/// the flags.
///
/// With [`Sender::Eoa`] the signer sends each call as its own transaction:
/// simulated together, confirmed once, then broadcast one after another,
/// each waiting for the one before it to be mined.
pub async fn send(ctx: SendContext, calls: Vec<Call>, opts: SendOpts) -> Result<SendOutcome> {
    let console = ctx.console();
    match ctx.sender {
        Sender::Safe(safe) => {
            opts.validate_safe(ctx.signer.is_some())?;
            let target = Target {
                rpc_url: ctx.rpc_url,
                safe: Some(safe),
                signer: ctx.signer,
                #[cfg(feature = "hd-wallet")]
                home: ctx.home,
            };
            dispatch(target, calls, opts, &console).await
        }
        Sender::Eoa => {
            opts.validate_eoa(calls.len())?;
            let signer = ctx.signer.ok_or(SendError::NoSigner)?;
            execute_eoa(&ctx.rpc_url, &signer, calls, &opts, &console).await
        }
    }
}

/// Sends `calls` from `signer`'s own account, one transaction per call.
///
/// Every transaction is simulated first, in order on one fork, so a later
/// call sees the effects of the earlier ones. Nothing is sent unless all of
/// them pass. They are then broadcast one at a time, each after the one
/// before it is mined; a failure part way returns
/// [`SendError::EoaBatchFailed`] naming the transactions already mined.
async fn execute_eoa(
    rpc_url: &Url,
    signer: &PrivateKeySigner,
    mut calls: Vec<Call>,
    args: &SendOpts,
    console: &Console,
) -> Result<SendOutcome> {
    check_eoa_calls(&calls)?;
    if let (Some(gas), [call]) = (args.fees.gas_limit, calls.as_mut_slice()) {
        call.gas_limit = Some(gas);
    }
    let from = signer.address();
    let provider = http_provider(rpc_url);
    let chain_id = provider.get_chain_id().await?;

    let details = format!("From: {from} (EOA)\n\n{}\n", calls_summary(&calls));
    console.line(&details);

    let fees = outer_fees(
        &provider,
        args.fees.max_fee_per_gas,
        args.fees.max_priority_fee_per_gas,
    )
    .await?;

    // The nonce and simulated gas limit of each transaction.
    let planned: Vec<(u64, Option<u64>)> = if args.skip_simulation {
        console.line("Skipping simulation (--skip-simulation)\n");
        let nonce = provider.get_transaction_count(from).await?;
        (nonce..).zip(calls.iter().map(|c| c.gas_limit)).collect()
    } else {
        let session = fork_session(provider.clone(), chain_id, &args.simulate.sim, true).await?;
        let simulated = simulate_eoa_calls(&session, from, &calls, fees)?;
        let failed = simulated
            .iter()
            .position(|s| !s.result.success)
            .map(|i| (i, &simulated[i].result));
        let traces = args
            .simulate
            .trace
            .then(|| {
                let all: Vec<String> = simulated
                    .iter()
                    .filter_map(|s| s.result.format_traces())
                    .collect();
                (!all.is_empty()).then(|| all.join("\n"))
            })
            .flatten();
        let gas_used = simulated.iter().map(|s| s.result.gas_used).sum();
        let revert_reason = failed.map(|(i, result)| {
            let reason = result
                .revert_reason
                .clone()
                .unwrap_or_else(|| "unknown reason".to_string());
            if calls.len() > 1 {
                format!("call {i}: {reason}")
            } else {
                reason
            }
        });
        let report = SimulationOutput {
            success: failed.is_none(),
            gas_used,
            revert_reason: revert_reason.clone(),
            traces,
            ..SimulationOutput::default()
        };
        if failed.is_some() {
            console.emit_or_line(&report);
        } else if args.simulate.simulate_only {
            console.emit(&report);
        } else {
            console.line(report.human());
            console.line("");
        }
        if let Some(reason) = revert_reason {
            return Err(SendError::SimulationFailed { reason });
        }
        if args.simulate.simulate_only {
            return Ok(SendOutcome::EoaSimulated { gas_used });
        }
        simulated
            .iter()
            .map(|s| (s.nonce, Some(s.gas_limit)))
            .collect()
    };

    let count = calls.len();
    let what = if count == 1 {
        "Send transaction".to_string()
    } else {
        format!("Send {count} transactions, one after another,")
    };
    let prompt = if args.skip_simulation {
        format!("{what} without simulation?")
    } else {
        format!("{what}?")
    };
    if !args.no_confirm && !console.confirm(&prompt, &details) {
        console.line("Aborted");
        return Ok(SendOutcome::EoaAborted);
    }

    let mut txs = Vec::with_capacity(count);
    for (index, (call, (nonce, simulated_gas))) in calls.iter().zip(planned).enumerate() {
        let sent = send_eoa_tx(
            &provider,
            signer,
            chain_id,
            EoaTxPlan {
                index,
                call,
                nonce,
                simulated_gas,
                fees,
            },
            args.fees.timeout,
            console,
        )
        .await;
        match sent {
            Ok(tx) => txs.push(tx),
            Err(source) if txs.is_empty() => return Err(source),
            Err(source) => {
                return Err(SendError::EoaBatchFailed {
                    mined: txs.iter().map(|tx: &EoaTx| tx.tx_hash).collect(),
                    failed_index: index,
                    source: Box::new(source),
                })
            }
        }
    }

    console.emit(&EoaExecutionOutput {
        from,
        txs: txs.clone(),
    });
    Ok(SendOutcome::EoaExecuted { txs })
}

/// One transaction of a send from an EOA, ready to sign.
struct EoaTxPlan<'a> {
    index: usize,
    call: &'a Call,
    nonce: u64,
    /// The gas limit the simulation used, unless it was skipped
    simulated_gas: Option<u64>,
    fees: Eip1559Estimation,
}

/// Signs, broadcasts and waits for one transaction of a send from an EOA.
///
/// The node estimates gas just before signing, when the transactions before
/// this one are mined, and the higher of its estimate and the simulation's is
/// used, as for `execTransaction`.
async fn send_eoa_tx(
    provider: &HttpProvider,
    signer: &PrivateKeySigner,
    chain_id: u64,
    plan: EoaTxPlan<'_>,
    timeout: u64,
    console: &Console,
) -> Result<EoaTx> {
    let from = signer.address();
    let call = plan.call;
    let gas_limit = if let Some(gas) = call.gas_limit {
        gas
    } else {
        let request = <AnyNetwork as Network>::TransactionRequest::default()
            .with_from(from)
            .with_to(call.to)
            .with_value(call.value)
            .with_input(call.data.clone());
        if let Some(simulated) = plan.simulated_gas {
            let estimate = provider
                .estimate_gas(request)
                .await
                .map_err(|e| node_estimate_failed(e, "the transaction"))?;
            cross_check_gas_limit(simulated, estimate + estimate / 5, console)
        } else {
            let estimate = provider
                .estimate_gas(request)
                .await
                .map_err(|e| SendError::other(format!("gas estimation failed: {e}")))?;
            estimate + estimate / 5
        }
    };

    let outer = sign_outer_tx(
        signer,
        OuterTxParams::call(chain_id, from, call, plan.nonce, gas_limit, plan.fees),
    )
    .await?;
    broadcast(provider, outer.tx_hash, &outer.raw, console).await?;
    console.line(format!("Sent {}, waiting for receipt...", outer.tx_hash));
    let receipt = receipt(provider, outer.tx_hash, timeout).await?;
    if !receipt.status() {
        return Err(SendError::EoaTxReverted {
            tx_hash: outer.tx_hash,
            index: plan.index,
        });
    }
    Ok(EoaTx {
        tx_hash: outer.tx_hash,
        gas_used: receipt.gas_used,
        block: receipt.block_number(),
    })
}

async fn dispatch(
    target: Target,
    calls: Vec<Call>,
    opts: SendOpts,
    console: &Console,
) -> Result<SendOutcome> {
    #[cfg(feature = "hd-wallet")]
    if opts.rotate {
        return Box::pin(run_rotating(target, calls, opts, console)).await;
    }
    execute(target, opts, calls, ExecHooks::default(), console).await
}

/// Checks the Safe in the session the simulated transaction was committed to.
/// An error stops the run before anything is signed or broadcast.
pub type PostCheck<'a> = &'a (dyn Fn(&mut ForkSession) -> safe_rs::Result<()> + Sync);

/// What another command adds to the send pipeline.
#[derive(Default)]
pub struct ExecHooks<'a> {
    /// Checked against the simulated post-state
    pub post_check: Option<PostCheck<'a>>,
}

/// Runs `cli_calls` (with `--bundle` and the other flags in `args`) through the
/// Safe: signature collection, simulation, then approveHash, saving to the
/// bundle or execution. Ignores `--rotate`: [`send`] handles it.
pub async fn execute(
    target: Target,
    args: SendOpts,
    cli_calls: Vec<Call>,
    hooks: ExecHooks<'_>,
    console: &Console,
) -> Result<SendOutcome> {
    // 1. Load/Build Calls & Existing Bundle State
    let bundle_existed = args.collect.bundle.as_ref().is_some_and(|p| p.exists());
    let mut bundle = if let Some(bundle_path) = &args.collect.bundle {
        if bundle_path.exists() {
            let mut loaded = BundleFile::load(bundle_path)?;
            if !cli_calls.is_empty() {
                let cli_bundle_calls: Vec<BundleCall> =
                    cli_calls.iter().map(BundleCall::from).collect();
                if loaded.tx.is_none() {
                    loaded.calls.extend(cli_bundle_calls);
                    loaded.save(bundle_path)?;
                } else if loaded.calls != cli_bundle_calls {
                    return Err(SendError::other(format!(
                        "Bundle file {} already has a prepared Safe transaction whose calls differ from the CLI arguments",
                        bundle_path.display()
                    )));
                }
            }
            loaded
        } else {
            if cli_calls.is_empty() {
                return Err(SendError::other(format!(
                    "Bundle file not found: {} (pass calls on the command line to initialize a new bundle)",
                    bundle_path.display()
                )));
            }
            BundleFile::from_calls(&cli_calls)
        }
    } else {
        if cli_calls.is_empty() {
            return Err(SendError::NoCalls);
        }
        BundleFile::from_calls(&cli_calls)
    };

    for merge_path in &args.collect.merge_bundle {
        let other = BundleFile::load(merge_path)?;
        bundle.merge_from_file(&other)?;
    }

    let calls = bundle.calls()?;
    if calls.is_empty() && bundle.tx.is_none() && bundle.rotations.is_empty() {
        return Err(SendError::NoCalls);
    }

    // `--no-submit` without a destination writes the signed transaction to
    // stdout, unless the caller prints its own output.
    let raw_out = args
        .raw
        .raw_out
        .clone()
        .or_else(|| (args.raw.no_submit && console.prints_results()).then(|| "-".to_string()));
    if raw_out.as_deref() == Some("-") {
        console.stdout_carries_data();
    }

    // 2. Inspect Safe State & Resolve Signer / Payer
    let signer_opt = target.signer;
    let payer_opt = create_payer(&args.payer)?;
    let payer = match (&payer_opt, &signer_opt) {
        (Some(p), _) => p.clone(),
        (None, Some(s)) => s.clone(),
        (None, None) => return Err(SendError::NoSigner),
    };
    let from = payer.address();

    let provider = http_provider(&target.rpc_url);
    let chain_id = provider.get_chain_id().await?;
    // A prepared bundle names its Safe, so co-signers need not pass --safe.
    let safe_address = safe_or_default(
        &provider,
        target.safe.or(bundle.tx.as_ref().map(|tx| tx.safe)),
        signer_opt.as_ref(),
        BlockId::latest(),
        console,
    )
    .await?;
    let addresses = chain_addresses(&provider, &args, safe_address).await;
    let config = ChainConfig::with_addresses(chain_id, addresses.clone());

    let sim_block = args.simulate.sim.block.unwrap_or_else(BlockId::latest);
    let state = read_safe_state(
        &provider,
        safe_address,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await?;
    let need = state.threshold.saturating_to::<usize>();
    if need == 0 {
        return Err(SendError::other(format!(
            "Safe {safe_address} returned threshold 0"
        )));
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
                SendError::other(format!(
                    "{e}; pass the address it has on this chain with {flag}"
                ))
            })?;
    }

    let prepared = if let Some(existing) = bundle.prepared_tx()? {
        if existing.chain_id != chain_id {
            return Err(SendError::other(format!(
                "Bundle was prepared for chain {}, but connected RPC is chain {chain_id}",
                existing.chain_id
            )));
        }
        if existing.safe != safe_address {
            return Err(SendError::other(format!(
                "Bundle was prepared for Safe {}, not {safe_address}",
                existing.safe
            )));
        }
        let expected_nonce = args.nonce.unwrap_or(existing.params.nonce);
        if existing.params.nonce != expected_nonce {
            return Err(SendError::other(format!(
                "Bundle was prepared for Safe nonce {}, not {expected_nonce}",
                existing.params.nonce
            )));
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
        if let (false, Some(block)) = (args.skip_simulation, args.simulate.sim.block) {
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
            if args.collect.approve_hash {
                // When approving on-chain, the owner authorizes via approveHash (v = 1)
                // unless they also want an offchain signature in --bundle.
                if args.collect.bundle.is_some() && !offchain_sigs.contains_key(&signer.address()) {
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
    if !signer_is_owner && (args.collect.approve_hash || args.collect.sign_only || have < need) {
        let bad_signer = signer_opt.as_ref().map_or(from, |s| s.address());
        return Err(Error::NotOwner {
            signer: bad_signer,
            safe: safe_address,
        }
        .into());
    }

    // What a confirmation is about: logged now, and handed to the prompt.
    let mut details = format!("Safe: {safe_address}\n");
    if let Some(signer) = &signer_opt {
        details.push_str(&format!("Signer: {}\n", signer.address()));
    }
    if Some(from) != signer_opt.as_ref().map(|s| s.address()) {
        details.push_str(&format!("Payer: {from}\n"));
    }
    details.push_str(&format!(
        "Threshold: {have}/{need} signatures\nNonce: {}\nSafe Tx Hash: {}\n\n{}\n",
        prepared.params.nonce,
        prepared.safe_tx_hash,
        calls_summary(&calls)
    ));
    console.line(&details);

    let fees = outer_fees(
        &provider,
        args.fees.max_fee_per_gas,
        args.fees.max_priority_fee_per_gas,
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
            traces: args
                .simulate
                .trace
                .then(|| result.format_traces())
                .flatten(),
            signatures_collected: Some(have),
            threshold: Some(need),
            ready_to_execute: Some(have >= need),
        };
        if !result.success {
            // A host only sees the error: show it the traces too.
            console.emit_or_line(&report);
        } else if args.simulate.simulate_only {
            console.emit(&report);
        } else {
            console.line(report.human());
            console.line("");
        }
        if !result.success {
            return Err(SendError::SimulationFailed {
                reason: result
                    .revert_reason
                    .clone()
                    .unwrap_or_else(|| "unknown reason".to_string()),
            });
        }
        if args.simulate.simulate_only {
            return Ok(SendOutcome::Simulated {
                safe_tx_hash: prepared.safe_tx_hash,
                gas_used: result.gas_used,
            });
        }
        Some((simulated.payer_nonce, simulated.gas_limit))
    };

    // 5. Smart Action Branching
    // Branch A: --approve-hash
    if args.collect.approve_hash {
        let signer = signer_opt.as_ref().ok_or_else(|| {
            SendError::other("--approve-hash requires an owner wallet (--private-key, --keystore, or --interactive)")
        })?;
        let approver = signer.address();
        let bundle_path_str = if let Some(bundle_path) = &args.collect.bundle {
            bundle.merge(&prepared, &offchain_sigs, &[])?;
            bundle.save(bundle_path)?;
            Some(bundle_path.display().to_string())
        } else {
            None
        };

        let (approve_nonce, approve_gas) = if args.skip_simulation {
            let nonce = provider.get_transaction_count(approver).await?;
            let gas = if let Some(g) = args.fees.gas_limit {
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
            let session =
                fork_session(provider.clone(), chain_id, &args.simulate.sim, false).await?;
            let sim = simulate_approve_hash(
                &session,
                chain_id,
                safe_address,
                prepared.safe_tx_hash,
                approver,
                fees,
                args.fees.gas_limit,
            )?;
            if !sim.result.success {
                return Err(SendError::ApproveHashSimulationFailed {
                    reason: sim
                        .result
                        .revert_reason
                        .unwrap_or_else(|| "unknown reason".to_string()),
                });
            }
            let gas = if args.fees.gas_limit.is_some() {
                sim.gas_limit
            } else {
                let tx = <AnyNetwork as Network>::TransactionRequest::default()
                    .with_from(approver)
                    .with_to(safe_address)
                    .with_input(SignedSafeTx::approve_hash_calldata(prepared.safe_tx_hash));
                let est = provider
                    .estimate_gas(tx)
                    .await
                    .map_err(|e| node_estimate_failed(e, "approveHash"))?;
                cross_check_gas_limit(sim.gas_limit, est + est / 5, console)
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
        if !args.no_confirm && !console.confirm(&prompt, &details) {
            console.line("Aborted");
            return Ok(SendOutcome::Aborted {
                safe_tx_hash: prepared.safe_tx_hash,
            });
        }

        broadcast(&provider, outer.tx_hash, &outer.raw, console).await?;
        console.line(format!("Sent {}, waiting for receipt...", outer.tx_hash));
        let receipt = receipt(&provider, outer.tx_hash, args.fees.timeout).await?;

        let success = receipt.status();
        console.emit(&ApproveHashOutput {
            tx_hash: outer.tx_hash,
            success,
            gas_used: receipt.gas_used,
            safe_tx_hash: prepared.safe_tx_hash,
            safe_nonce: prepared.params.nonce,
            approver,
            signatures_collected: have,
            threshold: need,
            bundle_path: bundle_path_str,
        });
        if !success {
            return Err(SendError::ApproveHashReverted {
                tx_hash: outer.tx_hash,
            });
        }
        return Ok(SendOutcome::HashApproved {
            tx_hash: outer.tx_hash,
            safe_tx_hash: prepared.safe_tx_hash,
            gas_used: receipt.gas_used,
            block: receipt.block_number(),
        });
    }

    // Branch B: Offchain signature collection (`have < need` or `--sign-only`)
    if have < need || args.collect.sign_only {
        let Some(bundle_path) = &args.collect.bundle else {
            return Err(SendError::BelowThreshold { have, need });
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
        console.emit(&BundleSavedOutput {
            safe_tx_hash: prepared.safe_tx_hash,
            safe_nonce: prepared.params.nonce,
            signatures_collected: have,
            threshold: need,
            signers,
            remaining_owners,
            bundle_path: bundle_path.display().to_string(),
        });
        return Ok(SendOutcome::Signed {
            safe_tx_hash: prepared.safe_tx_hash,
            safe_nonce: prepared.params.nonce,
            signatures: have,
            threshold: need,
            bundle: bundle_path.clone(),
        });
    }

    // Branch C: Threshold met (`have >= need`) -> Execute `execTransaction`
    if !args.raw.no_submit {
        if let Some(bundle_path) = &args.collect.bundle {
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
        let gas_limit = if args.fees.gas_limit.is_some() {
            simulated
        } else {
            let est = provider
                .estimate_gas(exec_request(&exec_signed, from))
                .await
                .map_err(|e| node_estimate_failed(e, "execTransaction"))?;
            cross_check_gas_limit(simulated, est + est / 5, console)
        };
        (nonce, gas_limit)
    } else {
        let nonce = provider.get_transaction_count(from).await?;
        let gas_limit = if let Some(gas) = args.fees.gas_limit {
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
            .map_err(|e| SendError::other(format!("cannot write {dest}: {e}")))?;
        if dest != "-" {
            console.line(format!("Signed transaction written to {dest}"));
        }
    }

    if args.raw.no_submit {
        if raw_out.as_deref() == Some("-") {
            console.emit_human(&document);
        } else {
            console.emit(&document);
        }
        return Ok(SendOutcome::NotSubmitted {
            tx_hash: outer.tx_hash,
            safe_tx_hash: prepared.safe_tx_hash,
            raw: outer.raw.clone(),
        });
    }

    let prompt = if args.skip_simulation {
        format!("Execute transaction without simulation ({have}/{need} signatures)?")
    } else if need > 1 {
        format!("Execute transaction ({have}/{need} signatures)?")
    } else {
        "Execute transaction?".to_string()
    };
    if !args.no_confirm && !console.confirm(&prompt, &details) {
        console.line("Aborted");
        return Ok(SendOutcome::Aborted {
            safe_tx_hash: prepared.safe_tx_hash,
        });
    }

    broadcast(&provider, outer.tx_hash, &outer.raw, console).await?;
    console.line(format!("Sent {}, waiting for receipt...", outer.tx_hash));
    let receipt = receipt(&provider, outer.tx_hash, args.fees.timeout).await?;
    let outcome = safe_outcome_for_receipt(&receipt, safe_address, prepared.safe_tx_hash)?;

    console.emit(&ExecutionOutput {
        tx_hash: outer.tx_hash,
        success: outcome.is_success(),
        gas_used: receipt.gas_used,
        safe_tx_hash: Some(prepared.safe_tx_hash),
        outcome: Some(outcome.label()),
    });
    if !outcome.is_success() {
        return Err(SendError::SafeTxFailed {
            tx_hash: outer.tx_hash,
            outcome: outcome.label(),
        });
    }

    Ok(SendOutcome::Executed {
        tx_hash: outer.tx_hash,
        safe_tx_hash: prepared.safe_tx_hash,
        gas_used: receipt.gas_used,
        block: receipt.block_number(),
    })
}

/// `send --rotate`: the user's calls followed by a swap of the owner for the HD
/// wallet's next unused key, then a sweep of the old key's ETH.
#[cfg(feature = "hd-wallet")]
async fn run_rotating(
    target: Target,
    cli_calls: Vec<Call>,
    args: SendOpts,
    console: &Console,
) -> Result<SendOutcome> {
    let mut bundle_safe = None;
    let calls = if let Some(bundle_path) = &args.collect.bundle {
        if bundle_path.exists() {
            let loaded = BundleFile::load(bundle_path)?;
            bundle_safe = loaded.tx.as_ref().map(|tx| tx.safe);
            let loaded_calls = loaded.calls()?;
            let cli_bundle_calls: Vec<BundleCall> =
                cli_calls.iter().map(BundleCall::from).collect();
            if !cli_calls.is_empty() && loaded.tx.is_some() && loaded.calls != cli_bundle_calls {
                return Err(SendError::other(format!(
                    "Bundle file {} already has a prepared Safe transaction whose calls differ from the CLI arguments",
                    bundle_path.display()
                )));
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
        return Err(SendError::NoCalls);
    }
    let payer = create_payer(&args.payer)?;
    let ring = open_wallet(&args.hd, &args.password, target.home.as_deref(), console).await?;
    let safe = if let Some(safe) = target.safe.or(bundle_safe) {
        safe
    } else {
        let chain_id = http_provider(&target.rpc_url).get_chain_id().await?;
        recorded_safe(ring.state(), chain_id, "--safe")?
    };
    rotation::run(RotationRun {
        rpc_url: &target.rpc_url,
        safe,
        ring,
        legacy_owner: None,
        sweep_legacy: false,
        payer,
        sweep: &args.sweep,
        calls,
        multi_send_call_only: args.multi_send_call_only,
        sim: &args.simulate.sim,
        gas_limit: args.fees.gas_limit,
        max_fee_per_gas: args.fees.max_fee_per_gas,
        max_priority_fee_per_gas: args.fees.max_priority_fee_per_gas,
        timeout: args.fees.timeout,
        trace: args.simulate.trace,
        simulate_only: args.simulate.simulate_only,
        raw_out: args.raw.raw_out.clone(),
        no_submit: args.raw.no_submit,
        no_confirm: args.no_confirm,
        bundle: args.collect.bundle.clone(),
        merge_bundle: args.collect.merge_bundle.clone(),
        approve_hash: args.collect.approve_hash,
        sign_only: args.collect.sign_only,
        console,
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
    let session = fork_session(provider.clone(), chain_id, &args.simulate.sim, true).await?;
    Ok(simulate_exec_with_threshold(
        &session,
        signed,
        owners,
        threshold,
        from,
        fees,
        args.fees.gas_limit,
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
            SendError::other(
                "the inner Safe transaction reverts (GS013); run without --skip-simulation to see why",
            )
        } else {
            SendError::other(format!("gas estimation failed: {reason}"))
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
fn cross_check_gas_limit(simulated: u64, node: u64, console: &Console) -> u64 {
    let (gas_limit, warning) = reconcile_gas_limits(simulated, node);
    if let Some(warning) = warning {
        console.warn(warning);
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
fn node_estimate_failed(error: impl fmt::Display, what: &str) -> SendError {
    SendError::other(format!(
        "the simulation succeeded but the node's gas estimate for {what} failed, so the \
         transaction would likely revert on chain (the local EVM may not match the chain's \
         current fork); pass --gas-limit to send it anyway: {error}"
    ))
}

/// Broadcasts a signed transaction. A node that already knew it counts as
/// sent.
pub(crate) async fn broadcast(
    provider: &HttpProvider,
    tx_hash: B256,
    raw: &Bytes,
    console: &Console,
) -> Result<()> {
    match broadcast_raw(provider, raw, tx_hash).await {
        BroadcastOutcome::Accepted(_) => Ok(()),
        BroadcastOutcome::AlreadyKnown(_) => {
            console.line("Node already knew the transaction");
            Ok(())
        }
        BroadcastOutcome::Rejected { reason, class } => Err(BroadcastError::Rejected {
            tx_hash,
            reason,
            class,
        }
        .into()),
        BroadcastOutcome::Ambiguous { reason } => {
            Err(BroadcastError::Ambiguous { tx_hash, reason }.into())
        }
    }
}

/// Waits up to `timeout_secs` for the receipt of a broadcast transaction.
pub(crate) async fn receipt(
    provider: &HttpProvider,
    tx_hash: B256,
    timeout_secs: u64,
) -> Result<Box<<AnyNetwork as Network>::ReceiptResponse>> {
    let timeout = Duration::from_secs(timeout_secs);
    match wait_for_receipt(provider, tx_hash, timeout, RECEIPT_POLL_INTERVAL).await? {
        ReceiptWait::Mined(receipt) => Ok(receipt),
        ReceiptWait::TimedOut { tx_hash } => Err(BroadcastError::ReceiptTimeout {
            tx_hash,
            timeout_secs,
        }
        .into()),
    }
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

fn build_cli_calls(args: &SendArgs) -> eyre::Result<Vec<Call>> {
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
