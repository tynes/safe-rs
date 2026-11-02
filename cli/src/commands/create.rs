//! `safe create`, and [`create`] for a CLI that deploys Safes itself.
//!
//! [`CreateOpts`] leaves out `--rpc-url` and the signer, which the caller
//! resolves into a [`CreateContext`], so it flattens into another CLI's
//! command without clashing with that CLI's own flags.

use std::fmt::{self, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::network::{AnyNetwork, Network, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use clap::{Args, Parser};
use color_eyre::eyre::eyre;
use safe_rs::{
    is_safe_with, sign_outer_tx, submit_and_wait, OuterTxParams, SignedOuterTx, Submission,
};

pub use implementation::{
    BoxFuture, HttpProvider, Implementation, ResolvedSetup, SafeDeployment, SafeImplementation,
    StandardSafe,
};
use serde::Serialize;
use url::Url;

use crate::any_signer::AnySigner;
use crate::cli::{FeeArgs, SafeSetupArgs};
use crate::cli::{GasPayerArgs, RpcArgs, SignerArgs};
use crate::cli::{OwnerKeysArgs, SweepArgs};
use crate::commands::{http_provider, outer_fees, with_gas_margin, RECEIPT_POLL_INTERVAL};
use crate::console::Console;
pub use crate::error::CreateError;
use crate::error::{short_ether, BroadcastError, OptionsError};
use crate::log::{Level, Logger, NoopLogger};
use crate::output::{CreateOutput, Report};
pub use crate::output::{OwnerKey, SweptEth};
use crate::prompt::{Prompt, TerminalPrompt};
use crate::signers::{create_payer, create_signer};
use crate::RunConfig;

mod implementation;
mod rotating;

pub use rotating::{parse_same_as, SameAs};

/// How `safe create` deploys: the Safe's setup, fees, and the mnemonic wallet that
/// owns it. Leaves out `--rpc-url` and the signer.
///
/// [`Default`] matches the flag defaults.
#[derive(Args, Clone, Debug, Default)]
pub struct CreateOpts {
    #[command(flatten)]
    pub setup: SafeSetupArgs,

    /// Only compute and display the address, don't deploy
    #[arg(long)]
    pub compute_only: bool,

    /// Skip confirmation prompt
    #[arg(long)]
    pub no_confirm: bool,

    #[command(flatten)]
    pub fees: FeeArgs,

    /// When the account that pays holds too little ETH, wait for it to be
    /// funded instead of failing: `--wait-for-funds` waits without a limit,
    /// `--wait-for-funds=SECS` gives up after SECS seconds. With --rotate, no
    /// wallet key is used until the funds arrive
    #[arg(
        long,
        value_name = "SECS",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "0"
    )]
    pub wait_for_funds: Option<u64>,

    /// Deploy the same Safe a mnemonic wallet created on another chain, given as
    /// <CHAIN_ID>:<SAFE>. Reuses its first owner key and salt, so that key
    /// must be rotated right away
    #[arg(
        long,
        value_name = "CHAIN_ID:SAFE",
        value_parser = parse_same_as,
        conflicts_with_all = ["owners", "threshold", "salt_nonce", "safe_version", "singleton", "factory", "fallback_handler"]
    )]
    pub same_as: Option<SameAs>,

    /// Create a Safe whose owner key rotates: its first owner is the next
    /// unused key of --mnemonic or --ledger, used once and then replaced
    #[arg(long)]
    pub rotate: bool,

    /// The mnemonic wallet or Ledger the rotating owner keys come from. Not flags
    /// of its own: `--mnemonic` / `--ledger` (and the password) fill it under
    /// `--rotate`, see [`SignerArgs::take_rotation_keys`]
    #[arg(skip)]
    pub owner_keys: OwnerKeysArgs,

    #[command(flatten)]
    pub sweep: SweepArgs,

    #[command(flatten)]
    pub gas_payer: GasPayerArgs,

    /// How the Safe is deployed (default: the standard Safe proxy factory).
    /// Not a flag: a CLI whose Safes come from another factory sets it in
    /// code. Not supported with `--rotate`.
    #[arg(skip)]
    pub implementation: Implementation,
}

impl CreateOpts {
    /// Deploys with `implementation` instead of the standard Safe proxy
    /// factory.
    pub fn with_implementation(
        mut self,
        implementation: impl SafeImplementation + 'static,
    ) -> Self {
        self.implementation = Implementation::custom(implementation);
        self
    }

    /// The flag conflicts clap enforces, checked again for options built in
    /// code, then: `--rotate` needs `--mnemonic` or `--ledger` and refuses a
    /// signer, the rotating keys need `--rotate` (without a signer), and
    /// `--same-as`, `--no-sweep` and `--sweep-reserve` need `--rotate`.
    pub fn validate(&self, has_signer: bool) -> Result<(), OptionsError> {
        let setup = &self.setup;
        let defaults = SafeSetupArgs::default();
        if self.same_as.is_some() {
            let set = [
                (!setup.owners.is_empty(), "--owner"),
                (setup.threshold != defaults.threshold, "--threshold"),
                (setup.salt_nonce != defaults.salt_nonce, "--salt-nonce"),
                (
                    setup.safe_version != defaults.safe_version,
                    "--safe-version",
                ),
                (setup.singleton.is_some(), "--singleton"),
                (setup.factory.is_some(), "--factory"),
                (setup.fallback_handler.is_some(), "--fallback-handler"),
            ];
            if let Some((_, with)) = set.into_iter().find(|(set, _)| *set) {
                return Err(OptionsError::Conflict {
                    flag: "--same-as",
                    with,
                });
            }
        }
        if self.sweep.no_sweep && self.sweep.sweep_reserve.is_some() {
            return Err(OptionsError::Conflict {
                flag: "--sweep-reserve",
                with: "--no-sweep",
            });
        }
        if !self.rotate && self.owner_keys.is_set() && !has_signer {
            return Err(OptionsError::CreateOwnerKeysWithoutRotate);
        }
        if self.rotate {
            if !self.owner_keys.is_set() {
                return Err(OptionsError::RotateWithoutKeys);
            }
            if has_signer {
                return Err(OptionsError::SignerWithOwnerKeys);
            }
            if !self.implementation.is_standard() {
                return Err(OptionsError::Conflict {
                    flag: "a custom Safe implementation",
                    with: "--rotate",
                });
            }
        } else if self.same_as.is_some() {
            return Err(OptionsError::RotateOnly { flag: "--same-as" });
        } else if self.sweep.no_sweep {
            return Err(OptionsError::RotateOnly { flag: "--no-sweep" });
        } else if self.sweep.sweep_reserve.is_some() {
            return Err(OptionsError::RotateOnly {
                flag: "--sweep-reserve",
            });
        }
        Ok(())
    }

    /// Whether the owner comes from a mnemonic wallet or Ledger (`--rotate`).
    pub fn rotates(&self) -> bool {
        self.rotate
    }
}

/// `safe create`: [`CreateOpts`] plus `--rpc-url` and the signer.
#[derive(Parser, Clone, Debug)]
pub struct CreateArgs {
    #[command(flatten)]
    pub rpc: RpcArgs,

    #[command(flatten)]
    pub opts: CreateOpts,

    #[command(flatten)]
    pub signer: SignerArgs,
}

/// What a CLI embedding [`CreateOpts`] resolves itself: the RPC, the first
/// owner, and where progress and questions go.
#[derive(Clone)]
#[non_exhaustive]
pub struct CreateContext {
    /// RPC endpoint of the chain to deploy on
    pub rpc_url: Url,
    /// First owner and deployer (unless a `--gas-payer-*` key pays). `None`
    /// with `--rotate`, where the owner is the wallet's next
    /// unused key.
    pub signer: Option<AnySigner>,
    /// Where progress and warnings go (default: nowhere)
    pub logger: Arc<dyn Logger>,
    /// What asks for confirmation and passwords (default: the terminal)
    pub prompt: Arc<dyn Prompt>,
    /// Where mnemonic wallets and their state live (default: `$SAFE_RS_HOME` or
    /// `~/.safe-rs`)
    pub home: Option<PathBuf>,
}

impl CreateContext {
    /// A deployment over `rpc_url`, with no signer, a silent [`NoopLogger`]
    /// and a [`TerminalPrompt`].
    pub fn new(rpc_url: Url) -> Self {
        Self {
            rpc_url,
            signer: None,
            logger: Arc::new(NoopLogger),
            prompt: Arc::new(TerminalPrompt::new()),
            home: None,
        }
    }

    pub fn with_signer(mut self, signer: impl Into<AnySigner>) -> Self {
        self.signer = Some(signer.into());
        self
    }

    /// Sends progress and warnings to `logger`.
    pub fn with_logger(mut self, logger: impl Logger + 'static) -> Self {
        self.logger = Arc::new(logger);
        self
    }

    /// Asks `prompt` for the confirmation and any password.
    pub fn with_prompt(mut self, prompt: impl Prompt + 'static) -> Self {
        self.prompt = Arc::new(prompt);
        self
    }

    /// Looks for mnemonic wallets and their state under `home`.
    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home = Some(home);
        self
    }

    fn console(&self) -> Console {
        Console::new(self.logger.clone(), self.prompt.clone())
    }

    /// Logs to and asks what `console` does.
    pub(crate) fn with_console(mut self, console: &Console) -> Self {
        self.logger = console.logger().clone();
        self.prompt = console.prompt().clone();
        self
    }
}

impl fmt::Debug for CreateContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateContext")
            .field("rpc_url", &self.rpc_url.as_str())
            .field("signer", &self.signer.as_ref().map(|s| s.address()))
            .finish_non_exhaustive()
    }
}

/// How a create ended. Failures are [`CreateError`]s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CreateOutcome {
    /// `--compute-only`: nothing was sent or reserved. `deployed` says
    /// whether a Safe is already there.
    Computed {
        safe: Address,
        owners: Vec<Address>,
        threshold: u64,
        deployed: bool,
        /// The mnemonic wallet key that would own the Safe
        owner_key: Option<OwnerKey>,
        /// The account that would pay, with `--rotate`
        payer: Option<Address>,
    },
    /// A Safe with this setup already exists, so no deployment was sent. With
    /// a mnemonic wallet the Safe is still recorded in the wallet, and sweeps owed
    /// from earlier runs are sent.
    AlreadyDeployed {
        safe: Address,
        owners: Vec<Address>,
        threshold: u64,
        owner_key: Option<OwnerKey>,
        /// The account that would have paid, with `--rotate`
        payer: Option<Address>,
        sweep: Option<SweptEth>,
        warnings: Vec<String>,
    },
    /// The confirmation was declined. Nothing was sent or reserved.
    Aborted { safe: Address },
    /// The Safe was deployed.
    Deployed {
        safe: Address,
        tx_hash: B256,
        owners: Vec<Address>,
        threshold: u64,
        /// The account that sent and paid for the deployment
        payer: Address,
        /// The mnemonic wallet key that owns the Safe
        owner_key: Option<OwnerKey>,
        /// ETH moved from the funding key to the owner key
        sweep: Option<SweptEth>,
        warnings: Vec<String>,
    },
}

impl CreateOutcome {
    /// The Safe this is about.
    pub fn safe(&self) -> Address {
        match self {
            Self::Computed { safe, .. }
            | Self::AlreadyDeployed { safe, .. }
            | Self::Aborted { safe }
            | Self::Deployed { safe, .. } => *safe,
        }
    }
}

impl Report for CreateOutcome {
    fn human(&self) -> String {
        document(self).map_or_else(
            || format!("Aborted: Safe {} was not deployed", self.safe()),
            |doc| doc.human(),
        )
    }
}

/// What `safe create` prints for an outcome, as it always has: the
/// rotating document when a mnemonic wallet key owns the Safe, else the plain one.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Document {
    Plain(CreateOutput),
    Rotating(rotating::RotatingCreateOutput),
}

impl Report for Document {
    fn human(&self) -> String {
        match self {
            Self::Plain(doc) => doc.human(),
            Self::Rotating(doc) => doc.human(),
        }
    }
}

pub(crate) fn document(outcome: &CreateOutcome) -> Option<Document> {
    let none = Vec::new();
    let (safe, tx_hash, owners, threshold, already_deployed, owner_key, payer, sweep, warnings) =
        match outcome {
            CreateOutcome::Computed {
                safe,
                owners,
                threshold,
                deployed,
                owner_key,
                payer,
            } => (
                *safe, None, owners, *threshold, *deployed, *owner_key, *payer, None, &none,
            ),
            CreateOutcome::AlreadyDeployed {
                safe,
                owners,
                threshold,
                owner_key,
                payer,
                sweep,
                warnings,
            } => (
                *safe, None, owners, *threshold, true, *owner_key, *payer, *sweep, warnings,
            ),
            CreateOutcome::Deployed {
                safe,
                tx_hash,
                owners,
                threshold,
                payer,
                owner_key,
                sweep,
                warnings,
            } => (
                *safe,
                Some(*tx_hash),
                owners,
                *threshold,
                false,
                *owner_key,
                Some(*payer),
                *sweep,
                warnings,
            ),
            CreateOutcome::Aborted { .. } => return None,
        };
    Some(match (owner_key, payer) {
        (Some(owner), Some(payer)) => Document::Rotating(rotating::RotatingCreateOutput {
            safe_address: safe,
            tx_hash,
            owner,
            owners: owners.clone(),
            threshold,
            already_deployed,
            payer,
            sweep,
            warnings: warnings.clone(),
        }),
        _ => Document::Plain(CreateOutput {
            safe_address: safe,
            tx_hash,
            owners: owners.clone(),
            threshold,
            already_deployed,
        }),
    })
}

/// Deploys a Safe as `safe create` does, with every option in `opts`.
///
/// The address is computed from the first owner (the signer, or with
/// `--rotate` the wallet's next unused key), the `--owner`s,
/// the threshold, the salt and the contracts, so the same options give the
/// same Safe on every chain. Options built in code are checked for the same
/// conflicts clap enforces on the flags.
pub async fn create(ctx: CreateContext, opts: CreateOpts) -> Result<CreateOutcome, CreateError> {
    let console = ctx.console();
    create_with(ctx, opts, &console).await
}

pub(crate) async fn create_with(
    ctx: CreateContext,
    opts: CreateOpts,
    console: &Console,
) -> Result<CreateOutcome, CreateError> {
    opts.validate(ctx.signer.is_some())?;
    if opts.rotates() {
        return Box::pin(rotating::create(ctx, opts, console)).await;
    }
    let signer = ctx.signer.ok_or(CreateError::NoSigner)?;
    let first = signer.address();
    opts.setup
        .validate(first)
        .map_err(CreateError::InvalidSetup)?;
    let setup = opts.setup.resolve(first);

    let provider = http_provider(&ctx.rpc_url);
    let implementation = opts.implementation.get();
    let plan = implementation.plan(&provider, &setup, &signer).await?;
    let payer = create_payer(&opts.gas_payer, console)
        .await
        .map_err(CreateError::Other)?
        .unwrap_or(signer);
    let safe = plan.safe;
    let mut details = String::from("Computing Safe address...\n");
    if !opts.implementation.is_standard() {
        let _ = writeln!(details, "  Implementation: {}", implementation.name());
    }
    let _ = writeln!(details, "  Factory: {}", plan.to);
    let _ = writeln!(details, "  Singleton: {}", plan.singleton);
    if opts.implementation.is_standard() {
        let _ = writeln!(details, "  Salt Nonce: {}", setup.salt_nonce);
    }
    let _ = writeln!(details, "  Owners: {:?}", plan.owners);
    let _ = writeln!(details, "  Threshold: {}", plan.threshold);
    if payer.address() != first {
        let _ = writeln!(details, "  Payer: {}", payer.address());
    }
    console.line(&details);

    let deployed = is_safe_with(&provider, safe, &[plan.singleton]).await?;
    if opts.compute_only {
        return Ok(CreateOutcome::Computed {
            safe,
            owners: plan.owners,
            threshold: plan.threshold,
            deployed,
            owner_key: None,
            payer: None,
        });
    }
    if deployed {
        console.line(format!("Safe already deployed at {safe}"));
        return Ok(CreateOutcome::AlreadyDeployed {
            safe,
            owners: plan.owners,
            threshold: plan.threshold,
            owner_key: None,
            payer: None,
            sweep: None,
            warnings: Vec::new(),
        });
    }

    console.line(format!("Safe Address: {safe}\n"));
    let _ = write!(details, "  Safe Address: {safe}");
    if !opts.no_confirm && !console.confirm("Deploy new Safe?", &details) {
        console.line("Aborted");
        return Ok(CreateOutcome::Aborted { safe });
    }

    let chain_id = provider.get_chain_id().await?;
    let tx = || {
        deployment_tx(
            &provider,
            chain_id,
            payer.address(),
            plan.to,
            plan.input.clone(),
            &opts.fees,
        )
    };
    let mut params = tx().await?;
    let funding = Payer {
        label: "the deployer",
        sweeps: false,
        resume: None,
    };
    if ensure_funds(&provider, &params, opts.wait_for_funds, &funding, console).await? {
        // Fees may have moved while waiting.
        params = tx().await?;
    }
    let outer = sign_outer_tx(&payer, params).await?;
    let tx_hash = submit(&provider, &outer, safe, opts.fees.timeout, console).await?;
    if !is_safe_with(&provider, safe, &[plan.singleton]).await? {
        return Err(CreateError::NotDeployed { safe, tx_hash });
    }
    Ok(CreateOutcome::Deployed {
        safe,
        tx_hash,
        owners: plan.owners,
        threshold: plan.threshold,
        payer: payer.address(),
        owner_key: None,
        sweep: None,
        warnings: Vec::new(),
    })
}

/// The unsigned deployment transaction calling `to` with `input`, sent by
/// `from`, with the `--gas-limit` and fee overrides applied.
pub(crate) async fn deployment_tx(
    provider: &HttpProvider,
    chain_id: u64,
    from: Address,
    to: Address,
    input: Bytes,
    fees: &FeeArgs,
) -> Result<OuterTxParams, CreateError> {
    let gas_limit = if let Some(gas) = fees.gas_limit {
        gas
    } else {
        let request = <AnyNetwork as Network>::TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_input(input.clone());
        let estimate = provider
            .estimate_gas(request)
            .await
            .map_err(|e| eyre!("cannot estimate the deployment ({from} may need ETH): {e}"))?;
        with_gas_margin(estimate)
    };
    let estimated = outer_fees(
        provider,
        fees.max_fee_per_gas,
        fees.max_priority_fee_per_gas,
    )
    .await?;
    Ok(OuterTxParams {
        chain_id,
        from,
        nonce: provider.get_transaction_count(from).await?,
        gas_limit,
        max_fee_per_gas: estimated.max_fee_per_gas,
        max_priority_fee_per_gas: estimated.max_priority_fee_per_gas,
        to,
        value: U256::ZERO,
        input,
    })
}

/// How often the payer's balance is read under `--wait-for-funds`.
const FUNDS_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Gas set aside for the Safe's first rotating send, for the amount
/// suggested when the funding key pays and sweeps the rest to the owner.
const FIRST_SEND_GAS: u64 = 300_000;

/// Who pays for a deployment, for the funding messages.
pub(crate) struct Payer<'a> {
    /// "the funding address" or "the deployer"
    pub label: &'a str,
    /// Whether what is left moves to the Safe's owner key afterwards, so a
    /// little more than the deployment is worth sending
    pub sweeps: bool,
    /// With --rotate, before a new owner key is used: the command that
    /// creates the same Safe later, so stopping the wait is safe
    pub resume: Option<String>,
}

/// Checks that `params.from` holds what `params` can cost. Without `wait`,
/// fails with [`CreateError::NeedsFunding`]; with it, says how much to send
/// and polls the balance until it is there, or until `wait` seconds pass
/// (`0`: no limit). Returns whether it waited.
pub(crate) async fn ensure_funds(
    provider: &HttpProvider,
    params: &OuterTxParams,
    wait: Option<u64>,
    payer: &Payer<'_>,
    console: &Console,
) -> Result<bool, CreateError> {
    let needed = U256::from(params.gas_limit) * U256::from(params.max_fee_per_gas) + params.value;
    let mut balance = provider.get_balance(params.from).await?;
    if balance >= needed {
        return Ok(false);
    }
    let needs_funding = |balance| CreateError::NeedsFunding {
        payer: params.from,
        chain_id: params.chain_id,
        needed,
        balance,
    };
    let Some(limit) = wait else {
        return Err(needs_funding(balance));
    };

    let address = params.from;
    let chain_id = params.chain_id;
    if console.logger().enabled(Level::Info) {
        let mut s = format!(
            "Send at least {} ETH to {} ({address}) on chain {chain_id}.",
            short_ether(needed - balance),
            payer.label
        );
        if payer.sweeps {
            let first_send = U256::from(FIRST_SEND_GAS) * U256::from(params.max_fee_per_gas);
            let _ = write!(
                s,
                "\n  Recommended: {} ETH. What is left after the deployment moves to the Safe's \
                 owner key and pays for its next transactions.",
                short_ether(needed + first_send - balance)
            );
        }
        let _ = write!(s, "\nWaiting for funds");
        if limit > 0 {
            let _ = write!(s, " (up to {limit}s)");
        }
        s.push_str("...");
        if let Some(resume) = &payer.resume {
            let _ = write!(
                s,
                "\nCtrl-C is safe: no wallet key has been used yet, and `{resume}` with the \
                 same options creates the same Safe later."
            );
        }
        console.line(s);
    } else {
        console.warn(format!(
            "waiting for {address} to hold {} ETH on chain {chain_id}",
            short_ether(needed)
        ));
    }

    let deadline = (limit > 0).then(|| std::time::Instant::now() + Duration::from_secs(limit));
    loop {
        tokio::time::sleep(FUNDS_POLL_INTERVAL).await;
        balance = provider.get_balance(address).await?;
        if balance >= needed {
            console.line(format!("  {address} holds {} ETH", short_ether(balance)));
            return Ok(true);
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(needs_funding(balance));
        }
    }
}

/// Broadcasts the signed deployment of `safe` and waits up to `timeout`
/// seconds for it to be mined.
pub(crate) async fn submit(
    provider: &HttpProvider,
    outer: &SignedOuterTx,
    safe: Address,
    timeout: u64,
    console: &Console,
) -> Result<B256, CreateError> {
    let tx_hash = outer.tx_hash;
    console.line(format!("Sent {tx_hash}, waiting for receipt..."));
    let submission = submit_and_wait(
        provider,
        outer,
        Duration::from_secs(timeout),
        RECEIPT_POLL_INTERVAL,
    )
    .await?;
    let error = match submission {
        Submission::Mined(receipt) if receipt.inner.inner.status() => return Ok(tx_hash),
        Submission::Mined(_) => return Err(CreateError::Reverted { safe, tx_hash }),
        Submission::TimedOut { tx_hash } => BroadcastError::ReceiptTimeout {
            tx_hash,
            timeout_secs: timeout,
        },
        Submission::Rejected { reason, class } => BroadcastError::Rejected {
            tx_hash,
            reason,
            class,
        },
        Submission::Ambiguous { reason } => BroadcastError::Ambiguous { tx_hash, reason },
    };
    if error.may_be_pending() {
        console.warn(format!(
            "the deployment {tx_hash} may still be mined; once it is, check for the Safe at \
             {safe} before retrying"
        ));
    }
    Err(CreateError::Broadcast { safe, error })
}

/// `safe create`: resolves the signer, calls [`create`], and prints the
/// outcome as `safe` does (JSON with `config.json`).
pub async fn run(args: CreateArgs, config: &RunConfig) -> color_eyre::Result<()> {
    let json = config.json;
    config
        .console()
        .printing(json, |console| async move {
            run_with(args, &console, json).await
        })
        .await
}

pub(crate) async fn run_with(
    mut args: CreateArgs,
    console: &Console,
    json: bool,
) -> color_eyre::Result<()> {
    // `--json` never prompts: it is the result document's only output.
    args.opts.no_confirm |= json;
    // With --rotate, --mnemonic or --ledger names where the rotating owner
    // keys come from.
    if args.opts.rotate {
        args.opts.owner_keys = args.signer.take_rotation_keys()?;
    }
    // Checked before any key or password prompt.
    args.opts.validate(args.signer.is_set())?;
    let signer = if args.opts.rotates() {
        None
    } else {
        Some(create_signer(&args.signer, console).await?)
    };
    let ctx = CreateContext {
        signer,
        ..CreateContext::new(args.rpc.rpc_url)
    }
    .with_console(console);
    let outcome = create_with(ctx, args.opts, console).await?;
    if let Some(doc) = document(&outcome) {
        console.emit(&doc);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SafeVersion;
    use clap::CommandFactory;
    use safe_rs::predict_safe_address;

    #[test]
    fn the_create_flags_are_consistent() {
        CreateArgs::command().debug_assert();
    }

    #[test]
    fn wait_for_funds_takes_an_optional_limit() {
        let parse = |extra: &[&str]| {
            let args = ["create", "--rpc-url", "http://localhost:8545"];
            CreateArgs::try_parse_from(args.iter().chain(extra))
                .unwrap()
                .opts
                .wait_for_funds
        };
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["--wait-for-funds"]), Some(0), "no limit");
        assert_eq!(parse(&["--wait-for-funds=30"]), Some(30));
    }

    #[test]
    fn defaults_match_the_flag_defaults() {
        let parsed =
            CreateArgs::try_parse_from(["create", "--rpc-url", "http://localhost:8545"]).unwrap();
        assert_eq!(parsed.opts.setup, SafeSetupArgs::default());
        assert_eq!(parsed.opts.fees, FeeArgs::default());
        assert!(!parsed.opts.compute_only && !parsed.opts.no_confirm);
        CreateOpts::default().validate(true).unwrap();
    }

    #[test]
    fn owners_put_the_first_owner_first_without_duplicates() {
        let first = Address::repeat_byte(1);
        let (a, b) = (Address::repeat_byte(2), Address::repeat_byte(3));
        let setup = SafeSetupArgs {
            owners: vec![b, first, a, b],
            threshold: 3,
            ..SafeSetupArgs::default()
        };
        assert_eq!(setup.owners(first), vec![first, b, a]);
        setup.validate(first).unwrap();
        let too_high = SafeSetupArgs {
            threshold: 4,
            ..setup.clone()
        };
        assert!(too_high
            .validate(first)
            .unwrap_err()
            .contains("must be 1-3"));
        let zero = SafeSetupArgs {
            owners: vec![Address::ZERO],
            ..SafeSetupArgs::default()
        };
        assert!(zero.validate(first).unwrap_err().contains("Zero address"));
    }

    /// The deployment computes the address the way `WalletBuilder` does, so
    /// the "default Safe" `send`, `call` and `info` fall back to stays put.
    #[test]
    fn the_address_matches_wallet_builder() {
        use safe_rs::{ChainAddresses, WalletConfig};

        let first = Address::repeat_byte(0x11);
        let co_owners = vec![
            Address::repeat_byte(0x33),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
        ];
        // Any creation code will do: both sides hash the same one.
        let code = Bytes::from_static(&[0x60, 0x80, 0x60, 0x40]);
        for version in [SafeVersion::V1_5_0, SafeVersion::V1_4_1] {
            for owners in [Vec::new(), co_owners.clone()] {
                let setup = SafeSetupArgs {
                    owners: owners.clone(),
                    threshold: 1,
                    salt_nonce: U256::from(7),
                    safe_version: version,
                    ..SafeSetupArgs::default()
                }
                .resolve(first);
                let ours = predict_safe_address(
                    setup.factory,
                    setup.singleton,
                    &setup.owners,
                    setup.threshold,
                    setup.fallback_handler,
                    setup.salt_nonce,
                    &code,
                )
                .0;
                let config = WalletConfig::new()
                    .with_salt_nonce(U256::from(7))
                    .with_additional_owners(owners)
                    .with_addresses(ChainAddresses::from(version));
                let builder = predict_safe_address(
                    config.addresses().proxy_factory,
                    config.addresses().safe_singleton,
                    &config.owners(first),
                    config.threshold,
                    config.fallback_handler(),
                    config.salt_nonce,
                    &code,
                )
                .0;
                assert_eq!(ours, builder, "{version}");
            }
        }
    }

    #[test]
    fn json_documents_keep_their_shape() {
        let safe = Address::repeat_byte(5);
        let owner = Address::repeat_byte(6);
        let deployed = CreateOutcome::Deployed {
            safe,
            tx_hash: B256::repeat_byte(7),
            owners: vec![owner],
            threshold: 1,
            payer: owner,
            owner_key: None,
            sweep: None,
            warnings: Vec::new(),
        };
        let Some(doc @ Document::Plain(_)) = document(&deployed) else {
            panic!("a plain create prints the plain document");
        };
        let json = serde_json::to_value(&doc).unwrap();
        let mut keys: Vec<_> = json.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "already_deployed",
                "owners",
                "safe_address",
                "threshold",
                "tx_hash"
            ]
        );
        assert!(document(&CreateOutcome::Aborted { safe }).is_none());

        let rotating = CreateOutcome::Deployed {
            safe,
            tx_hash: B256::repeat_byte(7),
            owners: vec![owner],
            threshold: 1,
            payer: owner,
            owner_key: Some(OwnerKey {
                index: Some(1),
                address: owner,
            }),
            sweep: None,
            warnings: Vec::new(),
        };
        let Some(doc @ Document::Rotating(_)) = document(&rotating) else {
            panic!("a rotating create prints the rotating document");
        };
        let json = serde_json::to_value(&doc).unwrap();
        let mut keys: Vec<_> = json.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "already_deployed",
                "owner",
                "owners",
                "payer",
                "safe_address",
                "threshold",
                "tx_hash"
            ]
        );
    }
}
