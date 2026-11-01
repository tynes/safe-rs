//! `safe create`, and [`create`] for a CLI that deploys Safes itself.
//!
//! [`CreateOpts`] leaves out `--rpc-url` and the signer, which the caller
//! resolves into a [`CreateContext`], so it flattens into another CLI's
//! command without clashing with that CLI's own flags.

use std::fmt;
#[cfg(feature = "hd-wallet")]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::network::{AnyNetwork, Network, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use clap::{Args, Parser};
use color_eyre::eyre::eyre;
use safe_rs::{
    fetch_proxy_creation_code, is_safe_with, predict_safe_address, sign_outer_tx, submit_and_wait,
    OuterTxParams, SignedOuterTx, Submission,
};

pub use implementation::{
    BoxFuture, HttpProvider, Implementation, ResolvedSetup, SafeDeployment, SafeImplementation,
    StandardSafe,
};
use serde::Serialize;
use url::Url;

use crate::any_signer::AnySigner;
use crate::cli::{FeeArgs, SafeSetupArgs};
#[cfg(feature = "hd-wallet")]
use crate::cli::{HdArgs, SweepArgs};
use crate::cli::{PasswordArgs, PayerArgs, RpcArgs, SignerArgs};
use crate::commands::{http_provider, outer_fees};
use crate::console::{Console, Reports};
pub use crate::error::CreateError;
use crate::error::{BroadcastError, OptionsError};
use crate::log::{Logger, NoopLogger};
use crate::output::{CreateOutput, Report};
pub use crate::output::{OwnerKey, SweptEth};
use crate::prompt::{Prompt, TerminalPrompt};
use crate::signers::{create_payer, create_signer};
use crate::RunConfig;

#[cfg(feature = "hd-wallet")]
mod hd;
mod implementation;

#[cfg(feature = "hd-wallet")]
pub use hd::{parse_same_as, SameAs};

/// How often to poll for the deployment receipt.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How `safe create` deploys: the Safe's setup, fees, and the HD wallet that
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

    /// Deploy the same Safe an HD wallet created on another chain, given as
    /// <CHAIN_ID>:<SAFE>. Reuses its first owner key and salt, so that key
    /// must be rotated right away
    #[cfg(feature = "hd-wallet")]
    #[arg(
        long,
        value_name = "CHAIN_ID:SAFE",
        value_parser = parse_same_as,
        conflicts_with_all = ["owners", "threshold", "salt_nonce", "safe_version", "singleton", "factory", "fallback_handler"]
    )]
    pub same_as: Option<SameAs>,

    #[cfg(feature = "hd-wallet")]
    #[command(flatten)]
    pub hd: HdArgs,

    #[cfg(feature = "hd-wallet")]
    #[command(flatten)]
    pub sweep: SweepArgs,

    #[command(flatten)]
    pub password: PasswordArgs,

    #[command(flatten)]
    pub payer: PayerArgs,

    /// How the Safe is deployed (default: the standard Safe proxy factory).
    /// Not a flag: a CLI whose Safes come from another factory sets it in
    /// code. Not supported with `--hd-wallet` or `--ledger`.
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
    /// code, then: `--same-as`, `--no-sweep` and `--sweep-reserve` need
    /// `--hd-wallet` or `--ledger`, and a signer with `--hd-wallet` is
    /// refused.
    pub fn validate(&self, has_signer: bool) -> Result<(), OptionsError> {
        #[cfg(not(feature = "hd-wallet"))]
        let _ = has_signer;
        #[cfg(feature = "hd-wallet")]
        {
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
            if self.hd.is_set() {
                if has_signer {
                    return Err(OptionsError::SignerWithHd);
                }
                if !self.implementation.is_standard() {
                    return Err(OptionsError::Conflict {
                        flag: "a custom Safe implementation",
                        with: if self.hd.ledger {
                            "--ledger"
                        } else {
                            "--hd-wallet"
                        },
                    });
                }
            } else if self.same_as.is_some() {
                return Err(OptionsError::HdOnly { flag: "--same-as" });
            } else if self.sweep.no_sweep {
                return Err(OptionsError::HdOnly { flag: "--no-sweep" });
            } else if self.sweep.sweep_reserve.is_some() {
                return Err(OptionsError::HdOnly {
                    flag: "--sweep-reserve",
                });
            }
        }
        Ok(())
    }

    /// Whether the owner comes from an HD wallet or Ledger.
    pub fn uses_hd(&self) -> bool {
        #[cfg(feature = "hd-wallet")]
        return self.hd.is_set();
        #[cfg(not(feature = "hd-wallet"))]
        return false;
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
    /// First owner and deployer (unless `--payer-private-key` pays). `None`
    /// with `--hd-wallet` / `--ledger`, where the owner is the wallet's next
    /// unused key.
    pub signer: Option<AnySigner>,
    /// Where progress and warnings go (default: nowhere)
    pub logger: Arc<dyn Logger>,
    /// What asks for confirmation and passwords (default: the terminal)
    pub prompt: Arc<dyn Prompt>,
    /// Where HD wallets and their state live (default: `$SAFE_RS_HOME` or
    /// `~/.safe-rs`)
    #[cfg(feature = "hd-wallet")]
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
            #[cfg(feature = "hd-wallet")]
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

    /// Looks for HD wallets and their state under `home`.
    #[cfg(feature = "hd-wallet")]
    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home = Some(home);
        self
    }

    fn console(&self) -> Console {
        Console::new(self.logger.clone(), self.prompt.clone())
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
        /// The HD wallet key that would own the Safe
        owner_key: Option<OwnerKey>,
        /// The account that would pay, with `--hd-wallet` / `--ledger`
        payer: Option<Address>,
    },
    /// A Safe with this setup already exists, so no deployment was sent. With
    /// an HD wallet the Safe is still recorded in the wallet, and sweeps owed
    /// from earlier runs are sent.
    AlreadyDeployed {
        safe: Address,
        owners: Vec<Address>,
        threshold: u64,
        owner_key: Option<OwnerKey>,
        /// The account that would have paid, with `--hd-wallet` / `--ledger`
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
        /// The HD wallet key that owns the Safe
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
        match document(self) {
            Some(Document::Plain(doc)) => doc.human(),
            #[cfg(feature = "hd-wallet")]
            Some(Document::Hd(doc)) => doc.human(),
            None => format!("Aborted: Safe {} was not deployed", self.safe()),
        }
    }
}

/// What `safe create` prints for an outcome, as it always has.
enum Document {
    Plain(CreateOutput),
    #[cfg(feature = "hd-wallet")]
    Hd(hd::HdCreateOutput),
}

fn document(outcome: &CreateOutcome) -> Option<Document> {
    #[cfg(feature = "hd-wallet")]
    if let Some(doc) = hd::HdCreateOutput::from_outcome(outcome) {
        return Some(Document::Hd(doc));
    }
    let (safe_address, tx_hash, owners, threshold, already_deployed) = match outcome {
        CreateOutcome::Computed {
            safe,
            owners,
            threshold,
            deployed,
            ..
        } => (*safe, None, owners, *threshold, *deployed),
        CreateOutcome::AlreadyDeployed {
            safe,
            owners,
            threshold,
            ..
        } => (*safe, None, owners, *threshold, true),
        CreateOutcome::Deployed {
            safe,
            tx_hash,
            owners,
            threshold,
            ..
        } => (*safe, Some(*tx_hash), owners, *threshold, false),
        CreateOutcome::Aborted { .. } => return None,
    };
    Some(Document::Plain(CreateOutput {
        safe_address,
        tx_hash,
        owners: owners.clone(),
        threshold,
        already_deployed,
    }))
}

/// Deploys a Safe as `safe create` does, with every option in `opts`.
///
/// The address is computed from the first owner (the signer, or with
/// `--hd-wallet` / `--ledger` the wallet's next unused key), the `--owner`s,
/// the threshold, the salt and the contracts, so the same options give the
/// same Safe on every chain. Options built in code are checked for the same
/// conflicts clap enforces on the flags.
pub async fn create(ctx: CreateContext, opts: CreateOpts) -> Result<CreateOutcome, CreateError> {
    let console = ctx.console();
    create_with(ctx, opts, &console).await
}

async fn create_with(
    ctx: CreateContext,
    opts: CreateOpts,
    console: &Console,
) -> Result<CreateOutcome, CreateError> {
    opts.validate(ctx.signer.is_some())?;
    #[cfg(feature = "hd-wallet")]
    if opts.hd.is_set() {
        return Box::pin(hd::create(ctx, opts, console)).await;
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
    let payer = create_payer(&opts.payer)?.map_or(signer, AnySigner::from);
    let safe = plan.safe;
    let mut details = String::from("Computing Safe address...\n");
    if !opts.implementation.is_standard() {
        details.push_str(&format!("  Implementation: {}\n", implementation.name()));
    }
    details.push_str(&format!("  Factory: {}\n", plan.to));
    details.push_str(&format!("  Singleton: {}\n", plan.singleton));
    if opts.implementation.is_standard() {
        details.push_str(&format!("  Salt Nonce: {}\n", setup.salt_nonce));
    }
    details.push_str(&format!("  Owners: {:?}\n", plan.owners));
    details.push_str(&format!("  Threshold: {}\n", plan.threshold));
    if payer.address() != first {
        details.push_str(&format!("  Payer: {}\n", payer.address()));
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
    details.push_str(&format!("  Safe Address: {safe}"));
    if !opts.no_confirm && !console.confirm("Deploy new Safe?", &details) {
        console.line("Aborted");
        return Ok(CreateOutcome::Aborted { safe });
    }

    let chain_id = provider.get_chain_id().await?;
    let params = deployment_tx(
        &provider,
        chain_id,
        payer.address(),
        plan.to,
        plan.input.clone(),
        &opts.fees,
    )
    .await?;
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

/// The Safe address `setup` deploys to, and the initializer that sets it up.
pub(crate) async fn predict(
    provider: &HttpProvider,
    setup: &ResolvedSetup,
) -> Result<(Address, Bytes), CreateError> {
    let creation_code = fetch_proxy_creation_code(provider, setup.factory).await?;
    Ok(predict_safe_address(
        setup.factory,
        setup.singleton,
        &setup.owners,
        setup.threshold,
        setup.fallback_handler,
        setup.salt_nonce,
        &creation_code,
    ))
}

/// The unsigned `createProxyWithNonce` transaction, sent by `from`, with the
/// `--gas-limit` and fee overrides applied.
#[cfg(feature = "hd-wallet")]
pub(crate) async fn deployment(
    provider: &HttpProvider,
    chain_id: u64,
    from: Address,
    setup: &ResolvedSetup,
    initializer: Bytes,
    fees: &FeeArgs,
) -> Result<OuterTxParams, CreateError> {
    let input =
        safe_rs::encode_create_proxy_with_nonce(setup.singleton, initializer, setup.salt_nonce);
    deployment_tx(provider, chain_id, from, setup.factory, input, fees).await
}

/// The unsigned deployment transaction calling `to` with `input`, sent by
/// `from`, with the `--gas-limit` and fee overrides applied.
async fn deployment_tx(
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
        estimate + estimate / 5
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
    let reports = Arc::new(Reports::default());
    let console = config.console().with_reports(reports.clone());
    let result = run_with(args, &console, config.json).await;
    reports.print(config.json);
    result
}

pub(crate) async fn run_with(
    mut args: CreateArgs,
    console: &Console,
    json: bool,
) -> color_eyre::Result<()> {
    // `--json` never prompts: it is the result document's only output.
    args.opts.no_confirm |= json;
    // Checked before any key or password prompt.
    args.opts.validate(args.signer.is_set())?;
    let signer = if args.opts.uses_hd() {
        None
    } else {
        Some(create_signer(&args.signer, &args.opts.password, console).await?)
    };
    let mut ctx = CreateContext::new(args.rpc.rpc_url);
    ctx.signer = signer;
    ctx.logger = console.logger().clone();
    ctx.prompt = console.prompt().clone();
    let outcome = create_with(ctx, args.opts, console).await?;
    match document(&outcome) {
        Some(Document::Plain(doc)) => console.emit(&doc),
        #[cfg(feature = "hd-wallet")]
        Some(Document::Hd(doc)) => console.emit(&doc),
        None => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SafeVersion;
    use clap::CommandFactory;

    #[test]
    fn the_create_flags_are_consistent() {
        CreateArgs::command().debug_assert();
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
        let Some(Document::Plain(doc)) = document(&deployed) else {
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
    }
}
