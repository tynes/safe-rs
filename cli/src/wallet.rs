//! `safe wallet`: HD wallets and the record of which of their keys are used,
//! as functions a CLI can call and a [`WalletCommand`] it can mount.
//!
//! The subcommands leave out `--rpc-url` and `--safe`, which the caller puts
//! in a [`WalletContext`], so a CLI with its own global `--rpc-url` or
//! `--safe` can mount [`WalletCommand`] as it is.

use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use alloy::primitives::{Address, TxHash, U256};
use alloy::providers::Provider;
use clap::{Args, Subcommand};
use color_eyre::eyre::{eyre, WrapErr};
use rand::rngs::OsRng;
use safe_rs::hd::{key_path, normalize_phrase};
use safe_rs::keystore::{encrypt_mnemonic_keystore, keystore_address, ScryptParams};
use safe_rs::rotation::store::write_private;
use safe_rs::rotation::{Binding, Exposure, KeySource, RotatingSafe, RotationState};
use safe_rs::HdWallet;
use serde::Serialize;
use url::Url;
use zeroize::Zeroizing;

use crate::cli::{parse_ether_value, HdArgs, PasswordArgs, DEFAULT_TIMEOUT};
use crate::commands::default_safe::recorded_safe;
use crate::commands::rotation::rotation_config;
use crate::commands::{http_provider, latest_sim_spec};
use crate::console::{Console, Reports};
pub use crate::error::WalletError;
use crate::log::{Logger, NoopLogger};
use crate::output::Report;
pub use crate::output::{OwnerKey, SweptEth};
use crate::paths;
use crate::prompt::{Prompt, TerminalPrompt};
use crate::signers::{check_new_password, new_password, open_keys, open_state, open_wallet, wallet_id};

type Result<T, E = WalletError> = std::result::Result<T, E>;

/// `safe wallet`'s subcommands.
#[derive(Subcommand, Clone, Debug)]
pub enum WalletCommand {
    /// Create an HD wallet from a new 24-word phrase and encrypt it to disk
    New(WalletNewOpts),

    /// Encrypt an existing BIP-39 phrase to disk as an HD wallet
    Import(WalletImportOpts),

    /// List the HD wallets on disk
    List,

    /// Print the wallet's funding address, or the address of one owner key
    Address(WalletAddressOpts),

    /// Show which keys own which Safe, and where to send gas money
    Status(WalletStatusOpts),

    /// Rebuild the record of used keys for a Safe from the chain
    Sync(WalletSyncOpts),

    /// Move the ETH left on a Safe's retired owner keys to its current owner
    Sweep(WalletSweepOpts),
}

#[derive(Args, Clone, Debug)]
pub struct WalletNewOpts {
    /// Wallet name (stored as <name>.json under ~/.safe-rs/wallets)
    pub name: String,

    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Clone, Debug)]
pub struct WalletImportOpts {
    /// Wallet name (stored as <name>.json under ~/.safe-rs/wallets)
    pub name: String,

    /// File holding the phrase (default: prompt, without echo)
    #[arg(long, value_name = "PATH")]
    pub phrase_file: Option<PathBuf>,

    /// First index to use for owner keys, for a phrase whose lower indices
    /// were already used by another wallet
    #[arg(long, value_name = "INDEX")]
    pub start_index: Option<u32>,

    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Clone, Debug)]
pub struct WalletAddressOpts {
    #[command(flatten)]
    pub hd: HdArgs,

    /// Owner key index (default: the funding address, which needs no password)
    #[arg(long)]
    pub index: Option<u32>,

    #[command(flatten)]
    pub password: PasswordArgs,
}

/// `status` shows only the context's Safe when it has one.
#[derive(Args, Clone, Debug)]
pub struct WalletStatusOpts {
    #[command(flatten)]
    pub hd: HdArgs,
}

/// `sync` reads the context's Safe, or the wallet's sole recorded Safe on
/// the chain.
#[derive(Args, Clone, Debug)]
pub struct WalletSyncOpts {
    #[command(flatten)]
    pub hd: HdArgs,

    /// How many wallet indices to derive and compare (default: 1000 for an HD
    /// wallet file, 52 for a Ledger, which answers one address at a time)
    #[arg(long)]
    pub scan_limit: Option<u32>,

    /// Also read the Safe's owner events from this block on, to restore its
    /// history and find keys that never paid for gas. Use the Safe's
    /// deployment block or earlier
    #[arg(long, value_name = "BLOCK")]
    pub from_block: Option<u64>,

    /// Blocks per eth_getLogs request
    #[arg(long, default_value_t = 10_000, requires = "from_block")]
    pub chunk: u64,

    /// MultiSendCallOnly address (default: canonical v1.4.1)
    #[arg(long)]
    pub multi_send_call_only: Option<Address>,

    #[command(flatten)]
    pub password: PasswordArgs,
}

/// `sweep` reads the context's Safe, or the wallet's sole recorded Safe on
/// the chain.
#[derive(Args, Clone, Debug)]
pub struct WalletSweepOpts {
    #[command(flatten)]
    pub hd: HdArgs,

    /// Wei to leave on the retired owner, or a number with a unit ("0.01ether")
    /// (default: what the chain charges outside gas)
    #[arg(long, value_name = "WEI", value_parser = parse_ether_value)]
    pub sweep_reserve: Option<U256>,

    /// Seconds to wait for the receipt after broadcasting
    #[arg(long, default_value_t = DEFAULT_TIMEOUT)]
    pub timeout: u64,

    #[command(flatten)]
    pub password: PasswordArgs,
}

/// What a CLI that manages HD wallets resolves itself: where the wallets
/// live, the chain and Safe `sync` and `sweep` read, and where progress and
/// questions go.
#[derive(Clone)]
#[non_exhaustive]
pub struct WalletContext {
    /// Where HD wallets and their state live (default: `$SAFE_RS_HOME` or
    /// `~/.safe-rs`, resolved when first needed)
    pub home: Option<PathBuf>,
    /// The chain `sync` and `sweep` read
    pub rpc_url: Option<Url>,
    /// The Safe `sync` and `sweep` act on, and the one `status` shows
    pub safe: Option<Address>,
    /// Where progress and warnings go (default: nowhere)
    pub logger: Arc<dyn Logger>,
    /// What asks for passwords (default: the terminal)
    pub prompt: Arc<dyn Prompt>,
}

impl Default for WalletContext {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletContext {
    /// Wallets under `$SAFE_RS_HOME` or `~/.safe-rs`, no RPC or Safe, a silent
    /// [`NoopLogger`] and a [`TerminalPrompt`].
    pub fn new() -> Self {
        Self {
            home: None,
            rpc_url: None,
            safe: None,
            logger: Arc::new(NoopLogger),
            prompt: Arc::new(TerminalPrompt::new()),
        }
    }

    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home = Some(home);
        self
    }

    pub fn with_rpc_url(mut self, rpc_url: Url) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    pub fn with_safe(mut self, safe: Address) -> Self {
        self.safe = Some(safe);
        self
    }

    pub fn with_logger(mut self, logger: impl Logger + 'static) -> Self {
        self.logger = Arc::new(logger);
        self
    }

    pub fn with_prompt(mut self, prompt: impl Prompt + 'static) -> Self {
        self.prompt = Arc::new(prompt);
        self
    }

    fn console(&self) -> Console {
        Console::new(self.logger.clone(), self.prompt.clone())
    }

    fn home(&self) -> Result<PathBuf> {
        Ok(paths::home_or(self.home.as_deref())?)
    }

    fn rpc_url(&self) -> Result<&Url> {
        self.rpc_url.as_ref().ok_or(WalletError::NoRpcUrl)
    }
}

impl fmt::Debug for WalletContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletContext")
            .field("home", &self.home)
            .field("rpc_url", &self.rpc_url.as_ref().map(Url::as_str))
            .field("safe", &self.safe)
            .finish_non_exhaustive()
    }
}

/// Sorts the failures a host branches on out of an `eyre` report.
fn classify(report: color_eyre::eyre::Report) -> WalletError {
    for cause in report.chain() {
        if let Some(error) = cause.downcast_ref::<safe_rs::Error>() {
            match error {
                safe_rs::Error::WrongPassword => return WalletError::WrongPassword,
                safe_rs::Error::StateLocked(path) => {
                    return WalletError::Locked {
                        path: PathBuf::from(path),
                    }
                }
                _ => {}
            }
        }
        if let Some(missing) = cause.downcast_ref::<MissingWallet>() {
            return WalletError::NotFound {
                path: missing.0.clone(),
            };
        }
    }
    WalletError::Other(report)
}

/// A wallet file that is not there.
#[derive(Debug)]
pub(crate) struct MissingWallet(pub PathBuf);

impl fmt::Display for MissingWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} does not exist", self.0.display())
    }
}

impl std::error::Error for MissingWallet {}

fn read_state(home: &Path, wallet_id: Address) -> Result<Option<RotationState>> {
    let path = paths::state_file(home, wallet_id);
    match std::fs::read_to_string(&path) {
        Ok(json) => Ok(Some(serde_json::from_str(&json).wrap_err_with(|| {
            format!("{} is not a rotation state file", path.display())
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(eyre!("cannot read {}: {e}", path.display()).into()),
    }
}

/// A wallet written by [`new_wallet`] or [`import_wallet`].
#[derive(Clone, Serialize)]
#[non_exhaustive]
pub struct WalletCreated {
    pub name: String,
    pub path: String,
    /// The address to send gas money to before creating a Safe
    pub funding_address: Address,
    /// The recovery phrase, for a new wallet only: show it once
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phrase: Option<Zeroizing<String>>,
    #[serde(skip)]
    pub warnings: Vec<String>,
}

impl fmt::Debug for WalletCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletCreated")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("funding_address", &self.funding_address)
            .field("phrase", &self.phrase.as_ref().map(|_| "<redacted>"))
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl Report for WalletCreated {
    fn human(&self) -> String {
        let mut s = format!("HD wallet \"{}\" saved to {}", self.name, self.path);
        let _ = write!(s, "\n  Funding address: {}", self.funding_address);
        if let Some(phrase) = &self.phrase {
            let _ = write!(
                s,
                "\n\nRecovery phrase (shown once; it is the only backup of every key):\n\n  {}\n\n\
                 Write it down and keep it offline. Anyone who has it controls every Safe\n\
                 this wallet owns.",
                phrase.as_str()
            );
        }
        s
    }
}

/// Encrypts `phrase` to `path`, after checking the result opens again.
fn write_keystore(path: &Path, phrase: &str, password: &str) -> Result<HdWallet> {
    let json = encrypt_mnemonic_keystore(
        phrase,
        password.as_bytes(),
        ScryptParams::default(),
        &mut OsRng,
    )?;
    let wallet = HdWallet::from_keystore_json(&json, password.as_bytes())
        .wrap_err("the new keystore did not decrypt; nothing was written")?;
    write_private(path, json.as_bytes())?;
    Ok(wallet)
}

fn new_wallet_path(home: &Path, name: &str) -> Result<PathBuf> {
    paths::validate_wallet_name(name)?;
    let path = paths::wallet_file(home, name);
    if path.exists() {
        return Err(WalletError::AlreadyExists { path });
    }
    Ok(path)
}

/// Creates an HD wallet from a new 24-word phrase, encrypted with `password`.
/// The phrase comes back once, in [`WalletCreated::phrase`].
pub fn new_wallet(ctx: &WalletContext, name: &str, password: &str) -> Result<WalletCreated> {
    let console = ctx.console();
    let path = new_wallet_path(&ctx.home()?, name)?;
    let warnings = check_new_password(password)?;
    console.warnings(&warnings);
    let (_, phrase) = HdWallet::generate()?;
    let wallet = write_keystore(&path, &phrase, password)?;
    Ok(WalletCreated {
        name: name.to_string(),
        path: path.display().to_string(),
        funding_address: wallet.id(),
        phrase: Some(Zeroizing::new(phrase.to_string())),
        warnings,
    })
}

/// The warning `import` gives about a phrase used elsewhere.
const IMPORT_WARNING: &str = "if this phrase was ever used in another wallet (MetaMask, cast, a \
    hardware wallet), some of its keys have already signed and are not one-time keys any more. \
    Use --start-index to begin above them; a phrase made with `safe wallet new` avoids this.";

/// Checks a phrase before anything else is asked for.
pub fn check_phrase(phrase: &str) -> Result<Zeroizing<String>> {
    let phrase = normalize_phrase(phrase);
    HdWallet::from_phrase(&phrase).map_err(|e| WalletError::InvalidPhrase(e.to_string()))?;
    Ok(phrase)
}

/// Encrypts an existing BIP-39 phrase to disk as an HD wallet. With
/// `start_index`, owner keys start there, above indices used elsewhere.
pub fn import_wallet(
    ctx: &WalletContext,
    name: &str,
    phrase: &str,
    password: &str,
    start_index: Option<u32>,
) -> Result<WalletCreated> {
    let console = ctx.console();
    if start_index == Some(0) {
        return Err(eyre!("--start-index must be at least 1: index 0 is the funding key").into());
    }
    let home = ctx.home()?;
    let path = new_wallet_path(&home, name)?;
    let phrase = check_phrase(phrase)?;
    let mut warnings = vec![IMPORT_WARNING.to_string()];
    warnings.extend(check_new_password(password)?);
    console.warnings(&warnings);
    let wallet = write_keystore(&path, &phrase, password)?;

    if let Some(start) = start_index {
        let mut store = open_state(wallet.id(), Some(&home)).map_err(classify)?;
        store.state.note_used(start - 1);
        store.save()?;
    }
    Ok(WalletCreated {
        name: name.to_string(),
        path: path.display().to_string(),
        funding_address: wallet.id(),
        phrase: None,
        warnings,
    })
}

/// One wallet on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct WalletEntry {
    pub name: String,
    pub path: String,
    /// `None` when the file is not a readable keystore
    pub funding_address: Option<Address>,
    /// Safes this wallet owns keys of
    pub safes: usize,
}

#[derive(Serialize)]
struct WalletListOutput {
    wallets: Vec<WalletEntry>,
}

impl Report for WalletListOutput {
    fn human(&self) -> String {
        if self.wallets.is_empty() {
            return "No HD wallets yet. Create one with `safe wallet new <NAME>`.".to_string();
        }
        let mut s = String::from("HD wallets:");
        for wallet in &self.wallets {
            let _ = write!(s, "\n  {}", wallet.name);
            match wallet.funding_address {
                Some(address) => {
                    let _ = write!(s, "\n    Funding address: {address}");
                }
                None => {
                    let _ = write!(s, "\n    (not a readable keystore)");
                }
            }
            let _ = write!(s, "\n    Safes: {}", wallet.safes);
        }
        s
    }
}

/// The HD wallets on disk, by name.
pub fn list_wallets(ctx: &WalletContext) -> Result<Vec<WalletEntry>> {
    let home = ctx.home()?;
    let dir = paths::wallets_dir(&home);
    let mut wallets = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let funding_address = std::fs::read_to_string(&path)
                .ok()
                .and_then(|json| keystore_address(&json).ok().flatten());
            let safes = match funding_address {
                Some(id) => read_state(&home, id)?.map_or(0, |state| state.safes.len()),
                None => 0,
            };
            wallets.push(WalletEntry {
                name: name.to_string(),
                path: path.display().to_string(),
                funding_address,
                safes,
            });
        }
    }
    wallets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(wallets)
}

/// One key of an HD wallet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct WalletAddress {
    pub index: u32,
    pub address: Address,
    /// BIP-32 derivation path of the key
    pub path: String,
}

impl Report for WalletAddress {
    fn human(&self) -> String {
        self.address.to_string()
    }
}

/// The wallet's funding address (index 0, read without a password), or the
/// address of owner key `index`.
pub async fn wallet_address(
    ctx: &WalletContext,
    hd: &HdArgs,
    password: &PasswordArgs,
    index: Option<u32>,
) -> Result<WalletAddress> {
    let home = ctx.home()?;
    let (index, address) = match index {
        None | Some(0) => (0, wallet_id(hd, Some(&home)).await.map_err(classify)?),
        Some(index) => {
            let keys = open_keys(hd, password, Some(&home), &ctx.console())
                .await
                .map_err(classify)?;
            (index, keys.address(index).await?)
        }
    };
    Ok(WalletAddress {
        index,
        address,
        path: key_path(index),
    })
}

fn exposure_label(exposure: Exposure) -> &'static str {
    match exposure {
        Exposure::Signed => "signed",
        Exposure::Rebuilt => "rebuilt",
        Exposure::Adopted => "adopted",
        Exposure::SharedKey => "shared_key",
    }
}

fn exposure_note(exposure: Exposure) -> &'static str {
    match exposure {
        Exposure::Signed => "a signature by this key has left this machine; rotate it",
        Exposure::Rebuilt => {
            "state was rebuilt from chain, which cannot show every signature; rotate to be sure"
        }
        Exposure::Adopted => "the chain showed an owner this state did not expect; rotate it",
        Exposure::SharedKey => "this key was already used on another Safe or chain; rotate it now",
    }
}

/// What the wallet knows about one Safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SafeStatus {
    pub chain_id: Option<u64>,
    pub safe: String,
    /// The key that signs for the Safe, and the address to send gas money to
    pub owner: OwnerKey,
    /// Why the owner's public key must be assumed public, if it must
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposed: Option<&'static str>,
    /// The key every signature by the owner rotates to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_owner: Option<OwnerKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_tx: Option<TxHash>,
    /// Retired keys whose ETH still has to be moved to the owner
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sweeps_owed_from: Vec<Address>,
    pub retired_keys: Vec<OwnerKey>,
    #[serde(skip)]
    pub exposure: Option<Exposure>,
}

impl SafeStatus {
    fn new(key: &str, binding: &Binding) -> Self {
        let (chain_id, safe) = match key.split_once(':') {
            Some((chain, safe)) => (chain.parse().ok(), safe.to_string()),
            None => (None, key.to_string()),
        };
        Self {
            chain_id,
            safe,
            owner: binding.current.into(),
            exposed: binding.exposed.map(exposure_label),
            next_owner: binding.reserved.map(Into::into),
            pending_tx: binding.pending.as_ref().map(|p| p.outer_tx_hash),
            sweeps_owed_from: binding
                .sweep_due
                .iter()
                .map(|due| due.from.address())
                .collect(),
            retired_keys: binding
                .history
                .iter()
                .map(|retired| retired.owner.into())
                .collect(),
            exposure: binding.exposed,
        }
    }
}

/// Which keys own which Safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct WalletStatus {
    /// The wallet's funding address
    pub wallet: Address,
    /// The next key index that has never been handed out
    pub next_index: u32,
    pub safes: Vec<SafeStatus>,
}

impl Report for WalletStatus {
    fn human(&self) -> String {
        let mut s = format!("Wallet: {}", self.wallet);
        let _ = write!(s, "\nNext unused key: {}", self.next_index);
        if self.safes.is_empty() {
            let _ = write!(s, "\nNo Safes tracked yet.");
        }
        for safe in &self.safes {
            let chain = safe
                .chain_id
                .map_or_else(|| "?".to_string(), |id| id.to_string());
            let _ = write!(s, "\n\nSafe {} (chain {chain})", safe.safe);
            let _ = write!(s, "\n  Owner: {}", safe.owner);
            let _ = write!(s, "\n  Send gas money to: {}", safe.owner.address);
            if let Some(exposure) = safe.exposure {
                let _ = write!(s, "\n  Exposed: {}", exposure_note(exposure));
            }
            if let Some(next) = &safe.next_owner {
                let _ = write!(s, "\n  Next owner: {next}");
            }
            if let Some(pending) = safe.pending_tx {
                let _ = write!(s, "\n  Pending transaction: {pending}");
            }
            for from in &safe.sweeps_owed_from {
                let _ = write!(
                    s,
                    "\n  Sweep owed: ETH on {from} still has to move to the owner (`safe wallet sweep`)"
                );
            }
            let _ = write!(s, "\n  Retired keys: {}", safe.retired_keys.len());
        }
        s
    }
}

/// The wallet's record of used keys, read without taking its lock. Only the
/// context's Safe, when it has one.
pub async fn wallet_status(ctx: &WalletContext, hd: &HdArgs) -> Result<WalletStatus> {
    let home = ctx.home()?;
    let wallet = wallet_id(hd, Some(&home)).await.map_err(classify)?;
    let state = read_state(&home, wallet)?.unwrap_or_else(|| RotationState::new(wallet, 1));
    let only = ctx.safe.map(|safe| safe.to_string());
    let safes = state
        .safes
        .iter()
        .filter(|(key, _)| {
            only.as_ref()
                .is_none_or(|safe| key.ends_with(safe.as_str()))
        })
        .map(|(key, binding)| SafeStatus::new(key, binding))
        .collect();
    Ok(WalletStatus {
        wallet,
        next_index: state.next_index,
        safes,
    })
}

/// What [`sync_wallet`] found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct WalletSync {
    pub safe: Address,
    pub owner: OwnerKey,
    /// Wallet key indices found in use on chain
    pub used: Vec<u32>,
    /// Owner events read from the Safe's logs
    pub events: usize,
    pub next_index: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Report for WalletSync {
    fn human(&self) -> String {
        let mut s = format!("Synced Safe {}", self.safe);
        let _ = write!(s, "\n  Owner: {}", self.owner);
        let _ = write!(s, "\n  Keys found in use: {:?}", self.used);
        let _ = write!(s, "\n  Owner events read: {}", self.events);
        let _ = write!(s, "\n  Next unused key: {}", self.next_index);
        let _ = write!(
            s,
            "\n\nOnly this Safe and this chain were read. If the phrase was used with other\n\
             Safes or chains, sync each of them before sending."
        );
        if self.events == 0 {
            let _ = write!(
                s,
                "\nWithout --from-block, keys that never paid for gas themselves are not found."
            );
        }
        s
    }
}

/// Rebuilds the record of used keys for the context's Safe (or the wallet's
/// sole recorded Safe on the chain) from the chain.
pub async fn sync_wallet(ctx: &WalletContext, opts: WalletSyncOpts) -> Result<WalletSync> {
    let console = ctx.console();
    let rpc_url = ctx.rpc_url()?;
    let ring = open_wallet(&opts.hd, &opts.password, ctx.home.as_deref(), &console)
        .await
        .map_err(classify)?;
    let provider = http_provider(rpc_url);
    let chain_id = provider.get_chain_id().await.map_err(|e| eyre!(e))?;
    let spec = latest_sim_spec(&provider, chain_id, None, 12).await?;
    let mut config = rotation_config(opts.multi_send_call_only, spec, 12, 120);
    config.scan_limit = opts.scan_limit;
    let safe = match ctx.safe {
        Some(safe) => safe,
        None => recorded_safe(ring.state(), chain_id, "--safe")?,
    };
    let mut rotating = RotatingSafe::with_keyring(provider, safe, ring, config).await?;
    let report = rotating.sync(opts.from_block, opts.chunk).await?;
    let warnings = rotating.take_warnings();
    console.warnings(&warnings);
    Ok(WalletSync {
        safe,
        owner: report.current.into(),
        used: report.used,
        events: report.events,
        next_index: report.next_index,
        warnings,
    })
}

/// A retired key whose ETH could not be moved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct OwedSweep {
    pub from: Address,
    pub reason: String,
}

/// What [`sweep_wallet`] moved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct WalletSweep {
    /// Transfers that moved ETH to the current owner
    pub sweeps: Vec<SweptEth>,
    /// Retired keys that still hold ETH, and why it could not be moved
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub still_owed: Vec<OwedSweep>,
    #[serde(skip)]
    pub warnings: Vec<String>,
}

impl Report for WalletSweep {
    fn human(&self) -> String {
        let mut lines: Vec<String> = self.sweeps.iter().map(Report::human).collect();
        for owed in &self.still_owed {
            lines.push(format!("Still owed from {}: {}", owed.from, owed.reason));
        }
        if lines.is_empty() {
            lines.push("Nothing to sweep: no retired key holds spare ETH.".to_string());
        }
        lines.join("\n")
    }
}

/// Moves the ETH left on the Safe's retired owner keys to its current owner.
/// If some could not be moved, [`WalletError::Sweep`] lists both the sweeps
/// sent and the ones still owed.
pub async fn sweep_wallet(ctx: &WalletContext, opts: WalletSweepOpts) -> Result<WalletSweep> {
    let console = ctx.console();
    let rpc_url = ctx.rpc_url()?;
    let ring = open_wallet(&opts.hd, &opts.password, ctx.home.as_deref(), &console)
        .await
        .map_err(classify)?;
    let provider = http_provider(rpc_url);
    let chain_id = provider.get_chain_id().await.map_err(|e| eyre!(e))?;
    let spec = latest_sim_spec(&provider, chain_id, None, 12).await?;
    let mut config = rotation_config(None, spec, 12, opts.timeout);
    config.sweep_reserve = opts.sweep_reserve;
    let safe = match ctx.safe {
        Some(safe) => safe,
        None => recorded_safe(ring.state(), chain_id, "--safe")?,
    };
    let mut rotating = RotatingSafe::with_keyring(provider, safe, ring, config).await?;
    rotating.schedule_retired_sweeps().await?;
    let report = rotating.sweep_all().await?;
    let warnings = rotating.take_warnings();
    console.warnings(&warnings);
    let sweeps: Vec<SweptEth> = report.swept.iter().copied().map(Into::into).collect();
    let still_owed: Vec<OwedSweep> = report
        .failed
        .iter()
        .map(|(from, error)| OwedSweep {
            from: *from,
            reason: error.to_string(),
        })
        .collect();
    if !still_owed.is_empty() {
        return Err(WalletError::Sweep {
            swept: sweeps,
            still_owed,
        });
    }
    Ok(WalletSweep {
        sweeps,
        still_owed,
        warnings,
    })
}

/// `safe wallet`: asks `ctx.prompt` for a phrase and a new password where
/// needed, calls the functions above, and prints the outcome as `safe` does
/// (JSON with `json`).
pub async fn run(command: WalletCommand, ctx: &WalletContext, json: bool) -> color_eyre::Result<()> {
    let reports = Arc::new(Reports::default());
    let console = ctx.console().with_reports(reports.clone());
    let result = run_in(command, ctx, &console).await;
    reports.print(json);
    result
}

pub(crate) async fn run_in(
    command: WalletCommand,
    ctx: &WalletContext,
    console: &Console,
) -> color_eyre::Result<()> {
    match command {
        WalletCommand::New(opts) => {
            // Checked before the password is asked for.
            new_wallet_path(&ctx.home()?, &opts.name)?;
            let password = new_password(&opts.password, console)?;
            console.emit(&new_wallet(ctx, &opts.name, &password)?);
        }
        WalletCommand::Import(opts) => {
            new_wallet_path(&ctx.home()?, &opts.name)?;
            let phrase = match &opts.phrase_file {
                Some(file) => Zeroizing::new(
                    std::fs::read_to_string(file)
                        .wrap_err_with(|| format!("cannot read {}", file.display()))?,
                ),
                None => console.secret("Recovery phrase: ")?,
            };
            // Checked before the password is asked for.
            let phrase = check_phrase(&phrase)?;
            let password = new_password(&opts.password, console)?;
            console.emit(&import_wallet(
                ctx,
                &opts.name,
                &phrase,
                &password,
                opts.start_index,
            )?);
        }
        WalletCommand::List => console.emit(&WalletListOutput {
            wallets: list_wallets(ctx)?,
        }),
        WalletCommand::Address(opts) => {
            console.emit(&wallet_address(ctx, &opts.hd, &opts.password, opts.index).await?);
        }
        WalletCommand::Status(opts) => console.emit(&wallet_status(ctx, &opts.hd).await?),
        WalletCommand::Sync(opts) => console.emit(&sync_wallet(ctx, opts).await?),
        WalletCommand::Sweep(opts) => match sweep_wallet(ctx, opts).await {
            Ok(sweep) => console.emit(&sweep),
            Err(WalletError::Sweep { swept, still_owed }) => {
                let owed = still_owed.len();
                console.emit(&WalletSweep {
                    sweeps: swept,
                    still_owed,
                    warnings: Vec::new(),
                });
                return Err(eyre!("{owed} sweep(s) could not be completed"));
            }
            Err(e) => return Err(e.into()),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::NoPrompt;
    use safe_rs::rotation::OwnerRef;

    #[test]
    fn status_lists_the_address_to_fund_for_each_safe() {
        let wallet = Address::repeat_byte(0x01);
        let owner = Address::repeat_byte(0x02);
        let mut state = RotationState::new(wallet, 1);
        let key = format!("10:{}", Address::repeat_byte(0x5A));
        state
            .bind(
                &key,
                OwnerRef::Derived {
                    index: 3,
                    address: owner,
                },
            )
            .unwrap();
        state.mark_exposed(&key, Exposure::Signed).unwrap();

        let (key, binding) = state.safes.iter().next().unwrap();
        let output = WalletStatus {
            wallet,
            next_index: state.next_index,
            safes: vec![SafeStatus::new(key, binding)],
        };
        let human = output.human();
        assert!(
            human.contains(&format!("Send gas money to: {owner}")),
            "{human}"
        );
        assert!(human.contains("chain 10"), "{human}");
        assert!(human.contains("Exposed:"), "{human}");

        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["safes"][0]["chain_id"], 10);
        assert_eq!(json["safes"][0]["owner"]["index"], 3);
        assert_eq!(json["safes"][0]["exposed"], "signed");
        assert_eq!(json["next_index"], 4);
    }

    const PHRASE: &str = "test test test test test test test test test test test junk";

    #[tokio::test]
    async fn wallets_live_under_the_context_home() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = WalletContext::new()
            .with_home(dir.path().to_path_buf())
            .with_prompt(NoPrompt);

        let imported = import_wallet(&ctx, "demo", PHRASE, "pw", Some(3)).unwrap();
        assert!(imported.phrase.is_none());
        assert!(imported.warnings[0].contains("--start-index"));
        assert!(dir.path().join("wallets/demo.json").exists());
        let again = import_wallet(&ctx, "demo", PHRASE, "pw", None).unwrap_err();
        assert!(matches!(again, WalletError::AlreadyExists { .. }), "{again}");

        let listed = list_wallets(&ctx).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].funding_address, Some(imported.funding_address));

        let hd = HdArgs {
            hd_wallet: Some("demo".to_string()),
            ledger: false,
        };
        let funding = wallet_address(&ctx, &hd, &PasswordArgs::default(), None)
            .await
            .unwrap();
        assert_eq!(funding.address, imported.funding_address);
        // An owner key needs the password, which NoPrompt does not give.
        let refused = wallet_address(&ctx, &hd, &PasswordArgs::default(), Some(1))
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("no prompt"), "{refused}");
        let wrong = PasswordArgs {
            password_file: None,
            password: Some("nope".to_string()),
        };
        let refused = wallet_address(&ctx, &hd, &wrong, Some(1)).await.unwrap_err();
        assert!(matches!(refused, WalletError::WrongPassword), "{refused}");

        let status = wallet_status(&ctx, &hd).await.unwrap();
        assert_eq!(status.next_index, 3, "--start-index 3 leaves 1 and 2 unused");

        let missing = HdArgs {
            hd_wallet: Some("missing".to_string()),
            ledger: false,
        };
        let error = wallet_status(&ctx, &missing).await.unwrap_err();
        assert!(matches!(error, WalletError::NotFound { .. }), "{error}");
    }

    #[test]
    fn bad_input_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = WalletContext::new().with_home(dir.path().to_path_buf());
        let error = import_wallet(&ctx, "demo", PHRASE, "pw", Some(0)).unwrap_err();
        assert!(error.to_string().contains("at least 1"), "{error}");
        let error = import_wallet(&ctx, "demo", "not a phrase", "pw", None).unwrap_err();
        assert!(matches!(error, WalletError::InvalidPhrase(_)), "{error}");
        let error = import_wallet(&ctx, "demo", PHRASE, "", None).unwrap_err();
        assert!(error.to_string().contains("must not be empty"), "{error}");
        assert!(!dir.path().join("wallets/demo.json").exists());
        assert!(matches!(
            WalletContext::new().rpc_url().unwrap_err(),
            WalletError::NoRpcUrl
        ));
    }
}
