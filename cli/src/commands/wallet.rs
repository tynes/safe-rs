//! `safe wallet`: HD wallets and the record of which of their keys are used.

use std::fmt::Write as _;
use std::path::Path;

use alloy::primitives::{Address, TxHash};
use alloy::providers::Provider;
use color_eyre::eyre::{bail, eyre, Result, WrapErr};
use rand::rngs::OsRng;
use safe_rs::hd::{key_path, normalize_phrase};
use safe_rs::keystore::{encrypt_mnemonic_keystore, keystore_address, ScryptParams};
use safe_rs::rotation::store::write_private;
use safe_rs::rotation::KeySource;
use safe_rs::rotation::{Binding, Exposure, RotatingSafe, RotationState};
use safe_rs::{HdWallet, SpecId};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::cli::{
    WalletAddressArgs, WalletCommand, WalletImportArgs, WalletNewArgs, WalletStatusArgs,
    WalletSweepArgs, WalletSyncArgs,
};
use crate::commands::default_safe::recorded_safe;
use crate::commands::http_provider;
use crate::commands::rotation::{print_warnings, rotation_config};
use crate::output::{OwnerOutput, Report, SweepOutput};
use crate::paths;
use crate::wallet::{new_password, open_keys, open_state, open_wallet, wallet_id};

pub async fn run(command: WalletCommand, json: bool) -> Result<()> {
    match command {
        WalletCommand::New(args) => new(&args, json),
        WalletCommand::Import(args) => import(&args, json),
        WalletCommand::List => list(json),
        WalletCommand::Address(args) => address(&args, json).await,
        WalletCommand::Status(args) => status(&args, json).await,
        WalletCommand::Sync(args) => sync(args, json).await,
        WalletCommand::Sweep(args) => sweep(args, json).await,
    }
}

#[derive(Serialize)]
struct WalletCreatedOutput {
    name: String,
    path: String,
    /// The address to send gas money to before creating a Safe
    funding_address: Address,
    /// Shown once, for a new wallet only
    #[serde(skip_serializing_if = "Option::is_none")]
    phrase: Option<String>,
}

impl Report for WalletCreatedOutput {
    fn human(&self) -> String {
        let mut s = format!("HD wallet \"{}\" saved to {}", self.name, self.path);
        let _ = write!(s, "\n  Funding address: {}", self.funding_address);
        if let Some(phrase) = &self.phrase {
            let _ = write!(
                s,
                "\n\nRecovery phrase (shown once; it is the only backup of every key):\n\n  {phrase}\n\n\
                 Write it down and keep it offline. Anyone who has it controls every Safe\n\
                 this wallet owns."
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

fn new_wallet_path(name: &str) -> Result<std::path::PathBuf> {
    paths::validate_wallet_name(name)?;
    let path = paths::wallet_file(&paths::home()?, name);
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    Ok(path)
}

fn new(args: &WalletNewArgs, json: bool) -> Result<()> {
    let path = new_wallet_path(&args.name)?;
    let password = new_password(&args.password)?;
    let (_, phrase) = HdWallet::generate()?;
    let wallet = write_keystore(&path, &phrase, &password)?;
    WalletCreatedOutput {
        name: args.name.clone(),
        path: path.display().to_string(),
        funding_address: wallet.id(),
        phrase: Some(phrase.to_string()),
    }
    .print(json);
    Ok(())
}

fn import(args: &WalletImportArgs, json: bool) -> Result<()> {
    let path = new_wallet_path(&args.name)?;
    let phrase = match &args.phrase_file {
        Some(file) => Zeroizing::new(
            std::fs::read_to_string(file)
                .wrap_err_with(|| format!("cannot read {}", file.display()))?,
        ),
        None => Zeroizing::new(rpassword::prompt_password("Recovery phrase: ")?),
    };
    let phrase = normalize_phrase(&phrase);
    // Validate before asking for a password.
    HdWallet::from_phrase(&phrase)?;
    eprintln!(
        "warning: if this phrase was ever used in another wallet (MetaMask, cast, a hardware \
         wallet), some of its keys have already signed and are not one-time keys any more. \
         Use --start-index to begin above them; a phrase made with `safe wallet new` avoids this."
    );
    let password = new_password(&args.password)?;
    let wallet = write_keystore(&path, &phrase, &password)?;

    if let Some(start) = args.start_index {
        if start == 0 {
            bail!("--start-index must be at least 1: index 0 is the funding key");
        }
        let mut store = open_state(wallet.id())?;
        store.state.note_used(start - 1);
        store.save()?;
    }
    WalletCreatedOutput {
        name: args.name.clone(),
        path: path.display().to_string(),
        funding_address: wallet.id(),
        phrase: None,
    }
    .print(json);
    Ok(())
}

/// Reads a wallet's rotation state without taking its lock.
fn read_state(home: &Path, wallet_id: Address) -> Result<Option<RotationState>> {
    let path = paths::state_file(home, wallet_id);
    match std::fs::read_to_string(&path) {
        Ok(json) => Ok(Some(serde_json::from_str(&json).wrap_err_with(|| {
            format!("{} is not a rotation state file", path.display())
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(eyre!("cannot read {}: {e}", path.display())),
    }
}

#[derive(Serialize)]
struct WalletEntry {
    name: String,
    path: String,
    funding_address: Option<Address>,
    /// Safes this wallet owns keys of
    safes: usize,
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

fn list(json: bool) -> Result<()> {
    let home = paths::home()?;
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
    WalletListOutput { wallets }.print(json);
    Ok(())
}

#[derive(Serialize)]
struct WalletAddressOutput {
    index: u32,
    address: Address,
    /// BIP-32 derivation path of the key
    path: String,
}

impl Report for WalletAddressOutput {
    fn human(&self) -> String {
        self.address.to_string()
    }
}

async fn address(args: &WalletAddressArgs, json: bool) -> Result<()> {
    let (index, address) = match args.index {
        None | Some(0) => (0, wallet_id(&args.hd).await?),
        Some(index) => {
            let keys = open_keys(&args.hd, &args.password).await?;
            (index, keys.address(index).await?)
        }
    };
    WalletAddressOutput {
        index,
        address,
        path: key_path(index),
    }
    .print(json);
    Ok(())
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

#[derive(Serialize)]
struct SafeStatus {
    chain_id: Option<u64>,
    safe: String,
    /// The key that signs for the Safe, and the address to send gas money to
    owner: OwnerOutput,
    /// Why the owner's public key must be assumed public, if it must
    #[serde(skip_serializing_if = "Option::is_none")]
    exposed: Option<&'static str>,
    /// The key every signature by the owner rotates to
    #[serde(skip_serializing_if = "Option::is_none")]
    next_owner: Option<OwnerOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_tx: Option<TxHash>,
    /// Retired keys whose ETH still has to be moved to the owner
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sweeps_owed_from: Vec<Address>,
    retired_keys: Vec<OwnerOutput>,
    #[serde(skip)]
    exposure: Option<Exposure>,
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

#[derive(Serialize)]
struct WalletStatusOutput {
    /// The wallet's funding address
    wallet: Address,
    /// The next key index that has never been handed out
    next_index: u32,
    safes: Vec<SafeStatus>,
}

impl Report for WalletStatusOutput {
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

async fn status(args: &WalletStatusArgs, json: bool) -> Result<()> {
    let wallet = wallet_id(&args.hd).await?;
    let state =
        read_state(&paths::home()?, wallet)?.unwrap_or_else(|| RotationState::new(wallet, 1));
    let only = args.safe.map(|safe| safe.to_string());
    let safes = state
        .safes
        .iter()
        .filter(|(key, _)| {
            only.as_ref()
                .is_none_or(|safe| key.ends_with(safe.as_str()))
        })
        .map(|(key, binding)| SafeStatus::new(key, binding))
        .collect();
    WalletStatusOutput {
        wallet,
        next_index: state.next_index,
        safes,
    }
    .print(json);
    Ok(())
}

#[derive(Serialize)]
struct WalletSyncOutput {
    safe: Address,
    owner: OwnerOutput,
    /// Wallet key indices found in use on chain
    used: Vec<u32>,
    /// Owner events read from the Safe's logs
    events: usize,
    next_index: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

impl Report for WalletSyncOutput {
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

async fn sync(args: WalletSyncArgs, json: bool) -> Result<()> {
    let ring = open_wallet(&args.hd, &args.password).await?;
    let mut config = rotation_config(args.multi_send_call_only, SpecId::OSAKA, 12, 120);
    config.scan_limit = args.scan_limit;
    let provider = http_provider(&args.rpc.rpc_url);
    let safe = match args.safe.safe {
        Some(safe) => safe,
        None => recorded_safe(ring.state(), provider.get_chain_id().await?, "--safe")?,
    };
    let mut rotating = RotatingSafe::with_keyring(provider, safe, ring, config).await?;
    let report = rotating.sync(args.from_block, args.chunk).await?;
    let warnings = rotating.take_warnings();
    if !json {
        print_warnings(&warnings);
    }
    WalletSyncOutput {
        safe,
        owner: report.current.into(),
        used: report.used,
        events: report.events,
        next_index: report.next_index,
        warnings,
    }
    .print(json);
    Ok(())
}

async fn sweep(args: WalletSweepArgs, json: bool) -> Result<()> {
    let ring = open_wallet(&args.hd, &args.password).await?;
    let mut config = rotation_config(None, SpecId::OSAKA, 12, args.timeout);
    config.sweep_reserve = args.sweep_reserve;
    let provider = http_provider(&args.rpc.rpc_url);
    let safe = match args.safe.safe {
        Some(safe) => safe,
        None => recorded_safe(ring.state(), provider.get_chain_id().await?, "--safe")?,
    };
    let mut rotating = RotatingSafe::with_keyring(provider, safe, ring, config).await?;
    rotating.schedule_retired_sweeps().await?;
    let report = rotating.sweep_all().await?;
    print_warnings(&rotating.take_warnings());
    let output = WalletSweepOutput {
        sweeps: report.swept.iter().copied().map(Into::into).collect(),
        still_owed: report
            .failed
            .iter()
            .map(|(from, error)| OwedSweep {
                from: *from,
                reason: error.to_string(),
            })
            .collect(),
    };
    output.print(json);
    if !output.still_owed.is_empty() {
        bail!(
            "{} sweep(s) could not be completed",
            output.still_owed.len()
        );
    }
    Ok(())
}

#[derive(Serialize)]
struct OwedSweep {
    from: Address,
    reason: String,
}

#[derive(Serialize)]
struct WalletSweepOutput {
    /// Transfers that moved ETH to the current owner
    sweeps: Vec<SweepOutput>,
    /// Retired keys that still hold ETH, and why it could not be moved
    #[serde(skip_serializing_if = "Vec::is_empty")]
    still_owed: Vec<OwedSweep>,
}

impl Report for WalletSweepOutput {
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let output = WalletStatusOutput {
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
}
