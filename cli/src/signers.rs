use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre::{bail, eyre, Result, WrapErr};
use foundry_wallets::wallet_raw::RawWalletOpts;
use foundry_wallets::{WalletOpts, WalletSigner};
use safe_rs::keystore::{decrypt_keystore, keystore_address};
use safe_rs::rotation::{KeySource, Keyring, StateFile};
use safe_rs::{KeyPath, LedgerKeys, MnemonicWallet};
use zeroize::Zeroizing;

use crate::any_signer::AnySigner;
use crate::cli::{GasPayerArgs, OwnerKeysArgs, PasswordArgs, SignerArgs};
use crate::console::Console;
use crate::keys::CliKeys;
use crate::ledger_wallet::LedgerWallet;
use crate::paths;

/// The flags that name a key, for the message when none is given.
pub(crate) const SIGNER_FLAGS_HELP: &str =
    "--private-key, --keystore, --account, --mnemonic, --ledger, \
     --trezor, --aws, --gcp, --turnkey or --interactive";

/// The signer the options name, as `cast` resolves them: a hardware wallet
/// or remote key first, then `--interactive`, `--private-key`, `--mnemonic`,
/// and last `--keystore` / `--account`.
///
/// `console`'s prompt asks for an `--interactive` key and a keystore or
/// mnemonic wallet password (unless `--password` or `--password-file` gives it): the
/// library never reads the terminal itself. With `--from`, the key must have
/// that address.
pub async fn create_signer(args: &SignerArgs, console: &Console) -> Result<AnySigner> {
    let signer = resolve(args, console).await?;
    if let Some(from) = args.from {
        if signer.address() != from {
            bail!(
                "the key given has address {}, not {from} (--from)",
                signer.address()
            );
        }
    }
    Ok(signer)
}

async fn resolve(args: &SignerArgs, console: &Console) -> Result<AnySigner> {
    let ledger_wallet = match &args.mnemonic {
        Some(value) => named_ledger_wallet(value)?,
        None => None,
    };
    if let (true, Some(wallet)) = (args.ledger, &ledger_wallet) {
        return ledger_wallet_signer(args, wallet).await;
    }
    if args.ledger || args.trezor || args.aws || args.gcp || args.turnkey {
        let opts = WalletOpts {
            raw: RawWalletOpts {
                hd_path: args.hd_path.as_deref().map(normalize_hd_path),
                mnemonic_index: args.mnemonic_index,
                ..RawWalletOpts::default()
            },
            ledger: args.ledger,
            trezor: args.trezor,
            aws: args.aws,
            gcp: args.gcp,
            turnkey: args.turnkey,
            ..WalletOpts::default()
        };
        // Boxed: the remote signers' futures are deep enough to overflow the
        // compiler's layout depth in every command that awaits this.
        return Ok(Box::pin(opts.signer()).await?.into());
    }
    if args.interactive {
        let key = console.secret("Enter private key: ")?;
        return private_key_signer(&key);
    }
    if let Some(key) = &args.private_key {
        return private_key_signer(key);
    }
    if let Some(wallet) = &ledger_wallet {
        return ledger_wallet_signer(args, wallet).await;
    }
    if let Some(mnemonic) = &args.mnemonic {
        let phrase = mnemonic_phrase(mnemonic, &args.password, console)?;
        let signer = WalletSigner::from_mnemonic(
            &phrase,
            args.mnemonic_passphrase.as_deref(),
            args.hd_path.as_deref(),
            args.mnemonic_index,
        )?;
        return Ok(signer.into());
    }
    if let Some(path) = foundry_wallets::utils::maybe_get_keystore_path(
        args.keystore_path.as_deref(),
        args.keystore_account_name.as_deref(),
    )? {
        if path.is_dir() {
            bail!(
                "keystore path {} is a directory: name the keystore file",
                path.display()
            );
        }
        let password = read_password(&args.password, "Enter keystore password: ", console)?;
        return keystore_signer(&path, password.as_bytes()).map(AnySigner::from);
    }
    Err(eyre!("No wallet specified. Use {SIGNER_FLAGS_HELP}"))
}

impl SignerArgs {
    /// The signer these flags name, as the `safe` commands resolve it:
    /// `--interactive` asks `prompt` for the key, `--keystore`, `--account`
    /// and a mnemonic wallet `--mnemonic` read the password from the password
    /// flags or ask `prompt`, `--ledger` and `--trezor` connect to the device.
    pub async fn resolve(
        &self,
        prompt: std::sync::Arc<dyn crate::prompt::Prompt>,
    ) -> Result<AnySigner> {
        let console = Console::with_prompt(prompt);
        create_signer(self, &console).await
    }
}

impl GasPayerArgs {
    /// The gas payer these flags name, if any, resolved like
    /// [`SignerArgs::resolve`].
    pub async fn resolve(
        &self,
        prompt: std::sync::Arc<dyn crate::prompt::Prompt>,
    ) -> Result<Option<AnySigner>> {
        let console = Console::with_prompt(prompt);
        create_payer(self, &console).await
    }
}

/// The separate gas payer, if one was given.
pub async fn create_payer(args: &GasPayerArgs, console: &Console) -> Result<Option<AnySigner>> {
    if !args.is_set() {
        return Ok(None);
    }
    create_signer(&args.as_signer(), console)
        .await
        .wrap_err("cannot open the gas payer's key")
        .map(Some)
}

/// A derivation path with `'` for hardened components, which a device takes:
/// `m/44h/60h/0h/0/0` becomes `m/44'/60'/0'/0/0`. Anything that does not
/// parse as a path goes through as it is, for the device to judge.
fn normalize_hd_path(path: &str) -> String {
    path.parse::<KeyPath>()
        .map_or_else(|_| path.to_string(), |path| path.to_string())
}

/// The Ledger wallet `--mnemonic <NAME|PATH>` names, if it names one: a file
/// at that path, or a name under the data directory. A phrase never does.
fn named_ledger_wallet(value: &str) -> Result<Option<LedgerWallet>> {
    let value = value.trim();
    if value.is_empty() || value.contains(char::is_whitespace) {
        return Ok(None);
    }
    let path = Path::new(value);
    if path.is_file() {
        return LedgerWallet::read(path);
    }
    LedgerWallet::read(&paths::wallet_file(&paths::home()?, value))
}

/// One key of a Ledger wallet, as a signer: key `--mnemonic-index` (0, the
/// funding key, by default), or the literal `--mnemonic-derivation-path`.
/// The funding key is checked against the wallet's record, so the wrong
/// device fails before anything is signed.
async fn ledger_wallet_signer(args: &SignerArgs, wallet: &LedgerWallet) -> Result<AnySigner> {
    if args.mnemonic_passphrase.is_some() {
        bail!("--mnemonic-passphrase does not apply to a Ledger wallet: set it on the device");
    }
    let (hd_path, funding) = match &args.hd_path {
        Some(path) => (normalize_hd_path(path), false),
        None => (
            wallet.path.key(args.mnemonic_index)?,
            args.mnemonic_index == 0,
        ),
    };
    let opts = WalletOpts {
        raw: RawWalletOpts {
            hd_path: Some(hd_path),
            ..RawWalletOpts::default()
        },
        ledger: true,
        ..WalletOpts::default()
    };
    let signer: AnySigner = Box::pin(opts.signer()).await?.into();
    if funding {
        wallet.check_device(signer.address())?;
    }
    Ok(signer)
}

/// A raw private key, with or without `0x`, as `cast` reads it.
fn private_key_signer(key: &str) -> Result<AnySigner> {
    Ok(foundry_wallets::utils::create_private_key_signer(key.trim())?.into())
}

/// The phrase `--mnemonic` names, in this order: a `safe` mnemonic wallet (the
/// path of a mnemonic keystore, or a name under the data directory, which a
/// phrase of 12 or more words can never be), any other file (read as the
/// phrase, as `cast` does), or else the phrase itself.
fn mnemonic_phrase(
    value: &str,
    password: &PasswordArgs,
    console: &Console,
) -> Result<Zeroizing<String>> {
    let path = Path::new(value);
    if path.is_file() {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("cannot read mnemonic file {}", path.display()))?;
        if text.trim_start().starts_with('{') {
            return keystore_phrase(path, &text, password, console);
        }
        return Ok(normalize(&text));
    }
    if !value.trim().contains(char::is_whitespace) {
        let wallet = paths::wallet_file(&paths::home()?, value.trim());
        if wallet.is_file() {
            let text = std::fs::read_to_string(&wallet)
                .wrap_err_with(|| format!("cannot read mnemonic wallet {}", wallet.display()))?;
            return keystore_phrase(&wallet, &text, password, console);
        }
        bail!(
            "--mnemonic {value}: no such file, and no mnemonic wallet {} (create one with \
             `safe wallet new`)",
            wallet.display()
        );
    }
    Ok(normalize(value))
}

/// The phrase of the mnemonic keystore at `path`.
fn keystore_phrase(
    path: &Path,
    json: &str,
    password: &PasswordArgs,
    console: &Console,
) -> Result<Zeroizing<String>> {
    let password = read_password(password, &wallet_password_label(path), console)?;
    let decrypted = decrypt_keystore(json, password.as_bytes())
        .wrap_err_with(|| format!("cannot open mnemonic wallet {}", path.display()))?;
    match decrypted.mnemonic {
        Some(mnemonic) => Ok(mnemonic.phrase),
        None => bail!(
            "{} is a keystore without a phrase: pass it with --keystore",
            path.display()
        ),
    }
}

/// The words of a phrase, one space apart.
fn normalize(phrase: &str) -> Zeroizing<String> {
    Zeroizing::new(phrase.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn keystore_signer(path: &Path, password: &[u8]) -> Result<PrivateKeySigner> {
    let json = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("cannot read keystore {}", path.display()))?;
    Ok(decrypt_keystore(&json, password)
        .wrap_err_with(|| format!("cannot open keystore {}", path.display()))?
        .signer)
}

fn strip_newline(mut text: String) -> String {
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    text
}

/// The password, from `--password-file`, `--password` or the prompt, in that order.
pub fn read_password(
    args: &PasswordArgs,
    label: &str,
    console: &Console,
) -> Result<Zeroizing<String>> {
    if let Some(path) = &args.password_file {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("cannot read password file {}", path.display()))?;
        return Ok(Zeroizing::new(strip_newline(text)));
    }
    if let Some(password) = &args.password {
        console.warn(
            "--password is visible in the process list and shell history; \
             prefer --password-file or the prompt",
        );
        return Ok(Zeroizing::new(password.clone()));
    }
    Ok(console.secret(label)?)
}

// Keys and state for the rotating owner keys: `--mnemonic` and `--ledger`
// under `--rotate`, and `safe wallet`. `home` is the data directory.

/// A password for a new keystore: asked twice unless supplied.
pub fn new_password(args: &PasswordArgs, console: &Console) -> Result<Zeroizing<String>> {
    let supplied = args.password_file.is_some() || args.password.is_some();
    let password = read_password(args, "New wallet password: ", console)?;
    if !supplied {
        let again = console.secret("Repeat password: ")?;
        if *again != *password {
            bail!("the passwords do not match");
        }
    }
    Ok(password)
}

/// Checks a new wallet password, returning the warnings it raises.
pub fn check_new_password(password: &str) -> Result<Vec<String>> {
    if password.is_empty() {
        bail!("the wallet password must not be empty");
    }
    let mut warnings = Vec::new();
    if !password.is_ascii() {
        warnings.push(
            "the password has non-ASCII characters; other tools normalize them \
             differently and may not open this keystore"
                .to_string(),
        );
    }
    Ok(warnings)
}

/// The wallet `--mnemonic` / `--ledger` chose.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyChoice {
    /// A connected Ledger: at the first Ledger Live account for a bare
    /// `--ledger`, or where a Ledger wallet file says
    Ledger(Option<LedgerWallet>),
    /// A mnemonic wallet keystore file
    Phrase(PathBuf),
}

impl KeyChoice {
    /// The path of key 0, from which key `i` is `i` past the last number.
    pub fn key_path(&self) -> KeyPath {
        match self {
            Self::Ledger(Some(wallet)) => wallet.path.clone(),
            Self::Ledger(None) | Self::Phrase(_) => KeyPath::default(),
        }
    }
}

/// Which wallet the options name. A `--mnemonic` naming a Ledger wallet file
/// is that Ledger wallet; otherwise `--ledger` wins, so a `mnemonic` left in
/// the config file does not get in its way.
pub fn key_choice(owner_keys: &OwnerKeysArgs, home: &Path) -> Result<KeyChoice> {
    if let Some(wallet) = &owner_keys.mnemonic {
        if let Some(ledger) = LedgerWallet::read(&paths::wallet_file(home, wallet))? {
            return Ok(KeyChoice::Ledger(Some(ledger)));
        }
    }
    if owner_keys.ledger {
        return Ok(KeyChoice::Ledger(None));
    }
    let wallet = owner_keys
        .mnemonic
        .as_deref()
        .ok_or_else(|| eyre!("no wallet given: pass --mnemonic <NAME|PATH> or --ledger"))?;
    Ok(KeyChoice::Phrase(paths::wallet_file(home, wallet)))
}

fn read_wallet_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        let report = if e.kind() == std::io::ErrorKind::NotFound {
            color_eyre::eyre::Report::new(crate::wallet::MissingWallet(path.to_path_buf()))
        } else {
            color_eyre::eyre::Report::new(e)
        };
        report.wrap_err(format!(
            "cannot read mnemonic wallet {} (create one with `safe wallet new`)",
            path.display()
        ))
    })
}

/// What the password prompt of the mnemonic wallet at `path` says.
pub(crate) fn wallet_password_label(path: &Path) -> String {
    format!("Password for {}: ", path.display())
}

/// Decrypts the mnemonic wallet at `path`.
fn load_phrase(path: &Path, password: &PasswordArgs, console: &Console) -> Result<MnemonicWallet> {
    let json = read_wallet_file(path)?;
    let password = read_password(password, &wallet_password_label(path), console)?;
    MnemonicWallet::from_keystore_json(&json, password.as_bytes())
        .wrap_err_with(|| format!("cannot open mnemonic wallet {}", path.display()))
}

/// Connects to the Ledger, at the wallet's path if there is one, after
/// checking its funding key is the wallet's.
async fn connect_ledger(wallet: Option<&LedgerWallet>) -> Result<CliKeys> {
    let Some(wallet) = wallet else {
        return Ok(CliKeys::Ledger(LedgerKeys::connect().await?));
    };
    let keys = LedgerKeys::connect_at(wallet.path.clone()).await?;
    wallet.check_device(keys.address(0).await?)?;
    Ok(CliKeys::Ledger(keys))
}

/// The keys `--mnemonic` / `--ledger` chose. A phrase is decrypted (asking
/// for its password); a Ledger is connected (never asking for a password).
pub async fn open_keys(
    owner_keys: &OwnerKeysArgs,
    home: &Path,
    console: &Console,
) -> Result<CliKeys> {
    match key_choice(owner_keys, home)? {
        KeyChoice::Ledger(wallet) => connect_ledger(wallet.as_ref()).await,
        KeyChoice::Phrase(path) => Ok(CliKeys::Phrase(Box::new(load_phrase(
            &path,
            &owner_keys.password,
            console,
        )?))),
    }
}

/// The key at `m/44'/60'/0'/0/{index}` of the mnemonic wallet `wallet` (a name
/// under `home` or a keystore path), decrypting the wallet with `password`
/// or the prompt.
pub fn mnemonic_key_signer(
    wallet: &str,
    index: u32,
    password: &PasswordArgs,
    home: &Path,
    console: &Console,
) -> Result<PrivateKeySigner> {
    let path = paths::wallet_file(home, wallet);
    if LedgerWallet::read(&path)?.is_some() {
        bail!(
            "{} is a Ledger wallet: its keys never leave the device",
            path.display()
        );
    }
    let wallet = load_phrase(&path, password, console)?;
    Ok(wallet.key_at(index)?)
}

/// The wallet's funding address, which identifies it: read from the keystore
/// without its password or from the Ledger wallet file, or asked of the
/// Ledger for a bare `--ledger`.
pub async fn wallet_id(owner_keys: &OwnerKeysArgs, home: &Path) -> Result<Address> {
    match key_choice(owner_keys, home)? {
        KeyChoice::Ledger(Some(wallet)) => Ok(wallet.address),
        KeyChoice::Ledger(None) => Ok(connect_ledger(None).await?.address(0).await?),
        KeyChoice::Phrase(path) => keystore_address(&read_wallet_file(&path)?)?
            .ok_or_else(|| eyre!("{} has no address field", path.display())),
    }
}

/// Opens and locks the rotation state of the wallet whose key 0 is `wallet_id`.
pub fn open_state(wallet_id: Address, home: &Path) -> Result<StateFile> {
    let path = paths::state_file(home, wallet_id);
    StateFile::open(&path, wallet_id).map_err(|e| match e {
        safe_rs::Error::StateLocked(_) => color_eyre::eyre::Report::new(e).wrap_err(format!(
            "another safe command is using this mnemonic wallet ({} is locked); wait for it to finish",
            path.display()
        )),
        other => eyre!(other),
    })
}

/// The wallet `--mnemonic` / `--ledger` chose, paired with its locked state.
/// `home` defaults to the data directory.
pub async fn open_wallet(
    owner_keys: &OwnerKeysArgs,
    home: Option<&Path>,
    console: &Console,
) -> Result<Keyring<CliKeys>> {
    let home = paths::home_or(home)?;
    let keys = open_keys(owner_keys, &home, console).await?;
    let store = open_state(keys.address(0).await?, &home)?;
    Ok(Keyring::open(keys, store).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_wins_over_a_configured_mnemonic_wallet() {
        let home = Path::new("/data");
        // As if the config file named a wallet and --ledger were passed.
        let both = OwnerKeysArgs {
            mnemonic: Some("treasury".to_string()),
            ledger: true,
            ..OwnerKeysArgs::default()
        };
        assert_eq!(key_choice(&both, home).unwrap(), KeyChoice::Ledger(None));
        let phrase = OwnerKeysArgs {
            mnemonic: Some("treasury".to_string()),
            ledger: false,
            ..OwnerKeysArgs::default()
        };
        assert_eq!(
            key_choice(&phrase, home).unwrap(),
            KeyChoice::Phrase(home.join("wallets/treasury.json"))
        );
        assert!(key_choice(&OwnerKeysArgs::default(), home).is_err());
    }

    #[test]
    fn a_ledger_wallet_file_names_its_path() {
        let home = tempfile::tempdir().unwrap();
        let wallets = paths::wallets_dir(home.path());
        std::fs::create_dir_all(&wallets).unwrap();
        let path: KeyPath = "m/44h/60h/2h/0/0".parse().unwrap();
        let wallet = LedgerWallet::new(path.clone(), Address::repeat_byte(0x33));
        std::fs::write(wallets.join("cold.json"), wallet.to_json()).unwrap();

        for ledger in [false, true] {
            let args = OwnerKeysArgs {
                mnemonic: Some("cold".to_string()),
                ledger,
                ..OwnerKeysArgs::default()
            };
            let choice = key_choice(&args, home.path()).unwrap();
            let KeyChoice::Ledger(Some(read)) = &choice else {
                panic!("{choice:?}");
            };
            assert_eq!(read.address, wallet.address);
            assert_eq!(choice.key_path(), path);
        }
        assert_eq!(
            KeyChoice::Ledger(None).key_path().to_string(),
            "m/44'/60'/0'/0/0"
        );
        let refused = mnemonic_key_signer(
            "cold",
            1,
            &PasswordArgs::default(),
            home.path(),
            &Console::default(),
        )
        .unwrap_err();
        assert!(refused.to_string().contains("Ledger wallet"), "{refused}");
    }

    #[test]
    fn hd_paths_take_h_for_hardened() {
        assert_eq!(normalize_hd_path("m/44h/60H/1h/0/0"), "m/44'/60'/1'/0/0");
        assert_eq!(normalize_hd_path("m/44'/60'/0'/0/3"), "m/44'/60'/0'/0/3");
        assert_eq!(normalize_hd_path("garbage"), "garbage");
    }

    #[test]
    fn password_files_lose_only_their_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, " two words \r\n").unwrap();
        let args = PasswordArgs {
            password_file: Some(path),
            password: Some("ignored".to_string()),
        };
        let console = Console::default();
        assert_eq!(*read_password(&args, "", &console).unwrap(), " two words ");
        assert_eq!(*new_password(&args, &console).unwrap(), " two words ");
    }

    #[test]
    fn empty_new_passwords_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "\n").unwrap();
        let args = PasswordArgs {
            password_file: Some(path),
            password: None,
        };
        let password = new_password(&args, &Console::default()).unwrap();
        assert!(check_new_password(&password).is_err());
        assert!(check_new_password("pässword").unwrap()[0].contains("non-ASCII"));
    }

    #[test]
    fn single_key_options_are_detected() {
        let none = SignerArgs::default();
        assert!(!none.is_set());
        let env_key = SignerArgs {
            private_key: Some("0x01".to_string()),
            ..none.clone()
        };
        assert!(env_key.is_set());
    }

    #[test]
    fn a_keystore_file_yields_its_key() {
        use rand::rngs::OsRng;
        use safe_rs::keystore::{encrypt_mnemonic_keystore, ScryptParams};

        let phrase = "test test test test test test test test test test test junk";
        let params = ScryptParams {
            log_n: 4,
            r: 8,
            p: 1,
        };
        let json = encrypt_mnemonic_keystore(phrase, b"pw", params, &mut OsRng).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        std::fs::write(&path, json).unwrap();

        let signer = keystore_signer(&path, b"pw").unwrap();
        assert_eq!(
            signer.address(),
            MnemonicWallet::from_phrase(phrase).unwrap().id()
        );
        assert!(keystore_signer(&path, b"nope").is_err());
        assert!(keystore_signer(&dir.path().join("missing.json"), b"pw").is_err());
    }
}
