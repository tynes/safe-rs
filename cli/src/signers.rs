use std::path::Path;

use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre::{eyre, Result, WrapErr};
use safe_rs::keystore::decrypt_keystore;
use zeroize::Zeroizing;

use crate::any_signer::AnySigner;
use crate::cli::{PasswordArgs, PayerArgs, SignerArgs};
use crate::console::Console;
#[cfg(feature = "hd-wallet")]
pub use hd::*;

/// The signer the options name, asking `console`'s prompt for an
/// `--interactive` key or a keystore password, or connecting to the Ledger.
pub async fn create_signer(
    args: &SignerArgs,
    password: &PasswordArgs,
    console: &Console,
) -> Result<AnySigner> {
    if let Some(index) = args.ledger {
        if args.interactive || args.keystore.is_some() || hd_key(args).is_some() {
            return Err(eyre!(
                "--ledger cannot be combined with --interactive, --keystore or --hd-key"
            ));
        }
        return ledger_signer(index).await;
    }
    local_signer(args, password, console).map(AnySigner::from)
}

#[cfg(feature = "ledger")]
async fn ledger_signer(index: u32) -> Result<AnySigner> {
    let keys = safe_rs::LedgerKeys::connect().await?;
    Ok(keys.signer(index).await?.into())
}

#[cfg(not(feature = "ledger"))]
async fn ledger_signer(_index: u32) -> Result<AnySigner> {
    Err(eyre!(
        "this build of safe has no Ledger support (it was built without the `ledger` feature)"
    ))
}

/// A local key the options name (anything but `--ledger`).
fn local_signer(
    args: &SignerArgs,
    password: &PasswordArgs,
    console: &Console,
) -> Result<PrivateKeySigner> {
    // Priority: interactive > keystore > HD key > private_key
    if args.interactive {
        let key = console.secret("Enter private key: ")?;
        parse_private_key(&key)
    } else if let Some(keystore) = &args.keystore {
        let password = read_password(password, "Keystore password: ", console)?;
        keystore_signer(Path::new(keystore), password.as_bytes())
    } else if let Some(key) = hd_key(args) {
        hd_key_signer(key, password, None, console)
    } else if let Some(private_key) = &args.private_key {
        parse_private_key(private_key)
    } else {
        Err(eyre!(
            "No wallet specified. Use --private-key, --keystore, --hd-key, --ledger or \
             --interactive"
        ))
    }
}

impl SignerArgs {
    /// The signer these flags name, as the `safe` commands resolve it:
    /// `--interactive` asks `prompt` for the key, `--keystore` reads the
    /// password from `password` or asks `prompt`, `--ledger` connects
    /// to the Ledger.
    pub async fn resolve(
        &self,
        password: &PasswordArgs,
        prompt: std::sync::Arc<dyn crate::prompt::Prompt>,
    ) -> Result<AnySigner> {
        let console = Console::new(std::sync::Arc::new(crate::log::NoopLogger), prompt);
        create_signer(self, password, &console).await
    }
}

#[cfg(feature = "hd-wallet")]
fn hd_key(args: &SignerArgs) -> Option<&crate::cli::HdKey> {
    args.hd_key.as_ref()
}

#[cfg(not(feature = "hd-wallet"))]
fn hd_key(_: &SignerArgs) -> Option<&std::convert::Infallible> {
    None
}

#[cfg(not(feature = "hd-wallet"))]
fn hd_key_signer(
    key: &std::convert::Infallible,
    _: &PasswordArgs,
    _: Option<&Path>,
    _: &Console,
) -> Result<PrivateKeySigner> {
    match *key {}
}

/// The separate gas payer, if one was given.
pub fn create_payer(args: &PayerArgs) -> Result<Option<PrivateKeySigner>> {
    args.payer_private_key
        .as_deref()
        .map(parse_private_key)
        .transpose()
}

fn parse_private_key(key: &str) -> Result<PrivateKeySigner> {
    let key = key.trim();
    // Strip 0x prefix if present
    let key = key.strip_prefix("0x").unwrap_or(key);

    key.parse::<PrivateKeySigner>()
        .map_err(|e| eyre!("Invalid private key: {}", e))
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

/// Keys and state for `--hd-wallet` and `--ledger`.
#[cfg(feature = "hd-wallet")]
mod hd {
    use std::path::{Path, PathBuf};

    use alloy::primitives::Address;
    use alloy::signers::local::PrivateKeySigner;
    use color_eyre::eyre::{bail, eyre, Result, WrapErr};
    use safe_rs::keystore::keystore_address;
    use safe_rs::rotation::{KeySource, Keyring, StateFile};
    use safe_rs::HdWallet;
    use zeroize::Zeroizing;

    use super::{keystore_signer, parse_private_key, read_password};
    use crate::cli::{HdArgs, PasswordArgs};
    use crate::console::Console;
    use crate::keys::CliKeys;
    use crate::paths;

    /// The key of a Safe's current owner, for `safe rotate --from-*`.
    pub fn legacy_signer(
        private_key: Option<&str>,
        keystore: Option<&Path>,
        interactive: bool,
        console: &Console,
    ) -> Result<Option<PrivateKeySigner>> {
        if let Some(key) = private_key {
            return parse_private_key(key).map(Some);
        }
        if let Some(path) = keystore {
            // Always prompted: the HD wallet's password options do not apply to it.
            let password = console.secret(&format!("Password for {}: ", path.display()))?;
            return keystore_signer(path, password.as_bytes()).map(Some);
        }
        if interactive {
            let key = console.secret("Enter the current owner's private key: ")?;
            return parse_private_key(&key).map(Some);
        }
        Ok(None)
    }

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

    /// The wallet `--hd-wallet` / `--ledger` chose.
    #[derive(Debug, PartialEq, Eq)]
    pub enum KeyChoice {
        /// A connected Ledger
        Ledger,
        /// An HD wallet keystore file
        Phrase(PathBuf),
    }

    /// Which wallet the options name. `--ledger` wins, so an `SAFE_HD_WALLET`
    /// left in the environment does not get in its way.
    pub fn key_choice(hd: &HdArgs, home: &Path) -> Result<KeyChoice> {
        if hd.ledger {
            return Ok(KeyChoice::Ledger);
        }
        let wallet = hd.hd_wallet.as_deref().ok_or_else(|| {
            eyre!("no wallet given: pass --hd-wallet <NAME|PATH> (or set SAFE_HD_WALLET), or --ledger")
        })?;
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
                "cannot read HD wallet {} (create one with `safe wallet new`)",
                path.display()
            ))
        })
    }

    /// Decrypts the HD wallet at `path`.
    fn load_phrase(path: &Path, password: &PasswordArgs, console: &Console) -> Result<HdWallet> {
        let json = read_wallet_file(path)?;
        let password = read_password(
            password,
            &format!("Password for {}: ", path.display()),
            console,
        )?;
        HdWallet::from_keystore_json(&json, password.as_bytes())
            .wrap_err_with(|| format!("cannot open HD wallet {}", path.display()))
    }

    #[cfg(feature = "ledger")]
    async fn connect_ledger() -> Result<CliKeys> {
        Ok(CliKeys::Ledger(safe_rs::LedgerKeys::connect().await?))
    }

    #[cfg(not(feature = "ledger"))]
    #[allow(
        clippy::unused_async,
        reason = "matches the signature of the Ledger build"
    )]
    async fn connect_ledger() -> Result<CliKeys> {
        bail!(
            "this build of safe has no Ledger support (it was built without the `ledger` feature)"
        )
    }

    /// The keys `--hd-wallet` / `--ledger` chose. A phrase is decrypted (asking
    /// for its password); a Ledger is connected (never asking for a password).
    pub async fn open_keys(
        hd: &HdArgs,
        password: &PasswordArgs,
        home: Option<&Path>,
        console: &Console,
    ) -> Result<CliKeys> {
        match key_choice(hd, &paths::home_or(home)?)? {
            KeyChoice::Ledger => connect_ledger().await,
            KeyChoice::Phrase(path) => Ok(CliKeys::Phrase(Box::new(load_phrase(
                &path, password, console,
            )?))),
        }
    }

    /// The key at `m/44'/60'/0'/0/{key.index}` of the HD wallet `key.wallet`
    /// (under `home`, default the data directory), decrypting the wallet with
    /// `password` or the prompt.
    pub fn hd_key_signer(
        key: &crate::cli::HdKey,
        password: &PasswordArgs,
        home: Option<&Path>,
        console: &Console,
    ) -> Result<PrivateKeySigner> {
        let path = paths::wallet_file(&paths::home_or(home)?, &key.wallet);
        let wallet = load_phrase(&path, password, console)?;
        Ok(wallet.key_at(key.index)?)
    }

    /// The wallet's funding address, which identifies it: read from the keystore
    /// without its password, or asked of the Ledger.
    pub async fn wallet_id(hd: &HdArgs, home: Option<&Path>) -> Result<Address> {
        match key_choice(hd, &paths::home_or(home)?)? {
            KeyChoice::Ledger => Ok(connect_ledger().await?.address(0).await?),
            KeyChoice::Phrase(path) => keystore_address(&read_wallet_file(&path)?)?
                .ok_or_else(|| eyre!("{} has no address field", path.display())),
        }
    }

    /// Opens and locks the rotation state of the wallet whose key 0 is `wallet_id`.
    pub fn open_state(wallet_id: Address, home: Option<&Path>) -> Result<StateFile> {
        let path = paths::state_file(&paths::home_or(home)?, wallet_id);
        StateFile::open(&path, wallet_id).map_err(|e| match e {
            safe_rs::Error::StateLocked(_) => color_eyre::eyre::Report::new(e).wrap_err(format!(
                "another safe command is using this HD wallet ({} is locked); wait for it to finish",
                path.display()
            )),
            other => eyre!(other),
        })
    }

    /// The wallet `--hd-wallet` / `--ledger` chose, paired with its locked state.
    pub async fn open_wallet(
        hd: &HdArgs,
        password: &PasswordArgs,
        home: Option<&Path>,
        console: &Console,
    ) -> Result<Keyring<CliKeys>> {
        let keys = open_keys(hd, password, home, console).await?;
        let store = open_state(keys.address(0).await?, home)?;
        Ok(Keyring::open(keys, store).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "hd-wallet")]
    use crate::cli::HdArgs;
    #[cfg(feature = "hd-wallet")]
    use safe_rs::HdWallet;

    #[cfg(feature = "hd-wallet")]
    #[test]
    fn ledger_wins_over_an_hd_wallet_from_the_environment() {
        let home = Path::new("/data");
        // As if SAFE_HD_WALLET were set and --ledger passed.
        let both = HdArgs {
            hd_wallet: Some("treasury".to_string()),
            ledger: true,
        };
        assert_eq!(key_choice(&both, home).unwrap(), KeyChoice::Ledger);
        let phrase = HdArgs {
            hd_wallet: Some("treasury".to_string()),
            ledger: false,
        };
        assert_eq!(
            key_choice(&phrase, home).unwrap(),
            KeyChoice::Phrase(home.join("wallets/treasury.json"))
        );
        assert!(key_choice(&HdArgs::default(), home).is_err());
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
        #[cfg(feature = "hd-wallet")]
        assert_eq!(*new_password(&args, &console).unwrap(), " two words ");
    }

    #[cfg(feature = "hd-wallet")]
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

    #[cfg(feature = "hd-wallet")]
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
            HdWallet::from_phrase(phrase).unwrap().id()
        );
        assert!(keystore_signer(&path, b"nope").is_err());
        assert!(keystore_signer(&dir.path().join("missing.json"), b"pw").is_err());
    }
}
