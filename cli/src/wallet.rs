use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre::{bail, eyre, Result, WrapErr};
use safe_rs::keystore::{decrypt_keystore, keystore_address};
use safe_rs::rotation::StateFile;
use safe_rs::HdWallet;
use zeroize::Zeroizing;

use crate::cli::{HdArgs, PasswordArgs, PayerArgs, WalletArgs};
use crate::paths;

pub fn create_signer(args: &WalletArgs, password: &PasswordArgs) -> Result<PrivateKeySigner> {
    // Priority: interactive > keystore > private_key
    if args.interactive {
        let key = Zeroizing::new(rpassword::prompt_password("Enter private key: ")?);
        parse_private_key(&key)
    } else if let Some(keystore) = &args.keystore {
        let password = read_password(password, "Keystore password: ")?;
        keystore_signer(Path::new(keystore), password.as_bytes())
    } else if let Some(private_key) = &args.private_key {
        parse_private_key(private_key)
    } else {
        Err(eyre!(
            "No wallet specified. Use --private-key, --keystore or --interactive"
        ))
    }
}

/// The separate gas payer, if one was given.
pub fn create_payer(args: &PayerArgs) -> Result<Option<PrivateKeySigner>> {
    args.payer_private_key
        .as_deref()
        .map(parse_private_key)
        .transpose()
}

/// The key of a Safe's current owner, for `safe rotate --from-*`.
pub fn legacy_signer(
    private_key: Option<&str>,
    keystore: Option<&Path>,
    interactive: bool,
) -> Result<Option<PrivateKeySigner>> {
    if let Some(key) = private_key {
        return parse_private_key(key).map(Some);
    }
    if let Some(path) = keystore {
        // Always prompted: the HD wallet's password options do not apply to it.
        let password = Zeroizing::new(rpassword::prompt_password(format!(
            "Password for {}: ",
            path.display()
        ))?);
        return keystore_signer(path, password.as_bytes()).map(Some);
    }
    if interactive {
        let key = Zeroizing::new(rpassword::prompt_password(
            "Enter the current owner's private key: ",
        )?);
        return parse_private_key(&key).map(Some);
    }
    Ok(None)
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

/// The password, from `--password-file`, `--password` or a prompt, in that order.
pub fn read_password(args: &PasswordArgs, prompt: &str) -> Result<Zeroizing<String>> {
    if let Some(path) = &args.password_file {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("cannot read password file {}", path.display()))?;
        return Ok(Zeroizing::new(strip_newline(text)));
    }
    if let Some(password) = &args.password {
        eprintln!(
            "warning: --password is visible in the process list and shell history; \
             prefer --password-file or the prompt"
        );
        return Ok(Zeroizing::new(password.clone()));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// A password for a new keystore: prompted twice unless supplied.
pub fn new_password(args: &PasswordArgs) -> Result<Zeroizing<String>> {
    let supplied = args.password_file.is_some() || args.password.is_some();
    let password = read_password(args, "New wallet password: ")?;
    if !supplied {
        let again = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
        if *again != *password {
            bail!("the passwords do not match");
        }
    }
    if password.is_empty() {
        bail!("the wallet password must not be empty");
    }
    if !password.is_ascii() {
        eprintln!(
            "warning: the password has non-ASCII characters; other tools normalize \
             them differently and may not open this keystore"
        );
    }
    Ok(password)
}

/// The keystore file `--hd-wallet` refers to.
pub fn hd_wallet_file(hd: &HdArgs) -> Result<PathBuf> {
    let wallet = hd.hd_wallet.as_deref().ok_or_else(|| {
        eyre!("no HD wallet given: pass --hd-wallet <NAME|PATH> or set SAFE_HD_WALLET")
    })?;
    Ok(paths::wallet_file(&paths::home()?, wallet))
}

fn read_wallet_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).wrap_err_with(|| {
        format!(
            "cannot read HD wallet {} (create one with `safe wallet new`)",
            path.display()
        )
    })
}

/// The wallet's funding address, read from the keystore without a password.
pub fn hd_wallet_id(hd: &HdArgs) -> Result<Address> {
    let path = hd_wallet_file(hd)?;
    keystore_address(&read_wallet_file(&path)?)?
        .ok_or_else(|| eyre!("{} has no address field", path.display()))
}

/// Decrypts the HD wallet `--hd-wallet` refers to.
pub fn load_hd_wallet(hd: &HdArgs, password: &PasswordArgs) -> Result<HdWallet> {
    let path = hd_wallet_file(hd)?;
    let json = read_wallet_file(&path)?;
    let password = read_password(password, &format!("Password for {}: ", path.display()))?;
    HdWallet::from_keystore_json(&json, password.as_bytes())
        .wrap_err_with(|| format!("cannot open HD wallet {}", path.display()))
}

/// Opens and locks the rotation state of `wallet`.
pub fn open_state(wallet: &HdWallet) -> Result<StateFile> {
    let path = paths::state_file(&paths::home()?, wallet.id());
    StateFile::open(&path, wallet.id()).map_err(|e| match e {
        safe_rs::Error::StateLocked(_) => eyre!(
            "another safe command is using this HD wallet ({} is locked); wait for it to finish",
            path.display()
        ),
        other => eyre!(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_files_lose_only_their_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, " two words \r\n").unwrap();
        let args = PasswordArgs {
            password_file: Some(path),
            password: Some("ignored".to_string()),
        };
        assert_eq!(*read_password(&args, "").unwrap(), " two words ");
        assert_eq!(*new_password(&args).unwrap(), " two words ");
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
        assert!(new_password(&args).is_err());
    }

    #[test]
    fn single_key_options_are_detected() {
        let none = WalletArgs {
            private_key: None,
            keystore: None,
            interactive: false,
        };
        assert!(!none.is_set());
        let env_key = WalletArgs {
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
            HdWallet::from_phrase(phrase).unwrap().id()
        );
        assert!(keystore_signer(&path, b"nope").is_err());
        assert!(keystore_signer(&dir.path().join("missing.json"), b"pw").is_err());
    }
}
