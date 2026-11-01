//! Where HD wallets and their rotation state live on disk.
//!
//! Everything is under one directory: `$SAFE_RS_HOME`, or `~/.safe-rs`.
//!
//! - `wallets/<name>.json`: the encrypted phrase (a mnemonic keystore)
//! - `state/<funding address>.json`: which keys were used, and for which Safe

use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use color_eyre::eyre::{eyre, Result};

/// Environment variable overriding the data directory.
pub const HOME_ENV: &str = "SAFE_RS_HOME";

/// The data directory.
pub fn home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(HOME_ENV).filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    std::env::home_dir()
        .map(|home| home.join(".safe-rs"))
        .ok_or_else(|| eyre!("cannot find the home directory; set {HOME_ENV}"))
}

/// `home` if given, else [`home`].
pub fn home_or(home: Option<&Path>) -> Result<PathBuf> {
    match home {
        Some(home) => Ok(home.to_path_buf()),
        None => self::home(),
    }
}

/// The directory holding wallet keystores.
pub fn wallets_dir(home: &Path) -> PathBuf {
    home.join("wallets")
}

/// True if `wallet` names a file rather than a wallet under the data directory.
fn is_path(wallet: &str) -> bool {
    wallet.contains(std::path::MAIN_SEPARATOR)
        || wallet.contains('/')
        || Path::new(wallet)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

/// The keystore file for `--hd-wallet <NAME|PATH>`.
pub fn wallet_file(home: &Path, wallet: &str) -> PathBuf {
    if is_path(wallet) {
        PathBuf::from(wallet)
    } else {
        wallets_dir(home).join(format!("{wallet}.json"))
    }
}

/// Checks that `name` is usable as a wallet file name.
pub fn validate_wallet_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(eyre!(
            "wallet names may only contain letters, digits, '-' and '_'"
        ))
    }
}

/// The rotation state file of the wallet whose funding address is `wallet_id`.
///
/// The state follows the phrase, not the keystore file: two keystores of the
/// same phrase share it.
pub fn state_file(home: &Path, wallet_id: Address) -> PathBuf {
    home.join("state")
        .join(format!("{}.json", wallet_id.to_string().to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_resolve_under_the_data_directory_and_paths_do_not() {
        let home = Path::new("/data");
        assert_eq!(
            wallet_file(home, "treasury"),
            Path::new("/data/wallets/treasury.json")
        );
        assert_eq!(
            wallet_file(home, "./treasury.json"),
            Path::new("./treasury.json")
        );
        assert_eq!(wallet_file(home, "backup.json"), Path::new("backup.json"));
        assert_eq!(
            wallet_file(home, "/keys/treasury"),
            Path::new("/keys/treasury")
        );
    }

    #[test]
    fn wallet_names_cannot_escape_the_directory() {
        for name in ["treasury", "cold-1", "a_b"] {
            validate_wallet_name(name).unwrap();
        }
        for name in ["", "../x", "a/b", "a.json", "a b"] {
            assert!(validate_wallet_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn state_is_named_after_the_funding_address() {
        let id = Address::repeat_byte(0xAB);
        assert_eq!(
            state_file(Path::new("/data"), id),
            Path::new("/data/state/0xabababababababababababababababababababab.json")
        );
    }
}
