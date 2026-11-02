//! Ledger wallets: a named file under `~/.safe-rs/wallets`, beside the
//! mnemonic keystores, that says which Ledger account a wallet's keys come
//! from. It holds no secret: the path of key 0 and the address the device gave
//! for it, which identifies the device when the wallet is used again.
//!
//! ```json
//! { "kind": "ledger", "path": "m/44'/60'/1'/0/0", "address": "0x…" }
//! ```
//!
//! Key `i` of the wallet is the path with `i` added to its last number, so the
//! owner keys of the wallet above are `m/44'/60'/1'/0/1`, `m/44'/60'/1'/0/2`
//! and so on. Which of them were used is recorded in the rotation state, under
//! the funding address, like a mnemonic wallet's.

use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use color_eyre::eyre::{bail, Result, WrapErr};
use safe_rs::KeyPath;
use serde::{Deserialize, Serialize};

/// The `kind` that tells a Ledger wallet from a mnemonic keystore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Ledger,
}

/// A Ledger wallet file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerWallet {
    kind: Kind,
    /// The path of key 0, the funding key
    pub path: KeyPath,
    /// The address of key 0, as the device gave it when the wallet was made
    pub address: Address,
    /// Where it was read from, for messages
    #[serde(skip)]
    file: PathBuf,
}

impl LedgerWallet {
    pub fn new(path: KeyPath, address: Address) -> Self {
        Self {
            kind: Kind::Ledger,
            path,
            address,
            file: PathBuf::new(),
        }
    }

    /// The Ledger wallet at `file`, or `None` when there is no such file or it
    /// is not a Ledger wallet (such as a mnemonic keystore).
    pub fn read(file: &Path) -> Result<Option<Self>> {
        let Ok(json) = std::fs::read_to_string(file) else {
            return Ok(None);
        };
        let wallet = Self::parse(&json)
            .wrap_err_with(|| format!("{} is not a valid Ledger wallet", file.display()))?;
        Ok(wallet.map(|wallet| Self {
            file: file.to_path_buf(),
            ..wallet
        }))
    }

    /// `json` as a Ledger wallet, or `None` when it is some other file.
    fn parse(json: &str) -> Result<Option<Self>> {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
            return Ok(None);
        };
        if value.get("kind").and_then(|kind| kind.as_str()) != Some("ledger") {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(value)?))
    }

    pub fn to_json(&self) -> String {
        let mut json = serde_json::to_string_pretty(self).expect("a Ledger wallet serializes");
        json.push('\n');
        json
    }

    /// Checks that `address`, which the connected device gives for key 0, is
    /// the one this wallet was made with.
    pub fn check_device(&self, address: Address) -> Result<()> {
        if address != self.address {
            bail!(
                "the connected Ledger is not the one {} was made with: its key at {} is {address}, \
                 not {} (another device, or another seed or passphrase on it)",
                self.file.display(),
                self.path,
                self.address
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_round_trips_and_is_told_from_a_keystore() {
        let wallet = LedgerWallet::new(
            "m/44h/60h/1h/0/0".parse().unwrap(),
            Address::repeat_byte(0x11),
        );
        let json = wallet.to_json();
        assert!(json.contains(r#""kind": "ledger""#), "{json}");
        assert!(json.contains(r#""path": "m/44'/60'/1'/0/0""#), "{json}");
        assert_eq!(LedgerWallet::parse(&json).unwrap(), Some(wallet));

        let keystore = r#"{"version":3,"address":"11","crypto":{}}"#;
        assert_eq!(LedgerWallet::parse(keystore).unwrap(), None);
        assert_eq!(LedgerWallet::parse("not json").unwrap(), None);
        assert!(LedgerWallet::parse(r#"{"kind":"ledger","path":"x","address":"0x00"}"#).is_err());
    }

    #[test]
    fn the_wrong_device_is_refused() {
        let wallet = LedgerWallet::new(KeyPath::default(), Address::repeat_byte(0x11));
        wallet.check_device(Address::repeat_byte(0x11)).unwrap();
        let error = wallet.check_device(Address::repeat_byte(0x22)).unwrap_err();
        assert!(error.to_string().contains("not the one"), "{error}");
    }
}
