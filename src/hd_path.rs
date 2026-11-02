//! BIP-32 derivation paths for a family of keys.
//!
//! A [`KeyPath`] names a wallet's key 0, the *funding key*. Every other key
//! follows from it: key `i` is the same path with `i` added to its last
//! component. The default is the first Ledger Live account,
//! `m/44'/60'/0'/0/0`, whose keys `m/44'/60'/0'/0/i` are those a phrase gives.
//! Another Ledger Live account, `m/44'/60'/1'/0/0`, is a separate family:
//! `m/44'/60'/1'/0/i`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Components end here: BIP-32 marks a hardened one with this bit.
const HARDENED: u32 = 1 << 31;

/// One step of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Component {
    /// Below [`HARDENED`]
    value: u32,
    hardened: bool,
}

/// The path of a wallet's key 0, from which key `i` is `i` past its last
/// component.
///
/// Parsed from `m/44'/60'/0'/0/0`. `h` or `H` may stand for `'`, as in
/// Bitcoin descriptors, which spares quoting it in a shell:
/// `m/44h/60h/0h/0/0`. It prints with `'`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyPath {
    /// At least one
    components: Vec<Component>,
}

impl KeyPath {
    /// The path of key `index`: this path with `index` added to its last
    /// component, which keeps its hardening.
    pub fn key(&self, index: u32) -> Result<String> {
        let past_the_end = || {
            Error::KeyPath(format!(
                "key {index} of {self} is past the last BIP-32 index"
            ))
        };
        let mut components = self.components.clone();
        let last = components.last_mut().ok_or_else(past_the_end)?;
        last.value = last
            .value
            .checked_add(index)
            .filter(|value| *value < HARDENED)
            .ok_or_else(past_the_end)?;
        Ok(Self { components }.to_string())
    }
}

impl KeyPath {
    /// Whether the keys of `self` and `other` overlap without being the same
    /// family: both count up the same last step from different starts, so one
    /// wallet's owner keys are the other's. (The same path is the same keys,
    /// and shares one record of used keys; that is no overlap.)
    pub fn overlaps(&self, other: &Self) -> bool {
        let (Some((mine, my_parents)), Some((theirs, their_parents))) =
            (self.components.split_last(), other.components.split_last())
        else {
            return false;
        };
        my_parents == their_parents && mine.hardened == theirs.hardened && mine != theirs
    }
}

impl Default for KeyPath {
    /// The first Ledger Live account, `m/44'/60'/0'/0/0`.
    fn default() -> Self {
        Self {
            components: [(44, true), (60, true), (0, true), (0, false), (0, false)]
                .map(|(value, hardened)| Component { value, hardened })
                .to_vec(),
        }
    }
}

impl FromStr for KeyPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let invalid = |why: &str| {
            Error::KeyPath(format!(
                "{s:?} is not a derivation path like m/44'/60'/0'/0/0: {why}"
            ))
        };
        let rest = s
            .trim()
            .strip_prefix("m/")
            .ok_or_else(|| invalid("it must start with m/"))?;
        let components = rest
            .split('/')
            .map(|component| {
                let (digits, hardened) = match component.strip_suffix(['\'', 'h', 'H']) {
                    Some(digits) => (digits, true),
                    None => (component, false),
                };
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid(&format!("{component:?} is not a number")));
                }
                let value: u32 = digits
                    .parse()
                    .ok()
                    .filter(|value| *value < HARDENED)
                    .ok_or_else(|| invalid(&format!("{component:?} is too large")))?;
                Ok(Component { value, hardened })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { components })
    }
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for component in &self.components {
            write!(f, "/{}", component.value)?;
            if component.hardened {
                f.write_str("'")?;
            }
        }
        Ok(())
    }
}

impl TryFrom<String> for KeyPath {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<KeyPath> for String {
    fn from(path: KeyPath) -> Self {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_first_ledger_live_account() {
        let path = KeyPath::default();
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(path.key(0).unwrap(), "m/44'/60'/0'/0/0");
        assert_eq!(path.key(7).unwrap(), "m/44'/60'/0'/0/7");
    }

    #[test]
    fn h_stands_for_an_apostrophe() {
        let quoted: KeyPath = "m/44'/60'/3'/0/0".parse().unwrap();
        assert_eq!("m/44h/60H/3h/0/0".parse::<KeyPath>().unwrap(), quoted);
        assert_eq!(quoted.key(2).unwrap(), "m/44'/60'/3'/0/2");
    }

    #[test]
    fn keys_count_up_from_the_last_component() {
        let path: KeyPath = "m/44'/60'/0'/0/5".parse().unwrap();
        assert_eq!(path.key(0).unwrap(), "m/44'/60'/0'/0/5");
        assert_eq!(path.key(3).unwrap(), "m/44'/60'/0'/0/8");
        let hardened: KeyPath = "m/44'/60'/2'".parse().unwrap();
        assert_eq!(hardened.key(1).unwrap(), "m/44'/60'/3'");
        let near_end: KeyPath = format!("m/0/{}", HARDENED - 2).parse().unwrap();
        assert!(near_end.key(1).is_ok());
        assert!(near_end.key(2).is_err());
    }

    #[test]
    fn paths_counting_up_the_same_step_overlap() {
        let path = |s: &str| s.parse::<KeyPath>().unwrap();
        let first = KeyPath::default();
        assert!(first.overlaps(&path("m/44'/60'/0'/0/2")));
        assert!(!first.overlaps(&first), "the same keys share one record");
        assert!(!first.overlaps(&path("m/44'/60'/1'/0/0")));
        assert!(!first.overlaps(&path("m/44'/60'/0'/0/2'")));
        assert!(!first.overlaps(&path("m/44'/60'/0'/1/0")));
    }

    #[test]
    fn bad_paths_are_refused() {
        for bad in [
            "",
            "m",
            "m/",
            "44'/60'/0'/0/0",
            "m/44'/60'//0",
            "m/44''/60'",
            "m/-1",
            "m/+1",
            "m/x",
            "m/2147483648",
        ] {
            assert!(bad.parse::<KeyPath>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn it_serializes_as_a_string() {
        let path: KeyPath = "m/44h/60h/1h/0/0".parse().unwrap();
        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(json, r#""m/44'/60'/1'/0/0""#);
        assert_eq!(serde_json::from_str::<KeyPath>(&json).unwrap(), path);
        assert!(serde_json::from_str::<KeyPath>(r#""nope""#).is_err());
    }
}
