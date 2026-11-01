//! BIP-39 phrases and the keys derived from them.
//!
//! One phrase yields every key the rotation flow uses, at the standard BIP-44
//! Ethereum path `m/44'/60'/0'/0/i`:
//!
//! - index 0 is the *funding key*: the address to send gas money to first, and
//!   the key a wallet keystore exposes to other tools;
//! - indices 1 and up are one-time Safe owner keys.
//!
//! The leaves are not hardened, so the account's extended public key (the
//! parent public key and chain code) must never be exported: with it, one
//! recovered child private key yields all the others. Nothing here exposes it,
//! and [`HdWallet`]'s `Debug` output shows only the funding address.

use alloy::primitives::Address;
use alloy::signers::local::coins_bip39::{English, Entropy, Mnemonic, Wordlist};
use alloy::signers::local::{MnemonicBuilder, MnemonicKey, PrivateKeySigner};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Derivation path of the funding key (index 0).
pub const FUNDING_PATH: &str = "m/44'/60'/0'/0/0";

/// Derivation path of key `index`: `m/44'/60'/0'/0/{index}`.
///
/// Every key source uses this path, so a device seeded with a phrase derives
/// the same keys as the phrase itself, and shares its state.
pub fn key_path(index: u32) -> String {
    format!("m/44'/60'/0'/0/{index}")
}

/// BIP-32 non-hardened child indices end here.
const MAX_INDEX: u32 = 1 << 31;

/// Entropy sizes BIP-39 defines, in bytes (12 to 24 words).
const ENTROPY_SIZES: [usize; 5] = [16, 20, 24, 28, 32];

/// Trims, lowercases and single-spaces a phrase.
pub fn normalize_phrase(phrase: &str) -> Zeroizing<String> {
    let mut normalized = Zeroizing::new(String::with_capacity(phrase.len()));
    for word in phrase.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        for c in word.chars() {
            normalized.extend(c.to_lowercase());
        }
    }
    normalized
}

/// The BIP-39 phrase (English) for `entropy`.
pub fn entropy_to_phrase(entropy: &[u8]) -> Result<Zeroizing<String>> {
    if !ENTROPY_SIZES.contains(&entropy.len()) {
        return Err(Error::Mnemonic(format!(
            "entropy must be 16, 20, 24, 28 or 32 bytes, got {}",
            entropy.len()
        )));
    }
    let entropy = Entropy::from_slice(entropy)
        .map_err(|_| Error::Mnemonic("invalid entropy length".to_string()))?;
    Ok(Zeroizing::new(
        Mnemonic::<English>::new_from_entropy(entropy).to_phrase(),
    ))
}

/// The entropy a BIP-39 phrase (English) encodes, after checking its checksum.
///
/// Errors never contain the phrase or any of its words.
pub fn phrase_to_entropy(phrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let phrase = normalize_phrase(phrase);
    let words: Vec<&str> = phrase.split(' ').collect();
    let entropy_len = words.len() * 4 / 3;
    if !words.len().is_multiple_of(3) || !ENTROPY_SIZES.contains(&entropy_len) {
        return Err(Error::Mnemonic(format!(
            "a recovery phrase has 12, 15, 18, 21 or 24 words, got {}",
            words.len()
        )));
    }

    // Each word is an 11-bit index; the bits are the entropy followed by a checksum.
    let mut bytes = Zeroizing::new(Vec::with_capacity(entropy_len + 1));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for (position, word) in words.iter().enumerate() {
        let index = English::get_index(word).map_err(|_| {
            Error::Mnemonic(format!(
                "word {} is not in the BIP-39 English word list",
                position + 1
            ))
        })?;
        let index = u32::try_from(index)
            .map_err(|_| Error::Mnemonic("word index out of range".to_string()))?;
        acc = (acc << 11) | index;
        bits += 11;
        while bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    bytes.truncate(entropy_len);

    if *entropy_to_phrase(&bytes)? != *phrase {
        return Err(Error::Mnemonic(
            "the recovery phrase checksum does not match".to_string(),
        ));
    }
    Ok(bytes)
}

/// Keys derived from one BIP-39 phrase.
#[derive(Clone)]
pub struct HdWallet {
    /// The key at `m/44'/60'/0'/0`, from which every index is one step away
    parent: MnemonicKey,
    funding: PrivateKeySigner,
}

impl std::fmt::Debug for HdWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the parent key: its debug output is an extended key.
        f.debug_struct("HdWallet")
            .field("funding", &self.funding.address())
            .finish_non_exhaustive()
    }
}

impl HdWallet {
    /// Creates a wallet from a new random 24-word phrase and returns the phrase.
    pub fn generate() -> Result<(Self, Zeroizing<String>)> {
        Self::generate_with(&mut OsRng)
    }

    /// Like [`HdWallet::generate`], with a caller-supplied random source.
    pub fn generate_with(rng: &mut impl RngCore) -> Result<(Self, Zeroizing<String>)> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(entropy.as_mut_slice());
        let phrase = entropy_to_phrase(entropy.as_slice())?;
        Ok((Self::from_phrase(&phrase)?, phrase))
    }

    /// Creates a wallet from a BIP-39 phrase (English, no BIP-39 passphrase).
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        // Validates word count, words and checksum without echoing the phrase.
        phrase_to_entropy(phrase)?;
        let normalized = normalize_phrase(phrase);
        let parent = MnemonicBuilder::<English>::default()
            .phrase(normalized.as_str())
            .build_parent_key()
            .map_err(|_| Error::Mnemonic("could not derive keys from the phrase".to_string()))?;
        let funding = Self::child(&parent, 0)?;
        Ok(Self { parent, funding })
    }

    /// Opens a mnemonic keystore (see [`crate::keystore`]) with its password.
    ///
    /// Fails with [`Error::Keystore`] if the keystore holds a single key and
    /// no phrase.
    pub fn from_keystore_json(json: &str, password: &[u8]) -> Result<Self> {
        let decrypted = crate::keystore::decrypt_keystore(json, password)?;
        let Some(mnemonic) = decrypted.mnemonic else {
            return Err(Error::Keystore(
                "this keystore holds a single key, not a recovery phrase".to_string(),
            ));
        };
        Self::from_phrase(&mnemonic.phrase)
    }

    fn child(parent: &MnemonicKey, index: u32) -> Result<PrivateKeySigner> {
        if index >= MAX_INDEX {
            return Err(Error::Mnemonic(format!(
                "key index {index} is out of range"
            )));
        }
        Ok(parent
            .child(index)
            .map_err(|_| Error::Mnemonic(format!("could not derive key {index}")))?
            .signer())
    }

    /// The funding key (index 0).
    pub fn funding(&self) -> &PrivateKeySigner {
        &self.funding
    }

    /// The funding address, which identifies the wallet.
    pub fn id(&self) -> Address {
        self.funding.address()
    }

    /// The key at `m/44'/60'/0'/0/{index}`, whatever role it has.
    pub fn key_at(&self, index: u32) -> Result<PrivateKeySigner> {
        if index == 0 {
            return Ok(self.funding.clone());
        }
        Self::child(&self.parent, index)
    }

    /// Owner key `index`. Index 0 is the funding key and never an owner.
    pub fn owner(&self, index: u32) -> Result<PrivateKeySigner> {
        if index == 0 {
            return Err(Error::Mnemonic(
                "index 0 is the funding key, not an owner key".to_string(),
            ));
        }
        Self::child(&self.parent, index)
    }

    /// The address of owner key `index`.
    pub fn owner_address(&self, index: u32) -> Result<Address> {
        Ok(self.owner(index)?.address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-39 test vectors (English): entropy and phrase.
    const VECTORS: [(&str, &str); 4] = [
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
    ];

    const TEST_PHRASE: &str = "test test test test test test test test test test test junk";

    fn unhex(s: &str) -> Vec<u8> {
        alloy::primitives::hex::decode(s).unwrap()
    }

    #[test]
    fn bip39_vectors_convert_both_ways() {
        for (entropy, phrase) in VECTORS {
            let entropy = unhex(entropy);
            assert_eq!(*entropy_to_phrase(&entropy).unwrap(), phrase);
            assert_eq!(*phrase_to_entropy(phrase).unwrap(), entropy);
        }
    }

    #[test]
    fn phrases_are_normalized_before_use() {
        let messy =
            "  Legal WINNER thank\tyear wave sausage worth useful legal winner thank\n yellow ";
        assert_eq!(*normalize_phrase(messy), VECTORS[1].1);
        assert_eq!(*phrase_to_entropy(messy).unwrap(), unhex(VECTORS[1].0));
    }

    #[test]
    fn bad_phrases_are_rejected_without_echoing_them() {
        let wrong_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let unknown_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzzz";
        let too_short = "abandon abandon abandon";
        for phrase in [wrong_checksum, unknown_word, too_short, ""] {
            let message = phrase_to_entropy(phrase).unwrap_err().to_string();
            assert!(!message.contains("abandon"), "{message}");
            assert!(!message.contains("zzzzzz"), "{message}");
            assert!(HdWallet::from_phrase(phrase).is_err());
        }
        assert!(entropy_to_phrase(&[0u8; 17]).is_err());
    }

    #[test]
    fn derived_keys_match_the_standard_path() {
        let wallet = HdWallet::from_phrase(TEST_PHRASE).unwrap();
        // The well-known first account of the test phrase.
        assert_eq!(
            wallet.id(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse::<Address>()
                .unwrap()
        );
        for index in 1..5 {
            let expected = MnemonicBuilder::<English>::default()
                .phrase(TEST_PHRASE)
                .index(index)
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(wallet.owner_address(index).unwrap(), expected.address());
            assert_eq!(wallet.owner(index).unwrap().to_bytes(), expected.to_bytes());
        }
    }

    #[test]
    fn owner_indices_are_bounded() {
        let wallet = HdWallet::from_phrase(TEST_PHRASE).unwrap();
        assert!(wallet.owner(0).is_err(), "index 0 is the funding key");
        assert!(wallet.owner(MAX_INDEX).is_err(), "hardened range");
        assert!(wallet.owner(MAX_INDEX - 1).is_ok());
    }

    #[test]
    fn key_paths_follow_bip44() {
        assert_eq!(key_path(0), FUNDING_PATH);
        assert_eq!(key_path(7), "m/44'/60'/0'/0/7");
    }

    #[test]
    fn generated_wallets_round_trip_through_their_phrase() {
        let (wallet, phrase) = HdWallet::generate().unwrap();
        assert_eq!(phrase.split(' ').count(), 24);
        let again = HdWallet::from_phrase(&phrase).unwrap();
        assert_eq!(again.id(), wallet.id());
        assert_eq!(
            again.owner_address(1).unwrap(),
            wallet.owner_address(1).unwrap()
        );
    }

    #[test]
    fn debug_output_shows_only_the_funding_address() {
        let wallet = HdWallet::from_phrase(TEST_PHRASE).unwrap();
        let debug = format!("{wallet:?}");
        assert!(debug.contains("funding"));
        assert!(!debug.contains("XPriv"));
        assert!(!debug.contains("chain_code"));
        assert!(!debug.contains("parent"));
    }
}
