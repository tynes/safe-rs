//! Password-encrypted keystores.
//!
//! The format is Web3 Secret Storage version 3, the one geth and Foundry
//! write: `scrypt` stretches the password, AES-128-CTR encrypts a private key,
//! and a keccak256 MAC detects a wrong password. Everything in it is symmetric
//! cryptography.
//!
//! A *mnemonic keystore* additionally carries the BIP-39 phrase the key was
//! derived from, in the `x-ethers` field ethers.js defines. scrypt produces 64
//! bytes instead of 32 (the file still says `dklen: 32`, as ethers does):
//!
//! | bytes      | use                                              |
//! |------------|--------------------------------------------------|
//! | `0..16`    | AES-128-CTR key for the private key (`ciphertext`) |
//! | `16..32`   | MAC key: `keccak256(dk[16..32] ‖ ciphertext)`    |
//! | `32..64`   | AES-256-CTR key for the phrase entropy           |
//!
//! Other tools see an ordinary keystore for the key at `x-ethers.path`; ethers
//! and this crate also recover the phrase. No MAC covers the phrase, so on
//! decryption the key is re-derived from it and must match.
//!
//! The `keystore` feature reads keystores. Recovering the phrase and writing
//! mnemonic keystores need `hd-wallet`; without it `x-ethers` is ignored, as
//! geth and Foundry ignore it.

use aes::cipher::{KeyIvInit, StreamCipher};
use alloy::primitives::{hex, keccak256, Address};
use alloy::signers::local::PrivateKeySigner;
#[cfg(feature = "hd-wallet")]
use rand::{CryptoRng, RngCore};
#[cfg(feature = "hd-wallet")]
use serde_json::json;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
#[cfg(feature = "hd-wallet")]
use crate::hd::{entropy_to_phrase, phrase_to_entropy, HdWallet, FUNDING_PATH};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
#[cfg(feature = "hd-wallet")]
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// The largest `N * r` accepted when reading: 1 GiB of scrypt memory.
const MAX_SCRYPT_COST: u64 = 1 << 23;

/// scrypt work parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptParams {
    /// log2 of the CPU/memory cost `N`
    pub log_n: u8,
    /// Block size
    pub r: u32,
    /// Parallelization
    pub p: u32,
}

impl Default for ScryptParams {
    /// `N = 2^18, r = 8, p = 1` (256 MiB), the cost geth uses. Foundry writes
    /// `N = 2^13`, which makes each password guess 32 times cheaper.
    fn default() -> Self {
        Self {
            log_n: 18,
            r: 8,
            p: 1,
        }
    }
}

/// A phrase recovered from a mnemonic keystore.
#[derive(Clone)]
pub struct DecryptedMnemonic {
    /// The BIP-39 phrase
    pub phrase: Zeroizing<String>,
    /// Derivation path of the keystore's own key
    pub path: String,
}

/// The contents of a decrypted keystore.
#[derive(Clone)]
pub struct Decrypted {
    /// The keystore's private key
    pub signer: PrivateKeySigner,
    /// The phrase, for a mnemonic keystore. Always `None` without the
    /// `hd-wallet` feature, which recovering a phrase needs.
    pub mnemonic: Option<DecryptedMnemonic>,
}

impl std::fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted")
            .field("address", &self.signer.address())
            .field("has_mnemonic", &self.mnemonic.is_some())
            .finish()
    }
}

fn malformed(what: impl std::fmt::Display) -> Error {
    Error::Keystore(what.to_string())
}

/// Looks up `key` ignoring case, as ethers does (`crypto` or `Crypto`).
fn field<'a>(object: &'a Value, key: &str) -> Option<&'a Value> {
    object
        .as_object()?
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
}

fn require<'a>(object: &'a Value, key: &str) -> Result<&'a Value> {
    field(object, key).ok_or_else(|| malformed(format!("missing field `{key}`")))
}

fn string<'a>(object: &'a Value, key: &str) -> Result<&'a str> {
    require(object, key)?
        .as_str()
        .ok_or_else(|| malformed(format!("field `{key}` is not a string")))
}

fn bytes(object: &Value, key: &str) -> Result<Vec<u8>> {
    hex::decode(string(object, key)?).map_err(|_| malformed(format!("field `{key}` is not hex")))
}

fn uint(object: &Value, key: &str) -> Result<u64> {
    require(object, key)?
        .as_u64()
        .ok_or_else(|| malformed(format!("field `{key}` is not an unsigned integer")))
}

fn parse_address(text: &str) -> Result<Address> {
    text.parse()
        .or_else(|_| format!("0x{text}").parse())
        .map_err(|_| malformed("field `address` is not an address"))
}

/// The address a keystore says it holds, readable without the password.
///
/// The field is optional in the format (Foundry omits it); it is checked
/// against the key when the keystore is decrypted.
pub fn keystore_address(json: &str) -> Result<Option<Address>> {
    let root: Value =
        serde_json::from_str(json).map_err(|e| malformed(format!("not JSON: {e}")))?;
    field(&root, "address")
        .and_then(Value::as_str)
        .map(parse_address)
        .transpose()
}

/// Derives the 64-byte key from the keystore's `kdfparams`.
fn derive_key(crypto: &Value, password: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let kdf = string(crypto, "kdf")?;
    if !kdf.eq_ignore_ascii_case("scrypt") {
        return Err(malformed(format!(
            "unsupported kdf `{kdf}` (only scrypt keystores are supported)"
        )));
    }
    let params = require(crypto, "kdfparams")?;
    let (n, r, p) = (uint(params, "n")?, uint(params, "r")?, uint(params, "p")?);
    if uint(params, "dklen")? != 32 {
        return Err(malformed("kdfparams.dklen must be 32"));
    }
    if !n.is_power_of_two() || n < 2 {
        return Err(malformed("kdfparams.n must be a power of two"));
    }
    if r == 0 || p == 0 || p > 16 || n.saturating_mul(r) > MAX_SCRYPT_COST {
        return Err(malformed("kdfparams are out of the supported range"));
    }
    let salt = bytes(params, "salt")?;
    let params = ScryptParams {
        log_n: u8::try_from(n.trailing_zeros()).map_err(malformed)?,
        r: u32::try_from(r).map_err(malformed)?,
        p: u32::try_from(p).map_err(malformed)?,
    };
    stretch(password, &salt, params)
}

fn stretch(password: &[u8], salt: &[u8], params: ScryptParams) -> Result<Zeroizing<[u8; 64]>> {
    let params = scrypt::Params::new(params.log_n, params.r, params.p, 64)
        .map_err(|e| malformed(format!("invalid scrypt parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; 64]);
    scrypt::scrypt(password, salt, &params, key.as_mut_slice())
        .map_err(|e| malformed(format!("scrypt failed: {e}")))?;
    Ok(key)
}

fn mac(key: &[u8; 64], ciphertext: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(16 + ciphertext.len());
    input.extend_from_slice(&key[16..32]);
    input.extend_from_slice(ciphertext);
    keccak256(input).0
}

fn aes128_ctr(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()> {
    Aes128Ctr::new_from_slices(key, iv)
        .map_err(|_| malformed("invalid AES-128-CTR key or IV length"))?
        .apply_keystream(data);
    Ok(())
}

#[cfg(feature = "hd-wallet")]
fn aes256_ctr(key: &[u8], counter: &[u8], data: &mut [u8]) -> Result<()> {
    Aes256Ctr::new_from_slices(key, counter)
        .map_err(|_| malformed("invalid AES-256-CTR key or counter length"))?
        .apply_keystream(data);
    Ok(())
}

/// Decrypts a V3 keystore, with or without the `x-ethers` mnemonic field.
/// Without the `hd-wallet` feature the field is ignored: the key is still
/// returned, and `mnemonic` is `None`.
///
/// Fails with [`Error::WrongPassword`] if the MAC does not match, and with
/// [`Error::Keystore`] if the file is malformed, uses a cipher or KDF other
/// than `aes-128-ctr` with `scrypt`, or carries a phrase that does not derive
/// the keystore's key.
pub fn decrypt_keystore(json: &str, password: &[u8]) -> Result<Decrypted> {
    let root: Value =
        serde_json::from_str(json).map_err(|e| malformed(format!("not JSON: {e}")))?;
    if uint(&root, "version")? != 3 {
        return Err(malformed("only version 3 keystores are supported"));
    }
    let crypto = require(&root, "crypto")?;
    let cipher = string(crypto, "cipher")?;
    if !cipher.eq_ignore_ascii_case("aes-128-ctr") {
        return Err(malformed(format!("unsupported cipher `{cipher}`")));
    }
    let iv = bytes(require(crypto, "cipherparams")?, "iv")?;
    if iv.len() != 16 {
        return Err(malformed("cipherparams.iv must be 16 bytes"));
    }
    let ciphertext = bytes(crypto, "ciphertext")?;
    if ciphertext.len() != 32 {
        return Err(malformed("ciphertext must be a 32-byte private key"));
    }
    let expected_mac = bytes(crypto, "mac")?;

    let key = derive_key(crypto, password)?;
    if mac(&key, &ciphertext).as_slice() != expected_mac.as_slice() {
        return Err(Error::WrongPassword);
    }

    let mut secret = Zeroizing::new(ciphertext);
    aes128_ctr(&key[..16], &iv, secret.as_mut_slice())?;
    let signer = PrivateKeySigner::from_slice(&secret)
        .map_err(|_| malformed("the keystore does not hold a valid private key"))?;

    if let Some(address) = field(&root, "address").and_then(Value::as_str) {
        if parse_address(address)? != signer.address() {
            return Err(malformed(
                "the keystore's address field does not match its key",
            ));
        }
    }

    #[cfg(feature = "hd-wallet")]
    let mnemonic = match field(&root, "x-ethers") {
        Some(extension) => Some(decrypt_mnemonic(extension, &key, &signer)?),
        None => None,
    };
    #[cfg(not(feature = "hd-wallet"))]
    let mnemonic = None;
    Ok(Decrypted { signer, mnemonic })
}

#[cfg(feature = "hd-wallet")]
fn decrypt_mnemonic(
    extension: &Value,
    key: &[u8; 64],
    signer: &PrivateKeySigner,
) -> Result<DecryptedMnemonic> {
    let version = string(extension, "version")?;
    if version != "0.1" {
        return Err(malformed(format!(
            "unsupported x-ethers version `{version}`"
        )));
    }
    if let Some(locale) = field(extension, "locale").and_then(Value::as_str) {
        if locale != "en" {
            return Err(malformed(format!(
                "unsupported phrase locale `{locale}` (only `en`)"
            )));
        }
    }
    let path = field(extension, "path")
        .and_then(Value::as_str)
        .unwrap_or(FUNDING_PATH)
        .to_string();
    if path != FUNDING_PATH {
        return Err(malformed(format!(
            "unsupported derivation path `{path}` (expected `{FUNDING_PATH}`)"
        )));
    }
    let counter = bytes(extension, "mnemonicCounter")?;
    if counter.len() != 16 {
        return Err(malformed("x-ethers.mnemonicCounter must be 16 bytes"));
    }
    let mut entropy = Zeroizing::new(bytes(extension, "mnemonicCiphertext")?);
    aes256_ctr(&key[32..], &counter, entropy.as_mut_slice())?;

    // Nothing authenticates the phrase ciphertext: it is only trusted if it
    // derives the key the MAC did authenticate.
    let mismatch = || malformed("the keystore's phrase does not derive its key");
    let phrase = entropy_to_phrase(&entropy).map_err(|_| mismatch())?;
    let wallet = HdWallet::from_phrase(&phrase).map_err(|_| mismatch())?;
    if wallet.id() != signer.address() {
        return Err(mismatch());
    }
    Ok(DecryptedMnemonic { phrase, path })
}

#[cfg(feature = "hd-wallet")]
fn uuid_v4(rng: &mut impl RngCore) -> String {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16])
    )
}

/// Encrypts a BIP-39 phrase as a mnemonic keystore and returns the JSON.
///
/// The keystore's own key is the phrase's funding key (`m/44'/60'/0'/0/0`), so
/// geth, Foundry and other V3 readers can use the file for that key, while
/// ethers.js and [`decrypt_keystore`] also recover the phrase.
///
/// The password is used as the bytes given. Tools disagree on Unicode
/// normalization (ethers applies NFKC, Foundry none), so a non-ASCII password
/// may not open the file elsewhere.
#[cfg(feature = "hd-wallet")]
pub fn encrypt_mnemonic_keystore(
    phrase: &str,
    password: &[u8],
    params: ScryptParams,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<String> {
    let entropy = phrase_to_entropy(phrase)?;
    let wallet = HdWallet::from_phrase(phrase)?;
    let address = wallet.id();

    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut counter = [0u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);
    rng.fill_bytes(&mut counter);

    let key = stretch(password, &salt, params)?;
    let mut ciphertext = Zeroizing::new(wallet.funding().to_bytes().0);
    aes128_ctr(&key[..16], &iv, ciphertext.as_mut_slice())?;
    let mut mnemonic_ciphertext = entropy.clone();
    aes256_ctr(&key[32..], &counter, mnemonic_ciphertext.as_mut_slice())?;

    let bare_address = hex::encode(address);
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S.0Z");
    let keystore = json!({
        "address": bare_address,
        "id": uuid_v4(rng),
        "version": 3,
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": { "iv": hex::encode(iv) },
            "ciphertext": hex::encode(ciphertext.as_slice()),
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 1u64 << params.log_n,
                "p": params.p,
                "r": params.r,
                "salt": hex::encode(salt),
            },
            "mac": hex::encode(mac(&key, ciphertext.as_slice())),
        },
        "x-ethers": {
            "client": concat!("safe-rs/", env!("CARGO_PKG_VERSION")),
            "gethFilename": format!("UTC--{timestamp}--{bare_address}"),
            "path": FUNDING_PATH,
            "locale": "en",
            "mnemonicCounter": hex::encode(counter),
            "mnemonicCiphertext": hex::encode(mnemonic_ciphertext.as_slice()),
            "version": "0.1",
        },
    });
    serde_json::to_string_pretty(&keystore).map_err(|e| Error::Encoding(e.to_string()))
}

#[cfg(all(test, feature = "hd-wallet"))]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const PHRASE: &str = "test test test test test test test test test test test junk";
    const PASSWORD: &[u8] = b"correct horse battery staple";

    /// Cheap parameters so tests do not spend seconds in scrypt.
    const FAST: ScryptParams = ScryptParams {
        log_n: 4,
        r: 8,
        p: 1,
    };

    fn encrypted() -> String {
        encrypt_mnemonic_keystore(PHRASE, PASSWORD, FAST, &mut OsRng).unwrap()
    }

    fn edit(json: &str, change: impl FnOnce(&mut Value)) -> String {
        let mut value: Value = serde_json::from_str(json).unwrap();
        change(&mut value);
        value.to_string()
    }

    #[test]
    fn the_first_half_of_a_64_byte_key_is_the_32_byte_key() {
        // This is what lets other V3 readers, which derive 32 bytes, open the file.
        let long = stretch(b"pw", b"salt", FAST).unwrap();
        let mut short = [0u8; 32];
        scrypt::scrypt(
            b"pw",
            b"salt",
            &scrypt::Params::new(FAST.log_n, FAST.r, FAST.p, 32).unwrap(),
            &mut short,
        )
        .unwrap();
        assert_eq!(&long[..32], &short);
    }

    #[test]
    fn a_mnemonic_keystore_round_trips() {
        let json = encrypted();
        let wallet = HdWallet::from_phrase(PHRASE).unwrap();
        assert_eq!(keystore_address(&json).unwrap(), Some(wallet.id()));

        let decrypted = decrypt_keystore(&json, PASSWORD).unwrap();
        assert_eq!(decrypted.signer.address(), wallet.id());
        let mnemonic = decrypted.mnemonic.unwrap();
        assert_eq!(*mnemonic.phrase, PHRASE);
        assert_eq!(mnemonic.path, FUNDING_PATH);
    }

    #[test]
    fn the_file_has_the_documented_shape() {
        let value: Value = serde_json::from_str(&encrypted()).unwrap();
        assert_eq!(value["version"], 3);
        assert_eq!(value["crypto"]["cipher"], "aes-128-ctr");
        assert_eq!(value["crypto"]["kdf"], "scrypt");
        assert_eq!(value["crypto"]["kdfparams"]["dklen"], 32);
        assert_eq!(value["crypto"]["kdfparams"]["n"], 16);
        assert_eq!(value["x-ethers"]["version"], "0.1");
        assert_eq!(value["x-ethers"]["path"], FUNDING_PATH);
        assert_eq!(value["x-ethers"]["locale"], "en");
        // 12 words are 16 bytes of entropy.
        assert_eq!(
            value["x-ethers"]["mnemonicCiphertext"]
                .as_str()
                .unwrap()
                .len(),
            32
        );
        let id = value["id"].as_str().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4", "a version 4 UUID");
        // Nothing secret or derivable is stored in the clear.
        let text = value.to_string();
        for word in ["junk", "xpub", "chain"] {
            assert!(!text.contains(word), "{word} leaked");
        }
    }

    #[test]
    fn two_encryptions_share_no_salt_iv_or_ciphertext() {
        let a: Value = serde_json::from_str(&encrypted()).unwrap();
        let b: Value = serde_json::from_str(&encrypted()).unwrap();
        assert_ne!(
            a["crypto"]["kdfparams"]["salt"],
            b["crypto"]["kdfparams"]["salt"]
        );
        assert_ne!(
            a["crypto"]["cipherparams"]["iv"],
            b["crypto"]["cipherparams"]["iv"]
        );
        assert_ne!(a["crypto"]["ciphertext"], b["crypto"]["ciphertext"]);
        assert_ne!(
            a["x-ethers"]["mnemonicCiphertext"],
            b["x-ethers"]["mnemonicCiphertext"]
        );
    }

    #[test]
    fn a_wrong_password_is_reported_as_such() {
        assert!(matches!(
            decrypt_keystore(&encrypted(), b"wrong"),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn a_tampered_phrase_ciphertext_is_rejected() {
        // The MAC does not cover the phrase, so the key check has to catch it.
        let json = edit(&encrypted(), |value| {
            let text = value["x-ethers"]["mnemonicCiphertext"].as_str().unwrap();
            let mut raw = hex::decode(text).unwrap();
            raw[0] ^= 0x01;
            value["x-ethers"]["mnemonicCiphertext"] = hex::encode(raw).into();
        });
        let error = decrypt_keystore(&json, PASSWORD).unwrap_err();
        assert!(matches!(error, Error::Keystore(_)), "{error}");
    }

    #[test]
    fn a_tampered_key_ciphertext_fails_the_mac() {
        let json = edit(&encrypted(), |value| {
            let text = value["crypto"]["ciphertext"].as_str().unwrap();
            let mut raw = hex::decode(text).unwrap();
            raw[31] ^= 0x80;
            value["crypto"]["ciphertext"] = hex::encode(raw).into();
        });
        assert!(matches!(
            decrypt_keystore(&json, PASSWORD),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn unsupported_or_malformed_parameters_are_rejected() {
        let base = encrypted();
        type Change = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Change)> = vec![
            ("version", Box::new(|v| v["version"] = 4.into())),
            (
                "cipher",
                Box::new(|v| v["crypto"]["cipher"] = "aes-256-ctr".into()),
            ),
            ("kdf", Box::new(|v| v["crypto"]["kdf"] = "pbkdf2".into())),
            (
                "dklen",
                Box::new(|v| v["crypto"]["kdfparams"]["dklen"] = 64.into()),
            ),
            (
                "n not a power of two",
                Box::new(|v| v["crypto"]["kdfparams"]["n"] = 1000.into()),
            ),
            (
                "n too large",
                Box::new(|v| v["crypto"]["kdfparams"]["n"] = (1u64 << 30).into()),
            ),
            ("r", Box::new(|v| v["crypto"]["kdfparams"]["r"] = 0.into())),
            (
                "iv length",
                Box::new(|v| v["crypto"]["cipherparams"]["iv"] = "00ff".into()),
            ),
            (
                "ciphertext length",
                Box::new(|v| v["crypto"]["ciphertext"] = "00ff".into()),
            ),
            ("hex", Box::new(|v| v["crypto"]["mac"] = "not hex".into())),
            (
                "address",
                Box::new(|v| v["address"] = hex::encode(Address::repeat_byte(1)).into()),
            ),
            (
                "x-ethers version",
                Box::new(|v| v["x-ethers"]["version"] = "0.2".into()),
            ),
            (
                "path",
                Box::new(|v| v["x-ethers"]["path"] = "m/44'/60'/0'/0/1".into()),
            ),
            (
                "locale",
                Box::new(|v| v["x-ethers"]["locale"] = "fr".into()),
            ),
            (
                "counter length",
                Box::new(|v| v["x-ethers"]["mnemonicCounter"] = "00".into()),
            ),
            (
                "missing crypto",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("crypto");
                }),
            ),
        ];
        for (name, change) in cases {
            let json = edit(&base, change);
            let error = decrypt_keystore(&json, PASSWORD).unwrap_err();
            assert!(matches!(error, Error::Keystore(_)), "{name}: {error}");
        }
        assert!(decrypt_keystore("not json", PASSWORD).is_err());
    }

    #[test]
    fn capitalized_keys_and_prefixed_hex_are_accepted() {
        // ethers v6 writes `Crypto` and tolerates `0x` prefixes.
        let json = edit(&encrypted(), |value| {
            let object = value.as_object_mut().unwrap();
            let crypto = object.remove("crypto").unwrap();
            object.insert("Crypto".to_string(), crypto);
            let address = object["address"].as_str().unwrap().to_string();
            object.insert("address".to_string(), format!("0x{address}").into());
        });
        let decrypted = decrypt_keystore(&json, PASSWORD).unwrap();
        assert_eq!(*decrypted.mnemonic.unwrap().phrase, PHRASE);
    }

    #[test]
    fn a_plain_keystore_without_a_phrase_decrypts_to_its_key() {
        let json = edit(&encrypted(), |value| {
            value.as_object_mut().unwrap().remove("x-ethers");
        });
        let decrypted = decrypt_keystore(&json, PASSWORD).unwrap();
        assert!(decrypted.mnemonic.is_none());
        assert_eq!(
            decrypted.signer.address(),
            HdWallet::from_phrase(PHRASE).unwrap().id()
        );
        assert!(!format!("{decrypted:?}").contains("junk"));
    }

    #[test]
    fn our_keystore_opens_with_the_reader_foundry_uses() {
        // Foundry decrypts through `PrivateKeySigner::decrypt_keystore`
        // (eth-keystore), which derives 32 bytes and ignores `x-ethers`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        std::fs::write(&path, encrypted()).unwrap();
        let signer = PrivateKeySigner::decrypt_keystore(&path, PASSWORD).unwrap();
        assert_eq!(
            signer.address(),
            HdWallet::from_phrase(PHRASE).unwrap().id()
        );
    }

    #[test]
    fn a_keystore_written_by_eth_keystore_decrypts_here() {
        let dir = tempfile::tempdir().unwrap();
        let (signer, name) =
            PrivateKeySigner::new_keystore(dir.path(), &mut OsRng, PASSWORD, None).unwrap();
        let json = std::fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(keystore_address(&json).unwrap(), None, "no address field");
        let decrypted = decrypt_keystore(&json, PASSWORD).unwrap();
        assert_eq!(decrypted.signer.address(), signer.address());
        assert!(decrypted.mnemonic.is_none());
    }

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/keystores/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(path).unwrap()
    }

    /// Keystores written by ethers.js (see `tests/fixtures/keystores/NOTICE.md`):
    /// two mnemonic wallets at N=2^17 and N=2^18 and a plain one, all with a
    /// capitalized `Crypto` key and no `path` or `locale`.
    #[test]
    fn ethers_keystores_decrypt_to_their_documented_contents() {
        let vectors: Value = serde_json::from_str(&fixture("vectors.json")).unwrap();
        let vectors = vectors.as_array().unwrap();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            let name = vector["name"].as_str().unwrap();
            let json = fixture(&format!("{name}.json"));
            let password = vector["password"].as_str().unwrap().as_bytes();
            let address: Address = vector["address"].as_str().unwrap().parse().unwrap();

            let decrypted = decrypt_keystore(&json, password).unwrap();
            assert_eq!(decrypted.signer.address(), address, "{name}");
            assert_eq!(
                hex::encode_prefixed(decrypted.signer.to_bytes()),
                vector["privateKey"].as_str().unwrap(),
                "{name}"
            );
            match vector["mnemonic"].as_str() {
                Some(phrase) => {
                    assert_eq!(*decrypted.mnemonic.unwrap().phrase, phrase, "{name}");
                }
                None => assert!(decrypted.mnemonic.is_none(), "{name}"),
            }
            assert_eq!(keystore_address(&json).unwrap(), Some(address), "{name}");
            assert!(matches!(
                decrypt_keystore(&json, b"not the password"),
                Err(Error::WrongPassword)
            ));
        }
    }
}

/// Without `hd-wallet`: keystores still decrypt, phrase or not, to their key.
#[cfg(all(test, not(feature = "hd-wallet")))]
mod plain_tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/keystores/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn ethers_keystores_decrypt_to_their_keys_without_the_phrase() {
        let vectors: Value = serde_json::from_str(&fixture("vectors.json")).unwrap();
        for vector in vectors.as_array().unwrap() {
            let name = vector["name"].as_str().unwrap();
            let json = fixture(&format!("{name}.json"));
            let password = vector["password"].as_str().unwrap().as_bytes();
            let address: Address = vector["address"].as_str().unwrap().parse().unwrap();

            let decrypted = decrypt_keystore(&json, password).unwrap();
            assert_eq!(decrypted.signer.address(), address, "{name}");
            assert!(decrypted.mnemonic.is_none(), "{name}");
            assert!(matches!(
                decrypt_keystore(&json, b"not the password"),
                Err(Error::WrongPassword)
            ));
        }
    }
}
