//! Where owner keys come from, and the record of their addresses.
//!
//! A [`KeySource`] is one seed's keys at `m/44'/60'/0'/0/i`: a phrase held in
//! memory ([`HdWallet`]) or a hardware wallet. Index 0 is the funding key and
//! indices 1 and up are one-time owner keys.
//!
//! A [`Keyring`] pairs a source with its rotation state. It records every
//! address it asks the source for, so a slow source (a device) is asked once,
//! and it looks ahead: [`SETUP_LOOKAHEAD`] keys when a Safe is set up and
//! [`SEND_LOOKAHEAD`] on every send, so the next keys are always at hand. The
//! record is only a cache: before a key signs, the source is asked for its
//! address again and must agree, so the wrong device or phrase fails before
//! anything is signed.

use std::collections::HashMap;
use std::future::Future;

use alloy::network::AnyNetwork;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;

use crate::envelope::{PreparedSafeTx, SignedSafeTx};
use crate::error::{Error, Result};
use crate::hd::HdWallet;
use crate::outer::{sign_outer_tx, OuterTxParams, SignedOuterTx};
use crate::rotation::state::{Reserved, RotationState};
use crate::rotation::store::StateFile;

/// Keys looked ahead when a Safe is set up (created, adopted or synced).
pub const SETUP_LOOKAHEAD: u32 = 20;

/// Keys kept looked ahead of the next unused one on every send.
pub const SEND_LOOKAHEAD: u32 = 5;

/// How many keys a source is searched by default for an owner that is not on
/// record. Local derivation is fast; a device overrides this.
pub const DEFAULT_SCAN_LIMIT: u32 = 1_000;

/// One seed's keys at `m/44'/60'/0'/0/i`.
///
/// Implementations only derive and sign; recording addresses, checking them
/// and choosing indices is [`Keyring`]'s job.
pub trait KeySource: Send + Sync {
    /// The address of key `index`, from the source itself.
    fn address(&self, index: u32) -> impl Future<Output = Result<Address>> + Send;

    /// How many keys to search for an owner that is not on record. A source
    /// that answers slowly (a device) keeps this small.
    fn scan_limit(&self) -> u32 {
        DEFAULT_SCAN_LIMIT
    }

    /// Signs a Safe transaction with key `index`.
    fn sign_safe_tx(
        &self,
        index: u32,
        tx: &PreparedSafeTx,
    ) -> impl Future<Output = Result<SignedSafeTx>> + Send;

    /// Signs an outer transaction with key `index`.
    fn sign_outer_tx(
        &self,
        index: u32,
        params: OuterTxParams,
    ) -> impl Future<Output = Result<SignedOuterTx>> + Send;
}

impl HdWallet {
    /// Key `index`, the funding key included.
    fn key(&self, index: u32) -> Result<PrivateKeySigner> {
        if index == 0 {
            Ok(self.funding().clone())
        } else {
            self.owner(index)
        }
    }
}

impl KeySource for HdWallet {
    fn address(&self, index: u32) -> impl Future<Output = Result<Address>> + Send {
        std::future::ready(self.key(index).map(|key| key.address()))
    }

    async fn sign_safe_tx(&self, index: u32, tx: &PreparedSafeTx) -> Result<SignedSafeTx> {
        tx.sign(&self.key(index)?).await
    }

    async fn sign_outer_tx(&self, index: u32, params: OuterTxParams) -> Result<SignedOuterTx> {
        sign_outer_tx(&self.key(index)?, params).await
    }
}

/// A key source and its rotation state.
#[derive(Debug)]
pub struct Keyring<K> {
    keys: K,
    /// The rotation state, locked for as long as the keyring lives
    pub store: StateFile,
}

impl<K: KeySource> Keyring<K> {
    /// Pairs `keys` with `store`, after checking the state belongs to them: its
    /// wallet ID is the address of key 0.
    pub async fn open(keys: K, mut store: StateFile) -> Result<Self> {
        let id = keys.address(0).await?;
        if id != store.state.wallet_id {
            return Err(Error::Rotation(format!(
                "the state belongs to wallet {}, not {id}",
                store.state.wallet_id
            )));
        }
        store.state.addresses.insert(0, id);
        Ok(Self { keys, store })
    }

    /// The key source.
    pub fn keys(&self) -> &K {
        &self.keys
    }

    /// The wallet ID: the address of key 0.
    pub fn id(&self) -> Address {
        self.store.state.wallet_id
    }

    /// Everything recorded for the wallet.
    pub fn state(&self) -> &RotationState {
        &self.store.state
    }

    /// Writes the state to disk.
    pub fn save(&self) -> Result<()> {
        self.store.save()
    }

    /// The address of key `index`: the recorded one, or the source's, which
    /// is then recorded (and saved with the next [`Keyring::save`]).
    pub async fn address(&mut self, index: u32) -> Result<Address> {
        if let Some(address) = self.store.state.addresses.get(&index) {
            return Ok(*address);
        }
        let address = self.keys.address(index).await?;
        self.store.state.addresses.insert(index, address);
        Ok(address)
    }

    /// Records the address of every key up to `ahead` past the next unused
    /// one, so they are at hand without asking the source. Returns how many
    /// it had to ask for.
    pub async fn look_ahead(&mut self, ahead: u32) -> Result<u32> {
        let end = self.store.state.next_index.saturating_add(ahead);
        let mut asked = 0;
        for index in 0..end {
            if !self.store.state.addresses.contains_key(&index) {
                self.address(index).await?;
                asked += 1;
            }
        }
        if asked > 0 {
            self.save()?;
        }
        Ok(asked)
    }

    /// Every owner key known, address to index: all recorded ones, plus the
    /// rest of `1..=limit` asked of the source for this call only (a search far
    /// ahead is not worth keeping). `limit` bounds the questions, not the
    /// record.
    pub async fn scan(&self, limit: u32) -> Result<HashMap<Address, u32>> {
        let mut found: HashMap<Address, u32> = self.recorded_owner_keys().collect();
        for index in 1..=limit {
            if !self.store.state.addresses.contains_key(&index) {
                found.insert(self.keys.address(index).await?, index);
            }
        }
        Ok(found)
    }

    /// The first owner key in `owners`: among all recorded ones, then among
    /// the rest of `1..=limit`, asked of the source.
    pub async fn find(&self, owners: &[Address], limit: u32) -> Result<Option<(u32, Address)>> {
        let recorded = self
            .recorded_owner_keys()
            .find(|(address, _)| owners.contains(address));
        if let Some((address, index)) = recorded {
            return Ok(Some((index, address)));
        }
        for index in 1..=limit {
            if self.store.state.addresses.contains_key(&index) {
                continue;
            }
            let address = self.keys.address(index).await?;
            if owners.contains(&address) {
                return Ok(Some((index, address)));
            }
        }
        Ok(None)
    }

    /// Recorded owner keys (index 1 and up), address first.
    fn recorded_owner_keys(&self) -> impl Iterator<Item = (Address, u32)> + '_ {
        self.store
            .state
            .addresses
            .iter()
            .filter(|(index, _)| **index > 0)
            .map(|(index, address)| (*address, *index))
    }

    /// Takes the next key that has never been handed out and whose address
    /// has neither sent a transaction nor holds code on this chain. Returns it
    /// with a note for each key skipped.
    ///
    /// The counter is saved before a key is looked at, so no key is handed out
    /// twice, even by two processes or across a crash.
    pub async fn take_unused<P: Provider<AnyNetwork>>(
        &mut self,
        provider: &P,
    ) -> Result<(Reserved, Vec<String>)> {
        let mut skipped = Vec::new();
        loop {
            let index = self.store.state.allocate()?;
            self.save()?;
            let address = self.address(index).await?;
            let provider_error =
                |e: alloy::transports::TransportError| Error::Provider(e.to_string());
            let nonce = provider
                .get_transaction_count(address)
                .await
                .map_err(provider_error)?;
            let code = provider
                .get_code_at(address)
                .await
                .map_err(provider_error)?;
            if nonce != 0 || !code.is_empty() {
                skipped.push(format!(
                    "skipping key {index}: {address} was already used on this chain"
                ));
                continue;
            }
            self.save()?;
            return Ok((Reserved { index, address }, skipped));
        }
    }

    /// Checks the source still has `expected` at `index`, before it signs.
    async fn confirm(&self, index: u32, expected: Address) -> Result<()> {
        let actual = self.keys.address(index).await?;
        if actual == expected {
            Ok(())
        } else {
            Err(Error::Rotation(format!(
                "key {index} is {actual} here, but {expected} is recorded for it; \
                 is this the wallet (or device, or passphrase) the state belongs to?"
            )))
        }
    }

    /// Signs a Safe transaction with key `index`, which must be `expected`.
    pub async fn sign_safe_tx(
        &self,
        index: u32,
        expected: Address,
        tx: &PreparedSafeTx,
    ) -> Result<SignedSafeTx> {
        self.confirm(index, expected).await?;
        self.keys.sign_safe_tx(index, tx).await
    }

    /// Signs an outer transaction with key `index`, which must be `expected`.
    pub async fn sign_outer_tx(
        &self,
        index: u32,
        expected: Address,
        params: OuterTxParams,
    ) -> Result<SignedOuterTx> {
        self.confirm(index, expected).await?;
        self.keys.sign_outer_tx(index, params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::SafeTxGasPolicy;
    use crate::types::Call;
    use alloy::primitives::{Bytes, U256};

    const PHRASE: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn wallet() -> HdWallet {
        HdWallet::from_phrase(PHRASE).unwrap()
    }

    async fn open(dir: &tempfile::TempDir) -> Keyring<HdWallet> {
        let store = StateFile::open(dir.path().join("state.json"), wallet().id()).unwrap();
        Keyring::open(wallet(), store).await.unwrap()
    }

    #[tokio::test]
    async fn a_state_of_another_wallet_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            StateFile::open(dir.path().join("state.json"), Address::repeat_byte(1)).unwrap();
        assert!(matches!(
            Keyring::open(wallet(), store).await,
            Err(Error::Rotation(_))
        ));
    }

    #[tokio::test]
    async fn looking_ahead_records_the_window_and_saves_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut ring = open(&dir).await;
        // The next unused key is 1, so the look-ahead is keys 1 to 5.
        assert_eq!(ring.look_ahead(SEND_LOOKAHEAD).await.unwrap(), 5);
        assert_eq!(
            ring.look_ahead(SEND_LOOKAHEAD).await.unwrap(),
            0,
            "all recorded"
        );
        let recorded: Vec<u32> = ring.state().addresses.keys().copied().collect();
        assert_eq!(recorded, (0..6).collect::<Vec<_>>());
        assert_eq!(
            ring.state().addresses[&3],
            wallet().owner_address(3).unwrap()
        );
        drop(ring);

        let reopened = open(&dir).await;
        assert_eq!(reopened.state().addresses.len(), 6, "saved to disk");
    }

    #[tokio::test]
    async fn find_and_scan_look_past_the_record_without_keeping_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut ring = open(&dir).await;
        ring.look_ahead(2).await.unwrap(); // records keys 0..=2
        let ninth = wallet().owner_address(9).unwrap();
        let stranger = Address::repeat_byte(0xEE);

        assert_eq!(
            ring.find(&[stranger, ring.state().addresses[&2]], 20)
                .await
                .unwrap(),
            Some((2, wallet().owner_address(2).unwrap()))
        );
        assert_eq!(
            ring.find(&[stranger, ninth], 20).await.unwrap(),
            Some((9, ninth))
        );
        assert_eq!(
            ring.find(&[ninth], 8).await.unwrap(),
            None,
            "beyond the limit"
        );
        // A recorded key is found whatever the limit.
        let second = ring.state().addresses[&2];
        assert_eq!(ring.find(&[second], 1).await.unwrap(), Some((2, second)));
        assert_eq!(ring.scan(1).await.unwrap()[&second], 2);
        assert_eq!(
            ring.find(&[ring.id()], 20).await.unwrap(),
            None,
            "key 0 never owns"
        );

        let scanned = ring.scan(12).await.unwrap();
        assert_eq!(scanned.len(), 12);
        assert_eq!(scanned[&ninth], 9);
        assert_eq!(
            ring.state().addresses.len(),
            3,
            "nothing past the window kept"
        );
    }

    #[tokio::test]
    async fn a_key_whose_recorded_address_disagrees_does_not_sign() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(&dir).await;
        let safe = Address::repeat_byte(0x5A);
        let tx = PreparedSafeTx::single_call(
            1,
            safe,
            &Call::new(safe, U256::ZERO, Bytes::new()),
            U256::ZERO,
            SafeTxGasPolicy::Zero,
        )
        .unwrap();

        let right = wallet().owner_address(2).unwrap();
        let signed = ring.sign_safe_tx(2, right, &tx).await.unwrap();
        assert_eq!(signed.owner(), Some(right));

        // A different phrase (or device) behind the same state.
        let wrong = Address::repeat_byte(0x22);
        assert!(matches!(
            ring.sign_safe_tx(2, wrong, &tx).await,
            Err(Error::Rotation(_))
        ));
    }
}
