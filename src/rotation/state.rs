//! The local record of which keys own which Safe and which are used up.
//!
//! The state holds addresses and indices only: no private keys, and never an
//! extended public key or chain code. It is a cache of what the chain says plus
//! the two things the chain cannot say: which index is reserved as the next
//! owner, and whether a signature by the current owner has left this machine.
//!
//! Who the current owner is only ever changes through [`RotationState::observe`],
//! which is fed the owner list read from the chain.

use std::collections::BTreeMap;

use alloy::primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Version of the state file layout.
pub const STATE_VERSION: u32 = 1;

/// BIP-32 non-hardened child indices end here.
const MAX_INDEX: u32 = 1 << 31;

/// The key of a binding: `"<chain_id>:<safe>"`.
pub fn binding_key(chain_id: u64, safe: Address) -> String {
    format!("{chain_id}:{safe}")
}

/// An owner key, either derived from the wallet's phrase or foreign to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnerRef {
    /// Key `index` of the wallet
    Derived {
        /// Derivation index
        index: u32,
        /// Its address
        address: Address,
    },
    /// A key the wallet cannot derive (for example the key a Safe was created with)
    External {
        /// Its address
        address: Address,
    },
}

impl OwnerRef {
    /// The owner's address.
    pub fn address(&self) -> Address {
        match self {
            Self::Derived { address, .. } | Self::External { address } => *address,
        }
    }

    /// The derivation index, for a derived key.
    pub fn index(&self) -> Option<u32> {
        match self {
            Self::Derived { index, .. } => Some(*index),
            Self::External { .. } => None,
        }
    }
}

/// The index every signature by the current owner swaps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reserved {
    /// Derivation index
    pub index: u32,
    /// Its address
    pub address: Address,
}

/// Why the current owner's public key must be assumed public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// A signature by this key left the process (broadcast or written out)
    Signed,
    /// The binding was rebuilt from chain, which cannot show reverted or
    /// unbroadcast signatures
    Rebuilt,
    /// The chain shows an owner this state did not expect
    Adopted,
    /// The same key was retired or exposed on another Safe or chain
    SharedKey,
}

/// A signed transaction that was armed for broadcast and is not yet resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTx {
    /// Hash of the Safe transaction
    pub safe_tx_hash: B256,
    /// Safe nonce it was signed for
    pub safe_nonce: U256,
    /// Hash of the outer transaction
    pub outer_tx_hash: B256,
    /// Sender of the outer transaction
    pub payer: Address,
    /// The sender's account nonce
    pub payer_nonce: u64,
    /// The signed outer transaction, for rebroadcast
    pub raw: Bytes,
    /// Unix time the transaction was armed
    pub created_at: u64,
    /// The sweep of the retiring owner, signed to be broadcast right behind
    /// this transaction so that both can land in the same block
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweep: Option<SignedSweep>,
}

/// A signed ETH transfer from a retired owner to the current one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSweep {
    /// Transaction hash
    pub tx_hash: B256,
    /// The retired owner's account nonce
    pub nonce: u64,
    /// Wei transferred
    pub amount: U256,
    /// The signed transaction, for rebroadcast
    pub raw: Bytes,
}

/// ETH that still has to move from a retired owner to the current one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepDue {
    /// The retired owner holding the ETH
    pub from: OwnerRef,
    /// The transfer, once signed
    pub signed: Option<SignedSweep>,
}

/// A completed sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Swept {
    /// Transaction hash
    pub tx_hash: B256,
    /// Wei transferred
    pub amount: U256,
}

/// A retired owner and what replaced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retired {
    /// The owner that was swapped out
    pub owner: OwnerRef,
    /// The owner that took its place
    pub replaced_by: OwnerRef,
    /// Block at which the change was observed
    pub observed_block: Option<u64>,
    /// The sweep of its remaining ETH, if one happened
    pub swept: Option<Swept>,
}

fn default_threshold() -> u64 {
    1
}

/// Parameters a Safe was created with, kept so the same address can be
/// deployed on another chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationParams {
    /// Index of the initial owner
    pub owner_index: u32,
    /// CREATE2 salt nonce
    pub salt_nonce: U256,
    /// Safe singleton
    pub singleton: Address,
    /// Proxy factory
    pub factory: Address,
    /// Fallback handler
    pub fallback_handler: Address,
    /// Additional co-owners beyond `owner_index`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_owners: Vec<Address>,
    /// Safe signature threshold (default: 1)
    #[serde(default = "default_threshold")]
    pub threshold: u64,
}

/// Rotation state of one Safe on one chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The owner this wallet signs with
    pub current: OwnerRef,
    /// The next owner, fixed for as long as `current` is unchanged
    pub reserved: Option<Reserved>,
    /// Set once the current owner's public key must be assumed public
    pub exposed: Option<Exposure>,
    /// A broadcast (or written out) transaction not yet seen on chain
    pub pending: Option<PendingTx>,
    /// ETH still to be moved off retired owners, oldest first. An entry stays
    /// until its sweep is done: a later rotation adds one, it never replaces one
    #[serde(default)]
    pub sweep_due: Vec<SweepDue>,
    /// Retired owners, oldest first
    pub history: Vec<Retired>,
    /// How the Safe was created, if this wallet created it
    pub creation: Option<CreationParams>,
}

impl Binding {
    fn new(current: OwnerRef) -> Self {
        Self {
            current,
            reserved: None,
            exposed: None,
            pending: None,
            sweep_due: Vec::new(),
            history: Vec::new(),
            creation: None,
        }
    }

    /// Adds a sweep from `from`, unless one is already owed from it.
    fn owe_sweep(&mut self, from: OwnerRef) {
        if !self.sweep_due.iter().any(|due| due.from == from) {
            self.sweep_due.push(SweepDue { from, signed: None });
        }
    }

    /// The index that replaced derived key `index` on this Safe, if any.
    fn successor_of(&self, index: u32) -> Option<Reserved> {
        self.history.iter().rev().find_map(|retired| {
            match (retired.owner.index(), retired.replaced_by) {
                (
                    Some(owner),
                    OwnerRef::Derived {
                        index: next,
                        address,
                    },
                ) if owner == index => Some(Reserved {
                    index: next,
                    address,
                }),
                _ => None,
            }
        })
    }
}

/// What reading the owner list told us about a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The current owner is still an owner
    Unchanged,
    /// The reserved key replaced the current owner
    Rotated {
        /// The owner that was retired
        from: OwnerRef,
        /// Index of the new owner
        to: u32,
    },
    /// A different key of this wallet is an owner; it was adopted as current
    Adopted {
        /// Index of the adopted key
        index: u32,
    },
    /// Neither the current owner nor any key of this wallet is an owner
    Lost,
}

/// Everything recorded for one wallet (one phrase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationState {
    /// File layout version
    pub version: u32,
    /// The wallet's funding address (index 0), which identifies the phrase
    pub wallet_id: Address,
    /// The next index that has never been handed out
    pub next_index: u32,
    /// Bindings by [`binding_key`]
    pub safes: BTreeMap<String, Binding>,
    /// Addresses of the wallet's keys by index, as far as they were looked up.
    /// A cache: before a key signs, its source must still agree
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub addresses: BTreeMap<u32, Address>,
}

impl RotationState {
    /// An empty state whose first owner key is `first_index`.
    ///
    /// Index 0 is the funding key and never an owner, so `first_index` is at
    /// least 1.
    pub fn new(wallet_id: Address, first_index: u32) -> Self {
        Self {
            version: STATE_VERSION,
            wallet_id,
            next_index: first_index.max(1),
            safes: BTreeMap::new(),
            addresses: BTreeMap::new(),
        }
    }

    /// The binding for `key`.
    pub fn binding(&self, key: &str) -> Result<&Binding> {
        self.safes
            .get(key)
            .ok_or_else(|| Error::Rotation(format!("no rotation state for {key}")))
    }

    fn binding_mut(&mut self, key: &str) -> Result<&mut Binding> {
        self.safes
            .get_mut(key)
            .ok_or_else(|| Error::Rotation(format!("no rotation state for {key}")))
    }

    /// Starts tracking a Safe whose owner is `current`.
    pub fn bind(&mut self, key: &str, current: OwnerRef) -> Result<()> {
        if self.safes.contains_key(key) {
            return Err(Error::Rotation(format!("{key} is already tracked")));
        }
        if let Some(index) = current.index() {
            self.note_used(index);
        }
        self.safes.insert(key.to_string(), Binding::new(current));
        Ok(())
    }

    /// Records that `index` is in use, so it is never handed out again.
    pub fn note_used(&mut self, index: u32) {
        self.next_index = self.next_index.max(index.saturating_add(1));
    }

    /// Leaves `margin` indices unused, for when the counter was rebuilt from
    /// sources that cannot show every index that was handed out.
    pub fn skip_ahead(&mut self, margin: u32) {
        self.next_index = self.next_index.saturating_add(margin).min(MAX_INDEX);
    }

    /// Hands out the next never-used index.
    ///
    /// The counter is advanced before the index is returned and never moves
    /// back, so an index is handed out at most once per state. Save the state
    /// before using the key.
    pub fn allocate(&mut self) -> Result<u32> {
        let index = self.next_index;
        if index >= MAX_INDEX {
            return Err(Error::Rotation(
                "the wallet has no unused key indices left".to_string(),
            ));
        }
        self.next_index = index + 1;
        Ok(index)
    }

    /// Fixes `reserved` as the next owner of `key`.
    ///
    /// A binding keeps its reservation until the owner changes, so this fails
    /// if a different index is already reserved.
    pub fn reserve(&mut self, key: &str, reserved: Reserved) -> Result<()> {
        let binding = self.binding_mut(key)?;
        match binding.reserved {
            Some(existing) if existing != reserved => Err(Error::Rotation(format!(
                "{key} already reserves index {} as its next owner",
                existing.index
            ))),
            _ => {
                binding.reserved = Some(reserved);
                Ok(())
            }
        }
    }

    /// Records that a signature by the current owner is about to leave the
    /// process, together with the transaction that carries it.
    pub fn arm(&mut self, key: &str, pending: PendingTx) -> Result<()> {
        let binding = self.binding_mut(key)?;
        if binding.reserved.is_none() {
            return Err(Error::Rotation(format!(
                "{key} has no reserved next owner to rotate to"
            )));
        }
        binding.exposed.get_or_insert(Exposure::Signed);
        binding.pending = Some(pending);
        Ok(())
    }

    /// Marks the current owner of `key` as exposed, keeping an earlier reason.
    pub fn mark_exposed(&mut self, key: &str, reason: Exposure) -> Result<()> {
        self.binding_mut(key)?.exposed.get_or_insert(reason);
        Ok(())
    }

    /// Drops a pending transaction that can no longer be mined.
    pub fn clear_pending(&mut self, key: &str) -> Result<()> {
        self.binding_mut(key)?.pending = None;
        Ok(())
    }

    /// Updates a binding from the Safe's owner list.
    ///
    /// `lookup` maps an address to the wallet index that derives it, if any.
    /// With `sweep`, a rotation away from the current owner schedules a sweep of
    /// its ETH.
    pub fn observe(
        &mut self,
        key: &str,
        owners: &[Address],
        block: Option<u64>,
        lookup: impl Fn(Address) -> Option<u32>,
        sweep: bool,
    ) -> Result<Observation> {
        let binding = self.binding_mut(key)?;
        let current = binding.current;
        if owners.contains(&current.address()) {
            return Ok(Observation::Unchanged);
        }

        let (next, observation) = match binding.reserved {
            Some(reserved) if owners.contains(&reserved.address) => (
                reserved,
                Observation::Rotated {
                    from: current,
                    to: reserved.index,
                },
            ),
            _ => {
                let adopted = owners.iter().find_map(|owner| {
                    lookup(*owner).map(|index| Reserved {
                        index,
                        address: *owner,
                    })
                });
                match adopted {
                    Some(adopted) => (
                        adopted,
                        Observation::Adopted {
                            index: adopted.index,
                        },
                    ),
                    None => return Ok(Observation::Lost),
                }
            }
        };

        let replaced_by = OwnerRef::Derived {
            index: next.index,
            address: next.address,
        };
        binding.history.push(Retired {
            owner: current,
            replaced_by,
            observed_block: block,
            swept: None,
        });
        binding.current = replaced_by;
        // A sweep signed alongside the rotation moves `current`'s ETH to the
        // reserved key, which is where it belongs only if this is that rotation.
        let presigned = binding.pending.take().and_then(|pending| pending.sweep);
        if let Observation::Rotated { .. } = observation {
            binding.reserved = None;
            binding.exposed = None;
            if sweep {
                binding.owe_sweep(current);
                if let Some(due) = binding
                    .sweep_due
                    .iter_mut()
                    .find(|due| due.from == current && due.signed.is_none())
                {
                    due.signed = presigned;
                }
            }
        } else {
            // An owner we did not rotate to: it may be an earlier key whose
            // rotation was undone, in which case its signatures already name
            // a successor.
            binding.reserved = binding.successor_of(next.index);
            binding.exposed = Some(Exposure::Adopted);
        }
        self.note_used(next.index);
        Ok(observation)
    }

    /// Stores the sweep signed to go out with the pending transaction
    /// `outer_tx_hash`, or forgets it (`None`) when the node turned it down.
    pub fn set_pending_sweep(
        &mut self,
        key: &str,
        outer_tx_hash: B256,
        sweep: Option<SignedSweep>,
    ) -> Result<()> {
        match &mut self.binding_mut(key)?.pending {
            Some(pending) if pending.outer_tx_hash == outer_tx_hash => {
                pending.sweep = sweep;
                Ok(())
            }
            _ => Err(Error::Rotation(format!(
                "{key} has no pending transaction {outer_tx_hash}"
            ))),
        }
    }

    /// Stores the signed sweep from `from` before it is first broadcast, or
    /// forgets it (`None`) when the node turned it down and another one has to
    /// be signed.
    pub fn set_signed_sweep(
        &mut self,
        key: &str,
        from: Address,
        signed: Option<SignedSweep>,
    ) -> Result<()> {
        let binding = self.binding_mut(key)?;
        match binding
            .sweep_due
            .iter_mut()
            .find(|due| due.from.address() == from)
        {
            Some(due) => {
                due.signed = signed;
                Ok(())
            }
            None => Err(Error::Rotation(format!(
                "{key} has no sweep due from {from}"
            ))),
        }
    }

    /// Schedules a sweep of `from`'s ETH to the current owner of `key`, unless
    /// one is already owed.
    pub fn schedule_sweep(&mut self, key: &str, from: OwnerRef) -> Result<()> {
        self.binding_mut(key)?.owe_sweep(from);
        Ok(())
    }

    /// Replaces the recorded history of `key`, for a rebuild from chain.
    pub fn set_history(&mut self, key: &str, history: Vec<Retired>) -> Result<()> {
        for index in history.iter().filter_map(|retired| retired.owner.index()) {
            self.note_used(index);
        }
        self.binding_mut(key)?.history = history;
        Ok(())
    }

    /// Records how the Safe of `key` was created.
    pub fn set_creation(&mut self, key: &str, creation: CreationParams) -> Result<()> {
        self.binding_mut(key)?.creation = Some(creation);
        Ok(())
    }

    /// Clears the sweep owed from `from`, recording `swept` on the retired
    /// owner if ETH moved.
    pub fn finish_sweep(&mut self, key: &str, from: Address, swept: Option<Swept>) -> Result<()> {
        let binding = self.binding_mut(key)?;
        binding.sweep_due.retain(|due| due.from.address() != from);
        if let Some(retired) = binding
            .history
            .iter_mut()
            .rev()
            .find(|retired| retired.owner.address() == from)
        {
            retired.swept = swept;
        }
        Ok(())
    }

    /// Flags bindings whose current key was retired or exposed in another
    /// binding, and returns a message for each newly flagged one.
    ///
    /// This happens when the same Safe address exists on several chains with
    /// the same initial owner: rotating on one chain publishes the key that
    /// still owns the others.
    pub fn cross_check(&mut self) -> Vec<String> {
        let mut burned: BTreeMap<u32, String> = BTreeMap::new();
        for (key, binding) in &self.safes {
            for retired in &binding.history {
                if let Some(index) = retired.owner.index() {
                    burned.entry(index).or_insert_with(|| key.clone());
                }
            }
            if let (Some(index), Some(_)) = (binding.current.index(), binding.exposed) {
                burned.entry(index).or_insert_with(|| key.clone());
            }
        }

        let mut warnings = Vec::new();
        for (key, binding) in &mut self.safes {
            let Some(index) = binding.current.index() else {
                continue;
            };
            let Some(source) = burned.get(&index) else {
                continue;
            };
            if source != key && binding.exposed.is_none() {
                binding.exposed = Some(Exposure::SharedKey);
                warnings.push(format!(
                    "key {index} still owns {key} but was already used on {source}; rotate {key} now"
                ));
            }
        }
        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "1:0x00000000000000000000000000000000000005AF";
    const OTHER: &str = "10:0x00000000000000000000000000000000000005AF";

    fn addr(index: u32) -> Address {
        Address::left_padding_from(&(0x1000 + index).to_be_bytes())
    }

    /// Allocates the next index, with its test address.
    fn take(state: &mut RotationState) -> Reserved {
        let index = state.allocate().unwrap();
        Reserved {
            index,
            address: addr(index),
        }
    }

    fn lookup(address: Address) -> Option<u32> {
        (1..64).find(|index| addr(*index) == address)
    }

    fn derived(index: u32) -> OwnerRef {
        OwnerRef::Derived {
            index,
            address: addr(index),
        }
    }

    fn pending() -> PendingTx {
        PendingTx {
            safe_tx_hash: B256::repeat_byte(1),
            safe_nonce: U256::from(3),
            outer_tx_hash: B256::repeat_byte(2),
            payer: addr(1),
            payer_nonce: 0,
            raw: Bytes::from_static(&[0x02, 0xff]),
            created_at: 1_700_000_000,
            sweep: None,
        }
    }

    /// A state tracking `KEY` with owner 1 and index 2 reserved.
    fn reserved_state() -> RotationState {
        let mut state = RotationState::new(addr(0), 1);
        let first = take(&mut state);
        assert_eq!(first.index, 1);
        state.bind(KEY, derived(1)).unwrap();
        let next = take(&mut state);
        state.reserve(KEY, next).unwrap();
        state
    }

    #[test]
    fn allocation_is_monotonic_and_skips_bound_indices() {
        let mut state = RotationState::new(addr(0), 0);
        assert_eq!(state.next_index, 1, "index 0 is never an owner");
        state.bind(KEY, derived(5)).unwrap();
        assert_eq!(take(&mut state).index, 6);
        assert_eq!(take(&mut state).index, 7);
        assert!(state.bind(KEY, derived(9)).is_err(), "already tracked");

        state.next_index = MAX_INDEX;
        assert!(state.allocate().is_err());
    }

    #[test]
    fn a_reservation_is_stable_until_the_owner_changes() {
        let mut state = reserved_state();
        let reserved = state.binding(KEY).unwrap().reserved.unwrap();
        state.reserve(KEY, reserved).unwrap();
        let other = take(&mut state);
        assert!(state.reserve(KEY, other).is_err());
    }

    #[test]
    fn arming_marks_the_owner_exposed() {
        let mut state = RotationState::new(addr(0), 1);
        state.bind(KEY, derived(1)).unwrap();
        assert!(state.arm(KEY, pending()).is_err(), "nothing reserved yet");

        let mut state = reserved_state();
        state.arm(KEY, pending()).unwrap();
        let binding = state.binding(KEY).unwrap();
        assert_eq!(binding.exposed, Some(Exposure::Signed));
        assert_eq!(binding.pending, Some(pending()));
    }

    #[test]
    fn observing_the_current_owner_changes_nothing() {
        let mut state = reserved_state();
        state.arm(KEY, pending()).unwrap();
        let before = state.clone();
        let seen = state
            .observe(KEY, &[addr(1)], Some(10), lookup, true)
            .unwrap();
        assert_eq!(seen, Observation::Unchanged);
        assert_eq!(state, before);
    }

    #[test]
    fn observing_the_reserved_owner_completes_the_rotation() {
        let mut state = reserved_state();
        state.arm(KEY, pending()).unwrap();
        let seen = state
            .observe(KEY, &[addr(2)], Some(11), lookup, true)
            .unwrap();
        assert_eq!(
            seen,
            Observation::Rotated {
                from: derived(1),
                to: 2
            }
        );
        let binding = state.binding(KEY).unwrap();
        assert_eq!(binding.current, derived(2));
        assert_eq!(binding.reserved, None);
        assert_eq!(binding.exposed, None);
        assert_eq!(binding.pending, None);
        assert_eq!(
            binding.sweep_due,
            vec![SweepDue {
                from: derived(1),
                signed: None
            }]
        );
        assert_eq!(binding.history.len(), 1);
        assert_eq!(binding.history[0].observed_block, Some(11));
    }

    #[test]
    fn no_sweep_is_scheduled_when_disabled() {
        let mut state = reserved_state();
        state.observe(KEY, &[addr(2)], None, lookup, false).unwrap();
        assert!(state.binding(KEY).unwrap().sweep_due.is_empty());
    }

    #[test]
    fn an_unexpected_wallet_key_is_adopted_and_flagged() {
        let mut state = reserved_state();
        let seen = state.observe(KEY, &[addr(9)], None, lookup, true).unwrap();
        assert_eq!(seen, Observation::Adopted { index: 9 });
        let binding = state.binding(KEY).unwrap();
        assert_eq!(binding.current, derived(9));
        assert_eq!(binding.exposed, Some(Exposure::Adopted));
        assert_eq!(binding.reserved, None);
        assert!(binding.sweep_due.is_empty());
        assert_eq!(state.next_index, 10, "the adopted index is used up");
    }

    #[test]
    fn a_rotation_undone_by_a_reorg_keeps_its_successor() {
        let mut state = reserved_state();
        state
            .observe(KEY, &[addr(2)], Some(11), lookup, false)
            .unwrap();
        // The chain now shows key 1 again: every signature key 1 made names key 2.
        let seen = state
            .observe(KEY, &[addr(1)], Some(11), lookup, false)
            .unwrap();
        assert_eq!(seen, Observation::Adopted { index: 1 });
        let binding = state.binding(KEY).unwrap();
        assert_eq!(binding.current, derived(1));
        assert_eq!(
            binding.reserved,
            Some(Reserved {
                index: 2,
                address: addr(2)
            })
        );
        assert_eq!(binding.exposed, Some(Exposure::Adopted));
    }

    #[test]
    fn an_owner_list_without_wallet_keys_is_lost() {
        let mut state = reserved_state();
        let before = state.clone();
        let stranger = Address::repeat_byte(0xEE);
        let seen = state.observe(KEY, &[stranger], None, lookup, true).unwrap();
        assert_eq!(seen, Observation::Lost);
        assert_eq!(state, before);
    }

    #[test]
    fn a_finished_sweep_is_recorded_on_the_retired_owner() {
        let mut state = reserved_state();
        state.observe(KEY, &[addr(2)], None, lookup, true).unwrap();
        let signed = SignedSweep {
            tx_hash: B256::repeat_byte(7),
            nonce: 1,
            amount: U256::from(99),
            raw: Bytes::from_static(&[0x02]),
        };
        state
            .set_signed_sweep(KEY, addr(1), Some(signed.clone()))
            .unwrap();
        assert_eq!(
            state.binding(KEY).unwrap().sweep_due[0].signed,
            Some(signed)
        );

        let swept = Swept {
            tx_hash: B256::repeat_byte(7),
            amount: U256::from(99),
        };
        state.finish_sweep(KEY, addr(1), Some(swept)).unwrap();
        let binding = state.binding(KEY).unwrap();
        assert!(binding.sweep_due.is_empty());
        assert_eq!(binding.history[0].swept, Some(swept));
        assert!(
            state.set_signed_sweep(KEY, addr(1), None).is_err(),
            "nothing is due"
        );
    }

    #[test]
    fn a_later_rotation_adds_to_the_owed_sweeps_instead_of_replacing_them() {
        let mut state = reserved_state();
        state.observe(KEY, &[addr(2)], None, lookup, true).unwrap();
        let signed = SignedSweep {
            tx_hash: B256::repeat_byte(7),
            nonce: 1,
            amount: U256::from(99),
            raw: Bytes::from_static(&[0x02]),
        };
        state
            .set_signed_sweep(KEY, addr(1), Some(signed.clone()))
            .unwrap();

        // Key 2 rotates to key 3 while the sweep from key 1 is still owed.
        let next = take(&mut state);
        state.reserve(KEY, next).unwrap();
        state.observe(KEY, &[addr(3)], None, lookup, true).unwrap();
        let due = &state.binding(KEY).unwrap().sweep_due;
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].from, derived(1), "oldest first");
        assert_eq!(due[0].signed, Some(signed), "its signed transfer is kept");
        assert_eq!(due[1].from, derived(2));

        // Scheduling the same key again changes nothing.
        state.schedule_sweep(KEY, derived(1)).unwrap();
        assert_eq!(state.binding(KEY).unwrap().sweep_due.len(), 2);

        // Each is finished on its own, in any order.
        state.finish_sweep(KEY, addr(2), None).unwrap();
        let due = &state.binding(KEY).unwrap().sweep_due;
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].from, derived(1));
    }

    #[test]
    fn a_key_retired_on_one_chain_flags_the_other() {
        let mut state = RotationState::new(addr(0), 1);
        state.bind(KEY, derived(1)).unwrap();
        state.bind(OTHER, derived(1)).unwrap();
        assert!(state.cross_check().is_empty());

        let next = take(&mut state);
        state.reserve(KEY, next).unwrap();
        state.observe(KEY, &[addr(2)], None, lookup, false).unwrap();

        let warnings = state.cross_check();
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            state.binding(OTHER).unwrap().exposed,
            Some(Exposure::SharedKey)
        );
        assert!(state.cross_check().is_empty(), "reported once");
    }

    #[test]
    fn a_state_file_from_before_the_address_cache_still_loads() {
        // As written before key addresses were recorded.
        let json = r#"{
          "version": 1,
          "wallet_id": "0x0000000000000000000000000000000000001000",
          "next_index": 3,
          "safes": {
            "1:0x00000000000000000000000000000000000005AF": {
              "current": { "kind": "derived", "index": 2, "address": "0x0000000000000000000000000000000000001002" },
              "reserved": null,
              "exposed": null,
              "pending": null,
              "sweep_due": [],
              "history": [
                {
                  "owner": { "kind": "derived", "index": 1, "address": "0x0000000000000000000000000000000000001001" },
                  "replaced_by": { "kind": "derived", "index": 2, "address": "0x0000000000000000000000000000000000001002" },
                  "observed_block": 9,
                  "swept": null
                }
              ],
              "creation": null
            }
          }
        }"#;
        let state: RotationState = serde_json::from_str(json).unwrap();
        assert!(state.addresses.is_empty());
        assert_eq!(state.next_index, 3);
        assert_eq!(state.binding(KEY).unwrap().current, derived(2));
        // An empty cache is not written, so the file stays readable by builds
        // that predate it.
        assert!(!serde_json::to_string(&state).unwrap().contains("addresses"));
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut state = reserved_state();
        state.arm(KEY, pending()).unwrap();
        state
            .bind(OTHER, OwnerRef::External { address: addr(40) })
            .unwrap();
        state.addresses.insert(0, addr(0));
        state.addresses.insert(7, addr(7));
        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(!json.contains("xpub"));
        let back: RotationState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}
