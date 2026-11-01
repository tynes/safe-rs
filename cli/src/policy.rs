//! Rules a host CLI holds every Safe transaction to, checked against the
//! simulated result before anything is signed or sent.
//!
//! A host whose Safes must keep a shape (for example, an app whose off-chain
//! service only accepts a Safe still owned by the key it was created for) sets
//! a [`SafePolicy`] on [`RunConfig`](crate::RunConfig) or
//! [`SendContext`](crate::SendContext). Every Safe transaction then has to be
//! simulated (`--skip-simulation` is refused), the policy sees the Safe before
//! and after, and owner key rotation is refused unless the policy allows it.

use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;
use safe_rs::{ForkSession, ISafe, SafeState};

/// The parts of a Safe a policy checks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SafeSnapshot {
    pub safe: Address,
    pub owners: Vec<Address>,
    pub threshold: U256,
    /// The implementation the proxy delegates to (storage slot 0)
    pub singleton: Address,
}

impl SafeSnapshot {
    /// A snapshot, for testing a policy.
    pub fn new(safe: Address, owners: Vec<Address>, threshold: U256, singleton: Address) -> Self {
        Self {
            safe,
            owners,
            threshold,
            singleton,
        }
    }

    pub(crate) fn from_state(state: &SafeState) -> Self {
        Self {
            safe: state.address,
            owners: state.owners.clone(),
            threshold: state.threshold,
            singleton: state.singleton,
        }
    }

    /// Reads the Safe from the simulated post-state.
    pub(crate) fn read(post: &mut ForkSession, safe: Address) -> safe_rs::Result<Self> {
        fn call<C: SolCall>(
            post: &mut ForkSession,
            safe: Address,
            call: &C,
        ) -> safe_rs::Result<C::Return> {
            let out = post.call(Address::ZERO, safe, call.abi_encode().into())?;
            C::abi_decode_returns(&out).map_err(|e| safe_rs::Error::Abi(e.to_string()))
        }
        let owners = call(post, safe, &ISafe::getOwnersCall {})?;
        let threshold = call(post, safe, &ISafe::getThresholdCall {})?;
        let slot0 = call(
            post,
            safe,
            &ISafe::getStorageAtCall {
                offset: U256::ZERO,
                length: U256::from(1),
            },
        )?;
        if slot0.len() != 32 {
            return Err(safe_rs::Error::Abi(format!(
                "getStorageAt returned {} bytes, expected 32",
                slot0.len()
            )));
        }
        Ok(Self {
            safe,
            owners,
            threshold,
            singleton: Address::from_slice(&slot0[12..]),
        })
    }
}

/// What a host requires of its Safes.
pub trait SafePolicy: Send + Sync {
    /// A short name for error messages, such as "polymarket".
    fn name(&self) -> &str;

    /// Whether `--rotate` and `safe rotate` may swap the Safe's owner key.
    /// Default: yes.
    fn allows_rotation(&self) -> bool {
        true
    }

    /// Checks a Safe transaction by the Safe before and after it (in
    /// simulation). An `Err` stops the send before anything is signed or sent,
    /// with that reason.
    fn check(&self, before: &SafeSnapshot, after: &SafeSnapshot) -> Result<(), String>;
}

/// Keeps every Safe's owners, threshold and implementation as they are, and
/// refuses owner key rotation: for a host whose Safes an off-chain service
/// ties to their current owner.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixedOwners;

impl SafePolicy for FixedOwners {
    fn name(&self) -> &'static str {
        "fixed owners"
    }

    fn allows_rotation(&self) -> bool {
        false
    }

    fn check(&self, before: &SafeSnapshot, after: &SafeSnapshot) -> Result<(), String> {
        if after.owners != before.owners {
            return Err(format!(
                "it changes the owners from {:?} to {:?}",
                before.owners, after.owners
            ));
        }
        if after.threshold != before.threshold {
            return Err(format!(
                "it changes the threshold from {} to {}",
                before.threshold, after.threshold
            ));
        }
        if after.singleton != before.singleton {
            return Err(format!(
                "it changes the implementation from {} to {}",
                before.singleton, after.singleton
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(owners: &[u8], threshold: u64, singleton: u8) -> SafeSnapshot {
        SafeSnapshot {
            safe: Address::repeat_byte(0xAA),
            owners: owners.iter().map(|b| Address::repeat_byte(*b)).collect(),
            threshold: U256::from(threshold),
            singleton: Address::repeat_byte(singleton),
        }
    }

    #[test]
    fn fixed_owners_refuses_owner_threshold_and_implementation_changes() {
        let before = snapshot(&[1], 1, 9);
        FixedOwners.check(&before, &before).unwrap();
        for after in [
            snapshot(&[2], 1, 9),
            snapshot(&[1, 2], 1, 9),
            snapshot(&[1], 2, 9),
            snapshot(&[1], 1, 8),
        ] {
            assert!(FixedOwners.check(&before, &after).is_err(), "{after:?}");
        }
        assert!(!FixedOwners.allows_rotation());
    }
}
