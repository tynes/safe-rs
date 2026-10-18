//! Planning owner swaps and the Safe transaction that carries them.
//!
//! Nothing here holds key material or talks to the network. A plan is built
//! from a block-pinned [`SafeState`] and is checked against the simulated
//! post-state with `check_post_state` (the `simulation` feature) before
//! anything is broadcast.

use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;

use crate::contracts::ISafe;
use crate::envelope::{PreparedSafeTx, SafeTxGasPolicy};
use crate::error::{Error, Result};
use crate::inspect::{prev_in_list, SafeState, SENTINEL};
#[cfg(feature = "simulation")]
use crate::simulation::ForkSession;
use crate::types::Call;

/// The Safe versions rotation supports.
///
/// In both, `swapOwner` keeps the owner's place in the list, the owner and
/// execution events are indexed (which the outcome and history decoding rely
/// on), and with `safeTxGas = 0` and no refund a failing inner call reverts the
/// whole transaction without using the Safe nonce. They differ in what that
/// revert carries: v1.4.1 reverts with `GS013`, v1.5.0 with the inner call's
/// own revert data.
pub const SUPPORTED_VERSIONS: [&str; 2] = ["1.4.1", "1.5.0"];

/// The entry before `owner` in the Safe's owner linked list.
///
/// `owners` must be in list order, as `getOwners()` returns it. The first owner
/// is preceded by [`SENTINEL`].
pub fn prev_owner(owners: &[Address], owner: Address) -> Result<Address> {
    prev_in_list(owners, owner).ok_or_else(|| Error::Rotation(format!("{owner} is not an owner")))
}

/// One `swapOwner(prevOwner, oldOwner, newOwner)` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerSwap {
    /// The list entry pointing at `old_owner`
    pub prev_owner: Address,
    /// The owner being removed
    pub old_owner: Address,
    /// The owner taking its place in the list
    pub new_owner: Address,
}

impl OwnerSwap {
    /// Plans the swap of `old_owner` for `new_owner` against `owners` (in list
    /// order), applying the same checks as the Safe (`GS203`, `GS204`).
    pub fn plan(
        owners: &[Address],
        safe: Address,
        old_owner: Address,
        new_owner: Address,
    ) -> Result<Self> {
        if new_owner == Address::ZERO || new_owner == SENTINEL || new_owner == safe {
            return Err(Error::Rotation(format!(
                "{new_owner} cannot be a Safe owner"
            )));
        }
        if owners.contains(&new_owner) {
            return Err(Error::Rotation(format!("{new_owner} is already an owner")));
        }
        Ok(Self {
            prev_owner: prev_owner(owners, old_owner)?,
            old_owner,
            new_owner,
        })
    }

    /// The Safe self-call that performs the swap.
    pub fn call(&self, safe: Address) -> Call {
        let data = ISafe::swapOwnerCall {
            prevOwner: self.prev_owner,
            oldOwner: self.old_owner,
            newOwner: self.new_owner,
        }
        .abi_encode();
        Call::call(safe, data)
    }

    fn apply(&self, owners: &mut [Address]) {
        if let Some(slot) = owners.iter_mut().find(|o| **o == self.old_owner) {
            *slot = self.new_owner;
        }
    }
}

/// Plans several `(old, new)` swaps executed in order within one transaction.
///
/// Each swap is planned against the list as the previous swaps leave it, so
/// two adjacent owners rotating together get the right `prevOwner`.
pub fn plan_swaps(
    owners: &[Address],
    safe: Address,
    swaps: &[(Address, Address)],
) -> Result<Vec<OwnerSwap>> {
    let mut current = owners.to_vec();
    let mut planned = Vec::with_capacity(swaps.len());
    for (old_owner, new_owner) in swaps {
        let swap = OwnerSwap::plan(&current, safe, *old_owner, *new_owner)?;
        swap.apply(&mut current);
        planned.push(swap);
    }
    Ok(planned)
}

/// The owner list after `swaps` run in order: positions are preserved.
pub fn expected_owners_after(owners: &[Address], swaps: &[OwnerSwap]) -> Vec<Address> {
    let mut current = owners.to_vec();
    for swap in swaps {
        swap.apply(&mut current);
    }
    current
}

/// A frozen Safe transaction that runs the user's calls and then rotates owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPlan {
    /// Owners at the block the plan was built from, in list order
    pub pre_owners: Vec<Address>,
    /// Owners the Safe must have after the transaction
    pub expected_owners: Vec<Address>,
    /// Threshold, which the transaction must leave unchanged
    pub threshold: U256,
    /// The swaps appended after the user's calls
    pub swaps: Vec<OwnerSwap>,
    /// The Safe transaction to sign
    pub prepared: PreparedSafeTx,
}

impl RotationPlan {
    /// The Safe the plan is for.
    pub fn safe(&self) -> Address {
        self.prepared.safe
    }
}

fn is_owner_management(data: &[u8]) -> bool {
    let Some(selector) = data.get(..4) else {
        return false;
    };
    selector == ISafe::addOwnerWithThresholdCall::SELECTOR
        || selector == ISafe::removeOwnerCall::SELECTOR
        || selector == ISafe::swapOwnerCall::SELECTOR
        || selector == ISafe::changeThresholdCall::SELECTOR
}

/// Builds the Safe transaction `user_calls ++ swapOwner…` at the nonce in `state`.
///
/// The transaction is fail-closed (`safeTxGas = 0`, no refund), so it either
/// executes every call and every swap or reverts as a whole. Two or more calls
/// go through `MultiSendCallOnly`; a rotation without user calls and with a
/// single swap is a direct self-call.
///
/// Rejected up front: a Safe whose version is not in [`SUPPORTED_VERSIONS`] or
/// whose threshold is 0, an empty swap list, DelegateCall entries, and user
/// calls that change the Safe's owners or threshold themselves.
pub fn plan_rotation(
    state: &SafeState,
    chain_id: u64,
    multi_send_call_only: Address,
    user_calls: &[Call],
    swaps: &[(Address, Address)],
) -> Result<RotationPlan> {
    let safe = state.address;
    let supported = state
        .version
        .as_deref()
        .is_some_and(|version| SUPPORTED_VERSIONS.contains(&version));
    if !supported {
        return Err(Error::Rotation(format!(
            "owner rotation needs Safe v{}, found {}",
            SUPPORTED_VERSIONS.join(" or v"),
            state.version.as_deref().unwrap_or("an unknown version")
        )));
    }
    if state.threshold.is_zero() {
        return Err(Error::InvalidThreshold { threshold: 0 });
    }
    if swaps.is_empty() {
        return Err(Error::Rotation("no owner swap requested".to_string()));
    }
    if let Some(index) = user_calls
        .iter()
        .position(|c| c.to == safe && is_owner_management(&c.data))
    {
        return Err(Error::Rotation(format!(
            "call {index} changes the Safe's owners or threshold; \
             it cannot be combined with an owner rotation"
        )));
    }

    let swaps = plan_swaps(&state.owners, safe, swaps)?;
    let mut calls = user_calls.to_vec();
    calls.extend(swaps.iter().map(|swap| swap.call(safe)));
    let prepared = PreparedSafeTx::call_only_batch(
        chain_id,
        safe,
        multi_send_call_only,
        &calls,
        state.nonce,
        SafeTxGasPolicy::Zero,
    )?;

    Ok(RotationPlan {
        expected_owners: expected_owners_after(&state.owners, &swaps),
        pre_owners: state.owners.clone(),
        threshold: state.threshold,
        swaps,
        prepared,
    })
}

#[cfg(feature = "simulation")]
fn read<C: SolCall>(post: &mut ForkSession, safe: Address, call: &C) -> Result<C::Return> {
    let out = post.call(Address::ZERO, safe, call.abi_encode().into())?;
    C::abi_decode_returns(&out).map_err(|e| Error::Abi(e.to_string()))
}

/// Checks the Safe in `post` (a session the plan's transaction was committed
/// to) against the plan: owners are exactly the expected list, the threshold is
/// unchanged and the nonce advanced by one.
///
/// This is the guard against anything in the batch that touches owner
/// configuration, and against a batch target with no code (a DELEGATECALL to
/// it succeeds and changes nothing).
#[cfg(feature = "simulation")]
pub fn check_post_state(post: &mut ForkSession, plan: &RotationPlan) -> Result<()> {
    let safe = plan.safe();
    let owners = read(post, safe, &ISafe::getOwnersCall {})?;
    if owners != plan.expected_owners {
        return Err(Error::Rotation(format!(
            "simulated owners {owners:?} differ from the planned {:?}",
            plan.expected_owners
        )));
    }
    let threshold = read(post, safe, &ISafe::getThresholdCall {})?;
    if threshold != plan.threshold {
        return Err(Error::Rotation(format!(
            "simulated threshold {threshold} differs from {}",
            plan.threshold
        )));
    }
    let nonce = read(post, safe, &ISafe::nonceCall {})?;
    let expected = plan.prepared.params.nonce + U256::from(1);
    if nonce != expected {
        return Err(Error::Rotation(format!(
            "simulated Safe nonce {nonce} differs from {expected}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::ModuleList;
    use crate::types::Operation;
    use alloy::eips::BlockId;
    use alloy::primitives::{address, Bytes, B256};

    const SAFE: Address = address!("0x00000000000000000000000000000000000005AF");
    const MSCO: Address = address!("0x9641d764fc13c8B624c04430C7356C1C7C8102e2");

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn state(owners: &[Address]) -> SafeState {
        SafeState {
            address: SAFE,
            code_hash: B256::ZERO,
            singleton: Address::ZERO,
            version: Some("1.4.1".to_string()),
            owners: owners.to_vec(),
            threshold: U256::from(1),
            nonce: U256::from(7),
            modules: ModuleList {
                modules: Vec::new(),
                complete: true,
            },
            guard: Address::ZERO,
            fallback_handler: Address::ZERO,
            module_guard: None,
            block: BlockId::latest(),
        }
    }

    #[test]
    fn prev_owner_follows_list_order() {
        let owners = [addr(0xA), addr(0xB), addr(0xC)];
        assert_eq!(prev_owner(&owners, addr(0xA)).unwrap(), SENTINEL);
        assert_eq!(prev_owner(&owners, addr(0xB)).unwrap(), addr(0xA));
        assert_eq!(prev_owner(&owners, addr(0xC)).unwrap(), addr(0xB));
        assert!(matches!(
            prev_owner(&owners, addr(0xD)),
            Err(Error::Rotation(_))
        ));
    }

    #[test]
    fn swap_rejects_invalid_new_owners() {
        let owners = [addr(0xA), addr(0xB)];
        for bad in [Address::ZERO, SENTINEL, SAFE, addr(0xB)] {
            assert!(
                OwnerSwap::plan(&owners, SAFE, addr(0xA), bad).is_err(),
                "{bad} must be rejected"
            );
        }
        assert!(OwnerSwap::plan(&owners, SAFE, addr(0xD), addr(0xE)).is_err());
    }

    #[test]
    fn adjacent_swaps_use_the_updated_list() {
        let owners = [addr(0xA), addr(0xB), addr(0xC)];
        let swaps = plan_swaps(
            &owners,
            SAFE,
            &[(addr(0xA), addr(0x1A)), (addr(0xB), addr(0x1B))],
        )
        .unwrap();
        assert_eq!(swaps[0].prev_owner, SENTINEL);
        assert_eq!(
            swaps[1].prev_owner,
            addr(0x1A),
            "the second swap follows the first swap's new owner"
        );
        assert_eq!(
            expected_owners_after(&owners, &swaps),
            vec![addr(0x1A), addr(0x1B), addr(0xC)]
        );
    }

    #[test]
    fn a_new_owner_cannot_be_reused_within_one_plan() {
        let owners = [addr(0xA), addr(0xB)];
        let result = plan_swaps(
            &owners,
            SAFE,
            &[(addr(0xA), addr(0xE)), (addr(0xB), addr(0xE))],
        );
        assert!(result.is_err());
    }

    #[test]
    fn rotation_only_is_a_direct_self_call() {
        let plan = plan_rotation(
            &state(&[addr(0xA)]),
            1,
            MSCO,
            &[],
            &[(addr(0xA), addr(0xB))],
        )
        .unwrap();
        let params = &plan.prepared.params;
        assert_eq!(params.to, SAFE);
        assert_eq!(params.operation, Operation::Call);
        assert_eq!(params.nonce, U256::from(7));
        assert!(plan.prepared.is_fail_closed());
        assert_eq!(plan.expected_owners, vec![addr(0xB)]);
    }

    #[test]
    fn user_calls_and_swap_go_through_multi_send_call_only() {
        let user = [Call::new(addr(0x42), U256::from(1), Bytes::new())];
        let plan = plan_rotation(
            &state(&[addr(0xA)]),
            1,
            MSCO,
            &user,
            &[(addr(0xA), addr(0xB))],
        )
        .unwrap();
        assert_eq!(plan.prepared.params.to, MSCO);
        assert_eq!(plan.prepared.params.operation, Operation::DelegateCall);
    }

    #[test]
    fn unsupported_safes_and_batches_are_rejected() {
        let swap = [(addr(0xA), addr(0xB))];

        for unsupported in [Some("1.3.0"), Some("1.6.0"), None] {
            let mut other = state(&[addr(0xA)]);
            other.version = unsupported.map(str::to_string);
            let refused = plan_rotation(&other, 1, MSCO, &[], &swap);
            let Err(Error::Rotation(message)) = refused else {
                panic!("{unsupported:?} must be refused, got {refused:?}")
            };
            assert!(message.contains("v1.4.1 or v1.5.0"), "{message}");
        }
        for supported in SUPPORTED_VERSIONS {
            let mut safe = state(&[addr(0xA)]);
            safe.version = Some(supported.to_string());
            assert!(
                plan_rotation(&safe, 1, MSCO, &[], &swap).is_ok(),
                "{supported}"
            );
        }

        let mut multisig = state(&[addr(0xA), addr(0xC)]);
        multisig.threshold = U256::from(2);
        let plan = plan_rotation(&multisig, 1, MSCO, &[], &swap).unwrap();
        assert_eq!(plan.expected_owners, vec![addr(0xB), addr(0xC)]);
        assert_eq!(plan.threshold, U256::from(2));

        assert!(plan_rotation(&state(&[addr(0xA)]), 1, MSCO, &[], &[]).is_err());

        let delegate = [Call::delegate_call(addr(0x42), Bytes::new())];
        assert!(matches!(
            plan_rotation(&state(&[addr(0xA)]), 1, MSCO, &delegate, &swap),
            Err(Error::DelegateCallNotAllowed { index: 0 })
        ));

        let add_owner = ISafe::addOwnerWithThresholdCall {
            owner: addr(0xC),
            _threshold: U256::from(1),
        }
        .abi_encode();
        let touches_owners = [Call::call(SAFE, add_owner)];
        assert!(matches!(
            plan_rotation(&state(&[addr(0xA)]), 1, MSCO, &touches_owners, &swap),
            Err(Error::Rotation(_))
        ));
    }
}
