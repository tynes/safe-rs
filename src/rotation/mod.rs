//! One-time owner keys: rotating a Safe owner as part of every transaction.
//!
//! Each Safe transaction is the caller's calls followed by
//! `swapOwner(prev, current, next)`, so the key that signed is no longer an
//! owner by the time its signature (and with it its public key) is on chain.
//!
//! This module holds the parts with no key material: planning the swap
//! ([`plan`]), the record of which keys are used ([`state`]) and its file on
//! disk ([`store`]).

pub mod plan;
pub mod state;
pub mod store;

pub use plan::{
    check_post_state, expected_owners_after, plan_rotation, plan_swaps, prev_owner, OwnerSwap,
    RotationPlan,
};
pub use state::{
    binding_key, Binding, CreationParams, Exposure, Observation, OwnerRef, PendingTx, Reserved,
    Retired, RotationState, SignedSweep, SweepDue, Swept,
};
pub use store::StateFile;
