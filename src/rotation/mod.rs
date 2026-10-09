//! One-time owner keys: rotating a Safe owner as part of every transaction.
//!
//! Each Safe transaction is the caller's calls followed by
//! `swapOwner(prev, current, next)`, so the key that signed is no longer an
//! owner by the time its signature (and with it its public key) is on chain.
//!
//! This module holds the parts with no key material: planning the swap
//! ([`plan`]).

pub mod plan;

pub use plan::{
    check_post_state, expected_owners_after, plan_rotation, plan_swaps, prev_owner, OwnerSwap,
    RotationPlan,
};
