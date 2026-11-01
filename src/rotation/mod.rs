//! One-time owner keys: rotating a Safe owner as part of every transaction.
//!
//! Each Safe transaction is the caller's calls followed by
//! `swapOwner(prev, current, next)`, so the key that signed is no longer an
//! owner by the time its signature (and with it its public key) is on chain.
//!
//! [`plan`], [`state`], [`store`] and [`history`] hold no key material:
//! planning the swap, the record of which keys are used, its file on disk, and
//! the Safe's owner changes read from its logs. With the
//! `hd-wallet` feature, `keys` adds where owner keys come from and
//! `safe` adds `RotatingSafe`, which drives the whole flow.

pub mod history;
#[cfg(feature = "hd-wallet")]
pub mod keys;
pub mod plan;
#[cfg(feature = "hd-wallet")]
pub mod safe;
pub mod state;
pub mod store;

pub use history::{owner_history, OwnerEvent, OwnerEventKind};
#[cfg(feature = "hd-wallet")]
pub use keys::{KeySource, Keyring, DEFAULT_SCAN_LIMIT, SEND_LOOKAHEAD, SETUP_LOOKAHEAD};
#[cfg(feature = "simulation")]
pub use plan::check_post_state;
pub use plan::{
    expected_owners_after, plan_rotation, plan_swaps, prev_owner, OwnerSwap, RotationPlan,
};
#[cfg(feature = "hd-wallet")]
pub use safe::{
    ExecOptions, Payer, PlannedSweep, RotatingSafe, RotationConfig, RotationOutcome,
    RotationStatus, RotationTx, SweepOutcome, SweepReport, SyncReport, REBUILD_MARGIN,
};
pub use state::{
    binding_key, Binding, CreationParams, Exposure, Observation, OwnerRef, PendingTx, Reserved,
    Retired, RotationState, SignedSweep, SweepDue, Swept,
};
pub use store::StateFile;
