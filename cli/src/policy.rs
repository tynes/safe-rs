//! Rules a host CLI holds every Safe transaction to.
//!
//! A host sets a [`SafePolicy`] on [`RunConfig`](crate::RunConfig) or
//! [`SendContext`](crate::SendContext). Before a Safe transaction leaves the
//! machine (broadcast, `--approve-hash`, a bundle, `--sign-only` or
//! `--no-submit`), the CLI calls the policy's [`check`](SafePolicy::check),
//! then its [`check_async`](SafePolicy::check_async), with everything it
//! planned: the options, the calls, the Safe transaction, and the Safe before
//! and (when simulated) after. If either returns `false`, the CLI stops with
//! [`SendError::PolicyRefused`](crate::SendError::PolicyRefused).
//!
//! The CLI draws no conclusions of its own: what a policy allows is up to the
//! host. Without a policy, none of this runs.

use std::future::Future;
use std::pin::Pin;

use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;
use safe_rs::{Call, ForkSession, ISafe, PreparedSafeTx, RotationPlan, SafeState};
use url::Url;

use crate::cli::SendOpts;

/// A boxed future, for [`SafePolicy::check_async`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The Safe's owners, threshold and implementation, as a policy sees them
/// after the transaction.
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

    /// The same parts of `state`.
    pub fn of(state: &SafeState) -> Self {
        Self::new(
            state.address,
            state.owners.clone(),
            state.threshold,
            state.singleton,
        )
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
        Ok(Self::new(
            safe,
            owners,
            threshold,
            Address::from_slice(&slot0[12..]),
        ))
    }
}

/// What the Safe transaction was planned from.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Plan<'a> {
    /// `send` (and `safe config`, which plans its calls and sends them):
    /// the options it was run with
    Send(&'a SendOpts),
    /// `safe rotate` and `send --rotate`: the owner swaps appended to the
    /// calls, and the owners the Safe must have afterwards
    Rotation(&'a RotationPlan),
}

/// Everything the CLI planned for one Safe transaction.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SafeTxCheck<'a> {
    pub rpc_url: &'a Url,
    pub chain_id: u64,
    /// What the transaction was planned from
    pub plan: Plan<'a>,
    /// The calls asked for, before any the plan adds (such as owner swaps)
    pub calls: &'a [Call],
    /// The Safe transaction to be signed or sent
    pub prepared: &'a PreparedSafeTx,
    /// The Safe as the transaction was planned against
    pub before: &'a SafeState,
    /// The Safe after the simulated transaction. `None` with
    /// `--skip-simulation`. For a rotation, the owners its plan must leave
    /// (the rotation is checked against them on-chain too).
    pub after: Option<&'a SafeSnapshot>,
}

/// What a host requires of its Safe transactions. Both checks default to
/// allowing everything; implement either or both.
pub trait SafePolicy: Send + Sync {
    /// A short name for error messages, such as "polymarket".
    fn name(&self) -> &str;

    /// `false` stops the transaction.
    fn check(&self, tx: &SafeTxCheck<'_>) -> bool {
        let _ = tx;
        true
    }

    /// `false` stops the transaction. Runs after [`check`](Self::check)
    /// passes, for a policy that needs to look something up.
    fn check_async<'a>(&'a self, tx: &'a SafeTxCheck<'a>) -> BoxFuture<'a, bool> {
        let _ = tx;
        Box::pin(async { true })
    }
}

impl<P: SafePolicy + ?Sized> SafePolicy for Box<P> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn check(&self, tx: &SafeTxCheck<'_>) -> bool {
        (**self).check(tx)
    }

    fn check_async<'a>(&'a self, tx: &'a SafeTxCheck<'a>) -> BoxFuture<'a, bool> {
        (**self).check_async(tx)
    }
}

/// Runs both checks of `policy`.
pub(crate) async fn enforce(
    policy: &dyn SafePolicy,
    tx: &SafeTxCheck<'_>,
) -> Result<(), crate::SendError> {
    if policy.check(tx) && policy.check_async(tx).await {
        Ok(())
    } else {
        Err(crate::SendError::PolicyRefused {
            policy: policy.name().to_string(),
        })
    }
}
