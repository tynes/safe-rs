//! Planning changes to a Safe's own configuration: owners, threshold,
//! modules, guards and fallback handler.
//!
//! Nothing here holds key material or talks to the network. [`plan_config`]
//! turns a set of requested changes and a block-pinned [`SafeState`] into the
//! Safe self-calls that make them, in one transaction, and the configuration
//! the Safe must have afterwards. With the `simulation` feature,
//! [`check_config_post_state`] compares a simulated post-state against it.
//!
//! The owner and module lists are linked lists, and every removal names the
//! entry before the one removed. The planner applies each call to a local
//! model of both lists, so a `prevOwner` or `prevModule` is right even when an
//! earlier call in the same transaction moved it.

use std::collections::HashSet;
use std::fmt;

use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;

use crate::contracts::ISafe;
#[cfg(feature = "simulation")]
use crate::envelope::{PreparedSafeTx, SafeTxGasPolicy, SignedSafeTx};
use crate::error::{Error, Result};
use crate::inspect::{has_module_guard, prev_in_list, SafeState, SENTINEL};
#[cfg(feature = "simulation")]
use crate::inspect::{
    FALLBACK_HANDLER_STORAGE_SLOT, GUARD_STORAGE_SLOT, MODULE_GUARD_STORAGE_SLOT,
};
#[cfg(feature = "simulation")]
use crate::simulation::{ForkSession, SimTx, SimulationResult, READ_CALL_GAS};
use crate::types::Call;

/// The configuration changes requested in one Safe transaction.
///
/// For `guard`, `fallback_handler` and `module_guard`, `Some(Address::ZERO)`
/// clears the setting and `None` leaves it alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigChanges {
    /// Owners to add
    pub add_owners: Vec<Address>,
    /// Owners to remove
    pub remove_owners: Vec<Address>,
    /// `(old, new)` owners to swap; the new owner takes the old one's place
    pub swap_owners: Vec<(Address, Address)>,
    /// Threshold after the transaction (default: unchanged)
    pub threshold: Option<U256>,
    /// Modules to enable
    pub enable_modules: Vec<Address>,
    /// Modules to disable
    pub disable_modules: Vec<Address>,
    /// New transaction guard
    pub guard: Option<Address>,
    /// New fallback handler
    pub fallback_handler: Option<Address>,
    /// New module guard (Safe v1.5.0)
    pub module_guard: Option<Address>,
}

impl ConfigChanges {
    /// Returns true if no change is requested.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// One Safe self-call that changes its configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigOp {
    /// `swapOwner(prevOwner, oldOwner, newOwner)`
    SwapOwner {
        prev_owner: Address,
        old_owner: Address,
        new_owner: Address,
    },
    /// `addOwnerWithThreshold(owner, threshold)`
    AddOwner { owner: Address, threshold: U256 },
    /// `removeOwner(prevOwner, owner, threshold)`
    RemoveOwner {
        prev_owner: Address,
        owner: Address,
        threshold: U256,
    },
    /// `changeThreshold(threshold)`
    ChangeThreshold { threshold: U256 },
    /// `enableModule(module)`
    EnableModule { module: Address },
    /// `disableModule(prevModule, module)`
    DisableModule {
        prev_module: Address,
        module: Address,
    },
    /// `setFallbackHandler(handler)`
    SetFallbackHandler { handler: Address },
    /// `setModuleGuard(moduleGuard)`
    SetModuleGuard { module_guard: Address },
    /// `setGuard(guard)`
    SetGuard { guard: Address },
}

impl ConfigOp {
    /// The calldata of the self-call.
    pub fn calldata(&self) -> Vec<u8> {
        match *self {
            Self::SwapOwner {
                prev_owner,
                old_owner,
                new_owner,
            } => ISafe::swapOwnerCall {
                prevOwner: prev_owner,
                oldOwner: old_owner,
                newOwner: new_owner,
            }
            .abi_encode(),
            Self::AddOwner { owner, threshold } => ISafe::addOwnerWithThresholdCall {
                owner,
                _threshold: threshold,
            }
            .abi_encode(),
            Self::RemoveOwner {
                prev_owner,
                owner,
                threshold,
            } => ISafe::removeOwnerCall {
                prevOwner: prev_owner,
                owner,
                _threshold: threshold,
            }
            .abi_encode(),
            Self::ChangeThreshold { threshold } => ISafe::changeThresholdCall {
                _threshold: threshold,
            }
            .abi_encode(),
            Self::EnableModule { module } => ISafe::enableModuleCall { module }.abi_encode(),
            Self::DisableModule {
                prev_module,
                module,
            } => ISafe::disableModuleCall {
                prevModule: prev_module,
                module,
            }
            .abi_encode(),
            Self::SetFallbackHandler { handler } => {
                ISafe::setFallbackHandlerCall { handler }.abi_encode()
            }
            Self::SetModuleGuard { module_guard } => ISafe::setModuleGuardCall {
                moduleGuard: module_guard,
            }
            .abi_encode(),
            Self::SetGuard { guard } => ISafe::setGuardCall { guard }.abi_encode(),
        }
    }

    /// The self-call on `safe`.
    pub fn call(&self, safe: Address) -> Call {
        Call::call(safe, self.calldata())
    }
}

fn or_none(address: Address) -> String {
    if address == Address::ZERO {
        "none".to_string()
    } else {
        address.to_string()
    }
}

impl fmt::Display for ConfigOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SwapOwner {
                old_owner,
                new_owner,
                ..
            } => write!(f, "swap owner {old_owner} -> {new_owner}"),
            Self::AddOwner { owner, threshold } => {
                write!(f, "add owner {owner} (threshold {threshold})")
            }
            Self::RemoveOwner {
                owner, threshold, ..
            } => write!(f, "remove owner {owner} (threshold {threshold})"),
            Self::ChangeThreshold { threshold } => write!(f, "change threshold to {threshold}"),
            Self::EnableModule { module } => write!(f, "enable module {module}"),
            Self::DisableModule { module, .. } => write!(f, "disable module {module}"),
            Self::SetFallbackHandler { handler } => {
                write!(f, "set fallback handler to {}", or_none(handler))
            }
            Self::SetModuleGuard { module_guard } => {
                write!(f, "set module guard to {}", or_none(module_guard))
            }
            Self::SetGuard { guard } => write!(f, "set guard to {}", or_none(guard)),
        }
    }
}

/// The configuration a Safe must have after a planned transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedConfig {
    /// Owners, in list order
    pub owners: Vec<Address>,
    /// Signature threshold
    pub threshold: U256,
    /// Enabled modules, in list order; `None` if the list could not be read
    /// completely and no module change was requested
    pub modules: Option<Vec<Address>>,
    /// Transaction guard
    pub guard: Address,
    /// Fallback handler
    pub fallback_handler: Address,
    /// Module guard; `None` for versions without one
    pub module_guard: Option<Address>,
}

/// The self-calls for a [`ConfigChanges`] and the configuration they lead to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPlan {
    /// The Safe the plan is for
    pub safe: Address,
    /// Self-calls, in execution order
    pub ops: Vec<ConfigOp>,
    /// Configuration before the transaction
    pub before: ExpectedConfig,
    /// Configuration after the transaction
    pub after: ExpectedConfig,
}

impl ConfigPlan {
    /// The calls of the Safe transaction, in execution order.
    pub fn calls(&self) -> Vec<Call> {
        self.ops.iter().map(|op| op.call(self.safe)).collect()
    }
}

fn config_err(message: impl Into<String>) -> Error {
    Error::Config(message.into())
}

/// Rejects an address the Safe will not accept as an owner (`GS203`) or module
/// (`GS101`); the Safe itself is refused for both.
fn check_new_entry(what: &str, address: Address, safe: Address) -> Result<()> {
    if address == Address::ZERO || address == SENTINEL || address == safe {
        return Err(config_err(format!("{address} cannot be a Safe {what}")));
    }
    Ok(())
}

/// Plans the self-calls that apply `changes` to the Safe in `state`.
///
/// The calls run in this order, whatever the order of the request:
///
/// 1. owner swaps
/// 2. owner additions
/// 3. owner removals
/// 4. `changeThreshold`, only when no addition or removal set the threshold
/// 5. module enables
/// 6. module disables
/// 7. fallback handler
/// 8. module guard
/// 9. transaction guard, last, so a new guard sees no call of this
///    transaction before its own installation
///
/// Each addition and removal passes `min(final threshold, owner count after
/// it)` as its threshold, which the Safe accepts at every step and which ends
/// at the final threshold.
///
/// The threshold is never lowered implicitly: without `changes.threshold` it
/// stays at its current value, and a change that leaves fewer owners than that
/// is rejected.
///
/// Also rejected: an empty or no-op request, an address named twice, adding an
/// existing owner, removing or swapping out an address that is not an owner,
/// enabling an enabled module, disabling one that is not enabled, any module
/// change when the module list could not be read completely, and a module
/// guard on a Safe version without one.
pub fn plan_config(state: &SafeState, changes: &ConfigChanges) -> Result<ConfigPlan> {
    let safe = state.address;
    if state.threshold.is_zero() || state.owners.is_empty() {
        return Err(config_err(format!(
            "Safe {safe} is not set up (threshold {}, {} owners)",
            state.threshold,
            state.owners.len()
        )));
    }

    let mut seen = HashSet::new();
    let owner_addresses = changes
        .add_owners
        .iter()
        .chain(&changes.remove_owners)
        .chain(changes.swap_owners.iter().flat_map(|(old, new)| [old, new]));
    for address in owner_addresses {
        if !seen.insert(*address) {
            return Err(config_err(format!(
                "{address} is named in more than one owner change"
            )));
        }
    }
    let mut seen = HashSet::new();
    for address in changes
        .enable_modules
        .iter()
        .chain(&changes.disable_modules)
    {
        if !seen.insert(*address) {
            return Err(config_err(format!(
                "{address} is named in more than one module change"
            )));
        }
    }

    let modules_change = !changes.enable_modules.is_empty() || !changes.disable_modules.is_empty();
    if modules_change && !state.modules.complete {
        return Err(config_err(
            "the Safe's module list could not be read completely, so modules cannot be changed",
        ));
    }
    if changes.module_guard.is_some() && !has_module_guard(state.version.as_deref()) {
        return Err(config_err(format!(
            "a module guard needs Safe v1.5.0, found {}",
            state.version.as_deref().unwrap_or("an unknown version")
        )));
    }

    let before = ExpectedConfig {
        owners: state.owners.clone(),
        threshold: state.threshold,
        modules: state
            .modules
            .complete
            .then(|| state.modules.modules.clone()),
        guard: state.guard,
        fallback_handler: state.fallback_handler,
        module_guard: state.module_guard,
    };

    let threshold = changes.threshold.unwrap_or(state.threshold);
    if threshold.is_zero() {
        return Err(config_err("the threshold must be at least 1"));
    }

    let mut ops = Vec::new();
    let mut owners = state.owners.clone();

    for &(old_owner, new_owner) in &changes.swap_owners {
        check_new_entry("owner", new_owner, safe)?;
        if owners.contains(&new_owner) {
            return Err(config_err(format!("{new_owner} is already an owner")));
        }
        let prev_owner = prev_in_list(&owners, old_owner)
            .ok_or_else(|| config_err(format!("{old_owner} is not an owner")))?;
        if let Some(slot) = owners.iter_mut().find(|o| **o == old_owner) {
            *slot = new_owner;
        }
        ops.push(ConfigOp::SwapOwner {
            prev_owner,
            old_owner,
            new_owner,
        });
    }

    let mut threshold_set = false;
    for &owner in &changes.add_owners {
        check_new_entry("owner", owner, safe)?;
        if owners.contains(&owner) {
            return Err(config_err(format!("{owner} is already an owner")));
        }
        owners.insert(0, owner);
        ops.push(ConfigOp::AddOwner {
            owner,
            threshold: threshold.min(U256::from(owners.len())),
        });
        threshold_set = true;
    }

    for &owner in &changes.remove_owners {
        let prev_owner = prev_in_list(&owners, owner)
            .ok_or_else(|| config_err(format!("{owner} is not an owner")))?;
        owners.retain(|o| *o != owner);
        ops.push(ConfigOp::RemoveOwner {
            prev_owner,
            owner,
            threshold: threshold.min(U256::from(owners.len())),
        });
        threshold_set = true;
    }

    if threshold > U256::from(owners.len()) {
        let hint = if changes.threshold.is_none() {
            "; pass --threshold to lower it"
        } else {
            ""
        };
        return Err(config_err(format!(
            "threshold {threshold} is more than the {} owners the Safe would have{hint}",
            owners.len()
        )));
    }

    if !threshold_set && threshold != state.threshold {
        ops.push(ConfigOp::ChangeThreshold { threshold });
    }

    let mut modules = before.modules.clone();
    if modules_change {
        // Checked above: the list is complete when modules change.
        let list = modules.get_or_insert_with(Vec::new);
        for &module in &changes.enable_modules {
            check_new_entry("module", module, safe)?;
            if list.contains(&module) {
                return Err(config_err(format!("module {module} is already enabled")));
            }
            list.insert(0, module);
            ops.push(ConfigOp::EnableModule { module });
        }
        for &module in &changes.disable_modules {
            let prev_module = prev_in_list(list, module)
                .ok_or_else(|| config_err(format!("module {module} is not enabled")))?;
            list.retain(|m| *m != module);
            ops.push(ConfigOp::DisableModule {
                prev_module,
                module,
            });
        }
    }

    if let Some(handler) = changes.fallback_handler {
        if handler == safe {
            return Err(config_err("the Safe cannot be its own fallback handler"));
        }
        if handler == state.fallback_handler {
            return Err(config_err(format!(
                "the fallback handler is already {}",
                or_none(handler)
            )));
        }
        ops.push(ConfigOp::SetFallbackHandler { handler });
    }

    if let Some(module_guard) = changes.module_guard {
        if Some(module_guard) == state.module_guard {
            return Err(config_err(format!(
                "the module guard is already {}",
                or_none(module_guard)
            )));
        }
        ops.push(ConfigOp::SetModuleGuard { module_guard });
    }

    if let Some(guard) = changes.guard {
        if guard == state.guard {
            return Err(config_err(format!(
                "the guard is already {}",
                or_none(guard)
            )));
        }
        ops.push(ConfigOp::SetGuard { guard });
    }

    if ops.is_empty() {
        return Err(config_err("nothing to change"));
    }

    let after = ExpectedConfig {
        owners,
        threshold,
        modules,
        guard: changes.guard.unwrap_or(state.guard),
        fallback_handler: changes.fallback_handler.unwrap_or(state.fallback_handler),
        module_guard: changes.module_guard.or(state.module_guard),
    };

    Ok(ConfigPlan {
        safe,
        ops,
        before,
        after,
    })
}

#[cfg(feature = "simulation")]
fn read_slot(
    post: &mut ForkSession,
    safe: Address,
    slot: alloy::primitives::B256,
) -> Result<Address> {
    let word = post.call_sol(
        safe,
        &ISafe::getStorageAtCall {
            offset: slot.into(),
            length: U256::from(1),
        },
    )?;
    if word.len() != 32 {
        return Err(Error::Abi(format!(
            "getStorageAt returned {} bytes, expected 32",
            word.len()
        )));
    }
    Ok(Address::from_slice(&word[12..]))
}

/// Checks the Safe in `post` (a session the plan's transaction was committed
/// to) against `plan.after`: owners in the exact planned order, threshold,
/// modules, guard, fallback handler and module guard.
///
/// Comparing owners and modules in order also checks the planner's model of
/// the linked lists.
#[cfg(feature = "simulation")]
pub fn check_config_post_state(post: &mut ForkSession, plan: &ConfigPlan) -> Result<()> {
    let safe = plan.safe;
    let want = &plan.after;
    let mismatch = |what: &str, got: String, want: String| {
        config_err(format!(
            "simulated {what} {got} differs from the planned {want}"
        ))
    };

    let owners = post.call_sol(safe, &ISafe::getOwnersCall {})?;
    if owners != want.owners {
        return Err(mismatch(
            "owners",
            format!("{owners:?}"),
            format!("{:?}", want.owners),
        ));
    }
    let threshold = post.call_sol(safe, &ISafe::getThresholdCall {})?;
    if threshold != want.threshold {
        return Err(mismatch(
            "threshold",
            threshold.to_string(),
            want.threshold.to_string(),
        ));
    }
    if let Some(modules) = &want.modules {
        let page = post.call_sol(
            safe,
            &ISafe::getModulesPaginatedCall {
                start: SENTINEL,
                pageSize: U256::from(modules.len() + 1),
            },
        )?;
        if page.array != *modules {
            return Err(mismatch(
                "modules",
                format!("{:?}", page.array),
                format!("{modules:?}"),
            ));
        }
    }
    let guard = read_slot(post, safe, GUARD_STORAGE_SLOT)?;
    if guard != want.guard {
        return Err(mismatch("guard", or_none(guard), or_none(want.guard)));
    }
    let handler = read_slot(post, safe, FALLBACK_HANDLER_STORAGE_SLOT)?;
    if handler != want.fallback_handler {
        return Err(mismatch(
            "fallback handler",
            or_none(handler),
            or_none(want.fallback_handler),
        ));
    }
    if let Some(want_module_guard) = want.module_guard {
        let module_guard = read_slot(post, safe, MODULE_GUARD_STORAGE_SLOT)?;
        if module_guard != want_module_guard {
            return Err(mismatch(
                "module guard",
                or_none(module_guard),
                or_none(want_module_guard),
            ));
        }
    }
    Ok(())
}

/// Checks that a transaction guard or module guard that `plan` installs does
/// not reject every later transaction, on a checkpoint of `post` (a session the
/// plan's transaction was committed to).
///
/// The transaction that installs a guard is not checked by it, so the
/// simulation of that transaction says nothing about the guard. Here a trivial
/// follow-up runs through each new non-zero guard:
///
/// - transaction guard: a zero-value call from the Safe to itself at the next
///   nonce, through `execTransaction`, approved on-chain by `plan.after`'s
///   first `threshold` owners. A guard that rejects it would block every Safe
///   transaction, including the one that removes it, and lock the Safe.
/// - module guard (Safe v1.5.0): the same call through
///   `execTransactionFromModule`, sent by the first module enabled after the
///   plan. A module guard that rejects it stops every module, until the owners
///   replace it. Without an enabled module there is nothing to send it from,
///   and the module guard is not checked.
///
/// A rejected follow-up is an [`Error::Config`] with the reason.
#[cfg(feature = "simulation")]
pub fn check_new_guards_allow_followup(post: &ForkSession, plan: &ConfigPlan) -> Result<()> {
    let safe = plan.safe;
    let new_guard = plan
        .ops
        .iter()
        .any(|op| matches!(op, ConfigOp::SetGuard { guard } if *guard != Address::ZERO));
    if new_guard {
        let mut session = post.checkpoint();
        if let Some(reason) = followup_exec(&mut session, plan)? {
            return Err(config_err(format!(
                "the new guard {} rejects a later Safe transaction (a zero-value call from the \
                 Safe to itself at the next nonce): {reason}. Once installed, it would block \
                 every Safe transaction, including one that removes it, and lock the Safe",
                plan.after.guard
            )));
        }
    }

    let new_module_guard = plan.ops.iter().any(
        |op| matches!(op, ConfigOp::SetModuleGuard { module_guard } if *module_guard != Address::ZERO),
    );
    let module = plan
        .after
        .modules
        .as_ref()
        .and_then(|modules| modules.first().copied());
    if let (true, Some(module)) = (new_module_guard, module) {
        let mut session = post.checkpoint();
        if let Some(reason) = followup_module_exec(&mut session, safe, module)? {
            return Err(config_err(format!(
                "the new module guard {} rejects a module transaction (a zero-value call from \
                 the Safe to itself, sent by module {module}): {reason}. Once installed, no \
                 module could execute until the owners replace the module guard",
                or_none(plan.after.module_guard.unwrap_or_default())
            )));
        }
    }
    Ok(())
}

/// The revert reason of a failed follow-up, or `None` if it succeeded.
#[cfg(feature = "simulation")]
fn failure_reason(mut result: SimulationResult) -> Option<String> {
    result.apply_inner_revert_reason();
    (!result.success).then(|| {
        result
            .revert_reason
            .unwrap_or_else(|| "unknown reason".to_string())
    })
}

/// Runs a zero-value self-call through `execTransaction` at the Safe's
/// current nonce, approved by the planned owners.
#[cfg(feature = "simulation")]
fn followup_exec(session: &mut ForkSession, plan: &ConfigPlan) -> Result<Option<String>> {
    let safe = plan.safe;
    let nonce = session.call_sol(safe, &ISafe::nonceCall {})?;
    let prepared = PreparedSafeTx::single_call(
        session.chain_id(),
        safe,
        &Call::new(safe, U256::ZERO, alloy::primitives::Bytes::new()),
        nonce,
        SafeTxGasPolicy::Zero,
    )?;
    let owners = &plan.after.owners;
    let threshold = plan.after.threshold.saturating_to::<usize>();
    let Some(&sender) = owners.first() else {
        return Err(config_err("the planned Safe has no owners"));
    };

    let gas = session.max_tx_gas();
    let approve = SignedSafeTx::approve_hash_calldata(prepared.safe_tx_hash);
    for &owner in owners.iter().take(threshold) {
        let approved = session.transact_commit(SimTx::relaxed(
            owner,
            safe,
            U256::ZERO,
            approve.clone(),
            gas.min(READ_CALL_GAS),
        ))?;
        if let Some(reason) = failure_reason(approved) {
            return Ok(Some(format!(
                "approveHash by owner {owner} failed: {reason}"
            )));
        }
    }
    let signed = SignedSafeTx::empty(prepared.clone()).with_simulated_co_owners(owners, threshold);
    let mut result = session.transact(SimTx::relaxed(
        sender,
        safe,
        U256::ZERO,
        signed.exec_calldata(),
        gas,
    ))?;
    result.require_safe_success(safe, prepared.safe_tx_hash);
    Ok(failure_reason(result))
}

/// Runs a zero-value self-call through `execTransactionFromModule`, sent by
/// `module`.
#[cfg(feature = "simulation")]
fn followup_module_exec(
    session: &mut ForkSession,
    safe: Address,
    module: Address,
) -> Result<Option<String>> {
    let call = ISafe::execTransactionFromModuleCall {
        to: safe,
        value: U256::ZERO,
        data: alloy::primitives::Bytes::new(),
        operation: 0,
    };
    let gas = session.max_tx_gas();
    let result = session.transact(SimTx::relaxed(
        module,
        safe,
        U256::ZERO,
        call.abi_encode().into(),
        gas,
    ))?;
    let output = result.return_data.clone();
    if let Some(reason) = failure_reason(result) {
        return Ok(Some(reason));
    }
    let success = ISafe::execTransactionFromModuleCall::abi_decode_returns(&output)
        .map_err(|e| Error::Abi(e.to_string()))?;
    Ok((!success).then(|| "execTransactionFromModule returned false".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::ModuleList;
    use alloy::eips::BlockId;
    use alloy::primitives::{address, B256};

    const SAFE: Address = address!("0x00000000000000000000000000000000000005AF");
    const A: Address = address!("0x000000000000000000000000000000000000000a");
    const B: Address = address!("0x000000000000000000000000000000000000000b");
    const C: Address = address!("0x000000000000000000000000000000000000000c");
    const D: Address = address!("0x000000000000000000000000000000000000000d");
    const E: Address = address!("0x000000000000000000000000000000000000000e");
    const M1: Address = address!("0x00000000000000000000000000000000000000f1");
    const M2: Address = address!("0x00000000000000000000000000000000000000f2");
    const G: Address = address!("0x00000000000000000000000000000000000000aa");

    fn state(owners: &[Address], threshold: u64) -> SafeState {
        SafeState {
            address: SAFE,
            code_hash: B256::ZERO,
            singleton: Address::ZERO,
            version: Some("1.4.1".to_string()),
            owners: owners.to_vec(),
            threshold: U256::from(threshold),
            nonce: U256::ZERO,
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

    fn u(n: u64) -> U256 {
        U256::from(n)
    }

    fn err(state: &SafeState, changes: &ConfigChanges) -> String {
        plan_config(state, changes).unwrap_err().to_string()
    }

    #[test]
    fn add_owner_goes_to_the_head_and_keeps_the_threshold() {
        let plan = plan_config(
            &state(&[A, B], 2),
            &ConfigChanges {
                add_owners: vec![C],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            plan.ops,
            [ConfigOp::AddOwner {
                owner: C,
                threshold: u(2)
            }]
        );
        assert_eq!(plan.after.owners, [C, A, B]);
        assert_eq!(plan.after.threshold, u(2));
        assert_eq!(plan.calls().len(), 1);
        assert_eq!(plan.calls()[0].to, SAFE);
    }

    #[test]
    fn removes_name_the_previous_entry() {
        let s = state(&[A, B, C], 1);
        for (owner, prev, rest) in [
            (A, SENTINEL, vec![B, C]),
            (B, A, vec![A, C]),
            (C, B, vec![A, B]),
        ] {
            let plan = plan_config(
                &s,
                &ConfigChanges {
                    remove_owners: vec![owner],
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(
                plan.ops,
                [ConfigOp::RemoveOwner {
                    prev_owner: prev,
                    owner,
                    threshold: u(1)
                }]
            );
            assert_eq!(plan.after.owners, rest);
        }
    }

    #[test]
    fn removal_after_an_addition_points_at_the_new_head() {
        let plan = plan_config(
            &state(&[A, B], 1),
            &ConfigChanges {
                add_owners: vec![C],
                remove_owners: vec![A],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            plan.ops[1],
            ConfigOp::RemoveOwner {
                prev_owner: C,
                owner: A,
                threshold: u(1)
            }
        );
        assert_eq!(plan.after.owners, [C, B]);
    }

    #[test]
    fn swaps_run_first_and_keep_their_place() {
        let plan = plan_config(
            &state(&[A, B, C], 1),
            &ConfigChanges {
                remove_owners: vec![C],
                swap_owners: vec![(B, D)],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            plan.ops,
            [
                ConfigOp::SwapOwner {
                    prev_owner: A,
                    old_owner: B,
                    new_owner: D
                },
                ConfigOp::RemoveOwner {
                    prev_owner: D,
                    owner: C,
                    threshold: u(1)
                },
            ]
        );
        assert_eq!(plan.after.owners, [A, D]);
    }

    #[test]
    fn swap_alone_with_a_new_threshold_uses_change_threshold() {
        let plan = plan_config(
            &state(&[A, B], 1),
            &ConfigChanges {
                swap_owners: vec![(A, C)],
                threshold: Some(u(2)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(plan.ops[1], ConfigOp::ChangeThreshold { threshold: u(2) });
        assert_eq!(plan.after.threshold, u(2));
    }

    #[test]
    fn intermediate_thresholds_stay_valid_and_end_at_the_target() {
        // 1-of-1 to 3-of-3: the first addition cannot ask for 3 of 2 owners.
        let plan = plan_config(
            &state(&[A], 1),
            &ConfigChanges {
                add_owners: vec![B, C],
                threshold: Some(u(3)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            plan.ops,
            [
                ConfigOp::AddOwner {
                    owner: B,
                    threshold: u(2)
                },
                ConfigOp::AddOwner {
                    owner: C,
                    threshold: u(3)
                },
            ]
        );

        // 3-of-4 to 1-of-2: removals lower the threshold as they go.
        let plan = plan_config(
            &state(&[A, B, C, D], 3),
            &ConfigChanges {
                add_owners: vec![E],
                remove_owners: vec![A, B, C],
                threshold: Some(u(1)),
                ..Default::default()
            },
        )
        .unwrap();
        let thresholds: Vec<U256> =
            plan.ops
                .iter()
                .map(|op| match op {
                    ConfigOp::AddOwner { threshold, .. }
                    | ConfigOp::RemoveOwner { threshold, .. } => *threshold,
                    other => panic!("unexpected {other:?}"),
                })
                .collect();
        assert_eq!(thresholds, [u(1), u(1), u(1), u(1)]);
        assert_eq!(plan.after.owners, [E, D]);
    }

    #[test]
    fn threshold_only_change() {
        let plan = plan_config(
            &state(&[A, B], 1),
            &ConfigChanges {
                threshold: Some(u(2)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(plan.ops, [ConfigOp::ChangeThreshold { threshold: u(2) }]);
    }

    #[test]
    fn modules_are_modeled_like_owners() {
        let mut s = state(&[A], 1);
        s.modules.modules = vec![M1];
        let plan = plan_config(
            &s,
            &ConfigChanges {
                enable_modules: vec![M2],
                disable_modules: vec![M1],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            plan.ops,
            [
                ConfigOp::EnableModule { module: M2 },
                ConfigOp::DisableModule {
                    prev_module: M2,
                    module: M1
                },
            ]
        );
        assert_eq!(plan.after.modules, Some(vec![M2]));
    }

    #[test]
    fn settings_run_in_a_fixed_order_with_the_guard_last() {
        let mut s = state(&[A], 1);
        s.version = Some("1.5.0".to_string());
        s.module_guard = Some(Address::ZERO);
        s.guard = G;
        let plan = plan_config(
            &s,
            &ConfigChanges {
                guard: Some(Address::ZERO),
                fallback_handler: Some(G),
                module_guard: Some(G),
                enable_modules: vec![M1],
                add_owners: vec![B],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            plan.ops,
            [
                ConfigOp::AddOwner {
                    owner: B,
                    threshold: u(1)
                },
                ConfigOp::EnableModule { module: M1 },
                ConfigOp::SetFallbackHandler { handler: G },
                ConfigOp::SetModuleGuard { module_guard: G },
                ConfigOp::SetGuard {
                    guard: Address::ZERO
                },
            ]
        );
        assert_eq!(plan.after.guard, Address::ZERO);
        assert_eq!(plan.after.module_guard, Some(G));
        assert_eq!(plan.before.guard, G);
    }

    #[test]
    fn calldata_matches_the_safe_abi() {
        let op = ConfigOp::RemoveOwner {
            prev_owner: SENTINEL,
            owner: A,
            threshold: u(1),
        };
        let data = op.calldata();
        assert_eq!(&data[..4], ISafe::removeOwnerCall::SELECTOR);
        let decoded = ISafe::removeOwnerCall::abi_decode(&data).unwrap();
        assert_eq!(decoded.prevOwner, SENTINEL);
        assert_eq!(decoded.owner, A);
        assert_eq!(
            &ConfigOp::SetModuleGuard { module_guard: G }.calldata()[..4],
            ISafe::setModuleGuardCall::SELECTOR
        );
    }

    #[test]
    fn the_threshold_is_never_lowered_implicitly() {
        let msg = err(
            &state(&[A, B], 2),
            &ConfigChanges {
                remove_owners: vec![B],
                ..Default::default()
            },
        );
        assert!(msg.contains("--threshold"), "{msg}");

        let msg = err(
            &state(&[A, B], 1),
            &ConfigChanges {
                threshold: Some(u(3)),
                ..Default::default()
            },
        );
        assert!(msg.contains("more than the 2 owners"), "{msg}");

        let msg = err(
            &state(&[A, B], 1),
            &ConfigChanges {
                threshold: Some(U256::ZERO),
                ..Default::default()
            },
        );
        assert!(msg.contains("at least 1"), "{msg}");
    }

    #[test]
    fn rejects_bad_owner_changes() {
        let s = state(&[A, B], 1);
        let cases = [
            (
                ConfigChanges {
                    add_owners: vec![A],
                    ..Default::default()
                },
                "already an owner",
            ),
            (
                ConfigChanges {
                    add_owners: vec![SAFE],
                    ..Default::default()
                },
                "cannot be a Safe owner",
            ),
            (
                ConfigChanges {
                    add_owners: vec![Address::ZERO],
                    ..Default::default()
                },
                "cannot be a Safe owner",
            ),
            (
                ConfigChanges {
                    add_owners: vec![SENTINEL],
                    ..Default::default()
                },
                "cannot be a Safe owner",
            ),
            (
                ConfigChanges {
                    remove_owners: vec![C],
                    ..Default::default()
                },
                "is not an owner",
            ),
            (
                ConfigChanges {
                    swap_owners: vec![(C, D)],
                    ..Default::default()
                },
                "is not an owner",
            ),
            (
                ConfigChanges {
                    swap_owners: vec![(A, B)],
                    ..Default::default()
                },
                "already an owner",
            ),
            (
                ConfigChanges {
                    add_owners: vec![C],
                    remove_owners: vec![C],
                    ..Default::default()
                },
                "more than one owner change",
            ),
            (
                ConfigChanges {
                    swap_owners: vec![(A, C), (B, C)],
                    ..Default::default()
                },
                "more than one owner change",
            ),
        ];
        for (changes, want) in cases {
            let msg = err(&s, &changes);
            assert!(msg.contains(want), "{changes:?}: {msg}");
        }
    }

    #[test]
    fn rejects_bad_module_and_setting_changes() {
        let mut s = state(&[A], 1);
        s.modules.modules = vec![M1];
        let cases = [
            (
                ConfigChanges {
                    enable_modules: vec![M1],
                    ..Default::default()
                },
                "already enabled",
            ),
            (
                ConfigChanges {
                    disable_modules: vec![M2],
                    ..Default::default()
                },
                "is not enabled",
            ),
            (
                ConfigChanges {
                    enable_modules: vec![M2],
                    disable_modules: vec![M2],
                    ..Default::default()
                },
                "more than one module change",
            ),
            (
                ConfigChanges {
                    guard: Some(Address::ZERO),
                    ..Default::default()
                },
                "guard is already none",
            ),
            (
                ConfigChanges {
                    fallback_handler: Some(SAFE),
                    ..Default::default()
                },
                "its own fallback handler",
            ),
            (
                ConfigChanges {
                    module_guard: Some(G),
                    ..Default::default()
                },
                "needs Safe v1.5.0",
            ),
            (ConfigChanges::default(), "nothing to change"),
            (
                ConfigChanges {
                    threshold: Some(u(1)),
                    ..Default::default()
                },
                "nothing to change",
            ),
        ];
        for (changes, want) in cases {
            let msg = err(&s, &changes);
            assert!(msg.contains(want), "{changes:?}: {msg}");
        }

        s.modules.complete = false;
        let msg = err(
            &s,
            &ConfigChanges {
                enable_modules: vec![M2],
                ..Default::default()
            },
        );
        assert!(msg.contains("could not be read completely"), "{msg}");
    }
}
