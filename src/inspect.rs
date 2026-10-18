//! Block-pinned inspection of a Safe's security-relevant configuration.
//!
//! Every read in [`read_safe_state`] uses the same [`BlockId`], so the returned
//! [`SafeState`] is a coherent snapshot. Reads that cannot be completed are
//! errors, never silently "empty": an incomplete module enumeration is reported
//! through [`ModuleList::complete`].

use alloy::eips::BlockId;
use alloy::network::Network;
use alloy::primitives::{address, b256, keccak256, Address, B256, U256};
use alloy::providers::Provider;

use crate::contracts::ISafe;
use crate::error::{Error, Result};
use crate::safe::SAFE_SINGLETON_SLOT;

/// Storage slot holding the transaction guard (`keccak256("guard_manager.guard.address")`).
pub const GUARD_STORAGE_SLOT: B256 =
    b256!("0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8");

/// Storage slot holding the fallback handler (`keccak256("fallback_manager.handler.address")`).
pub const FALLBACK_HANDLER_STORAGE_SLOT: B256 =
    b256!("0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5");

/// Storage slot holding the module guard in Safe v1.5.0
/// (`keccak256("module_manager.module_guard.address")`).
pub const MODULE_GUARD_STORAGE_SLOT: B256 =
    b256!("0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947");

/// The Safe versions that have a module guard.
pub const MODULE_GUARD_VERSIONS: [&str; 1] = ["1.5.0"];

/// Returns true if a Safe reporting `version` has a module guard.
pub fn has_module_guard(version: Option<&str>) -> bool {
    version.is_some_and(|v| MODULE_GUARD_VERSIONS.contains(&v))
}

/// Sentinel used by the Safe's owner and module linked lists.
pub const SENTINEL: Address = address!("0x0000000000000000000000000000000000000001");

/// The entry before `item` in one of the Safe's linked lists (owners or
/// modules), given the list in order. The first entry is preceded by
/// [`SENTINEL`]; `None` if `item` is not in the list.
pub fn prev_in_list(list: &[Address], item: Address) -> Option<Address> {
    match list.iter().position(|entry| *entry == item)? {
        0 => Some(SENTINEL),
        i => Some(list[i - 1]),
    }
}

/// Enabled modules and whether the enumeration reached the end of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleList {
    /// Modules found, in list order
    pub modules: Vec<Address>,
    /// True only if the enumeration reached the sentinel
    pub complete: bool,
}

/// Options for [`read_safe_state`].
#[derive(Debug, Clone, Copy)]
pub struct ReadSafeStateOptions {
    /// Page size for `getModulesPaginated`
    pub module_page_size: u64,
    /// Maximum number of module pages to read before reporting an incomplete list
    pub max_module_pages: u64,
}

impl Default for ReadSafeStateOptions {
    fn default() -> Self {
        Self {
            module_page_size: 10,
            max_module_pages: 10,
        }
    }
}

/// A coherent snapshot of a Safe's configuration at one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeState {
    /// Safe (proxy) address
    pub address: Address,
    /// keccak256 of the proxy runtime code
    pub code_hash: B256,
    /// Singleton (implementation) address from storage slot 0
    pub singleton: Address,
    /// `VERSION()` if the call succeeded
    pub version: Option<String>,
    /// All owners
    pub owners: Vec<Address>,
    /// Signature threshold
    pub threshold: U256,
    /// Safe nonce
    pub nonce: U256,
    /// Enabled modules
    pub modules: ModuleList,
    /// Transaction guard (zero if none)
    pub guard: Address,
    /// Fallback handler (zero if none)
    pub fallback_handler: Address,
    /// Module guard (zero if none); `None` for versions without one
    pub module_guard: Option<Address>,
    /// Block the snapshot was read at
    pub block: BlockId,
}

impl SafeState {
    /// Returns true when the Safe is a strict 1-of-1 owned by `owner`.
    pub fn is_sole_owner(&self, owner: Address) -> bool {
        self.owners == [owner] && self.threshold == U256::from(1)
    }
}

/// Maps a failed safety-critical read of `what` to [`Error::IncompleteRead`].
fn incomplete<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::IncompleteRead {
        what,
        reason: e.to_string(),
    }
}

fn word_to_address(word: U256) -> Address {
    Address::from_slice(&word.to_be_bytes::<32>()[12..])
}

async fn storage_address<P: Provider<N>, N: Network>(
    provider: &P,
    address: Address,
    slot: U256,
    block: BlockId,
    what: &'static str,
) -> Result<Address> {
    let word = provider
        .get_storage_at(address, slot)
        .block_id(block)
        .await
        .map_err(incomplete(what))?;
    Ok(word_to_address(word))
}

/// Enumerates enabled modules with `getModulesPaginated`.
///
/// Returns `complete = false` if `max_pages` pages were read without reaching
/// the end. A revert (for example on an uninitialized proxy) is an error.
pub async fn enumerate_modules<P: Provider<N>, N: Network>(
    provider: &P,
    safe: Address,
    block: BlockId,
    page_size: u64,
    max_pages: u64,
) -> Result<ModuleList> {
    let contract = ISafe::new(safe, provider);
    let mut modules = Vec::new();
    let mut start = SENTINEL;
    for _ in 0..max_pages {
        let page = contract
            .getModulesPaginated(start, U256::from(page_size))
            .block(block)
            .call()
            .await
            .map_err(incomplete("modules"))?;
        modules.extend(page.array.iter().copied());
        if page.next == SENTINEL || page.next == Address::ZERO || page.array.is_empty() {
            return Ok(ModuleList {
                modules,
                complete: true,
            });
        }
        start = page.next;
    }
    Ok(ModuleList {
        modules,
        complete: false,
    })
}

/// Reads a [`SafeState`] at `block`.
///
/// Fails with [`Error::SafeNotDeployed`] if there is no code at `safe`, and with
/// [`Error::IncompleteRead`] if any safety-critical read fails.
pub async fn read_safe_state<P: Provider<N>, N: Network>(
    provider: &P,
    safe: Address,
    block: BlockId,
    opts: ReadSafeStateOptions,
) -> Result<SafeState> {
    let code = provider
        .get_code_at(safe)
        .block_id(block)
        .await
        .map_err(incomplete("code"))?;
    if code.is_empty() {
        return Err(Error::SafeNotDeployed(safe));
    }
    let code_hash = keccak256(&code);

    let singleton =
        storage_address(provider, safe, SAFE_SINGLETON_SLOT, block, "singleton").await?;
    let guard = storage_address(provider, safe, GUARD_STORAGE_SLOT.into(), block, "guard").await?;
    let fallback_handler = storage_address(
        provider,
        safe,
        FALLBACK_HANDLER_STORAGE_SLOT.into(),
        block,
        "fallback handler",
    )
    .await?;

    let contract = ISafe::new(safe, provider);
    let owners = contract
        .getOwners()
        .block(block)
        .call()
        .await
        .map_err(incomplete("owners"))?;
    let threshold = contract
        .getThreshold()
        .block(block)
        .call()
        .await
        .map_err(incomplete("threshold"))?;
    let nonce = contract
        .nonce()
        .block(block)
        .call()
        .await
        .map_err(incomplete("nonce"))?;
    let version = contract.VERSION().block(block).call().await.ok();
    let module_guard = if has_module_guard(version.as_deref()) {
        Some(
            storage_address(
                provider,
                safe,
                MODULE_GUARD_STORAGE_SLOT.into(),
                block,
                "module guard",
            )
            .await?,
        )
    } else {
        None
    };
    let modules = enumerate_modules(
        provider,
        safe,
        block,
        opts.module_page_size,
        opts.max_module_pages,
    )
    .await?;

    Ok(SafeState {
        address: safe,
        code_hash,
        singleton,
        version,
        owners,
        threshold,
        nonce,
        modules,
        guard,
        fallback_handler,
        module_guard,
        block,
    })
}

/// Fails with [`Error::MultiSendNotDeployed`] if `target` has no code at `block`.
///
/// A DELEGATECALL to an address without code succeeds and does nothing: a Safe
/// sent a batch through such a target emits `ExecutionSuccess`, in simulation
/// and on chain, while none of the batched calls ran. A read that fails is an
/// error too, never "deployed".
pub async fn require_batch_target<P: Provider<N>, N: Network>(
    provider: &P,
    target: Address,
    block: BlockId,
) -> Result<()> {
    let code = provider
        .get_code_at(target)
        .block_id(block)
        .await
        .map_err(incomplete("batch target code"))?;
    if code.is_empty() {
        return Err(Error::MultiSendNotDeployed(target));
    }
    Ok(())
}

/// Returns true if `address` is a proxy whose singleton (slot 0) is one of `singletons`.
pub async fn is_safe_with<P: Provider<N>, N: Network>(
    provider: &P,
    address: Address,
    singletons: &[Address],
) -> Result<bool> {
    let singleton = storage_address(
        provider,
        address,
        SAFE_SINGLETON_SLOT,
        BlockId::latest(),
        "singleton",
    )
    .await?;
    Ok(singletons.contains(&singleton))
}

/// Reads which of `owners` have approved `safe_tx_hash` on-chain (`approvedHashes(owner, safe_tx_hash) != 0`).
pub async fn read_approved_owners<P: Provider<N>, N: Network>(
    provider: &P,
    safe: Address,
    owners: &[Address],
    safe_tx_hash: B256,
    block: BlockId,
) -> Result<Vec<Address>> {
    let contract = ISafe::new(safe, provider);
    let mut approved = Vec::new();
    for &owner in owners {
        let val = contract
            .approvedHashes(owner, safe_tx_hash)
            .block(block)
            .call()
            .await
            .map_err(incomplete("approvedHashes"))?;
        if !val.is_zero() {
            approved.push(owner);
        }
    }
    Ok(approved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_constants_match_their_preimages() {
        assert_eq!(keccak256("guard_manager.guard.address"), GUARD_STORAGE_SLOT);
        assert_eq!(
            keccak256("fallback_manager.handler.address"),
            FALLBACK_HANDLER_STORAGE_SLOT
        );
        assert_eq!(
            keccak256("module_manager.module_guard.address"),
            MODULE_GUARD_STORAGE_SLOT
        );
    }

    #[test]
    fn sole_owner_requires_exactly_one_owner_and_threshold_one() {
        let owner = address!("0x00000000000000000000000000000000000000aa");
        let other = address!("0x00000000000000000000000000000000000000bb");
        let mut state = SafeState {
            address: Address::ZERO,
            code_hash: B256::ZERO,
            singleton: Address::ZERO,
            version: None,
            owners: vec![owner],
            threshold: U256::from(1),
            nonce: U256::ZERO,
            modules: ModuleList {
                modules: vec![],
                complete: true,
            },
            guard: Address::ZERO,
            fallback_handler: Address::ZERO,
            module_guard: None,
            block: BlockId::latest(),
        };
        assert!(state.is_sole_owner(owner));
        assert!(!state.is_sole_owner(other));
        state.owners.push(other);
        assert!(!state.is_sole_owner(owner));
        state.owners = vec![owner];
        state.threshold = U256::from(2);
        assert!(!state.is_sole_owner(owner));
    }
}
