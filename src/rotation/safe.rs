//! A Safe whose owner key is used once.
//!
//! [`RotatingSafe`] ties together an [`HdWallet`], the rotation state on disk
//! and a provider. Every transaction it sends is the caller's calls followed by
//! a swap of the signing owner for the wallet's next unused key, and after the
//! swap the old owner's remaining ETH is moved to the new one.
//!
//! The order of operations is what keeps a crash or a failed transaction from
//! losing track of a key:
//!
//! 1. *Reconcile*: read the owner list and update the state from it.
//! 2. *Reserve* the next key index and save.
//! 3. *Plan, sign, simulate* and check the simulated owner list. Nothing has
//!    left the process yet.
//! 4. *Arm*: record the signed transaction and mark the owner exposed; save.
//! 5. *Broadcast*, wait, and reconcile again from the receipt's block.
//! 6. *Sweep* the old owner's ETH to the new owner.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::eips::eip1559::{BaseFeeParams, Eip1559Estimation};
use alloy::eips::BlockId;
use alloy::network::{AnyNetwork, AnyTransactionReceipt, Network, TransactionBuilder};
use alloy::primitives::{address, Address, B256, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;

use crate::chain::ChainAddresses;
use crate::contracts::{IGasPriceOracle, ISafe};
use crate::envelope::SignedSafeTx;
use crate::error::{Error, Result};
use crate::exec::{simulate_exec, submit_and_wait, Submission};
use crate::hd::HdWallet;
use crate::inspect::{read_safe_state, require_batch_target, ReadSafeStateOptions};
use crate::outer::{
    decode_signed_outer_tx, sign_outer_tx, sweep_value, OuterTxParams, SignedOuterTx,
};
use crate::rotation::history::{owner_history, OwnerEventKind};
use crate::rotation::plan::{check_post_state, plan_rotation, RotationPlan};
use crate::rotation::state::{
    binding_key, Binding, Exposure, Observation, OwnerRef, PendingTx, Reserved, Retired,
    RotationState, SignedSweep, SweepDue, Swept,
};
use crate::rotation::store::StateFile;
use crate::simulation::session::READ_CALL_GAS;
use crate::simulation::{ForkSession, ParentHeader, SimBlockEnv, SimulationResult, SpecId};
use crate::submit::{decode_safe_outcome, receipt_logs, RejectClass, SafeExecutionOutcome};
use crate::types::{Call, Operation};

/// OP-stack `GasPriceOracle` predeploy.
const GAS_PRICE_ORACLE: Address = address!("0x420000000000000000000000000000000000000F");

/// Gas a transfer to an account without code uses.
const TRANSFER_GAS: u64 = 21_000;

/// Indices skipped when a binding is rebuilt from chain, to stay clear of keys
/// that were reserved or used without leaving a trace the rebuild can see.
pub const REBUILD_MARGIN: u32 = 16;

/// How a [`RotatingSafe`] behaves.
#[derive(Clone)]
pub struct RotationConfig {
    /// Safe contract addresses (`multi_send_call_only` carries the batches).
    /// They are used as given, whatever the Safe's version:
    /// [`detect_addresses`](crate::detect_addresses) returns the ones matching it.
    pub addresses: ChainAddresses,
    /// Sends the outer transaction and pays for gas. `None`: the current owner.
    pub payer: Option<PrivateKeySigner>,
    /// The key of a current owner the wallet cannot derive, to move a Safe onto
    /// the wallet
    pub legacy_owner: Option<PrivateKeySigner>,
    /// Move a retired owner's ETH to the new owner after each rotation
    pub sweep: bool,
    /// Wei to leave behind when sweeping. `None`: the fee an OP-stack chain
    /// charges outside gas, if the chain has one, otherwise nothing.
    pub sweep_reserve: Option<U256>,
    /// EVM specification used for simulation
    pub spec: SpecId,
    /// Seconds between blocks, for the simulated block's timestamp
    pub block_time: u64,
    /// How long to wait for a receipt
    pub timeout: Duration,
    /// How often to poll for a receipt
    pub poll_interval: Duration,
    /// How many wallet indices to search for an owner the state does not know
    pub scan_limit: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            addresses: ChainAddresses::v1_4_1(),
            payer: None,
            legacy_owner: None,
            sweep: true,
            sweep_reserve: None,
            spec: SpecId::OSAKA,
            block_time: 12,
            timeout: Duration::from_mins(2),
            poll_interval: Duration::from_millis(500),
            scan_limit: 1_000,
        }
    }
}

impl std::fmt::Debug for RotationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationConfig")
            .field("addresses", &self.addresses)
            .field("payer", &self.payer.as_ref().map(PrivateKeySigner::address))
            .field(
                "legacy_owner",
                &self.legacy_owner.as_ref().map(PrivateKeySigner::address),
            )
            .field("sweep", &self.sweep)
            .field("sweep_reserve", &self.sweep_reserve)
            .field("spec", &self.spec)
            .field("block_time", &self.block_time)
            .field("timeout", &self.timeout)
            .field("poll_interval", &self.poll_interval)
            .field("scan_limit", &self.scan_limit)
            .finish()
    }
}

/// Per-transaction overrides.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecOptions {
    /// EIP-1559 fees of the outer transaction (default: the node's estimate)
    pub fees: Option<Eip1559Estimation>,
    /// Gas limit of the outer transaction (default: simulated gas plus 20%)
    pub gas_limit: Option<u64>,
}

/// The sweep a rotation is expected to be followed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedSweep {
    /// The owner being retired
    pub from: Address,
    /// The owner taking over
    pub to: Address,
    /// Roughly what will be moved; the exact amount depends on the gas the
    /// rotation ends up paying
    pub estimated: U256,
}

/// A rotation that is signed and simulated but has not left the process.
#[derive(Debug, Clone)]
pub struct RotationTx {
    /// The Safe transaction and the owner list it must produce
    pub plan: RotationPlan,
    /// The owner that signed
    pub from: OwnerRef,
    /// The owner it rotates to
    pub to: Reserved,
    /// Sender of the outer transaction
    pub payer: Address,
    /// The signed Safe transaction
    pub signed: SignedSafeTx,
    /// The signed outer transaction
    pub outer: SignedOuterTx,
    /// The strict simulation of `outer`
    pub simulation: SimulationResult,
    /// The sweep that will follow, if any
    pub planned_sweep: Option<PlannedSweep>,
}

/// What a mined rotation did to the owner list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStatus {
    /// The transaction succeeded and the owner is the new key
    Rotated,
    /// The owner is the new key, but not through this transaction's success
    /// (the same signed Safe transaction was mined in another transaction)
    RotatedElsewhere,
    /// The owner is unchanged: the transaction reverted. Its signature is
    /// public and the Safe transaction stays valid until the Safe nonce is used
    NotRotated,
}

/// A completed sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Transaction hash of the transfer
    pub tx_hash: B256,
    /// Wei moved
    pub amount: U256,
    /// The retired owner
    pub from: Address,
    /// The current owner
    pub to: Address,
}

/// What [`RotatingSafe::sweep_all`] did with each sweep that was owed.
#[derive(Debug, Default)]
pub struct SweepReport {
    /// Sweeps that moved ETH
    pub swept: Vec<SweepOutcome>,
    /// Retired owners whose sweep is still owed, with the reason
    pub failed: Vec<(Address, Error)>,
}

impl SweepReport {
    /// The completed sweeps, or the first failure if any sweep is still owed.
    pub fn into_result(self) -> Result<Vec<SweepOutcome>> {
        match self.failed.into_iter().next() {
            Some((_, error)) => Err(error),
            None => Ok(self.swept),
        }
    }
}

/// The result of a mined rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationOutcome {
    /// Hash of the outer transaction
    pub tx_hash: B256,
    /// Hash of the Safe transaction
    pub safe_tx_hash: B256,
    /// Gas the outer transaction used
    pub gas_used: u64,
    /// What the Safe reported for the Safe transaction
    pub safe_outcome: SafeExecutionOutcome,
    /// What happened to the owner list
    pub status: RotationStatus,
    /// The sweep of the owner this transaction retired, if ETH was moved
    pub sweep: Option<SweepOutcome>,
}

/// What [`RotatingSafe::sync`] found on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// The owner the wallet signs with
    pub current: OwnerRef,
    /// Wallet indices found in use: owners in the Safe's history, and keys
    /// that sent a transaction on this chain
    pub used: Vec<u32>,
    /// Owner events read (zero without a history scan)
    pub events: usize,
    /// The next index that will be handed out
    pub next_index: u32,
}

fn provider_error(e: impl std::fmt::Display) -> Error {
    Error::Provider(e.to_string())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A Safe that rotates its owner with every transaction.
pub struct RotatingSafe<P> {
    provider: P,
    chain_id: u64,
    safe: Address,
    key: String,
    wallet: HdWallet,
    store: StateFile,
    config: RotationConfig,
    warnings: Vec<String>,
}

impl<P> std::fmt::Debug for RotatingSafe<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingSafe")
            .field("chain_id", &self.chain_id)
            .field("safe", &self.safe)
            .field("wallet", &self.wallet)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<P> RotatingSafe<P>
where
    P: Provider<AnyNetwork> + Clone + 'static,
{
    /// Opens `safe` with the default configuration, locking the state at
    /// `state_path` until the value is dropped.
    pub async fn open(
        provider: P,
        safe: Address,
        wallet: HdWallet,
        state_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        let store = StateFile::open(state_path, wallet.id())?;
        Self::open_with(provider, safe, wallet, store, RotationConfig::default()).await
    }

    /// Opens `safe` and reconciles the state with the chain.
    ///
    /// A Safe the state does not know yet is adopted if one of its owners is a
    /// key of the wallet, or is [`RotationConfig::legacy_owner`]. Opening only
    /// reads from the chain; it sends nothing.
    pub async fn open_with(
        provider: P,
        safe: Address,
        wallet: HdWallet,
        store: StateFile,
        config: RotationConfig,
    ) -> Result<Self> {
        if store.state.wallet_id != wallet.id() {
            return Err(Error::Rotation(format!(
                "the state belongs to wallet {}, not {}",
                store.state.wallet_id,
                wallet.id()
            )));
        }
        let chain_id = provider.get_chain_id().await.map_err(provider_error)?;
        let mut this = Self {
            provider,
            chain_id,
            safe,
            key: binding_key(chain_id, safe),
            wallet,
            store,
            config,
            warnings: Vec::new(),
        };
        if !this.store.state.safes.contains_key(&this.key) {
            this.adopt().await?;
        }
        this.reconcile().await?;
        Ok(this)
    }

    /// The Safe address.
    pub fn safe(&self) -> Address {
        self.safe
    }

    /// The chain the Safe is on.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The wallet the owner keys come from.
    pub fn wallet(&self) -> &HdWallet {
        &self.wallet
    }

    /// The configuration in use.
    pub fn config(&self) -> &RotationConfig {
        &self.config
    }

    /// Everything recorded for the wallet.
    pub fn state(&self) -> &RotationState {
        &self.store.state
    }

    /// This Safe's rotation state.
    pub fn binding(&self) -> Result<&Binding> {
        self.store.state.binding(&self.key)
    }

    /// Problems that did not stop the last operation, such as a sweep that is
    /// still owed or a key that is also in use elsewhere.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Returns the collected warnings and clears them.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    async fn owners_at(&self, block: BlockId) -> Result<Vec<Address>> {
        ISafe::new(self.safe, &self.provider)
            .getOwners()
            .block(block)
            .call()
            .await
            .map_err(|e| Error::Fetch {
                what: "owners",
                reason: e.to_string(),
            })
    }

    /// Starts tracking a Safe from what the chain shows.
    async fn adopt(&mut self) -> Result<()> {
        let owners = self.owners_at(BlockId::latest()).await?;
        let found = self.wallet.find_owner(&owners, self.config.scan_limit)?;
        let current = if let Some((index, address)) = found {
            OwnerRef::Derived { index, address }
        } else if let Some(legacy) = self
            .config
            .legacy_owner
            .as_ref()
            .filter(|key| owners.contains(&key.address()))
        {
            OwnerRef::External {
                address: legacy.address(),
            }
        } else {
            return Err(Error::Rotation(format!(
                "none of the wallet's first {} keys owns Safe {}; \
                 supply the current owner's key to move the Safe onto this wallet",
                self.config.scan_limit, self.safe
            )));
        };
        self.store.state.bind(&self.key, current)?;
        if current.index().is_some() {
            // The chain cannot show signatures that reverted or were never
            // mined, nor indices reserved but not yet used.
            self.store
                .state
                .mark_exposed(&self.key, Exposure::Rebuilt)?;
            self.store.state.skip_ahead(REBUILD_MARGIN);
        }
        self.store.save()
    }

    fn observe(&mut self, owners: &[Address], block: Option<u64>) -> Result<Observation> {
        let binding = self.store.state.binding(&self.key)?;
        let known = owners.contains(&binding.current.address())
            || binding
                .reserved
                .is_some_and(|reserved| owners.contains(&reserved.address));
        let found = if known {
            None
        } else {
            self.wallet.find_owner(owners, self.config.scan_limit)?
        };
        self.store.state.observe(
            &self.key,
            owners,
            block,
            |address| found.and_then(|(index, owner)| (owner == address).then_some(index)),
            self.config.sweep,
        )
    }

    fn lost(&self) -> Error {
        Error::Rotation(format!(
            "neither the recorded owner nor any of the wallet's first {} keys owns Safe {}; \
             rebuild the state from the Safe's history, or supply the current owner's key",
            self.config.scan_limit, self.safe
        ))
    }

    /// Updates the state from the chain: who owns the Safe, whether a pending
    /// transaction can still be mined, and whether this wallet's keys are in
    /// use elsewhere.
    ///
    /// This only reads. A rotation it discovers schedules a sweep, which
    /// [`RotatingSafe::sweep`] or the next [`RotatingSafe::execute`] carries out.
    pub async fn reconcile(&mut self) -> Result<Observation> {
        let head = ParentHeader::fetch(&self.provider, BlockId::latest()).await?;
        let owners = self.owners_at(head.block_id()).await?;
        let observation = self.observe(&owners, Some(head.number))?;
        if observation == Observation::Lost {
            return Err(self.lost());
        }
        self.resolve_pending().await?;
        let warnings = self.store.state.cross_check();
        self.warnings.extend(warnings);
        self.store.save()?;
        Ok(observation)
    }

    /// Drops the pending transaction once it is mined or its sender's nonce
    /// has moved past it: either way those bytes can no longer be mined.
    async fn resolve_pending(&mut self) -> Result<()> {
        let Some(pending) = self.binding()?.pending.clone() else {
            return Ok(());
        };
        let mined = self
            .provider
            .get_transaction_receipt(pending.outer_tx_hash)
            .await
            .map_err(provider_error)?
            .is_some();
        let nonce = self
            .provider
            .get_transaction_count(pending.payer)
            .await
            .map_err(provider_error)?;
        if mined || nonce > pending.payer_nonce {
            self.store.state.clear_pending(&self.key)?;
        }
        Ok(())
    }

    /// The key for an owner: derived from the wallet, or the legacy key.
    fn signer_for(&self, owner: &OwnerRef) -> Result<Option<PrivateKeySigner>> {
        match *owner {
            OwnerRef::Derived { index, address } => {
                let signer = if index == 0 {
                    self.wallet.funding().clone()
                } else {
                    self.wallet.owner(index)?
                };
                if signer.address() != address {
                    return Err(Error::Rotation(format!(
                        "the state records {address} for key {index}, but the wallet derives {}",
                        signer.address()
                    )));
                }
                Ok(Some(signer))
            }
            OwnerRef::External { address } => Ok(self
                .config
                .legacy_owner
                .clone()
                .filter(|key| key.address() == address)),
        }
    }

    /// The next owner: the binding's reservation, or a fresh index.
    ///
    /// A fresh index is written to disk before its key is looked at, and is
    /// skipped if its address has ever sent a transaction or holds code here.
    async fn reserve(&mut self) -> Result<Reserved> {
        if let Some(reserved) = self.binding()?.reserved {
            return Ok(reserved);
        }
        loop {
            let wallet = &self.wallet;
            let candidate = self
                .store
                .state
                .allocate(|index| wallet.owner_address(index))?;
            self.store.save()?;
            let nonce = self
                .provider
                .get_transaction_count(candidate.address)
                .await
                .map_err(provider_error)?;
            let code = self
                .provider
                .get_code_at(candidate.address)
                .await
                .map_err(provider_error)?;
            if nonce != 0 || !code.is_empty() {
                self.warnings.push(format!(
                    "skipping key {}: {} was already used on this chain",
                    candidate.index, candidate.address
                ));
                continue;
            }
            self.store.state.reserve(&self.key, candidate)?;
            self.store.save()?;
            return Ok(candidate);
        }
    }

    fn session(&self, head: &ParentHeader) -> ForkSession {
        let env = SimBlockEnv::next_after(head, self.config.block_time, BaseFeeParams::ethereum());
        let session = ForkSession::new(
            self.provider.clone(),
            self.chain_id,
            head.block_id(),
            env,
            self.config.spec,
        )
        .with_tracing(true);
        if self.config.spec.is_enabled_in(SpecId::OSAKA) {
            session.with_tx_gas_cap(READ_CALL_GAS)
        } else {
            session
        }
    }

    /// Builds, signs and simulates `calls` followed by the owner swap.
    ///
    /// With no calls this is a rotation-only transaction. Nothing leaves the
    /// process and, apart from the reserved index, the state is unchanged: if
    /// the simulation fails the owner key has not been exposed.
    ///
    /// Fails if a transaction with user calls is still pending (two competing
    /// sets of calls must not be live at once; a rotation-only transaction is
    /// allowed), if the simulation reverts, or if the simulated owner list is
    /// not exactly the planned one. Calls batched with the swap need
    /// `MultiSendCallOnly` to have code at
    /// [`RotationConfig::addresses`]`.multi_send_call_only`, and fail with
    /// [`Error::MultiSendNotDeployed`] before anything is signed otherwise.
    ///
    /// Run [`RotatingSafe::sweep`] first if a sweep is owed: until then the
    /// current owner may not hold the ETH to pay for this.
    pub async fn prepare(&mut self, calls: &[Call], options: ExecOptions) -> Result<RotationTx> {
        let binding = self.binding()?;
        let current = binding.current;
        if let (Some(pending), false) = (&binding.pending, calls.is_empty()) {
            return Err(Error::Rotation(format!(
                "transaction {} is still pending; wait for it, or send a rotation-only transaction",
                pending.outer_tx_hash
            )));
        }
        let Some(owner) = self.signer_for(&current)? else {
            return Err(Error::Rotation(format!(
                "the current owner {} is not a key of this wallet; supply its key",
                current.address()
            )));
        };
        let reserved = self.reserve().await?;

        let head = ParentHeader::fetch(&self.provider, BlockId::latest()).await?;
        let state = read_safe_state(
            &self.provider,
            self.safe,
            head.block_id(),
            ReadSafeStateOptions::default(),
        )
        .await?;
        let plan = plan_rotation(
            &state,
            self.chain_id,
            self.config.addresses.multi_send_call_only,
            calls,
            &[(current.address(), reserved.address)],
        )?;
        // The plan has no DelegateCall entries, so this operation means the
        // calls are batched through MultiSendCallOnly. With no code there the
        // Safe would report success while neither the calls nor the swap ran.
        if plan.prepared.params.operation == Operation::DelegateCall {
            require_batch_target(&self.provider, plan.prepared.params.to, head.block_id()).await?;
        }

        let payer = self.config.payer.clone().unwrap_or_else(|| owner.clone());
        if payer.address() == reserved.address {
            return Err(Error::Rotation(
                "the payer must not be the next owner: paying would publish its key".to_string(),
            ));
        }
        let signed = plan.prepared.sign(&owner).await?;
        let fees = match options.fees {
            Some(fees) => fees,
            None => self
                .provider
                .estimate_eip1559_fees()
                .await
                .map_err(provider_error)?,
        };

        let owed = if !self.binding()?.sweep_due.is_empty() {
            " (a sweep to it is still owed: run it first)"
        } else {
            ""
        };
        let session = self.session(&head);
        let simulated = simulate_exec(&session, &signed, payer.address(), fees, options.gas_limit)
            .map_err(|e| match e {
                Error::Revm(reason) if reason.contains("LackOfFund") => Error::Rotation(format!(
                    "{} cannot pay for this transaction: fund it, or use a separate payer{owed}",
                    payer.address()
                )),
                other => other,
            })?;
        let Some(mut post) = simulated.post else {
            return Err(Error::SimulationReverted {
                reason: simulated
                    .result
                    .revert_reason
                    .unwrap_or_else(|| "unknown".to_string()),
            });
        };
        check_post_state(&mut post, &plan)?;

        let planned_sweep = if self.config.sweep {
            let left = post.balance(current.address())?;
            sweep_value(left, TRANSFER_GAS, fees.max_fee_per_gas, U256::ZERO).map(|estimated| {
                PlannedSweep {
                    from: current.address(),
                    to: reserved.address,
                    estimated,
                }
            })
        } else {
            None
        };

        let outer = sign_outer_tx(
            &payer,
            OuterTxParams::exec_transaction(
                &signed,
                payer.address(),
                simulated.payer_nonce,
                simulated.gas_limit,
                fees,
            ),
        )
        .await?;

        Ok(RotationTx {
            plan,
            from: current,
            to: reserved,
            payer: payer.address(),
            signed,
            outer,
            simulation: simulated.result,
            planned_sweep,
        })
    }

    /// Records that `tx` is about to leave the process: the owner is marked
    /// exposed and the signed bytes are stored, then the state is saved.
    ///
    /// Call this before writing the transaction anywhere or broadcasting it.
    /// Arming the same transaction twice is a no-op.
    pub fn arm(&mut self, tx: &RotationTx) -> Result<()> {
        let binding = self.binding()?;
        if binding
            .pending
            .as_ref()
            .is_some_and(|pending| pending.outer_tx_hash == tx.outer.tx_hash)
        {
            return Ok(());
        }
        if binding.current != tx.from || binding.reserved != Some(tx.to) {
            return Err(Error::Rotation(
                "the Safe's rotation state changed since the transaction was prepared".to_string(),
            ));
        }
        self.store.state.arm(
            &self.key,
            PendingTx {
                safe_tx_hash: tx.plan.prepared.safe_tx_hash,
                safe_nonce: tx.plan.prepared.params.nonce,
                outer_tx_hash: tx.outer.tx_hash,
                payer: tx.payer,
                payer_nonce: tx.outer.params.nonce,
                raw: tx.outer.raw.clone(),
                created_at: now(),
            },
        )?;
        self.store.save()
    }

    /// Arms, broadcasts and waits for `tx`, then updates the state from the
    /// receipt's block and sweeps the retired owner's ETH.
    ///
    /// A transaction the node rejects, or whose receipt does not arrive in
    /// time, is [`Error::Unconfirmed`]: the state keeps it as pending and the
    /// owner as exposed, and the next [`RotatingSafe::open`] resolves it.
    pub async fn submit(&mut self, tx: RotationTx) -> Result<RotationOutcome> {
        self.arm(&tx)?;
        let unconfirmed = |reason: String| Error::Unconfirmed {
            tx_hash: tx.outer.tx_hash,
            reason,
        };
        let receipt = match submit_and_wait(
            &self.provider,
            &tx.outer,
            self.config.timeout,
            self.config.poll_interval,
        )
        .await?
        {
            Submission::Mined(receipt) => receipt,
            Submission::TimedOut { .. } => {
                return Err(unconfirmed(
                    "no receipt arrived in time; it may still be pending".to_string(),
                ))
            }
            Submission::Rejected { reason, .. } => {
                return Err(unconfirmed(format!("the node rejected it: {reason}")))
            }
            Submission::Ambiguous { reason } => {
                return Err(unconfirmed(format!(
                    "the broadcast outcome is unknown: {reason}"
                )))
            }
        };
        self.finalize(&tx, &receipt).await
    }

    async fn finalize(
        &mut self,
        tx: &RotationTx,
        receipt: &AnyTransactionReceipt,
    ) -> Result<RotationOutcome> {
        let safe_tx_hash = tx.plan.prepared.safe_tx_hash;
        let safe_outcome = if receipt.inner.inner.status() {
            decode_safe_outcome(&receipt_logs(receipt), self.safe, safe_tx_hash)
        } else {
            SafeExecutionOutcome::NotFound
        };

        // The owner list, not the receipt, decides whether the key is retired:
        // the same signed Safe transaction may have been mined by someone else.
        let block = receipt.block_hash.map_or(BlockId::latest(), BlockId::hash);
        let owners = self.owners_at(block).await?;
        let observation = self.observe(&owners, receipt.block_number)?;
        // Mined bytes cannot be mined again.
        self.store.state.clear_pending(&self.key)?;
        let warnings = self.store.state.cross_check();
        self.warnings.extend(warnings);
        self.store.save()?;

        let status = match observation {
            Observation::Rotated { .. } if safe_outcome.is_success() => RotationStatus::Rotated,
            Observation::Rotated { .. } | Observation::Adopted { .. } => {
                RotationStatus::RotatedElsewhere
            }
            Observation::Unchanged | Observation::Lost => RotationStatus::NotRotated,
        };
        let retired = tx.from.address();
        let sweep = self
            .sweep_or_warn()
            .await
            .into_iter()
            .find(|sweep| sweep.from == retired);
        Ok(RotationOutcome {
            tx_hash: receipt.transaction_hash,
            safe_tx_hash,
            gas_used: receipt.gas_used,
            safe_outcome,
            status,
            sweep,
        })
    }

    /// Prepares and submits `calls` followed by the owner swap.
    ///
    /// A sweep still owed from an earlier rotation runs first, so the current
    /// owner has its gas; if it fails, that is a warning and the transaction is
    /// attempted anyway.
    pub async fn execute(&mut self, calls: &[Call]) -> Result<RotationOutcome> {
        self.sweep_or_warn().await;
        let tx = self.prepare(calls, ExecOptions::default()).await?;
        self.submit(tx).await
    }

    /// Sends a rotation-only transaction.
    pub async fn rotate(&mut self) -> Result<RotationOutcome> {
        self.execute(&[]).await
    }

    /// Attempts every owed sweep; the ones that fail become warnings.
    async fn sweep_or_warn(&mut self) -> Vec<SweepOutcome> {
        match self.sweep_all().await {
            Ok(report) => {
                for (from, error) in &report.failed {
                    self.warnings
                        .push(format!("a sweep from {from} is still owed: {error}"));
                }
                report.swept
            }
            Err(e) => {
                self.warnings.push(format!("a sweep is still owed: {e}"));
                Vec::new()
            }
        }
    }

    async fn transfer_gas(&self, from: Address, to: Address) -> u64 {
        let tx = <AnyNetwork as Network>::TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_value(U256::from(1));
        self.provider
            .estimate_gas(tx)
            .await
            .unwrap_or(TRANSFER_GAS)
            .max(TRANSFER_GAS)
    }

    /// What an OP-stack chain charges for `draft` outside gas, with a margin
    /// for the L1 fee moving before inclusion. Zero on any other chain.
    async fn fee_reserve(&self, draft: &SignedOuterTx) -> U256 {
        match self.provider.get_code_at(GAS_PRICE_ORACLE).await {
            Ok(code) if !code.is_empty() => {}
            _ => return U256::ZERO,
        }
        let oracle = IGasPriceOracle::new(GAS_PRICE_ORACLE, &self.provider);
        let l1_fee = oracle
            .getL1Fee(draft.raw.clone())
            .call()
            .await
            .unwrap_or_default();
        let operator_fee = oracle
            .getOperatorFee(U256::from(draft.params.gas_limit))
            .call()
            .await
            .unwrap_or_default();
        l1_fee
            .saturating_mul(U256::from(2))
            .saturating_add(operator_fee)
    }

    /// Attempts every owed sweep, oldest first, each to the current owner.
    ///
    /// A sweep that cannot be completed stays owed and does not stop the
    /// others; it is reported in [`SweepReport::failed`]. The outer `Err` is for
    /// failures to read or save the state itself.
    pub async fn sweep_all(&mut self) -> Result<SweepReport> {
        let mut report = SweepReport::default();
        for due in self.binding()?.sweep_due.clone() {
            let from = due.from.address();
            match self.sweep_one(due).await {
                Ok(Some(outcome)) => report.swept.push(outcome),
                Ok(None) => {}
                Err(error) => report.failed.push((from, error)),
            }
        }
        Ok(report)
    }

    /// Moves the ETH of every retired owner with a sweep owed to the current
    /// owner, and returns the sweeps that moved ETH.
    ///
    /// Fails with the first error if any sweep is still owed afterwards; use
    /// [`RotatingSafe::sweep_all`] to see each result.
    pub async fn sweep(&mut self) -> Result<Vec<SweepOutcome>> {
        self.sweep_all().await?.into_result()
    }

    /// Carries out one owed sweep.
    ///
    /// Returns `None` if the balance does not cover the transfer fee, which
    /// settles the sweep. The signed transfer is stored before its first
    /// broadcast; a retry rebroadcasts the same bytes while the sender's nonce
    /// is unchanged, and only signs a replacement (same nonce, higher fee,
    /// lower amount) once the network fee has risen by an eighth.
    async fn sweep_one(&mut self, due: SweepDue) -> Result<Option<SweepOutcome>> {
        let binding = self.binding()?;
        let to = binding.current.address();
        let from = due.from.address();
        let Some(signer) = self.signer_for(&due.from)? else {
            return Err(Error::Rotation(format!(
                "{from} is not a key of this wallet: move its ETH to {to} yourself, \
                 or supply its key"
            )));
        };
        let nonce = self
            .provider
            .get_transaction_count(from)
            .await
            .map_err(provider_error)?;
        let fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(provider_error)?;

        if let Some(stored) = &due.signed {
            let receipt = self
                .provider
                .get_transaction_receipt(stored.tx_hash)
                .await
                .map_err(provider_error)?;
            if let Some(receipt) = receipt {
                let success = receipt.inner.inner.status();
                return self.finish_sweep(stored.tx_hash, stored.amount, from, to, success);
            }
            if nonce == stored.nonce {
                let outer = decode_signed_outer_tx(&stored.raw)?;
                let signed_fee = outer.params.max_fee_per_gas;
                if fees.max_fee_per_gas < signed_fee + signed_fee / 8 {
                    return self.broadcast_sweep(outer, stored.amount, to).await;
                }
            }
        }

        let balance = self
            .provider
            .get_balance(from)
            .await
            .map_err(provider_error)?;
        let gas = self.transfer_gas(from, to).await;
        // Tip equal to the fee cap: the transfer costs exactly gas * cap, so
        // the sender ends at the reserve.
        let exact = Eip1559Estimation {
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_fee_per_gas,
        };
        let transfer =
            |amount| OuterTxParams::transfer(self.chain_id, from, to, amount, nonce, gas, exact);
        let reserve = match self.config.sweep_reserve {
            Some(reserve) => reserve,
            None => match sweep_value(balance, gas, exact.max_fee_per_gas, U256::ZERO) {
                Some(amount) => {
                    let draft = sign_outer_tx(&signer, transfer(amount)).await?;
                    self.fee_reserve(&draft).await
                }
                None => U256::ZERO,
            },
        };
        let Some(amount) = sweep_value(balance, gas, exact.max_fee_per_gas, reserve) else {
            self.store.state.finish_sweep(&self.key, from, None)?;
            self.store.save()?;
            return Ok(None);
        };

        let outer = sign_outer_tx(&signer, transfer(amount)).await?;
        self.store.state.set_signed_sweep(
            &self.key,
            from,
            Some(SignedSweep {
                tx_hash: outer.tx_hash,
                nonce,
                amount,
                raw: outer.raw.clone(),
            }),
        )?;
        self.store.save()?;
        self.broadcast_sweep(outer, amount, to).await
    }

    /// Rebuilds what the state knows about used keys from the chain.
    ///
    /// Two sources are read, and every wallet index either one shows is
    /// treated as used:
    ///
    /// - With `from_block`, the Safe's owner events from that block on. This
    ///   also restores the Safe's rotation history. Start at or before the
    ///   Safe's deployment to see every owner it ever had; `chunk` is the
    ///   block span of one `eth_getLogs` request.
    /// - The account nonce of each wallet address: a key that paid for gas
    ///   has a non-zero nonce on this chain, whichever Safe it owned.
    ///
    /// The counter then leaves [`REBUILD_MARGIN`] indices unused. Neither
    /// source shows keys used only on another chain, or only with a separate
    /// payer on a Safe that is not scanned here: run this for every Safe and
    /// chain the phrase was used with.
    pub async fn sync(&mut self, from_block: Option<u64>, chunk: u64) -> Result<SyncReport> {
        let limit = self.config.scan_limit;
        let mut index_of = HashMap::new();
        let mut address_of = BTreeMap::new();
        for index in 1..=limit {
            let address = self.wallet.owner_address(index)?;
            index_of.insert(address, index);
            address_of.insert(index, address);
        }
        let owner_ref = |address: Address| match index_of.get(&address) {
            Some(index) => OwnerRef::Derived {
                index: *index,
                address,
            },
            None => OwnerRef::External { address },
        };

        let binding = self.binding()?;
        let mut used: BTreeSet<u32> = binding.current.index().into_iter().collect();
        used.extend(binding.history.iter().filter_map(|r| r.owner.index()));

        let mut events = 0;
        if let Some(from_block) = from_block {
            let head = self
                .provider
                .get_block_number()
                .await
                .map_err(provider_error)?;
            let history = owner_history(&self.provider, self.safe, from_block, head, chunk).await?;
            events = history.len();
            used.extend(history.iter().filter_map(|e| index_of.get(&e.owner)));

            // A swap is one removal and one addition in the same transaction.
            let mut retired = Vec::new();
            for (position, removed) in history.iter().enumerate() {
                if removed.kind != OwnerEventKind::Removed {
                    continue;
                }
                let added = history[position + 1..]
                    .iter()
                    .take_while(|next| next.tx_hash == removed.tx_hash)
                    .find(|next| next.kind == OwnerEventKind::Added);
                if let Some(added) = added {
                    let owner = owner_ref(removed.owner);
                    let swept = self
                        .binding()?
                        .history
                        .iter()
                        .find(|known| known.owner == owner)
                        .and_then(|known| known.swept);
                    retired.push(Retired {
                        owner,
                        replaced_by: owner_ref(added.owner),
                        observed_block: removed.block,
                        swept,
                    });
                }
            }
            if !retired.is_empty() {
                self.store.state.set_history(&self.key, retired)?;
            }
        }

        // Keys that sent a transaction here, up to a gap past the last one known.
        let mut last = used
            .iter()
            .next_back()
            .copied()
            .unwrap_or(0)
            .max(self.store.state.next_index.saturating_sub(1));
        let mut index = 1;
        while index <= limit && index <= last.saturating_add(REBUILD_MARGIN) {
            if let Some(address) = address_of.get(&index) {
                let nonce = self
                    .provider
                    .get_transaction_count(*address)
                    .await
                    .map_err(provider_error)?;
                if nonce > 0 {
                    used.insert(index);
                    last = last.max(index);
                }
            }
            index += 1;
        }

        if let Some(highest) = used.iter().next_back() {
            self.store
                .state
                .note_used(highest.saturating_add(REBUILD_MARGIN));
        }
        self.store.save()?;
        Ok(SyncReport {
            current: self.binding()?.current,
            used: used.into_iter().collect(),
            events,
            next_index: self.store.state.next_index,
        })
    }

    /// Schedules a sweep for every retired owner that still holds ETH and has
    /// none owed yet, and returns how many were added.
    ///
    /// This picks up keys retired while sweeping was off. Only keys the wallet
    /// (or [`RotationConfig::legacy_owner`]) can sign for are considered.
    pub async fn schedule_retired_sweeps(&mut self) -> Result<usize> {
        let binding = self.binding()?;
        let candidates: Vec<OwnerRef> = binding
            .history
            .iter()
            .filter(|retired| retired.swept.is_none())
            .map(|retired| retired.owner)
            .filter(|owner| !binding.sweep_due.iter().any(|due| due.from == *owner))
            .collect();
        let mut added = 0;
        for owner in candidates {
            if self.signer_for(&owner)?.is_none() {
                continue;
            }
            let balance = self
                .provider
                .get_balance(owner.address())
                .await
                .map_err(provider_error)?;
            if !balance.is_zero() {
                self.store.state.schedule_sweep(&self.key, owner)?;
                added += 1;
            }
        }
        if added > 0 {
            self.store.save()?;
        }
        Ok(added)
    }

    /// Sweeps every retired owner that still holds ETH, whether or not a sweep
    /// was scheduled for it, for example because sweeping was off when it was
    /// retired.
    pub async fn sweep_retired(&mut self) -> Result<Vec<SweepOutcome>> {
        self.schedule_retired_sweeps().await?;
        self.sweep().await
    }

    async fn broadcast_sweep(
        &mut self,
        outer: SignedOuterTx,
        amount: U256,
        to: Address,
    ) -> Result<Option<SweepOutcome>> {
        let from = outer.params.from;
        let unconfirmed = |reason: String| Error::Unconfirmed {
            tx_hash: outer.tx_hash,
            reason,
        };
        match submit_and_wait(
            &self.provider,
            &outer,
            self.config.timeout,
            self.config.poll_interval,
        )
        .await?
        {
            Submission::Mined(receipt) => {
                let success = receipt.inner.inner.status();
                self.finish_sweep(outer.tx_hash, amount, from, to, success)
            }
            Submission::TimedOut { .. } => Err(unconfirmed(
                "no receipt arrived in time; it may still be pending".to_string(),
            )),
            Submission::Rejected { reason, class } => {
                // The node does not hold these bytes, so the next attempt may
                // sign a different transfer. An underpriced replacement means
                // an earlier one is still pending: keep the record.
                if class != RejectClass::Underpriced {
                    self.store.state.set_signed_sweep(&self.key, from, None)?;
                    self.store.save()?;
                }
                Err(unconfirmed(format!("the node rejected it: {reason}")))
            }
            Submission::Ambiguous { reason } => Err(unconfirmed(format!(
                "the broadcast outcome is unknown: {reason}"
            ))),
        }
    }

    fn finish_sweep(
        &mut self,
        tx_hash: B256,
        amount: U256,
        from: Address,
        to: Address,
        success: bool,
    ) -> Result<Option<SweepOutcome>> {
        if !success {
            // The nonce is used up; the next attempt has to sign afresh.
            self.store.state.set_signed_sweep(&self.key, from, None)?;
            self.store.save()?;
            return Err(Error::ExecutionFailed {
                reason: format!("sweep transaction {tx_hash} reverted"),
            });
        }
        self.store
            .state
            .finish_sweep(&self.key, from, Some(Swept { tx_hash, amount }))?;
        self.store.save()?;
        Ok(Some(SweepOutcome {
            tx_hash,
            amount,
            from,
            to,
        }))
    }
}
