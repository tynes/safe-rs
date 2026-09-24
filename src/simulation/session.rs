//! Stateful fork simulation pinned to a block.
//!
//! [`ForkSession`] keeps one in-memory copy of chain state forked at a pinned
//! block and applies transactions to it in order, so later transactions see the
//! effects of earlier ones. It runs with an explicit block environment
//! ([`SimBlockEnv`]) and EVM specification instead of revm defaults, so
//! timestamp-dependent logic (deadlines, Permit2 expirations) behaves as it would
//! in the next block.
//!
//! All state reads go through a `foundry-fork-db` backend, which blocks the
//! calling thread while it fetches from the RPC. Use a multi-threaded tokio
//! runtime.

use alloy::eips::eip1559::BaseFeeParams;
use alloy::eips::BlockId;
use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use foundry_fork_db::SharedBackend;
use revm::context::{BlockEnv, TxEnv};
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::database::CacheDB;
use revm::Database;

pub use revm::primitives::hardfork::SpecId;

use crate::error::{Error, Result};
use crate::outer::OuterTxParams;
use crate::simulation::evm::{self, canonical_hash, EvmSettings};
use crate::simulation::SimulationResult;

/// Gas limit for read-only [`ForkSession::call`]s: the Osaka per-transaction cap (EIP-7825).
pub const READ_CALL_GAS: u64 = 1 << 24;

/// Blob base fee update fraction from Prague onwards (EIP-7691).
const BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE: u64 = 5_007_716;

/// The subset of a parent block header needed to derive the next block's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentHeader {
    /// Block hash
    pub hash: B256,
    /// Block number
    pub number: u64,
    /// Block timestamp (seconds)
    pub timestamp: u64,
    /// Block gas limit
    pub gas_limit: u64,
    /// Gas used in the block
    pub gas_used: u64,
    /// Base fee of the block (EIP-1559)
    pub base_fee_per_gas: Option<u64>,
    /// `mixHash` / `prevrandao`
    pub mix_hash: B256,
    /// Fee recipient
    pub beneficiary: Address,
}

impl ParentHeader {
    /// Fetches the header of `block` from the provider.
    pub async fn fetch<P: Provider<AnyNetwork>>(provider: &P, block: BlockId) -> Result<Self> {
        let block = provider
            .get_block(block)
            .await
            .map_err(|e| Error::Fetch {
                what: "block header",
                reason: e.to_string(),
            })?
            .ok_or_else(|| Error::Fetch {
                what: "block header",
                reason: format!("block {block} not found"),
            })?;
        let header = &block.header;
        Ok(Self {
            hash: header.hash,
            number: header.number,
            timestamp: header.timestamp,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            base_fee_per_gas: header.base_fee_per_gas,
            mix_hash: header.mix_hash.unwrap_or_default(),
            beneficiary: header.beneficiary,
        })
    }

    /// A block id pinning this header's hash (required to be canonical).
    pub fn block_id(&self) -> BlockId {
        canonical_hash(self.hash)
    }
}

/// Block environment for simulated execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimBlockEnv {
    /// Block number
    pub number: u64,
    /// Block timestamp (seconds)
    pub timestamp: u64,
    /// Base fee per gas
    pub basefee: u64,
    /// `prevrandao`
    pub prevrandao: B256,
    /// Block gas limit
    pub gas_limit: u64,
    /// Fee recipient
    pub coinbase: Address,
}

impl SimBlockEnv {
    /// The environment of the block after `parent`, assuming `block_time_secs`
    /// between blocks and the given EIP-1559 parameters.
    ///
    /// The base fee is the protocol's next base fee; `prevrandao` reuses the
    /// parent's value because the real one is unknowable in advance. The blob
    /// base fee is not modeled.
    pub fn next_after(parent: &ParentHeader, block_time_secs: u64, params: BaseFeeParams) -> Self {
        let basefee = parent.base_fee_per_gas.map_or(0, |fee| {
            params.next_block_base_fee(parent.gas_used, parent.gas_limit, fee)
        });
        Self {
            number: parent.number + 1,
            timestamp: parent.timestamp + block_time_secs,
            basefee,
            prevrandao: parent.mix_hash,
            gas_limit: parent.gas_limit,
            coinbase: parent.beneficiary,
        }
    }

    pub(crate) fn apply(&self, block: &mut BlockEnv) {
        block.number = U256::from(self.number);
        block.timestamp = U256::from(self.timestamp);
        block.basefee = self.basefee;
        block.prevrandao = Some(self.prevrandao);
        block.difficulty = U256::ZERO;
        block.gas_limit = self.gas_limit;
        block.beneficiary = self.coinbase;
        block.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::new(
            0,
            BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
        ));
    }
}

/// Which validity checks the simulator enforces for a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxChecks {
    /// Enforce `maxFeePerGas >= basefee`
    pub base_fee: bool,
    /// Enforce the sender nonce
    pub nonce: bool,
    /// Enforce that the sender can pay `gas_limit * max_fee_per_gas + value`
    pub balance: bool,
}

impl TxChecks {
    /// All checks enabled: the transaction must be valid as sent.
    pub const STRICT: Self = Self {
        base_fee: true,
        nonce: true,
        balance: true,
    };
    /// Valid as sent except for the sender's balance: used to measure gas with
    /// a generous gas limit the sender need not be able to afford.
    pub const MEASURE: Self = Self {
        base_fee: true,
        nonce: true,
        balance: false,
    };
    /// No fee or nonce checks, for exploratory calls with gas price zero.
    pub const RELAXED: Self = Self {
        base_fee: false,
        nonce: false,
        balance: true,
    };
}

/// A transaction to simulate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimTx {
    /// Sender (may be a contract when checks are relaxed)
    pub from: Address,
    /// Recipient
    pub to: Address,
    /// Wei sent
    pub value: U256,
    /// Calldata
    pub input: Bytes,
    /// Gas limit
    pub gas_limit: u64,
    /// `maxFeePerGas` (or legacy gas price)
    pub max_fee_per_gas: u128,
    /// `maxPriorityFeePerGas`; `None` simulates a legacy-priced transaction
    pub max_priority_fee_per_gas: Option<u128>,
    /// Sender nonce; `None` uses the nonce in the forked state
    pub nonce: Option<u64>,
    /// Validity checks
    pub checks: TxChecks,
}

impl SimTx {
    /// A zero-fee exploratory call with relaxed checks.
    pub fn relaxed(from: Address, to: Address, value: U256, input: Bytes, gas_limit: u64) -> Self {
        Self {
            from,
            to,
            value,
            input,
            gas_limit,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: None,
            nonce: None,
            checks: TxChecks::RELAXED,
        }
    }

    /// The simulation of an outer transaction exactly as signed (sender, nonce,
    /// gas limit and EIP-1559 fees), with the given validity checks.
    pub fn from_outer(outer: &OuterTxParams, checks: TxChecks) -> Self {
        Self {
            from: outer.from,
            to: outer.to,
            value: outer.value,
            input: outer.input.clone(),
            gas_limit: outer.gas_limit,
            max_fee_per_gas: outer.max_fee_per_gas,
            max_priority_fee_per_gas: Some(outer.max_priority_fee_per_gas),
            nonce: Some(outer.nonce),
            checks,
        }
    }
}

/// A stateful simulation over a forked, pinned chain state.
#[derive(Clone)]
pub struct ForkSession {
    db: CacheDB<SharedBackend>,
    chain_id: u64,
    pin: BlockId,
    env: SimBlockEnv,
    spec: SpecId,
    tx_gas_cap: Option<u64>,
    tracing: bool,
}

impl std::fmt::Debug for ForkSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForkSession")
            .field("chain_id", &self.chain_id)
            .field("pin", &self.pin)
            .field("env", &self.env)
            .field("spec", &self.spec)
            .field("tx_gas_cap", &self.tx_gas_cap)
            .finish_non_exhaustive()
    }
}

impl ForkSession {
    /// Creates a session forked at `pin` (use a block hash for a stable snapshot).
    pub fn new<P>(provider: P, chain_id: u64, pin: BlockId, env: SimBlockEnv, spec: SpecId) -> Self
    where
        P: Provider<AnyNetwork> + Clone + 'static,
    {
        Self {
            db: evm::fork_db(provider, chain_id, pin),
            chain_id,
            pin,
            env,
            spec,
            tx_gas_cap: None,
            tracing: false,
        }
    }

    /// Creates a session forked at `parent` (pinned by its hash) that executes in
    /// the block after it, `block_time_secs` later, with the protocol base fee
    /// derived from `base_fee_params`.
    pub async fn fork_next_block<P>(
        provider: P,
        chain_id: u64,
        parent: BlockId,
        block_time_secs: u64,
        base_fee_params: BaseFeeParams,
        spec: SpecId,
    ) -> Result<Self>
    where
        P: Provider<AnyNetwork> + Clone + 'static,
    {
        let parent = ParentHeader::fetch(&provider, parent).await?;
        let env = SimBlockEnv::next_after(&parent, block_time_secs, base_fee_params);
        Ok(Self::new(provider, chain_id, parent.block_id(), env, spec))
    }

    /// Rejects transactions whose gas limit exceeds `cap` (EIP-7825 on Osaka).
    pub fn with_tx_gas_cap(mut self, cap: u64) -> Self {
        self.tx_gas_cap = Some(cap);
        self
    }

    /// Records call traces for every transaction (needed for inner revert reasons).
    pub fn with_tracing(mut self, enable: bool) -> Self {
        self.tracing = enable;
        self
    }

    /// The block environment transactions execute in.
    pub fn block_env(&self) -> &SimBlockEnv {
        &self.env
    }

    /// The pinned fork block.
    pub fn pin(&self) -> BlockId {
        self.pin
    }

    /// The EVM specification.
    pub fn spec(&self) -> SpecId {
        self.spec
    }

    /// The chain ID used for execution.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// A copy of the session's current state; later transactions on either copy
    /// do not affect the other.
    pub fn checkpoint(&self) -> Self {
        self.clone()
    }

    /// Mutable access to the underlying database (for advanced setup).
    pub fn db_mut(&mut self) -> &mut CacheDB<SharedBackend> {
        &mut self.db
    }

    /// Executes a transaction and keeps its state changes.
    pub fn transact_commit(&mut self, tx: SimTx) -> Result<SimulationResult> {
        self.run(tx, true)
    }

    /// Executes a transaction and discards its state changes.
    pub fn transact(&mut self, tx: SimTx) -> Result<SimulationResult> {
        self.run(tx, false)
    }

    /// Read-only call with relaxed checks; returns the output or an error on revert.
    pub fn call(&mut self, from: Address, to: Address, input: Bytes) -> Result<Bytes> {
        let gas = self
            .tx_gas_cap
            .map_or(READ_CALL_GAS, |cap| cap.min(READ_CALL_GAS));
        let result = self.run(SimTx::relaxed(from, to, U256::ZERO, input, gas), false)?;
        if result.success {
            Ok(result.return_data)
        } else {
            Err(Error::SimulationReverted {
                reason: result
                    .revert_reason
                    .unwrap_or_else(|| "unknown".to_string()),
            })
        }
    }

    /// Current balance of an account in the session state.
    pub fn balance(&mut self, address: Address) -> Result<U256> {
        Ok(self
            .db
            .basic(address)
            .map_err(|e| Error::ForkDb(format!("{e:?}")))?
            .map_or(U256::ZERO, |info| info.balance))
    }

    /// Current nonce of an account in the session state.
    pub fn nonce(&mut self, address: Address) -> Result<u64> {
        Ok(self
            .db
            .basic(address)
            .map_err(|e| Error::ForkDb(format!("{e:?}")))?
            .map_or(0, |info| info.nonce))
    }

    fn run(&mut self, tx: SimTx, commit: bool) -> Result<SimulationResult> {
        if let Some(cap) = self.tx_gas_cap {
            if tx.gas_limit > cap {
                return Err(Error::GasLimitAboveCap {
                    gas_limit: tx.gas_limit,
                    cap,
                });
            }
        }
        let nonce = match tx.nonce {
            Some(nonce) => nonce,
            None => self.nonce(tx.from)?,
        };
        let tx_env = TxEnv {
            tx_type: if tx.max_priority_fee_per_gas.is_some() {
                2
            } else {
                0
            },
            caller: tx.from,
            gas_limit: tx.gas_limit,
            gas_price: tx.max_fee_per_gas,
            kind: TxKind::Call(tx.to),
            value: tx.value,
            data: tx.input,
            nonce,
            chain_id: Some(self.chain_id),
            gas_priority_fee: tx.max_priority_fee_per_gas,
            ..Default::default()
        };

        let settings = EvmSettings {
            chain_id: self.chain_id,
            spec: self.spec,
            checks: tx.checks,
            tx_gas_cap: self.tx_gas_cap,
            block_env: Some(self.env.clone()),
            zero_basefee: false,
        };
        let mut result = evm::execute(&mut self.db, &settings, tx_env, self.tracing, commit)?;
        result.apply_inner_revert_reason();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_block_env_follows_parent() {
        let parent = ParentHeader {
            hash: B256::ZERO,
            number: 100,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            mix_hash: B256::repeat_byte(7),
            beneficiary: Address::repeat_byte(1),
        };
        let env = SimBlockEnv::next_after(&parent, 12, BaseFeeParams::ethereum());
        assert_eq!(env.number, 101);
        assert_eq!(env.timestamp, 1_012);
        // gas used equals the target, so the base fee is unchanged
        assert_eq!(env.basefee, 1_000_000_000);
        assert_eq!(env.prevrandao, B256::repeat_byte(7));
    }

    #[test]
    fn sim_tx_from_outer_copies_the_signed_fields() {
        let outer = OuterTxParams {
            chain_id: 1,
            from: Address::repeat_byte(1),
            nonce: 9,
            gas_limit: 50_000,
            max_fee_per_gas: 30,
            max_priority_fee_per_gas: 2,
            to: Address::repeat_byte(2),
            value: U256::from(4),
            input: Bytes::from(vec![1, 2]),
        };
        let tx = SimTx::from_outer(&outer, TxChecks::STRICT);
        assert_eq!((tx.from, tx.to, tx.value), (outer.from, outer.to, outer.value));
        assert_eq!(tx.input, outer.input);
        assert_eq!((tx.gas_limit, tx.nonce), (50_000, Some(9)));
        assert_eq!((tx.max_fee_per_gas, tx.max_priority_fee_per_gas), (30, Some(2)));
        assert_eq!(tx.checks, TxChecks::STRICT);
    }

    #[test]
    fn full_parent_block_raises_base_fee() {
        let parent = ParentHeader {
            hash: B256::ZERO,
            number: 1,
            timestamp: 0,
            gas_limit: 30_000_000,
            gas_used: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            mix_hash: B256::ZERO,
            beneficiary: Address::ZERO,
        };
        let env = SimBlockEnv::next_after(&parent, 12, BaseFeeParams::ethereum());
        assert_eq!(env.basefee, 1_125_000_000);
    }
}
