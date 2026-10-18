use alloy::eips::eip1559::{BaseFeeParams, Eip1559Estimation};
use alloy::eips::BlockId;
use alloy::network::AnyNetwork;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use color_eyre::eyre::Result;
use safe_rs::simulation::session::READ_CALL_GAS;
use safe_rs::{ethereum_spec_at, ForkSession, ParentHeader, SimBlockEnv, SpecId};
use url::Url;

use crate::cli::{EvmSpec, SimArgs};

pub mod approvals;
pub mod call;
pub mod config;
pub mod create;
mod default_safe;
pub mod info;
pub mod rotate;
pub mod rotation;
pub mod send;
pub mod wallet;

/// Read-only provider used by every command.
pub type HttpProvider = DynProvider<AnyNetwork>;

pub fn http_provider(url: &Url) -> HttpProvider {
    ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(url.clone())
        .erased()
}

/// A fork session that executes in the block after `--block` (default: latest).
///
/// From Osaka on, transactions above the EIP-7825 gas cap are rejected, as the
/// chain would reject them.
pub async fn fork_session(
    provider: HttpProvider,
    chain_id: u64,
    sim: &SimArgs,
    tracing: bool,
) -> Result<ForkSession> {
    let parent = ParentHeader::fetch(&provider, sim.block.unwrap_or(BlockId::latest())).await?;
    let env = SimBlockEnv::next_after(&parent, sim.block_time, BaseFeeParams::ethereum());
    let spec = sim_spec(sim.spec, chain_id, env.timestamp);
    let mut session =
        ForkSession::new(provider, chain_id, parent.block_id(), env, spec).with_tracing(tracing);
    if spec.is_enabled_in(SpecId::OSAKA) {
        session = session.with_tx_gas_cap(READ_CALL_GAS);
    }
    Ok(session)
}

/// The EVM spec to simulate a block with `timestamp` under: `explicit` (from
/// `--spec`) if given, else the fork active then on a known Ethereum network,
/// else Osaka.
pub fn sim_spec(explicit: Option<EvmSpec>, chain_id: u64, timestamp: u64) -> SpecId {
    explicit
        .map(SpecId::from)
        .or_else(|| ethereum_spec_at(chain_id, timestamp))
        .unwrap_or(SpecId::OSAKA)
}

/// [`sim_spec`] for the block after the latest one, `block_time` seconds
/// later: the spec for runs that always simulate at the head of the chain.
pub async fn latest_sim_spec(
    provider: &HttpProvider,
    chain_id: u64,
    explicit: Option<EvmSpec>,
    block_time: u64,
) -> Result<SpecId> {
    if let Some(spec) = explicit {
        return Ok(spec.into());
    }
    let latest = ParentHeader::fetch(provider, BlockId::latest()).await?;
    Ok(sim_spec(None, chain_id, latest.timestamp + block_time))
}

/// EIP-1559 fees for an outer transaction: the node estimate, with any
/// `--max-fee-per-gas` / `--max-priority-fee-per-gas` override applied.
pub async fn outer_fees(
    provider: &HttpProvider,
    max_fee_per_gas: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
) -> Result<Eip1559Estimation> {
    let mut fees = match (max_fee_per_gas, max_priority_fee_per_gas) {
        (Some(max_fee_per_gas), Some(max_priority_fee_per_gas)) => Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
        _ => provider.estimate_eip1559_fees().await?,
    };
    if let Some(max_fee) = max_fee_per_gas {
        fees.max_fee_per_gas = max_fee;
    }
    if let Some(priority_fee) = max_priority_fee_per_gas {
        fees.max_priority_fee_per_gas = priority_fee;
    }
    Ok(fees)
}
