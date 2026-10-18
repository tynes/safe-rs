use alloy::eips::eip1559::{BaseFeeParams, Eip1559Estimation};
use alloy::eips::BlockId;
use alloy::network::AnyNetwork;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use color_eyre::eyre::Result;
use safe_rs::simulation::session::READ_CALL_GAS;
use safe_rs::{ForkSession, SpecId};
use url::Url;

use crate::cli::SimArgs;

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
    let spec = SpecId::from(sim.spec);
    let mut session = ForkSession::fork_next_block(
        provider,
        chain_id,
        sim.block.unwrap_or(BlockId::latest()),
        sim.block_time,
        BaseFeeParams::ethereum(),
        spec,
    )
    .await?
    .with_tracing(tracing);
    if spec.is_enabled_in(SpecId::OSAKA) {
        session = session.with_tx_gas_cap(READ_CALL_GAS);
    }
    Ok(session)
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
