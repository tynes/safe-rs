use alloy::eips::eip1559::BaseFeeParams;
use alloy::eips::BlockId;
use alloy::network::AnyNetwork;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use color_eyre::eyre::Result;
use safe_rs::simulation::session::READ_CALL_GAS;
use safe_rs::{ForkSession, SpecId};
use url::Url;

use crate::cli::SimArgs;

pub mod call;
pub mod create;
pub mod info;
pub mod send;

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

/// The largest gas limit the session accepts: the per-transaction cap from
/// Osaka on, the block gas limit before.
pub fn max_tx_gas(session: &ForkSession) -> u64 {
    if session.spec().is_enabled_in(SpecId::OSAKA) {
        READ_CALL_GAS
    } else {
        session.block_env().gas_limit
    }
}
