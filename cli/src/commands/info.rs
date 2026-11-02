//! `safe info`, and [`info`] for a CLI that shows a Safe itself.

use alloy::eips::BlockId;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::transports::TransportError;
use color_eyre::eyre::{bail, Result};
use safe_rs::{read_safe_state, ParentHeader, ReadSafeStateOptions, SafeState};
use url::Url;

use crate::cli::InfoArgs;
use crate::commands::default_safe::read_default_safe;
use crate::commands::{http_provider, HttpProvider};
use crate::console::Console;
pub use crate::output::SafeInfoOutput as SafeInfo;
use crate::signers::{create_signer, SIGNER_FLAGS_HELP};

/// Why [`info`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InfoError {
    /// No Safe at the address, or reading it failed
    #[error(transparent)]
    Safe(#[from] safe_rs::Error),
    /// An RPC request failed
    #[error(transparent)]
    Rpc(#[from] TransportError),
}

/// What `safe info <SAFE>` shows: owners, threshold, nonce, implementation
/// (singleton), version, modules, guards and balance, all read at one block
/// (`block`, default: latest).
pub async fn info(
    rpc_url: &Url,
    safe: Address,
    block: Option<BlockId>,
) -> Result<SafeInfo, InfoError> {
    let provider = http_provider(rpc_url);
    let header = ParentHeader::fetch(&provider, block.unwrap_or(BlockId::latest())).await?;
    let state = read_safe_state(
        &provider,
        safe,
        header.block_id(),
        ReadSafeStateOptions::default(),
    )
    .await?;
    with_balance(&provider, state, &header).await
}

async fn with_balance(
    provider: &HttpProvider,
    state: SafeState,
    header: &ParentHeader,
) -> Result<SafeInfo, InfoError> {
    let balance = provider
        .get_balance(state.address)
        .block_id(header.block_id())
        .await?;
    Ok(SafeInfo::new(state, balance, header.number, header.hash))
}

pub async fn run(args: InfoArgs, console: &Console) -> Result<()> {
    if let Some(safe) = args.safe {
        console.emit(&info(&args.rpc.rpc_url, safe, args.block).await?);
        return Ok(());
    }
    if !args.signer.is_set() {
        bail!(
            "No Safe specified. Pass its address, or {SIGNER_FLAGS_HELP} to use the signer's \
             default Safe"
        );
    }
    let provider = http_provider(&args.rpc.rpc_url);
    // Resolve the block to a hash first so every read sees the same state.
    let header = ParentHeader::fetch(&provider, args.block.unwrap_or(BlockId::latest())).await?;
    let signer = create_signer(&args.signer, console).await?;
    let state = read_default_safe(&provider, signer.address(), header.block_id()).await?;
    console.emit(&with_balance(&provider, state, &header).await?);
    Ok(())
}
