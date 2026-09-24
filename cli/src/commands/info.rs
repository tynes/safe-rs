use alloy::eips::BlockId;
use color_eyre::eyre::Result;
use safe_rs::{read_safe_state, ParentHeader, ReadSafeStateOptions};

use crate::cli::InfoArgs;
use crate::commands::http_provider;
use crate::output::{Report, SafeInfoOutput};

pub async fn run(args: InfoArgs, json: bool) -> Result<()> {
    let provider = http_provider(&args.rpc.rpc_url);

    // Resolve the block to a hash first so every read sees the same state.
    let header = ParentHeader::fetch(&provider, args.block.unwrap_or(BlockId::latest())).await?;
    let state = read_safe_state(
        &provider,
        args.safe.safe,
        header.block_id(),
        ReadSafeStateOptions::default(),
    )
    .await?;

    SafeInfoOutput::new(state, header.number, header.hash).print(json);
    Ok(())
}
