use alloy::eips::BlockId;
use alloy::providers::Provider;
use color_eyre::eyre::{bail, Result};
use safe_rs::{read_safe_state, ParentHeader, ReadSafeStateOptions};

use crate::cli::InfoArgs;
use crate::commands::default_safe::read_default_safe;
use crate::commands::http_provider;
use crate::output::{Report, SafeInfoOutput};
use crate::wallet::create_signer;

pub async fn run(args: InfoArgs, json: bool) -> Result<()> {
    let provider = http_provider(&args.rpc.rpc_url);

    // Resolve the block to a hash first so every read sees the same state.
    let header = ParentHeader::fetch(&provider, args.block.unwrap_or(BlockId::latest())).await?;
    let block = header.block_id();
    let state = if let Some(safe) = args.safe {
        read_safe_state(&provider, safe, block, ReadSafeStateOptions::default()).await?
    } else {
        if !args.wallet.is_set() {
            bail!(
                "No Safe specified. Pass its address, or --private-key, --keystore or \
                 --interactive to use the signer's default Safe"
            );
        }
        let signer = create_signer(&args.wallet, &args.password)?;
        read_default_safe(&provider, signer, block).await?
    };

    let balance = provider.get_balance(state.address).block_id(block).await?;

    SafeInfoOutput::new(state, balance, header.number, header.hash).print(json);
    Ok(())
}
