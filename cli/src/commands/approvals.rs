use alloy::eips::BlockId;
use alloy::providers::Provider;
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::{
    read_approved_owners, read_safe_state, recover_signer, ParentHeader, ReadSafeStateOptions,
};

use crate::bundle::BundleFile;
use crate::cli::ApprovalsArgs;
use crate::commands::default_safe::safe_or_default;
use crate::commands::http_provider;
use crate::console::Console;
use crate::output::SafeApprovalsOutput;
use crate::signers::create_signer;

pub async fn run(args: ApprovalsArgs, console: &Console) -> Result<()> {
    let bundle = args.bundle.as_deref().map(BundleFile::load).transpose()?;
    let tx = bundle
        .as_ref()
        .map(|bundle| {
            bundle
                .tx
                .clone()
                .ok_or_else(|| eyre!("The bundle has no prepared Safe transaction yet"))
        })
        .transpose()?;
    let safe_tx_hash = match (args.safe_tx_hash, &tx) {
        (Some(hash), Some(tx)) if hash != tx.safe_tx_hash => bail!(
            "SafeTxHash {hash} does not match the bundle's prepared transaction ({})",
            tx.safe_tx_hash
        ),
        (Some(hash), _) => hash,
        (None, Some(tx)) => tx.safe_tx_hash,
        (None, None) => bail!("Pass a SafeTxHash or --bundle"),
    };

    let provider = http_provider(&args.rpc.rpc_url);
    let explicit_safe = args.safe.safe.or(tx.as_ref().map(|tx| tx.safe));
    // The signer only picks the default Safe, so a keystore is not unlocked
    // when the Safe is already known.
    let signer = if explicit_safe.is_none() && args.signer.is_set() {
        Some(create_signer(&args.signer, console).await?)
    } else {
        None
    };

    // Resolve the block to a hash first so every read sees the same state.
    let header = ParentHeader::fetch(&provider, args.block.unwrap_or(BlockId::latest())).await?;
    let block = header.block_id();
    let safe = safe_or_default(&provider, explicit_safe, signer.as_ref(), block, console).await?;
    if let Some(tx) = &tx {
        if tx.safe != safe {
            bail!("Bundle was prepared for Safe {}, not {safe}", tx.safe);
        }
        let chain_id = provider.get_chain_id().await?;
        if tx.chain_id != chain_id {
            bail!(
                "Bundle was prepared for chain {}, but the RPC is on chain {chain_id}",
                tx.chain_id
            );
        }
    }

    let state = read_safe_state(&provider, safe, block, ReadSafeStateOptions::default()).await?;
    let approved_onchain =
        read_approved_owners(&provider, safe, &state.owners, safe_tx_hash, block).await?;

    // Offchain signatures count only when they recover to a current owner. A
    // pre-validated (v = 1) entry is only valid with an on-chain approval,
    // which was read above.
    let signed_offchain = bundle
        .iter()
        .flat_map(|bundle| &bundle.signatures)
        .filter(|(owner, sig)| {
            state.owners.contains(owner)
                && !approved_onchain.contains(owner)
                && sig.get(64) != Some(&1)
                && recover_signer(safe_tx_hash, sig).is_ok_and(|signer| signer == **owner)
        })
        .map(|(&owner, _)| owner)
        .collect();

    console.emit(&SafeApprovalsOutput::new(
        &state,
        safe_tx_hash,
        approved_onchain,
        signed_offchain,
        tx.map(|tx| tx.nonce),
        header.number,
        header.hash,
    ));
    Ok(())
}
