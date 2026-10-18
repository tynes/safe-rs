use alloy::eips::BlockId;
use alloy::providers::Provider;
use color_eyre::eyre::Result;
use safe_rs::ParentHeader;

use crate::cli::RotateArgs;
use crate::commands::default_safe::{read_default_safe, recorded_safe};
use crate::commands::http_provider;
use crate::commands::rotation::{self, RotationRun};
use crate::wallet::{create_payer, legacy_signer, open_wallet};

/// `safe rotate`: swap the Safe's owner for the HD wallet's next unused key,
/// with no other calls.
///
/// With a `--from-*` option the current owner is a key outside the wallet,
/// which is how an existing Safe is moved onto it.
pub async fn run(args: RotateArgs, json: bool) -> Result<()> {
    let legacy_owner = legacy_signer(
        args.from_private_key.as_deref(),
        args.from_keystore.as_deref(),
        args.from_interactive,
    )?;
    let payer = create_payer(&args.payer)?;
    let ring = open_wallet(&args.hd, &args.password).await?;
    let safe = if let Some(safe) = args.safe {
        safe
    } else {
        let provider = http_provider(&args.rpc.rpc_url);
        if let Some(signer) = &legacy_owner {
            let header = ParentHeader::fetch(&provider, BlockId::latest()).await?;
            read_default_safe(&provider, signer.clone(), header.block_id())
                .await?
                .address
        } else {
            recorded_safe(
                ring.state(),
                provider.get_chain_id().await?,
                "`safe rotate <SAFE>`",
            )?
        }
    };
    rotation::run(RotationRun {
        rpc_url: &args.rpc.rpc_url,
        safe,
        ring,
        legacy_owner,
        sweep_legacy: args.sweep_legacy,
        payer,
        sweep: &args.sweep,
        calls: Vec::new(),
        multi_send_call_only: args.multi_send_call_only,
        sim: &args.sim,
        gas_limit: args.gas_limit,
        max_fee_per_gas: args.max_fee_per_gas,
        max_priority_fee_per_gas: args.max_priority_fee_per_gas,
        timeout: args.timeout,
        trace: args.trace,
        simulate_only: args.simulate_only,
        raw_out: None,
        no_submit: false,
        no_confirm: args.no_confirm,
        bundle: args.bundle.clone(),
        merge_bundle: args.merge_bundle.clone(),
        approve_hash: args.approve_hash,
        sign_only: args.sign_only,
        json,
    })
    .await
}
