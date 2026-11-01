use alloy::eips::BlockId;
use alloy::providers::Provider;
use color_eyre::eyre::Result;
use safe_rs::simulation::session::READ_CALL_GAS;
use safe_rs::SimTx;

use crate::cli::CallArgs;
use crate::commands::default_safe::safe_or_default;
use crate::commands::{fork_session, http_provider};
use crate::console::Console;
use crate::output::CallOutput;
use crate::sig_parser::encode_function_call;
use crate::signers::create_signer;

pub async fn run(args: CallArgs, console: &Console) -> Result<()> {
    let provider = http_provider(&args.rpc.rpc_url);
    let data = encode_function_call(&args.sig, &args.args)?;
    let chain_id = provider.get_chain_id().await?;
    let signer = if args.safe.safe.is_none() && args.signer.is_set() {
        Some(create_signer(&args.signer, console).await?)
    } else {
        None
    };
    let safe = safe_or_default(
        &provider,
        args.safe.safe,
        signer.as_ref(),
        args.sim.block.unwrap_or(BlockId::latest()),
        console,
    )
    .await?;

    // The call is made by the Safe itself, as its own transactions would be.
    let mut session = fork_session(provider, chain_id, &args.sim, args.trace).await?;
    let result = session.transact(SimTx::relaxed(
        safe,
        args.to,
        args.value,
        data,
        READ_CALL_GAS,
    ))?;

    console.emit(&CallOutput {
        success: result.success,
        gas_used: result.gas_used,
        return_data: (!result.return_data.is_empty()).then(|| result.return_data.clone()),
        traces: result.format_traces(),
        revert_reason: result.revert_reason,
    });

    Ok(())
}
