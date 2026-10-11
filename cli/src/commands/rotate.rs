use color_eyre::eyre::Result;

use crate::cli::RotateArgs;
use crate::commands::rotation::{self, RotationRun};
use crate::wallet::{create_payer, legacy_signer, load_hd_wallet, open_state};

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
    let wallet = load_hd_wallet(&args.hd, &args.password)?;
    let store = open_state(&wallet)?;
    rotation::run(RotationRun {
        rpc_url: &args.rpc.rpc_url,
        safe: args.safe.safe,
        wallet,
        store,
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
        json,
    })
    .await
}
