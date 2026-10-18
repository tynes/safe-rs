use std::fmt::Write as _;

use alloy::eips::BlockId;
use alloy::primitives::{Address, U256};
use color_eyre::eyre::{bail, Result};
use safe_rs::{
    check_config_post_state, check_new_guards_allow_followup, plan_config, read_safe_state,
    ConfigChanges, ConfigOp, ConfigPlan, ForkSession, ReadSafeStateOptions,
};

use crate::cli::{ConfigArgs, SafeArgs, SendArgs, SweepArgs};
use crate::commands::default_safe::safe_or_default;
use crate::commands::http_provider;
use crate::commands::send::{self, ExecHooks};
use crate::output::Console;
use crate::wallet::create_signer;

pub async fn run(args: ConfigArgs, json: bool) -> Result<()> {
    if args.hd.is_set() && !args.wallet.is_set() {
        bail!(
            "safe config does not rotate owner keys: signing with --hd-wallet or --ledger would \
             publish an owner key and leave it in charge of the Safe. Sign with --private-key, \
             --keystore or --interactive"
        );
    }

    let changes = ConfigChanges {
        add_owners: args.add_owners.clone(),
        remove_owners: args.remove_owners.clone(),
        swap_owners: args.swap_owners.clone(),
        threshold: args.threshold,
        enable_modules: args.enable_modules.clone(),
        disable_modules: args.disable_modules.clone(),
        guard: args.guard,
        fallback_handler: args.fallback_handler,
        module_guard: args.module_guard,
    };
    let signer = if args.wallet.is_set() {
        Some(create_signer(&args.wallet, &args.password)?)
    } else {
        None
    };

    // A co-signer signs the transaction frozen in the bundle instead of
    // planning again: the planned calls depend on the chain state they were
    // planned against.
    if changes.is_empty() {
        if args.bundle.is_none() {
            bail!(
                "nothing to change: pass --add-owner, --remove-owner, --swap-owner, --threshold, \
                 --enable-module, --disable-module, --guard, --fallback-handler or \
                 --module-guard, or --bundle to sign a change planned earlier"
            );
        }
        let hooks = ExecHooks {
            signer,
            post_check: None,
        };
        return send::execute(send_args(args), Vec::new(), hooks, json).await;
    }

    let raw_to_stdout =
        args.raw_out.as_deref() == Some("-") || (args.no_submit && args.raw_out.is_none());
    let console = Console::new(json, raw_to_stdout);

    let provider = http_provider(&args.rpc.rpc_url);
    let safe = safe_or_default(
        &provider,
        args.safe.safe,
        signer.as_ref(),
        BlockId::latest(),
    )
    .await?;
    let state = read_safe_state(
        &provider,
        safe,
        BlockId::latest(),
        ReadSafeStateOptions::default(),
    )
    .await?;
    let plan = plan_config(&state, &changes)?;
    console.line(describe(&plan));
    if let Some(signer) = &signer {
        let leaving = plan.before.owners.contains(&signer.address())
            && !plan.after.owners.contains(&signer.address());
        if leaving {
            console.line(format!(
                "WARNING: this removes the signer {} as an owner",
                signer.address()
            ));
        }
    }
    let new_guard = plan.ops.iter().any(|op| match op {
        ConfigOp::SetGuard { guard } => *guard != Address::ZERO,
        ConfigOp::SetModuleGuard { module_guard } => *module_guard != Address::ZERO,
        _ => false,
    });
    if new_guard && args.allow_unchecked_guard {
        console.line(
            "WARNING: --allow-unchecked-guard: a new guard that rejects every transaction \
             would lock the Safe for good",
        );
    } else if new_guard && args.skip_simulation {
        bail!(
            "--skip-simulation would install a new guard unchecked: a guard that rejects \
             every transaction locks the Safe for good. Simulate, or pass \
             --allow-unchecked-guard to install it anyway"
        );
    }
    console.line("");

    let check_guards = new_guard && !args.allow_unchecked_guard;
    let check = |post: &mut ForkSession| {
        check_config_post_state(post, &plan)?;
        if check_guards {
            check_new_guards_allow_followup(post, &plan).map_err(|e| match e {
                safe_rs::Error::Config(message) => safe_rs::Error::Config(format!(
                    "{message}. Pass --allow-unchecked-guard to install it anyway"
                )),
                e => e,
            })?;
        }
        Ok(())
    };
    let hooks = ExecHooks {
        signer,
        post_check: Some(&check),
    };
    let mut send_args = send_args(args);
    send_args.safe.safe = Some(safe);
    send::execute(send_args, plan.calls(), hooks, json).await
}

/// The planned changes and the configuration they lead to, for the console.
fn describe(plan: &ConfigPlan) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "Configuration changes for Safe {}:", plan.safe);
    for (i, op) in plan.ops.iter().enumerate() {
        let _ = writeln!(s, "  {}. {op}", i + 1);
    }
    let owner_change = plan.ops.iter().any(|op| {
        !matches!(
            op,
            ConfigOp::EnableModule { .. } | ConfigOp::DisableModule { .. }
        )
    });
    if owner_change || plan.before.threshold != plan.after.threshold {
        let _ = writeln!(
            s,
            "Threshold: {} of {} -> {} of {}",
            plan.before.threshold,
            plan.before.owners.len(),
            plan.after.threshold,
            plan.after.owners.len()
        );
    }
    if plan.before.owners != plan.after.owners {
        let _ = writeln!(s, "Owners after:");
        for (i, owner) in plan.after.owners.iter().enumerate() {
            let _ = writeln!(s, "  {}: {owner}", i + 1);
        }
    }
    s.truncate(s.trim_end().len());
    s
}

/// The `send` arguments that run the planned calls: always through
/// MultiSendCallOnly, fail-closed (`safeTxGas = 0`) and without rotation.
fn send_args(args: ConfigArgs) -> SendArgs {
    SendArgs {
        to: None,
        sig: None,
        args: Vec::new(),
        safe: SafeArgs {
            safe: args.safe.safe,
        },
        rpc: args.rpc,
        value: U256::ZERO,
        calls: Vec::new(),
        bundle: args.bundle,
        merge_bundle: args.merge_bundle,
        approve_hash: args.approve_hash,
        sign_only: args.sign_only,
        call_only: true,
        simulate_only: args.simulate_only,
        skip_simulation: args.skip_simulation,
        safe_tx_gas: None,
        nonce: args.nonce,
        gas_limit: args.gas_limit,
        max_fee_per_gas: args.max_fee_per_gas,
        max_priority_fee_per_gas: args.max_priority_fee_per_gas,
        raw_out: args.raw_out,
        no_submit: args.no_submit,
        timeout: args.timeout,
        trace: args.trace,
        sim: args.sim,
        multi_send: None,
        multi_send_call_only: args.multi_send_call_only,
        no_confirm: args.no_confirm,
        rotate: false,
        hd: args.hd,
        sweep: SweepArgs::default(),
        wallet: args.wallet,
        password: args.password,
        payer: args.payer,
    }
}
