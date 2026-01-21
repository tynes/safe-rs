use alloy::network::AnyNetwork;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::ProviderBuilder;
use color_eyre::eyre::{eyre, Result};
use safe_rs::{Call, Safe};

use crate::bundle::load_bundle;
use crate::cli::SendArgs;
use crate::output::{confirm_prompt, print_calls_summary, ExecutionOutput, SimulationOutput};
use crate::sig_parser::{encode_function_call, parse_call_spec};
use crate::wallet::create_signer;

pub async fn run(args: SendArgs, json: bool) -> Result<()> {
    // Build the calls based on mode
    let calls = build_calls(&args)?;

    if calls.is_empty() {
        return Err(eyre!("No calls specified"));
    }

    // Create signer
    let signer = create_signer(&args.wallet)?;
    let signer_address = signer.address();

    // Create provider with wallet for transaction signing
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(args.rpc_url.parse()?);

    let safe_address: Address = args.safe.parse()?;

    // Connect to the Safe
    let safe = Safe::connect(provider, signer, safe_address).await?;

    // Verify ownership
    safe.verify_single_owner().await?;

    if !json {
        println!("Safe: {}", safe_address);
        println!("Signer: {}", signer_address);
        println!("Nonce: {}", safe.nonce().await?);
        println!();
        print_calls_summary(&calls, false);
        println!();
    }

    // Build the multicall
    let mut builder = safe.multicall();

    for call in &calls {
        builder = builder.add_raw(call.to, call.value, call.data.clone());
    }

    if args.call_only {
        builder = builder.call_only();
    }

    // Set safe_tx_gas if provided
    if let Some(gas_str) = &args.safe_tx_gas {
        let gas: U256 = gas_str.parse()?;
        builder = builder.with_safe_tx_gas(gas);
    }

    // Handle skip-simulation mode
    if args.skip_simulation {
        if !json {
            println!("Skipping simulation (--skip-simulation)");
            println!();
        }

        // Confirm before execution
        if !args.no_confirm && !json {
            if !confirm_prompt("Execute transaction without simulation?") {
                println!("Aborted");
                return Ok(());
            }
        }

        let result = builder.execute_without_simulation().await?;

        let exec_output = ExecutionOutput {
            tx_hash: result.tx_hash,
            success: result.success,
            gas_used: 0, // Unknown without simulation
        };

        exec_output.print(json);
        return Ok(());
    }

    // Simulate
    let simulated = builder.simulate().await?;

    let sim_output = SimulationOutput {
        success: true,
        gas_used: simulated.gas_used(),
        revert_reason: None,
    };

    if args.simulate_only {
        sim_output.print(json);
        return Ok(());
    }

    if !json {
        sim_output.print(false);
        println!();
    }

    // Confirm before execution
    if !args.no_confirm && !json {
        if !confirm_prompt("Execute transaction?") {
            println!("Aborted");
            return Ok(());
        }
    }

    // Execute
    let result = simulated.execute().await?;

    let exec_output = ExecutionOutput {
        tx_hash: result.tx_hash,
        success: result.success,
        gas_used: sim_output.gas_used,
    };

    exec_output.print(json);

    Ok(())
}

fn build_calls(args: &SendArgs) -> Result<Vec<Call>> {
    // Mode 1: Bundle file
    if let Some(bundle_path) = &args.bundle {
        return load_bundle(bundle_path);
    }

    // Mode 2: Multicall via --call flags
    if !args.calls.is_empty() {
        return args
            .calls
            .iter()
            .map(|spec| {
                let (to, data) = parse_call_spec(spec)?;
                Ok(Call::new(to, U256::ZERO, data))
            })
            .collect();
    }

    // Mode 3: Single call (cast-style)
    let to = args
        .to
        .as_ref()
        .ok_or_else(|| eyre!("Target address required for single call mode"))?;

    let to: Address = to.parse()?;
    let value: U256 = args.value.parse()?;

    // Handle simple ETH transfer (no signature) or function call
    let data = match &args.sig {
        Some(sig) if !sig.is_empty() => encode_function_call(sig, &args.args)?,
        _ => Bytes::new(), // Simple ETH transfer
    };

    Ok(vec![Call::new(to, value, data)])
}
