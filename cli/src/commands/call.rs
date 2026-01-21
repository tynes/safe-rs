use alloy::network::AnyNetwork;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use color_eyre::eyre::Result;
use safe_rs::{Call, ForkSimulator, Operation};

use crate::cli::CallArgs;
use crate::output::CallOutput;
use crate::sig_parser::encode_function_call;

pub async fn run(args: CallArgs, json: bool) -> Result<()> {
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_http(args.rpc_url.parse()?);

    let safe_address: Address = args.safe.parse()?;
    let to: Address = args.to.parse()?;
    let value: U256 = args.value.parse()?;
    let data = encode_function_call(&args.sig, &args.args)?;

    let chain_id = provider.get_chain_id().await?;

    // For call command, we simulate directly without needing a signer
    let call = Call::new(to, value, data);

    let simulator = ForkSimulator::new(provider, chain_id);

    let result = simulator
        .simulate_call(safe_address, call.to, call.value, call.data, Operation::Call)
        .await?;

    let output = CallOutput {
        success: result.success,
        gas_used: result.gas_used,
        return_data: if !result.return_data.is_empty() {
            Some(format!("0x{}", hex::encode(&result.return_data)))
        } else {
            None
        },
        revert_reason: result.revert_reason,
    };

    output.print(json);

    Ok(())
}
