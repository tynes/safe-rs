use alloy::eips::BlockId;
use alloy::primitives::Address;
use alloy::providers::Provider;
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::rotation::RotationState;
use safe_rs::ParentHeader;

use crate::cli::RotateArgs;
use crate::commands::default_safe::read_default_safe;
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
            recorded_safe(ring.state(), provider.get_chain_id().await?)?
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
        json,
    })
    .await
}

/// Select only within the connected chain; never guess between wallet bindings.
fn recorded_safe(state: &RotationState, chain_id: u64) -> Result<Address> {
    let mut candidates = Vec::new();
    for key in state.safes.keys() {
        let (chain, safe) = key
            .split_once(':')
            .ok_or_else(|| eyre!("invalid Safe binding {key}"))?;
        let chain: u64 = chain
            .parse()
            .map_err(|_| eyre!("invalid chain ID in Safe binding {key}"))?;
        if chain == chain_id {
            let safe: Address = safe
                .parse()
                .map_err(|_| eyre!("invalid address in Safe binding {key}"))?;
            candidates.push(safe);
        }
    }
    match candidates.as_slice() {
        [safe] => Ok(*safe),
        [] => bail!(
            "No Safe recorded for this wallet on chain {chain_id}. Pass its address with \
             `safe rotate <SAFE>`, or recover its state with \
             `safe wallet sync --safe <SAFE>` using the same wallet and RPC URL"
        ),
        _ => bail!(
            "Multiple Safes recorded for this wallet on chain {chain_id}: {}. \
             Choose one with `safe rotate <SAFE>`",
            candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safe_rs::rotation::{binding_key, OwnerRef};

    #[test]
    fn recorded_safes_are_selected_only_when_unambiguous_on_this_chain() {
        let mut state = RotationState::new(Address::ZERO, 1);
        let first = Address::repeat_byte(1);
        let second = Address::repeat_byte(2);
        let owner = OwnerRef::Derived {
            index: 1,
            address: Address::repeat_byte(3),
        };
        state.bind(&binding_key(10, second), owner).unwrap();
        let before = state.clone();
        let error = recorded_safe(&state, 1).unwrap_err().to_string();
        assert!(error.contains("No Safe recorded"));
        assert!(error.contains("wallet sync"));
        assert_eq!(state, before);

        state.bind(&binding_key(1, first), owner).unwrap();
        assert_eq!(recorded_safe(&state, 1).unwrap(), first);
        assert_eq!(recorded_safe(&state, 10).unwrap(), second);

        state.bind(&binding_key(1, second), owner).unwrap();
        let before = state.clone();
        let error = recorded_safe(&state, 1).unwrap_err().to_string();
        assert!(error.contains("Multiple Safes"));
        assert!(error.contains(&first.to_string()));
        assert!(error.contains(&second.to_string()));
        assert_eq!(state, before);
    }
}
