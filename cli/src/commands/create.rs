use std::fmt::Write as _;
use std::time::Duration;

use alloy::network::{AnyNetwork, Network, TransactionBuilder};
use alloy::primitives::utils::format_ether;
use alloy::primitives::{Address, TxHash, U256};
use alloy::providers::Provider;
use color_eyre::eyre::{bail, eyre, Result};
use safe_rs::rotation::{binding_key, CreationParams, OwnerRef, Reserved, RotatingSafe, StateFile};
use safe_rs::{
    encode_create_proxy_with_nonce, fetch_proxy_creation_code, is_safe_with, predict_safe_address,
    sign_outer_tx, submit_and_wait, ChainAddresses, HdWallet, OuterTxParams, SpecId, Submission,
    WalletBuilder, WalletConfig,
};
use serde::Serialize;

use crate::cli::CreateArgs;
use crate::commands::rotation::{print_warnings, rotation_config};
use crate::commands::{http_provider, HttpProvider};
use crate::output::{confirm_prompt, CreateOutput, OwnerOutput, Report, SweepOutput};
use crate::wallet::{create_payer, create_signer, load_hd_wallet, open_state};

/// Seconds to wait for the deployment receipt.
const DEPLOY_TIMEOUT: u64 = 120;

pub async fn run(args: CreateArgs, json: bool) -> Result<()> {
    if args.hd.hd_wallet.is_some() {
        return run_hd(args, json).await;
    }
    if args.sweep.no_sweep || args.sweep.sweep_reserve.is_some() {
        bail!("--no-sweep and --sweep-reserve only apply with --hd-wallet");
    }
    if args.payer.payer_private_key.is_some() {
        eprintln!("note: the payer key is ignored without --hd-wallet; the signer deploys");
    }

    let signer = create_signer(&args.wallet, &args.password)?;
    let signer_address = signer.address();

    let mut addresses = ChainAddresses::from(args.safe_version);
    if let Some(singleton) = args.singleton {
        addresses.safe_singleton = singleton;
    }
    if let Some(factory) = args.factory {
        addresses.proxy_factory = factory;
    }
    let mut config = WalletConfig::new()
        .with_salt_nonce(args.salt_nonce)
        .with_additional_owners(args.owners.clone())
        .with_threshold(args.threshold)
        .with_addresses(addresses.clone());
    if let Some(handler) = args.fallback_handler {
        config = config.with_fallback_handler(handler);
    }
    config.validate(signer_address)?;
    let owners = config.owners(signer_address);

    let provider = http_provider(&args.rpc.rpc_url);
    let builder = WalletBuilder::new(provider.clone(), signer);
    let safe_address = builder.compute_address(&config).await?;

    if !json {
        println!("Computing Safe address...");
        println!("  Factory: {}", addresses.proxy_factory);
        println!("  Singleton: {}", addresses.safe_singleton);
        println!("  Salt Nonce: {}", args.salt_nonce);
        println!("  Owners: {:?}", owners);
        println!("  Threshold: {}", args.threshold);
        println!();
    }

    let already_deployed =
        is_safe_with(&provider, safe_address, &[addresses.safe_singleton]).await?;
    let output = |tx_hash| CreateOutput {
        safe_address,
        tx_hash,
        owners: owners.clone(),
        threshold: args.threshold,
        already_deployed,
    };

    if args.compute_only || already_deployed {
        if already_deployed && !args.compute_only && !json {
            println!("Safe already deployed at {}", safe_address);
        }
        output(None).print(json);
        return Ok(());
    }

    if !json {
        println!("Safe Address: {}", safe_address);
        println!();
    }

    // Confirm before deployment
    if !args.no_confirm && !json && !confirm_prompt("Deploy new Safe?") {
        println!("Aborted");
        return Ok(());
    }

    let deployment = builder
        .deploy_detailed(args.rpc.rpc_url.clone(), config)
        .await?;
    output(deployment.tx_hash).print(json);

    Ok(())
}

/// The result of `safe create --hd-wallet`.
#[derive(Serialize)]
struct HdCreateOutput {
    safe_address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<TxHash>,
    /// The wallet key that owns the Safe, and the address to send gas money to
    owner: OwnerOutput,
    threshold: u64,
    already_deployed: bool,
    /// The account that deploys and pays
    payer: Address,
    /// ETH moved from the funding key to the owner after deployment
    #[serde(skip_serializing_if = "Option::is_none")]
    sweep: Option<SweepOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

impl Report for HdCreateOutput {
    fn human(&self) -> String {
        let mut s = format!("Safe Address: {}", self.safe_address);
        if self.already_deployed {
            let _ = write!(s, "\n  Status: Already deployed");
        } else if let Some(tx_hash) = self.tx_hash {
            let _ = write!(s, "\n  Tx Hash: {tx_hash}");
        }
        let _ = write!(s, "\n  Threshold: {}", self.threshold);
        let _ = write!(s, "\n  Owner: {}", self.owner);
        if let Some(sweep) = &self.sweep {
            let _ = write!(
                s,
                "\n  Swept: {} ETH from the funding key {} to the owner (tx {})",
                format_ether(sweep.amount),
                sweep.from,
                sweep.tx_hash
            );
        }
        if self.tx_hash.is_some() || self.already_deployed {
            let _ = write!(
                s,
                "\n  Send gas money to: {} (the owner key pays for its one transaction)",
                self.owner.address
            );
        }
        for warning in &self.warnings {
            let _ = write!(s, "\n  Warning: {warning}");
        }
        s
    }
}

/// The contracts and salt a Safe is created with.
struct Creation {
    owner: Reserved,
    params: CreationParams,
}

/// Parses `--same-as <CHAIN_ID>:<SAFE>` into a binding key.
fn same_as_key(value: &str) -> Result<String> {
    let (chain, safe) = value
        .split_once(':')
        .ok_or_else(|| eyre!("--same-as takes <CHAIN_ID>:<SAFE>"))?;
    let chain: u64 = chain
        .parse()
        .map_err(|_| eyre!("--same-as: `{chain}` is not a chain ID"))?;
    let safe: Address = safe
        .parse()
        .map_err(|_| eyre!("--same-as: `{safe}` is not an address"))?;
    Ok(binding_key(chain, safe))
}

/// The next wallet key that has not been used on this chain.
///
/// With `commit` the index is taken (and saved) so no other command hands it
/// out; without it the state is left alone and the address is only a preview.
async fn fresh_owner(
    provider: &HttpProvider,
    wallet: &HdWallet,
    store: &mut StateFile,
    commit: bool,
) -> Result<Reserved> {
    if !commit {
        let index = store.state.next_index;
        return Ok(Reserved {
            index,
            address: wallet.owner_address(index)?,
        });
    }
    loop {
        let candidate = store.state.allocate(|index| wallet.owner_address(index))?;
        store.save()?;
        if provider.get_transaction_count(candidate.address).await? == 0 {
            return Ok(candidate);
        }
        eprintln!(
            "warning: skipping key {}: {} was already used on this chain",
            candidate.index, candidate.address
        );
    }
}

/// `safe create --hd-wallet`: a 1/1 Safe owned by a wallet key that has never
/// signed anything.
///
/// The funding key (or `--payer-private-key`) sends the deployment, so the
/// owner's public key stays unpublished; the funding key's remaining ETH then
/// moves to the owner, which pays for the Safe's first transaction.
async fn run_hd(args: CreateArgs, json: bool) -> Result<()> {
    if args.wallet.is_set() {
        bail!(
            "with --hd-wallet the owner key comes from the wallet: remove --private-key, \
             --keystore and --interactive, and unset PRIVATE_KEY"
        );
    }
    if !args.owners.is_empty() || args.threshold != 1 {
        bail!("a Safe created with --hd-wallet has one owner and threshold 1");
    }

    let explicit_payer = create_payer(&args.payer)?;
    let wallet = load_hd_wallet(&args.hd, &args.password)?;
    let mut store = open_state(&wallet)?;
    let provider = http_provider(&args.rpc.rpc_url);
    let chain_id = provider.get_chain_id().await?;
    let funded_by_wallet = explicit_payer.is_none();
    let payer = explicit_payer.unwrap_or_else(|| wallet.funding().clone());

    let creation = if let Some(same_as) = &args.same_as {
        let key = same_as_key(same_as)?;
        let params = store.state.binding(&key)?.creation.ok_or_else(|| {
            eyre!("{key} was not created by this wallet, so its creation parameters are unknown")
        })?;
        Creation {
            owner: Reserved {
                index: params.owner_index,
                address: wallet.owner_address(params.owner_index)?,
            },
            params,
        }
    } else {
        let defaults = ChainAddresses::from(args.safe_version);
        let owner = fresh_owner(&provider, &wallet, &mut store, !args.compute_only).await?;
        Creation {
            owner,
            params: CreationParams {
                owner_index: owner.index,
                salt_nonce: args.salt_nonce,
                singleton: args.singleton.unwrap_or(defaults.safe_singleton),
                factory: args.factory.unwrap_or(defaults.proxy_factory),
                fallback_handler: args.fallback_handler.unwrap_or(defaults.fallback_handler),
            },
        }
    };
    let Creation { owner, params } = creation;

    let creation_code = fetch_proxy_creation_code(&provider, params.factory).await?;
    let (safe, initializer) = predict_safe_address(
        params.factory,
        params.singleton,
        &[owner.address],
        1,
        params.fallback_handler,
        params.salt_nonce,
        &creation_code,
    );
    let key = binding_key(chain_id, safe);
    let already_deployed = is_safe_with(&provider, safe, &[params.singleton]).await?;

    if !json {
        println!("Computing Safe address...");
        println!("  Factory: {}", params.factory);
        println!("  Singleton: {}", params.singleton);
        println!("  Salt Nonce: {}", params.salt_nonce);
        println!("  Owner: {}", OwnerOutput::from(owner));
        println!("  Payer: {}", payer.address());
        println!("  Safe Address: {safe}");
        println!();
    }
    let output = |tx_hash, sweep, warnings| HdCreateOutput {
        safe_address: safe,
        tx_hash,
        owner: owner.into(),
        threshold: 1,
        already_deployed,
        payer: payer.address(),
        sweep,
        warnings,
    };
    if args.compute_only {
        output(None, None, Vec::new()).print(json);
        return Ok(());
    }

    let sweep = funded_by_wallet && !args.sweep.no_sweep;
    if !already_deployed {
        let prompt = if sweep {
            "Deploy new Safe and move the funding key's remaining ETH to its owner?"
        } else {
            "Deploy new Safe?"
        };
        if !args.no_confirm && !json && !confirm_prompt(prompt) {
            println!("Aborted");
            return Ok(());
        }
    }

    let tx_hash = if already_deployed {
        None
    } else {
        Some(deploy(&provider, chain_id, &payer, &params, initializer, safe).await?)
    };
    if !is_safe_with(&provider, safe, &[params.singleton]).await? {
        bail!("the deployment was mined but there is no Safe at {safe}");
    }

    // Record the Safe only now that it exists.
    if !store.state.safes.contains_key(&key) {
        store.state.bind(
            &key,
            OwnerRef::Derived {
                index: owner.index,
                address: owner.address,
            },
        )?;
        store.state.set_creation(&key, params)?;
        if sweep && tx_hash.is_some() {
            store.state.schedule_sweep(
                &key,
                OwnerRef::Derived {
                    index: 0,
                    address: wallet.id(),
                },
            )?;
        }
    }
    let mut warnings = store.state.cross_check();
    store.save()?;

    let mut config = rotation_config(None, SpecId::OSAKA, 12, DEPLOY_TIMEOUT);
    config.sweep_reserve = args.sweep.sweep_reserve;
    let mut rotating = RotatingSafe::open_with(provider, safe, wallet, store, config).await?;
    let report = rotating.sweep_all().await?;
    for (from, error) in &report.failed {
        warnings.push(format!("a sweep from {from} is still owed: {error}"));
    }
    let swept = report.swept.first().copied().map(SweepOutput::from);
    warnings.extend(rotating.take_warnings());
    if !json {
        print_warnings(&warnings);
    }
    output(tx_hash, swept, warnings).print(json);
    Ok(())
}

/// Sends `createProxyWithNonce` from `payer` and waits for it to be mined.
async fn deploy(
    provider: &HttpProvider,
    chain_id: u64,
    payer: &alloy::signers::local::PrivateKeySigner,
    params: &CreationParams,
    initializer: alloy::primitives::Bytes,
    safe: Address,
) -> Result<TxHash> {
    let from = payer.address();
    let input = encode_create_proxy_with_nonce(params.singleton, initializer, params.salt_nonce);
    let request = <AnyNetwork as Network>::TransactionRequest::default()
        .with_from(from)
        .with_to(params.factory)
        .with_input(input.clone());
    let estimate = provider
        .estimate_gas(request)
        .await
        .map_err(|e| eyre!("cannot estimate the deployment ({from} may need ETH): {e}"))?;
    let fees = provider.estimate_eip1559_fees().await?;
    let outer = sign_outer_tx(
        payer,
        OuterTxParams {
            chain_id,
            from,
            nonce: provider.get_transaction_count(from).await?,
            gas_limit: estimate + estimate / 5,
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            to: params.factory,
            value: U256::ZERO,
            input,
        },
    )
    .await?;
    let submission = submit_and_wait(
        provider,
        &outer,
        Duration::from_secs(DEPLOY_TIMEOUT),
        Duration::from_millis(500),
    )
    .await?;
    match submission {
        Submission::Mined(receipt) if receipt.inner.inner.status() => Ok(outer.tx_hash),
        Submission::Mined(_) => bail!("deployment transaction {} reverted", outer.tx_hash),
        Submission::TimedOut { tx_hash } => bail!(
            "no receipt for deployment {tx_hash} after {DEPLOY_TIMEOUT}s; it may still be \
             pending. Once it is mined, start tracking the Safe with \
             `safe wallet sync --safe {safe}`"
        ),
        Submission::Rejected { reason, .. } => bail!("the node rejected the deployment: {reason}"),
        Submission::Ambiguous { reason } => bail!(
            "the deployment {} may or may not have been broadcast: {reason}",
            outer.tx_hash
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_as_names_a_chain_and_a_safe() {
        let safe = Address::repeat_byte(0x5A);
        assert_eq!(
            same_as_key(&format!("10:{safe}")).unwrap(),
            binding_key(10, safe)
        );
        // Lowercase input resolves to the same key.
        assert_eq!(
            same_as_key(&format!("10:{}", safe.to_string().to_lowercase())).unwrap(),
            binding_key(10, safe)
        );
        for bad in ["", "10", "x:0x00", "10:nope"] {
            assert!(same_as_key(bad).is_err(), "{bad:?}");
        }
    }
}
