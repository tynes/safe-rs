//! `safe create --hd-wallet` / `--ledger`.

use std::fmt::Write as _;
use std::str::FromStr;

use alloy::primitives::utils::format_ether;
use alloy::primitives::{Address, TxHash};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use safe_rs::rotation::{
    binding_key, CreationParams, Keyring, OwnerRef, Reserved, RotatingSafe, SETUP_LOOKAHEAD,
};
use safe_rs::{is_safe_with, sign_outer_tx};
use serde::Serialize;

use super::{
    deployment, predict, submit, CreateContext, CreateError, CreateOpts, CreateOutcome, OwnerKey,
    SweptEth,
};
use crate::cli::{check_setup, ResolvedSetup};
use crate::commands::rotation::rotation_config;
use crate::commands::{http_provider, latest_sim_spec, HttpProvider};
use crate::console::Console;
use crate::keys::CliKeys;
use crate::output::Report;
use crate::signers::{create_payer, open_wallet};

/// `--same-as <CHAIN_ID>:<SAFE>`: a Safe an HD wallet created on another chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SameAs {
    pub chain_id: u64,
    pub safe: Address,
}

impl SameAs {
    /// The key the wallet's state records the Safe under.
    pub fn key(&self) -> String {
        binding_key(self.chain_id, self.safe)
    }
}

impl FromStr for SameAs {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let (chain, safe) = value
            .split_once(':')
            .ok_or_else(|| "--same-as takes <CHAIN_ID>:<SAFE>".to_string())?;
        let chain_id = chain
            .parse()
            .map_err(|_| format!("--same-as: `{chain}` is not a chain ID"))?;
        let safe = safe
            .parse()
            .map_err(|_| format!("--same-as: `{safe}` is not an address"))?;
        Ok(Self { chain_id, safe })
    }
}

/// Parses `--same-as <CHAIN_ID>:<SAFE>`.
pub fn parse_same_as(value: &str) -> Result<SameAs, String> {
    value.parse()
}

/// The result of `safe create --hd-wallet`.
#[derive(Serialize)]
pub(super) struct HdCreateOutput {
    safe_address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<TxHash>,
    /// The wallet key that owns the Safe, and the address to send gas money to
    owner: OwnerKey,
    owners: Vec<Address>,
    threshold: u64,
    already_deployed: bool,
    /// The account that deploys and pays
    payer: Address,
    /// ETH moved from the funding key to the owner after deployment
    #[serde(skip_serializing_if = "Option::is_none")]
    sweep: Option<SweptEth>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

impl HdCreateOutput {
    /// The document for an outcome with an HD owner key.
    pub(super) fn from_outcome(outcome: &CreateOutcome) -> Option<Self> {
        let doc = match outcome {
            CreateOutcome::Computed {
                safe,
                owners,
                threshold,
                deployed,
                owner_key: Some(owner),
                payer: Some(payer),
            } => Self {
                safe_address: *safe,
                tx_hash: None,
                owner: *owner,
                owners: owners.clone(),
                threshold: *threshold,
                already_deployed: *deployed,
                payer: *payer,
                sweep: None,
                warnings: Vec::new(),
            },
            CreateOutcome::AlreadyDeployed {
                safe,
                owners,
                threshold,
                owner_key: Some(owner),
                payer: Some(payer),
                sweep,
                warnings,
            } => Self {
                safe_address: *safe,
                tx_hash: None,
                owner: *owner,
                owners: owners.clone(),
                threshold: *threshold,
                already_deployed: true,
                payer: *payer,
                sweep: *sweep,
                warnings: warnings.clone(),
            },
            CreateOutcome::Deployed {
                safe,
                tx_hash,
                owners,
                threshold,
                payer,
                owner_key: Some(owner),
                sweep,
                warnings,
            } => Self {
                safe_address: *safe,
                tx_hash: Some(*tx_hash),
                owner: *owner,
                owners: owners.clone(),
                threshold: *threshold,
                already_deployed: false,
                payer: *payer,
                sweep: *sweep,
                warnings: warnings.clone(),
            },
            _ => return None,
        };
        Some(doc)
    }
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
        if self.owners.len() > 1 {
            let _ = write!(s, "\n  Owners:");
            for (i, owner) in self.owners.iter().enumerate() {
                let _ = write!(s, "\n    {}: {}", i + 1, owner);
            }
        }
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

/// The next wallet key that has not been used on this chain, without taking
/// it: the same check [`Keyring::take_unused`] makes, so the address the
/// prompt shows is the one the commit then reserves.
async fn peek_unused(
    provider: &HttpProvider,
    ring: &mut Keyring<CliKeys>,
) -> Result<(Reserved, Vec<String>), CreateError> {
    let mut skipped = Vec::new();
    let mut index = ring.state().next_index;
    loop {
        let address = ring.address(index).await?;
        let nonce = provider.get_transaction_count(address).await?;
        let code = provider.get_code_at(address).await?;
        if nonce == 0 && code.is_empty() {
            return Ok((Reserved { index, address }, skipped));
        }
        skipped.push(format!(
            "skipping key {index}: {address} was already used on this chain"
        ));
        index = index.checked_add(1).ok_or_else(|| {
            CreateError::Other(color_eyre::eyre::eyre!(
                "the wallet has no unused key indices left"
            ))
        })?;
    }
}

/// The setup a recorded Safe was created with, for `--same-as`.
fn setup_of(params: &CreationParams, owner: Address) -> ResolvedSetup {
    let mut owners = vec![owner];
    for &co_owner in &params.additional_owners {
        if !owners.contains(&co_owner) {
            owners.push(co_owner);
        }
    }
    ResolvedSetup {
        owners,
        threshold: params.threshold.max(1),
        salt_nonce: params.salt_nonce,
        singleton: params.singleton,
        factory: params.factory,
        fallback_handler: params.fallback_handler,
    }
}

/// The record of a new Safe's creation, for a later `--same-as`.
fn creation_params(owner_index: u32, setup: &ResolvedSetup) -> CreationParams {
    CreationParams {
        owner_index,
        salt_nonce: setup.salt_nonce,
        singleton: setup.singleton,
        factory: setup.factory,
        fallback_handler: setup.fallback_handler,
        additional_owners: setup.owners.iter().skip(1).copied().collect(),
        threshold: setup.threshold,
    }
}

/// `safe create --hd-wallet` / `--ledger`: a Safe whose first owner is a
/// wallet key that has never signed anything.
///
/// The funding key (or `--payer-private-key`) sends the deployment, so the
/// owner's public key stays unpublished; the funding key's remaining ETH then
/// moves to the owner, which pays for the Safe's first transaction.
///
/// The owner key is previewed, confirmed, and only then reserved, so a
/// declined prompt or `--compute-only` leaves the wallet's next key unused.
/// The wallet's state stays locked throughout.
pub(super) async fn create(
    ctx: CreateContext,
    opts: CreateOpts,
    console: &Console,
) -> Result<CreateOutcome, CreateError> {
    let explicit_payer = create_payer(&opts.payer)?;
    let mut ring = open_wallet(&opts.hd, &opts.password, ctx.home.as_deref(), console).await?;
    let provider = http_provider(&ctx.rpc_url);
    let chain_id = provider.get_chain_id().await?;
    let funded_by_wallet = explicit_payer.is_none();
    let payer = explicit_payer
        .as_ref()
        .map_or_else(|| ring.id(), PrivateKeySigner::address);
    let mut warnings = Vec::new();

    // The owner, and whether it is a new key to reserve once confirmed.
    let (owner, setup, fresh) = if let Some(same_as) = &opts.same_as {
        let key = same_as.key();
        let params = ring
            .state()
            .binding(&key)?
            .creation
            .clone()
            .ok_or_else(|| {
                CreateError::InvalidSetup(format!(
                    "{key} was not created by this wallet, so its creation parameters are unknown"
                ))
            })?;
        let owner = Reserved {
            index: params.owner_index,
            address: ring.address(params.owner_index).await?,
        };
        (owner, setup_of(&params, owner.address), false)
    } else {
        let (owner, skipped) = peek_unused(&provider, &mut ring).await?;
        console.warnings(&skipped);
        warnings.extend(skipped);
        opts.setup
            .validate(owner.address)
            .map_err(CreateError::InvalidSetup)?;
        (owner, opts.setup.resolve(owner.address), true)
    };
    check_setup(&setup.owners, setup.threshold).map_err(CreateError::InvalidSetup)?;

    let (safe, initializer) = predict(&provider, &setup).await?;
    let key = binding_key(chain_id, safe);
    let already_deployed = is_safe_with(&provider, safe, &[setup.singleton]).await?;
    let owner_key = OwnerKey::from(owner);

    let mut details = String::from("Computing Safe address...\n");
    let _ = writeln!(details, "  Factory: {}", setup.factory);
    let _ = writeln!(details, "  Singleton: {}", setup.singleton);
    let _ = writeln!(details, "  Salt Nonce: {}", setup.salt_nonce);
    let _ = writeln!(details, "  Owner: {owner_key}");
    if setup.owners.len() > 1 {
        let _ = writeln!(details, "  Owners: {:?}", setup.owners);
    }
    let _ = writeln!(details, "  Threshold: {}", setup.threshold);
    let _ = writeln!(details, "  Payer: {payer}");
    let _ = writeln!(details, "  Safe Address: {safe}");
    console.line(&details);

    if opts.compute_only {
        return Ok(CreateOutcome::Computed {
            safe,
            owners: setup.owners,
            threshold: setup.threshold,
            deployed: already_deployed,
            owner_key: Some(owner_key),
            payer: Some(payer),
        });
    }

    let sweep = funded_by_wallet && !opts.sweep.no_sweep;
    if !already_deployed && !opts.no_confirm {
        let question = if sweep {
            "Deploy new Safe and move the funding key's remaining ETH to its owner?"
        } else {
            "Deploy new Safe?"
        };
        if !console.confirm(question, details.trim_end()) {
            console.line("Aborted");
            return Ok(CreateOutcome::Aborted { safe });
        }
    }

    // Reserve the key now that the user agreed. Only a key used on chain
    // since the preview can make the commit land elsewhere.
    if fresh {
        let (reserved, skipped) = ring.take_unused(&provider).await?;
        console.warnings(&skipped);
        if reserved != owner {
            return Err(CreateError::OwnerChanged {
                previewed: owner.index,
            });
        }
    }

    let tx_hash = if already_deployed {
        None
    } else {
        let params =
            deployment(&provider, chain_id, payer, &setup, initializer, &opts.fees).await?;
        let outer = match &explicit_payer {
            Some(key) => sign_outer_tx(key, params).await?,
            None => ring.sign_outer_tx(0, ring.id(), params).await?,
        };
        Some(submit(&provider, &outer, safe, opts.fees.timeout, console).await?)
    };
    if let Some(tx_hash) = tx_hash {
        if !is_safe_with(&provider, safe, &[setup.singleton]).await? {
            return Err(CreateError::NotDeployed { safe, tx_hash });
        }
    }

    // Record the Safe only now that it exists.
    let state = &mut ring.store.state;
    if !state.safes.contains_key(&key) {
        state.bind(
            &key,
            OwnerRef::Derived {
                index: owner.index,
                address: owner.address,
            },
        )?;
        state.set_creation(&key, creation_params(owner.index, &setup))?;
        if sweep && tx_hash.is_some() {
            let funding = state.wallet_id;
            state.schedule_sweep(
                &key,
                OwnerRef::Derived {
                    index: 0,
                    address: funding,
                },
            )?;
        }
    }
    let mut late = state.cross_check();
    ring.save()?;
    // Set up the Safe with the next keys at hand.
    ring.look_ahead(SETUP_LOOKAHEAD).await?;

    let spec = latest_sim_spec(&provider, chain_id, None, 12).await?;
    let mut config = rotation_config(None, spec, 12, opts.fees.timeout);
    config.sweep_reserve = opts.sweep.sweep_reserve;
    let mut rotating = RotatingSafe::with_keyring(provider, safe, ring, config).await?;
    let report = rotating.sweep_all().await?;
    for (from, error) in &report.failed {
        late.push(format!("a sweep from {from} is still owed: {error}"));
    }
    let swept = report.swept.first().copied().map(SweptEth::from);
    late.extend(rotating.take_warnings());
    console.warnings(&late);
    warnings.extend(late);

    Ok(match tx_hash {
        Some(tx_hash) => CreateOutcome::Deployed {
            safe,
            tx_hash,
            owners: setup.owners,
            threshold: setup.threshold,
            payer,
            owner_key: Some(owner_key),
            sweep: swept,
            warnings,
        },
        None => CreateOutcome::AlreadyDeployed {
            safe,
            owners: setup.owners,
            threshold: setup.threshold,
            owner_key: Some(owner_key),
            payer: Some(payer),
            sweep: swept,
            warnings,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    #[test]
    fn same_as_names_a_chain_and_a_safe() {
        let safe = Address::repeat_byte(0x5A);
        let parsed = parse_same_as(&format!("10:{safe}")).unwrap();
        assert_eq!(parsed.key(), binding_key(10, safe));
        // Lowercase input resolves to the same key.
        let lower = parse_same_as(&format!("10:{}", safe.to_string().to_lowercase())).unwrap();
        assert_eq!(lower.key(), binding_key(10, safe));
        for bad in ["", "10", "x:0x00", "10:nope"] {
            assert!(parse_same_as(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn creation_params_round_trip_the_setup() {
        let owner = Address::repeat_byte(1);
        let setup = ResolvedSetup {
            owners: vec![owner, Address::repeat_byte(2), Address::repeat_byte(3)],
            threshold: 2,
            salt_nonce: U256::from(9),
            singleton: Address::repeat_byte(4),
            factory: Address::repeat_byte(5),
            fallback_handler: Address::repeat_byte(6),
        };
        let params = creation_params(7, &setup);
        assert_eq!(params.owner_index, 7);
        assert_eq!(setup_of(&params, owner), setup);
    }
}
