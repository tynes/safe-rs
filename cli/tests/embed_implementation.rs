//! A host CLI that deploys its Safes through its own [`SafeImplementation`],
//! then reads them back with [`safe_rs_cli::info`].
//!
//! Runs against a fresh local Anvil chain with Safe v1.4.1 deployed from the
//! vendored artifacts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness: failures panic"
)]

#[allow(dead_code, reason = "the harness is shared with the library's tests")]
#[path = "../../tests/local/common.rs"]
mod common;

use std::sync::{Arc, Mutex};

use alloy::primitives::{Address, U256};
use common::LocalHarness;
use safe_rs_cli::create::{
    BoxFuture, CreateContext, CreateError, CreateOpts, CreateOutcome, HttpProvider, ResolvedSetup,
    SafeDeployment, SafeImplementation, StandardSafe,
};
use safe_rs_cli::prompt::NoPrompt;
#[cfg(feature = "hd-wallet")]
use safe_rs_cli::OptionsError;
use safe_rs_cli::PrivateKeySigner;

/// A factory of the host's own: always one owner, and its own salt.
#[derive(Clone, Default)]
struct HostFactory {
    /// The owner each plan was asked for
    seen: Arc<Mutex<Vec<Address>>>,
}

const HOST_SALT: u64 = 4242;

impl SafeImplementation for HostFactory {
    fn name(&self) -> &'static str {
        "host"
    }

    fn plan<'a>(
        &'a self,
        provider: &'a HttpProvider,
        setup: &'a ResolvedSetup,
        owner: &'a PrivateKeySigner,
    ) -> BoxFuture<'a, Result<SafeDeployment, CreateError>> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(owner.address());
            if setup.owners.len() != 1 {
                return Err(CreateError::InvalidSetup(
                    "the host factory deploys single-owner Safes".into(),
                ));
            }
            let mut own = setup.clone();
            own.salt_nonce = U256::from(HOST_SALT);
            StandardSafe.plan(provider, &own, owner).await
        })
    }
}

fn opts(h: &LocalHarness, implementation: HostFactory) -> CreateOpts {
    let mut opts = CreateOpts::default().with_implementation(implementation);
    opts.setup.singleton = Some(h.addresses.safe_singleton);
    opts.setup.factory = Some(h.addresses.proxy_factory);
    opts.setup.fallback_handler = Some(h.addresses.fallback_handler);
    opts.no_confirm = true;
    opts
}

#[tokio::test]
async fn a_host_implementation_deploys_the_safe_and_info_shows_its_singleton() {
    let h = LocalHarness::new().await;
    let factory = HostFactory::default();
    let ctx = || {
        CreateContext::new(h.url())
            .with_signer(h.owner.clone())
            .with_prompt(NoPrompt)
    };

    // The standard implementation would put the Safe elsewhere: salt 0.
    let mut standard = opts(&h, factory.clone());
    standard.implementation = Default::default();
    standard.compute_only = true;
    let standard = safe_rs_cli::create::create(ctx(), standard).await.unwrap();

    let mut computed = opts(&h, factory.clone());
    computed.compute_only = true;
    let computed = safe_rs_cli::create::create(ctx(), computed).await.unwrap();
    assert_ne!(computed.safe(), standard.safe());

    let outcome = safe_rs_cli::create::create(ctx(), opts(&h, factory.clone()))
        .await
        .unwrap();
    let CreateOutcome::Deployed {
        safe,
        owners,
        threshold,
        ..
    } = outcome
    else {
        panic!("expected a deployment, got {outcome:?}");
    };
    assert_eq!(safe, computed.safe());
    assert_eq!(owners, vec![h.owner.address()]);
    assert_eq!(threshold, 1);
    assert_eq!(
        *factory.seen.lock().unwrap(),
        vec![h.owner.address(); 2],
        "each plan gets the signer as the owner"
    );

    let info = safe_rs_cli::info(&h.url(), safe, None).await.unwrap();
    assert_eq!(info.address, safe);
    assert_eq!(info.singleton, h.addresses.safe_singleton);
    assert_eq!(info.owners, vec![h.owner.address()]);
    assert_eq!(info.threshold, 1);

    // Running again finds it.
    let again = safe_rs_cli::create::create(ctx(), opts(&h, factory))
        .await
        .unwrap();
    assert!(
        matches!(again, CreateOutcome::AlreadyDeployed { safe: s, .. } if s == safe),
        "{again:?}"
    );
}

#[tokio::test]
async fn a_host_implementation_refuses_setups_it_cannot_deploy() {
    let h = LocalHarness::new().await;
    let mut opts = opts(&h, HostFactory::default());
    opts.setup.owners = vec![Address::repeat_byte(0x22)];
    let ctx = CreateContext::new(h.url())
        .with_signer(h.owner.clone())
        .with_prompt(NoPrompt);
    let error = safe_rs_cli::create::create(ctx, opts).await.unwrap_err();
    assert!(matches!(error, CreateError::InvalidSetup(_)), "{error:?}");
}

#[cfg(feature = "hd-wallet")]
#[tokio::test]
async fn a_host_implementation_is_refused_with_an_hd_wallet() {
    let mut opts = CreateOpts::default().with_implementation(HostFactory::default());
    opts.hd.hd_wallet = Some("demo".into());
    let ctx = CreateContext::new("http://127.0.0.1:9".parse().unwrap()).with_prompt(NoPrompt);
    let error = safe_rs_cli::create::create(ctx, opts).await.unwrap_err();
    assert!(
        matches!(
            error,
            CreateError::Options(OptionsError::Conflict {
                with: "--hd-wallet",
                ..
            })
        ),
        "{error:?}"
    );
}
