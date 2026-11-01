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

/// A host policy that keeps the owners: it sees the plan and the simulated
/// Safe, and refuses what it cannot check.
struct KeepOwners {
    seen: Arc<Mutex<Vec<(usize, bool)>>>,
}

impl safe_rs_cli::policy::SafePolicy for KeepOwners {
    fn name(&self) -> &'static str {
        "keep owners"
    }

    fn check(&self, tx: &safe_rs_cli::policy::SafeTxCheck<'_>) -> bool {
        use safe_rs_cli::policy::Plan;
        let simulate_only = matches!(tx.plan, Plan::Send(opts) if opts.simulate.simulate_only);
        self.seen
            .lock()
            .unwrap()
            .push((tx.calls.len(), simulate_only));
        assert_eq!(tx.prepared.safe, tx.before.address);
        tx.after
            .is_some_and(|after| after.owners == tx.before.owners)
    }
}

/// A host policy that looks something up before it decides.
struct AsyncNo;

impl safe_rs_cli::policy::SafePolicy for AsyncNo {
    fn name(&self) -> &'static str {
        "async no"
    }

    fn check_async<'a>(
        &'a self,
        tx: &'a safe_rs_cli::policy::SafeTxCheck<'a>,
    ) -> safe_rs_cli::policy::BoxFuture<'a, bool> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            tx.calls.is_empty()
        })
    }
}

/// A policy sees each Safe transaction with the simulated Safe, and its
/// `false` stops it.
#[tokio::test(flavor = "multi_thread")]
async fn a_policy_decides_from_the_plan_and_the_simulated_safe() {
    use alloy::sol_types::SolCall as _;
    use safe_rs_cli::args::SendOpts;
    use safe_rs_cli::policy::SafePolicy;
    use safe_rs_cli::safe_rs::{Bytes, Call, ISafe};
    use safe_rs_cli::{SendContext, SendError, SendOutcome};

    let h = LocalHarness::new().await;
    let safe = h.deploy_safe(77).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ctx = |policy: Box<dyn SafePolicy>| {
        SendContext::new(h.url(), safe)
            .with_signer(h.owner.clone())
            .with_prompt(NoPrompt)
            .with_policy(policy)
    };
    let keep = || -> Box<dyn SafePolicy> { Box::new(KeepOwners { seen: seen.clone() }) };
    let opts = || {
        let mut opts = SendOpts::default();
        opts.simulate.simulate_only = true;
        opts
    };
    let plain = || {
        vec![Call::new(
            Address::repeat_byte(0x42),
            U256::ZERO,
            Bytes::new(),
        )]
    };

    let outcome = safe_rs_cli::send(ctx(keep()), plain(), opts())
        .await
        .unwrap();
    assert!(
        matches!(outcome, SendOutcome::Simulated { .. }),
        "{outcome:?}"
    );
    assert_eq!(*seen.lock().unwrap(), [(1, true)]);

    let add_owner = ISafe::addOwnerWithThresholdCall {
        owner: Address::repeat_byte(0x43),
        _threshold: U256::from(1),
    };
    let calls = vec![Call::new(
        safe,
        U256::ZERO,
        Bytes::from(add_owner.abi_encode()),
    )];
    let error = safe_rs_cli::send(ctx(keep()), calls, opts())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, SendError::PolicyRefused { policy } if policy == "keep owners"),
        "{error:?}"
    );

    // Without a simulation there is no Safe after, which this policy refuses.
    let mut unchecked = opts();
    unchecked.simulate.simulate_only = false;
    unchecked.skip_simulation = true;
    unchecked.no_confirm = true;
    let error = safe_rs_cli::send(ctx(keep()), plain(), unchecked)
        .await
        .unwrap_err();
    assert!(
        matches!(error, SendError::PolicyRefused { .. }),
        "{error:?}"
    );

    // The async check runs too.
    let error = safe_rs_cli::send(ctx(Box::new(AsyncNo)), plain(), opts())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, SendError::PolicyRefused { policy } if policy == "async no"),
        "{error:?}"
    );
}

/// A rotation goes through the policy too, with its plan: the owners it swaps
/// and the owners it leaves.
#[cfg(feature = "hd-wallet")]
#[tokio::test(flavor = "multi_thread")]
async fn a_policy_sees_a_rotation_plan() {
    use safe_rs_cli::args::{PasswordArgs, SendOpts};
    use safe_rs_cli::policy::{Plan, SafePolicy, SafeTxCheck};
    use safe_rs_cli::safe_rs::{Bytes, Call, HdWallet};
    use safe_rs_cli::wallet::{self, WalletContext};
    use safe_rs_cli::{SendContext, SendError, SendOutcome};

    const PHRASE: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    /// Allows everything but a rotation, which it tells from the plan.
    struct NoRotation;

    impl SafePolicy for NoRotation {
        fn name(&self) -> &'static str {
            "no rotation"
        }

        fn check(&self, tx: &SafeTxCheck<'_>) -> bool {
            !matches!(tx.plan, Plan::Rotation(_))
        }
    }

    /// Allows a rotation that leaves one owner other than the old one.
    struct SeesRotation {
        seen: Arc<Mutex<Vec<Vec<Address>>>>,
    }
    impl SafePolicy for SeesRotation {
        fn name(&self) -> &'static str {
            "sees rotation"
        }
        fn check(&self, tx: &SafeTxCheck<'_>) -> bool {
            let Plan::Rotation(plan) = tx.plan else {
                return false;
            };
            let after = tx.after.expect("a rotation's planned owners");
            *self.seen.lock().unwrap() = vec![tx.before.owners.clone(), after.owners.clone()];
            plan.expected_owners == after.owners && after.owners != tx.before.owners
        }
    }

    let h = LocalHarness::new().await;
    let home = tempfile::tempdir().unwrap();
    let wallet_ctx = WalletContext::new()
        .with_home(home.path().to_path_buf())
        .with_prompt(NoPrompt);
    wallet::import_wallet(&wallet_ctx, "demo", PHRASE, "pw", None).unwrap();
    let owner = HdWallet::from_phrase(PHRASE)
        .unwrap()
        .owner_address(1)
        .unwrap();
    let safe = h
        .deploy_safe_on(h.addresses.safe_singleton, &[owner], 1, 503)
        .await;
    h.fund(owner, U256::from(10).pow(U256::from(18))).await;

    let opts = || {
        let mut opts = SendOpts {
            rotate: true,
            ..SendOpts::default()
        };
        opts.hd.hd_wallet = Some("demo".into());
        opts.password = PasswordArgs {
            password: Some("pw".into()),
            ..PasswordArgs::default()
        };
        opts.simulate.simulate_only = true;
        opts
    };
    let calls = || {
        vec![Call::new(
            Address::repeat_byte(0x42),
            U256::ZERO,
            Bytes::new(),
        )]
    };
    let ctx = |policy: Box<dyn SafePolicy>| {
        SendContext::new(h.url(), safe)
            .with_home(home.path().to_path_buf())
            .with_prompt(NoPrompt)
            .with_policy(policy)
    };

    let error = safe_rs_cli::send(ctx(Box::new(NoRotation)), calls(), opts())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, SendError::PolicyRefused { policy } if policy == "no rotation"),
        "{error:?}"
    );

    let seen = Arc::new(Mutex::new(Vec::new()));
    let outcome = safe_rs_cli::send(
        ctx(Box::new(SeesRotation { seen: seen.clone() })),
        calls(),
        opts(),
    )
    .await
    .unwrap();
    assert!(
        matches!(outcome, SendOutcome::Simulated { .. }),
        "{outcome:?}"
    );
    let seen = seen.lock().unwrap().clone();
    let [before, after] = &seen[..] else {
        panic!("the policy did not see the rotation: {seen:?}");
    };
    assert_eq!(before, &[owner]);
    assert_eq!(after.len(), 1);
    assert_ne!(after, before);
}
