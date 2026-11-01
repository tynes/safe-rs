//! How a Safe gets deployed: the standard Safe proxy factory, or a factory a
//! host CLI brings.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use alloy::primitives::{Address, Bytes};
use alloy::signers::local::PrivateKeySigner;
use safe_rs::encode_create_proxy_with_nonce;

use super::{predict, CreateError};
pub use crate::cli::ResolvedSetup;
pub use crate::commands::HttpProvider;

/// A boxed future, as [`SafeImplementation::plan`] returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The Safe a deployment creates, and the transaction that creates it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeDeployment {
    /// The address the Safe will have
    pub safe: Address,
    /// Its owners once deployed
    pub owners: Vec<Address>,
    pub threshold: u64,
    /// The implementation (singleton) the proxy delegates to. After the
    /// deployment is mined, `create` checks that a Safe using it is there.
    pub singleton: Address,
    /// The contract the deployment transaction calls
    pub to: Address,
    /// The deployment transaction's calldata
    pub input: Bytes,
}

/// How `create` deploys a Safe.
///
/// [`StandardSafe`], the default, calls `createProxyWithNonce` on the Safe
/// proxy factory with the `--owner`, `--threshold`, `--salt-nonce` and
/// contract options. A CLI whose Safes come from another factory implements
/// this trait and sets it on [`CreateOpts::implementation`](super::CreateOpts),
/// and `create` handles the preview, confirmation, payer, fees, broadcast
/// and checks as usual.
pub trait SafeImplementation: Send + Sync {
    /// A short name for progress output, such as "standard".
    fn name(&self) -> &str;

    /// The Safe `setup` deploys and its deployment transaction. `owner` is
    /// the first owner (the signer); an implementation that needs the owner
    /// to authorize the deployment signs with it. Refuse a setup the factory
    /// cannot deploy (more owners, a salt) with
    /// [`CreateError::InvalidSetup`] rather than ignore it.
    fn plan<'a>(
        &'a self,
        provider: &'a HttpProvider,
        setup: &'a ResolvedSetup,
        owner: &'a PrivateKeySigner,
    ) -> BoxFuture<'a, Result<SafeDeployment, CreateError>>;
}

/// The Safe proxy factory's `createProxyWithNonce`, with the setup's factory,
/// singleton, owners, threshold, fallback handler and salt.
#[derive(Clone, Copy, Debug, Default)]
pub struct StandardSafe;

impl SafeImplementation for StandardSafe {
    fn name(&self) -> &'static str {
        "standard"
    }

    fn plan<'a>(
        &'a self,
        provider: &'a HttpProvider,
        setup: &'a ResolvedSetup,
        _owner: &'a PrivateKeySigner,
    ) -> BoxFuture<'a, Result<SafeDeployment, CreateError>> {
        Box::pin(async move {
            let (safe, initializer) = predict(provider, setup).await?;
            Ok(SafeDeployment {
                safe,
                owners: setup.owners.clone(),
                threshold: setup.threshold,
                singleton: setup.singleton,
                to: setup.factory,
                input: encode_create_proxy_with_nonce(
                    setup.singleton,
                    initializer,
                    setup.salt_nonce,
                ),
            })
        })
    }
}

/// Which [`SafeImplementation`] `create` uses: [`StandardSafe`] unless a host
/// sets its own. Not a flag; set it in code.
#[derive(Clone, Default)]
pub struct Implementation(Option<Arc<dyn SafeImplementation>>);

impl Implementation {
    /// [`StandardSafe`].
    pub fn standard() -> Self {
        Self(None)
    }

    /// Deploys with `implementation` instead of the standard factory.
    pub fn custom(implementation: impl SafeImplementation + 'static) -> Self {
        Self(Some(Arc::new(implementation)))
    }

    /// Whether this is [`StandardSafe`].
    pub fn is_standard(&self) -> bool {
        self.0.is_none()
    }

    /// The implementation to deploy with.
    pub fn get(&self) -> &dyn SafeImplementation {
        match &self.0 {
            Some(implementation) => implementation.as_ref(),
            None => &StandardSafe,
        }
    }
}

impl fmt::Debug for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Implementation")
            .field(&self.get().name())
            .finish()
    }
}
