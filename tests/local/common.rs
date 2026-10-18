//! Harness for tests against a fresh, non-forked Anvil chain.
//!
//! Safe v1.4.1 (or, with [`LocalHarness::with_version`], v1.5.0) is deployed
//! from the vendored npm artifacts through Anvil's deterministic CREATE2
//! deployer, so these tests need no RPC URL.

use std::time::Duration;

use alloy::eips::eip1559::Eip1559Estimation;
use alloy::eips::BlockId;
use alloy::network::{AnyNetwork, EthereumWallet};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{address, hex, keccak256, Address, Bytes, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use safe_rs::{
    broadcast_raw, sign_outer_tx, wait_for_receipt, BroadcastOutcome, Call, ChainAddresses,
    ChainConfig, ISafe, OuterTxParams, PreparedSafeTx, ReceiptWait, Safe, SafeTxGasPolicy,
    SignedOuterTx,
};

/// Anvil's default deterministic CREATE2 deployer (Arachnid).
pub const CREATE2_DEPLOYER: Address = address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

/// The Safe version [`LocalHarness::new`] deploys.
pub const DEFAULT_VERSION: &str = "1.4.1";

/// The vendored Safe artifacts of `version`. The harness is also compiled into
/// the CLI crate's tests, whose manifest is one directory down.
fn fixtures_dir(version: &str) -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    [manifest.to_path_buf(), manifest.join("..")]
        .into_iter()
        .map(|dir| dir.join(format!("tests/fixtures/safe-{version}")))
        .find(|dir| dir.is_dir())
        .expect("Safe fixtures directory")
}

fn artifact_bytecode(name: &str) -> Bytes {
    artifact_bytecode_of(DEFAULT_VERSION, name)
}

fn artifact_bytecode_of(version: &str, name: &str) -> Bytes {
    let path = fixtures_dir(version).join(format!("{name}.json"));
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read artifact"))
            .expect("parse artifact");
    let hex = json["bytecode"].as_str().expect("bytecode field");
    hex.parse().expect("bytecode hex")
}

/// Runtime code of a contract whose code returns
/// `abi.encode(block.timestamp, block.number, block.basefee, block.prevrandao)`.
pub fn block_probe_initcode() -> Bytes {
    // init: copy the 19-byte runtime (at offset 10) to memory and return it
    // runtime: TIMESTAMP PUSH0 MSTORE NUMBER PUSH1 32 MSTORE BASEFEE PUSH1 64 MSTORE
    //          PREVRANDAO PUSH1 96 MSTORE PUSH1 128 PUSH0 RETURN
    "0x6013600a5f3960135ff3425f5243602052486040524460605260805ff3"
        .parse()
        .expect("hex")
}

/// Init code for a contract that always reverts with `Error("nope")`.
pub fn reverter_initcode() -> Bytes {
    let payload = "08c379a0\
        0000000000000000000000000000000000000000000000000000000000000020\
        0000000000000000000000000000000000000000000000000000000000000004\
        6e6f706500000000000000000000000000000000000000000000000000000000";
    format!("0x606e600a5f39606e5ff36064600a5f3960645ffd{payload}")
        .parse()
        .expect("hex")
}

/// A contract that succeeds on its first call (setting slot 0) and reverts on
/// every call after that.
pub fn one_shot_initcode() -> Bytes {
    // init: copy the 17-byte runtime (at offset 12) to memory and return it
    // runtime: PUSH1 0 SLOAD PUSH1 12 JUMPI PUSH1 1 PUSH1 0 SSTORE STOP
    //          JUMPDEST PUSH1 0 DUP1 REVERT
    "0x6011600c60003960116000f3600054600c576001600055005b600080fd"
        .parse()
        .expect("hex")
}

pub struct LocalHarness {
    pub anvil: AnvilInstance,
    /// Provider without a wallet (raw broadcasts, reads)
    pub provider: DynProvider<AnyNetwork>,
    /// Provider that signs with the deployer key
    pub deployer_provider: DynProvider<AnyNetwork>,
    pub deployer: PrivateKeySigner,
    pub owner: PrivateKeySigner,
    pub chain_id: u64,
    pub addresses: ChainAddresses,
    pub safe_l2: Address,
    /// `DebugTransactionGuard`; in v1.5.0 it is also a module guard
    pub guard: Address,
    /// The Safe version deployed
    pub version: &'static str,
}

impl LocalHarness {
    pub async fn new() -> Self {
        Self::with_version(DEFAULT_VERSION).await
    }

    /// A harness with Safe `version` ("1.4.1" or "1.5.0") deployed.
    pub async fn with_version(version: &'static str) -> Self {
        let anvil = Anvil::new().args(["--hardfork", "osaka"]).spawn();
        let deployer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let owner: PrivateKeySigner = anvil.keys()[1].clone().into();
        let url = anvil.endpoint_url();
        let provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_http(url.clone())
            .erased();
        let deployer_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(EthereumWallet::from(deployer.clone()))
            .connect_http(url)
            .erased();
        let chain_id = provider.get_chain_id().await.expect("chain id");

        let mut harness = Self {
            anvil,
            provider,
            deployer_provider,
            deployer,
            owner,
            chain_id,
            addresses: ChainAddresses::v1_4_1(),
            safe_l2: Address::ZERO,
            guard: Address::ZERO,
            version,
        };
        let artifact_bytecode = |name: &str| artifact_bytecode_of(version, name);
        let singleton = harness.create2(artifact_bytecode("Safe")).await;
        let safe_l2 = harness.create2(artifact_bytecode("SafeL2")).await;
        let proxy_factory = harness.create2(artifact_bytecode("SafeProxyFactory")).await;
        let multi_send_call_only = harness
            .create2(artifact_bytecode("MultiSendCallOnly"))
            .await;
        let fallback_handler = harness
            .create2(artifact_bytecode("CompatibilityFallbackHandler"))
            .await;
        let guard = harness
            .create2(artifact_bytecode("DebugTransactionGuard"))
            .await;
        harness.addresses = ChainAddresses {
            safe_singleton: singleton,
            multi_send: Address::ZERO,
            multi_send_call_only,
            proxy_factory,
            fallback_handler,
        };
        harness.safe_l2 = safe_l2;
        harness.guard = guard;
        harness
    }

    /// A `Safe` client for `safe`, signing and sending as the owner.
    pub fn safe_client(&self, safe: Address) -> Safe<DynProvider<AnyNetwork>> {
        self.safe_client_with(safe, self.addresses.clone())
    }

    /// A `Safe` client for `safe` that batches through `addresses`.
    pub fn safe_client_with(
        &self,
        safe: Address,
        addresses: ChainAddresses,
    ) -> Safe<DynProvider<AnyNetwork>> {
        Safe::new(
            self.owner_provider(),
            self.owner.clone(),
            safe,
            ChainConfig::with_addresses(self.chain_id, addresses),
        )
    }

    /// A provider that signs and sends as the owner.
    pub fn owner_provider(&self) -> DynProvider<AnyNetwork> {
        ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(EthereumWallet::from(self.owner.clone()))
            .connect_http(self.url())
            .erased()
    }

    pub fn url(&self) -> url::Url {
        self.anvil.endpoint_url()
    }

    /// Deploys `initcode` through the CREATE2 deployer with salt zero.
    pub async fn create2(&self, initcode: Bytes) -> Address {
        self.create2_salted(B256::ZERO, initcode).await
    }

    pub async fn create2_salted(&self, salt: B256, initcode: Bytes) -> Address {
        let expected = CREATE2_DEPLOYER.create2(salt, keccak256(&initcode));
        let mut data = salt.to_vec();
        data.extend_from_slice(&initcode);
        let tx = TransactionRequest::default()
            .to(CREATE2_DEPLOYER)
            .input(Bytes::from(data).into());
        self.deployer_provider
            .send_transaction(tx.into())
            .await
            .expect("send create2")
            .get_receipt()
            .await
            .expect("create2 receipt");
        let code = self.provider.get_code_at(expected).await.expect("code");
        assert!(!code.is_empty(), "create2 deployment produced no code");
        expected
    }

    /// Deploys another copy of `MultiSendCallOnly`, at an address set by `salt`.
    pub async fn deploy_multi_send_call_only(&self, salt: B256) -> Address {
        self.create2_salted(
            salt,
            artifact_bytecode_of(self.version, "MultiSendCallOnly"),
        )
        .await
    }

    /// Gives `address` the code of `MultiSendCallOnly`, as on a chain where
    /// the contract is deployed there.
    pub async fn set_multi_send_call_only(&self, address: Address) {
        let code = self
            .provider
            .get_code_at(self.addresses.multi_send_call_only)
            .await
            .expect("code");
        self.provider
            .anvil_set_code(address, code)
            .await
            .expect("set code");
    }

    /// Deploys a Safe singleton whose `VERSION()` reports `version`.
    ///
    /// The code is v1.4.1's with only that string replaced: enough for
    /// whatever reads the version to choose contracts or gate a feature.
    pub async fn deploy_singleton_reporting(&self, version: &str) -> Address {
        assert_eq!(version.len(), "1.4.1".len(), "same length as 1.4.1");
        let initcode = hex::encode(artifact_bytecode("Safe"));
        let reported = hex::encode("1.4.1");
        assert_eq!(initcode.matches(&reported).count(), 1);
        let patched = initcode.replace(&reported, &hex::encode(version));
        self.create2(patched.parse().expect("patched bytecode"))
            .await
    }

    /// Deploys a strict 1/1 Safe for the owner through the factory.
    pub async fn deploy_safe(&self, salt_nonce: u64) -> Address {
        self.deploy_safe_with(&[self.owner.address()], 1, salt_nonce)
            .await
    }

    pub async fn deploy_safe_with(
        &self,
        owners: &[Address],
        threshold: u64,
        salt_nonce: u64,
    ) -> Address {
        self.deploy_safe_on(self.addresses.safe_singleton, owners, threshold, salt_nonce)
            .await
    }

    /// Deploys a Safe that is a proxy for `singleton`.
    pub async fn deploy_safe_on(
        &self,
        singleton: Address,
        owners: &[Address],
        threshold: u64,
        salt_nonce: u64,
    ) -> Address {
        let creation_code =
            safe_rs::fetch_proxy_creation_code(&self.provider, self.addresses.proxy_factory)
                .await
                .expect("creation code");
        let (predicted, initializer) = safe_rs::predict_safe_address(
            self.addresses.proxy_factory,
            singleton,
            owners,
            threshold,
            self.addresses.fallback_handler,
            U256::from(salt_nonce),
            &creation_code,
        );
        let data =
            safe_rs::encode_create_proxy_with_nonce(singleton, initializer, U256::from(salt_nonce));
        let tx = TransactionRequest::default()
            .to(self.addresses.proxy_factory)
            .input(data.into());
        self.deployer_provider
            .send_transaction(tx.into())
            .await
            .expect("send deploy")
            .get_receipt()
            .await
            .expect("deploy receipt");
        predicted
    }

    /// Funds an address with ETH from the deployer.
    pub async fn fund(&self, to: Address, amount: U256) {
        let tx = TransactionRequest::default().to(to).value(amount);
        self.deployer_provider
            .send_transaction(tx.into())
            .await
            .expect("send fund")
            .get_receipt()
            .await
            .expect("fund receipt");
    }

    pub async fn safe_nonce(&self, safe: Address) -> U256 {
        ISafe::new(safe, &self.provider)
            .nonce()
            .call()
            .await
            .expect("nonce")
    }

    /// Prepares and signs a Safe transaction at the current nonce.
    pub async fn prepare(
        &self,
        safe: Address,
        calls: &[Call],
        gas: SafeTxGasPolicy,
    ) -> PreparedSafeTx {
        let nonce = self.safe_nonce(safe).await;
        PreparedSafeTx::call_only_batch(
            self.chain_id,
            safe,
            self.addresses.multi_send_call_only,
            calls,
            nonce,
            gas,
        )
        .expect("prepare")
    }

    /// Signs the outer `execTransaction` from the owner with a fixed gas limit.
    pub async fn sign_exec(&self, prepared: &PreparedSafeTx, gas_limit: u64) -> SignedOuterTx {
        self.sign_exec_with(prepared, &self.owner, &self.owner, gas_limit)
            .await
    }

    /// EIP-1559 fees that clear the next block's base fee.
    pub async fn fees(&self) -> Eip1559Estimation {
        let base_fee = self
            .provider
            .get_block(BlockId::latest())
            .await
            .expect("block")
            .expect("latest block")
            .header
            .base_fee_per_gas
            .unwrap_or(1);
        Eip1559Estimation {
            max_fee_per_gas: u128::from(base_fee) * 2 + 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        }
    }

    /// Signs the Safe transaction with `owner` and the outer `execTransaction`
    /// with `payer`, with a fixed gas limit.
    pub async fn sign_exec_with(
        &self,
        prepared: &PreparedSafeTx,
        owner: &PrivateKeySigner,
        payer: &PrivateKeySigner,
        gas_limit: u64,
    ) -> SignedOuterTx {
        let signed = prepared.sign(owner).await.expect("sign safe tx");
        let nonce = self
            .provider
            .get_transaction_count(payer.address())
            .await
            .expect("eoa nonce");
        let fees = self.fees().await;
        let params =
            OuterTxParams::exec_transaction(&signed, payer.address(), nonce, gas_limit, fees);
        sign_outer_tx(payer, params).await.expect("sign outer")
    }

    /// The Safe's owners, in list order.
    pub async fn owners(&self, safe: Address) -> Vec<Address> {
        ISafe::new(safe, &self.provider)
            .getOwners()
            .call()
            .await
            .expect("owners")
    }

    /// Broadcasts a signed outer transaction and waits for its receipt.
    pub async fn send(&self, outer: &SignedOuterTx) -> alloy::network::AnyTransactionReceipt {
        let outcome = broadcast_raw(&self.provider, &outer.raw, outer.tx_hash).await;
        assert_eq!(outcome, BroadcastOutcome::Accepted(outer.tx_hash));
        match wait_for_receipt(
            &self.provider,
            outer.tx_hash,
            Duration::from_secs(10),
            Duration::from_millis(50),
        )
        .await
        .expect("wait")
        {
            ReceiptWait::Mined(receipt) => *receipt,
            ReceiptWait::TimedOut { .. } => panic!("receipt timed out"),
        }
    }

    /// Executes a Safe self-call (for example `enableModule`).
    pub async fn exec_self(&self, safe: Address, data: Vec<u8>) {
        let prepared = self
            .prepare(
                safe,
                &[Call::call(safe, Bytes::from(data))],
                SafeTxGasPolicy::Zero,
            )
            .await;
        let outer = self.sign_exec(&prepared, 500_000).await;
        let receipt = self.send(&outer).await;
        assert!(receipt.inner.inner.status(), "self-call reverted");
    }
}

pub fn enable_module_call(module: Address) -> Vec<u8> {
    ISafe::enableModuleCall { module }.abi_encode()
}

pub fn set_guard_call(guard: Address) -> Vec<u8> {
    ISafe::setGuardCall { guard }.abi_encode()
}
