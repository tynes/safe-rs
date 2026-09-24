//! Harness for tests against a fresh, non-forked Anvil chain.
//!
//! Safe v1.4.1 is deployed from the vendored npm artifacts through Anvil's
//! deterministic CREATE2 deployer, so these tests need no RPC URL.

use std::time::Duration;

use alloy::eips::BlockId;
use alloy::network::{AnyNetwork, EthereumWallet};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use safe_rs::{
    broadcast_raw, sign_outer_tx, wait_for_receipt, BroadcastOutcome, Call, ChainAddresses,
    ChainConfig, ISafe, ISafeProxyFactory, OuterTxParams, PreparedSafeTx, ReceiptWait, Safe,
    SafeTxGasPolicy, SignedOuterTx,
};

/// Anvil's default deterministic CREATE2 deployer (Arachnid).
pub const CREATE2_DEPLOYER: Address = address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

fn artifact_bytecode(name: &str) -> Bytes {
    let path = format!(
        "{}/tests/fixtures/safe-1.4.1/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
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
    pub guard: Address,
}

impl LocalHarness {
    pub async fn new() -> Self {
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
        };
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
        let wallet_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(EthereumWallet::from(self.owner.clone()))
            .connect_http(self.url())
            .erased();
        Safe::new(
            wallet_provider,
            self.owner.clone(),
            safe,
            ChainConfig::with_addresses(self.chain_id, self.addresses.clone()),
        )
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
        let factory = ISafeProxyFactory::new(self.addresses.proxy_factory, &self.provider);
        let creation_code = factory
            .proxyCreationCode()
            .call()
            .await
            .expect("creation code");
        let (predicted, initializer) = safe_rs::predict_safe_address(
            self.addresses.proxy_factory,
            self.addresses.safe_singleton,
            owners,
            threshold,
            self.addresses.fallback_handler,
            U256::from(salt_nonce),
            &creation_code,
        );
        let data = safe_rs::encode_create_proxy_with_nonce(
            self.addresses.safe_singleton,
            initializer,
            U256::from(salt_nonce),
        );
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
        let signed = prepared.sign(&self.owner).await.expect("sign safe tx");
        let nonce = self
            .provider
            .get_transaction_count(self.owner.address())
            .await
            .expect("eoa nonce");
        let base_fee = self
            .provider
            .get_block(BlockId::latest())
            .await
            .expect("block")
            .expect("latest block")
            .header
            .base_fee_per_gas
            .unwrap_or(1);
        sign_outer_tx(
            &self.owner,
            OuterTxParams {
                chain_id: self.chain_id,
                from: self.owner.address(),
                nonce,
                gas_limit,
                max_fee_per_gas: u128::from(base_fee) * 2 + 1_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                to: prepared.safe,
                value: U256::ZERO,
                input: signed.exec_calldata(),
            },
        )
        .await
        .expect("sign outer")
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
