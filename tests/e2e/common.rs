//! Common test utilities for E2E tests

use alloy::network::{AnyNetwork, EthereumWallet};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use safe_rs::{compute_create2_address, encode_setup_call, ChainAddresses, ISafeProxyFactory, Safe};

/// Macro to skip tests when ETH_RPC_URL is not set
#[macro_export]
macro_rules! skip_if_no_rpc {
    () => {
        if std::env::var("ETH_RPC_URL").is_err() {
            eprintln!("Skipping test: ETH_RPC_URL not set");
            return;
        }
    };
}

// MockERC20 contract definition with bytecode for testing
// Compiled with Solidity 0.8.25 targeting Cancun EVM
sol! {
    #[sol(rpc, bytecode = "60806040526040518060400160405280600981526020017f4d6f636b546f6b656e00000000000000000000000000000000000000000000008152505f908161004791906102f3565b506040518060400160405280600481526020017f4d4f434b000000000000000000000000000000000000000000000000000000008152506001908161008c91906102f3565b50601260025f6101000a81548160ff021916908360ff1602179055503480156100b3575f80fd5b506103c2565b5f81519050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f600282049050600182168061013457607f821691505b602082108103610147576101466100f0565b5b50919050565b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f600883026101a97fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8261016e565b6101b3868361016e565b95508019841693508086168417925050509392505050565b5f819050919050565b5f819050919050565b5f6101f76101f26101ed846101cb565b6101d4565b6101cb565b9050919050565b5f819050919050565b610210836101dd565b61022461021c826101fe565b84845461017a565b825550505050565b5f90565b61023861022c565b610243818484610207565b505050565b5b818110156102665761025b5f82610230565b600181019050610249565b5050565b601f8211156102ab5761027c8161014d565b6102858461015f565b81016020851015610294578190505b6102a86102a08561015f565b830182610248565b50505b505050565b5f82821c905092915050565b5f6102cb5f19846008026102b0565b1980831691505092915050565b5f6102e383836102bc565b9150826002028217905092915050565b6102fc826100b9565b67ffffffffffffffff811115610315576103146100c3565b5b61031f825461011d565b61032a82828561026a565b5f60209050601f83116001811461035b575f8415610349578287015190505b61035385826102d8565b8655506103ba565b601f1984166103698661014d565b5f5b828110156103905784890151825560018201915060208501945060208101905061036b565b868310156103ad57848901516103a9601f8916826102bc565b8355505b6001600288020188555050505b505050505050565b610f6a806103cf5f395ff3fe608060405234801561000f575f80fd5b50600436106100a7575f3560e01c806340c10f191161006f57806340c10f191461016557806370a082311461018157806395d89b41146101b1578063a9059cbb146101cf578063da46098c146101ff578063dd62ed3e1461021b576100a7565b806306fdde03146100ab578063095ea7b3146100c957806318160ddd146100f957806323b872dd14610117578063313ce56714610147575b5f80fd5b6100b361024b565b6040516100c09190610b3d565b60405180910390f35b6100e360048036038101906100de9190610bee565b6102d6565b6040516100f09190610c46565b60405180910390f35b6101016103c3565b60405161010e9190610c6e565b60405180910390f35b610131600480360381019061012c9190610c87565b6103c9565b60405161013e9190610c46565b60405180910390f35b61014f6106a9565b60405161015c9190610cf2565b60405180910390f35b61017f600480360381019061017a9190610bee565b6106bb565b005b61019b60048036038101906101969190610d0b565b61078f565b6040516101a89190610c6e565b60405180910390f35b6101b96107a4565b6040516101c69190610b3d565b60405180910390f35b6101e960048036038101906101e49190610bee565b610830565b6040516101f69190610c46565b60405180910390f35b61021960048036038101906102149190610c87565b6109c6565b005b61023560048036038101906102309190610d36565b610aad565b6040516102429190610c6e565b60405180910390f35b5f805461025790610da1565b80601f016020809104026020016040519081016040528092919081815260200182805461028390610da1565b80156102ce5780601f106102a5576101008083540402835291602001916102ce565b820191905f5260205f20905b8154815290600101906020018083116102b157829003601f168201915b505050505081565b5f8160055f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516103b19190610c6e565b60405180910390a36001905092915050565b60035481565b5f8160045f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2054101561044a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161044190610e1b565b60405180910390fd5b8160055f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20541015610505576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104fc90610e83565b60405180910390fd5b8160055f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825461058c9190610ece565b925050819055508160045f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546105df9190610ece565b925050819055508160045f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546106329190610f01565b925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516106969190610c6e565b60405180910390a3600190509392505050565b60025f9054906101000a900460ff1681565b8060045f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546107079190610f01565b925050819055508060035f82825461071f9190610f01565b925050819055508173ffffffffffffffffffffffffffffffffffffffff165f73ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516107839190610c6e565b60405180910390a35050565b6004602052805f5260405f205f915090505481565b600180546107b190610da1565b80601f01602080910402602001604051908101604052809291908181526020018280546107dd90610da1565b80156108285780601f106107ff57610100808354040283529160200191610828565b820191905f5260205f20905b81548152906001019060200180831161080b57829003601f168201915b505050505081565b5f8160045f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205410156108b1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108a890610e1b565b60405180910390fd5b8160045f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546108fd9190610ece565b925050819055508160045f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546109509190610f01565b925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516109b49190610c6e565b60405180910390a36001905092915050565b8060055f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92583604051610aa09190610c6e565b60405180910390a3505050565b6005602052815f5260405f20602052805f5260405f205f91509150505481565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f610b0f82610acd565b610b198185610ad7565b9350610b29818560208601610ae7565b610b3281610af5565b840191505092915050565b5f6020820190508181035f830152610b558184610b05565b905092915050565b5f80fd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610b8a82610b61565b9050919050565b610b9a81610b80565b8114610ba4575f80fd5b50565b5f81359050610bb581610b91565b92915050565b5f819050919050565b610bcd81610bbb565b8114610bd7575f80fd5b50565b5f81359050610be881610bc4565b92915050565b5f8060408385031215610c0457610c03610b5d565b5b5f610c1185828601610ba7565b9250506020610c2285828601610bda565b9150509250929050565b5f8115159050919050565b610c4081610c2c565b82525050565b5f602082019050610c595f830184610c37565b92915050565b610c6881610bbb565b82525050565b5f602082019050610c815f830184610c5f565b92915050565b5f805f60608486031215610c9e57610c9d610b5d565b5b5f610cab86828701610ba7565b9350506020610cbc86828701610ba7565b9250506040610ccd86828701610bda565b9150509250925092565b5f60ff82169050919050565b610cec81610cd7565b82525050565b5f602082019050610d055f830184610ce3565b92915050565b5f60208284031215610d2057610d1f610b5d565b5b5f610d2d84828501610ba7565b91505092915050565b5f8060408385031215610d4c57610d4b610b5d565b5b5f610d5985828601610ba7565b9250506020610d6a85828601610ba7565b9150509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f6002820490506001821680610db857607f821691505b602082108103610dcb57610dca610d74565b5b50919050565b7f496e73756666696369656e742062616c616e63650000000000000000000000005f82015250565b5f610e05601483610ad7565b9150610e1082610dd1565b602082019050919050565b5f6020820190508181035f830152610e3281610df9565b9050919050565b7f496e73756666696369656e7420616c6c6f77616e6365000000000000000000005f82015250565b5f610e6d601683610ad7565b9150610e7882610e39565b602082019050919050565b5f6020820190508181035f830152610e9a81610e61565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610ed882610bbb565b9150610ee383610bbb565b9250828203905081811115610efb57610efa610ea1565b5b92915050565b5f610f0b82610bbb565b9150610f1683610bbb565b9250828201905080821115610f2e57610f2d610ea1565b5b9291505056fea26469706673582212205cc918f26a29c2de22d10670a161d8606f1e7847573aa076c606c6fc01e1ae9f64736f6c63430008190033")]
    contract MockERC20 {
        function name() external view returns (string memory);
        function symbol() external view returns (string memory);
        function decimals() external view returns (uint8);
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function mint(address to, uint256 amount) external;
        function setAllowance(address owner, address spender, uint256 amount) external;

        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
    }
}

/// Type alias for the wallet provider used in tests
pub type TestProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::fillers::WalletFiller<EthereumWallet>,
    >,
    alloy::providers::RootProvider<AnyNetwork>,
    AnyNetwork,
>;

/// Test harness that spawns Anvil with forking and provides a provider + signer
pub struct TestHarness {
    pub provider: TestProvider,
    pub signer: PrivateKeySigner,
    pub addresses: ChainAddresses,
    pub _anvil: AnvilInstance,
}

impl TestHarness {
    /// Creates a new test harness with Anvil forking from ETH_RPC_URL
    ///
    /// Supports optional environment variables for rate limiting:
    /// - `ANVIL_COMPUTE_UNITS_PER_SECOND`: Compute units per second (default: 330)
    /// - `ANVIL_RETRIES`: Number of retries for RPC requests (default: 5)
    /// - `ANVIL_TIMEOUT`: Timeout in milliseconds for RPC requests (default: 20000)
    pub async fn new() -> Self {
        let rpc_url = std::env::var("ETH_RPC_URL").expect("ETH_RPC_URL must be set");

        // Build Anvil args based on environment variables
        let mut args = vec!["--hardfork".to_string(), "cancun".to_string()];

        if let Ok(cus) = std::env::var("ANVIL_COMPUTE_UNITS_PER_SECOND") {
            args.push("--compute-units-per-second".to_string());
            args.push(cus);
        }

        if let Ok(retries) = std::env::var("ANVIL_RETRIES") {
            args.push("--retries".to_string());
            args.push(retries);
        }

        if let Ok(timeout) = std::env::var("ANVIL_TIMEOUT") {
            args.push("--timeout".to_string());
            args.push(timeout);
        }

        // Spawn Anvil with forking (use cancun hardfork for PUSH0 opcode support)
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let anvil = Anvil::new()
            .fork(rpc_url)
            .args(args_ref)
            .spawn();

        // Get the first default account's private key
        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();

        // Build wallet provider (required for sending transactions)
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(wallet)
            .connect_http(anvil.endpoint_url());

        Self {
            provider,
            signer,
            addresses: ChainAddresses::v1_4_1(),
            _anvil: anvil,
        }
    }

    /// Returns the signer address
    pub fn signer_address(&self) -> Address {
        self.signer.address()
    }

    /// Deploys a new Safe with the given owners and threshold
    pub async fn deploy_safe(
        &self,
        owners: Vec<Address>,
        threshold: u64,
        salt_nonce: U256,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        let initializer = encode_setup_call(&owners, threshold, self.addresses.fallback_handler);

        // Get proxy creation code for CREATE2 computation
        let factory = ISafeProxyFactory::new(self.addresses.proxy_factory, &self.provider);
        let creation_code = factory.proxyCreationCode().call().await?;

        // Compute deterministic address
        let safe_address = compute_create2_address(
            self.addresses.proxy_factory,
            self.addresses.safe_singleton,
            &initializer,
            salt_nonce,
            &creation_code,
        );

        // Check if already deployed
        let code: Bytes = self.provider.get_code_at(safe_address).await?;
        if !code.is_empty() {
            return Ok(safe_address);
        }

        // To deploy, we need a wallet provider
        let wallet = EthereumWallet::from(self.signer.clone());
        let wallet_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(wallet)
            .connect_http(self._anvil.endpoint_url());

        let factory_with_wallet = ISafeProxyFactory::new(self.addresses.proxy_factory, &wallet_provider);

        // Deploy the Safe
        let pending_tx = factory_with_wallet
            .createProxyWithNonce(self.addresses.safe_singleton, initializer, salt_nonce)
            .send()
            .await?;

        let _receipt = pending_tx.get_receipt().await?;

        // Verify deployment
        let code: Bytes = self.provider.get_code_at(safe_address).await?;
        if code.is_empty() {
            return Err("Safe deployment failed: no code at expected address".into());
        }

        Ok(safe_address)
    }

    /// Creates a Safe client for the given Safe address
    pub async fn safe_client(
        &self,
        safe_address: Address,
    ) -> Result<Safe<TestProvider>, Box<dyn std::error::Error>> {
        let safe = Safe::connect(
            self.provider.clone(),
            self.signer.clone(),
            safe_address,
        )
        .await?;
        Ok(safe)
    }

    /// Deploys a MockERC20 token
    pub async fn deploy_mock_erc20(&self) -> Result<Address, Box<dyn std::error::Error>> {
        let wallet = EthereumWallet::from(self.signer.clone());
        let wallet_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(wallet)
            .connect_http(self._anvil.endpoint_url());

        // Debug: Print chain info
        let chain_id = wallet_provider.get_chain_id().await?;
        eprintln!("Deploying MockERC20 on chain_id: {}", chain_id);

        let deployer = MockERC20::deploy(&wallet_provider).await?;
        Ok(*deployer.address())
    }

    /// Mints ETH to an address using anvil_setBalance
    pub async fn mint_eth(
        &self,
        to: Address,
        amount: U256,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = serde_json::json!([
            format!("{:?}", to),
            format!("0x{:x}", amount)
        ]);

        // anvil_setBalance returns null on success
        self.provider
            .client()
            .request::<_, Option<bool>>("anvil_setBalance", params)
            .await?;

        Ok(())
    }

    /// Gets storage at a specific slot
    pub async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let value = self.provider.get_storage_at(address, slot).await?;
        Ok(value)
    }

    /// Gets the ETH balance of an address
    pub async fn get_balance(&self, address: Address) -> Result<U256, Box<dyn std::error::Error>> {
        let balance = self.provider.get_balance(address).await?;
        Ok(balance)
    }

    /// Mints ERC20 tokens to an address using the MockERC20 mint function
    pub async fn mint_erc20(
        &self,
        token: Address,
        to: Address,
        amount: U256,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wallet = EthereumWallet::from(self.signer.clone());
        let wallet_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(wallet)
            .connect_http(self._anvil.endpoint_url());

        let token_contract = MockERC20::new(token, &wallet_provider);
        token_contract
            .mint(to, amount)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(())
    }

}

