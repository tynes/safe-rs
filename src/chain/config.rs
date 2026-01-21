//! Chain configuration for Safe contract addresses

use alloy::primitives::{address, Address};

/// Canonical Safe v1.4.1 contract addresses
/// These addresses are the same across all supported chains (CREATE2 deployment)
#[derive(Debug, Clone)]
pub struct ChainAddresses {
    /// Safe singleton address
    pub safe_singleton: Address,
    /// MultiSend contract address
    pub multi_send: Address,
    /// MultiSendCallOnly contract address
    pub multi_send_call_only: Address,
    /// Safe proxy factory address
    pub proxy_factory: Address,
    /// Compatibility fallback handler
    pub fallback_handler: Address,
}

impl Default for ChainAddresses {
    fn default() -> Self {
        Self::v1_4_1()
    }
}

impl ChainAddresses {
    /// Returns the canonical Safe v1.4.1 addresses
    pub fn v1_4_1() -> Self {
        Self {
            safe_singleton: address!("41675C099F32341bf84BFc5382aF534df5C7461a"),
            multi_send: address!("38869bf66a61cF6bDB996A6aE40D5853Fd43B526"),
            multi_send_call_only: address!("9641d764fc13c8B624c04430C7356C1C7C8102e2"),
            proxy_factory: address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"),
            fallback_handler: address!("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"),
        }
    }

    /// Returns the canonical Safe v1.3.0 addresses (for backwards compatibility)
    pub fn v1_3_0() -> Self {
        Self {
            safe_singleton: address!("d9Db270c1B5E3Bd161E8c8503c55cEABeE709552"),
            multi_send: address!("A238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"),
            multi_send_call_only: address!("40A2aCCbd92BCA938b02010E17A5b8929b49130D"),
            proxy_factory: address!("a6B71E26C5e0845f74c812102Ca7114b6a896AB2"),
            fallback_handler: address!("f48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4"),
        }
    }

    /// Creates a custom address configuration
    pub fn custom(
        safe_singleton: Address,
        multi_send: Address,
        multi_send_call_only: Address,
    ) -> Self {
        Self {
            safe_singleton,
            multi_send,
            multi_send_call_only,
            proxy_factory: Address::ZERO,
            fallback_handler: Address::ZERO,
        }
    }
}

/// Chain configuration including addresses and chain ID
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: u64,
    /// Contract addresses
    pub addresses: ChainAddresses,
}

impl ChainConfig {
    /// Creates a new chain configuration with canonical v1.4.1 addresses
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            addresses: ChainAddresses::v1_4_1(),
        }
    }

    /// Creates a chain configuration with custom addresses
    pub fn with_addresses(chain_id: u64, addresses: ChainAddresses) -> Self {
        Self { chain_id, addresses }
    }

    /// Returns configuration for Ethereum mainnet
    pub fn mainnet() -> Self {
        Self::new(1)
    }

    /// Returns configuration for Sepolia testnet
    pub fn sepolia() -> Self {
        Self::new(11155111)
    }

    /// Returns configuration for Arbitrum
    pub fn arbitrum() -> Self {
        Self::new(42161)
    }

    /// Returns configuration for Optimism
    pub fn optimism() -> Self {
        Self::new(10)
    }

    /// Returns configuration for Base
    pub fn base() -> Self {
        Self::new(8453)
    }

    /// Returns configuration for Polygon
    pub fn polygon() -> Self {
        Self::new(137)
    }
}

/// Well-known chain IDs
pub mod chain_ids {
    pub const MAINNET: u64 = 1;
    pub const SEPOLIA: u64 = 11155111;
    pub const ARBITRUM: u64 = 42161;
    pub const OPTIMISM: u64 = 10;
    pub const BASE: u64 = 8453;
    pub const POLYGON: u64 = 137;
    pub const BSC: u64 = 56;
    pub const AVALANCHE: u64 = 43114;
    pub const GNOSIS: u64 = 100;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_4_1_addresses() {
        let addrs = ChainAddresses::v1_4_1();
        assert_eq!(
            addrs.safe_singleton,
            address!("41675C099F32341bf84BFc5382aF534df5C7461a")
        );
        assert_eq!(
            addrs.multi_send,
            address!("38869bf66a61cF6bDB996A6aE40D5853Fd43B526")
        );
        assert_eq!(
            addrs.multi_send_call_only,
            address!("9641d764fc13c8B624c04430C7356C1C7C8102e2")
        );
    }

    #[test]
    fn test_chain_config_mainnet() {
        let config = ChainConfig::mainnet();
        assert_eq!(config.chain_id, 1);
    }

    #[test]
    fn test_default_addresses() {
        let default = ChainAddresses::default();
        let v1_4_1 = ChainAddresses::v1_4_1();
        assert_eq!(default.safe_singleton, v1_4_1.safe_singleton);
    }
}
