//! Contract ABI definitions for Safe v1.4.1

use alloy::sol;

sol! {
    /// Safe v1.4.1 interface for executing transactions
    #[sol(rpc)]
    interface ISafe {
        /// Execute a transaction (requires valid signature)
        function execTransaction(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address payable refundReceiver,
            bytes memory signatures
        ) external payable returns (bool success);

        /// Returns the current nonce of the Safe
        function nonce() external view returns (uint256 nonce);

        /// Returns the threshold (number of required signatures)
        function getThreshold() external view returns (uint256 threshold);

        /// Returns array of owners
        function getOwners() external view returns (address[] memory owners);

        /// Checks if an address is an owner
        function isOwner(address owner) external view returns (bool isOwner);

        /// Returns the domain separator for EIP-712 signing
        function domainSeparator() external view returns (bytes32);

        /// Computes the hash of a Safe transaction
        function getTransactionHash(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address refundReceiver,
            uint256 _nonce
        ) external view returns (bytes32);

        /// Encodes transaction data
        function encodeTransactionData(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address refundReceiver,
            uint256 _nonce
        ) external view returns (bytes memory);

        /// Checks the signature and returns the owner address
        function checkSignatures(
            bytes32 dataHash,
            bytes memory data,
            bytes memory signatures
        ) external view;

        /// Returns the chain ID
        function getChainId() external view returns (uint256);

        /// Events
        event ExecutionSuccess(bytes32 indexed txHash, uint256 payment);
        event ExecutionFailure(bytes32 indexed txHash, uint256 payment);
        event SafeReceived(address indexed sender, uint256 value);
    }

    /// MultiSend interface for batching multiple calls
    #[sol(rpc)]
    interface IMultiSend {
        /// Sends multiple transactions in a single call
        /// @param transactions Packed encoding of transactions:
        ///        operation (1 byte) | to (20 bytes) | value (32 bytes) | data length (32 bytes) | data
        function multiSend(bytes memory transactions) external payable;
    }

    /// MultiSendCallOnly - same as MultiSend but only allows Call operations (no DelegateCall)
    #[sol(rpc)]
    interface IMultiSendCallOnly {
        /// Sends multiple transactions in a single call (Call only, no DelegateCall)
        function multiSend(bytes memory transactions) external payable;
    }

    /// ERC20 interface for common token operations
    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);

        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
    }
}

/// EIP-712 type hash for SafeTx struct
/// keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
pub const SAFE_TX_TYPEHASH: [u8; 32] = [
    0xbb, 0x83, 0x10, 0xd4, 0x86, 0x36, 0x8d, 0xb6, 0xbd, 0x6f, 0x84, 0x94, 0x02, 0xfd, 0xd7, 0x3a,
    0xd5, 0x3d, 0x31, 0x6b, 0x5a, 0x4b, 0x26, 0x44, 0xad, 0x6e, 0xfe, 0x0f, 0x94, 0x12, 0x86, 0xd8,
];

/// EIP-712 domain type hash for Safe
/// keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
pub const DOMAIN_SEPARATOR_TYPEHASH: [u8; 32] = [
    0x47, 0xe7, 0x95, 0x34, 0xa2, 0x45, 0x95, 0x2e, 0x8b, 0x16, 0x89, 0x3a, 0x33, 0x6b, 0x85, 0xa3,
    0xd9, 0xea, 0x9f, 0xa8, 0xc5, 0x73, 0xf3, 0xd8, 0x03, 0xaf, 0xb9, 0x2a, 0x79, 0x46, 0x92, 0x18,
];

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;

    #[test]
    fn test_safe_tx_typehash() {
        let computed = keccak256(
            "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
        );
        assert_eq!(computed.as_slice(), &SAFE_TX_TYPEHASH);
    }

    #[test]
    fn test_domain_separator_typehash() {
        let computed = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
        assert_eq!(computed.as_slice(), &DOMAIN_SEPARATOR_TYPEHASH);
    }
}
