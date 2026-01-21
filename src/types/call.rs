//! Call types for Safe transactions

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;

use super::Operation;

/// Trait for types that can be converted to a Safe call
pub trait SafeCall {
    /// Returns the target address
    fn to(&self) -> Address;

    /// Returns the value to send (in wei)
    fn value(&self) -> U256;

    /// Returns the calldata
    fn data(&self) -> Bytes;

    /// Returns the operation type (Call or DelegateCall)
    fn operation(&self) -> Operation;
}

/// A raw call with explicit to, value, data, and operation
#[derive(Debug, Clone)]
pub struct Call {
    /// Target address
    pub to: Address,
    /// Value to send
    pub value: U256,
    /// Calldata
    pub data: Bytes,
    /// Operation type
    pub operation: Operation,
}

impl Call {
    /// Creates a new Call with the given parameters
    pub fn new(to: Address, value: U256, data: impl Into<Bytes>) -> Self {
        Self {
            to,
            value,
            data: data.into(),
            operation: Operation::Call,
        }
    }

    /// Creates a new Call with zero value
    pub fn call(to: Address, data: impl Into<Bytes>) -> Self {
        Self::new(to, U256::ZERO, data)
    }

    /// Creates a new delegate call
    pub fn delegate_call(to: Address, data: impl Into<Bytes>) -> Self {
        Self {
            to,
            value: U256::ZERO,
            data: data.into(),
            operation: Operation::DelegateCall,
        }
    }

    /// Sets the operation type
    pub fn with_operation(mut self, operation: Operation) -> Self {
        self.operation = operation;
        self
    }

    /// Sets the value
    pub fn with_value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }
}

impl SafeCall for Call {
    fn to(&self) -> Address {
        self.to
    }

    fn value(&self) -> U256 {
        self.value
    }

    fn data(&self) -> Bytes {
        self.data.clone()
    }

    fn operation(&self) -> Operation {
        self.operation
    }
}

/// A typed call wrapping a sol! macro generated call type
#[derive(Debug, Clone)]
pub struct TypedCall<C: SolCall> {
    /// Target address
    pub to: Address,
    /// Value to send
    pub value: U256,
    /// The typed call data
    pub call: C,
    /// Operation type
    pub operation: Operation,
}

impl<C: SolCall> TypedCall<C> {
    /// Creates a new TypedCall
    pub fn new(to: Address, call: C) -> Self {
        Self {
            to,
            value: U256::ZERO,
            call,
            operation: Operation::Call,
        }
    }

    /// Creates a new TypedCall with value
    pub fn with_value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    /// Sets the operation type
    pub fn with_operation(mut self, operation: Operation) -> Self {
        self.operation = operation;
        self
    }
}

impl<C: SolCall + Clone> SafeCall for TypedCall<C> {
    fn to(&self) -> Address {
        self.to
    }

    fn value(&self) -> U256 {
        self.value
    }

    fn data(&self) -> Bytes {
        self.call.abi_encode().into()
    }

    fn operation(&self) -> Operation {
        self.operation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_call_new() {
        let to = address!("0x1234567890123456789012345678901234567890");
        let value = U256::from(1000);
        let data = Bytes::from(vec![0x01, 0x02, 0x03]);

        let call = Call::new(to, value, data.clone());

        assert_eq!(call.to(), to);
        assert_eq!(call.value(), value);
        assert_eq!(call.data(), data);
        assert_eq!(call.operation(), Operation::Call);
    }

    #[test]
    fn test_call_delegate() {
        let to = address!("0x1234567890123456789012345678901234567890");
        let data = Bytes::from(vec![0x01, 0x02, 0x03]);

        let call = Call::delegate_call(to, data.clone());

        assert_eq!(call.to(), to);
        assert_eq!(call.value(), U256::ZERO);
        assert_eq!(call.data(), data);
        assert_eq!(call.operation(), Operation::DelegateCall);
    }
}
