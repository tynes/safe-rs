//! Call types for Safe transactions

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;
use std::future::Future;

use super::Operation;
use crate::error::Result;
use crate::simulation::SimulationResult;

/// Trait for builders that construct and execute batches of calls.
///
/// This trait provides a common interface for both `EoaBuilder` and `SafeBuilder`,
/// enabling generic code to work with either builder type.
pub trait CallBuilder: Sized {
    /// Adds a typed call to the batch.
    fn add_typed<C: SolCall + Clone>(self, to: Address, call: C) -> Self;

    /// Adds a typed call with value to the batch.
    fn add_typed_with_value<C: SolCall + Clone>(self, to: Address, call: C, value: U256) -> Self;

    /// Adds a raw call to the batch.
    fn add_raw(self, to: Address, value: U256, data: impl Into<Bytes>) -> Self;

    /// Adds a call implementing SafeCall to the batch.
    fn add(self, call: impl SafeCall) -> Self;

    /// Sets a fixed gas limit for the most recently added call.
    ///
    /// This bypasses gas estimation for that call, which is useful when
    /// you want to execute a transaction that would revert (and thus fail
    /// gas estimation).
    ///
    /// # Panics
    /// Panics if called before adding any calls to the batch.
    fn with_gas_limit(self, gas_limit: u64) -> Self;

    /// Returns the number of calls in the batch.
    fn call_count(&self) -> usize;

    /// Simulates all calls and stores the results.
    ///
    /// After simulation, you can inspect the results via `simulation_result()`
    /// and then call `execute()` which will use the simulation gas values.
    fn simulate(self) -> impl Future<Output = Result<Self>> + Send;

    /// Returns the simulation result if simulation was performed.
    fn simulation_result(&self) -> Option<&SimulationResult>;
}

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
    /// Optional fixed gas limit (bypasses estimation if set)
    pub gas_limit: Option<u64>,
}

impl Call {
    /// Creates a new Call with the given parameters
    pub fn new(to: Address, value: U256, data: impl Into<Bytes>) -> Self {
        Self {
            to,
            value,
            data: data.into(),
            operation: Operation::Call,
            gas_limit: None,
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
            gas_limit: None,
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

    /// Sets a fixed gas limit, bypassing gas estimation
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
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
