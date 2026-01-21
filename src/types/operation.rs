//! Operation types for Safe transactions

use serde::{Deserialize, Serialize};

/// Operation type for Safe transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum Operation {
    /// Regular call (default)
    #[default]
    Call = 0,
    /// Delegate call (executes in context of Safe)
    DelegateCall = 1,
}

impl Operation {
    /// Returns the operation as a u8 value
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Creates an Operation from a u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Operation::Call),
            1 => Some(Operation::DelegateCall),
            _ => None,
        }
    }
}

impl From<Operation> for u8 {
    fn from(op: Operation) -> Self {
        op.as_u8()
    }
}

impl TryFrom<u8> for Operation {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Operation::from_u8(value).ok_or("Invalid operation value")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_values() {
        assert_eq!(Operation::Call.as_u8(), 0);
        assert_eq!(Operation::DelegateCall.as_u8(), 1);
    }

    #[test]
    fn test_operation_from_u8() {
        assert_eq!(Operation::from_u8(0), Some(Operation::Call));
        assert_eq!(Operation::from_u8(1), Some(Operation::DelegateCall));
        assert_eq!(Operation::from_u8(2), None);
    }

    #[test]
    fn test_operation_default() {
        assert_eq!(Operation::default(), Operation::Call);
    }
}
