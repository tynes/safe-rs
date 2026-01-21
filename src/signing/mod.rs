//! Signature generation for Safe transactions

mod ecdsa;

pub use ecdsa::{encode_pre_validated_signature, eth_sign_hash, sign_hash, validate_signature};
