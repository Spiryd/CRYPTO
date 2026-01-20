//! Finite Field Arithmetic Library (L3)
//!
//! This library provides generic implementations for finite field arithmetic,
//! supporting prime fields F_p, extension fields F_p^k, and binary fields F_2^k.

/// API client for crypto25.random-oracle.xyz challenge service
pub mod api;
/// Big integer arithmetic module for finite field implementation
pub mod bigint;
/// Cryptographic primitives (DH, GHASH, Schnorr)
pub mod crypto;
pub use crypto::{diffie_hellman, ghash, schnorr, schnorr_encoding};
/// Elliptic curve groups over finite fields
pub mod elliptic_curve;
/// Finite field implementations (F_p, F_p^k, F_2^k)
pub mod field;
/// Re-export field trait module from field namespace
pub use field::field_trait;
/// Montgomery modular arithmetic context
pub mod montgomery;
