//! Finite Field Arithmetic Library (L3)
//!
//! This library provides generic implementations for finite field arithmetic,
//! supporting prime fields F_p, extension fields F_p^k, and binary fields F_2^k.

/// Big integer arithmetic module for finite field implementation
pub mod bigint;
/// Diffie-Hellman key exchange protocol for various algebraic structures
pub mod diffie_hellman;
/// Elliptic curve groups over finite fields
pub mod elliptic_curve;
/// Finite field implementations (F_p, F_p^k, F_2^k)
pub mod field;
/// Finite field trait interface
pub mod field_trait;
/// GHASH algorithm for Galois/Counter Mode (GCM)
pub mod ghash;
