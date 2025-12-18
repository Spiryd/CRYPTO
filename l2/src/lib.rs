//! # L2 - Finite Field Cryptography Library
//!
//! A comprehensive Rust library for finite field arithmetic and elliptic curve cryptography.
//!
//! ## Features
//!
//! - **Big Integer Arithmetic**: Arbitrary precision integers for cryptographic operations
//! - **Prime Fields (𝔽_p)**: Efficient modular arithmetic
//! - **Extension Fields (𝔽_p^k)**: Polynomial rings over prime fields
//! - **Binary Fields (𝔽₂ᵐ)**: Hardware-optimized characteristic-2 fields
//! - **Elliptic Curves**: Point operations over prime and binary fields
//! - **Serialization**: JSON, Base64, Base16, Base10 support
//!
//! ## Quick Start
//!
//! ```rust
//! use l2::{BigUint, Field, FieldElement, EllipticCurve};
//!
//! // Create a prime field F_17
//! let p = BigUint::from_u64(17);
//! let a = FieldElement::from_u64(5, p.clone());
//! let b = FieldElement::from_u64(12, p.clone());
//!
//! // Field arithmetic
//! let sum = &a + &b;  // (5 + 12) mod 17 = 0
//! let product = &a * &b;  // (5 * 12) mod 17 = 9
//! let inverse = a.inv().unwrap();  // 5^(-1) mod 17 = 7
//! ```
//!
//! ## Module Overview
//!
//! - [`bigint`] - Arbitrary precision unsigned integers
//! - [`field`] - Prime field arithmetic (𝔽_p)
//! - [`polynomial`] - Polynomial operations over fields
//! - [`extension_field`] - Extension field arithmetic (𝔽_p^k)
//! - [`binary_field`] - Binary field arithmetic (𝔽₂ᵐ)
//! - [`elliptic_curve`] - Elliptic curves over prime fields
//! - [`binary_elliptic_curve`] - Elliptic curves over binary fields
//! - [`serialization`] - Serialization and deserialization utilities

// Public modules
pub mod bigint;
pub mod field;
pub mod polynomial;
pub mod extension_field;
pub mod binary_field;
pub mod elliptic_curve;
pub mod binary_elliptic_curve;
pub mod serialization;

// Re-export commonly used types for convenience
pub use bigint::BigUint;
pub use field::{Field, FieldElement};
pub use polynomial::Polynomial;
pub use extension_field::ExtensionFieldElement;
pub use binary_field::BinaryFieldElement;
pub use elliptic_curve::{EllipticCurve, EllipticCurvePoint};
pub use binary_elliptic_curve::{BinaryEllipticCurve, BinaryEllipticCurvePoint};

// Re-export serialization utilities
pub use serialization::{
    SerializationFormat,
    SerializableFieldElement,
    SerializableBinaryFieldElement,
    SerializableExtensionFieldElement,
    SerializablePolynomial,
    SerializableECPoint,
    SerializableBinaryECPoint,
    SerializableEllipticCurve,
    SerializableBinaryEllipticCurve,
};
