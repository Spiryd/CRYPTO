//! Finite field implementations
//!
//! This module provides field arithmetic for:
//! - F_p: Prime fields (order p) - use `PrimeField` for k=1
//! - F_p^k: Extension fields (order p^k for k>1) - use `ExtensionField`
//! - F_2^k: Binary fields (p=2) - use `BinaryField` for efficient bit operations
//!
//! # When to use which implementation
//!
//! - **PrimeField<C, N>**: For F_p where p is any prime (k=1 case)
//!   - General prime field arithmetic
//!   - Compile-time modulus checking
//!
//! - **ExtensionField<C, N, K>**: For F_p^k where p is any prime and k>1
//!   - Polynomial arithmetic over prime fields
//!   - Requires irreducible polynomial of degree k
//!
//! - **BinaryField<C, N, K>**: For F_2^k (specialized for p=2)
//!   - Highly efficient bit string operations
//!   - Addition is XOR, no modular reduction needed
//!   - Common in cryptography (AES uses GF(2^8))
//!   - Also known as GF(2^k) or F_2^m

pub mod binary;
pub mod config;
pub mod extension;
pub mod prime;
pub mod field_trait;

// Re-export main types for convenience
pub use binary::BinaryField;
pub use config::FieldConfig;
pub use extension::ExtensionField;
pub use prime::PrimeField;
