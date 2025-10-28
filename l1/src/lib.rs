//! # L1 Cryptography Learning Library
//!
//! Educational implementations of cryptographic algorithms and GPU compute.
//!
//! ## Modules
//!
//! - **MD5**: Hash function implementation for studying vulnerabilities
//! - **GPU**: WGPU-based GPU compute for accelerated operations
//! - **Collision**: MD5 collision verification tools
//!
//! ## Security Warning
//!
//! MD5 is cryptographically broken. This is for educational use only.
//!
//! ## Examples
//!
//! ```rust
//! use l1::{md5, md5_to_hex};
//!
//! let hash = md5(b"Hello, world!");
//! println!("MD5: {}", md5_to_hex(&hash));
//! ```

pub mod gpu;
pub mod md5;
pub mod collision;

// Re-export commonly used functions
pub use md5::{hash as md5, hash_with_iv as md5_with_iv, to_hex as md5_to_hex, 
              InitialValues, process_raw_block};
