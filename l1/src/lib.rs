//! # L1 Cryptography Learning Library
//!
//! This library provides educational implementations of cryptographic algorithms
//! and GPU compute capabilities for cryptography students.
//!
//! ## Modules
//!
//! - **MD5 Hash Function**: Educational implementation of the MD5 algorithm
//!   for studying hash function vulnerabilities and collision attacks.
//! - **GPU Compute**: Clean WGPU-based GPU compute API for accelerated
//!   cryptographic operations and general computation.
//!
//! ##  Security Warning
//!
//! MD5 is cryptographically broken and unsuitable for further use. This
//! implementation is specifically created for educational purposes to demonstrate:
//! - Hash function internals and implementation details
//! - Vulnerabilities discovered by Xiaoyun Wang et al. in 2004
//! - Collision attack techniques on weak hash functions
//!
//! ## MD5 Example
//!
//! ```rust
//! use l1::{md5, md5_to_hex};
//!
//! let hash = md5(b"Hello, world!");
//! println!("MD5: {}", md5_to_hex(&hash));
//! ```
//!
//! ## GPU Compute Example
//!
//! ```rust,no_run
//! use l1::gpu::{GpuContext, ComputePipeline};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let ctx = GpuContext::new().await?;
//! let shader = include_str!("gpu/shaders/square.wgsl");
//! let pipeline = ComputePipeline::new(&ctx, shader, "main")?;
//!
//! let input = vec![1.0, 2.0, 3.0, 4.0];
//! let output = pipeline.execute(&ctx, &input).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## References
//!
//! - RFC 1321: The MD5 Message-Digest Algorithm
//! - Xiaoyun Wang et al. "Collisions for Hash Functions MD4, MD5, HAVAL-128 and RIPEMD" (2004)
//! - Xiaoyun Wang and Hongbo Yu. "How to Break MD5 and Other Hash Functions"

// Modules
pub mod gpu;
pub mod md5;

// Re-export commonly used MD5 functions for convenience
pub use md5::{hash as md5, to_hex as md5_to_hex};
