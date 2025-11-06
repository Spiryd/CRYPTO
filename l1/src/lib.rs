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

pub mod collision;
pub mod gpu;
pub mod md5;

// Re-export commonly used functions
pub use md5::{hash as md5, hash_with_iv as md5_with_iv, to_hex as md5_to_hex, 
              InitialValues, process_raw_block};
pub use collision::{CollisionSearch, Collision, DELTA_M0, 
                    WangCollisionExample, WANG_COLLISION_0, WANG_COLLISION_1};

/// Print text in a nice box with automatic sizing
pub fn print_box(text: &str) {
    let text_len = text.chars().count();
    let total_width = text_len + 4; // 2 spaces padding on each side
    
    println!("\n╔{}╗", "═".repeat(total_width));
    println!("║  {}  ║", text);
    println!("╚{}╝\n", "═".repeat(total_width));
}
