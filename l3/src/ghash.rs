//! GHASH implementation for Galois/Counter Mode (GCM)
//!
//! GHASH is the authentication component of GCM and GMAC, operating over GF(2^128).
//! It's commonly used with AES for authenticated encryption.
//!
//! # Algorithm
//!
//! Given:
//! - H: Hash key (authentication key derived from encryption key)
//! - A: Additional Authenticated Data (AAD)
//! - C: Ciphertext
//!
//! GHASH computes:
//! ```text
//! X₀ = 0
//! Xᵢ = (Xᵢ₋₁ + Sᵢ) · H    for i > 0
//! S = padWithZeros(A) || padWithZeros(C) || len(A) || len(C)
//! GHASH(H, A, C) = Xₘ₊ₙ₊₁
//! ```
//!
//! Where:
//! - len(A) and len(C) are 64-bit representations of bit lengths
//! - m = ⌈len(A)/128⌉, n = ⌈len(C)/128⌉
//! - padWithZeros pads to the next 128-bit block boundary
//! - Sᵢ are consecutive 128-bit blocks of S (counting from 1)
//!
//! # Field Definition
//!
//! GF(2^128) is defined by the irreducible polynomial:
//! x^128 + x^7 + x^2 + x + 1

use crate::bigint::BigInt;
use crate::field::{BinaryField, FieldConfig};
use crate::field_trait::FieldElement;

/// GF(2^128) field configuration for GHASH
/// Irreducible polynomial: x^128 + x^7 + x^2 + x + 1
#[derive(Clone, Debug)]
pub struct GF128Config;

// Base field is F_2
static F2_MOD: BigInt<3> = BigInt::from_u64(2);

// Irreducible polynomial: x^128 + x^7 + x^2 + x + 1
// Coefficients for x^0 through x^128
static GF128_IRRED: [BigInt<3>; 129] = [
    BigInt::from_u64(1), // x^0
    BigInt::from_u64(1), // x^1
    BigInt::from_u64(1), // x^2
    BigInt::from_u64(0), // x^3
    BigInt::from_u64(0), // x^4
    BigInt::from_u64(0), // x^5
    BigInt::from_u64(0), // x^6
    BigInt::from_u64(1), // x^7
    BigInt::from_u64(0), // x^8
    BigInt::from_u64(0), // x^9
    BigInt::from_u64(0), // x^10
    BigInt::from_u64(0), // x^11
    BigInt::from_u64(0), // x^12
    BigInt::from_u64(0), // x^13
    BigInt::from_u64(0), // x^14
    BigInt::from_u64(0), // x^15
    BigInt::from_u64(0), // x^16
    BigInt::from_u64(0), // x^17
    BigInt::from_u64(0), // x^18
    BigInt::from_u64(0), // x^19
    BigInt::from_u64(0), // x^20
    BigInt::from_u64(0), // x^21
    BigInt::from_u64(0), // x^22
    BigInt::from_u64(0), // x^23
    BigInt::from_u64(0), // x^24
    BigInt::from_u64(0), // x^25
    BigInt::from_u64(0), // x^26
    BigInt::from_u64(0), // x^27
    BigInt::from_u64(0), // x^28
    BigInt::from_u64(0), // x^29
    BigInt::from_u64(0), // x^30
    BigInt::from_u64(0), // x^31
    BigInt::from_u64(0), // x^32
    BigInt::from_u64(0), // x^33
    BigInt::from_u64(0), // x^34
    BigInt::from_u64(0), // x^35
    BigInt::from_u64(0), // x^36
    BigInt::from_u64(0), // x^37
    BigInt::from_u64(0), // x^38
    BigInt::from_u64(0), // x^39
    BigInt::from_u64(0), // x^40
    BigInt::from_u64(0), // x^41
    BigInt::from_u64(0), // x^42
    BigInt::from_u64(0), // x^43
    BigInt::from_u64(0), // x^44
    BigInt::from_u64(0), // x^45
    BigInt::from_u64(0), // x^46
    BigInt::from_u64(0), // x^47
    BigInt::from_u64(0), // x^48
    BigInt::from_u64(0), // x^49
    BigInt::from_u64(0), // x^50
    BigInt::from_u64(0), // x^51
    BigInt::from_u64(0), // x^52
    BigInt::from_u64(0), // x^53
    BigInt::from_u64(0), // x^54
    BigInt::from_u64(0), // x^55
    BigInt::from_u64(0), // x^56
    BigInt::from_u64(0), // x^57
    BigInt::from_u64(0), // x^58
    BigInt::from_u64(0), // x^59
    BigInt::from_u64(0), // x^60
    BigInt::from_u64(0), // x^61
    BigInt::from_u64(0), // x^62
    BigInt::from_u64(0), // x^63
    BigInt::from_u64(0), // x^64
    BigInt::from_u64(0), // x^65
    BigInt::from_u64(0), // x^66
    BigInt::from_u64(0), // x^67
    BigInt::from_u64(0), // x^68
    BigInt::from_u64(0), // x^69
    BigInt::from_u64(0), // x^70
    BigInt::from_u64(0), // x^71
    BigInt::from_u64(0), // x^72
    BigInt::from_u64(0), // x^73
    BigInt::from_u64(0), // x^74
    BigInt::from_u64(0), // x^75
    BigInt::from_u64(0), // x^76
    BigInt::from_u64(0), // x^77
    BigInt::from_u64(0), // x^78
    BigInt::from_u64(0), // x^79
    BigInt::from_u64(0), // x^80
    BigInt::from_u64(0), // x^81
    BigInt::from_u64(0), // x^82
    BigInt::from_u64(0), // x^83
    BigInt::from_u64(0), // x^84
    BigInt::from_u64(0), // x^85
    BigInt::from_u64(0), // x^86
    BigInt::from_u64(0), // x^87
    BigInt::from_u64(0), // x^88
    BigInt::from_u64(0), // x^89
    BigInt::from_u64(0), // x^90
    BigInt::from_u64(0), // x^91
    BigInt::from_u64(0), // x^92
    BigInt::from_u64(0), // x^93
    BigInt::from_u64(0), // x^94
    BigInt::from_u64(0), // x^95
    BigInt::from_u64(0), // x^96
    BigInt::from_u64(0), // x^97
    BigInt::from_u64(0), // x^98
    BigInt::from_u64(0), // x^99
    BigInt::from_u64(0), // x^100
    BigInt::from_u64(0), // x^101
    BigInt::from_u64(0), // x^102
    BigInt::from_u64(0), // x^103
    BigInt::from_u64(0), // x^104
    BigInt::from_u64(0), // x^105
    BigInt::from_u64(0), // x^106
    BigInt::from_u64(0), // x^107
    BigInt::from_u64(0), // x^108
    BigInt::from_u64(0), // x^109
    BigInt::from_u64(0), // x^110
    BigInt::from_u64(0), // x^111
    BigInt::from_u64(0), // x^112
    BigInt::from_u64(0), // x^113
    BigInt::from_u64(0), // x^114
    BigInt::from_u64(0), // x^115
    BigInt::from_u64(0), // x^116
    BigInt::from_u64(0), // x^117
    BigInt::from_u64(0), // x^118
    BigInt::from_u64(0), // x^119
    BigInt::from_u64(0), // x^120
    BigInt::from_u64(0), // x^121
    BigInt::from_u64(0), // x^122
    BigInt::from_u64(0), // x^123
    BigInt::from_u64(0), // x^124
    BigInt::from_u64(0), // x^125
    BigInt::from_u64(0), // x^126
    BigInt::from_u64(0), // x^127
    BigInt::from_u64(1), // x^128
];

impl FieldConfig<3> for GF128Config {
    fn modulus() -> &'static BigInt<3> {
        &F2_MOD
    }

    fn irreducible() -> &'static [BigInt<3>] {
        &GF128_IRRED
    }
}

/// GF(2^128) element type for GHASH
/// Uses 3 limbs (192 bits) to hold 128-bit values with room for intermediate computations
pub type GF128 = BinaryField<GF128Config, 3, 128>;

/// GHASH authentication function
///
/// Computes the GHASH of additional authenticated data (A) and ciphertext (C)
/// using hash key H.
///
/// # Arguments
///
/// * `h` - Hash key (128-bit element of GF(2^128))
/// * `a` - Additional authenticated data (arbitrary length byte slice)
/// * `c` - Ciphertext data (arbitrary length byte slice)
///
/// # Returns
///
/// 128-bit authentication tag as a GF(2^128) element
///
/// # Example
///
/// ```rust
/// use l3::ghash::{ghash, bytes_to_gf128};
///
/// // Hash key (typically derived from AES encryption of zero block)
/// let h_bytes = [0u8; 16];  // Example key (all zeros)
/// let h = bytes_to_gf128(&h_bytes);
///
/// // Additional authenticated data
/// let aad = b"metadata";
///
/// // Ciphertext
/// let ciphertext = b"encrypted message";
///
/// // Compute GHASH
/// let tag = ghash(h, aad, ciphertext);
/// ```
pub fn ghash(h: GF128, a: &[u8], c: &[u8]) -> GF128 {
    // Compute bit lengths
    let a_bits = a.len() * 8;
    let c_bits = c.len() * 8;

    // Build S = padWithZeros(A) || padWithZeros(C) || len(A) || len(C)
    let mut s_blocks = Vec::new();

    // Add padded A blocks
    let mut a_padded = a.to_vec();
    let a_padding_needed = if a_bits.is_multiple_of(128) {
        0
    } else {
        16 - (a.len() % 16)
    };
    a_padded.resize(a.len() + a_padding_needed, 0);

    for chunk in a_padded.chunks(16) {
        s_blocks.push(bytes_to_gf128(chunk));
    }

    // Add padded C blocks
    let mut c_padded = c.to_vec();
    let c_padding_needed = if c_bits.is_multiple_of(128) {
        0
    } else {
        16 - (c.len() % 16)
    };
    c_padded.resize(c.len() + c_padding_needed, 0);

    for chunk in c_padded.chunks(16) {
        s_blocks.push(bytes_to_gf128(chunk));
    }

    // Add len(A) || len(C) as final block
    let mut len_block = [0u8; 16];
    // len(A) in bits as 64-bit big-endian
    len_block[0..8].copy_from_slice(&(a_bits as u64).to_be_bytes());
    // len(C) in bits as 64-bit big-endian
    len_block[8..16].copy_from_slice(&(c_bits as u64).to_be_bytes());
    s_blocks.push(bytes_to_gf128(&len_block));

    // Compute GHASH: X₀ = 0, Xᵢ = (Xᵢ₋₁ + Sᵢ) · H
    let mut x = GF128::zero();

    for s_i in s_blocks {
        x = (x + s_i) * h.clone();
    }

    x
}

/// Converts a 16-byte slice to a GF(2^128) element
///
/// Interprets bytes in big-endian order (network byte order).
/// The first byte becomes the most significant bits.
///
/// # Arguments
///
/// * `bytes` - 16-byte slice representing a 128-bit value
///
/// # Returns
///
/// GF(2^128) element
///
/// # Panics
///
/// Panics if the slice length is not exactly 16 bytes
pub fn bytes_to_gf128(bytes: &[u8]) -> GF128 {
    assert_eq!(bytes.len(), 16, "Input must be exactly 16 bytes");

    // Convert bytes to BigInt limbs (little-endian limbs, big-endian bytes within each limb)
    let mut limbs = [0u64; 3];

    // Process bytes 0-7 into limb 1 (most significant)
    limbs[1] = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);

    // Process bytes 8-15 into limb 0 (least significant)
    limbs[0] = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);

    GF128::new(BigInt::from_limbs_internal(limbs))
}

/// Converts a GF(2^128) element to a 16-byte array
///
/// Outputs bytes in big-endian order (network byte order).
///
/// # Arguments
///
/// * `elem` - GF(2^128) element
///
/// # Returns
///
/// 16-byte array representing the element
pub fn gf128_to_bytes(elem: &GF128) -> [u8; 16] {
    let limbs = elem.to_bigint().limbs();
    let mut bytes = [0u8; 16];

    // limb 1 (most significant) -> bytes 0-7
    bytes[0..8].copy_from_slice(&limbs[1].to_be_bytes());

    // limb 0 (least significant) -> bytes 8-15
    bytes[8..16].copy_from_slice(&limbs[0].to_be_bytes());

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_conversion() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];

        let elem = bytes_to_gf128(&bytes);
        let result = gf128_to_bytes(&elem);

        assert_eq!(bytes, result);
    }

    #[test]
    fn test_ghash_zero_inputs() {
        // H = 0 (not realistic, but tests the algorithm)
        let h = GF128::zero();
        let a = b"";
        let c = b"";

        let tag = ghash(h, a, c);

        // With H=0 and empty inputs, result should be 0
        assert!(tag.is_zero());
    }

    #[test]
    fn test_ghash_empty_aad_and_ciphertext() {
        // Non-zero H
        let h_bytes = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let h = bytes_to_gf128(&h_bytes);
        let a = b"";
        let c = b"";

        let tag = ghash(h.clone(), a, c);

        // With empty A and C, we only process the length block [0, 0]
        // X₁ = (0 + 0) · H = 0
        assert!(tag.is_zero());
    }

    #[test]
    fn test_ghash_single_block() {
        // Test with single block of AAD
        let h_bytes = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let h = bytes_to_gf128(&h_bytes);

        // 16 bytes of AAD (exactly one block, no padding needed)
        let a = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let c = b"";

        let tag = ghash(h.clone(), &a, c);

        // Result should be non-zero
        assert!(!tag.is_zero());
    }

    #[test]
    fn test_ghash_multiple_blocks() {
        let h_bytes = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let h = bytes_to_gf128(&h_bytes);

        // AAD with 20 bytes (2 blocks after padding)
        let a = b"Hello, World! :)    ";
        // Ciphertext with 10 bytes (1 block after padding)
        let c = b"1234567890";

        let tag = ghash(h.clone(), a, c);

        // Result should be non-zero and deterministic
        assert!(!tag.is_zero());

        // Computing again should give same result
        let tag2 = ghash(h, a, c);
        assert_eq!(gf128_to_bytes(&tag), gf128_to_bytes(&tag2));
    }

    #[test]
    fn test_ghash_different_inputs_different_tags() {
        let h_bytes = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let h = bytes_to_gf128(&h_bytes);

        let tag1 = ghash(h.clone(), b"AAD1", b"CT1");
        let tag2 = ghash(h.clone(), b"AAD2", b"CT1");
        let tag3 = ghash(h.clone(), b"AAD1", b"CT2");

        // Different inputs should produce different tags
        assert_ne!(gf128_to_bytes(&tag1), gf128_to_bytes(&tag2));
        assert_ne!(gf128_to_bytes(&tag1), gf128_to_bytes(&tag3));
        assert_ne!(gf128_to_bytes(&tag2), gf128_to_bytes(&tag3));
    }
}
