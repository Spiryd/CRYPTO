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
static F2_MOD: BigInt<4> = BigInt::from_u64(2);

// Irreducible polynomial as compact bitstring: x^128 + x^7 + x^2 + x + 1
// Bit representation: bit 0=1, bit 1=1, bit 2=1, bit 7=1, bit 128=1
// = 0x100000000000000000000087 (17 bytes in little-endian)
//
// Memory optimization: 17 bytes vs 3096 bytes for the legacy array format!
// (129 coefficients × 24 bytes per BigInt<4> = 3096 bytes)
static GF128_IRRED_BITS: [u8; 17] = [
    0x87, // bits 0-7:   10000111 = x^7 + x^2 + x + 1
    0x00, // bits 8-15:  00000000
    0x00, // bits 16-23: 00000000
    0x00, // bits 24-31: 00000000
    0x00, // bits 32-39: 00000000
    0x00, // bits 40-47: 00000000
    0x00, // bits 48-55: 00000000
    0x00, // bits 56-63: 00000000
    0x00, // bits 64-71: 00000000
    0x00, // bits 72-79: 00000000
    0x00, // bits 80-87: 00000000
    0x00, // bits 88-95: 00000000
    0x00, // bits 96-103: 00000000
    0x00, // bits 104-111: 00000000
    0x00, // bits 112-119: 00000000
    0x00, // bits 120-127: 00000000
    0x01, // bits 128-135: 00000001 = x^128
];

impl FieldConfig<4> for GF128Config {
    fn modulus() -> &'static BigInt<4> {
        &F2_MOD
    }

    fn irreducible() -> &'static [BigInt<4>] {
        &[] // Binary fields use irreducible_bitstring() instead
    }

    fn irreducible_bitstring() -> &'static [u8] {
        &GF128_IRRED_BITS
    }
}

/// GF(2^128) element type for GHASH
/// Uses 4 limbs (256 bits) to hold 128-bit values with room for intermediate computations
pub type GF128 = BinaryField<GF128Config, 4, 128>;

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
    // lengths in bits, modulo 2^64 behavior
    let a_bits = (a.len() as u64).wrapping_mul(8);
    let c_bits = (c.len() as u64).wrapping_mul(8);

    let mut x = 0u128;
    let h_u = gf128_to_u128(&h);

    // Process A in 16-byte blocks with zero padding
    for chunk in a.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        let s_i = u128::from_be_bytes(block);
        x = gf128_mul_gcm(x ^ s_i, h_u);
    }

    // Process C in 16-byte blocks with zero padding
    for chunk in c.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        let s_i = u128::from_be_bytes(block);
        x = gf128_mul_gcm(x ^ s_i, h_u);
    }

    // Length block: [len(A)]_64 || [len(C)]_64, both big-endian, lengths in bits
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&a_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&c_bits.to_be_bytes());
    let l = u128::from_be_bytes(len_block);

    x = gf128_mul_gcm(x ^ l, h_u);

    u128_to_gf128(x)
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
    let mut limbs = [0u64; 4];

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

/// Converts a GF(2^128) element to u128
fn gf128_to_u128(x: &GF128) -> u128 {
    u128::from_be_bytes(gf128_to_bytes(x))
}

/// Converts a u128 to GF(2^128) element
fn u128_to_gf128(x: u128) -> GF128 {
    bytes_to_gf128(&x.to_be_bytes())
}

/// GF(2^128) multiplication using NIST Algorithm 1
///
/// Implements the NIST specification for GCM multiplication.
/// This is the bit-by-bit algorithm defined in NIST SP 800-38D.
///
/// # Arguments
///
/// * `x` - First operand (128-bit integer)
/// * `y` - Second operand (128-bit integer)
///
/// # Returns
///
/// Product in GF(2^128) as a 128-bit integer
fn gf128_mul_gcm(x: u128, y: u128) -> u128 {
    // R = 11100001 || 0^120
    const R: u128 = 0xE1000000000000000000000000000000u128;

    let mut z: u128 = 0;
    let mut v: u128 = y;

    // X_0 is the MSB, X_127 is the LSB
    for i in 0..128 {
        let xi = (x >> (127 - i)) & 1;
        if xi == 1 {
            z ^= v;
        }

        // Multiply V by x in GF(2^128) (per spec): right shift, conditional xor with R
        let lsb = v & 1;
        v >>= 1;
        if lsb == 1 {
            v ^= R;
        }
    }

    z
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

#[cfg(test)]
mod macsec_vectors {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len().is_multiple_of(2), "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn gf128_from_hex_16(s: &str) -> GF128 {
        let b = hex_to_bytes(s);
        assert_eq!(b.len(), 16);
        bytes_to_gf128(&b)
    }

    #[test]
    fn ghash_macsec_2_1_1_auth_only_a_560_c_0() {
        // From MACsec vectors section 2.1.1 (GCM-AES-128 authentication-only).
        // H: 73A23D80121DE2D5A850253FCF43120E
        // A: 560 bits (70 bytes), C: empty
        // GHASH(H,A,C): 1BDA7DB505D8A165264986A703A6920D

        let h = gf128_from_hex_16("73A23D80121DE2D5A850253FCF43120E");

        let a = hex_to_bytes(
            "D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001",
        );

        let c: &[u8] = &[];

        let expected = gf128_from_hex_16("1BDA7DB505D8A165264986A703A6920D");

        let got = ghash(h, &a, c);
        assert_eq!(gf128_to_bytes(&got), gf128_to_bytes(&expected));
    }

    #[test]
    fn ghash_macsec_2_2_1_encrypt_a_224_c_384() {
        // From MACsec vectors section 2.2.1 (GCM-AES-128 authenticated encryption).
        // H: 73A23D80121DE2D5A850253FCF43120E
        // A: 224 bits (28 bytes)
        // C: 384 bits (48 bytes)
        // GHASH(H,A,C): A4C350FB66B8C960E83363381BA90F50

        let h = gf128_from_hex_16("73A23D80121DE2D5A850253FCF43120E");

        let a = hex_to_bytes(
            "
            D609B1F056637A0D46DF998D88E52E00
            B2C2846512153524C0895E81
            ",
        );

        let c = hex_to_bytes(
            "
            701AFA1CC039C0D765128A665DAB6924
            3899BF7318CCDC81C9931DA17FBE8EDD
            7D17CB8B4C26FC81E3284F2B7FBA713D
            ",
        );

        let expected = gf128_from_hex_16("A4C350FB66B8C960E83363381BA90F50");

        let got = ghash(h, &a, &c);
        assert_eq!(gf128_to_bytes(&got), gf128_to_bytes(&expected));
    }
}
