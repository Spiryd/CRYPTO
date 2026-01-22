//! Helper functions for hex encoding/decoding and API data conversion

use crate::bigint::BigInt;
use crate::elliptic_curve::Point;
use crate::field::{BinaryField, ExtensionField, FieldConfig, PrimeField};
use std::cmp::Ordering;

use super::types::{EC2mPoint, ECPPoint, ECPkPoint};

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

/// Convert hex string to bytes (big-endian)
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    if hex.is_empty() {
        return vec![];
    }

    // Handle odd-length hex strings by prepending '0'
    if hex.len() % 2 == 1 {
        let padded = format!("0{}", hex);
        hex::decode(&padded).unwrap_or_else(|_| vec![])
    } else {
        hex::decode(hex).unwrap_or_else(|_| vec![])
    }
}

/// Convert bytes to hex string (big-endian, lowercase)
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ============================================================================
// Efficient Hash Input Construction (avoids allocations in hot loops)
// ============================================================================

/// Build a JSON-quoted hex string directly into a buffer: `"HEXVALUE"`
/// Uses lowercase hex to match bigint_to_padded_hex behavior.
#[inline]
pub fn write_quoted_hex_to_buffer(buf: &mut Vec<u8>, bytes: &[u8]) {
    const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
    buf.push(b'"');
    for &byte in bytes {
        buf.push(HEX_CHARS_LOWER[(byte >> 4) as usize]);
        buf.push(HEX_CHARS_LOWER[(byte & 0x0F) as usize]);
    }
    buf.push(b'"');
}

/// Build a JSON-quoted padded BigInt hex directly into a buffer
/// Uses lowercase hex to match bigint_to_padded_hex behavior.
#[inline]
pub fn write_quoted_bigint_to_buffer<const N: usize>(
    buf: &mut Vec<u8>,
    value: &BigInt<N>,
    byte_len: usize,
) {
    const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.to_be_bytes();
    
    // Find the actual start of significant bytes
    let total_bytes = bytes.len();
    let skip = total_bytes.saturating_sub(byte_len);
    let significant_bytes = &bytes[skip..];
    let padding_needed = byte_len.saturating_sub(significant_bytes.len());
    
    buf.push(b'"');
    // Write leading zeros for padding
    for _ in 0..padding_needed {
        buf.push(b'0');
        buf.push(b'0');
    }
    // Write actual hex digits
    for &byte in significant_bytes {
        buf.push(HEX_CHARS_LOWER[(byte >> 4) as usize]);
        buf.push(HEX_CHARS_LOWER[(byte & 0x0F) as usize]);
    }
    buf.push(b'"');
}

/// Build a JSON EC point object directly into a buffer: `{"x":"HEX","y":"HEX"}`
#[inline]
pub fn write_ec_point_to_buffer<const N: usize>(
    buf: &mut Vec<u8>,
    x: &BigInt<N>,
    y: &BigInt<N>,
    byte_len: usize,
) {
    buf.extend_from_slice(b"{\"x\":");
    write_quoted_bigint_to_buffer(buf, x, byte_len);
    buf.extend_from_slice(b",\"y\":");
    write_quoted_bigint_to_buffer(buf, y, byte_len);
    buf.push(b'}');
}

/// Build a JSON extension field element directly into buffer: `["HEX","HEX",...]`
#[inline]
pub fn write_ext_field_to_buffer<const N: usize>(
    buf: &mut Vec<u8>,
    coeffs: &[BigInt<N>],
    byte_len: usize,
) {
    buf.push(b'[');
    for (i, coeff) in coeffs.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        write_quoted_bigint_to_buffer(buf, coeff, byte_len);
    }
    buf.push(b']');
}

/// Build a JSON EC point over extension field: `{"x":[...],"y":[...]}`
#[inline]
pub fn write_ec_ext_point_to_buffer<const N: usize>(
    buf: &mut Vec<u8>,
    x_coeffs: &[BigInt<N>],
    y_coeffs: &[BigInt<N>],
    byte_len: usize,
) {
    buf.extend_from_slice(b"{\"x\":");
    write_ext_field_to_buffer(buf, x_coeffs, byte_len);
    buf.extend_from_slice(b",\"y\":");
    write_ext_field_to_buffer(buf, y_coeffs, byte_len);
    buf.push(b'}');
}

/// Convert BigInt to hex string with proper padding for a given bit length
pub fn bigint_to_hex_padded<const N: usize>(value: &BigInt<N>, target_bits: usize) -> String {
    let hex = value.to_hex();
    let target_len = target_bits.div_ceil(8) * 2;
    if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len)
    } else {
        hex
    }
}

/// Generate a random BigInt in range [1, max-1] using rejection sampling
pub fn generate_random_bigint<const N: usize>(max: &BigInt<N>) -> BigInt<N> {
    use rand::RngCore;

    let mut rng = rand::rng();
    let one = BigInt::<N>::one();
    let max_minus_1 = max.sub_with_borrow(&one).0;

    let bit_len = max_minus_1.bit_length();
    let byte_len = bit_len.div_ceil(8);
    let top_bits = bit_len % 8;
    let top_mask: u8 = if top_bits == 0 {
        0xFF
    } else {
        (1u8 << top_bits) - 1
    };

    let mut bytes = vec![0u8; byte_len];
    loop {
        rng.fill_bytes(&mut bytes);
        if !bytes.is_empty() {
            bytes[0] &= top_mask;
        }

        let candidate = BigInt::<N>::from_be_bytes(&bytes);
        if candidate.compare(&max_minus_1) == Ordering::Less {
            return candidate.add_with_carry(&one).0;
        }
    }
}

/// Convert scalar to NAF (Non-Adjacent Form) for faster scalar multiplication
pub fn bigint_to_naf<const N: usize>(k: &BigInt<N>) -> Vec<i8> {
    let mut naf = Vec::new();
    let mut k = *k;

    while !k.is_zero() {
        if k.limbs()[0] & 1 == 1 {
            let width = 2;
            let mask = (1u64 << width) - 1;
            let remainder = k.limbs()[0] & mask;

            if remainder < (1u64 << (width - 1)) {
                naf.push(remainder as i8);
                k = k >> 1;
            } else {
                naf.push((remainder as i8) - (1 << width) as i8);
                k = (k >> 1) + BigInt::one();
            }
        } else {
            naf.push(0);
            k = k >> 1;
        }
    }

    naf
}

// ============================================================================
// Encoding Helpers for API Responses
// ============================================================================

/// Strip quotes from JSON encoded string
pub fn strip_json_quotes(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Encode a PrimeField element for API (hex string, uppercase)
pub fn encode_prime_field_for_api<C: FieldConfig<N>, const N: usize>(
    field: &PrimeField<C, N>,
) -> String {
    let modulus = C::modulus();
    let bit_len = modulus.bit_length();
    let byte_len = bit_len.div_ceil(8);
    let target_len = byte_len * 2;

    let hex = field.value().to_hex();
    let padded = if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len)
    } else {
        hex
    };
    padded.to_uppercase()
}

/// Encode a BinaryField element for API (hex string, uppercase)
pub fn encode_binary_field_for_api<C: FieldConfig<N>, const N: usize, const K: usize>(
    field: &BinaryField<C, N, K>,
) -> String {
    let byte_len = K.div_ceil(8);
    let target_len = byte_len * 2;

    let hex = field.bits().to_hex();
    let padded = if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len)
    } else {
        hex
    };
    padded.to_uppercase()
}

/// Encode an ExtensionField element for API (array of hex strings)
pub fn encode_extension_field_for_api<C: FieldConfig<N>, const N: usize, const K: usize>(
    field: &ExtensionField<C, N, K>,
) -> Vec<String> {
    let modulus = C::modulus();
    let bit_len = modulus.bit_length();
    let byte_len = bit_len.div_ceil(8);
    let target_len = byte_len * 2;

    field
        .coefficients()
        .iter()
        .map(|coeff| {
            let hex = coeff.to_hex();
            let padded = if hex.len() < target_len {
                format!("{:0>width$}", hex, width = target_len)
            } else {
                hex
            };
            padded.to_uppercase()
        })
        .collect()
}

/// Encode an EC point over prime field for API
pub fn encode_ecp_point_for_api<C: FieldConfig<N>, const N: usize>(
    point: &Point<PrimeField<C, N>>,
) -> ECPPoint {
    match point {
        Point::Infinity => ECPPoint {
            x: "inf".to_string(),
            y: "inf".to_string(),
        },
        Point::Affine { x, y } => ECPPoint {
            x: encode_prime_field_for_api(x),
            y: encode_prime_field_for_api(y),
        },
    }
}

/// Encode an EC point over binary field for API
pub fn encode_ec2m_point_for_api<C: FieldConfig<N>, const N: usize, const K: usize>(
    point: &Point<BinaryField<C, N, K>>,
) -> EC2mPoint {
    match point {
        Point::Infinity => EC2mPoint {
            x: "inf".to_string(),
            y: "inf".to_string(),
        },
        Point::Affine { x, y } => EC2mPoint {
            x: encode_binary_field_for_api(x),
            y: encode_binary_field_for_api(y),
        },
    }
}

/// Encode an EC point over extension field for API
pub fn encode_ecpk_point_for_api<C: FieldConfig<N>, const N: usize, const K: usize>(
    point: &Point<ExtensionField<C, N, K>>,
) -> ECPkPoint {
    match point {
        Point::Infinity => ECPkPoint {
            x: vec!["inf".to_string(); K],
            y: vec!["inf".to_string(); K],
        },
        Point::Affine { x, y } => ECPkPoint {
            x: encode_extension_field_for_api(x),
            y: encode_extension_field_for_api(y),
        },
    }
}

// ============================================================================
// Internal helpers used by test_runner
// ============================================================================

/// Default (max) limbs fallback when a size isn't matched
pub const BIGINT_LIMBS: usize = 48;

/// Choose an efficient limb count for a given bit length.
pub fn select_limbs_from_bits(bits: usize) -> usize {
    let required = bits.div_ceil(64);
    if required <= 4 {
        4
    } else if required <= 6 {
        6
    } else if required <= 9 {
        9
    } else if required <= 32 {
        32
    } else {
        BIGINT_LIMBS
    }
}

/// Determine bit length from a hex string
pub fn hex_bit_length_str(hex: &str) -> usize {
    let h = hex.trim_start_matches('0');
    if h.is_empty() {
        return 0;
    }
    let first = h.as_bytes()[0];
    let first_nibble_bits = match first {
        b'0' => 0,
        b'1' => 1,
        b'2' | b'3' => 2,
        b'4' | b'5' | b'6' | b'7' => 3,
        _ => 4,
    };
    (h.len() - 1) * 4 + first_nibble_bits
}

/// Modular exponentiation using Montgomery when possible
pub fn mod_pow<const N: usize>(
    base: &BigInt<N>,
    exp: &BigInt<N>,
    modulus: &BigInt<N>,
) -> BigInt<N> {
    use crate::montgomery::MontgomeryCtx;

    if modulus.is_one() {
        return BigInt::zero();
    }

    if (modulus.limbs()[0] & 1) == 1
        && let Some(ctx) = MontgomeryCtx::<N>::new(*modulus)
    {
        return ctx.mod_pow(base, exp);
    }

    // Fallback: square-and-multiply
    let mut result = BigInt::<N>::one();
    let mut base = base.modulo(modulus);
    let mut exp = *exp;

    while !exp.is_zero() {
        if exp.limbs()[0] & 1 == 1 {
            result = result.mod_mul(&base, modulus);
        }
        exp = exp >> 1;
        base = base.mod_mul(&base, modulus);
    }

    result
}

/// Convert hash bytes to scalar mod q
pub fn hash_to_scalar<const N: usize>(hash: &[u8], order: &BigInt<N>) -> BigInt<N> {
    let hash_int = BigInt::<N>::from_be_bytes(hash);
    hash_int.modulo(order)
}

/// Convert BigInt to padded hex string (lowercase)
pub fn bigint_to_padded_hex<const N: usize>(value: &BigInt<N>, byte_len: usize) -> String {
    let hex = value.to_hex();
    let target_len = byte_len * 2;
    if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len).to_lowercase()
    } else {
        hex.to_lowercase()
    }
}

/// Convert BigInt to padded hex string (uppercase)
pub fn bigint_to_padded_hex_upper<const N: usize>(value: &BigInt<N>, byte_len: usize) -> String {
    let hex = value.to_hex();
    let target_len = byte_len * 2;
    let padded = if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len)
    } else {
        hex
    };
    padded.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let bytes = hex_to_bytes("DEADBEEF");
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "deadbeef"); // bytes_to_hex returns lowercase
    }

    #[test]
    fn test_strip_json_quotes() {
        assert_eq!(strip_json_quotes(r#""hello""#), "hello");
        assert_eq!(strip_json_quotes("hello"), "hello");
    }
}
