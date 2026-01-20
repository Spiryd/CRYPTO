//! Schnorr encoding implementations for field types
//!
//! This module implements the SchnorrEncodable trait for different field types
//! according to the encoding rules for SHA256 hashing in Schnorr signatures.

use crate::field::config::FieldConfig;
use crate::field::{BinaryField, ExtensionField, PrimeField};
use crate::schnorr::SchnorrEncodable;

// ============================================================================
// PrimeField encoding: big-endian hex string
// ============================================================================

impl<C: FieldConfig<N>, const N: usize> SchnorrEncodable for PrimeField<C, N> {
    fn encode_for_hash(&self) -> String {
        // Encode as big-endian hex string with same bit/byte length as modulus
        // Example: if p = 65537 = 0x010001, encode 17 as "000011"

        let modulus = C::modulus();
        let bit_len = modulus.bit_length();
        let byte_len = bit_len.div_ceil(8); // Round up to full bytes

        // Convert value to hex (already big-endian from BigInt)
        let hex = self.value().to_hex();

        // Pad to match modulus byte length (2 hex chars per byte)
        let target_len = byte_len * 2;
        let padded = if hex.len() < target_len {
            format!("{:0>width$}", hex, width = target_len)
        } else {
            hex
        };

        // Return as quoted JSON string
        format!(r#""{}""#, padded.to_uppercase())
    }
}

// ============================================================================
// BinaryField encoding: bit string as integer (hex)
// ============================================================================

impl<C: FieldConfig<N>, const N: usize, const K: usize> SchnorrEncodable for BinaryField<C, N, K> {
    fn encode_for_hash(&self) -> String {
        // Encode bit string as integer, rounded up to 8 bits (full bytes)
        // Example: if m = 33, round to 40 bits (5 bytes)
        // x^3 + x^2 + 1 = 0b1101 = 0x0D -> "000000000D"

        let byte_len = K.div_ceil(8); // Round up to full bytes

        // Convert bits to hex
        let hex = self.bits().to_hex();

        // Pad to byte boundary (2 hex chars per byte)
        let target_len = byte_len * 2;
        let padded = if hex.len() < target_len {
            format!("{:0>width$}", hex, width = target_len)
        } else {
            hex
        };

        // Return as quoted JSON string
        format!(r#""{}""#, padded.to_uppercase())
    }
}

// ============================================================================
// ExtensionField encoding: array of coefficients
// ============================================================================

impl<C: FieldConfig<N>, const N: usize, const K: usize> SchnorrEncodable
    for ExtensionField<C, N, K>
{
    fn encode_for_hash(&self) -> String {
        // Encode as array of k coefficients [c0, c1, ..., c_{k-1}]
        // Each coefficient is encoded as big-endian hex like PrimeField
        // Example: 3x^2 + 16 in F_17^3 -> ["10","00","03"]

        let modulus = C::modulus();
        let bit_len = modulus.bit_length();
        let byte_len = bit_len.div_ceil(8);
        let target_len = byte_len * 2;

        let coeffs = self.coefficients();
        let encoded_coeffs: Vec<String> = coeffs
            .iter()
            .map(|coeff| {
                let hex = coeff.to_hex();
                let padded = if hex.len() < target_len {
                    format!("{:0>width$}", hex, width = target_len)
                } else {
                    hex
                };
                format!(r#""{}""#, padded.to_uppercase())
            })
            .collect();

        // Return as JSON array
        format!("[{}]", encoded_coeffs.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigInt;
    use crate::field::FieldConfig;

    #[derive(Clone, Debug)]
    struct F65537;
    static F65537_MOD: BigInt<4> = BigInt::from_u64(65537);
    impl FieldConfig<4> for F65537 {
        fn modulus() -> &'static BigInt<4> {
            &F65537_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }
    type Fp65537 = PrimeField<F65537, 4>;

    #[test]
    fn test_prime_field_encoding() {
        // Example from spec: p = 65537 = 0x010001, n = 17 -> "000011"
        let n = Fp65537::from_u64(17);
        let encoded = n.encode_for_hash();
        assert_eq!(encoded, r#""000011""#);
    }

    #[derive(Clone, Debug)]
    struct F2_33;
    static F2_MOD: BigInt<4> = BigInt::from_u64(2);
    static F2_33_IRRED: [BigInt<4>; 34] = [
        BigInt::from_u64(1),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(0),
        BigInt::from_u64(1),
    ];
    impl FieldConfig<4> for F2_33 {
        fn modulus() -> &'static BigInt<4> {
            &F2_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &F2_33_IRRED
        }
    }
    type F2k33 = BinaryField<F2_33, 4, 33>;

    #[test]
    fn test_binary_field_encoding() {
        // Example from spec: x^3 + x^2 + 1 = 0b1101 = 0x0D
        // m = 33 rounds to 40 bits (5 bytes) -> "000000000D"
        let n = F2k33::from_u64(0x0D); // x^3 + x^2 + 1
        let encoded = n.encode_for_hash();
        assert_eq!(encoded, r#""000000000D""#);
    }

    #[derive(Clone, Debug)]
    struct F17_3;
    static F17_MOD: BigInt<4> = BigInt::from_u64(17);
    static F17_IRRED: [BigInt<4>; 3] = [
        BigInt::from_u64(1),
        BigInt::from_u64(0),
        BigInt::from_u64(1),
    ];
    impl FieldConfig<4> for F17_3 {
        fn modulus() -> &'static BigInt<4> {
            &F17_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &F17_IRRED
        }
    }
    type F173 = ExtensionField<F17_3, 4, 3>;

    #[test]
    fn test_extension_field_encoding() {
        // Example from spec: 3x^2 + 16 in F_17^3 -> ["10","00","03"]
        let coeffs = [
            BigInt::from_u64(16),
            BigInt::from_u64(0),
            BigInt::from_u64(3),
        ];
        let n = F173::from_coeffs(coeffs);
        let encoded = n.encode_for_hash();
        assert_eq!(encoded, r#"["10","00","03"]"#);
    }
}
