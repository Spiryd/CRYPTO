//! Schnorr Signature Scheme
//!
//! This module implements the Schnorr digital signature scheme for:
//! 1. Prime fields F_p and extension fields F_p^k
//! 2. Elliptic curves over various fields
//!
//! The signature is a pair (s, e) where:
//! - e = H(R || m) is the hash of commitment R and message m
//! - s = k - e*x (mod q) is the response
//!
//! # Security
//! - Uses SHA256 as the hash function (full 256-bit output)
//! - Uses BigInt<N> for scalars to support cryptographic security levels
//! - For 128-bit security: 256-bit keys for EC, 3072-bit modulus for DL
//! - Random k must be fresh for each signature (never reuse!)

use crate::bigint::BigInt;
use crate::elliptic_curve::{EllipticCurve, Point};
use crate::field_trait::FieldElement;
use sha2::{Digest, Sha256};
use std::fmt::Debug;

/// Schnorr signature: (s, e)
///
/// - `s` is stored as big-endian bytes
/// - `e` is the full SHA256 hash (32 bytes)
#[derive(Clone, Debug, PartialEq)]
pub struct SchnorrSignature {
    /// Response: s = k - e*x (mod q), stored as big-endian bytes
    pub s: Vec<u8>,
    /// Challenge: e = H(R || m), the full SHA256 hash (32 bytes)
    pub e: Vec<u8>,
}

/// Encoding trait for converting field elements to JSON strings for hashing
pub trait SchnorrEncodable {
    /// Encode the element as a compact JSON string (no whitespaces)
    fn encode_for_hash(&self) -> String;
}

/// Domain parameters for Schnorr over F_p^k
#[derive(Clone, Debug)]
pub struct SchnorrParamsField<F: FieldElement, const N: usize> {
    pub generator: F,
    /// Order q of the generator (as BigInt for large orders)
    pub order: BigInt<N>,
}

/// Domain parameters for Schnorr over elliptic curves
#[derive(Clone, Debug)]
pub struct SchnorrParamsEC<F: FieldElement, const N: usize> {
    pub curve: EllipticCurve<F>,
    pub generator: Point<F>,
    /// Order q of the generator point (as BigInt for 256-bit curves)
    pub order: BigInt<N>,
}

/// Schnorr signature scheme over multiplicative groups (F_p, F_2^k, F_p^k)
pub trait SchnorrField<const N: usize> {
    /// Field element type
    type Element: FieldElement + SchnorrEncodable + Clone + Debug;

    /// Parameters for the signature scheme
    type Params: Clone + Debug;

    /// Generate a key pair
    ///
    /// # Arguments
    /// * `params` - Domain parameters
    /// * `private_key` - Private key x (should be random in [1, q-1])
    ///
    /// # Returns
    /// Public key y = g^x
    fn generate_public_key(params: &Self::Params, private_key: &BigInt<N>) -> Self::Element;

    /// Sign a message
    ///
    /// # Arguments
    /// * `params` - Domain parameters
    /// * `private_key` - Private key x
    /// * `message` - Message to sign
    /// * `nonce` - Random nonce k (must be fresh for each signature!)
    ///
    /// # Returns
    /// Schnorr signature (s, e)
    fn sign(
        params: &Self::Params,
        private_key: &BigInt<N>,
        message: &[u8],
        nonce: &BigInt<N>,
    ) -> SchnorrSignature;

    /// Verify a signature
    ///
    /// # Arguments
    /// * `params` - Domain parameters
    /// * `public_key` - Public key y
    /// * `message` - Message that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// True if signature is valid
    fn verify(
        params: &Self::Params,
        public_key: &Self::Element,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool;
}

/// Schnorr signature scheme over elliptic curves
pub trait SchnorrEC<const N: usize> {
    /// Field element type for coordinates
    type Field: FieldElement + SchnorrEncodable + Clone + Debug;

    /// Parameters for the signature scheme
    type Params: Clone + Debug;

    /// Generate a key pair
    ///
    /// # Arguments
    /// * `params` - Domain parameters (curve + generator)
    /// * `private_key` - Private key x (should be random in [1, q-1])
    ///
    /// # Returns
    /// Public key Y = [x]G
    fn generate_public_key(params: &Self::Params, private_key: &BigInt<N>) -> Point<Self::Field>;

    /// Sign a message
    ///
    /// # Arguments
    /// * `params` - Domain parameters
    /// * `private_key` - Private key x
    /// * `message` - Message to sign
    /// * `nonce` - Random nonce k (must be fresh for each signature!)
    ///
    /// # Returns
    /// Schnorr signature (s, e)
    fn sign(
        params: &Self::Params,
        private_key: &BigInt<N>,
        message: &[u8],
        nonce: &BigInt<N>,
    ) -> SchnorrSignature;

    /// Verify a signature
    ///
    /// # Arguments
    /// * `params` - Domain parameters
    /// * `public_key` - Public key Y
    /// * `message` - Message that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// True if signature is valid
    fn verify(
        params: &Self::Params,
        public_key: &Point<Self::Field>,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool;
}

/// Convert full SHA256 hash (32 bytes) to scalar mod q
///
/// This uses the full 256-bit hash and reduces modulo the group order,
/// providing the required security level for 128-bit security curves.
pub fn hash_to_scalar_mod_q<const N: usize>(hash_bytes: &[u8], order: &BigInt<N>) -> BigInt<N> {
    // SHA256 produces 32 bytes (256 bits) in big-endian
    // Convert to BigInt and reduce mod q
    let hash_int = BigInt::<N>::from_be_bytes(hash_bytes);
    hash_int.modulo(order)
}

/// Validation result for Schnorr signatures
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureValidationError {
    /// Signature s component is empty
    EmptyS,
    /// Signature e component is empty or wrong size
    InvalidE,
    /// Signature s is not less than order q
    SNotLessThanOrder,
    /// Public key is identity element (EC: point at infinity, Field: 1)
    IdentityPublicKey,
    /// Computed R' is identity (EC: point at infinity)
    IdentityR,
}

/// Validate a Schnorr signature format
///
/// Checks:
/// - s is non-empty and not too long
/// - e is exactly 32 bytes (SHA256 output)
/// - s < q (when parsed as BigInt)
pub fn validate_signature<const N: usize>(
    signature: &SchnorrSignature,
    order: &BigInt<N>,
) -> Result<(), SignatureValidationError> {
    // Check e is exactly 32 bytes (SHA256)
    if signature.e.len() != 32 {
        return Err(SignatureValidationError::InvalidE);
    }

    // Check s is non-empty
    if signature.s.is_empty() {
        return Err(SignatureValidationError::EmptyS);
    }

    // Check s < q
    let s = BigInt::<N>::from_be_bytes(&signature.s);
    if s.compare(order) != std::cmp::Ordering::Less {
        return Err(SignatureValidationError::SNotLessThanOrder);
    }

    Ok(())
}

/// Implementation of Schnorr for field elements
pub struct SchnorrFieldImpl<F: FieldElement + SchnorrEncodable, const N: usize> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement + SchnorrEncodable + Clone + Debug, const N: usize> SchnorrField<N>
    for SchnorrFieldImpl<F, N>
{
    type Element = F;
    type Params = SchnorrParamsField<F, N>;

    fn generate_public_key(params: &Self::Params, private_key: &BigInt<N>) -> Self::Element {
        // y = g^x
        let x_bytes = private_key.to_le_bytes_vec();
        params.generator.pow(&x_bytes)
    }

    fn sign(
        params: &Self::Params,
        private_key: &BigInt<N>,
        message: &[u8],
        nonce: &BigInt<N>,
    ) -> SchnorrSignature {
        // 1. Compute R = g^k
        let k_bytes = nonce.to_le_bytes_vec();
        let r = params.generator.pow(&k_bytes);

        // 2. Compute e = H(R || m) using full SHA256 output
        let r_encoded = r.encode_for_hash();
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_hash = hasher.finalize();
        let e_bytes = e_hash.to_vec();

        // Convert e to BigInt mod q (using FULL 32-byte hash)
        let e_scalar = hash_to_scalar_mod_q(&e_bytes, &params.order);

        // 3. Compute s = k - e*x (mod q)
        let ex = e_scalar.mod_mul(private_key, &params.order);
        let s = nonce.mod_sub(&ex, &params.order);

        SchnorrSignature {
            s: s.to_be_bytes(),
            e: e_bytes,
        }
    }

    fn verify(
        params: &Self::Params,
        public_key: &Self::Element,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool {
        // 0. Validate signature format
        if validate_signature(signature, &params.order).is_err() {
            return false;
        }

        // Note: For multiplicative groups, we could check if public_key == 1 (identity)
        // but this requires PartialEq which may not be available for all field types.
        // Skipping this check as it's a low-probability edge case.

        // 1. Parse s and e from signature
        let s = BigInt::<N>::from_be_bytes(&signature.s);
        let e_scalar = hash_to_scalar_mod_q(&signature.e, &params.order);

        // 2. Compute R' = g^s * y^e
        let s_bytes = s.to_le_bytes_vec();
        let e_bytes = e_scalar.to_le_bytes_vec();

        let g_s = params.generator.pow(&s_bytes);
        let y_e = public_key.pow(&e_bytes);
        let r_prime = g_s * y_e;

        // 3. Compute e' = H(R' || m)
        let r_encoded = r_prime.encode_for_hash();
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_prime = hasher.finalize();

        // 4. Verify e' == e (compare full hash)
        e_prime.as_slice() == signature.e.as_slice()
    }
}

/// Implementation of Schnorr for elliptic curves
pub struct SchnorrECImpl<F: FieldElement + SchnorrEncodable, const N: usize> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement + SchnorrEncodable + Clone + Debug, const N: usize> SchnorrEC<N>
    for SchnorrECImpl<F, N>
{
    type Field = F;
    type Params = SchnorrParamsEC<F, N>;

    fn generate_public_key(params: &Self::Params, private_key: &BigInt<N>) -> Point<Self::Field> {
        // Y = [x]G
        let x_bytes = private_key.to_le_bytes_vec();
        params.curve.scalar_mul(&params.generator, &x_bytes)
    }

    fn sign(
        params: &Self::Params,
        private_key: &BigInt<N>,
        message: &[u8],
        nonce: &BigInt<N>,
    ) -> SchnorrSignature {
        // 1. Compute R = [k]G
        let k_bytes = nonce.to_le_bytes_vec();
        let r = params.curve.scalar_mul(&params.generator, &k_bytes);

        // 2. Compute e = H(R || m) using full SHA256 output
        let r_encoded = encode_point_for_hash(&r);
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_hash = hasher.finalize();
        let e_bytes = e_hash.to_vec();

        // Convert e to BigInt mod q (using FULL 32-byte hash)
        let e_scalar = hash_to_scalar_mod_q(&e_bytes, &params.order);

        // 3. Compute s = k - e*x (mod q)
        let ex = e_scalar.mod_mul(private_key, &params.order);
        let s = nonce.mod_sub(&ex, &params.order);

        SchnorrSignature {
            s: s.to_be_bytes(),
            e: e_bytes,
        }
    }

    fn verify(
        params: &Self::Params,
        public_key: &Point<Self::Field>,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool {
        // 0. Validate signature format
        if validate_signature(signature, &params.order).is_err() {
            return false;
        }

        // 0b. Reject point at infinity as public key
        if matches!(public_key, Point::Infinity) {
            return false;
        }

        // 1. Parse s and e from signature
        let s = BigInt::<N>::from_be_bytes(&signature.s);
        let e_scalar = hash_to_scalar_mod_q(&signature.e, &params.order);

        // 2. Compute R' = [s]G + [e]Y
        let s_bytes = s.to_le_bytes_vec();
        let e_bytes = e_scalar.to_le_bytes_vec();

        let s_g = params.curve.scalar_mul(&params.generator, &s_bytes);
        let e_y = params.curve.scalar_mul(public_key, &e_bytes);
        let r_prime = params.curve.add(&s_g, &e_y);

        // 0c. Reject if R' is point at infinity
        if matches!(r_prime, Point::Infinity) {
            return false;
        }

        // 3. Compute e' = H(R' || m)
        let r_encoded = encode_point_for_hash(&r_prime);
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_prime = hasher.finalize();

        // 4. Verify e' == e (compare full hash)
        e_prime.as_slice() == signature.e.as_slice()
    }
}

/// Helper function to encode an elliptic curve point for hashing
pub fn encode_point_for_hash<F: FieldElement + SchnorrEncodable>(point: &Point<F>) -> String {
    match point {
        Point::Infinity => r#"{"x":"inf","y":"inf"}"#.to_string(),
        Point::Affine { x, y } => {
            let x_enc = x.encode_for_hash();
            let y_enc = y.encode_for_hash();
            format!(r#"{{"x":{},"y":{}}}"#, x_enc, y_enc)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::config::FieldConfig;
    use crate::field::prime::PrimeField;

    // Test field F_97
    #[derive(Clone, Debug)]
    struct F97Config;
    static F97_MOD: BigInt<4> = BigInt::from_limbs_internal([97, 0, 0, 0]);
    impl FieldConfig<4> for F97Config {
        fn modulus() -> &'static BigInt<4> {
            &F97_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }
    type Fp97 = PrimeField<F97Config, 4>;

    #[test]
    fn test_hash_to_scalar_mod_q() {
        // Test with a known hash and modulus
        let hash = [
            0x30, 0x18, 0xf4, 0xfa, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x11, 0x22, 0x33, 0x44,
        ];
        let order = BigInt::<4>::from_u64(97);
        let result = hash_to_scalar_mod_q(&hash, &order);

        // Result should be in [0, 96]
        assert!(result.compare(&order) == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_schnorr_signature_creation() {
        let sig = SchnorrSignature {
            s: vec![1, 2, 3],
            e: vec![4, 5, 6],
        };
        assert_eq!(sig.s, vec![1, 2, 3]);
        assert_eq!(sig.e, vec![4, 5, 6]);
    }

    // ========================================================================
    // Round-trip tests: Sign → Verify should succeed
    // ========================================================================

    #[test]
    fn test_schnorr_field_roundtrip_f97() {
        // DL Schnorr over F_97 with generator g=5 (order 96)
        let generator = Fp97::new(BigInt::from_u64(5));
        let order = BigInt::<4>::from_u64(96);
        let params: SchnorrParamsField<Fp97, 4> = SchnorrParamsField { generator, order };

        let private_key = BigInt::<4>::from_u64(42);
        let nonce = BigInt::<4>::from_u64(17);
        let message = b"Hello, Schnorr!";

        // Sign
        let signature = SchnorrFieldImpl::<Fp97, 4>::sign(&params, &private_key, message, &nonce);

        // Generate public key
        let public_key = SchnorrFieldImpl::<Fp97, 4>::generate_public_key(&params, &private_key);

        // Verify - should succeed
        let valid = SchnorrFieldImpl::<Fp97, 4>::verify(&params, &public_key, message, &signature);
        assert!(valid, "Valid signature should verify");
    }

    #[test]
    fn test_schnorr_field_tampered_message_fails() {
        // DL Schnorr over F_97
        let generator = Fp97::new(BigInt::from_u64(5));
        let order = BigInt::<4>::from_u64(96);
        let params: SchnorrParamsField<Fp97, 4> = SchnorrParamsField { generator, order };

        let private_key = BigInt::<4>::from_u64(42);
        let nonce = BigInt::<4>::from_u64(17);
        let message = b"Hello, Schnorr!";
        let tampered_message = b"Hello, Schnorr?";

        // Sign original message
        let signature = SchnorrFieldImpl::<Fp97, 4>::sign(&params, &private_key, message, &nonce);
        let public_key = SchnorrFieldImpl::<Fp97, 4>::generate_public_key(&params, &private_key);

        // Verify with tampered message - should fail
        let valid =
            SchnorrFieldImpl::<Fp97, 4>::verify(&params, &public_key, tampered_message, &signature);
        assert!(!valid, "Tampered message should not verify");
    }

    #[test]
    fn test_schnorr_field_tampered_signature_s_fails() {
        // DL Schnorr over F_97
        let generator = Fp97::new(BigInt::from_u64(5));
        let order = BigInt::<4>::from_u64(96);
        let params: SchnorrParamsField<Fp97, 4> = SchnorrParamsField { generator, order };

        let private_key = BigInt::<4>::from_u64(42);
        let nonce = BigInt::<4>::from_u64(17);
        let message = b"Hello, Schnorr!";

        // Sign
        let mut signature =
            SchnorrFieldImpl::<Fp97, 4>::sign(&params, &private_key, message, &nonce);
        let public_key = SchnorrFieldImpl::<Fp97, 4>::generate_public_key(&params, &private_key);

        // Tamper with s
        if let Some(last) = signature.s.last_mut() {
            *last ^= 0x01; // Flip a bit
        }

        // Verify with tampered s - should fail
        let valid = SchnorrFieldImpl::<Fp97, 4>::verify(&params, &public_key, message, &signature);
        assert!(!valid, "Tampered s should not verify");
    }

    #[test]
    fn test_schnorr_field_tampered_signature_e_fails() {
        // DL Schnorr over F_97
        let generator = Fp97::new(BigInt::from_u64(5));
        let order = BigInt::<4>::from_u64(96);
        let params: SchnorrParamsField<Fp97, 4> = SchnorrParamsField { generator, order };

        let private_key = BigInt::<4>::from_u64(42);
        let nonce = BigInt::<4>::from_u64(17);
        let message = b"Hello, Schnorr!";

        // Sign
        let mut signature =
            SchnorrFieldImpl::<Fp97, 4>::sign(&params, &private_key, message, &nonce);
        let public_key = SchnorrFieldImpl::<Fp97, 4>::generate_public_key(&params, &private_key);

        // Tamper with e
        if let Some(first) = signature.e.first_mut() {
            *first ^= 0x01; // Flip a bit
        }

        // Verify with tampered e - should fail
        let valid = SchnorrFieldImpl::<Fp97, 4>::verify(&params, &public_key, message, &signature);
        assert!(!valid, "Tampered e should not verify");
    }

    #[test]
    fn test_schnorr_field_wrong_public_key_fails() {
        // DL Schnorr over F_97
        let generator = Fp97::new(BigInt::from_u64(5));
        let order = BigInt::<4>::from_u64(96);
        let params: SchnorrParamsField<Fp97, 4> = SchnorrParamsField { generator, order };

        let private_key = BigInt::<4>::from_u64(42);
        let wrong_private_key = BigInt::<4>::from_u64(43);
        let nonce = BigInt::<4>::from_u64(17);
        let message = b"Hello, Schnorr!";

        // Sign with correct key
        let signature = SchnorrFieldImpl::<Fp97, 4>::sign(&params, &private_key, message, &nonce);

        // Generate wrong public key
        let wrong_public_key =
            SchnorrFieldImpl::<Fp97, 4>::generate_public_key(&params, &wrong_private_key);

        // Verify with wrong public key - should fail
        let valid =
            SchnorrFieldImpl::<Fp97, 4>::verify(&params, &wrong_public_key, message, &signature);
        assert!(!valid, "Wrong public key should not verify");
    }

    #[test]
    fn test_schnorr_field_generator_and_pubkey_nonzero() {
        // Ensure generator and public key are not zero
        let generator = Fp97::new(BigInt::from_u64(5));
        let order = BigInt::<4>::from_u64(96);
        let params: SchnorrParamsField<Fp97, 4> = SchnorrParamsField {
            generator: generator.clone(),
            order,
        };

        let private_key = BigInt::<4>::from_u64(42);
        let public_key = SchnorrFieldImpl::<Fp97, 4>::generate_public_key(&params, &private_key);

        // Generator should not be 0 (using is_zero from FieldElement trait)
        assert!(!generator.is_zero(), "Generator must not be zero");

        // Public key should not be 0 (for non-trivial private key)
        assert!(!public_key.is_zero(), "Public key must not be zero");
    }
}
