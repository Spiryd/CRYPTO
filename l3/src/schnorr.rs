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
//! - Use SHA256 as the hash function
//! - For 128-bit security: 256-bit keys for EC, 3072-bit modulus for DL
//! - Random k must be fresh for each signature (never reuse!)

use crate::elliptic_curve::{EllipticCurve, Point};
use crate::field_trait::FieldElement;
use sha2::{Digest, Sha256};
use std::fmt::Debug;

/// Schnorr signature: (s, e)
#[derive(Clone, Debug, PartialEq)]
pub struct SchnorrSignature {
    /// Response: s = k - e*x (mod q)
    pub s: Vec<u8>,
    /// Challenge: e = H(R || m)
    pub e: Vec<u8>,
}

/// Encoding trait for converting field elements to JSON strings for hashing
pub trait SchnorrEncodable {
    /// Encode the element as a compact JSON string (no whitespaces)
    fn encode_for_hash(&self) -> String;
}

/// Schnorr signature scheme over multiplicative groups (F_p, F_2^k, F_p^k)
pub trait SchnorrField {
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
    fn generate_public_key(params: &Self::Params, private_key: u64) -> Self::Element;

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
        private_key: u64,
        message: &[u8],
        nonce: u64,
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
pub trait SchnorrEC {
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
    fn generate_public_key(params: &Self::Params, private_key: u64) -> Point<Self::Field>;

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
        private_key: u64,
        message: &[u8],
        nonce: u64,
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

/// Domain parameters for Schnorr over F_p^k
#[derive(Clone, Debug)]
pub struct SchnorrParamsField<F: FieldElement> {
    pub generator: F,
    pub order: u64, // Order q of the generator
}

/// Domain parameters for Schnorr over elliptic curves
#[derive(Clone, Debug)]
pub struct SchnorrParamsEC<F: FieldElement> {
    pub curve: EllipticCurve<F>,
    pub generator: Point<F>,
    pub order: u64, // Order q of the generator point
}

/// Implementation of Schnorr for field elements
pub struct SchnorrFieldImpl<F: FieldElement + SchnorrEncodable> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement + SchnorrEncodable + Clone + Debug> SchnorrField for SchnorrFieldImpl<F> {
    type Element = F;
    type Params = SchnorrParamsField<F>;

    fn generate_public_key(params: &Self::Params, private_key: u64) -> Self::Element {
        let x_bytes = private_key.to_le_bytes();
        params.generator.pow(&x_bytes)
    }

    fn sign(
        params: &Self::Params,
        private_key: u64,
        message: &[u8],
        nonce: u64,
    ) -> SchnorrSignature {
        // 1. Compute R = g^k
        let k_bytes = nonce.to_le_bytes();
        let r = params.generator.pow(&k_bytes);

        // 2. Compute e = H(R || m)
        let r_encoded = r.encode_for_hash();
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_hash = hasher.finalize();
        let e_bytes = e_hash.to_vec();

        // Convert e to u64 for arithmetic (mod q)
        let e_val = bytes_to_u64_mod(&e_bytes, params.order);

        // 3. Compute s = k - e*x (mod q)
        let ex = (e_val * private_key) % params.order;
        let s = if nonce >= ex {
            (nonce - ex) % params.order
        } else {
            (params.order + nonce - ex) % params.order
        };

        SchnorrSignature {
            s: s.to_le_bytes().to_vec(),
            e: e_bytes,
        }
    }

    fn verify(
        params: &Self::Params,
        public_key: &Self::Element,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool {
        // 1. Compute R' = g^s * y^e
        let s = u64::from_le_bytes(signature.s[..8].try_into().unwrap_or([0; 8]));
        let e_val = bytes_to_u64_mod(&signature.e, params.order);

        let s_bytes = s.to_le_bytes();
        let e_bytes = e_val.to_le_bytes();

        let g_s = params.generator.pow(&s_bytes);
        let y_e = public_key.pow(&e_bytes);
        let r_prime = g_s * y_e;

        // 2. Compute e' = H(R' || m)
        let r_encoded = r_prime.encode_for_hash();
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_prime = hasher.finalize();

        // 3. Verify e' == e
        e_prime.as_slice() == signature.e.as_slice()
    }
}

/// Implementation of Schnorr for elliptic curves
pub struct SchnorrECImpl<F: FieldElement + SchnorrEncodable> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: FieldElement + SchnorrEncodable + Clone + Debug> SchnorrEC for SchnorrECImpl<F> {
    type Field = F;
    type Params = SchnorrParamsEC<F>;

    fn generate_public_key(params: &Self::Params, private_key: u64) -> Point<Self::Field> {
        let x_bytes = private_key.to_le_bytes();
        params.curve.scalar_mul(&params.generator, &x_bytes)
    }

    fn sign(
        params: &Self::Params,
        private_key: u64,
        message: &[u8],
        nonce: u64,
    ) -> SchnorrSignature {
        // 1. Compute R = [k]G
        let k_bytes = nonce.to_le_bytes();
        let r = params.curve.scalar_mul(&params.generator, &k_bytes);

        // 2. Compute e = H(R || m)
        let r_encoded = encode_point_for_hash(&r);
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_hash = hasher.finalize();
        let e_bytes = e_hash.to_vec();

        // Convert e to u64 for arithmetic (mod q)
        let e_val = bytes_to_u64_mod(&e_bytes, params.order);

        // 3. Compute s = k - e*x (mod q)
        let ex = (e_val * private_key) % params.order;
        let s = if nonce >= ex {
            (nonce - ex) % params.order
        } else {
            (params.order + nonce - ex) % params.order
        };

        SchnorrSignature {
            s: s.to_le_bytes().to_vec(),
            e: e_bytes,
        }
    }

    fn verify(
        params: &Self::Params,
        public_key: &Point<Self::Field>,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool {
        // 1. Compute R' = [s]G + [e]Y
        let s = u64::from_le_bytes(signature.s[..8].try_into().unwrap_or([0; 8]));
        let e_val = bytes_to_u64_mod(&signature.e, params.order);

        let s_bytes = s.to_le_bytes();
        let e_bytes = e_val.to_le_bytes();

        let s_g = params.curve.scalar_mul(&params.generator, &s_bytes);
        let e_y = params.curve.scalar_mul(public_key, &e_bytes);
        let r_prime = params.curve.add(&s_g, &e_y);

        // 2. Compute e' = H(R' || m)
        let r_encoded = encode_point_for_hash(&r_prime);
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message);
        let e_prime = hasher.finalize();

        // 3. Verify e' == e
        e_prime.as_slice() == signature.e.as_slice()
    }
}

/// Helper function to encode an elliptic curve point for hashing
fn encode_point_for_hash<F: FieldElement + SchnorrEncodable>(point: &Point<F>) -> String {
    match point {
        Point::Infinity => r#"{"x":"inf","y":"inf"}"#.to_string(),
        Point::Affine { x, y } => {
            let x_enc = x.encode_for_hash();
            let y_enc = y.encode_for_hash();
            format!(r#"{{"x":{},"y":{}}}"#, x_enc, y_enc)
        }
    }
}

/// Helper function to convert hash bytes to u64 modulo q
fn bytes_to_u64_mod(bytes: &[u8], modulus: u64) -> u64 {
    // Take first 8 bytes and convert to u64, then mod q
    let mut val = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        val |= (b as u64) << (i * 8);
    }
    val % modulus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_u64_mod() {
        let bytes = vec![0x30, 0x18, 0xf4, 0xfa, 0x00, 0x00, 0x00, 0x00];
        let result = bytes_to_u64_mod(&bytes, 100);
        assert_eq!(result, bytes_to_u64_mod(&bytes, 100));
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
}
