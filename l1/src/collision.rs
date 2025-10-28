//! MD5 collision verification for differential cryptanalysis attacks.
//! Verifies collisions: MD5(MD5(IV, M0), M1) == MD5(MD5(IV, M'0), M'1)

use crate::md5::{compute_md5_digest_with_iv, bit_padding};
use crate::InitialValues;

#[derive(Debug, Clone)]
pub struct CollisionResult {
    pub is_collision: bool,
    pub h_hex: String,
    pub h_prime_hex: String,
    pub iv0: InitialValues,
    pub iv0_prime: InitialValues,
}

pub struct CollisionVerifier {
    initial_iv: InitialValues,
}

impl CollisionVerifier {
    pub fn new(iv: InitialValues) -> Self {
        Self { initial_iv: iv }
    }
    
    /// Compute intermediate IV: IV0 = MD5(IV, M)
    pub fn compute_iv(&self, message: &[u8]) -> InitialValues {
        let padded = bit_padding(message);
        let digest = compute_md5_digest_with_iv(padded, self.initial_iv);
        
        // Convert [u8; 16] to [u32; 4] (little-endian)
        let a = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let b = u32::from_le_bytes([digest[4], digest[5], digest[6], digest[7]]);
        let c = u32::from_le_bytes([digest[8], digest[9], digest[10], digest[11]]);
        let d = u32::from_le_bytes([digest[12], digest[13], digest[14], digest[15]]);
        
        InitialValues { a, b, c, d }
    }
    
    /// Compute final hash: H = MD5(IV, M)
    pub fn compute_hash(&self, iv: InitialValues, message: &[u8]) -> [u32; 4] {
        let padded = bit_padding(message);
        let digest = compute_md5_digest_with_iv(padded, iv);
        
        [
            u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]),
            u32::from_le_bytes([digest[4], digest[5], digest[6], digest[7]]),
            u32::from_le_bytes([digest[8], digest[9], digest[10], digest[11]]),
            u32::from_le_bytes([digest[12], digest[13], digest[14], digest[15]]),
        ]
    }
    
    /// Verify collision: MD5(MD5(IV, M0), M1) == MD5(MD5(IV, M'0), M'1)
    pub fn verify(&self, m0: &[u8], m0_prime: &[u8], m1: &[u8], m1_prime: &[u8]) -> CollisionResult {
        let iv0 = self.compute_iv(m0);
        let iv0_prime = self.compute_iv(m0_prime);
        let h = self.compute_hash(iv0, m1);
        let h_prime = self.compute_hash(iv0_prime, m1_prime);
        
        CollisionResult {
            is_collision: h == h_prime,
            h_hex: format!("{:08x}{:08x}{:08x}{:08x}", h[0], h[1], h[2], h[3]),
            h_prime_hex: format!("{:08x}{:08x}{:08x}{:08x}", h_prime[0], h_prime[1], h_prime[2], h_prime[3]),
            iv0,
            iv0_prime,
        }
    }
}

pub fn verify_collision(
    iv: InitialValues,
    m0: &[u8],
    m0_prime: &[u8],
    m1: &[u8],
    m1_prime: &[u8],
) -> CollisionResult {
    let verifier = CollisionVerifier::new(iv);
    verifier.verify(m0, m0_prime, m1, m1_prime)
}

/// Parse hex string to bytes (expects 64 bytes / 128 hex chars for one MD5 block)
pub fn parse_hex_block(hex_str: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&cleaned).map_err(|e| format!("Hex decode error: {}", e))
}

/// Convert hash array to hex string (little-endian)
pub fn hash_to_hex(hash: &[u32; 4]) -> String {
    let mut bytes = Vec::with_capacity(16);
    for &word in hash.iter() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    hex::encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_collision_verifier_same_messages() {
        let iv = InitialValues::STANDARD;
        let m0 = b"test message 1";
        let m1 = b"test message 2";
        
        let result = verify_collision(iv, m0, m0, m1, m1);
        
        // Same messages should always produce same hash
        assert!(result.is_collision);
        assert_eq!(result.h_hex, result.h_prime_hex);
    }
    
    #[test]
    fn test_collision_verifier_different_messages() {
        let iv = InitialValues::STANDARD;
        let m0 = b"message A";
        let m0_prime = b"message B";
        let m1 = b"continuation";
        let m1_prime = b"continuation";
        
        let result = verify_collision(iv, m0, m0_prime, m1, m1_prime);
        
        // Different messages (without crafted collision) should produce different hashes
        assert!(!result.is_collision);
        assert_ne!(result.h_hex, result.h_prime_hex);
    }
    
    #[test]
    fn test_parse_hex_block() {
        let hex = "0123456789abcdef0123456789abcdef\
                   0123456789abcdef0123456789abcdef\
                   0123456789abcdef0123456789abcdef\
                   0123456789abcdef0123456789abcdef";
        
        let bytes = parse_hex_block(hex).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x23);
    }
    
    #[test]
    fn test_parse_hex_block_with_whitespace() {
        let hex = "00 11 22 33\n44 55 66 77\n88 99 aa bb\ncc dd ee ff\
                   00 11 22 33\n44 55 66 77\n88 99 aa bb\ncc dd ee ff\
                   00 11 22 33\n44 55 66 77\n88 99 aa bb\ncc dd ee ff\
                   00 11 22 33\n44 55 66 77\n88 99 aa bb\ncc dd ee ff";
        
        let bytes = parse_hex_block(hex).unwrap();
        assert_eq!(bytes.len(), 64);
    }
    
    #[test]
    fn test_hash_to_hex() {
        let hash = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210];
        let hex = hash_to_hex(&hash);
        
        // Should be in little-endian byte order
        assert_eq!(hex, "67452301efcdab8998badcfe10325476");
    }
}
