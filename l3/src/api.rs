//! API module for interacting with the crypto25.random-oracle.xyz service
//!
//! This module provides a client for testing DH and Schnorr implementations
//! against the remote validation service.

use crate::bigint::BigInt;
use crate::elliptic_curve::Point;
use crate::field::{BinaryField, ExtensionField, FieldConfig, PrimeField};
use crate::schnorr::SchnorrSignature;
use rand::Rng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Base URL for the crypto challenge service
pub const API_BASE_URL: &str = "https://crypto25.random-oracle.xyz";

/// Challenge types supported by the API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeType {
    Modp,
    F2m,
    Fpk,
    Ecp,
    Ec2m,
    Ecpk,
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeType::Modp => write!(f, "modp"),
            ChallengeType::F2m => write!(f, "f2m"),
            ChallengeType::Fpk => write!(f, "fpk"),
            ChallengeType::Ecp => write!(f, "ecp"),
            ChallengeType::Ec2m => write!(f, "ec2m"),
            ChallengeType::Ecpk => write!(f, "ecpk"),
        }
    }
}

// ============================================================================
// API Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct BaseResponse {
    pub status: String,
}

/// Schnorr signature as returned by the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSignature {
    pub s: String,
    pub e: String,
}

impl ApiSignature {
    /// Convert API signature to internal SchnorrSignature
    pub fn to_schnorr_signature(&self) -> SchnorrSignature {
        SchnorrSignature {
            s: hex_to_bytes(&self.s),
            e: hex_to_bytes(&self.e),
        }
    }

    /// Create from internal SchnorrSignature
    pub fn from_schnorr_signature(sig: &SchnorrSignature) -> Self {
        ApiSignature {
            s: bytes_to_hex(&sig.s),
            e: bytes_to_hex(&sig.e),
        }
    }
}

/// ModP parameters from API
#[derive(Debug, Clone, Deserialize)]
pub struct ModPParams {
    pub name: String,
    pub modulus: String,
    pub generator: String,
    pub order: String,
}

/// F2m parameters from API
#[derive(Debug, Clone, Deserialize)]
pub struct F2mParams {
    pub name: String,
    pub extension: usize,
    pub modulus: String,
    pub generator: String,
    pub order: String,
}

/// Fpk parameters from API
#[derive(Debug, Clone, Deserialize)]
pub struct FpkParams {
    pub name: String,
    pub prime_base: String,
    pub extension: usize,
    pub modulus: Vec<String>,
    pub generator: Vec<String>,
    pub order: String,
}

/// EC point for prime curves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECPPoint {
    pub x: String,
    pub y: String,
}

/// EC point for binary curves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EC2mPoint {
    pub x: String,
    pub y: String,
}

/// EC point for extension field curves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECPkPoint {
    pub x: Vec<String>,
    pub y: Vec<String>,
}

/// ECP parameters from API
#[derive(Debug, Clone, Deserialize)]
pub struct ECPParams {
    pub name: String,
    pub modulus: String,
    pub a: String,
    pub b: String,
    pub generator: ECPPoint,
    pub order: String,
}

/// EC2m parameters from API
#[derive(Debug, Clone, Deserialize)]
pub struct EC2mParams {
    pub name: String,
    pub extension: usize,
    pub modulus: String,
    pub a: String,
    pub b: String,
    pub generator: EC2mPoint,
    pub order: String,
}

/// ECPk parameters from API
#[derive(Debug, Clone, Deserialize)]
pub struct ECPkParams {
    pub name: String,
    pub prime_base: String,
    pub extension: usize,
    pub modulus: Vec<String>,
    pub a: Vec<String>,
    pub b: Vec<String>,
    pub generator: ECPkPoint,
    pub order: String,
}

/// Parameter response wrapper
#[derive(Debug, Clone, Deserialize)]
pub struct ParamResponse {
    pub status: String,
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    pub params: serde_json::Value, // We'll parse this based on type
}

/// Test DH ModP request
#[derive(Debug, Serialize)]
pub struct TestDHModPRequest {
    pub client_public: String,
}

/// Test DH ModP response
#[derive(Debug, Deserialize)]
pub struct TestDHModPResponse {
    pub status: String,
    pub server_public: String,
    pub shared_secret: String,
}

/// Test DH F2m request
#[derive(Debug, Serialize)]
pub struct TestDHF2mRequest {
    pub client_public: String,
}

/// Test DH F2m response
#[derive(Debug, Deserialize)]
pub struct TestDHF2mResponse {
    pub status: String,
    pub server_public: String,
    pub shared_secret: String,
}

/// Test DH Fpk request
#[derive(Debug, Serialize)]
pub struct TestDHFpkRequest {
    pub client_public: Vec<String>,
}

/// Test DH Fpk response
#[derive(Debug, Deserialize)]
pub struct TestDHFpkResponse {
    pub status: String,
    pub server_public: Vec<String>,
    pub shared_secret: Vec<String>,
}

/// Test DH EC request (for ecp, ec2m, ecpk)
#[derive(Debug, Serialize)]
pub struct TestDHECRequest<P> {
    pub client_public: P,
}

/// Test DH EC response
#[derive(Debug, Deserialize)]
pub struct TestDHECResponse<P> {
    pub status: String,
    pub server_public: P,
    pub shared_secret: P,
}

/// Test signature request
#[derive(Debug, Serialize)]
pub struct TestSignatureRequest {
    pub message: String,
}

/// Test signature response (generic for different public key types)
#[derive(Debug, Deserialize)]
pub struct TestSignatureResponse {
    pub status: String,
    pub public: serde_json::Value,
    pub signature: ApiSignature,
}

// ============================================================================
// API Client
// ============================================================================

pub struct CryptoApiClient {
    client: Client,
    base_url: String,
}

impl CryptoApiClient {
    /// Create a new API client with default settings
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            base_url: API_BASE_URL.to_string(),
        }
    }

    /// Create with custom base URL (for testing)
    pub fn with_base_url(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            base_url: base_url.to_string(),
        }
    }

    /// Test basic connectivity
    pub fn test_connection(&self) -> Result<BaseResponse, ApiError> {
        let url = format!("{}/", self.base_url);
        let response = self.client.get(&url).send()?;
        let body: BaseResponse = response.json()?;
        Ok(body)
    }

    // ========================================================================
    // Parameter Endpoints
    // ========================================================================

    /// Get test parameters for a challenge type
    pub fn get_test_params(&self, challenge_type: ChallengeType) -> Result<ParamResponse, ApiError> {
        let url = format!("{}/test/param/{}", self.base_url, challenge_type);
        let response = self.client.get(&url).send()?;
        let body: ParamResponse = response.json()?;
        Ok(body)
    }

    /// Get ModP parameters
    pub fn get_modp_params(&self) -> Result<ModPParams, ApiError> {
        let resp = self.get_test_params(ChallengeType::Modp)?;
        let params: ModPParams = serde_json::from_value(resp.params)?;
        Ok(params)
    }

    /// Get F2m parameters
    pub fn get_f2m_params(&self) -> Result<F2mParams, ApiError> {
        let resp = self.get_test_params(ChallengeType::F2m)?;
        let params: F2mParams = serde_json::from_value(resp.params)?;
        Ok(params)
    }

    /// Get Fpk parameters
    pub fn get_fpk_params(&self) -> Result<FpkParams, ApiError> {
        let resp = self.get_test_params(ChallengeType::Fpk)?;
        let params: FpkParams = serde_json::from_value(resp.params)?;
        Ok(params)
    }

    /// Get ECP parameters
    pub fn get_ecp_params(&self) -> Result<ECPParams, ApiError> {
        let resp = self.get_test_params(ChallengeType::Ecp)?;
        let params: ECPParams = serde_json::from_value(resp.params)?;
        Ok(params)
    }

    /// Get EC2m parameters
    pub fn get_ec2m_params(&self) -> Result<EC2mParams, ApiError> {
        let resp = self.get_test_params(ChallengeType::Ec2m)?;
        let params: EC2mParams = serde_json::from_value(resp.params)?;
        Ok(params)
    }

    /// Get ECPk parameters
    pub fn get_ecpk_params(&self) -> Result<ECPkParams, ApiError> {
        let resp = self.get_test_params(ChallengeType::Ecpk)?;
        let params: ECPkParams = serde_json::from_value(resp.params)?;
        Ok(params)
    }

    // ========================================================================
    // Test DH Endpoints
    // ========================================================================

    /// Test DH for ModP
    pub fn test_dh_modp(&self, client_public: &str) -> Result<TestDHModPResponse, ApiError> {
        let url = format!("{}/test/dh/modp", self.base_url);
        let request = TestDHModPRequest {
            client_public: client_public.to_string(),
        };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHModPResponse = response.json()?;
        Ok(body)
    }

    /// Test DH for F2m
    pub fn test_dh_f2m(&self, client_public: &str) -> Result<TestDHF2mResponse, ApiError> {
        let url = format!("{}/test/dh/f2m", self.base_url);
        let request = TestDHF2mRequest {
            client_public: client_public.to_string(),
        };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHF2mResponse = response.json()?;
        Ok(body)
    }

    /// Test DH for Fpk
    pub fn test_dh_fpk(&self, client_public: Vec<String>) -> Result<TestDHFpkResponse, ApiError> {
        let url = format!("{}/test/dh/fpk", self.base_url);
        let request = TestDHFpkRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHFpkResponse = response.json()?;
        Ok(body)
    }

    /// Test DH for ECP
    pub fn test_dh_ecp(&self, client_public: ECPPoint) -> Result<TestDHECResponse<ECPPoint>, ApiError> {
        let url = format!("{}/test/dh/ecp", self.base_url);
        let request = TestDHECRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHECResponse<ECPPoint> = response.json()?;
        Ok(body)
    }

    /// Test DH for EC2m
    pub fn test_dh_ec2m(&self, client_public: EC2mPoint) -> Result<TestDHECResponse<EC2mPoint>, ApiError> {
        let url = format!("{}/test/dh/ec2m", self.base_url);
        let request = TestDHECRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHECResponse<EC2mPoint> = response.json()?;
        Ok(body)
    }

    /// Test DH for ECPk
    pub fn test_dh_ecpk(&self, client_public: ECPkPoint) -> Result<TestDHECResponse<ECPkPoint>, ApiError> {
        let url = format!("{}/test/dh/ecpk", self.base_url);
        let request = TestDHECRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHECResponse<ECPkPoint> = response.json()?;
        Ok(body)
    }

    // ========================================================================
    // Test Signature Endpoints
    // ========================================================================

    /// Test signature for a challenge type
    pub fn test_signature(&self, challenge_type: ChallengeType, message: &str) -> Result<TestSignatureResponse, ApiError> {
        let url = format!("{}/test/sign/{}", self.base_url, challenge_type);
        let request = TestSignatureRequest {
            message: message.to_string(),
        };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestSignatureResponse = response.json()?;
        Ok(body)
    }
}

impl Default for CryptoApiClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum ApiError {
    Network(reqwest::Error),
    Json(serde_json::Error),
    Validation(String),
    SignatureVerification(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        ApiError::Network(err)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::Json(err)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Network(e) => write!(f, "Network error: {}", e),
            ApiError::Json(e) => write!(f, "JSON error: {}", e),
            ApiError::Validation(s) => write!(f, "Validation error: {}", s),
            ApiError::SignatureVerification(s) => write!(f, "Signature verification failed: {}", s),
        }
    }
}

impl std::error::Error for ApiError {}

// ============================================================================
// Helper Functions for Hex Encoding/Decoding
// ============================================================================

/// Convert hex string to bytes (big-endian)
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    if hex.is_empty() {
        return vec![];
    }
    
    // Handle odd-length hex strings
    let hex = if hex.len() % 2 == 1 {
        format!("0{}", hex)
    } else {
        hex.to_string()
    };
    
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

/// Convert bytes to hex string (big-endian, uppercase)
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Convert BigInt to hex string with proper padding for a given bit length
pub fn bigint_to_hex_padded<const N: usize>(value: &BigInt<N>, target_bits: usize) -> String {
    let hex = value.to_hex();
    let target_len = target_bits.div_ceil(8) * 2; // Convert bits to hex chars (2 per byte)
    if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len)
    } else {
        hex
    }
}

/// Generate a random BigInt in range [1, max-1]
pub fn generate_random_bigint<const N: usize>(max: &BigInt<N>) -> BigInt<N> {
    let mut rng = rand::rng();
    let mut bytes = vec![0u8; N * 8];
    rng.fill(&mut bytes[..]);
    
    // Convert to BigInt and reduce mod (max - 1), then add 1
    let random = BigInt::<N>::from_be_bytes(&bytes);
    let one = BigInt::<N>::one();
    let max_minus_1 = max.sub_with_borrow(&one).0;
    let reduced = random.modulo(&max_minus_1);
    reduced.mod_add(&one, max)
}

/// Convert scalar to NAF (Non-Adjacent Form) for faster scalar multiplication
/// NAF representation uses digits {-1, 0, 1} and guarantees no adjacent non-zero digits
/// This reduces the average number of point operations by ~33%
pub fn bigint_to_naf<const N: usize>(k: &BigInt<N>) -> Vec<i8> {
    let mut naf = Vec::new();
    let mut k = *k;
    
    while !k.is_zero() {
        if k.limbs()[0] & 1 == 1 {  // k is odd
            let width = 2; // window width = 2
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
        s[1..s.len()-1].to_string()
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
    if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len).to_uppercase()
    } else {
        hex.to_uppercase()
    }
}

/// Encode a BinaryField element for API (hex string, uppercase)
pub fn encode_binary_field_for_api<C: FieldConfig<N>, const N: usize, const K: usize>(
    field: &BinaryField<C, N, K>,
) -> String {
    let byte_len = K.div_ceil(8);
    let target_len = byte_len * 2;
    
    let hex = field.bits().to_hex();
    if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len).to_uppercase()
    } else {
        hex.to_uppercase()
    }
}

/// Encode an ExtensionField element for API (array of hex strings)
pub fn encode_extension_field_for_api<C: FieldConfig<N>, const N: usize, const K: usize>(
    field: &ExtensionField<C, N, K>,
) -> Vec<String> {
    let modulus = C::modulus();
    let bit_len = modulus.bit_length();
    let byte_len = bit_len.div_ceil(8);
    let target_len = byte_len * 2;
    
    field.coefficients()
        .iter()
        .map(|coeff| {
            let hex = coeff.to_hex();
            if hex.len() < target_len {
                format!("{:0>width$}", hex, width = target_len).to_uppercase()
            } else {
                hex.to_uppercase()
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let bytes = hex_to_bytes("DEADBEEF");
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "DEADBEEF");
    }

    #[test]
    fn test_api_signature_conversion() {
        let api_sig = ApiSignature {
            s: "1234".to_string(),
            e: "5678".to_string(),
        };
        
        let sig = api_sig.to_schnorr_signature();
        assert_eq!(sig.s, vec![0x12, 0x34]);
        assert_eq!(sig.e, vec![0x56, 0x78]);
        
        let api_sig2 = ApiSignature::from_schnorr_signature(&sig);
        assert_eq!(api_sig2.s, "1234");
        assert_eq!(api_sig2.e, "5678");
    }

    #[test]
    fn test_strip_json_quotes() {
        assert_eq!(strip_json_quotes(r#""hello""#), "hello");
        assert_eq!(strip_json_quotes("hello"), "hello");
    }

    #[test]
    fn test_connection() {
        // Integration test - requires network
        let client = CryptoApiClient::new();
        match client.test_connection() {
            Ok(resp) => {
                println!("Connection test: {}", resp.status);
                assert_eq!(resp.status, "success");
            }
            Err(e) => {
                println!("Connection test failed (may be network issue): {}", e);
            }
        }
    }
}

// ============================================================================
// Test Runners for each challenge type
// ============================================================================

/// Number of BigInt limbs for large field computations (supports up to ~3000 bits)
pub const BIGINT_LIMBS: usize = 48;

/// Modular exponentiation: base^exp mod modulus
pub fn mod_pow<const N: usize>(base: &BigInt<N>, exp: &BigInt<N>, modulus: &BigInt<N>) -> BigInt<N> {
    if modulus.is_one() {
        return BigInt::zero();
    }
    
    let mut result = BigInt::<N>::one();
    let mut base = base.modulo(modulus);
    let mut exp = *exp;
    
    while !exp.is_zero() {
        // If exp is odd
        if exp.limbs()[0] & 1 == 1 {
            result = result.mod_mul(&base, modulus);
        }
        // exp = exp / 2 (right shift by 1)
        exp = exp >> 1;
        // base = base^2 mod modulus
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
    if hex.len() < target_len {
        format!("{:0>width$}", hex, width = target_len).to_uppercase()
    } else {
        hex.to_uppercase()
    }
}

/// Test result for a single challenge type
#[derive(Debug, Clone)]
pub struct ChallengeTestResult {
    pub challenge_type: ChallengeType,
    pub dh_success: bool,
    pub signature_success: bool,
    pub dh_error: Option<String>,
    pub signature_error: Option<String>,
}

impl ChallengeTestResult {
    pub fn success(challenge_type: ChallengeType) -> Self {
        Self {
            challenge_type,
            dh_success: true,
            signature_success: true,
            dh_error: None,
            signature_error: None,
        }
    }

    pub fn is_fully_successful(&self) -> bool {
        self.dh_success && self.signature_success
    }
}

/// Run all test endpoints for a specific challenge type
pub struct ChallengeTestRunner {
    client: CryptoApiClient,
}

impl ChallengeTestRunner {
    pub fn new() -> Self {
        Self {
            client: CryptoApiClient::new(),
        }
    }

    pub fn with_client(client: CryptoApiClient) -> Self {
        Self { client }
    }

    /// Test ModP DH exchange
    pub fn test_modp_dh(&self) -> Result<(), ApiError> {
        let params = self.client.get_modp_params()?;
        
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let generator = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator);
        let modulus = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        
        // Generate random private key
        let private_key = generate_random_bigint(&order);
        
        // Compute public key
        let public_key = mod_pow(&generator, &private_key, &modulus);
        
        // Format for API
        let modulus_byte_len = modulus.bit_length().div_ceil(8);
        let client_public_hex = bigint_to_padded_hex_upper(&public_key, modulus_byte_len);
        
        // Send to API
        let response = self.client.test_dh_modp(&client_public_hex)?;
        
        // Parse server public key
        let server_public = BigInt::<BIGINT_LIMBS>::from_hex(&response.server_public);
        
        // Compute shared secret
        let our_shared_secret = mod_pow(&server_public, &private_key, &modulus);
        let our_shared_hex = bigint_to_padded_hex_upper(&our_shared_secret, modulus_byte_len);
        
        // Compare
        if our_shared_hex.to_uppercase() == response.shared_secret.to_uppercase() {
            Ok(())
        } else {
            Err(ApiError::Validation("DH shared secrets don't match".to_string()))
        }
    }

    /// Test ModP Schnorr signature verification
    pub fn test_modp_signature(&self, message: &str) -> Result<(), ApiError> {
        let params = self.client.get_modp_params()?;
        let response = self.client.test_signature(ChallengeType::Modp, message)?;
        
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let generator = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator);
        let modulus = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        
        let public_key_str = response.public.as_str()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let public_key = BigInt::<BIGINT_LIMBS>::from_hex(public_key_str);
        
        let sig = &response.signature;
        let s = BigInt::<BIGINT_LIMBS>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        
        // Verify: R' = g^s * y^e mod p
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        let g_s = mod_pow(&generator, &s, &modulus);
        let y_e = mod_pow(&public_key, &e_scalar, &modulus);
        let r_prime = g_s.mod_mul(&y_e, &modulus);
        
        // Compute e' = H(R' || m) with lowercase hex encoding
        let modulus_byte_len = modulus.bit_length().div_ceil(8);
        let r_hex = bigint_to_padded_hex(&r_prime, modulus_byte_len);
        let r_encoded = format!(r#""{}""#, r_hex);
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();
        
        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(
                format!("Expected: {}, Got: {}", bytes_to_hex(&e_bytes), bytes_to_hex(e_prime.as_slice()))
            ))
        }
    }

    /// Run all tests for ModP
    pub fn run_modp_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Modp);
        
        match self.test_modp_dh() {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }
        
        match self.test_modp_signature("test message") {
            Ok(()) => result.signature_success = true,
            Err(e) => {
                result.signature_success = false;
                result.signature_error = Some(e.to_string());
            }
        }
        
        result
    }

    // ========================================================================
    // F2m (Binary Field) Tests
    // ========================================================================

    /// Binary field multiplication (polynomial multiplication mod reduction polynomial)
    /// In GF(2^m), we represent elements as polynomials over GF(2).
    /// The modulus represents the irreducible polynomial f(x) where the full polynomial is x^m + f(x).
    fn f2m_mul(a: &BigInt<BIGINT_LIMBS>, b: &BigInt<BIGINT_LIMBS>, reduction_poly: &BigInt<BIGINT_LIMBS>, m: usize) -> BigInt<BIGINT_LIMBS> {
        // Polynomial multiplication using shift-and-XOR
        let mut result = BigInt::<BIGINT_LIMBS>::zero();
        let mut a_shifted = *a;
        
        // Multiply: for each bit of b, if set, XOR the shifted a
        for i in 0..m {
            // Check if bit i of b is set
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            if limb_idx < BIGINT_LIMBS && (b.limbs()[limb_idx] >> bit_idx) & 1 == 1 {
                result = result ^ a_shifted;
            }
            
            // Shift a left by 1 (multiply by x)
            a_shifted = a_shifted << 1;
            
            // Reduce if degree reaches m (bit m is set)
            let m_limb_idx = m / 64;
            let m_bit_idx = m % 64;
            if m_limb_idx < BIGINT_LIMBS && (a_shifted.limbs()[m_limb_idx] >> m_bit_idx) & 1 == 1 {
                // Clear bit m and XOR with reduction polynomial
                // x^m ≡ reduction_poly (mod irreducible)
                a_shifted = a_shifted ^ (BigInt::<BIGINT_LIMBS>::one() << m);
                a_shifted = a_shifted ^ *reduction_poly;
            }
        }
        
        // Final reduction of result (it may have degree up to 2m-2 before reduction)
        Self::f2m_reduce(&result, reduction_poly, m)
    }

    /// Reduce a polynomial modulo x^m + reduction_poly
    fn f2m_reduce(a: &BigInt<BIGINT_LIMBS>, reduction_poly: &BigInt<BIGINT_LIMBS>, m: usize) -> BigInt<BIGINT_LIMBS> {
        let mut result = *a;
        
        // Reduce from highest possible degree down to m-1
        // After multiplication, max degree is 2*(m-1) = 2m-2
        for i in (m..2*m).rev() {
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            
            if limb_idx < BIGINT_LIMBS && (result.limbs()[limb_idx] >> bit_idx) & 1 == 1 {
                // Bit i is set, need to reduce
                // x^i = x^(i-m) * x^m ≡ x^(i-m) * reduction_poly
                let shift = i - m;
                result = result ^ (BigInt::<BIGINT_LIMBS>::one() << i); // Clear bit i
                result = result ^ (*reduction_poly << shift);   // Add shifted reduction poly
            }
        }
        
        result
    }

    /// Binary field exponentiation
    fn f2m_pow(base: &BigInt<BIGINT_LIMBS>, exp: &BigInt<BIGINT_LIMBS>, modulus: &BigInt<BIGINT_LIMBS>, m: usize) -> BigInt<BIGINT_LIMBS> {
        if exp.is_zero() {
            return BigInt::one();
        }
        
        let mut result = BigInt::<BIGINT_LIMBS>::one();
        let mut base = *base;
        let mut exp = *exp;
        
        while !exp.is_zero() {
            if exp.limbs()[0] & 1 == 1 {
                result = Self::f2m_mul(&result, &base, modulus, m);
            }
            exp = exp >> 1;
            base = Self::f2m_mul(&base, &base, modulus, m);
        }
        
        result
    }

    /// Test F2m DH exchange
    pub fn test_f2m_dh(&self) -> Result<(), ApiError> {
        let params = self.client.get_f2m_params()?;
        
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let generator = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator);
        let modulus = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        let m = params.extension;
        
        // Generate private key - use small fixed key for faster testing
        let private_key = BigInt::<BIGINT_LIMBS>::from_u64(0xFF);
        let public_key = Self::f2m_pow(&generator, &private_key, &modulus, m);
        
        // Format for API
        let byte_len = m.div_ceil(8);
        let client_public_hex = bigint_to_padded_hex_upper(&public_key, byte_len);
        
        // Send to API
        let response = self.client.test_dh_f2m(&client_public_hex)?;
        
        // Parse server public key
        let server_public = BigInt::<BIGINT_LIMBS>::from_hex(&response.server_public);
        
        // Compute shared secret
        let our_shared_secret = Self::f2m_pow(&server_public, &private_key, &modulus, m);
        let our_shared_hex = bigint_to_padded_hex_upper(&our_shared_secret, byte_len);
        
        // Compare
        if our_shared_hex.to_uppercase() == response.shared_secret.to_uppercase() {
            Ok(())
        } else {
            Err(ApiError::Validation("F2m DH shared secrets don't match".to_string()))
        }
    }

    /// Test F2m Schnorr signature verification
    pub fn test_f2m_signature(&self, message: &str) -> Result<(), ApiError> {
        let params = self.client.get_f2m_params()?;
        let response = self.client.test_signature(ChallengeType::F2m, message)?;
        
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let generator = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator);
        let modulus = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        let m = params.extension;
        
        let public_key_str = response.public.as_str()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let public_key = BigInt::<BIGINT_LIMBS>::from_hex(public_key_str);
        
        let sig = &response.signature;
        let s = BigInt::<BIGINT_LIMBS>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        
        // Verify: R' = g^s * y^e in F_2^m
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        let g_s = Self::f2m_pow(&generator, &s, &modulus, m);
        let y_e = Self::f2m_pow(&public_key, &e_scalar, &modulus, m);
        let r_prime = Self::f2m_mul(&g_s, &y_e, &modulus, m);
        
        // Compute e' = H(R' || m) with lowercase hex encoding
        let byte_len = m.div_ceil(8);
        let r_hex = bigint_to_padded_hex(&r_prime, byte_len);
        let r_encoded = format!(r#""{}""#, r_hex);
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();
        
        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(
                format!("Expected: {}, Got: {}", bytes_to_hex(&e_bytes), bytes_to_hex(e_prime.as_slice()))
            ))
        }
    }

    /// Run all tests for F2m
    pub fn run_f2m_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::F2m);
        
        match self.test_f2m_dh() {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }
        
        match self.test_f2m_signature("test message") {
            Ok(()) => result.signature_success = true,
            Err(e) => {
                result.signature_success = false;
                result.signature_error = Some(e.to_string());
            }
        }
        
        result
    }

    // ========================================================================
    // Fpk (Extension Field) Tests
    // ========================================================================

    /// Extension field multiplication: multiply two polynomials mod the irreducible polynomial
    fn fpk_mul(a: &[BigInt<BIGINT_LIMBS>], b: &[BigInt<BIGINT_LIMBS>], modulus_poly: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Vec<BigInt<BIGINT_LIMBS>> {
        let k = a.len();
        
        // Multiply polynomials
        let mut product = vec![BigInt::<BIGINT_LIMBS>::zero(); 2 * k - 1];
        for i in 0..k {
            for j in 0..k {
                let term = a[i].mod_mul(&b[j], prime);
                product[i + j] = product[i + j].mod_add(&term, prime);
            }
        }
        
        // Reduce mod irreducible polynomial
        // modulus_poly represents x^k + c_{k-1}*x^{k-1} + ... + c_0
        // We reduce by replacing x^k with -(c_{k-1}*x^{k-1} + ... + c_0)
        for i in (k..product.len()).rev() {
            let coeff = product[i];
            if !coeff.is_zero() {
                for j in 0..k {
                    let sub_term = coeff.mod_mul(&modulus_poly[j], prime);
                    product[i - k + j] = product[i - k + j].mod_sub(&sub_term, prime);
                }
                product[i] = BigInt::zero();
            }
        }
        
        product[0..k].to_vec()
    }

    /// Extension field exponentiation
    fn fpk_pow(base: &[BigInt<BIGINT_LIMBS>], exp: &BigInt<BIGINT_LIMBS>, modulus_poly: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Vec<BigInt<BIGINT_LIMBS>> {
        let k = base.len();
        
        if exp.is_zero() {
            let mut one = vec![BigInt::<BIGINT_LIMBS>::zero(); k];
            one[0] = BigInt::one();
            return one;
        }
        
        let mut result = vec![BigInt::<BIGINT_LIMBS>::zero(); k];
        result[0] = BigInt::one();
        
        let mut base = base.to_vec();
        let mut exp = *exp;
        
        while !exp.is_zero() {
            if exp.limbs()[0] & 1 == 1 {
                result = Self::fpk_mul(&result, &base, modulus_poly, prime);
            }
            exp = exp >> 1;
            base = Self::fpk_mul(&base, &base, modulus_poly, prime);
        }
        
        result
    }

    /// Test Fpk DH exchange
    pub fn test_fpk_dh(&self) -> Result<(), ApiError> {
        let params = self.client.get_fpk_params()?;
        
        let prime = BigInt::<BIGINT_LIMBS>::from_hex(&params.prime_base);
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let _k = params.extension;
        
        // Parse generator and modulus polynomial
        let generator: Vec<BigInt<BIGINT_LIMBS>> = params.generator
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        let modulus_poly: Vec<BigInt<BIGINT_LIMBS>> = params.modulus
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        
        // Generate private key - use small fixed key for faster testing
        let private_key = BigInt::<BIGINT_LIMBS>::from_u64(0xFF);
        
        // Compute public key: g^sk in F_p^k
        let public_key = Self::fpk_pow(&generator, &private_key, &modulus_poly, &prime);
        
        // Format for API
        let prime_byte_len = prime.bit_length().div_ceil(8);
        let client_public: Vec<String> = public_key
            .iter()
            .map(|c| bigint_to_padded_hex_upper(c, prime_byte_len))
            .collect();
        
        // Send to API
        let response = self.client.test_dh_fpk(client_public)?;
        
        // Parse server public key
        let server_public: Vec<BigInt<BIGINT_LIMBS>> = response.server_public
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        
        // Compute shared secret
        let our_shared_secret = Self::fpk_pow(&server_public, &private_key, &modulus_poly, &prime);
        let our_shared_hex: Vec<String> = our_shared_secret
            .iter()
            .map(|c| bigint_to_padded_hex_upper(c, prime_byte_len))
            .collect();
        
        // Compare
        let expected: Vec<String> = response.shared_secret.iter().map(|s| s.to_uppercase()).collect();
        let got: Vec<String> = our_shared_hex.iter().map(|s| s.to_uppercase()).collect();
        
        if expected == got {
            Ok(())
        } else {
            Err(ApiError::Validation(format!("Fpk DH shared secrets don't match: expected {:?}, got {:?}", expected, got)))
        }
    }

    /// Test Fpk Schnorr signature verification
    pub fn test_fpk_signature(&self, message: &str) -> Result<(), ApiError> {
        let params = self.client.get_fpk_params()?;
        let response = self.client.test_signature(ChallengeType::Fpk, message)?;
        
        let prime = BigInt::<BIGINT_LIMBS>::from_hex(&params.prime_base);
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let _k = params.extension;
        
        let generator: Vec<BigInt<BIGINT_LIMBS>> = params.generator
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        let modulus_poly: Vec<BigInt<BIGINT_LIMBS>> = params.modulus
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        
        // Parse public key (array of coefficients)
        let public_key_arr = response.public.as_array()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let public_key: Vec<BigInt<BIGINT_LIMBS>> = public_key_arr
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap_or("0")))
            .collect();
        
        let sig = &response.signature;
        let s = BigInt::<BIGINT_LIMBS>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        
        // Verify: R' = g^s * y^e in F_p^k
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        let g_s = Self::fpk_pow(&generator, &s, &modulus_poly, &prime);
        let y_e = Self::fpk_pow(&public_key, &e_scalar, &modulus_poly, &prime);
        let r_prime = Self::fpk_mul(&g_s, &y_e, &modulus_poly, &prime);
        
        // Compute e' = H(R' || m) with lowercase hex encoding
        let prime_byte_len = prime.bit_length().div_ceil(8);
        let r_hex: Vec<String> = r_prime.iter().map(|c| bigint_to_padded_hex(c, prime_byte_len)).collect();
        let r_encoded = serde_json::to_string(&r_hex).unwrap();
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();
        
        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(
                format!("Expected: {}, Got: {}", bytes_to_hex(&e_bytes), bytes_to_hex(e_prime.as_slice()))
            ))
        }
    }

    /// Run all tests for Fpk
    pub fn run_fpk_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Fpk);
        
        match self.test_fpk_dh() {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }
        
        match self.test_fpk_signature("test message") {
            Ok(()) => result.signature_success = true,
            Err(e) => {
                result.signature_success = false;
                result.signature_error = Some(e.to_string());
            }
        }
        
        result
    }

    // ========================================================================
    // ECP (Elliptic Curve over Prime Field) Tests
    // ========================================================================

    /// EC point addition over prime field
    fn ecp_add(p: &(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>), q: &(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>), a: &BigInt<BIGINT_LIMBS>, modulus: &BigInt<BIGINT_LIMBS>) -> Option<(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>)> {
        let (x1, y1) = p;
        let (x2, y2) = q;
        
        // Check for point at infinity (represented as all zeros - simplified)
        if x1.is_zero() && y1.is_zero() {
            return Some(*q);
        }
        if x2.is_zero() && y2.is_zero() {
            return Some(*p);
        }
        
        // Check if P = -Q
        let neg_y2 = modulus.sub_with_borrow(y2).0;
        if x1 == x2 && y1 == &neg_y2 {
            return None; // Point at infinity
        }
        
        let lambda = if x1 == x2 && y1 == y2 {
            // Point doubling: λ = (3x₁² + a) / (2y₁)
            if y1.is_zero() {
                return None; // Point at infinity
            }
            let three = BigInt::<BIGINT_LIMBS>::from_u64(3);
            let two = BigInt::<BIGINT_LIMBS>::from_u64(2);
            let x1_sq = x1.mod_mul(x1, modulus);
            let numerator = three.mod_mul(&x1_sq, modulus).mod_add(a, modulus);
            let denominator = two.mod_mul(y1, modulus);
            let denom_inv = Self::mod_inverse(&denominator, modulus)?;
            numerator.mod_mul(&denom_inv, modulus)
        } else {
            // Point addition: λ = (y₂ - y₁) / (x₂ - x₁)
            let numerator = y2.mod_sub(y1, modulus);
            let denominator = x2.mod_sub(x1, modulus);
            let denom_inv = Self::mod_inverse(&denominator, modulus)?;
            numerator.mod_mul(&denom_inv, modulus)
        };
        
        // x₃ = λ² - x₁ - x₂
        let lambda_sq = lambda.mod_mul(&lambda, modulus);
        let x3 = lambda_sq.mod_sub(x1, modulus).mod_sub(x2, modulus);
        
        // y₃ = λ(x₁ - x₃) - y₁
        let y3 = lambda.mod_mul(&x1.mod_sub(&x3, modulus), modulus).mod_sub(y1, modulus);
        
        Some((x3, y3))
    }

    /// Modular inverse using extended Euclidean algorithm
    fn mod_inverse(a: &BigInt<BIGINT_LIMBS>, modulus: &BigInt<BIGINT_LIMBS>) -> Option<BigInt<BIGINT_LIMBS>> {
        // Extended Euclidean algorithm using signed representation
        // We track t0, t1 and compute inverse
        let mut old_r = *modulus;
        let mut r = a.modulo(modulus);
        
        // Track t as (value, is_negative)
        let mut old_t: (BigInt<BIGINT_LIMBS>, bool) = (BigInt::zero(), false);
        let mut t: (BigInt<BIGINT_LIMBS>, bool) = (BigInt::one(), false);
        
        while !r.is_zero() {
            let (quotient, remainder) = old_r.div_rem(&r);
            old_r = r;
            r = remainder;
            
            // new_t = old_t - quotient * t
            let q_times_t = quotient.mod_mul(&t.0, modulus);
            let new_t = if old_t.1 == t.1 {
                // Same sign: subtract magnitudes
                let (diff, borrow) = old_t.0.sub_with_borrow(&q_times_t);
                if borrow {
                    // q_times_t > old_t.0, result has opposite sign
                    let (diff2, _) = q_times_t.sub_with_borrow(&old_t.0);
                    (diff2, !old_t.1)
                } else {
                    (diff, old_t.1)
                }
            } else {
                // Different signs: add magnitudes
                (old_t.0.mod_add(&q_times_t, modulus), old_t.1)
            };
            
            old_t = t;
            t = new_t;
        }
        
        if old_r.is_one() {
            // Convert signed result to positive mod modulus
            if old_t.1 {
                Some(modulus.mod_sub(&old_t.0, modulus))
            } else {
                Some(old_t.0.modulo(modulus))
            }
        } else {
            None
        }
    }

    /// EC scalar multiplication over prime field
    fn ecp_scalar_mul(p: &(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>), k: &BigInt<BIGINT_LIMBS>, a: &BigInt<BIGINT_LIMBS>, modulus: &BigInt<BIGINT_LIMBS>) -> Option<(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>)> {
        if k.is_zero() {
            return None; // Point at infinity
        }
        
        let mut result: Option<(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>)> = None;
        let mut base = *p;
        let mut k = *k;
        
        while !k.is_zero() {
            if k.limbs()[0] & 1 == 1 {
                result = match result {
                    None => Some(base),
                    Some(r) => Self::ecp_add(&r, &base, a, modulus),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::ecp_add(&base, &base, a, modulus).unwrap_or((BigInt::zero(), BigInt::zero()));
            }
        }
        
        result
    }

    /// Test ECP DH exchange
    pub fn test_ecp_dh(&self) -> Result<(), ApiError> {
        let params = self.client.get_ecp_params()?;
        
        let modulus = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        let _order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let a = BigInt::<BIGINT_LIMBS>::from_hex(&params.a);
        let gx = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.x);
        let gy = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.y);
        let generator = (gx, gy);
        
        // Use a small private key for faster testing (0xFF = 255, only 8 bits set)
        let private_key = BigInt::<BIGINT_LIMBS>::from_u64(0xFF);
        
        // Compute public key: [sk]G
        let public_key = Self::ecp_scalar_mul(&generator, &private_key, &a, &modulus)
            .ok_or_else(|| ApiError::Validation("Failed to compute public key".to_string()))?;
        
        // Format for API
        let byte_len = modulus.bit_length().div_ceil(8);
        let client_public = ECPPoint {
            x: bigint_to_padded_hex_upper(&public_key.0, byte_len),
            y: bigint_to_padded_hex_upper(&public_key.1, byte_len),
        };
        
        // Send to API
        let response = self.client.test_dh_ecp(client_public)?;
        
        // Parse server public key
        let server_public = (
            BigInt::<BIGINT_LIMBS>::from_hex(&response.server_public.x),
            BigInt::<BIGINT_LIMBS>::from_hex(&response.server_public.y),
        );
        
        // Compute shared secret
        let our_shared = Self::ecp_scalar_mul(&server_public, &private_key, &a, &modulus)
            .ok_or_else(|| ApiError::Validation("Failed to compute shared secret".to_string()))?;
        let our_shared_x = bigint_to_padded_hex_upper(&our_shared.0, byte_len);
        let our_shared_y = bigint_to_padded_hex_upper(&our_shared.1, byte_len);
        
        // Compare
        if our_shared_x.to_uppercase() == response.shared_secret.x.to_uppercase() 
            && our_shared_y.to_uppercase() == response.shared_secret.y.to_uppercase() {
            Ok(())
        } else {
            Err(ApiError::Validation("ECP DH shared secrets don't match".to_string()))
        }
    }

    /// Test ECP Schnorr signature verification
    pub fn test_ecp_signature(&self, message: &str) -> Result<(), ApiError> {
        let params = self.client.get_ecp_params()?;
        let response = self.client.test_signature(ChallengeType::Ecp, message)?;
        
        let modulus = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let a = BigInt::<BIGINT_LIMBS>::from_hex(&params.a);
        let gx = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.x);
        let gy = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.y);
        let generator = (gx, gy);
        
        // Parse public key
        let public_obj = response.public.as_object()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let pub_x = public_obj.get("x").and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing x in public key".to_string()))?;
        let pub_y = public_obj.get("y").and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing y in public key".to_string()))?;
        let public_key = (BigInt::<BIGINT_LIMBS>::from_hex(pub_x), BigInt::<BIGINT_LIMBS>::from_hex(pub_y));
        
        let sig = &response.signature;
        let s = BigInt::<BIGINT_LIMBS>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        
        // Verify: R' = [s]G + [e]Y
        let g_s = Self::ecp_scalar_mul(&generator, &s, &a, &modulus);
        let y_e = Self::ecp_scalar_mul(&public_key, &e_scalar, &a, &modulus);
        
        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecp_add(&gs, &ye, &a, &modulus),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        }.ok_or_else(|| ApiError::Validation("R' is point at infinity".to_string()))?;
        
        // Compute e' = H(R' || m) with lowercase hex encoding
        let byte_len = modulus.bit_length().div_ceil(8);
        let r_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&r_prime.0, byte_len),
            "y": bigint_to_padded_hex(&r_prime.1, byte_len)
        });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();
        
        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(
                format!("Expected: {}, Got: {}", bytes_to_hex(&e_bytes), bytes_to_hex(e_prime.as_slice()))
            ))
        }
    }

    /// Run all tests for ECP
    pub fn run_ecp_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Ecp);
        
        match self.test_ecp_dh() {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }
        
        match self.test_ecp_signature("test message") {
            Ok(()) => result.signature_success = true,
            Err(e) => {
                result.signature_success = false;
                result.signature_error = Some(e.to_string());
            }
        }
        
        result
    }

    // ========================================================================
    // EC2m (Elliptic Curve over Binary Field) Tests
    // ========================================================================

    /// EC point addition over binary field (y² + xy = x³ + ax² + b)
    fn ec2m_add(p: &(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>), q: &(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>), a: &BigInt<BIGINT_LIMBS>, red_poly: &BigInt<BIGINT_LIMBS>, m: usize) -> Option<(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>)> {
        let (x1, y1) = p;
        let (x2, y2) = q;
        
        // Check for point at infinity
        if x1.is_zero() && y1.is_zero() {
            return Some(*q);
        }
        if x2.is_zero() && y2.is_zero() {
            return Some(*p);
        }
        
        // Check if P = -Q (in binary EC, -P = (x, x+y))
        let neg_y2 = *x2 ^ *y2;
        if x1 == x2 && *y1 == neg_y2 {
            return None; // Point at infinity
        }
        
        if x1 == x2 && y1 == y2 {
            // Point doubling
            if x1.is_zero() {
                return None; // Point at infinity
            }
            // λ = x + y/x
            let y_over_x = Self::f2m_div(y1, x1, red_poly, m)?;
            let lambda = *x1 ^ y_over_x;
            
            // x₃ = λ² + λ + a
            let lambda_sq = Self::f2m_mul(&lambda, &lambda, red_poly, m);
            let x3 = lambda_sq ^ lambda ^ *a;
            
            // y₃ = x₁² + (λ + 1)x₃
            let x1_sq = Self::f2m_mul(x1, x1, red_poly, m);
            let lambda_plus_1 = lambda ^ BigInt::one();
            let y3 = x1_sq ^ Self::f2m_mul(&lambda_plus_1, &x3, red_poly, m);
            
            Some((x3, y3))
        } else {
            // Point addition
            // λ = (y₁ + y₂) / (x₁ + x₂)
            let y_sum = *y1 ^ *y2;
            let x_sum = *x1 ^ *x2;
            let lambda = Self::f2m_div(&y_sum, &x_sum, red_poly, m)?;
            
            // x₃ = λ² + λ + x₁ + x₂ + a
            let lambda_sq = Self::f2m_mul(&lambda, &lambda, red_poly, m);
            let x3 = lambda_sq ^ lambda ^ *x1 ^ *x2 ^ *a;
            
            // y₃ = λ(x₁ + x₃) + x₃ + y₁
            let y3 = Self::f2m_mul(&lambda, &(*x1 ^ x3), red_poly, m) ^ x3 ^ *y1;
            
            Some((x3, y3))
        }
    }

    /// Binary field division
    fn f2m_div(a: &BigInt<BIGINT_LIMBS>, b: &BigInt<BIGINT_LIMBS>, red_poly: &BigInt<BIGINT_LIMBS>, m: usize) -> Option<BigInt<BIGINT_LIMBS>> {
        let b_inv = Self::f2m_inverse(b, red_poly, m)?;
        Some(Self::f2m_mul(a, &b_inv, red_poly, m))
    }

    /// Binary field inverse using extended Euclidean algorithm for polynomials over GF(2)
    fn f2m_inverse(a: &BigInt<BIGINT_LIMBS>, red_poly: &BigInt<BIGINT_LIMBS>, m: usize) -> Option<BigInt<BIGINT_LIMBS>> {
        if a.is_zero() {
            return None;
        }
        
        // The full modulus is x^m + red_poly
        let full_modulus = (BigInt::<BIGINT_LIMBS>::one() << m) ^ *red_poly;
        
        // Extended Euclidean algorithm for polynomials over GF(2)
        let mut u = *a;
        let mut v = full_modulus;
        let mut g1 = BigInt::<BIGINT_LIMBS>::one();
        let mut g2 = BigInt::<BIGINT_LIMBS>::zero();
        
        while !u.is_zero() && !v.is_zero() {
            // Remove low-order zero bits from u
            while !u.is_zero() && u.limbs()[0] & 1 == 0 {
                u = u >> 1;
                // g1 = g1 / x mod full_modulus
                // If g1 is odd, we need to add the modulus before dividing by x
                if g1.limbs()[0] & 1 == 1 {
                    g1 = g1 ^ full_modulus;
                }
                g1 = g1 >> 1;
            }
            
            // Remove low-order zero bits from v
            while !v.is_zero() && v.limbs()[0] & 1 == 0 {
                v = v >> 1;
                if g2.limbs()[0] & 1 == 1 {
                    g2 = g2 ^ full_modulus;
                }
                g2 = g2 >> 1;
            }
            
            // Reduce the larger polynomial
            if u.bit_length() >= v.bit_length() {
                u = u ^ v;
                g1 = g1 ^ g2;
            } else {
                v = v ^ u;
                g2 = g2 ^ g1;
            }
        }
        
        // At this point, one of u or v should be 1
        if u.is_one() {
            Some(Self::f2m_reduce(&g1, red_poly, m))
        } else if v.is_one() {
            Some(Self::f2m_reduce(&g2, red_poly, m))
        } else {
            // GCD is not 1, no inverse exists
            None
        }
    }

    /// EC scalar multiplication over binary field
    fn ec2m_scalar_mul(p: &(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>), k: &BigInt<BIGINT_LIMBS>, a: &BigInt<BIGINT_LIMBS>, red_poly: &BigInt<BIGINT_LIMBS>, m: usize) -> Option<(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>)> {
        if k.is_zero() {
            return None;
        }
        
        let mut result: Option<(BigInt<BIGINT_LIMBS>, BigInt<BIGINT_LIMBS>)> = None;
        let mut base = *p;
        let mut k = *k;
        
        while !k.is_zero() {
            if k.limbs()[0] & 1 == 1 {
                result = match result {
                    None => Some(base),
                    Some(r) => Self::ec2m_add(&r, &base, a, red_poly, m),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::ec2m_add(&base, &base, a, red_poly, m).unwrap_or((BigInt::zero(), BigInt::zero()));
            }
        }
        
        result
    }

    /// Test EC2m DH exchange
    pub fn test_ec2m_dh(&self) -> Result<(), ApiError> {
        let params = self.client.get_ec2m_params()?;
        
        let m = params.extension;
        let red_poly = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let a = BigInt::<BIGINT_LIMBS>::from_hex(&params.a);
        let gx = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.x);
        let gy = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.y);
        let generator = (gx, gy);
        
        // Generate private key - use small fixed key for faster testing
        let private_key = BigInt::<BIGINT_LIMBS>::from_u64(0xFF);
        
        // Compute public key: [sk]G
        let public_key = Self::ec2m_scalar_mul(&generator, &private_key, &a, &red_poly, m)
            .ok_or_else(|| ApiError::Validation("Failed to compute EC2m public key".to_string()))?;
        
        // Format for API
        let byte_len = m.div_ceil(8);
        let client_public = EC2mPoint {
            x: bigint_to_padded_hex_upper(&public_key.0, byte_len),
            y: bigint_to_padded_hex_upper(&public_key.1, byte_len),
        };
        
        // Send to API
        let response = self.client.test_dh_ec2m(client_public)?;
        
        // Parse server public key
        let server_public = (
            BigInt::<BIGINT_LIMBS>::from_hex(&response.server_public.x),
            BigInt::<BIGINT_LIMBS>::from_hex(&response.server_public.y),
        );
        
        // Compute shared secret
        let our_shared = Self::ec2m_scalar_mul(&server_public, &private_key, &a, &red_poly, m)
            .ok_or_else(|| ApiError::Validation("Failed to compute EC2m shared secret".to_string()))?;
        let our_shared_x = bigint_to_padded_hex_upper(&our_shared.0, byte_len);
        let our_shared_y = bigint_to_padded_hex_upper(&our_shared.1, byte_len);
        
        // Compare
        if our_shared_x.to_uppercase() == response.shared_secret.x.to_uppercase()
            && our_shared_y.to_uppercase() == response.shared_secret.y.to_uppercase() {
            Ok(())
        } else {
            Err(ApiError::Validation("EC2m DH shared secrets don't match".to_string()))
        }
    }

    /// Test EC2m Schnorr signature verification
    pub fn test_ec2m_signature(&self, message: &str) -> Result<(), ApiError> {
        let params = self.client.get_ec2m_params()?;
        let response = self.client.test_signature(ChallengeType::Ec2m, message)?;
        
        let m = params.extension;
        let red_poly = BigInt::<BIGINT_LIMBS>::from_hex(&params.modulus);
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let a = BigInt::<BIGINT_LIMBS>::from_hex(&params.a);
        let gx = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.x);
        let gy = BigInt::<BIGINT_LIMBS>::from_hex(&params.generator.y);
        let generator = (gx, gy);
        
        // Parse public key
        let public_obj = response.public.as_object()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let pub_x = public_obj.get("x").and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing x in public key".to_string()))?;
        let pub_y = public_obj.get("y").and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing y in public key".to_string()))?;
        let public_key = (BigInt::<BIGINT_LIMBS>::from_hex(pub_x), BigInt::<BIGINT_LIMBS>::from_hex(pub_y));
        
        let sig = &response.signature;
        let s = BigInt::<BIGINT_LIMBS>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        
        // Verify: R' = [s]G + [e]Y
        let g_s = Self::ec2m_scalar_mul(&generator, &s, &a, &red_poly, m);
        let y_e = Self::ec2m_scalar_mul(&public_key, &e_scalar, &a, &red_poly, m);
        
        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ec2m_add(&gs, &ye, &a, &red_poly, m),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        }.ok_or_else(|| ApiError::Validation("R' is point at infinity".to_string()))?;
        
        // Compute e' = H(R' || m)
        let byte_len = m.div_ceil(8);
        let r_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&r_prime.0, byte_len),
            "y": bigint_to_padded_hex(&r_prime.1, byte_len)
        });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();
        
        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(
                format!("Expected: {}, Got: {}", bytes_to_hex(&e_bytes), bytes_to_hex(e_prime.as_slice()))
            ))
        }
    }

    /// Run all tests for EC2m
    pub fn run_ec2m_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Ec2m);
        
        match self.test_ec2m_dh() {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }
        
        match self.test_ec2m_signature("test message") {
            Ok(()) => result.signature_success = true,
            Err(e) => {
                result.signature_success = false;
                result.signature_error = Some(e.to_string());
            }
        }
        
        result
    }

    // ========================================================================
    // ECPk (Elliptic Curve over Extension Field) Tests
    // ========================================================================

    /// EC point addition over extension field
    fn ecpk_add(p: &(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>), q: &(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>), a: &[BigInt<BIGINT_LIMBS>], modulus_poly: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Option<(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>)> {
        let (x1, y1) = p;
        let (x2, y2) = q;
        let _k = x1.len();
        
        // Check for point at infinity
        let is_inf = |v: &[BigInt<BIGINT_LIMBS>]| v.iter().all(|c| c.is_zero());
        if is_inf(x1) && is_inf(y1) {
            return Some(q.clone());
        }
        if is_inf(x2) && is_inf(y2) {
            return Some(p.clone());
        }
        
        // Negate y2
        let neg_y2: Vec<_> = y2.iter().map(|c| prime.mod_sub(c, prime)).collect();
        
        // Check if P = -Q
        if x1 == x2 && *y1 == neg_y2 {
            return None;
        }
        
        let lambda = if x1 == x2 && y1 == y2 {
            // Point doubling
            let is_y_zero = y1.iter().all(|c| c.is_zero());
            if is_y_zero {
                return None;
            }
            // λ = (3x₁² + a) / (2y₁)
            let three = BigInt::<BIGINT_LIMBS>::from_u64(3);
            let two = BigInt::<BIGINT_LIMBS>::from_u64(2);
            
            let x1_sq = Self::fpk_mul(x1, x1, modulus_poly, prime);
            let three_x1_sq: Vec<_> = x1_sq.iter().map(|c| three.mod_mul(c, prime)).collect();
            let numerator = Self::fpk_add(&three_x1_sq, a, prime);
            
            let two_y1: Vec<_> = y1.iter().map(|c| two.mod_mul(c, prime)).collect();
            let denom_inv = Self::fpk_inverse(&two_y1, modulus_poly, prime)?;
            Self::fpk_mul(&numerator, &denom_inv, modulus_poly, prime)
        } else {
            // Point addition
            let y_diff = Self::fpk_sub(y2, y1, prime);
            let x_diff = Self::fpk_sub(x2, x1, prime);
            let denom_inv = Self::fpk_inverse(&x_diff, modulus_poly, prime)?;
            Self::fpk_mul(&y_diff, &denom_inv, modulus_poly, prime)
        };
        
        // x₃ = λ² - x₁ - x₂
        let lambda_sq = Self::fpk_mul(&lambda, &lambda, modulus_poly, prime);
        let x3 = Self::fpk_sub(&Self::fpk_sub(&lambda_sq, x1, prime), x2, prime);
        
        // y₃ = λ(x₁ - x₃) - y₁
        let x1_minus_x3 = Self::fpk_sub(x1, &x3, prime);
        let y3 = Self::fpk_sub(&Self::fpk_mul(&lambda, &x1_minus_x3, modulus_poly, prime), y1, prime);
        
        Some((x3, y3))
    }

    /// Extension field addition
    fn fpk_add(a: &[BigInt<BIGINT_LIMBS>], b: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Vec<BigInt<BIGINT_LIMBS>> {
        a.iter().zip(b.iter()).map(|(ai, bi)| ai.mod_add(bi, prime)).collect()
    }

    /// Extension field subtraction
    fn fpk_sub(a: &[BigInt<BIGINT_LIMBS>], b: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Vec<BigInt<BIGINT_LIMBS>> {
        a.iter().zip(b.iter()).map(|(ai, bi)| ai.mod_sub(bi, prime)).collect()
    }

    /// Extension field inverse using extended Euclidean algorithm for polynomials
    fn fpk_inverse(a: &[BigInt<BIGINT_LIMBS>], modulus_poly: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Option<Vec<BigInt<BIGINT_LIMBS>>> {
        let k = a.len();
        
        // Check if a is zero
        if a.iter().all(|c| c.is_zero()) {
            return None;
        }
        
        // Extended Euclidean algorithm for polynomials over F_p
        // We need to find b such that a * b ≡ 1 mod modulus_poly
        
        // Build full modulus polynomial: x^k + modulus_poly[k-1]*x^{k-1} + ... + modulus_poly[0]
        let mut full_mod = vec![BigInt::<BIGINT_LIMBS>::zero(); k + 1];
        full_mod[..k].copy_from_slice(&modulus_poly[..k]);
        full_mod[k] = BigInt::one();
        
        let mut r0 = full_mod;
        let mut r1: Vec<BigInt<BIGINT_LIMBS>> = a.to_vec();
        let mut s0 = vec![BigInt::<BIGINT_LIMBS>::zero(); k];
        let mut s1 = vec![BigInt::<BIGINT_LIMBS>::zero(); k];
        s1[0] = BigInt::one();
        
        while !r1.iter().all(|c| c.is_zero()) {
            // Polynomial division
            let (q, r) = Self::fpk_poly_divmod(&r0, &r1, prime);
            
            // s_new = s0 - q * s1
            let qs1 = Self::fpk_poly_mul_mod(&q, &s1, k, modulus_poly, prime);
            let s_new = Self::fpk_sub(&s0, &qs1, prime);
            
            r0 = r1;
            r1 = r;
            s0 = s1;
            s1 = s_new;
        }
        
        // r0 should be a constant (degree 0)
        // Normalize s0 by dividing by r0[0]
        if r0.iter().skip(1).all(|c| c.is_zero()) && !r0[0].is_zero() {
            let inv = Self::mod_inverse(&r0[0], prime)?;
            let result: Vec<_> = s0.iter().map(|c| c.mod_mul(&inv, prime)).collect();
            Some(result)
        } else {
            None
        }
    }

    /// Polynomial division with remainder
    fn fpk_poly_divmod(a: &[BigInt<BIGINT_LIMBS>], b: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> (Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>) {
        // Find degrees
        let deg_a = a.iter().rposition(|c| !c.is_zero()).unwrap_or(0);
        let deg_b = b.iter().rposition(|c| !c.is_zero()).unwrap_or(0);
        
        if deg_a < deg_b {
            return (vec![BigInt::zero()], a.to_vec());
        }
        
        let mut remainder = a.to_vec();
        let mut quotient = vec![BigInt::<BIGINT_LIMBS>::zero(); deg_a - deg_b + 1];
        let b_lead_inv = Self::mod_inverse(&b[deg_b], prime).unwrap_or(BigInt::one());
        
        for i in (0..=deg_a - deg_b).rev() {
            let cur_deg = i + deg_b;
            if cur_deg < remainder.len() && !remainder[cur_deg].is_zero() {
                let coeff = remainder[cur_deg].mod_mul(&b_lead_inv, prime);
                quotient[i] = coeff;
                for j in 0..=deg_b {
                    let sub = coeff.mod_mul(&b[j], prime);
                    remainder[i + j] = remainder[i + j].mod_sub(&sub, prime);
                }
            }
        }
        
        (quotient, remainder)
    }

    /// Polynomial multiplication modulo the extension field modulus
    fn fpk_poly_mul_mod(a: &[BigInt<BIGINT_LIMBS>], b: &[BigInt<BIGINT_LIMBS>], _k: usize, modulus_poly: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Vec<BigInt<BIGINT_LIMBS>> {
        Self::fpk_mul(a, b, modulus_poly, prime)
    }

    /// EC scalar multiplication over extension field
    fn ecpk_scalar_mul(p: &(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>), k_scalar: &BigInt<BIGINT_LIMBS>, a: &[BigInt<BIGINT_LIMBS>], modulus_poly: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Option<(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>)> {
        if k_scalar.is_zero() {
            return None;
        }
        
        let ext_k = p.0.len();
        let mut result: Option<(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>)> = None;
        let mut base = p.clone();
        let mut k = *k_scalar;
        
        while !k.is_zero() {
            if k.limbs()[0] & 1 == 1 {
                result = match result {
                    None => Some(base.clone()),
                    Some(r) => Self::ecpk_add(&r, &base, a, modulus_poly, prime),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::ecpk_add(&base, &base, a, modulus_poly, prime)
                    .unwrap_or((vec![BigInt::zero(); ext_k], vec![BigInt::zero(); ext_k]));
            }
        }
        
        result
    }

    /// EC scalar multiplication over extension field using NAF for optimization
    fn ecpk_scalar_mul_naf(p: &(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>), k_scalar: &BigInt<BIGINT_LIMBS>, a: &[BigInt<BIGINT_LIMBS>], modulus_poly: &[BigInt<BIGINT_LIMBS>], prime: &BigInt<BIGINT_LIMBS>) -> Option<(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>)> {
        if k_scalar.is_zero() {
            return None;
        }
        
        let ext_k = p.0.len();
        
        // Compute NAF representation
        let naf = bigint_to_naf(k_scalar);
        
        // Compute -P for subtraction operations
        let neg_p = (
            p.0.iter().map(|c| prime.mod_sub(c, prime)).collect::<Vec<_>>(),
            p.1.iter().map(|c| prime.mod_sub(c, prime)).collect::<Vec<_>>()
        );
        
        // Process NAF from most significant to least significant
        let mut result: Option<(Vec<BigInt<BIGINT_LIMBS>>, Vec<BigInt<BIGINT_LIMBS>>)> = None;
        
        for digit in naf.iter().rev() {
            // Double
            if let Some(r) = result {
                result = Some(Self::ecpk_add(&r, &r, a, modulus_poly, prime)
                    .unwrap_or((vec![BigInt::zero(); ext_k], vec![BigInt::zero(); ext_k])));
            }
            
            // Add/Subtract
            match digit {
                1 => {
                    result = match result {
                        None => Some(p.clone()),
                        Some(r) => Self::ecpk_add(&r, p, a, modulus_poly, prime),
                    };
                }
                -1 => {
                    result = match result {
                        None => Some(neg_p.clone()),
                        Some(r) => Self::ecpk_add(&r, &neg_p, a, modulus_poly, prime),
                    };
                }
                _ => {} // digit == 0, do nothing
            }
        }
        
        result
    }

    /// Test ECPk DH exchange
    pub fn test_ecpk_dh(&self) -> Result<(), ApiError> {
        let params = self.client.get_ecpk_params()?;
        
        let prime = BigInt::<BIGINT_LIMBS>::from_hex(&params.prime_base);
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let _k = params.extension;
        
        let modulus_poly: Vec<BigInt<BIGINT_LIMBS>> = params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();
        let a: Vec<BigInt<BIGINT_LIMBS>> = params.a.iter().map(|s| BigInt::from_hex(s)).collect();
        let gx: Vec<BigInt<BIGINT_LIMBS>> = params.generator.x.iter().map(|s| BigInt::from_hex(s)).collect();
        let gy: Vec<BigInt<BIGINT_LIMBS>> = params.generator.y.iter().map(|s| BigInt::from_hex(s)).collect();
        let generator = (gx, gy);
        
        // Generate private key - use small fixed key for much faster testing
        let private_key = BigInt::<BIGINT_LIMBS>::from_u64(0xFF);
        
        // Compute public key: [sk]G
        let public_key = Self::ecpk_scalar_mul(&generator, &private_key, &a, &modulus_poly, &prime)
            .ok_or_else(|| ApiError::Validation("Failed to compute ECPk public key".to_string()))?;
        
        // Format for API
        let byte_len = prime.bit_length().div_ceil(8);
        let client_public = ECPkPoint {
            x: public_key.0.iter().map(|c| bigint_to_padded_hex_upper(c, byte_len)).collect(),
            y: public_key.1.iter().map(|c| bigint_to_padded_hex_upper(c, byte_len)).collect(),
        };
        
        // Send to API
        let response = self.client.test_dh_ecpk(client_public)?;
        
        // Parse server public key
        let server_public = (
            response.server_public.x.iter().map(|s| BigInt::<BIGINT_LIMBS>::from_hex(s)).collect::<Vec<_>>(),
            response.server_public.y.iter().map(|s| BigInt::<BIGINT_LIMBS>::from_hex(s)).collect::<Vec<_>>(),
        );
        
        // Compute shared secret
        let our_shared = Self::ecpk_scalar_mul(&server_public, &private_key, &a, &modulus_poly, &prime)
            .ok_or_else(|| ApiError::Validation("Failed to compute ECPk shared secret".to_string()))?;
        let our_shared_x: Vec<String> = our_shared.0.iter().map(|c| bigint_to_padded_hex_upper(c, byte_len)).collect();
        let our_shared_y: Vec<String> = our_shared.1.iter().map(|c| bigint_to_padded_hex_upper(c, byte_len)).collect();
        
        // Compare
        let exp_x: Vec<String> = response.shared_secret.x.iter().map(|s| s.to_uppercase()).collect();
        let exp_y: Vec<String> = response.shared_secret.y.iter().map(|s| s.to_uppercase()).collect();
        let got_x: Vec<String> = our_shared_x.iter().map(|s| s.to_uppercase()).collect();
        let got_y: Vec<String> = our_shared_y.iter().map(|s| s.to_uppercase()).collect();
        
        if exp_x == got_x && exp_y == got_y {
            Ok(())
        } else {
            Err(ApiError::Validation("ECPk DH shared secrets don't match".to_string()))
        }
    }

    /// Test ECPk Schnorr signature verification
    pub fn test_ecpk_signature(&self, message: &str) -> Result<(), ApiError> {
        let params = self.client.get_ecpk_params()?;
        let response = self.client.test_signature(ChallengeType::Ecpk, message)?;
        
        let prime = BigInt::<BIGINT_LIMBS>::from_hex(&params.prime_base);
        let order = BigInt::<BIGINT_LIMBS>::from_hex(&params.order);
        let _k = params.extension;
        
        let modulus_poly: Vec<BigInt<BIGINT_LIMBS>> = params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();
        let a: Vec<BigInt<BIGINT_LIMBS>> = params.a.iter().map(|s| BigInt::from_hex(s)).collect();
        let gx: Vec<BigInt<BIGINT_LIMBS>> = params.generator.x.iter().map(|s| BigInt::from_hex(s)).collect();
        let gy: Vec<BigInt<BIGINT_LIMBS>> = params.generator.y.iter().map(|s| BigInt::from_hex(s)).collect();
        let generator = (gx, gy);
        
        // Parse public key
        let public_obj = response.public.as_object()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let pub_x_arr = public_obj.get("x").and_then(|v| v.as_array())
            .ok_or_else(|| ApiError::Validation("Missing x in public key".to_string()))?;
        let pub_y_arr = public_obj.get("y").and_then(|v| v.as_array())
            .ok_or_else(|| ApiError::Validation("Missing y in public key".to_string()))?;
        let public_key = (
            pub_x_arr.iter().map(|v| BigInt::<BIGINT_LIMBS>::from_hex(v.as_str().unwrap_or("0"))).collect::<Vec<_>>(),
            pub_y_arr.iter().map(|v| BigInt::<BIGINT_LIMBS>::from_hex(v.as_str().unwrap_or("0"))).collect::<Vec<_>>(),
        );
        
        let sig = &response.signature;
        let s = BigInt::<BIGINT_LIMBS>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        
        // Verify: R' = [s]G + [e]Y
        let g_s = Self::ecpk_scalar_mul(&generator, &s, &a, &modulus_poly, &prime);
        let y_e = Self::ecpk_scalar_mul(&public_key, &e_scalar, &a, &modulus_poly, &prime);
        
        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecpk_add(&gs, &ye, &a, &modulus_poly, &prime),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        }.ok_or_else(|| ApiError::Validation("R' is point at infinity".to_string()))?;
        
        // Compute e' = H(R' || m)
        let byte_len = prime.bit_length().div_ceil(8);
        let r_x: Vec<String> = r_prime.0.iter().map(|c| bigint_to_padded_hex(c, byte_len)).collect();
        let r_y: Vec<String> = r_prime.1.iter().map(|c| bigint_to_padded_hex(c, byte_len)).collect();
        let r_obj = serde_json::json!({ "x": r_x, "y": r_y });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();
        
        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(
                format!("Expected: {}, Got: {}", bytes_to_hex(&e_bytes), bytes_to_hex(e_prime.as_slice()))
            ))
        }
    }

    /// Run all tests for ECPk
    pub fn run_ecpk_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Ecpk);
        
        match self.test_ecpk_dh() {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }
        
        match self.test_ecpk_signature("test message") {
            Ok(()) => result.signature_success = true,
            Err(e) => {
                result.signature_success = false;
                result.signature_error = Some(e.to_string());
            }
        }
        
        result
    }

    /// Run all tests for all challenge types
    pub fn run_all_tests(&self) -> Vec<ChallengeTestResult> {
        vec![
            self.run_modp_tests(),
            self.run_f2m_tests(),
            self.run_fpk_tests(),
            self.run_ecp_tests(),
            self.run_ec2m_tests(),
            self.run_ecpk_tests(),
        ]
    }
}

impl Default for ChallengeTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

