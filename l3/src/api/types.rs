//! API request and response types for the crypto challenge service

use crate::schnorr::SchnorrSignature;
use serde::{Deserialize, Serialize};

use super::helpers::{bytes_to_hex, hex_to_bytes};

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
    pub params: serde_json::Value,
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
// Submit Challenge Types
// ============================================================================

/// Response from /submit/start/{type}
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitStartResponse {
    pub status: String,
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    pub session_id: String,
    pub params: serde_json::Value,
    pub server_public_sign: serde_json::Value,
    pub server_public_dh: serde_json::Value,
    pub signature: ApiSignature,
}

/// Request to /submit/finish
#[derive(Debug, Clone, Serialize)]
pub struct SubmitFinishRequest {
    pub session_id: String,
    pub client_public_sign: serde_json::Value,
    pub client_public_dh: serde_json::Value,
    pub signature: ApiSignature,
    pub shared_secret: serde_json::Value,
}

/// Response from /submit/finish
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitFinishResponse {
    pub status: String,
}
