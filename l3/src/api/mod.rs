//! API module for interacting with the crypto25.random-oracle.xyz service
//!
//! This module provides a client for testing DH and Schnorr implementations
//! against the remote validation service.
//!
//! # Structure
//! - `client`: HTTP client for API communication
//! - `types`: Request/response data structures
//! - `error`: Error types
//! - `helpers`: Hex encoding and utility functions
//! - `test_runner`: Challenge test runner with crypto implementations

pub mod client;
pub mod error;
pub mod helpers;
pub mod submit_runner;
pub mod test_runner;
pub mod types;

// Re-export commonly used items at the module level
pub use client::{API_BASE_URL, CryptoApiClient};
pub use error::ApiError;
pub use helpers::{
    BIGINT_LIMBS, bigint_to_hex_padded, bigint_to_naf, bigint_to_padded_hex,
    bigint_to_padded_hex_upper, bytes_to_hex, encode_binary_field_for_api,
    encode_ec2m_point_for_api, encode_ecp_point_for_api, encode_ecpk_point_for_api,
    encode_extension_field_for_api, encode_prime_field_for_api, generate_random_bigint,
    hash_to_scalar, hex_to_bytes, mod_pow, strip_json_quotes,
};
pub use submit_runner::{SubmitChallengeRunner, SubmitResult};
pub use test_runner::{ChallengeTestResult, ChallengeTestRunner};
pub use types::{
    ApiSignature, BaseResponse, ChallengeType, EC2mParams, EC2mPoint, ECPParams, ECPPoint,
    ECPkParams, ECPkPoint, F2mParams, FpkParams, ModPParams, ParamResponse, SubmitFinishRequest,
    SubmitFinishResponse, SubmitStartResponse, TestDHECRequest, TestDHECResponse, TestDHF2mRequest,
    TestDHF2mResponse, TestDHFpkRequest, TestDHFpkResponse, TestDHModPRequest, TestDHModPResponse,
    TestSignatureRequest, TestSignatureResponse,
};
