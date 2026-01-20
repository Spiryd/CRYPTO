//! Submit challenge runner for the crypto25.random-oracle.xyz service
//!
//! This module handles the /submit/start and /submit/finish flow for all challenge types.

use sha2::{Digest, Sha256};

use crate::bigint::BigInt;
use crate::montgomery::MontgomeryCtx;

use super::client::CryptoApiClient;
use super::error::ApiError;
use super::helpers::{
    BIGINT_LIMBS, bigint_to_padded_hex, bytes_to_hex, generate_random_bigint, hash_to_scalar,
    hex_to_bytes, select_limbs_from_bits,
};
use super::types::*;

/// Result of a submit challenge attempt
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub challenge_type: ChallengeType,
    pub success: bool,
    pub session_id: Option<String>,
    pub error: Option<String>,
    pub poisoned: bool,
    pub attempt_time: Option<f64>,
}

impl SubmitResult {
    pub fn success(challenge_type: ChallengeType, session_id: String, attempt_time: f64) -> Self {
        Self {
            challenge_type,
            success: true,
            session_id: Some(session_id),
            error: None,
            poisoned: false,
            attempt_time: Some(attempt_time),
        }
    }

    pub fn poisoned(challenge_type: ChallengeType, session_id: String, attempt_time: f64) -> Self {
        Self {
            challenge_type,
            success: false,
            session_id: Some(session_id),
            error: Some("Poisoned session - signature verification failed".to_string()),
            poisoned: true,
            attempt_time: Some(attempt_time),
        }
    }

    pub fn failed(challenge_type: ChallengeType, error: String) -> Self {
        Self {
            challenge_type,
            success: false,
            session_id: None,
            error: Some(error),
            poisoned: false,
            attempt_time: None,
        }
    }
}

/// Submit challenge runner
pub struct SubmitChallengeRunner {
    client: CryptoApiClient,
}

impl SubmitChallengeRunner {
    pub fn new() -> Self {
        Self {
            client: CryptoApiClient::new(),
        }
    }

    pub fn with_client(client: CryptoApiClient) -> Self {
        Self { client }
    }

    /// Try to complete a submit challenge, retrying on poisoned sessions
    /// Stops at the first successful attempt
    pub fn run_submit(&self, challenge_type: ChallengeType, max_retries: usize) -> SubmitResult {
        for attempt in 0..max_retries {
            println!(
                "    Attempt {}/{} for {:?}...",
                attempt + 1,
                max_retries,
                challenge_type
            );

            let result = match challenge_type {
                ChallengeType::Modp => self.submit_modp(),
                ChallengeType::F2m => self.submit_f2m(),
                ChallengeType::Fpk => self.submit_fpk(),
                ChallengeType::Ecp => self.submit_ecp(),
                ChallengeType::Ec2m => self.submit_ec2m(),
                ChallengeType::Ecpk => self.submit_ecpk(),
            };

            match &result {
                Ok(r) if r.success => {
                    let attempt_time = r.attempt_time.unwrap_or(0.0);
                    println!("      ✓ Success! (attempt time: {:.3}s)", attempt_time);
                    return r.clone();
                }
                Ok(r) if r.poisoned => {
                    let attempt_time = r.attempt_time.unwrap_or(0.0);
                    println!(
                        "      ✗ Poisoned session (attempt time: {:.3}s), retrying...",
                        attempt_time
                    );
                    continue;
                }
                Ok(r) => {
                    println!("      ✗ Submission failed: {:?}", r.error);
                    return r.clone();
                }
                Err(e) => {
                    println!("      ✗ Error: {}", e);
                    return SubmitResult::failed(challenge_type, e.to_string());
                }
            }
        }

        SubmitResult::failed(
            challenge_type,
            format!(
                "Failed after {} attempts (all poisoned or failed)",
                max_retries
            ),
        )
    }

    // ========================================================================
    // ModP Submit
    // ========================================================================

    fn submit_modp(&self) -> Result<SubmitResult, ApiError> {
        let bits = 2048;
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            32 => self.submit_modp_with_limbs::<32>(),
            _ => self.submit_modp_with_limbs::<{ BIGINT_LIMBS }>(),
        }
    }

    fn submit_modp_with_limbs<const N: usize>(&self) -> Result<SubmitResult, ApiError> {
        use std::time::Instant;
        let attempt_start = Instant::now();

        let start = self.client.submit_start(ChallengeType::Modp)?;
        let session_id = start.session_id.clone();
        println!("      [ModP] Session ID: {}", session_id);

        // Parse params
        let params: ModPParams = serde_json::from_value(start.params)?;
        let order = BigInt::<N>::from_hex(&params.order);
        let generator = BigInt::<N>::from_hex(&params.generator);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let ctx = MontgomeryCtx::<N>::new(modulus).expect("odd modulus required");
        let modulus = &ctx.modulus;
        let modulus_byte_len = modulus.bit_length().div_ceil(8);
        println!("      [ModP] Modulus bit length: {}", modulus.bit_length());

        // Parse server public keys
        let server_public_sign_str = start
            .server_public_sign
            .as_str()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_sign".to_string()))?;
        let server_public_sign = BigInt::<N>::from_hex(server_public_sign_str);

        let server_public_dh_str = start
            .server_public_dh
            .as_str()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_dh".to_string()))?;
        let server_public_dh = BigInt::<N>::from_hex(server_public_dh_str);
        println!("      [ModP] Received server public keys");

        // Verify server signature on server_public_dh
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        // R' = g^s * y^e mod p
        let g_s = ctx.mod_pow_noreduce(&generator, &s);
        let y_e = ctx.mod_pow_noreduce(&server_public_sign, &e_scalar);
        let r_prime = ctx.mod_mul_noreduce(&g_s, &y_e);

        // e' = H(R' || message)
        let r_hex = bigint_to_padded_hex(&r_prime, modulus_byte_len);
        let r_encoded = format!(r#""{}""#, r_hex);
        let message = format!(
            r#""{}""#,
            bigint_to_padded_hex(&server_public_dh, modulus_byte_len)
        );

        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            println!("      [ModP] Server signature FAILED verification - poisoned session");
            let attempt_time = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Modp,
                session_id,
                attempt_time,
            ));
        }
        println!("      [ModP] Server signature verified ✓");

        // Generate our keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = ctx.mod_pow_noreduce(&generator, &dh_private);
        println!("      [ModP] Generated DH keypair");

        let sign_private = generate_random_bigint(&order);
        let sign_public = ctx.mod_pow_noreduce(&generator, &sign_private);
        println!("      [ModP] Generated Schnorr keypair");

        // Sign our DH public key
        let k = generate_random_bigint(&order);
        let r = ctx.mod_pow_noreduce(&generator, &k);
        let r_hex_sign = bigint_to_padded_hex(&r, modulus_byte_len);
        let r_encoded_sign = format!(r#""{}""#, r_hex_sign);
        let dh_public_msg = format!(
            r#""{}""#,
            bigint_to_padded_hex(&dh_public, modulus_byte_len)
        );

        let mut hasher = Sha256::new();
        hasher.update(r_encoded_sign.as_bytes());
        hasher.update(dh_public_msg.as_bytes());
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        // s = k - e*x mod order (computed as (k - e*x) mod order)
        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = k.mod_sub(&ex, &order);
        println!("      [ModP] Computed Schnorr signature");

        // Compute shared secret
        let shared_secret = ctx.mod_pow_noreduce(&server_public_dh, &dh_private);
        println!("      [ModP] Computed shared secret");

        // Submit finish
        let sign_public_hex = bigint_to_padded_hex(&sign_public, modulus_byte_len); // lowercase
        let dh_public_hex = bigint_to_padded_hex(&dh_public, modulus_byte_len); // lowercase
        let s_sig_hex = bigint_to_padded_hex(&s_sig, order.bit_length().div_ceil(8)); // lowercase for signature
        let e_hex = bytes_to_hex(e_hash.as_slice());
        let shared_secret_hex = bigint_to_padded_hex(&shared_secret, modulus_byte_len); // lowercase

        println!("      [ModP] Request data:");
        println!(
            "        - client_public_sign: {}...{}",
            &sign_public_hex[..32.min(sign_public_hex.len())],
            &sign_public_hex[sign_public_hex.len().saturating_sub(32)..]
        );
        println!(
            "        - client_public_dh: {}...{}",
            &dh_public_hex[..32.min(dh_public_hex.len())],
            &dh_public_hex[dh_public_hex.len().saturating_sub(32)..]
        );
        println!(
            "        - signature.s: {}...{}",
            &s_sig_hex[..32.min(s_sig_hex.len())],
            &s_sig_hex[s_sig_hex.len().saturating_sub(32)..]
        );
        println!("        - signature.e: {}", &e_hex);
        println!(
            "        - shared_secret: {}...{}",
            &shared_secret_hex[..32.min(shared_secret_hex.len())],
            &shared_secret_hex[shared_secret_hex.len().saturating_sub(32)..]
        );

        let request = SubmitFinishRequest {
            session_id: session_id.clone(),
            client_public_sign: serde_json::Value::String(sign_public_hex),
            client_public_dh: serde_json::Value::String(dh_public_hex),
            signature: ApiSignature {
                s: s_sig_hex,
                e: e_hex,
            },
            shared_secret: serde_json::Value::String(shared_secret_hex),
        };
        println!("      [ModP] Submitting solution...");

        let response = self.client.submit_finish(request)?;
        let attempt_time = attempt_start.elapsed().as_secs_f64();

        println!("      [ModP] Server response: {}", response.status);
        if response.status == "success" {
            println!("      [ModP] ✓ ACCEPTED!");
            Ok(SubmitResult::success(
                ChallengeType::Modp,
                session_id,
                attempt_time,
            ))
        } else {
            println!("      [ModP] ✗ REJECTED: {}", response.status);
            Ok(SubmitResult::failed(
                ChallengeType::Modp,
                format!("Server returned: {}", response.status),
            ))
        }
    }

    // ========================================================================
    // F2m Submit
    // ========================================================================

    fn submit_f2m(&self) -> Result<SubmitResult, ApiError> {
        // First, peek at params to get m
        let start = self.client.submit_start(ChallengeType::F2m)?;
        let params: F2mParams = serde_json::from_value(start.params.clone())?;
        let m = params.extension;

        // Need N*64 > m (strictly greater) to access bit m
        let required_bits = m + 1;
        let limbs = select_limbs_from_bits(required_bits);

        match limbs {
            32 => {
                if 32 * 64 > m {
                    self.submit_f2m_with_limbs::<32>(start)
                } else {
                    self.submit_f2m_with_limbs::<{ BIGINT_LIMBS }>(start)
                }
            }
            _ => self.submit_f2m_with_limbs::<{ BIGINT_LIMBS }>(start),
        }
    }

    fn submit_f2m_with_limbs<const N: usize>(
        &self,
        start: SubmitStartResponse,
    ) -> Result<SubmitResult, ApiError> {
        use std::time::Instant;
        let attempt_start = Instant::now();

        let session_id = start.session_id.clone();

        let params: F2mParams = serde_json::from_value(start.params)?;
        let m = params.extension;

        // Verify we have enough bits (need to access bit m, so N*64 must be > m)
        debug_assert!(N * 64 > m, "Need N*64 > m (got N*64={}, m={})", N * 64, m);
        let order = BigInt::<N>::from_hex(&params.order);
        let generator = BigInt::<N>::from_hex(&params.generator);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let byte_len = m.div_ceil(8);

        let server_public_sign_str = start
            .server_public_sign
            .as_str()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_sign".to_string()))?;
        let server_public_sign = BigInt::<N>::from_hex(server_public_sign_str);

        let server_public_dh_str = start
            .server_public_dh
            .as_str()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_dh".to_string()))?;
        let server_public_dh = BigInt::<N>::from_hex(server_public_dh_str);

        // Verify server signature
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        let g_s = Self::f2m_pow::<N>(&generator, &s, &modulus, m);
        let y_e = Self::f2m_pow::<N>(&server_public_sign, &e_scalar, &modulus, m);
        let r_prime = Self::f2m_mul::<N>(&g_s, &y_e, &modulus, m);

        let r_hex = bigint_to_padded_hex(&r_prime, byte_len);
        let r_encoded = format!(r#""{}""#, r_hex);
        let message = format!(r#""{}""#, bigint_to_padded_hex(&server_public_dh, byte_len));

        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            let attempt_time = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::F2m,
                session_id,
                attempt_time,
            ));
        }

        // Generate keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::f2m_pow::<N>(&generator, &dh_private, &modulus, m);

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::f2m_pow::<N>(&generator, &sign_private, &modulus, m);

        // Sign DH public key
        let k = generate_random_bigint(&order);
        let r = Self::f2m_pow::<N>(&generator, &k, &modulus, m);
        let r_hex_sign = bigint_to_padded_hex(&r, byte_len);
        let r_encoded_sign = format!(r#""{}""#, r_hex_sign);
        let dh_public_msg = format!(r#""{}""#, bigint_to_padded_hex(&dh_public, byte_len));

        let mut hasher = Sha256::new();
        hasher.update(r_encoded_sign.as_bytes());
        hasher.update(dh_public_msg.as_bytes());
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = k.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret = Self::f2m_pow::<N>(&server_public_dh, &dh_private, &modulus, m);

        let order_byte_len = order.bit_length().div_ceil(8);
        let request = SubmitFinishRequest {
            session_id: session_id.clone(),
            client_public_sign: serde_json::Value::String(bigint_to_padded_hex(
                &sign_public,
                byte_len,
            )),
            client_public_dh: serde_json::Value::String(bigint_to_padded_hex(&dh_public, byte_len)),
            signature: ApiSignature {
                s: bigint_to_padded_hex(&s_sig, order_byte_len),
                e: bytes_to_hex(e_hash.as_slice()),
            },
            shared_secret: serde_json::Value::String(bigint_to_padded_hex(
                &shared_secret,
                byte_len,
            )),
        };

        let response = self.client.submit_finish(request)?;
        let attempt_time = attempt_start.elapsed().as_secs_f64();

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::F2m,
                session_id,
                attempt_time,
            ))
        } else {
            Ok(SubmitResult::failed(
                ChallengeType::F2m,
                format!("Server returned: {}", response.status),
            ))
        }
    }

    // ========================================================================
    // Fpk Submit
    // ========================================================================

    fn submit_fpk(&self) -> Result<SubmitResult, ApiError> {
        let bits = 256; // Assuming 256-bit prime base
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => self.submit_fpk_with_limbs::<4>(),
            _ => self.submit_fpk_with_limbs::<{ BIGINT_LIMBS }>(),
        }
    }

    fn submit_fpk_with_limbs<const N: usize>(&self) -> Result<SubmitResult, ApiError> {
        use std::time::Instant;
        let attempt_start = Instant::now();

        let start = self.client.submit_start(ChallengeType::Fpk)?;
        let session_id = start.session_id.clone();

        let params: FpkParams = serde_json::from_value(start.params)?;
        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let order = BigInt::<N>::from_hex(&params.order);
        let _k = params.extension;
        let prime_byte_len = prime.bit_length().div_ceil(8);

        let generator: Vec<BigInt<N>> = params
            .generator
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        let modulus_poly: Vec<BigInt<N>> =
            params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();

        // Parse server public keys
        let server_public_sign_arr = start
            .server_public_sign
            .as_array()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_sign".to_string()))?;
        let server_public_sign: Vec<BigInt<N>> = server_public_sign_arr
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap_or("0")))
            .collect();

        let server_public_dh_arr = start
            .server_public_dh
            .as_array()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_dh".to_string()))?;
        let server_public_dh: Vec<BigInt<N>> = server_public_dh_arr
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap_or("0")))
            .collect();

        // Verify server signature
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        let g_s = Self::fpk_pow::<N>(&generator, &s, &modulus_poly, &prime);
        let y_e = Self::fpk_pow::<N>(&server_public_sign, &e_scalar, &modulus_poly, &prime);
        let r_prime = Self::fpk_mul::<N>(&g_s, &y_e, &modulus_poly, &prime);

        let r_hex: Vec<String> = r_prime
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let r_encoded = serde_json::to_string(&r_hex).unwrap();
        let server_dh_hex: Vec<String> = server_public_dh
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let message = serde_json::to_string(&server_dh_hex).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            let attempt_time = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Fpk,
                session_id,
                attempt_time,
            ));
        }

        // Generate keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::fpk_pow::<N>(&generator, &dh_private, &modulus_poly, &prime);

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::fpk_pow::<N>(&generator, &sign_private, &modulus_poly, &prime);

        // Sign DH public key
        let nonce = generate_random_bigint(&order);
        let r = Self::fpk_pow::<N>(&generator, &nonce, &modulus_poly, &prime);
        let r_hex_sign: Vec<String> = r
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let r_encoded_sign = serde_json::to_string(&r_hex_sign).unwrap();
        let dh_pub_hex: Vec<String> = dh_public
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let dh_public_msg = serde_json::to_string(&dh_pub_hex).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(r_encoded_sign.as_bytes());
        hasher.update(dh_public_msg.as_bytes());
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = nonce.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret =
            Self::fpk_pow::<N>(&server_public_dh, &dh_private, &modulus_poly, &prime);

        let order_byte_len = order.bit_length().div_ceil(8);
        let sign_pub_hex: Vec<String> = sign_public
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let dh_pub_hex: Vec<String> = dh_public
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let shared_hex: Vec<String> = shared_secret
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();

        let request = SubmitFinishRequest {
            session_id: session_id.clone(),
            client_public_sign: serde_json::to_value(&sign_pub_hex).unwrap(),
            client_public_dh: serde_json::to_value(&dh_pub_hex).unwrap(),
            signature: ApiSignature {
                s: bigint_to_padded_hex(&s_sig, order_byte_len),
                e: bytes_to_hex(e_hash.as_slice()),
            },
            shared_secret: serde_json::to_value(&shared_hex).unwrap(),
        };

        let response = self.client.submit_finish(request)?;
        let attempt_time = attempt_start.elapsed().as_secs_f64();

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Fpk,
                session_id,
                attempt_time,
            ))
        } else {
            Ok(SubmitResult::failed(
                ChallengeType::Fpk,
                format!("Server returned: {}", response.status),
            ))
        }
    }

    // ========================================================================
    // ECP Submit
    // ========================================================================

    fn submit_ecp(&self) -> Result<SubmitResult, ApiError> {
        let bits = 256;
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => self.submit_ecp_with_limbs::<4>(),
            _ => self.submit_ecp_with_limbs::<{ BIGINT_LIMBS }>(),
        }
    }

    fn submit_ecp_with_limbs<const N: usize>(&self) -> Result<SubmitResult, ApiError> {
        use std::time::Instant;
        let attempt_start = Instant::now();

        let start = self.client.submit_start(ChallengeType::Ecp)?;
        let session_id = start.session_id.clone();

        let params: ECPParams = serde_json::from_value(start.params)?;
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let order = BigInt::<N>::from_hex(&params.order);
        let a = BigInt::<N>::from_hex(&params.a);
        let gx = BigInt::<N>::from_hex(&params.generator.x);
        let gy = BigInt::<N>::from_hex(&params.generator.y);
        let generator = (gx, gy);
        let byte_len = modulus.bit_length().div_ceil(8);

        // Parse server public keys
        let server_sign_obj = start
            .server_public_sign
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_sign".to_string()))?;
        let server_sign_x =
            BigInt::<N>::from_hex(server_sign_obj.get("x").unwrap().as_str().unwrap());
        let server_sign_y =
            BigInt::<N>::from_hex(server_sign_obj.get("y").unwrap().as_str().unwrap());
        let server_public_sign = (server_sign_x, server_sign_y);

        let server_dh_obj = start
            .server_public_dh
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_dh".to_string()))?;
        let server_dh_x = BigInt::<N>::from_hex(server_dh_obj.get("x").unwrap().as_str().unwrap());
        let server_dh_y = BigInt::<N>::from_hex(server_dh_obj.get("y").unwrap().as_str().unwrap());
        let server_public_dh = (server_dh_x, server_dh_y);

        // Verify server signature
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        let g_s = Self::ecp_scalar_mul::<N>(&generator, &s, &a, &modulus);
        let y_e = Self::ecp_scalar_mul::<N>(&server_public_sign, &e_scalar, &a, &modulus);

        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecp_add::<N>(&gs, &ye, &a, &modulus),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        };

        let r_prime = match r_prime {
            Some(r) => r,
            None => {
                let attempt_time = attempt_start.elapsed().as_secs_f64();
                return Ok(SubmitResult::poisoned(
                    ChallengeType::Ecp,
                    session_id,
                    attempt_time,
                ));
            }
        };

        let r_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&r_prime.0, byte_len),
            "y": bigint_to_padded_hex(&r_prime.1, byte_len)
        });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();
        let msg_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&server_public_dh.0, byte_len),
            "y": bigint_to_padded_hex(&server_public_dh.1, byte_len)
        });
        let message = serde_json::to_string(&msg_obj).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            let attempt_time = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Ecp,
                session_id,
                attempt_time,
            ));
        }

        // Generate keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::ecp_scalar_mul::<N>(&generator, &dh_private, &a, &modulus)
            .ok_or_else(|| ApiError::Validation("Failed to compute DH public key".to_string()))?;

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::ecp_scalar_mul::<N>(&generator, &sign_private, &a, &modulus)
            .ok_or_else(|| ApiError::Validation("Failed to compute sign public key".to_string()))?;

        // Sign DH public key
        let k = generate_random_bigint(&order);
        let r = Self::ecp_scalar_mul::<N>(&generator, &k, &a, &modulus)
            .ok_or_else(|| ApiError::Validation("Failed to compute R".to_string()))?;

        let r_obj_sign = serde_json::json!({
            "x": bigint_to_padded_hex(&r.0, byte_len),
            "y": bigint_to_padded_hex(&r.1, byte_len)
        });
        let r_encoded_sign = serde_json::to_string(&r_obj_sign).unwrap();
        let dh_pub_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&dh_public.0, byte_len),
            "y": bigint_to_padded_hex(&dh_public.1, byte_len)
        });
        let dh_public_msg = serde_json::to_string(&dh_pub_obj).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(r_encoded_sign.as_bytes());
        hasher.update(dh_public_msg.as_bytes());
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = k.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret = Self::ecp_scalar_mul::<N>(&server_public_dh, &dh_private, &a, &modulus)
            .ok_or_else(|| ApiError::Validation("Failed to compute shared secret".to_string()))?;

        let order_byte_len = order.bit_length().div_ceil(8);
        let request = SubmitFinishRequest {
            session_id: session_id.clone(),
            client_public_sign: serde_json::json!({
                "x": bigint_to_padded_hex(&sign_public.0, byte_len),
                "y": bigint_to_padded_hex(&sign_public.1, byte_len)
            }),
            client_public_dh: serde_json::json!({
                "x": bigint_to_padded_hex(&dh_public.0, byte_len),
                "y": bigint_to_padded_hex(&dh_public.1, byte_len)
            }),
            signature: ApiSignature {
                s: bigint_to_padded_hex(&s_sig, order_byte_len),
                e: bytes_to_hex(e_hash.as_slice()),
            },
            shared_secret: serde_json::json!({
                "x": bigint_to_padded_hex(&shared_secret.0, byte_len),
                "y": bigint_to_padded_hex(&shared_secret.1, byte_len)
            }),
        };

        let response = self.client.submit_finish(request)?;
        let attempt_time = attempt_start.elapsed().as_secs_f64();

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Ecp,
                session_id,
                attempt_time,
            ))
        } else {
            Ok(SubmitResult::failed(
                ChallengeType::Ecp,
                format!("Server returned: {}", response.status),
            ))
        }
    }

    // ========================================================================
    // EC2m Submit
    // ========================================================================

    fn submit_ec2m(&self) -> Result<SubmitResult, ApiError> {
        let bits = 512; // Needs 2*m capacity for field operations
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            9 => self.submit_ec2m_with_limbs::<9>(),
            _ => self.submit_ec2m_with_limbs::<{ BIGINT_LIMBS }>(),
        }
    }

    fn submit_ec2m_with_limbs<const N: usize>(&self) -> Result<SubmitResult, ApiError> {
        use std::time::Instant;
        let attempt_start = Instant::now();

        let start = self.client.submit_start(ChallengeType::Ec2m)?;
        let session_id = start.session_id.clone();

        let params: EC2mParams = serde_json::from_value(start.params)?;
        let m = params.extension;
        let order = BigInt::<N>::from_hex(&params.order);
        let red_poly = BigInt::<N>::from_hex(&params.modulus);
        let a = BigInt::<N>::from_hex(&params.a);
        let gx = BigInt::<N>::from_hex(&params.generator.x);
        let gy = BigInt::<N>::from_hex(&params.generator.y);
        let generator = (gx, gy);
        let byte_len = m.div_ceil(8);

        // Parse server public keys
        let server_sign_obj = start
            .server_public_sign
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_sign".to_string()))?;
        let server_sign_x =
            BigInt::<N>::from_hex(server_sign_obj.get("x").unwrap().as_str().unwrap());
        let server_sign_y =
            BigInt::<N>::from_hex(server_sign_obj.get("y").unwrap().as_str().unwrap());
        let server_public_sign = (server_sign_x, server_sign_y);

        let server_dh_obj = start
            .server_public_dh
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_dh".to_string()))?;
        let server_dh_x = BigInt::<N>::from_hex(server_dh_obj.get("x").unwrap().as_str().unwrap());
        let server_dh_y = BigInt::<N>::from_hex(server_dh_obj.get("y").unwrap().as_str().unwrap());
        let server_public_dh = (server_dh_x, server_dh_y);

        // Verify server signature
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        let g_s = Self::ec2m_scalar_mul::<N>(&generator, &s, &a, &red_poly, m);
        let y_e = Self::ec2m_scalar_mul::<N>(&server_public_sign, &e_scalar, &a, &red_poly, m);

        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ec2m_add::<N>(&gs, &ye, &a, &red_poly, m),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        };

        let r_prime = match r_prime {
            Some(r) => r,
            None => {
                let attempt_time = attempt_start.elapsed().as_secs_f64();
                return Ok(SubmitResult::poisoned(
                    ChallengeType::Ec2m,
                    session_id,
                    attempt_time,
                ));
            }
        };

        let r_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&r_prime.0, byte_len),
            "y": bigint_to_padded_hex(&r_prime.1, byte_len)
        });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();
        let msg_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&server_public_dh.0, byte_len),
            "y": bigint_to_padded_hex(&server_public_dh.1, byte_len)
        });
        let message = serde_json::to_string(&msg_obj).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            let attempt_time = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Ec2m,
                session_id,
                attempt_time,
            ));
        }

        // Generate keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::ec2m_scalar_mul::<N>(&generator, &dh_private, &a, &red_poly, m)
            .ok_or_else(|| ApiError::Validation("Failed to compute DH public key".to_string()))?;

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::ec2m_scalar_mul::<N>(&generator, &sign_private, &a, &red_poly, m)
            .ok_or_else(|| {
            ApiError::Validation("Failed to compute sign public key".to_string())
        })?;

        // Sign DH public key
        let k = generate_random_bigint(&order);
        let r = Self::ec2m_scalar_mul::<N>(&generator, &k, &a, &red_poly, m)
            .ok_or_else(|| ApiError::Validation("Failed to compute R".to_string()))?;

        let r_obj_sign = serde_json::json!({
            "x": bigint_to_padded_hex(&r.0, byte_len),
            "y": bigint_to_padded_hex(&r.1, byte_len)
        });
        let r_encoded_sign = serde_json::to_string(&r_obj_sign).unwrap();
        let dh_pub_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&dh_public.0, byte_len),
            "y": bigint_to_padded_hex(&dh_public.1, byte_len)
        });
        let dh_public_msg = serde_json::to_string(&dh_pub_obj).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(r_encoded_sign.as_bytes());
        hasher.update(dh_public_msg.as_bytes());
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = k.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret =
            Self::ec2m_scalar_mul::<N>(&server_public_dh, &dh_private, &a, &red_poly, m)
                .ok_or_else(|| {
                    ApiError::Validation("Failed to compute shared secret".to_string())
                })?;

        let order_byte_len = order.bit_length().div_ceil(8);
        let request = SubmitFinishRequest {
            session_id: session_id.clone(),
            client_public_sign: serde_json::json!({
                "x": bigint_to_padded_hex(&sign_public.0, byte_len),
                "y": bigint_to_padded_hex(&sign_public.1, byte_len)
            }),
            client_public_dh: serde_json::json!({
                "x": bigint_to_padded_hex(&dh_public.0, byte_len),
                "y": bigint_to_padded_hex(&dh_public.1, byte_len)
            }),
            signature: ApiSignature {
                s: bigint_to_padded_hex(&s_sig, order_byte_len),
                e: bytes_to_hex(e_hash.as_slice()),
            },
            shared_secret: serde_json::json!({
                "x": bigint_to_padded_hex(&shared_secret.0, byte_len),
                "y": bigint_to_padded_hex(&shared_secret.1, byte_len)
            }),
        };

        let response = self.client.submit_finish(request)?;
        let attempt_time = attempt_start.elapsed().as_secs_f64();

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Ec2m,
                session_id,
                attempt_time,
            ))
        } else {
            Ok(SubmitResult::failed(
                ChallengeType::Ec2m,
                format!("Server returned: {}", response.status),
            ))
        }
    }

    // ========================================================================
    // ECPk Submit
    // ========================================================================

    fn submit_ecpk(&self) -> Result<SubmitResult, ApiError> {
        let bits = 256;
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => self.submit_ecpk_with_limbs::<4>(),
            _ => self.submit_ecpk_with_limbs::<{ BIGINT_LIMBS }>(),
        }
    }

    fn submit_ecpk_with_limbs<const N: usize>(&self) -> Result<SubmitResult, ApiError> {
        use std::time::Instant;
        let attempt_start = Instant::now();

        println!("      [ECPk] Starting ECPk submission");
        let start = self.client.submit_start(ChallengeType::Ecpk)?;
        let session_id = start.session_id.clone();

        let params: ECPkParams = serde_json::from_value(start.params)?;
        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let order = BigInt::<N>::from_hex(&params.order);
        let k = params.extension;
        let prime_byte_len = prime.bit_length().div_ceil(8);

        let modulus_poly: Vec<BigInt<N>> =
            params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();
        let a_coeffs: Vec<BigInt<N>> = params.a.iter().map(|s| BigInt::from_hex(s)).collect();
        let gx: Vec<BigInt<N>> = params
            .generator
            .x
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        let gy: Vec<BigInt<N>> = params
            .generator
            .y
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        let generator = (gx.clone(), gy.clone());
        println!(
            "      [ECPk] Parsed parameters: k={}, prime_byte_len={}",
            k, prime_byte_len
        );
        println!("      [ECPk] Parsed server public keys");

        // Parse server public keys
        let server_sign_obj = start
            .server_public_sign
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_sign".to_string()))?;
        let server_sign_x: Vec<BigInt<N>> = server_sign_obj
            .get("x")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap()))
            .collect();
        let server_sign_y: Vec<BigInt<N>> = server_sign_obj
            .get("y")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap()))
            .collect();
        let server_public_sign = (server_sign_x, server_sign_y);

        let server_dh_obj = start
            .server_public_dh
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_dh".to_string()))?;
        let server_dh_x: Vec<BigInt<N>> = server_dh_obj
            .get("x")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap()))
            .collect();
        let server_dh_y: Vec<BigInt<N>> = server_dh_obj
            .get("y")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap()))
            .collect();
        let server_public_dh = (server_dh_x, server_dh_y);

        // Verify server signature
        let sig = &start.signature;
        let s_scalar = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        println!("      [ECPk] Computing g^s...");
        let g_s =
            Self::ecpk_scalar_mul::<N>(&generator, &s_scalar, &a_coeffs, &modulus_poly, &prime);
        println!(
            "      [ECPk] g_s result: {}",
            if g_s.is_some() { "Some" } else { "None" }
        );
        println!("      [ECPk] Computing y^e...");
        let y_e = Self::ecpk_scalar_mul::<N>(
            &server_public_sign,
            &e_scalar,
            &a_coeffs,
            &modulus_poly,
            &prime,
        );
        println!(
            "      [ECPk] y_e result: {}",
            if y_e.is_some() { "Some" } else { "None" }
        );

        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecpk_add::<N>(&gs, &ye, &a_coeffs, &modulus_poly, &prime),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        };

        let r_prime = match r_prime {
            Some(r) => r,
            None => {
                let attempt_time = attempt_start.elapsed().as_secs_f64();
                return Ok(SubmitResult::poisoned(
                    ChallengeType::Ecpk,
                    session_id,
                    attempt_time,
                ));
            }
        };

        let r_x_hex: Vec<String> = r_prime
            .0
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let r_y_hex: Vec<String> = r_prime
            .1
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let r_obj = serde_json::json!({ "x": r_x_hex, "y": r_y_hex });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();

        let dh_x_hex: Vec<String> = server_public_dh
            .0
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let dh_y_hex: Vec<String> = server_public_dh
            .1
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let msg_obj = serde_json::json!({ "x": dh_x_hex, "y": dh_y_hex });
        let message = serde_json::to_string(&msg_obj).unwrap();

        println!(
            "      [ECPk] r_prime.0.len()={}, r_prime.1.len()={}",
            r_prime.0.len(),
            r_prime.1.len()
        );
        println!(
            "      [ECPk] r_encoded: {}",
            &r_encoded[..r_encoded.len().min(200)]
        );
        println!(
            "      [ECPk] message: {}",
            &message[..message.len().min(200)]
        );

        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            println!("      [ECPk] Signature verification FAILED");
            println!("      [ECPk]   Expected e: {}", hex::encode(&e_bytes));
            println!("      [ECPk]   Computed e': {}", hex::encode(e_prime));
            let attempt_time = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Ecpk,
                session_id,
                attempt_time,
            ));
        }

        // Generate keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::ecpk_scalar_mul::<N>(
            &generator,
            &dh_private,
            &a_coeffs,
            &modulus_poly,
            &prime,
        )
        .ok_or_else(|| ApiError::Validation("Failed to compute DH public key".to_string()))?;

        let sign_private = generate_random_bigint(&order);
        let sign_public =
            Self::ecpk_scalar_mul::<N>(&generator, &sign_private, &a_coeffs, &modulus_poly, &prime)
                .ok_or_else(|| {
                    ApiError::Validation("Failed to compute sign public key".to_string())
                })?;

        // Sign DH public key
        let nonce = generate_random_bigint(&order);
        let r = Self::ecpk_scalar_mul::<N>(&generator, &nonce, &a_coeffs, &modulus_poly, &prime)
            .ok_or_else(|| ApiError::Validation("Failed to compute R".to_string()))?;

        let r_x_sign: Vec<String> =
            r.0.iter()
                .map(|c| bigint_to_padded_hex(c, prime_byte_len))
                .collect();
        let r_y_sign: Vec<String> =
            r.1.iter()
                .map(|c| bigint_to_padded_hex(c, prime_byte_len))
                .collect();
        let r_obj_sign = serde_json::json!({ "x": r_x_sign, "y": r_y_sign });
        let r_encoded_sign = serde_json::to_string(&r_obj_sign).unwrap();

        let dh_pub_x: Vec<String> = dh_public
            .0
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let dh_pub_y: Vec<String> = dh_public
            .1
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let dh_pub_obj = serde_json::json!({ "x": dh_pub_x, "y": dh_pub_y });
        let dh_public_msg = serde_json::to_string(&dh_pub_obj).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(r_encoded_sign.as_bytes());
        hasher.update(dh_public_msg.as_bytes());
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = nonce.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret = Self::ecpk_scalar_mul::<N>(
            &server_public_dh,
            &dh_private,
            &a_coeffs,
            &modulus_poly,
            &prime,
        )
        .ok_or_else(|| ApiError::Validation("Failed to compute shared secret".to_string()))?;

        let order_byte_len = order.bit_length().div_ceil(8);
        let sign_pub_x: Vec<String> = sign_public
            .0
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let sign_pub_y: Vec<String> = sign_public
            .1
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let dh_pub_x_upper: Vec<String> = dh_public
            .0
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let dh_pub_y_upper: Vec<String> = dh_public
            .1
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let shared_x: Vec<String> = shared_secret
            .0
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let shared_y: Vec<String> = shared_secret
            .1
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();

        let request = SubmitFinishRequest {
            session_id: session_id.clone(),
            client_public_sign: serde_json::json!({ "x": sign_pub_x, "y": sign_pub_y }),
            client_public_dh: serde_json::json!({ "x": dh_pub_x_upper, "y": dh_pub_y_upper }),
            signature: ApiSignature {
                s: bigint_to_padded_hex(&s_sig, order_byte_len),
                e: bytes_to_hex(e_hash.as_slice()),
            },
            shared_secret: serde_json::json!({ "x": shared_x, "y": shared_y }),
        };

        let response = self.client.submit_finish(request)?;
        let attempt_time = attempt_start.elapsed().as_secs_f64();

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Ecpk,
                session_id,
                attempt_time,
            ))
        } else {
            Ok(SubmitResult::failed(
                ChallengeType::Ecpk,
                format!("Server returned: {}", response.status),
            ))
        }
    }

    // ========================================================================
    // Cryptographic Primitives (duplicated from test_runner for independence)
    // ========================================================================

    fn f2m_mul<const N: usize>(
        a: &BigInt<N>,
        b: &BigInt<N>,
        reduction_poly: &BigInt<N>,
        m: usize,
    ) -> BigInt<N> {
        let mut result = BigInt::<N>::zero();
        let mut a_shifted = *a;

        for i in 0..m {
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            if limb_idx < N && (b.limbs()[limb_idx] >> bit_idx) & 1 == 1 {
                result = result ^ a_shifted;
            }

            a_shifted = a_shifted << 1;

            let m_limb_idx = m / 64;
            let m_bit_idx = m % 64;
            if m_limb_idx < N && (a_shifted.limbs()[m_limb_idx] >> m_bit_idx) & 1 == 1 {
                a_shifted = a_shifted ^ (BigInt::<N>::one() << m);
                a_shifted = a_shifted ^ *reduction_poly;
            }
        }

        Self::f2m_reduce::<N>(&result, reduction_poly, m)
    }

    fn f2m_reduce<const N: usize>(
        a: &BigInt<N>,
        reduction_poly: &BigInt<N>,
        m: usize,
    ) -> BigInt<N> {
        let mut result = *a;

        for i in (m..2 * m).rev() {
            let limb_idx = i / 64;
            let bit_idx = i % 64;

            if limb_idx < N && (result.limbs()[limb_idx] >> bit_idx) & 1 == 1 {
                let shift = i - m;
                result = result ^ (BigInt::<N>::one() << i);
                result = result ^ (*reduction_poly << shift);
            }
        }

        result
    }

    fn f2m_pow<const N: usize>(
        base: &BigInt<N>,
        exp: &BigInt<N>,
        modulus: &BigInt<N>,
        m: usize,
    ) -> BigInt<N> {
        if exp.is_zero() {
            return BigInt::one();
        }

        let mut result = BigInt::<N>::one();
        let mut base = *base;
        let mut exp = *exp;

        while !exp.is_zero() {
            if exp.limbs()[0] & 1 == 1 {
                result = Self::f2m_mul::<N>(&result, &base, modulus, m);
            }
            exp = exp >> 1;
            base = Self::f2m_mul::<N>(&base, &base, modulus, m);
        }

        result
    }

    fn fpk_mul<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        let k = a.len();
        let mut product = vec![BigInt::<N>::zero(); 2 * k - 1];
        for i in 0..k {
            if a[i].is_zero() {
                continue;
            }
            for j in 0..k {
                if b[j].is_zero() {
                    continue;
                }
                let term = a[i].mod_mul(&b[j], prime);
                product[i + j] = product[i + j].mod_add(&term, prime);
            }
        }

        let mut result = product;
        for i in (k..result.len()).rev() {
            let coeff = result[i];
            if !coeff.is_zero() {
                for j in 0..k {
                    let sub_term = coeff.mod_mul(&modulus_poly[j], prime);
                    result[i - k + j] = result[i - k + j].mod_sub(&sub_term, prime);
                }
                result[i] = BigInt::zero();
            }
        }

        result[0..k].to_vec()
    }

    fn fpk_pow<const N: usize>(
        base: &[BigInt<N>],
        exp: &BigInt<N>,
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        let k = base.len();

        if exp.is_zero() {
            let mut one = vec![BigInt::<N>::zero(); k];
            one[0] = BigInt::one();
            return one;
        }

        let mut result = vec![BigInt::<N>::zero(); k];
        result[0] = BigInt::one();

        let mut base = base.to_vec();
        let mut exp = *exp;

        while !exp.is_zero() {
            if exp.limbs()[0] & 1 == 1 {
                result = Self::fpk_mul::<N>(&result, &base, modulus_poly, prime);
            }
            exp = exp >> 1;
            base = Self::fpk_mul::<N>(&base, &base, modulus_poly, prime);
        }

        result
    }

    fn mod_inverse<const N: usize>(a: &BigInt<N>, modulus: &BigInt<N>) -> Option<BigInt<N>> {
        let mut old_r = *modulus;
        let mut r = a.modulo(modulus);
        let mut old_t: (BigInt<N>, bool) = (BigInt::zero(), false);
        let mut t: (BigInt<N>, bool) = (BigInt::one(), false);

        while !r.is_zero() {
            let (quotient, remainder) = old_r.div_rem(&r);
            old_r = r;
            r = remainder;

            let q_times_t = quotient.mod_mul(&t.0, modulus);
            let new_t = if old_t.1 == t.1 {
                let (diff, borrow) = old_t.0.sub_with_borrow(&q_times_t);
                if borrow {
                    let (diff2, _) = q_times_t.sub_with_borrow(&old_t.0);
                    (diff2, !old_t.1)
                } else {
                    (diff, old_t.1)
                }
            } else {
                (old_t.0.mod_add(&q_times_t, modulus), old_t.1)
            };

            old_t = t;
            t = new_t;
        }

        if old_r.is_one() {
            if old_t.1 {
                Some(modulus.mod_sub(&old_t.0, modulus))
            } else {
                Some(old_t.0.modulo(modulus))
            }
        } else {
            None
        }
    }

    fn ecp_add<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        q: &(BigInt<N>, BigInt<N>),
        a: &BigInt<N>,
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        let (x1, y1) = p;
        let (x2, y2) = q;

        if x1.is_zero() && y1.is_zero() {
            return Some(*q);
        }
        if x2.is_zero() && y2.is_zero() {
            return Some(*p);
        }

        let neg_y2 = modulus.sub_with_borrow(y2).0;
        if x1 == x2 && y1 == &neg_y2 {
            return None;
        }

        let lambda = if x1 == x2 && y1 == y2 {
            if y1.is_zero() {
                return None;
            }
            let three = BigInt::<N>::from_u64(3);
            let two = BigInt::<N>::from_u64(2);
            let x1_sq = x1.mod_mul(x1, modulus);
            let numerator = three.mod_mul(&x1_sq, modulus).mod_add(a, modulus);
            let denominator = two.mod_mul(y1, modulus);
            let denom_inv = Self::mod_inverse(&denominator, modulus)?;
            numerator.mod_mul(&denom_inv, modulus)
        } else {
            let numerator = y2.mod_sub(y1, modulus);
            let denominator = x2.mod_sub(x1, modulus);
            let denom_inv = Self::mod_inverse(&denominator, modulus)?;
            numerator.mod_mul(&denom_inv, modulus)
        };

        let lambda_sq = lambda.mod_mul(&lambda, modulus);
        let x3 = lambda_sq.mod_sub(x1, modulus).mod_sub(x2, modulus);
        let y3 = lambda
            .mod_mul(&x1.mod_sub(&x3, modulus), modulus)
            .mod_sub(y1, modulus);

        Some((x3, y3))
    }

    fn ecp_scalar_mul<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        k: &BigInt<N>,
        a: &BigInt<N>,
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        if k.is_zero() {
            return None;
        }

        let mut result: Option<(BigInt<N>, BigInt<N>)> = None;
        let mut base = *p;
        let mut k = *k;

        while !k.is_zero() {
            if k.limbs()[0] & 1 == 1 {
                result = match result {
                    None => Some(base),
                    Some(r) => Self::ecp_add::<N>(&r, &base, a, modulus),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::ecp_add::<N>(&base, &base, a, modulus)?;
            }
        }

        result
    }

    fn f2m_div<const N: usize>(
        a: &BigInt<N>,
        b: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<BigInt<N>> {
        let b_inv = Self::f2m_inverse::<N>(b, red_poly, m)?;
        Some(Self::f2m_mul::<N>(a, &b_inv, red_poly, m))
    }

    fn f2m_inverse<const N: usize>(
        a: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<BigInt<N>> {
        if a.is_zero() {
            return None;
        }

        let full_modulus = (BigInt::<N>::one() << m) ^ *red_poly;
        let mut u = *a;
        let mut v = full_modulus;
        let mut g1 = BigInt::<N>::one();
        let mut g2 = BigInt::<N>::zero();

        while !u.is_zero() && !v.is_zero() {
            while !u.is_zero() && u.limbs()[0] & 1 == 0 {
                u = u >> 1;
                if g1.limbs()[0] & 1 == 1 {
                    g1 = g1 ^ full_modulus;
                }
                g1 = g1 >> 1;
            }

            while !v.is_zero() && v.limbs()[0] & 1 == 0 {
                v = v >> 1;
                if g2.limbs()[0] & 1 == 1 {
                    g2 = g2 ^ full_modulus;
                }
                g2 = g2 >> 1;
            }

            if u.bit_length() >= v.bit_length() {
                u = u ^ v;
                g1 = g1 ^ g2;
            } else {
                v = v ^ u;
                g2 = g2 ^ g1;
            }
        }

        if u.is_one() {
            Some(Self::f2m_reduce::<N>(&g1, red_poly, m))
        } else if v.is_one() {
            Some(Self::f2m_reduce::<N>(&g2, red_poly, m))
        } else {
            None
        }
    }

    fn ec2m_add<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        q: &(BigInt<N>, BigInt<N>),
        a: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        let (x1, y1) = p;
        let (x2, y2) = q;

        if x1.is_zero() && y1.is_zero() {
            return Some(*q);
        }
        if x2.is_zero() && y2.is_zero() {
            return Some(*p);
        }

        let neg_y2 = *x2 ^ *y2;
        if x1 == x2 && *y1 == neg_y2 {
            return None;
        }

        if x1 == x2 && y1 == y2 {
            if x1.is_zero() {
                return None;
            }
            let y_over_x = Self::f2m_div::<N>(y1, x1, red_poly, m)?;
            let lambda = *x1 ^ y_over_x;
            let lambda_sq = Self::f2m_mul::<N>(&lambda, &lambda, red_poly, m);
            let x3 = lambda_sq ^ lambda ^ *a;
            let x1_sq = Self::f2m_mul::<N>(x1, x1, red_poly, m);
            let lambda_plus_1 = lambda ^ BigInt::one();
            let y3 = x1_sq ^ Self::f2m_mul::<N>(&lambda_plus_1, &x3, red_poly, m);
            Some((x3, y3))
        } else {
            let y_sum = *y1 ^ *y2;
            let x_sum = *x1 ^ *x2;
            let lambda = Self::f2m_div::<N>(&y_sum, &x_sum, red_poly, m)?;
            let lambda_sq = Self::f2m_mul::<N>(&lambda, &lambda, red_poly, m);
            let x3 = lambda_sq ^ lambda ^ *x1 ^ *x2 ^ *a;
            let y3 = Self::f2m_mul::<N>(&lambda, &(*x1 ^ x3), red_poly, m) ^ x3 ^ *y1;
            Some((x3, y3))
        }
    }

    fn ec2m_scalar_mul<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        k: &BigInt<N>,
        a: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        if k.is_zero() {
            return None;
        }

        let mut result: Option<(BigInt<N>, BigInt<N>)> = None;
        let mut base = *p;
        let mut k = *k;

        while !k.is_zero() {
            if k.limbs()[0] & 1 == 1 {
                result = match result {
                    None => Some(base),
                    Some(r) => Self::ec2m_add::<N>(&r, &base, a, red_poly, m),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::ec2m_add::<N>(&base, &base, a, red_poly, m)
                    .unwrap_or((BigInt::zero(), BigInt::zero()));
            }
        }

        result
    }

    // ========================================================================
    // Fixed-length F_p^k element operations (always produce length k)
    // ========================================================================

    fn fpk_elem_add<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        (0..k)
            .map(|i| {
                let ai = a.get(i).cloned().unwrap_or_else(BigInt::zero);
                let bi = b.get(i).cloned().unwrap_or_else(BigInt::zero);
                ai.mod_add(&bi, prime)
            })
            .collect()
    }

    fn fpk_elem_sub<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        (0..k)
            .map(|i| {
                let ai = a.get(i).cloned().unwrap_or_else(BigInt::zero);
                let bi = b.get(i).cloned().unwrap_or_else(BigInt::zero);
                ai.mod_sub(&bi, prime)
            })
            .collect()
    }

    fn fpk_elem_neg<const N: usize>(
        a: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        (0..k)
            .map(|i| {
                let ai = a.get(i).cloned().unwrap_or_else(BigInt::zero);
                if ai.is_zero() {
                    BigInt::zero()
                } else {
                    prime.mod_sub(&ai, prime)
                }
            })
            .collect()
    }

    fn fpk_elem_scalar_mul<const N: usize>(
        a: &[BigInt<N>],
        s: &BigInt<N>,
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        (0..k)
            .map(|i| {
                a.get(i)
                    .cloned()
                    .unwrap_or_else(BigInt::zero)
                    .mod_mul(s, prime)
            })
            .collect()
    }

    fn fpk_elem_mul<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        let mut product = vec![BigInt::<N>::zero(); 2 * k - 1];

        for i in 0..k {
            let ai = a.get(i).cloned().unwrap_or_else(BigInt::zero);
            if ai.is_zero() {
                continue;
            }
            for j in 0..k {
                let bj = b.get(j).cloned().unwrap_or_else(BigInt::zero);
                if bj.is_zero() {
                    continue;
                }
                let term = ai.mod_mul(&bj, prime);
                product[i + j] = product[i + j].mod_add(&term, prime);
            }
        }

        // Use only the low coefficients of the modulus (degree < k part).
        let m: Vec<BigInt<N>> = if modulus_poly.len() >= k {
            modulus_poly[..k].to_vec()
        } else {
            let mut mm = modulus_poly.to_vec();
            mm.resize(k, BigInt::zero());
            mm
        };

        // Reduce from high degree down
        for idx in (k..product.len()).rev() {
            let coeff = product[idx].clone();
            if coeff.is_zero() {
                continue;
            }
            for j in 0..k {
                let sub_term = coeff.mod_mul(&m[j], prime);
                product[idx - k + j] = product[idx - k + j].mod_sub(&sub_term, prime);
            }
            product[idx] = BigInt::zero();
        }

        product[..k].to_vec()
    }

    // ========================================================================
    // Polynomial operations for EEA inversion (different from field element ops)
    // ========================================================================

    fn poly_trim<const N: usize>(mut v: Vec<BigInt<N>>) -> Vec<BigInt<N>> {
        while v.len() > 1 && v.last().is_some_and(|c| c.is_zero()) {
            v.pop();
        }
        if v.is_empty() {
            v.push(BigInt::zero());
        }
        v
    }

    fn poly_is_zero<const N: usize>(v: &[BigInt<N>]) -> bool {
        v.iter().all(|c| c.is_zero())
    }

    fn poly_sub<const N: usize>(a: &[BigInt<N>], b: &[BigInt<N>], p: &BigInt<N>) -> Vec<BigInt<N>> {
        let n = a.len().max(b.len());
        Self::poly_trim(
            (0..n)
                .map(|i| {
                    let ai = a.get(i).cloned().unwrap_or_else(BigInt::zero);
                    let bi = b.get(i).cloned().unwrap_or_else(BigInt::zero);
                    ai.mod_sub(&bi, p)
                })
                .collect(),
        )
    }

    fn poly_mul<const N: usize>(a: &[BigInt<N>], b: &[BigInt<N>], p: &BigInt<N>) -> Vec<BigInt<N>> {
        if Self::poly_is_zero(a) || Self::poly_is_zero(b) {
            return vec![BigInt::zero()];
        }
        let mut out = vec![BigInt::<N>::zero(); a.len() + b.len() - 1];
        for i in 0..a.len() {
            if a[i].is_zero() {
                continue;
            }
            for j in 0..b.len() {
                if b[j].is_zero() {
                    continue;
                }
                let term = a[i].mod_mul(&b[j], p);
                out[i + j] = out[i + j].mod_add(&term, p);
            }
        }
        Self::poly_trim(out)
    }

    fn poly_mod_monic<const N: usize>(
        mut a: Vec<BigInt<N>>,
        modulus_full: &[BigInt<N>],
        p: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        let k = modulus_full.len() - 1;
        a = Self::poly_trim(a);
        while a.len() > k {
            let deg = a.len() - 1;
            let coeff = a[deg].clone();
            if !coeff.is_zero() {
                for j in 0..k {
                    let sub_term = coeff.mod_mul(&modulus_full[j], p);
                    a[deg - k + j] = a[deg - k + j].mod_sub(&sub_term, p);
                }
            }
            a.pop();
        }
        Self::poly_trim(a)
    }

    fn poly_divmod<const N: usize>(
        dividend: &[BigInt<N>],
        divisor: &[BigInt<N>],
        p: &BigInt<N>,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        let divisor = Self::poly_trim(divisor.to_vec());
        if Self::poly_is_zero(&divisor) {
            return Some((vec![BigInt::zero()], dividend.to_vec()));
        }

        let mut rem = Self::poly_trim(dividend.to_vec());
        let mut quo = vec![BigInt::<N>::zero()];

        let ddeg = divisor.len() - 1;
        let dlead = divisor[ddeg].clone();
        let dlead_inv = dlead.mod_inverse(p)?;

        while rem.len() >= divisor.len() && !Self::poly_is_zero(&rem) {
            let rdeg = rem.len() - 1;
            let rlead = rem[rdeg].clone();
            if rlead.is_zero() {
                rem.pop();
                rem = Self::poly_trim(rem);
                continue;
            }
            let coeff = rlead.mod_mul(&dlead_inv, p);
            let shift = rdeg - ddeg;

            if quo.len() <= shift {
                quo.resize(shift + 1, BigInt::zero());
            }
            quo[shift] = quo[shift].mod_add(&coeff, p);

            for i in 0..=ddeg {
                let prod = divisor[i].mod_mul(&coeff, p);
                rem[i + shift] = rem[i + shift].mod_sub(&prod, p);
            }
            rem = Self::poly_trim(rem);
        }

        Some((Self::poly_trim(quo), rem))
    }

    fn fpk_inverse_elem<const N: usize>(
        a_elem: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Option<Vec<BigInt<N>>> {
        if a_elem.iter().all(|c| c.is_zero()) {
            return None;
        }

        // Build monic modulus_full of degree k
        let modulus_full = if modulus_poly.len() == k + 1 {
            modulus_poly.to_vec()
        } else {
            let mut m = modulus_poly[..k.min(modulus_poly.len())].to_vec();
            m.resize(k, BigInt::zero());
            m.push(BigInt::one());
            m
        };

        let mut old_r = Self::poly_trim(modulus_full.clone());
        let mut r = Self::poly_trim(a_elem.to_vec());

        let mut old_t = vec![BigInt::<N>::zero()];
        let mut t = vec![BigInt::<N>::one()];

        let mut iterations = 0;
        let max_iterations = 10000;

        while !Self::poly_is_zero(&r) && iterations < max_iterations {
            iterations += 1;
            let (q, new_r) = Self::poly_divmod::<N>(&old_r, &r, prime)?;
            old_r = r;
            r = new_r;

            let qt = Self::poly_mul::<N>(&q, &t, prime);
            let qt = Self::poly_mod_monic::<N>(qt, &modulus_full, prime);
            let new_t = Self::poly_sub::<N>(&old_t, &qt, prime);
            old_t = t;
            t = Self::poly_mod_monic::<N>(new_t, &modulus_full, prime);
        }

        if iterations >= max_iterations {
            return None;
        }

        // gcd should be constant
        if old_r.len() != 1 {
            return None;
        }
        let g = &old_r[0];
        if g.is_zero() {
            return None;
        }
        let g_inv = g.mod_inverse(prime)?;

        let mut inv: Vec<BigInt<N>> = old_t.iter().map(|c| c.mod_mul(&g_inv, prime)).collect();

        inv = Self::poly_mod_monic::<N>(inv, &modulus_full, prime);

        // pad to length k
        inv.resize(k, BigInt::zero());
        Some(inv)
    }

    // Type alias for ECPk points: None = infinity, Some((x, y)) = affine point
    // This replaces the old convention of all-zero coords meaning infinity

    fn ecpk_add_opt<const N: usize>(
        p: Option<&(Vec<BigInt<N>>, Vec<BigInt<N>>)>,
        q: Option<&(Vec<BigInt<N>>, Vec<BigInt<N>>)>,
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        match (p, q) {
            (None, None) => None,
            (Some(pt), None) => Some(pt.clone()),
            (None, Some(pt)) => Some(pt.clone()),
            (Some((x1, y1)), Some((x2, y2))) => {
                // Normalize both points to have length k
                let x1_norm: Vec<BigInt<N>> = (0..k)
                    .map(|i| x1.get(i).cloned().unwrap_or_else(BigInt::zero))
                    .collect();
                let y1_norm: Vec<BigInt<N>> = (0..k)
                    .map(|i| y1.get(i).cloned().unwrap_or_else(BigInt::zero))
                    .collect();
                let x2_norm: Vec<BigInt<N>> = (0..k)
                    .map(|i| x2.get(i).cloned().unwrap_or_else(BigInt::zero))
                    .collect();
                let y2_norm: Vec<BigInt<N>> = (0..k)
                    .map(|i| y2.get(i).cloned().unwrap_or_else(BigInt::zero))
                    .collect();

                // Check if P = -Q (return infinity)
                let neg_y2 = Self::fpk_elem_neg::<N>(&y2_norm, prime, k);
                if x1_norm == x2_norm && y1_norm == neg_y2 {
                    return None; // P + (-P) = infinity
                }

                let lambda = if x1_norm == x2_norm && y1_norm == y2_norm {
                    // Point doubling: lambda = (3x1^2 + a) / (2y1)
                    if y1_norm.iter().all(|c| c.is_zero()) {
                        return None; // 2P = infinity when y=0
                    }
                    let three = BigInt::<N>::from_u64(3);
                    let two = BigInt::<N>::from_u64(2);

                    let x1_sq =
                        Self::fpk_elem_mul::<N>(&x1_norm, &x1_norm, modulus_poly, prime, k);
                    let three_x1_sq = Self::fpk_elem_scalar_mul::<N>(&x1_sq, &three, prime, k);
                    let numerator = Self::fpk_elem_add::<N>(&three_x1_sq, a, prime, k);
                    let two_y1 = Self::fpk_elem_scalar_mul::<N>(&y1_norm, &two, prime, k);
                    let denom_inv =
                        Self::fpk_inverse_elem::<N>(&two_y1, modulus_poly, prime, k)?;
                    Self::fpk_elem_mul::<N>(&numerator, &denom_inv, modulus_poly, prime, k)
                } else {
                    // Point addition: lambda = (y2 - y1) / (x2 - x1)
                    let y_diff = Self::fpk_elem_sub::<N>(&y2_norm, &y1_norm, prime, k);
                    let x_diff = Self::fpk_elem_sub::<N>(&x2_norm, &x1_norm, prime, k);
                    let denom_inv =
                        Self::fpk_inverse_elem::<N>(&x_diff, modulus_poly, prime, k)?;
                    Self::fpk_elem_mul::<N>(&y_diff, &denom_inv, modulus_poly, prime, k)
                };

                // x3 = lambda^2 - x1 - x2
                let lambda_sq =
                    Self::fpk_elem_mul::<N>(&lambda, &lambda, modulus_poly, prime, k);
                let temp = Self::fpk_elem_sub::<N>(&lambda_sq, &x1_norm, prime, k);
                let x3 = Self::fpk_elem_sub::<N>(&temp, &x2_norm, prime, k);

                // y3 = lambda * (x1 - x3) - y1
                let x1_minus_x3 = Self::fpk_elem_sub::<N>(&x1_norm, &x3, prime, k);
                let prod =
                    Self::fpk_elem_mul::<N>(&lambda, &x1_minus_x3, modulus_poly, prime, k);
                let y3 = Self::fpk_elem_sub::<N>(&prod, &y1_norm, prime, k);

                Some((x3, y3))
            }
        }
    }

    fn ecpk_scalar_mul_opt<const N: usize>(
        p: Option<&(Vec<BigInt<N>>, Vec<BigInt<N>>)>,
        k_scalar: &BigInt<N>,
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        if k_scalar.is_zero() {
            return None;
        }

        let mut result: Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> = None;
        let mut base = p?.clone();
        let mut scalar = *k_scalar;

        while !scalar.is_zero() {
            if scalar.limbs()[0] & 1 == 1 {
                // result = result + base (ecpk_add_opt handles None correctly now)
                result =
                    Self::ecpk_add_opt::<N>(result.as_ref(), Some(&base), a, modulus_poly, prime, k);
            }
            scalar = scalar >> 1;
            if !scalar.is_zero() {
                // base = 2 * base
                base =
                    Self::ecpk_add_opt::<N>(Some(&base), Some(&base), a, modulus_poly, prime, k)?;
            }
        }

        result
    }

    // Keep legacy ecpk_add for any other code that uses it
    fn ecpk_add<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>),
        q: &(Vec<BigInt<N>>, Vec<BigInt<N>>),
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        let k = modulus_poly.len().saturating_sub(1).max(p.0.len()).max(1);
        Self::ecpk_add_opt::<N>(Some(p), Some(q), a, modulus_poly, prime, k)
    }

    fn ecpk_scalar_mul<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>),
        k_scalar: &BigInt<N>,
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        let k = modulus_poly.len().saturating_sub(1).max(p.0.len()).max(1);
        Self::ecpk_scalar_mul_opt::<N>(Some(p), k_scalar, a, modulus_poly, prime, k)
    }
}

impl Default for SubmitChallengeRunner {
    fn default() -> Self {
        Self::new()
    }
}
