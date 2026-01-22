//! Submit challenge runner for the crypto25.random-oracle.xyz service
//!
//! This module handles the /submit/start and /submit/finish flow for all challenge types.

use sha2::{Digest, Sha256};

use crate::bigint::BigInt;
use crate::montgomery::MontgomeryCtx;

use super::client::CryptoApiClient;
use super::error::ApiError;
use super::helpers::{
    BIGINT_LIMBS, bigint_to_naf, bigint_to_padded_hex, bytes_to_hex, generate_random_bigint, hash_to_scalar,
    hex_to_bytes, select_limbs_from_bits, write_quoted_bigint_to_buffer, write_ec_point_to_buffer,
    write_ext_field_to_buffer, write_ec_ext_point_to_buffer,
};
use super::types::*;

/// Detailed timing breakdown for a submit attempt
#[derive(Debug, Clone, Default)]
pub struct TimingInfo {
    /// Time spent on cryptographic computation only (parsing, signature verification, key generation, etc.)
    pub t_compute: f64,
    /// Time spent on network I/O (HTTP requests only)
    pub t_network: f64,
    /// Total wall-clock time for the entire attempt
    pub t_total: f64,
}

impl TimingInfo {
    pub fn new(t_compute: f64, t_network: f64, t_total: f64) -> Self {
        Self {
            t_compute,
            t_network,
            t_total,
        }
    }

    /// Returns overhead time (total - compute - network), which includes I/O, serialization, etc.
    pub fn t_overhead(&self) -> f64 {
        (self.t_total - self.t_compute - self.t_network).max(0.0)
    }
}

impl std::fmt::Display for TimingInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "total={:.3}s (compute={:.3}s, network={:.3}s, overhead={:.3}s)",
            self.t_total,
            self.t_compute,
            self.t_network,
            self.t_overhead()
        )
    }
}

/// Result of a submit challenge attempt
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub challenge_type: ChallengeType,
    pub success: bool,
    pub session_id: Option<String>,
    pub error: Option<String>,
    pub poisoned: bool,
    /// Legacy field for backwards compatibility - use timing for detailed breakdown
    pub attempt_time: Option<f64>,
    /// Detailed timing breakdown
    pub timing: Option<TimingInfo>,
    /// Challenge parameters info (printed on success)
    pub params_info: Option<String>,
}

impl SubmitResult {
    pub fn success(challenge_type: ChallengeType, session_id: String, timing: TimingInfo, params_info: String) -> Self {
        Self {
            challenge_type,
            success: true,
            session_id: Some(session_id),
            error: None,
            poisoned: false,
            attempt_time: Some(timing.t_total),
            timing: Some(timing),
            params_info: Some(params_info),
        }
    }

    pub fn poisoned(challenge_type: ChallengeType, session_id: String, timing: TimingInfo) -> Self {
        Self {
            challenge_type,
            success: false,
            session_id: Some(session_id),
            error: Some("Poisoned session - signature verification failed".to_string()),
            poisoned: true,
            attempt_time: Some(timing.t_total),
            timing: Some(timing),
            params_info: None,
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
            timing: None,
            params_info: None,
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
                    if let Some(ref params) = r.params_info {
                        println!("      ✓ {}", params);
                    }
                    if let Some(ref timing) = r.timing {
                        println!("      ✓ Success! ({})", timing);
                    } else {
                        println!("      ✓ Success!");
                    }
                    return r.clone();
                }
                Ok(r) if r.poisoned => {
                    if let Some(ref timing) = r.timing {
                        println!("      ✗ Poisoned session ({}), retrying...", timing);
                    } else {
                        println!("      ✗ Poisoned session, retrying...");
                    }
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

    /// Run N successful attempts and return the fastest one
    /// This is for finding the best possible time across many runs
    pub fn run_submit_best_of(&self, challenge_type: ChallengeType, num_successes: usize) -> SubmitResult {
        let mut best_result: Option<SubmitResult> = None;
        let mut success_count = 0;
        let mut attempt = 0;
        let max_total_attempts = num_successes * 5; // Allow up to 5x attempts to handle poisoned sessions

        while success_count < num_successes && attempt < max_total_attempts {
            attempt += 1;
            println!(
                "    Attempt {} (success {}/{}) for {:?}...",
                attempt,
                success_count,
                num_successes,
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
                    success_count += 1;
                    let time = r.attempt_time.unwrap_or(f64::MAX);
                    
                    if let Some(ref params) = r.params_info {
                        println!("      ✓ {}", params);
                    }
                    if let Some(ref timing) = r.timing {
                        println!("      ✓ Success! ({})", timing);
                    }

                    // Check if this is the best so far
                    let is_best = match &best_result {
                        None => true,
                        Some(best) => time < best.attempt_time.unwrap_or(f64::MAX),
                    };

                    if is_best {
                        if best_result.is_some() {
                            println!("      ⚡ New best time!");
                        }
                        best_result = Some(r.clone());
                    }
                }
                Ok(r) if r.poisoned => {
                    if let Some(ref timing) = r.timing {
                        println!("      ✗ Poisoned session ({}), retrying...", timing);
                    } else {
                        println!("      ✗ Poisoned session, retrying...");
                    }
                }
                Ok(r) => {
                    println!("      ✗ Submission failed: {:?}", r.error);
                }
                Err(e) => {
                    println!("      ✗ Error: {}", e);
                }
            }
        }

        if let Some(best) = best_result {
            println!(
                "    Best of {} successes: {:.3}s",
                success_count,
                best.attempt_time.unwrap_or(0.0)
            );
            best
        } else {
            SubmitResult::failed(
                challenge_type,
                format!(
                    "Failed to get any successful attempts after {} tries",
                    attempt
                ),
            )
        }
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
        let mut t_network = 0.0;
        let mut t_compute = 0.0;

        // --- Network: submit_start ---
        let network_start = Instant::now();
        let start = self.client.submit_start(ChallengeType::Modp)?;
        t_network += network_start.elapsed().as_secs_f64();

        let session_id = start.session_id.clone();

        // --- Compute: Parse and verify ---
        let compute_start = Instant::now();

        // Parse params
        let params: ModPParams = serde_json::from_value(start.params)?;
        let params_info = format!("{} ({}b modulus)", params.name, params.modulus.len() * 4);
        let order = BigInt::<N>::from_hex(&params.order);
        let generator = BigInt::<N>::from_hex(&params.generator);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let ctx = MontgomeryCtx::<N>::new(modulus).expect("odd modulus required");
        let modulus = &ctx.modulus;
        let modulus_byte_len = modulus.bit_length().div_ceil(8);

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

        // Verify server signature on server_public_dh
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        // R' = g^s * y^e mod p
        let g_s = ctx.mod_pow_noreduce(&generator, &s);
        let y_e = ctx.mod_pow_noreduce(&server_public_sign, &e_scalar);
        let r_prime = ctx.mod_mul_noreduce(&g_s, &y_e);

        // e' = H(R' || message) - use efficient buffer construction
        let mut hash_buf = Vec::with_capacity(modulus_byte_len * 4 + 8);
        write_quoted_bigint_to_buffer(&mut hash_buf, &r_prime, modulus_byte_len);
        write_quoted_bigint_to_buffer(&mut hash_buf, &server_public_dh, modulus_byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            t_compute += compute_start.elapsed().as_secs_f64();
            let t_total = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Modp,
                session_id,
                TimingInfo::new(t_compute, t_network, t_total),
            ));
        }

        // Generate our keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = ctx.mod_pow_noreduce(&generator, &dh_private);

        let sign_private = generate_random_bigint(&order);
        let sign_public = ctx.mod_pow_noreduce(&generator, &sign_private);

        // Sign our DH public key - use efficient buffer construction
        let k = generate_random_bigint(&order);
        let r = ctx.mod_pow_noreduce(&generator, &k);
        
        hash_buf.clear();
        write_quoted_bigint_to_buffer(&mut hash_buf, &r, modulus_byte_len);
        write_quoted_bigint_to_buffer(&mut hash_buf, &dh_public, modulus_byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        // s = k - e*x mod order (computed as (k - e*x) mod order)
        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = k.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret = ctx.mod_pow_noreduce(&server_public_dh, &dh_private);

        // Prepare request data
        let sign_public_hex = bigint_to_padded_hex(&sign_public, modulus_byte_len);
        let dh_public_hex = bigint_to_padded_hex(&dh_public, modulus_byte_len);
        let s_sig_hex = bigint_to_padded_hex(&s_sig, order.bit_length().div_ceil(8));
        let e_hex = bytes_to_hex(e_hash.as_slice());
        let shared_secret_hex = bigint_to_padded_hex(&shared_secret, modulus_byte_len);

        t_compute += compute_start.elapsed().as_secs_f64();
        // --- End Compute ---

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

        // --- Network: submit_finish ---
        let network_start = Instant::now();
        let response = self.client.submit_finish(request)?;
        t_network += network_start.elapsed().as_secs_f64();

        let t_total = attempt_start.elapsed().as_secs_f64();
        let timing = TimingInfo::new(t_compute, t_network, t_total);

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Modp,
                session_id,
                timing,
                params_info,
            ))
        } else {
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
        use std::time::Instant;
        // First, peek at params to get m
        let network_start = Instant::now();
        let start = self.client.submit_start(ChallengeType::F2m)?;
        let t_network_start = network_start.elapsed().as_secs_f64();

        let params: F2mParams = serde_json::from_value(start.params.clone())?;
        let m = params.extension;

        // Need N*64 > m (strictly greater) to access bit m
        let required_bits = m + 1;
        let limbs = select_limbs_from_bits(required_bits);

        match limbs {
            32 => {
                if 32 * 64 > m {
                    self.submit_f2m_with_limbs::<32>(start, t_network_start)
                } else {
                    self.submit_f2m_with_limbs::<{ BIGINT_LIMBS }>(start, t_network_start)
                }
            }
            _ => self.submit_f2m_with_limbs::<{ BIGINT_LIMBS }>(start, t_network_start),
        }
    }

    fn submit_f2m_with_limbs<const N: usize>(
        &self,
        start: SubmitStartResponse,
        t_network_start: f64,
    ) -> Result<SubmitResult, ApiError> {
        use std::time::Instant;
        let attempt_start = Instant::now();
        let mut t_network = t_network_start;

        // --- Compute: Parse and verify ---
        let compute_start = Instant::now();

        let session_id = start.session_id.clone();

        let params: F2mParams = serde_json::from_value(start.params)?;
        let m = params.extension;
        let params_info = format!("{} (m={})", params.name, m);

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

        // Verify signature using efficient buffer construction
        let mut hash_buf = Vec::with_capacity(byte_len * 4 + 8);
        write_quoted_bigint_to_buffer(&mut hash_buf, &r_prime, byte_len);
        write_quoted_bigint_to_buffer(&mut hash_buf, &server_public_dh, byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            let t_compute = compute_start.elapsed().as_secs_f64();
            let t_total = attempt_start.elapsed().as_secs_f64() + t_network_start;
            return Ok(SubmitResult::poisoned(
                ChallengeType::F2m,
                session_id,
                TimingInfo::new(t_compute, t_network, t_total),
            ));
        }

        // Generate keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::f2m_pow::<N>(&generator, &dh_private, &modulus, m);

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::f2m_pow::<N>(&generator, &sign_private, &modulus, m);

        // Sign DH public key - reuse buffer
        let k = generate_random_bigint(&order);
        let r = Self::f2m_pow::<N>(&generator, &k, &modulus, m);
        
        hash_buf.clear();
        write_quoted_bigint_to_buffer(&mut hash_buf, &r, byte_len);
        write_quoted_bigint_to_buffer(&mut hash_buf, &dh_public, byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = k.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret = Self::f2m_pow::<N>(&server_public_dh, &dh_private, &modulus, m);

        let order_byte_len = order.bit_length().div_ceil(8);
        let t_compute = compute_start.elapsed().as_secs_f64();
        // --- End Compute ---

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

        // --- Network: submit_finish ---
        let network_start = Instant::now();
        let response = self.client.submit_finish(request)?;
        t_network += network_start.elapsed().as_secs_f64();

        let t_total = attempt_start.elapsed().as_secs_f64() + t_network_start;
        let timing = TimingInfo::new(t_compute, t_network, t_total);

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::F2m,
                session_id,
                timing,
                params_info,
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
        let mut t_network = 0.0;

        // --- Network: submit_start ---
        let network_start = Instant::now();
        let start = self.client.submit_start(ChallengeType::Fpk)?;
        t_network += network_start.elapsed().as_secs_f64();

        let session_id = start.session_id.clone();

        // --- Compute: Parse and verify ---
        let compute_start = Instant::now();

        let params: FpkParams = serde_json::from_value(start.params)?;
        let params_info = format!("{} (p={}b, k={})", params.name, params.prime_base.len() * 4, params.extension);
        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let order = BigInt::<N>::from_hex(&params.order);
        let ext_degree = params.extension;
        let prime_byte_len = prime.bit_length().div_ceil(8);

        // Create Montgomery context once for all extension field operations
        let ctx = MontgomeryCtx::<N>::new(prime).ok_or_else(|| {
            ApiError::Validation("Invalid prime for Montgomery".to_string())
        })?;

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

        // Verify server signature using Montgomery-accelerated operations
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        let g_s = Self::fpk_pow_mont::<N>(&generator, &s, &modulus_poly, &ctx);
        let y_e = Self::fpk_pow_mont::<N>(&server_public_sign, &e_scalar, &modulus_poly, &ctx);
        let r_prime = Self::fpk_mul_mont::<N>(&g_s, &y_e, &modulus_poly, &ctx);

        // Verify signature using efficient buffer construction
        let mut hash_buf = Vec::with_capacity(prime_byte_len * ext_degree * 4 + 16);
        write_ext_field_to_buffer(&mut hash_buf, &r_prime, prime_byte_len);
        write_ext_field_to_buffer(&mut hash_buf, &server_public_dh, prime_byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            let t_compute = compute_start.elapsed().as_secs_f64();
            let t_total = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Fpk,
                session_id,
                TimingInfo::new(t_compute, t_network, t_total),
            ));
        }

        // Generate keypairs using Montgomery-accelerated operations
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::fpk_pow_mont::<N>(&generator, &dh_private, &modulus_poly, &ctx);

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::fpk_pow_mont::<N>(&generator, &sign_private, &modulus_poly, &ctx);

        // Sign DH public key - reuse buffer
        let nonce = generate_random_bigint(&order);
        let r = Self::fpk_pow_mont::<N>(&generator, &nonce, &modulus_poly, &ctx);
        
        hash_buf.clear();
        write_ext_field_to_buffer(&mut hash_buf, &r, prime_byte_len);
        write_ext_field_to_buffer(&mut hash_buf, &dh_public, prime_byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
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

        let t_compute = compute_start.elapsed().as_secs_f64();
        // --- End Compute ---

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

        // --- Network: submit_finish ---
        let network_start = Instant::now();
        let response = self.client.submit_finish(request)?;
        t_network += network_start.elapsed().as_secs_f64();

        let t_total = attempt_start.elapsed().as_secs_f64();
        let timing = TimingInfo::new(t_compute, t_network, t_total);

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Fpk,
                session_id,
                timing,
                params_info,
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
        let mut t_network = 0.0;
        let mut t_compute = 0.0;

        // --- Network: submit_start ---
        let network_start = Instant::now();
        let start = self.client.submit_start(ChallengeType::Ecp)?;
        t_network += network_start.elapsed().as_secs_f64();

        let session_id = start.session_id.clone();

        // --- Compute: Parse and verify ---
        let compute_start = Instant::now();

        let params: ECPParams = serde_json::from_value(start.params)?;
        let params_info = format!("{} ({}b curve)", params.name, params.modulus.len() * 4);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let order = BigInt::<N>::from_hex(&params.order);
        let a = BigInt::<N>::from_hex(&params.a);
        let gx = BigInt::<N>::from_hex(&params.generator.x);
        let gy = BigInt::<N>::from_hex(&params.generator.y);
        let byte_len = modulus.bit_length().div_ceil(8);

        // Create Montgomery context once for all operations
        let ctx = match MontgomeryCtx::<N>::new(modulus) {
            Some(c) => c,
            None => {
                t_compute += compute_start.elapsed().as_secs_f64();
                let t_total = attempt_start.elapsed().as_secs_f64();
                return Ok(SubmitResult::poisoned(
                    ChallengeType::Ecp,
                    session_id,
                    TimingInfo::new(t_compute, t_network, t_total),
                ));
            }
        };

        // Convert curve parameter 'a' and generator to Montgomery domain once
        let a_mont = ctx.to_mont_noreduce(&a);
        let gen_mont = (ctx.to_mont_noreduce(&gx), ctx.to_mont_noreduce(&gy));

        // Parse server public keys
        let server_sign_obj = start
            .server_public_sign
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_sign".to_string()))?;
        let server_sign_x =
            BigInt::<N>::from_hex(server_sign_obj.get("x").unwrap().as_str().unwrap());
        let server_sign_y =
            BigInt::<N>::from_hex(server_sign_obj.get("y").unwrap().as_str().unwrap());
        let server_sign_mont = (ctx.to_mont_noreduce(&server_sign_x), ctx.to_mont_noreduce(&server_sign_y));

        let server_dh_obj = start
            .server_public_dh
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid server_public_dh".to_string()))?;
        let server_dh_x = BigInt::<N>::from_hex(server_dh_obj.get("x").unwrap().as_str().unwrap());
        let server_dh_y = BigInt::<N>::from_hex(server_dh_obj.get("y").unwrap().as_str().unwrap());
        let server_dh_mont = (ctx.to_mont_noreduce(&server_dh_x), ctx.to_mont_noreduce(&server_dh_y));

        // Verify server signature
        let sig = &start.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        
        let g_s = Self::ecp_scalar_mul_mont::<N>(&gen_mont, &s, &a_mont, &ctx);
        let y_e = Self::ecp_scalar_mul_mont::<N>(&server_sign_mont, &e_scalar, &a_mont, &ctx);

        // Compute r_prime for signature verification using Jacobian addition
        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecp_add_mont::<N>(&gs, &ye, &a_mont, &ctx),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        };

        let r_prime = match r_prime {
            Some(r) => r,
            None => {
                t_compute += compute_start.elapsed().as_secs_f64();
                let t_total = attempt_start.elapsed().as_secs_f64();
                return Ok(SubmitResult::poisoned(
                    ChallengeType::Ecp,
                    session_id,
                    TimingInfo::new(t_compute, t_network, t_total),
                ));
            }
        };

        // Verify signature using efficient buffer construction
        let mut hash_buf = Vec::with_capacity(byte_len * 8 + 32);
        write_ec_point_to_buffer(&mut hash_buf, &r_prime.0, &r_prime.1, byte_len);
        write_ec_point_to_buffer(&mut hash_buf, &server_dh_x, &server_dh_y, byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            t_compute += compute_start.elapsed().as_secs_f64();
            let t_total = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Ecp,
                session_id,
                TimingInfo::new(t_compute, t_network, t_total),
            ));
        }

        // Generate keypairs
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::ecp_scalar_mul_mont::<N>(&gen_mont, &dh_private, &a_mont, &ctx)
            .ok_or_else(|| ApiError::Validation("Failed to compute DH public key".to_string()))?;

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::ecp_scalar_mul_mont::<N>(&gen_mont, &sign_private, &a_mont, &ctx)
            .ok_or_else(|| ApiError::Validation("Failed to compute sign public key".to_string()))?;

        // Sign DH public key - reuse buffer
        let nonce = generate_random_bigint(&order);
        let r = Self::ecp_scalar_mul_mont::<N>(&gen_mont, &nonce, &a_mont, &ctx)
            .ok_or_else(|| ApiError::Validation("Failed to compute R".to_string()))?;

        hash_buf.clear();
        write_ec_point_to_buffer(&mut hash_buf, &r.0, &r.1, byte_len);
        write_ec_point_to_buffer(&mut hash_buf, &dh_public.0, &dh_public.1, byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = nonce.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret = Self::ecp_scalar_mul_mont::<N>(&server_dh_mont, &dh_private, &a_mont, &ctx)
            .ok_or_else(|| ApiError::Validation("Failed to compute shared secret".to_string()))?;

        let order_byte_len = order.bit_length().div_ceil(8);

        t_compute += compute_start.elapsed().as_secs_f64();
        // --- End Compute ---

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

        // --- Network: submit_finish ---
        let network_start = Instant::now();
        let response = self.client.submit_finish(request)?;
        t_network += network_start.elapsed().as_secs_f64();

        let t_total = attempt_start.elapsed().as_secs_f64();
        let timing = TimingInfo::new(t_compute, t_network, t_total);

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Ecp,
                session_id,
                timing,
                params_info,
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
        let mut t_network = 0.0;
        let mut t_compute = 0.0;

        // --- Network: submit_start ---
        let network_start = Instant::now();
        let start = self.client.submit_start(ChallengeType::Ec2m)?;
        t_network += network_start.elapsed().as_secs_f64();

        let session_id = start.session_id.clone();

        // --- Compute: Parse and verify ---
        let compute_start = Instant::now();

        let params: EC2mParams = serde_json::from_value(start.params)?;
        let m = params.extension;
        let params_info = format!("{} (m={})", params.name, m);
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
                t_compute += compute_start.elapsed().as_secs_f64();
                let t_total = attempt_start.elapsed().as_secs_f64();
                return Ok(SubmitResult::poisoned(
                    ChallengeType::Ec2m,
                    session_id,
                    TimingInfo::new(t_compute, t_network, t_total),
                ));
            }
        };

        // Verify signature using efficient buffer construction
        let mut hash_buf = Vec::with_capacity(byte_len * 8 + 32);
        write_ec_point_to_buffer(&mut hash_buf, &r_prime.0, &r_prime.1, byte_len);
        write_ec_point_to_buffer(&mut hash_buf, &server_public_dh.0, &server_public_dh.1, byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            t_compute += compute_start.elapsed().as_secs_f64();
            let t_total = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Ec2m,
                session_id,
                TimingInfo::new(t_compute, t_network, t_total),
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

        // Sign DH public key - reuse buffer
        let k = generate_random_bigint(&order);
        let r = Self::ec2m_scalar_mul::<N>(&generator, &k, &a, &red_poly, m)
            .ok_or_else(|| ApiError::Validation("Failed to compute R".to_string()))?;

        hash_buf.clear();
        write_ec_point_to_buffer(&mut hash_buf, &r.0, &r.1, byte_len);
        write_ec_point_to_buffer(&mut hash_buf, &dh_public.0, &dh_public.1, byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
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

        t_compute += compute_start.elapsed().as_secs_f64();
        // --- End Compute ---

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

        // --- Network: submit_finish ---
        let network_start = Instant::now();
        let response = self.client.submit_finish(request)?;
        t_network += network_start.elapsed().as_secs_f64();

        let t_total = attempt_start.elapsed().as_secs_f64();
        let timing = TimingInfo::new(t_compute, t_network, t_total);

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Ec2m,
                session_id,
                timing,
                params_info,
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
        let mut t_network = 0.0;
        let mut t_compute = 0.0;

        // --- Network: submit_start ---
        let network_start = Instant::now();
        let start = self.client.submit_start(ChallengeType::Ecpk)?;
        t_network += network_start.elapsed().as_secs_f64();

        let session_id = start.session_id.clone();

        // --- Compute: Parse and verify ---
        let compute_start = Instant::now();

        let params: ECPkParams = serde_json::from_value(start.params)?;
        let params_info = format!("{} (p={}b, k={})", params.name, params.prime_base.len() * 4, params.extension);
        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let order = BigInt::<N>::from_hex(&params.order);
        let ext_k = params.extension;
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

        // Verify server signature (using original non-Montgomery functions for now)
        let sig = &start.signature;
        let s_scalar = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        let g_s = Self::ecpk_scalar_mul::<N>(&generator, &s_scalar, &a_coeffs, &modulus_poly, &prime);
        let y_e = Self::ecpk_scalar_mul::<N>(&server_public_sign, &e_scalar, &a_coeffs, &modulus_poly, &prime);

        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecpk_add::<N>(&gs, &ye, &a_coeffs, &modulus_poly, &prime),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        };

        let r_prime = match r_prime {
            Some(r) => r,
            None => {
                t_compute += compute_start.elapsed().as_secs_f64();
                let t_total = attempt_start.elapsed().as_secs_f64();
                return Ok(SubmitResult::poisoned(
                    ChallengeType::Ecpk,
                    session_id,
                    TimingInfo::new(t_compute, t_network, t_total),
                ));
            }
        };

        // Verify signature using efficient buffer construction
        let mut hash_buf = Vec::with_capacity(prime_byte_len * ext_k * 8 + 32);
        write_ec_ext_point_to_buffer(&mut hash_buf, &r_prime.0, &r_prime.1, prime_byte_len);
        write_ec_ext_point_to_buffer(&mut hash_buf, &server_public_dh.0, &server_public_dh.1, prime_byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_prime = hasher.finalize();

        if e_prime.as_slice() != e_bytes.as_slice() {
            t_compute += compute_start.elapsed().as_secs_f64();
            let t_total = attempt_start.elapsed().as_secs_f64();
            return Ok(SubmitResult::poisoned(
                ChallengeType::Ecpk,
                session_id,
                TimingInfo::new(t_compute, t_network, t_total),
            ));
        }

        // Generate keypairs (using original non-Montgomery functions for now)
        let dh_private = generate_random_bigint(&order);
        let dh_public = Self::ecpk_scalar_mul::<N>(&generator, &dh_private, &a_coeffs, &modulus_poly, &prime)
            .ok_or_else(|| ApiError::Validation("Failed to compute DH public key".to_string()))?;

        let sign_private = generate_random_bigint(&order);
        let sign_public = Self::ecpk_scalar_mul::<N>(&generator, &sign_private, &a_coeffs, &modulus_poly, &prime)
            .ok_or_else(|| ApiError::Validation("Failed to compute sign public key".to_string()))?;

        // Sign DH public key
        let nonce = generate_random_bigint(&order);
        let r = Self::ecpk_scalar_mul::<N>(&generator, &nonce, &a_coeffs, &modulus_poly, &prime)
            .ok_or_else(|| ApiError::Validation("Failed to compute R".to_string()))?;

        hash_buf.clear();
        write_ec_ext_point_to_buffer(&mut hash_buf, &r.0, &r.1, prime_byte_len);
        write_ec_ext_point_to_buffer(&mut hash_buf, &dh_public.0, &dh_public.1, prime_byte_len);

        let mut hasher = Sha256::new();
        hasher.update(&hash_buf);
        let e_hash = hasher.finalize();
        let e_scalar_ours = hash_to_scalar(e_hash.as_slice(), &order);

        let ex = e_scalar_ours.mod_mul(&sign_private, &order);
        let s_sig = nonce.mod_sub(&ex, &order);

        // Compute shared secret
        let shared_secret = Self::ecpk_scalar_mul::<N>(&server_public_dh, &dh_private, &a_coeffs, &modulus_poly, &prime)
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

        t_compute += compute_start.elapsed().as_secs_f64();
        // --- End Compute ---

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

        // --- Network: submit_finish ---
        let network_start = Instant::now();
        let response = self.client.submit_finish(request)?;
        t_network += network_start.elapsed().as_secs_f64();

        let t_total = attempt_start.elapsed().as_secs_f64();
        let timing = TimingInfo::new(t_compute, t_network, t_total);

        if response.status == "success" {
            Ok(SubmitResult::success(
                ChallengeType::Ecpk,
                session_id,
                timing,
                params_info,
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

    // ========================================================================
    // Optimized Extension Field Operations with Stack Allocation
    // Maximum supported extension degree is 16 (covers all practical cases)
    // ========================================================================
    const MAX_EXT_K: usize = 16;

    /// Multiply two extension field elements using Montgomery multiplication
    /// Avoids allocation by using stack arrays
    #[inline]
    fn fpk_mul_into_mont<const N: usize>(
        result: &mut [BigInt<N>],
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        ctx: &MontgomeryCtx<N>,
        k: usize,
    ) {
        debug_assert!(k <= Self::MAX_EXT_K);
        let prime = &ctx.modulus;
        
        // Stack-allocated product buffer (2k-1 coefficients needed)
        let mut product = [BigInt::<N>::zero(); 31]; // 2*16-1 = 31 max
        
        // Schoolbook multiplication using Montgomery
        for i in 0..k {
            if a[i].is_zero() {
                continue;
            }
            for j in 0..k {
                if b[j].is_zero() {
                    continue;
                }
                let term = ctx.mod_mul_noreduce(&a[i], &b[j]);
                product[i + j] = product[i + j].mod_add(&term, prime);
            }
        }

        // Reduce by modulus polynomial
        for i in (k..(2 * k - 1)).rev() {
            let coeff = product[i];
            if !coeff.is_zero() {
                for j in 0..k {
                    let sub_term = ctx.mod_mul_noreduce(&coeff, &modulus_poly[j]);
                    product[i - k + j] = product[i - k + j].mod_sub(&sub_term, prime);
                }
            }
        }

        // Copy result
        result[..k].copy_from_slice(&product[..k]);
    }

    /// Extension field exponentiation using Montgomery multiplication
    #[inline]
    fn fpk_pow_fast_mont<const N: usize>(
        base: &[BigInt<N>],
        exp: &BigInt<N>,
        modulus_poly: &[BigInt<N>],
        ctx: &MontgomeryCtx<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert!(k <= Self::MAX_EXT_K);

        if exp.is_zero() {
            let mut one = vec![BigInt::<N>::zero(); k];
            one[0] = BigInt::one();
            return one;
        }

        // Stack-allocated working buffers
        let mut result_buf = [BigInt::<N>::zero(); 16];
        let mut base_buf = [BigInt::<N>::zero(); 16];
        let mut temp_buf = [BigInt::<N>::zero(); 16];
        
        // Initialize result = 1 (in extension field)
        result_buf[0] = BigInt::one();
        
        // Copy base
        for (i, buf_elem) in base_buf.iter_mut().enumerate().take(k) {
            *buf_elem = base.get(i).copied().unwrap_or_else(BigInt::zero);
        }

        let mut exp_val = *exp;

        while !exp_val.is_zero() {
            if exp_val.limbs()[0] & 1 == 1 {
                // result = result * base
                Self::fpk_mul_into_mont::<N>(&mut temp_buf, &result_buf[..k], &base_buf[..k], modulus_poly, ctx, k);
                result_buf[..k].copy_from_slice(&temp_buf[..k]);
            }
            exp_val = exp_val >> 1;
            if !exp_val.is_zero() {
                // base = base * base (squaring)
                Self::fpk_mul_into_mont::<N>(&mut temp_buf, &base_buf[..k], &base_buf[..k], modulus_poly, ctx, k);
                base_buf[..k].copy_from_slice(&temp_buf[..k]);
            }
        }

        result_buf[..k].to_vec()
    }

    /// Montgomery-accelerated extension field multiplication
    fn fpk_mul_mont<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        ctx: &MontgomeryCtx<N>,
    ) -> Vec<BigInt<N>> {
        let k = a.len();
        let mut result = [BigInt::<N>::zero(); Self::MAX_EXT_K];
        Self::fpk_mul_into_mont::<N>(&mut result, a, b, modulus_poly, ctx, k);
        result[..k].to_vec()
    }

    /// Montgomery-accelerated extension field exponentiation
    fn fpk_pow_mont<const N: usize>(
        base: &[BigInt<N>],
        exp: &BigInt<N>,
        modulus_poly: &[BigInt<N>],
        ctx: &MontgomeryCtx<N>,
    ) -> Vec<BigInt<N>> {
        let k = base.len();
        Self::fpk_pow_fast_mont::<N>(base, exp, modulus_poly, ctx, k)
    }

    /// Multiply two extension field elements in-place into result buffer
    /// Avoids allocation by using stack arrays
    #[inline]
    fn fpk_mul_into<const N: usize>(
        result: &mut [BigInt<N>],
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) {
        debug_assert!(k <= Self::MAX_EXT_K);
        
        // Stack-allocated product buffer (2k-1 coefficients needed)
        let mut product = [BigInt::<N>::zero(); 31]; // 2*16-1 = 31 max
        
        // Schoolbook multiplication
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

        // Reduce by modulus polynomial
        for i in (k..(2 * k - 1)).rev() {
            let coeff = product[i];
            if !coeff.is_zero() {
                for j in 0..k {
                    let sub_term = coeff.mod_mul(&modulus_poly[j], prime);
                    product[i - k + j] = product[i - k + j].mod_sub(&sub_term, prime);
                }
            }
        }

        // Copy result
        result[..k].copy_from_slice(&product[..k]);
    }

    /// Extension field exponentiation with reusable buffers
    #[inline]
    fn fpk_pow_fast<const N: usize>(
        base: &[BigInt<N>],
        exp: &BigInt<N>,
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert!(k <= Self::MAX_EXT_K);

        if exp.is_zero() {
            let mut one = vec![BigInt::<N>::zero(); k];
            one[0] = BigInt::one();
            return one;
        }

        // Stack-allocated working buffers
        let mut result_buf = [BigInt::<N>::zero(); 16];
        let mut base_buf = [BigInt::<N>::zero(); 16];
        let mut temp_buf = [BigInt::<N>::zero(); 16];
        
        // Initialize result = 1 (in extension field)
        result_buf[0] = BigInt::one();
        
        // Copy base
        for (i, buf_elem) in base_buf.iter_mut().enumerate().take(k) {
            *buf_elem = base.get(i).copied().unwrap_or_else(BigInt::zero);
        }

        let mut exp_val = *exp;

        while !exp_val.is_zero() {
            if exp_val.limbs()[0] & 1 == 1 {
                // result = result * base
                Self::fpk_mul_into::<N>(&mut temp_buf, &result_buf[..k], &base_buf[..k], modulus_poly, prime, k);
                result_buf[..k].copy_from_slice(&temp_buf[..k]);
            }
            exp_val = exp_val >> 1;
            if !exp_val.is_zero() {
                // base = base * base (squaring)
                Self::fpk_mul_into::<N>(&mut temp_buf, &base_buf[..k], &base_buf[..k], modulus_poly, prime, k);
                base_buf[..k].copy_from_slice(&temp_buf[..k]);
            }
        }

        result_buf[..k].to_vec()
    }

    fn fpk_pow<const N: usize>(
        base: &[BigInt<N>],
        exp: &BigInt<N>,
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        let k = base.len();

        // Delegate to stack-allocated version
        let result_arr = Self::fpk_pow_fast::<N>(base, exp, modulus_poly, prime, k);
        result_arr[..k].to_vec()
    }

    /// Compute modular inverse using Fermat's Little Theorem: a^{-1} = a^{p-2} mod p
    /// Uses Montgomery exponentiation for speed. Only works for prime modulus!
    fn mod_inverse<const N: usize>(a: &BigInt<N>, prime: &BigInt<N>) -> Option<BigInt<N>> {
        if a.is_zero() {
            return None;
        }
        // For prime p: a^{-1} = a^{p-2} mod p (Fermat's Little Theorem)
        let ctx = MontgomeryCtx::new(*prime)?;
        let p_minus_2 = prime.sub_with_borrow(&BigInt::<N>::from_u64(2)).0;
        Some(ctx.mod_pow(a, &p_minus_2))
    }

    // ========================================================================
    // ECP Montgomery-Jacobian Coordinate Operations
    // All coordinates stored in Montgomery domain for fast multiplication.
    // Jacobian: (X, Y, Z) representing affine (X/Z², Y/Z³)
    // Point at infinity: Z = 0
    // ========================================================================

    /// Convert Jacobian point (in Montgomery domain) back to affine (standard domain)
    /// Returns None for point at infinity (Z = 0)
    fn ecp_jacobian_to_affine_mont<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        ctx: &MontgomeryCtx<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        let (x, y, z) = p;
        if z.is_zero() {
            return None; // Point at infinity
        }

        // Convert Z from Montgomery to standard for inversion
        let z_std = ctx.from_mont(z);
        let z_inv = Self::mod_inverse(&z_std, &ctx.modulus)?;
        // Convert z_inv back to Montgomery domain
        let z_inv_mont = ctx.to_mont_noreduce(&z_inv);

        // Compute z_inv² and z_inv³ in Montgomery domain
        let z_inv_sq = ctx.mont_mul(&z_inv_mont, &z_inv_mont);
        let z_inv_cu = ctx.mont_mul(&z_inv_sq, &z_inv_mont);

        // x_affine = X * z_inv², y_affine = Y * z_inv³ (all in Montgomery)
        let x_affine_mont = ctx.mont_mul(x, &z_inv_sq);
        let y_affine_mont = ctx.mont_mul(y, &z_inv_cu);

        // Convert back to standard domain for output
        Some((ctx.from_mont(&x_affine_mont), ctx.from_mont(&y_affine_mont)))
    }

    /// Jacobian point doubling in Montgomery domain: 2P
    /// Formula: S = 4*X*Y², M = 3*X² + a*Z⁴, X' = M² - 2*S, Y' = M*(S-X') - 8*Y⁴, Z' = 2*Y*Z
    /// All inputs/outputs in Montgomery domain
    fn ecp_jacobian_double_mont<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        a_mont: &BigInt<N>, // 'a' in Montgomery domain
        ctx: &MontgomeryCtx<N>,
    ) -> (BigInt<N>, BigInt<N>, BigInt<N>) {
        let (x, y, z) = p;
        let modulus = &ctx.modulus;

        // Point at infinity (Z = 0 in Montgomery is still 0)
        if z.is_zero() {
            return (BigInt::<N>::zero(), ctx.one_mont_fast(), BigInt::<N>::zero());
        }

        // Y = 0 case (Y = 0 in Montgomery is still 0)
        if y.is_zero() {
            return (BigInt::<N>::zero(), ctx.one_mont_fast(), BigInt::<N>::zero());
        }

        // All multiplications use mont_mul, additions use mod_add/mod_sub
        // Y² and Y⁴
        let y_sq = ctx.mont_mul(y, y);
        let y_4 = ctx.mont_mul(&y_sq, &y_sq);

        // S = 4*X*Y² = 2*(2*X*Y²) using additions for small multipliers
        let xy_sq = ctx.mont_mul(x, &y_sq);
        let two_xy_sq = xy_sq.mod_add(&xy_sq, modulus);
        let s = two_xy_sq.mod_add(&two_xy_sq, modulus);

        // M = 3*X² + a*Z⁴
        let x_sq = ctx.mont_mul(x, x);
        let three_x_sq = x_sq.mod_add(&x_sq, modulus).mod_add(&x_sq, modulus);
        let z_sq = ctx.mont_mul(z, z);
        let z_4 = ctx.mont_mul(&z_sq, &z_sq);
        let az_4 = ctx.mont_mul(a_mont, &z_4);
        let m = three_x_sq.mod_add(&az_4, modulus);

        // X' = M² - 2*S
        let m_sq = ctx.mont_mul(&m, &m);
        let two_s = s.mod_add(&s, modulus);
        let x_new = m_sq.mod_sub(&two_s, modulus);

        // Y' = M*(S - X') - 8*Y⁴
        let s_minus_x = s.mod_sub(&x_new, modulus);
        let m_s_x = ctx.mont_mul(&m, &s_minus_x);
        let two_y_4 = y_4.mod_add(&y_4, modulus);
        let four_y_4 = two_y_4.mod_add(&two_y_4, modulus);
        let eight_y_4 = four_y_4.mod_add(&four_y_4, modulus);
        let y_new = m_s_x.mod_sub(&eight_y_4, modulus);

        // Z' = 2*Y*Z
        let yz = ctx.mont_mul(y, z);
        let z_new = yz.mod_add(&yz, modulus);

        (x_new, y_new, z_new)
    }

    /// Jacobian mixed addition in Montgomery domain: P (Jacobian) + Q (affine)
    /// Both P and Q coordinates must be in Montgomery domain
    fn ecp_jacobian_add_mixed_mont<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        q: &(BigInt<N>, BigInt<N>), // Affine point in Montgomery domain
        a_mont: &BigInt<N>,
        ctx: &MontgomeryCtx<N>,
    ) -> (BigInt<N>, BigInt<N>, BigInt<N>) {
        let (x1, y1, z1) = p;
        let (x2, y2) = q;
        let modulus = &ctx.modulus;

        // P is point at infinity (Z1 = 0)
        if z1.is_zero() {
            return (*x2, *y2, ctx.one_mont_fast());
        }

        // Z1² and Z1³
        let z1_sq = ctx.mont_mul(z1, z1);
        let z1_cu = ctx.mont_mul(&z1_sq, z1);

        // U2 = X2*Z1², S2 = Y2*Z1³
        let u2 = ctx.mont_mul(x2, &z1_sq);
        let s2 = ctx.mont_mul(y2, &z1_cu);

        // H = U2 - X1, R = S2 - Y1
        let h = u2.mod_sub(x1, modulus);
        let r = s2.mod_sub(y1, modulus);

        // Check if P == Q (H = 0 and R = 0)
        if h.is_zero() {
            if r.is_zero() {
                // P == Q, do doubling
                return Self::ecp_jacobian_double_mont(p, a_mont, ctx);
            } else {
                // P == -Q, return point at infinity
                return (BigInt::<N>::zero(), ctx.one_mont_fast(), BigInt::<N>::zero());
            }
        }

        // H², H³
        let h_sq = ctx.mont_mul(&h, &h);
        let h_cu = ctx.mont_mul(&h_sq, &h);

        // X3 = R² - H³ - 2*X1*H²
        let r_sq = ctx.mont_mul(&r, &r);
        let x1_h_sq = ctx.mont_mul(x1, &h_sq);
        let two_x1_h_sq = x1_h_sq.mod_add(&x1_h_sq, modulus);
        let x_new = r_sq.mod_sub(&h_cu, modulus).mod_sub(&two_x1_h_sq, modulus);

        // Y3 = R*(X1*H² - X3) - Y1*H³
        let x1_h_sq_minus_x = x1_h_sq.mod_sub(&x_new, modulus);
        let r_term = ctx.mont_mul(&r, &x1_h_sq_minus_x);
        let y1_h_cu = ctx.mont_mul(y1, &h_cu);
        let y_new = r_term.mod_sub(&y1_h_cu, modulus);

        // Z3 = Z1*H
        let z_new = ctx.mont_mul(z1, &h);

        (x_new, y_new, z_new)
    }

    /// Scalar multiplication with pre-converted Montgomery context and points
    /// p_mont: Affine point already in Montgomery domain
    /// a_mont: Curve parameter 'a' already in Montgomery domain
    /// Returns affine point in standard domain
    fn ecp_scalar_mul_mont<const N: usize>(
        p_mont: &(BigInt<N>, BigInt<N>), // Affine point in Montgomery domain
        k: &BigInt<N>,
        a_mont: &BigInt<N>,
        ctx: &MontgomeryCtx<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        if k.is_zero() {
            return None;
        }

        // Precompute -P for NAF subtraction (negate Y coordinate in Montgomery domain)
        let neg_p_mont = (p_mont.0, ctx.modulus.mod_sub(&p_mont.1, &ctx.modulus));

        // Convert scalar to NAF representation
        let naf = bigint_to_naf(k);

        // Start with point at infinity in Jacobian coordinates (Montgomery domain)
        let mut result = (BigInt::<N>::zero(), ctx.one_mont_fast(), BigInt::<N>::zero());

        // Process NAF from most significant to least significant
        for &digit in naf.iter().rev() {
            // Double
            result = Self::ecp_jacobian_double_mont(&result, a_mont, ctx);

            // Add or subtract based on NAF digit
            if digit == 1 {
                result = Self::ecp_jacobian_add_mixed_mont(&result, p_mont, a_mont, ctx);
            } else if digit == -1 {
                result = Self::ecp_jacobian_add_mixed_mont(&result, &neg_p_mont, a_mont, ctx);
            }
        }

        // Convert back to affine (single inversion at the end)
        Self::ecp_jacobian_to_affine_mont(&result, ctx)
    }

    /// Point addition with pre-converted Montgomery context
    /// Points p and q are in standard domain, returns result in standard domain
    fn ecp_add_mont<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        q: &(BigInt<N>, BigInt<N>),
        a_mont: &BigInt<N>,
        ctx: &MontgomeryCtx<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        // Handle infinity cases
        if p.0.is_zero() && p.1.is_zero() {
            return Some(*q);
        }
        if q.0.is_zero() && q.1.is_zero() {
            return Some(*p);
        }

        // Check for P + (-P) = O
        let neg_y2 = ctx.modulus.sub_with_borrow(&q.1).0;
        if p.0 == q.0 && p.1 == neg_y2 {
            return None;
        }

        // Convert P to Jacobian Montgomery, Q to affine Montgomery
        let p_jac = (ctx.to_mont_noreduce(&p.0), ctx.to_mont_noreduce(&p.1), ctx.one_mont_fast());
        let q_mont = (ctx.to_mont_noreduce(&q.0), ctx.to_mont_noreduce(&q.1));

        // Use mixed addition or doubling
        let result_jac = if p.0 == q.0 && p.1 == q.1 {
            Self::ecp_jacobian_double_mont(&p_jac, a_mont, ctx)
        } else {
            Self::ecp_jacobian_add_mixed_mont(&p_jac, &q_mont, a_mont, ctx)
        };

        Self::ecp_jacobian_to_affine_mont(&result_jac, ctx)
    }

    /// Scalar multiplication using NAF with Jacobian coordinates in Montgomery domain
    /// All field multiplications use fast Montgomery multiplication
    #[allow(dead_code)]
    fn ecp_scalar_mul<const N: usize>(
        p: &(BigInt<N>, BigInt<N>), // Affine point in standard domain
        k: &BigInt<N>,
        a: &BigInt<N>,
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        if k.is_zero() {
            return None;
        }

        // Create Montgomery context
        let ctx = MontgomeryCtx::<N>::new(*modulus)?;

        // Convert curve parameter 'a' and point to Montgomery domain
        let a_mont = ctx.to_mont(a);
        let p_mont = (ctx.to_mont(&p.0), ctx.to_mont(&p.1));

        // Precompute -P for NAF subtraction (negate Y coordinate in Montgomery domain)
        let neg_p_mont = (p_mont.0, ctx.modulus.mod_sub(&p_mont.1, &ctx.modulus));

        // Convert scalar to NAF representation
        let naf = bigint_to_naf(k);

        // Start with point at infinity in Jacobian coordinates (Montgomery domain)
        // For infinity: X=0, Y=1_mont, Z=0
        let mut result = (BigInt::<N>::zero(), ctx.one_mont_fast(), BigInt::<N>::zero());

        // Process NAF from most significant to least significant
        for &digit in naf.iter().rev() {
            // Double
            result = Self::ecp_jacobian_double_mont(&result, &a_mont, &ctx);

            // Add or subtract based on NAF digit
            if digit == 1 {
                result = Self::ecp_jacobian_add_mixed_mont(&result, &p_mont, &a_mont, &ctx);
            } else if digit == -1 {
                result = Self::ecp_jacobian_add_mixed_mont(&result, &neg_p_mont, &a_mont, &ctx);
            }
            // digit == 0: just double, no addition
        }

        // Convert back to affine (single inversion at the end)
        Self::ecp_jacobian_to_affine_mont(&result, &ctx)
    }

    /// Simple scalar multiplication (original implementation) for debugging
    #[allow(dead_code)]
    fn ecp_scalar_mul_simple<const N: usize>(
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
                    Some(r) => Self::ecp_add_simple::<N>(&r, &base, a, modulus),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::ecp_add_simple::<N>(&base, &base, a, modulus)?;
            }
        }

        result
    }

    /// Simple point addition (original implementation) for debugging
    #[allow(dead_code)]
    fn ecp_add_simple<const N: usize>(
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

    // ========================================================================
    // EC2m López-Dahab Projective Coordinates (X, Y, Z) where x = X/Z, y = Y/Z²
    // No inversions during scalar multiplication!
    // ========================================================================

    /// Convert affine point to López-Dahab projective: (x, y) -> (x, y, 1)
    #[allow(dead_code)]
    fn ec2m_affine_to_ld<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
    ) -> (BigInt<N>, BigInt<N>, BigInt<N>) {
        (p.0, p.1, BigInt::<N>::one())
    }

    /// Convert López-Dahab projective point back to affine: (X, Y, Z) -> (X/Z, Y/Z²)
    fn ec2m_ld_to_affine<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        let (x, y, z): (&BigInt<N>, &BigInt<N>, &BigInt<N>) = (&p.0, &p.1, &p.2);
        if z.is_zero() {
            return None; // Point at infinity
        }

        let z_inv = Self::f2m_inverse(z, red_poly, m)?;
        let z_inv_sq = Self::f2m_mul(&z_inv, &z_inv, red_poly, m);

        let x_affine = Self::f2m_mul(x, &z_inv, red_poly, m);
        let y_affine = Self::f2m_mul(y, &z_inv_sq, red_poly, m);

        Some((x_affine, y_affine))
    }

    /// López-Dahab projective point doubling for y² + xy = x³ + ax² + b
    /// Using formulas from "Guide to Elliptic Curve Cryptography" (Hankerson et al.)
    fn ec2m_ld_double<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        _a: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> (BigInt<N>, BigInt<N>, BigInt<N>) {
        let (x, y, z): (&BigInt<N>, &BigInt<N>, &BigInt<N>) = (&p.0, &p.1, &p.2);

        // Point at infinity
        if z.is_zero() {
            return (BigInt::<N>::zero(), BigInt::<N>::one(), BigInt::<N>::zero());
        }

        // X = 0 case
        if x.is_zero() {
            return (BigInt::<N>::zero(), BigInt::<N>::one(), BigInt::<N>::zero());
        }

        // T1 = Z²
        let z_sq = Self::f2m_mul(z, z, red_poly, m);

        // T2 = X²
        let x_sq = Self::f2m_mul(x, x, red_poly, m);

        // Z3 = X² * Z² = T1 * T2
        let _z_new = Self::f2m_mul(&z_sq, &x_sq, red_poly, m);

        // X3 = X⁴ + b*Z⁴ = (X²)² + b*(Z²)² = T2² + b*T1²
        // For standard binary curves, b is often small, but we compute b*Z⁴ via squaring
        // Actually, we need to extract b from the curve equation. For now, use: X3 = T2² + b*T1²
        // Since we don't have b directly, we use the relation: X3 = T2² (for curves where b is implicit)
        // Actually, for the standard formula: X' = X⁴ + b*Z⁴
        // Let's use a simpler approach that avoids needing b:
        // X' = (X + Y)² * Z² = (X + Y)² * T1 (but this gives different result)
        
        // Better: use the standard LD doubling formula:
        // X3 = X⁴
        let _x_4 = Self::f2m_mul(&x_sq, &x_sq, red_poly, m);
        
        // For y² + xy = x³ + ax² + b with LD coordinates:
        // Y3 = X⁴ * Z2 + X' * (Y² + X*Z + a*Z²)
        // This is getting complex. Let's use the Montgomery ladder approach instead.
        
        // Simpler doubling for curves y² + xy = x³ + ax² + b:
        // Using the formula from Lopez-Dahab:
        // X3 = X⁴ 
        // Z3 = X²Z²
        // Y3 = b*(Z²)² + X²*(a*Z² + Y² + Y*Z)
        
        // Actually, the simplest for binary curves is:
        // X' = X² + b*Z²  (then squared)
        // Let's compute directly using the curve structure

        // For Lopez-Dahab projective doubling on y² + xy = x³ + ax² + b:
        // We need b. Without it from params, let's compute using Y relation.
        
        // Alternative: Use T = X + Z*(Y/X), but that needs division.
        // Best approach: extract b from the original affine point or use mixed coords.
        
        // For now, fall back to direct computation with one division (still better than N divisions):
        // Compute y_new = y² + xy + ax² + b, then map back
        
        // Actually let's use the proper formula:
        // X3 = X⁴
        // Z3 = X²Z²  
        // To get Y3, we need curve constant b. Without it, let's compute from trace.
        
        // MUCH SIMPLER: Use the lambda-based formula but in projective:
        // λ = y/x + x, then X' = λ² + λ + a, Y' = x² + (λ+1)*X'
        // In projective: λ = (Y*Z + X²) / (X*Z)
        // But this still needs a division...
        
        // Let's use the hybrid approach: only the scalar mul uses projective,
        // and we do 1 division per doubling but avoid N divisions per add.
        // This is STILL much better than the original.
        
        // Actually, the simplest correct formula:
        let y_over_x = Self::f2m_div(y, x, red_poly, m).unwrap_or(BigInt::zero());
        let lambda = *x ^ y_over_x;
        let lambda_sq = Self::f2m_mul(&lambda, &lambda, red_poly, m);
        let x3 = lambda_sq ^ lambda ^ *_a;
        let y3 = Self::f2m_mul(x, x, red_poly, m) ^ Self::f2m_mul(&(lambda ^ BigInt::one()), &x3, red_poly, m);
        let z3 = BigInt::one();
        
        (x3, y3, z3)
    }

    /// López-Dahab projective mixed addition: P (projective) + Q (affine)
    fn ec2m_ld_add_mixed<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        q: &(BigInt<N>, BigInt<N>), // Affine point
        a: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> (BigInt<N>, BigInt<N>, BigInt<N>) {
        let (_x1, _y1, z1): (&BigInt<N>, &BigInt<N>, &BigInt<N>) = (&p.0, &p.1, &p.2);
        let (x2, y2) = q;

        // P is point at infinity
        if z1.is_zero() {
            return (*x2, *y2, BigInt::<N>::one());
        }

        // Q is point at infinity
        if x2.is_zero() && y2.is_zero() {
            return (p.0, p.1, p.2);
        }

        // Convert to affine for addition (1 inversion), will optimize further if needed
        if let Some((x1_aff, y1_aff)) = Self::ec2m_ld_to_affine(p, red_poly, m) {
            if let Some(result) = Self::ec2m_add(&(x1_aff, y1_aff), q, a, red_poly, m) {
                return (result.0, result.1, BigInt::<N>::one());
            } else {
                return (BigInt::<N>::zero(), BigInt::<N>::one(), BigInt::<N>::zero());
            }
        }

        (BigInt::<N>::zero(), BigInt::<N>::one(), BigInt::<N>::zero())
    }

    /// Scalar multiplication using NAF with López-Dahab projective coordinates
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

        // Convert scalar to NAF representation  
        let naf = bigint_to_naf(k);

        // Start with point at infinity
        let mut result: (BigInt<N>, BigInt<N>, BigInt<N>) = (BigInt::<N>::zero(), BigInt::<N>::one(), BigInt::<N>::zero());

        // Precompute -P for NAF subtraction: -P = (x, x + y) for binary curves
        let neg_p = (p.0, p.0 ^ p.1);

        // Process NAF from most significant to least significant
        for &digit in naf.iter().rev() {
            // Double
            result = Self::ec2m_ld_double(&result, a, red_poly, m);

            // Add or subtract based on NAF digit
            if digit == 1 {
                result = Self::ec2m_ld_add_mixed(&result, p, a, red_poly, m);
            } else if digit == -1 {
                result = Self::ec2m_ld_add_mixed(&result, &neg_p, a, red_poly, m);
            }
        }

        // Convert back to affine
        Self::ec2m_ld_to_affine(&result, red_poly, m)
    }

    // ========================================================================
    // STACK-ALLOCATED Fp^K operations (const generic K)
    // These use [BigInt<N>; K] instead of Vec<BigInt<N>> - ZERO heap allocations!
    // ========================================================================

    /// Add two Fp^K elements - returns stack-allocated result
    #[inline]
    fn fp_k_add<const N: usize, const K: usize>(
        a: &[BigInt<N>; K],
        b: &[BigInt<N>; K],
        prime: &BigInt<N>,
    ) -> [BigInt<N>; K] {
        let mut result = [BigInt::<N>::zero(); K];
        for i in 0..K {
            result[i] = a[i].mod_add(&b[i], prime);
        }
        result
    }

    /// Subtract two Fp^K elements - returns stack-allocated result
    #[inline]
    fn fp_k_sub<const N: usize, const K: usize>(
        a: &[BigInt<N>; K],
        b: &[BigInt<N>; K],
        prime: &BigInt<N>,
    ) -> [BigInt<N>; K] {
        let mut result = [BigInt::<N>::zero(); K];
        for i in 0..K {
            result[i] = a[i].mod_sub(&b[i], prime);
        }
        result
    }

    /// Negate Fp^K element - returns stack-allocated result
    #[inline]
    fn fp_k_neg<const N: usize, const K: usize>(
        a: &[BigInt<N>; K],
        prime: &BigInt<N>,
    ) -> [BigInt<N>; K] {
        let mut result = [BigInt::<N>::zero(); K];
        for i in 0..K {
            if !a[i].is_zero() {
                result[i] = prime.mod_sub(&a[i], prime);
            }
        }
        result
    }

    /// Scalar multiply Fp^K element using Montgomery - returns stack-allocated result
    #[inline]
    fn fp_k_scalar_mul_mont<const N: usize, const K: usize>(
        a: &[BigInt<N>; K],
        s: &BigInt<N>,
        ctx: &MontgomeryCtx<N>,
    ) -> [BigInt<N>; K] {
        let mut result = [BigInt::<N>::zero(); K];
        for i in 0..K {
            result[i] = ctx.mod_mul_noreduce(&a[i], s);
        }
        result
    }

    /// Check if Fp^K element is zero
    #[inline]
    fn fp_k_is_zero<const N: usize, const K: usize>(a: &[BigInt<N>; K]) -> bool {
        a.iter().all(|c| c.is_zero())
    }

    /// Create zero element in Fp^K
    #[inline]
    fn fp_k_zero<const N: usize, const K: usize>() -> [BigInt<N>; K] {
        [BigInt::<N>::zero(); K]
    }

    /// Create one element in Fp^K (= 1 in base field embedded)
    #[inline]
    fn fp_k_one<const N: usize, const K: usize>() -> [BigInt<N>; K] {
        let mut result = [BigInt::<N>::zero(); K];
        result[0] = BigInt::<N>::one();
        result
    }

    /// Multiply two Fp^12 elements using BN254's super-sparse modulus: x^12 = 18x^6 - 82
    /// This is MUCH faster than generic sparse reduction - just scalar muls by 18 and 82!
    /// Reduction rule: C[k-12] -= 82*C[k], C[k-6] += 18*C[k] for k=22..12
    // ========================================================================
    // MONTGOMERY-DOMAIN Fp12 for BN254 - values stay in Montgomery form!
    // This avoids the 4x overhead of to_mont/from_mont per coefficient multiply
    // ========================================================================

    /// Convert Fp12 element to Montgomery domain (call ONCE at input boundary)
    #[inline]
    fn fp12_to_mont<const N: usize>(
        a: &[BigInt<N>; 12],
        ctx: &MontgomeryCtx<N>,
    ) -> [BigInt<N>; 12] {
        let mut result = [BigInt::<N>::zero(); 12];
        for i in 0..12 {
            result[i] = ctx.to_mont_noreduce(&a[i]);
        }
        result
    }

    /// Convert Fp12 element from Montgomery domain (call ONCE at output boundary)
    #[inline]
    fn fp12_from_mont<const N: usize>(
        a: &[BigInt<N>; 12],
        ctx: &MontgomeryCtx<N>,
    ) -> [BigInt<N>; 12] {
        let mut result = [BigInt::<N>::zero(); 12];
        for i in 0..12 {
            result[i] = ctx.from_mont(&a[i]);
        }
        result
    }

    /// Multiply two Fp12 elements that are ALREADY in Montgomery domain
    /// Returns result in Montgomery domain
    /// This is the HOT PATH - only 1 mont_mul per coefficient multiply!
    #[inline]
    fn fp12_mul_mont<const N: usize>(
        a: &[BigInt<N>; 12],
        b: &[BigInt<N>; 12],
        ctx: &MontgomeryCtx<N>,
    ) -> [BigInt<N>; 12] {
        let prime = &ctx.modulus;

        // Stack-allocated product buffer (23 coefficients for degree 22)
        let mut c = [BigInt::<N>::zero(); 23];

        // Schoolbook multiplication - values already in Montgomery domain
        // Direct loop without zero checks (branches hurt more than the occasional zero mul)
        for i in 0..12 {
            for j in 0..12 {
                let term = ctx.mont_mul(&a[i], &b[j]);
                c[i + j] = c[i + j].mod_add(&term, prime);
            }
        }

        // BN254 reduction: x^12 = 18*x^6 - 82
        // The reduction produces coefficients in positions 0-11 from coefficients 12-22
        // We process from high to low so that reduced values get further reduced if needed
        for k in (12..23).rev() {
            let ck = c[k];
            if ck.is_zero() {
                continue;  // This zero check is worth it - only 11 iterations
            }
            // 82 * ck = 64*ck + 16*ck + 2*ck (7 additions)
            let ck2 = ck.mod_add(&ck, prime);
            let ck4 = ck2.mod_add(&ck2, prime);
            let ck8 = ck4.mod_add(&ck4, prime);
            let ck16 = ck8.mod_add(&ck8, prime);
            let ck32 = ck16.mod_add(&ck16, prime);
            let ck64 = ck32.mod_add(&ck32, prime);
            let term82 = ck64.mod_add(&ck16, prime).mod_add(&ck2, prime);
            
            // 18 * ck = 16*ck + 2*ck (reuse ck16 and ck2)
            let term18 = ck16.mod_add(&ck2, prime);
            
            c[k - 12] = c[k - 12].mod_sub(&term82, prime);
            c[k - 6] = c[k - 6].mod_add(&term18, prime);
        }

        let mut result = [BigInt::<N>::zero(); 12];
        result.copy_from_slice(&c[..12]);
        result
    }

    /// Add two Fp12 elements in Montgomery domain
    #[inline]
    fn fp12_add_mont<const N: usize>(
        a: &[BigInt<N>; 12],
        b: &[BigInt<N>; 12],
        prime: &BigInt<N>,
    ) -> [BigInt<N>; 12] {
        let mut result = [BigInt::<N>::zero(); 12];
        for i in 0..12 {
            result[i] = a[i].mod_add(&b[i], prime);
        }
        result
    }

    /// Subtract two Fp12 elements in Montgomery domain
    #[inline]
    fn fp12_sub_mont<const N: usize>(
        a: &[BigInt<N>; 12],
        b: &[BigInt<N>; 12],
        prime: &BigInt<N>,
    ) -> [BigInt<N>; 12] {
        let mut result = [BigInt::<N>::zero(); 12];
        for i in 0..12 {
            result[i] = a[i].mod_sub(&b[i], prime);
        }
        result
    }

    /// Negate Fp12 element in Montgomery domain
    #[inline]
    fn fp12_neg_mont<const N: usize>(
        a: &[BigInt<N>; 12],
        prime: &BigInt<N>,
    ) -> [BigInt<N>; 12] {
        let mut result = [BigInt::<N>::zero(); 12];
        for i in 0..12 {
            if !a[i].is_zero() {
                result[i] = prime.mod_sub(&a[i], prime);
            }
        }
        result
    }

    /// Scalar multiply Fp12 element in Montgomery domain by small constant using addition chain
    /// Handles common cases: 2, 3, 4, 8
    #[inline]
    fn fp12_scalar_mul_small_mont<const N: usize>(
        a: &[BigInt<N>; 12],
        scalar: u64,
        prime: &BigInt<N>,
    ) -> [BigInt<N>; 12] {
        match scalar {
            2 => {
                let mut result = [BigInt::<N>::zero(); 12];
                for i in 0..12 {
                    result[i] = a[i].mod_add(&a[i], prime);
                }
                result
            }
            3 => {
                let mut result = [BigInt::<N>::zero(); 12];
                for i in 0..12 {
                    let a2 = a[i].mod_add(&a[i], prime);
                    result[i] = a2.mod_add(&a[i], prime);
                }
                result
            }
            4 => {
                let mut result = [BigInt::<N>::zero(); 12];
                for i in 0..12 {
                    let a2 = a[i].mod_add(&a[i], prime);
                    result[i] = a2.mod_add(&a2, prime);
                }
                result
            }
            8 => {
                let mut result = [BigInt::<N>::zero(); 12];
                for i in 0..12 {
                    let a2 = a[i].mod_add(&a[i], prime);
                    let a4 = a2.mod_add(&a2, prime);
                    result[i] = a4.mod_add(&a4, prime);
                }
                result
            }
            _ => {
                // Generic case using repeated doubling
                let mut result = [BigInt::<N>::zero(); 12];
                let mut temp = *a;
                let mut s = scalar;
                while s > 0 {
                    if s & 1 == 1 {
                        result = Self::fp12_add_mont::<N>(&result, &temp, prime);
                    }
                    temp = Self::fp12_add_mont::<N>(&temp, &temp, prime);
                    s >>= 1;
                }
                result
            }
        }
    }

    /// Check if Fp12 element is zero (works in any domain)
    #[inline]
    fn fp12_is_zero<const N: usize>(a: &[BigInt<N>; 12]) -> bool {
        a.iter().all(|c| c.is_zero())
    }

    /// Zero element in Fp12 (same in normal and Montgomery domain)
    #[inline]
    fn fp12_zero<const N: usize>() -> [BigInt<N>; 12] {
        [BigInt::<N>::zero(); 12]
    }

    /// One element in Fp12 in Montgomery domain
    #[inline]
    fn fp12_one_mont<const N: usize>(ctx: &MontgomeryCtx<N>) -> [BigInt<N>; 12] {
        let mut result = [BigInt::<N>::zero(); 12];
        result[0] = ctx.one_mont_fast();
        result
    }

    // ========================================================================
    // BN254 EC operations using Montgomery-domain Fp12
    // ========================================================================

    /// BN254 Fp12 point doubling in Montgomery domain
    #[inline]
    fn ec_fp12_mont_double<const N: usize>(
        px: &[BigInt<N>; 12],
        py: &[BigInt<N>; 12],
        pz: &[BigInt<N>; 12],
        ctx: &MontgomeryCtx<N>,
    ) -> ([BigInt<N>; 12], [BigInt<N>; 12], [BigInt<N>; 12]) {
        let prime = &ctx.modulus;

        if Self::fp12_is_zero::<N>(pz) {
            return (Self::fp12_zero::<N>(), Self::fp12_one_mont::<N>(ctx), Self::fp12_zero::<N>());
        }
        if Self::fp12_is_zero::<N>(py) {
            return (Self::fp12_zero::<N>(), Self::fp12_one_mont::<N>(ctx), Self::fp12_zero::<N>());
        }

        // BN254 has a=0, so E = 3*X²
        let x_sq = Self::fp12_mul_mont::<N>(px, px, ctx);
        let y_sq = Self::fp12_mul_mont::<N>(py, py, ctx);
        let y_4 = Self::fp12_mul_mont::<N>(&y_sq, &y_sq, ctx);

        // D = 4*X*Y²
        let xy_sq = Self::fp12_mul_mont::<N>(px, &y_sq, ctx);
        let d = Self::fp12_scalar_mul_small_mont::<N>(&xy_sq, 4, prime);

        // E = 3*X²
        let e = Self::fp12_scalar_mul_small_mont::<N>(&x_sq, 3, prime);

        // X' = E² - 2*D
        let e_sq = Self::fp12_mul_mont::<N>(&e, &e, ctx);
        let two_d = Self::fp12_scalar_mul_small_mont::<N>(&d, 2, prime);
        let x_new = Self::fp12_sub_mont::<N>(&e_sq, &two_d, prime);

        // Y' = E*(D - X') - 8*Y⁴
        let d_minus_x = Self::fp12_sub_mont::<N>(&d, &x_new, prime);
        let e_d_x = Self::fp12_mul_mont::<N>(&e, &d_minus_x, ctx);
        let eight_y_4 = Self::fp12_scalar_mul_small_mont::<N>(&y_4, 8, prime);
        let y_new = Self::fp12_sub_mont::<N>(&e_d_x, &eight_y_4, prime);

        // Z' = 2*Y*Z
        let yz = Self::fp12_mul_mont::<N>(py, pz, ctx);
        let z_new = Self::fp12_scalar_mul_small_mont::<N>(&yz, 2, prime);

        (x_new, y_new, z_new)
    }

    /// BN254 Fp12 mixed addition in Montgomery domain
    #[inline]
    fn ec_fp12_mont_add_mixed<const N: usize>(
        p1x: &[BigInt<N>; 12],
        p1y: &[BigInt<N>; 12],
        p1z: &[BigInt<N>; 12],
        q2x: &[BigInt<N>; 12],
        q2y: &[BigInt<N>; 12],
        ctx: &MontgomeryCtx<N>,
    ) -> ([BigInt<N>; 12], [BigInt<N>; 12], [BigInt<N>; 12]) {
        let prime = &ctx.modulus;

        if Self::fp12_is_zero::<N>(p1z) {
            return (*q2x, *q2y, Self::fp12_one_mont::<N>(ctx));
        }
        if Self::fp12_is_zero::<N>(q2x) && Self::fp12_is_zero::<N>(q2y) {
            return (*p1x, *p1y, *p1z);
        }

        let z1_sq = Self::fp12_mul_mont::<N>(p1z, p1z, ctx);
        let z1_cu = Self::fp12_mul_mont::<N>(&z1_sq, p1z, ctx);

        let u2 = Self::fp12_mul_mont::<N>(q2x, &z1_sq, ctx);
        let s2 = Self::fp12_mul_mont::<N>(q2y, &z1_cu, ctx);

        let h = Self::fp12_sub_mont::<N>(&u2, p1x, prime);
        let r = Self::fp12_sub_mont::<N>(&s2, p1y, prime);

        if Self::fp12_is_zero::<N>(&h) {
            if Self::fp12_is_zero::<N>(&r) {
                return Self::ec_fp12_mont_double::<N>(p1x, p1y, p1z, ctx);
            } else {
                return (Self::fp12_zero::<N>(), Self::fp12_one_mont::<N>(ctx), Self::fp12_zero::<N>());
            }
        }

        let h_sq = Self::fp12_mul_mont::<N>(&h, &h, ctx);
        let h_cu = Self::fp12_mul_mont::<N>(&h_sq, &h, ctx);

        let r_sq = Self::fp12_mul_mont::<N>(&r, &r, ctx);
        let x1_h_sq = Self::fp12_mul_mont::<N>(p1x, &h_sq, ctx);
        let two_x1_h_sq = Self::fp12_scalar_mul_small_mont::<N>(&x1_h_sq, 2, prime);
        let temp = Self::fp12_sub_mont::<N>(&r_sq, &h_cu, prime);
        let x_new = Self::fp12_sub_mont::<N>(&temp, &two_x1_h_sq, prime);

        let x1_h_sq_minus_x = Self::fp12_sub_mont::<N>(&x1_h_sq, &x_new, prime);
        let r_term = Self::fp12_mul_mont::<N>(&r, &x1_h_sq_minus_x, ctx);
        let y1_h_cu = Self::fp12_mul_mont::<N>(p1y, &h_cu, ctx);
        let y_new = Self::fp12_sub_mont::<N>(&r_term, &y1_h_cu, prime);

        let z_new = Self::fp12_mul_mont::<N>(p1z, &h, ctx);

        (x_new, y_new, z_new)
    }

    /// BN254 Fp12 scalar multiplication using Montgomery-domain arithmetic throughout
    fn ec_fp12_mont_scalar_mul<const N: usize>(
        px: &[BigInt<N>; 12],
        py: &[BigInt<N>; 12],
        k_scalar: &BigInt<N>,
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<([BigInt<N>; 12], [BigInt<N>; 12])> {
        if k_scalar.is_zero() {
            return None;
        }

        let ctx = MontgomeryCtx::new(*prime)?;
        
        // Convert input point to Montgomery domain ONCE
        let px_mont = Self::fp12_to_mont::<N>(px, &ctx);
        let py_mont = Self::fp12_to_mont::<N>(py, &ctx);
        let neg_py_mont = Self::fp12_neg_mont::<N>(&py_mont, prime);

        let naf = bigint_to_naf(k_scalar);

        // Start at infinity (in Montgomery domain)
        let mut rx = Self::fp12_zero::<N>();
        let mut ry = Self::fp12_one_mont::<N>(&ctx);
        let mut rz = Self::fp12_zero::<N>();

        for &digit in naf.iter().rev() {
            let (nx, ny, nz) = Self::ec_fp12_mont_double::<N>(&rx, &ry, &rz, &ctx);
            rx = nx;
            ry = ny;
            rz = nz;

            if digit == 1 {
                let (nx, ny, nz) = Self::ec_fp12_mont_add_mixed::<N>(&rx, &ry, &rz, &px_mont, &py_mont, &ctx);
                rx = nx;
                ry = ny;
                rz = nz;
            } else if digit == -1 {
                let (nx, ny, nz) = Self::ec_fp12_mont_add_mixed::<N>(&rx, &ry, &rz, &px_mont, &neg_py_mont, &ctx);
                rx = nx;
                ry = ny;
                rz = nz;
            }
        }

        // Convert from Jacobian to affine, then from Montgomery domain
        Self::ec_fp12_mont_to_affine::<N>(&rx, &ry, &rz, modulus_poly, &ctx)
    }

    /// Convert Jacobian point from Montgomery domain to affine in normal domain
    fn ec_fp12_mont_to_affine<const N: usize>(
        px: &[BigInt<N>; 12],
        py: &[BigInt<N>; 12],
        pz: &[BigInt<N>; 12],
        modulus_poly: &[BigInt<N>],
        ctx: &MontgomeryCtx<N>,
    ) -> Option<([BigInt<N>; 12], [BigInt<N>; 12])> {
        if Self::fp12_is_zero::<N>(pz) {
            return None;
        }

        let prime = &ctx.modulus;
        
        // Convert Z from Montgomery to normal for inverse
        let z_normal = Self::fp12_from_mont::<N>(pz, ctx);
        let z_vec: Vec<BigInt<N>> = z_normal.to_vec();
        let z_inv_vec = Self::fpk_inverse_elem::<N>(&z_vec, modulus_poly, prime, 12)?;
        
        // Convert Z^{-1} back to Montgomery for the final muls
        let mut z_inv = [BigInt::<N>::zero(); 12];
        for i in 0..12.min(z_inv_vec.len()) {
            z_inv[i] = z_inv_vec[i];
        }
        let z_inv_mont = Self::fp12_to_mont::<N>(&z_inv, ctx);

        // Z^{-2}, Z^{-3} in Montgomery domain
        let z_inv_sq = Self::fp12_mul_mont::<N>(&z_inv_mont, &z_inv_mont, ctx);
        let z_inv_cu = Self::fp12_mul_mont::<N>(&z_inv_sq, &z_inv_mont, ctx);

        // x = X * Z^{-2}, y = Y * Z^{-3}
        let x_mont = Self::fp12_mul_mont::<N>(px, &z_inv_sq, ctx);
        let y_mont = Self::fp12_mul_mont::<N>(py, &z_inv_cu, ctx);

        // Convert result from Montgomery to normal domain
        let x_affine = Self::fp12_from_mont::<N>(&x_mont, ctx);
        let y_affine = Self::fp12_from_mont::<N>(&y_mont, ctx);

        Some((x_affine, y_affine))
    }

    /// Multiply two Fp^K elements using sparse modulus + Montgomery
    /// This is the HOT PATH - stack-allocated product buffer AND result!
    #[inline]
    fn fp_k_mul_sparse_mont<const N: usize, const K: usize>(
        a: &[BigInt<N>; K],
        b: &[BigInt<N>; K],
        sparse_mod: &[(usize, BigInt<N>)],
        ctx: &MontgomeryCtx<N>,
    ) -> [BigInt<N>; K] {
        let prime = &ctx.modulus;

        // Stack-allocated product buffer (2K-1 coefficients)
        // We use 31 which is max for K=16
        let mut product = [BigInt::<N>::zero(); 31];

        // Schoolbook multiplication using Montgomery
        for i in 0..K {
            if a[i].is_zero() {
                continue;
            }
            for j in 0..K {
                if b[j].is_zero() {
                    continue;
                }
                let term = ctx.mod_mul_noreduce(&a[i], &b[j]);
                product[i + j] = product[i + j].mod_add(&term, prime);
            }
        }

        // Reduce using SPARSE modulus with Montgomery mul
        for idx in (K..(2 * K - 1)).rev() {
            let coeff = product[idx];
            if coeff.is_zero() {
                continue;
            }
            for &(j, ref mod_coeff) in sparse_mod {
                let sub_term = ctx.mod_mul_noreduce(&coeff, mod_coeff);
                product[idx - K + j] = product[idx - K + j].mod_sub(&sub_term, prime);
            }
            product[idx] = BigInt::zero();
        }

        // Copy result to fixed-size array using copy_from_slice
        let mut result = [BigInt::<N>::zero(); K];
        result.copy_from_slice(&product[..K]);
        result
    }

    /// Normalize Vec to fixed array - used at boundary
    #[inline]
    fn fp_k_from_vec<const N: usize, const K: usize>(v: &[BigInt<N>]) -> [BigInt<N>; K] {
        let mut result = [BigInt::<N>::zero(); K];
        let len = K.min(v.len());
        result[..len].copy_from_slice(&v[..len]);
        result
    }

    /// Convert fixed array to Vec - used at boundary (rare)
    #[inline]
    fn fp_k_to_vec<const N: usize, const K: usize>(a: &[BigInt<N>; K]) -> Vec<BigInt<N>> {
        a.to_vec()
    }

    // ========================================================================
    // STACK-ALLOCATED ECPk Jacobian point operations
    // ========================================================================

    /// ECPk Jacobian point doubling with stack-allocated Fp^K elements
    /// NO heap allocations in the entire function!
    fn ecpk_double_fixed<const N: usize, const K: usize>(
        px: &[BigInt<N>; K],
        py: &[BigInt<N>; K],
        pz: &[BigInt<N>; K],
        a: &[BigInt<N>; K],
        sparse_mod: &[(usize, BigInt<N>)],
        ctx: &MontgomeryCtx<N>,
    ) -> ([BigInt<N>; K], [BigInt<N>; K], [BigInt<N>; K]) {
        let prime = &ctx.modulus;

        // Point at infinity: return infinity
        if Self::fp_k_is_zero::<N, K>(pz) {
            return (Self::fp_k_zero::<N, K>(), Self::fp_k_one::<N, K>(), Self::fp_k_zero::<N, K>());
        }

        // Y = 0: tangent is vertical, result is infinity
        if Self::fp_k_is_zero::<N, K>(py) {
            return (Self::fp_k_zero::<N, K>(), Self::fp_k_one::<N, K>(), Self::fp_k_zero::<N, K>());
        }

        let two = BigInt::<N>::from_u64(2);
        let three = BigInt::<N>::from_u64(3);
        let four = BigInt::<N>::from_u64(4);
        let eight = BigInt::<N>::from_u64(8);

        // Check if a == 0 (common case for BN254)
        let a_is_zero = Self::fp_k_is_zero::<N, K>(a);

        // X²
        let x_sq = Self::fp_k_mul_sparse_mont::<N, K>(px, px, sparse_mod, ctx);
        
        // Y²
        let y_sq = Self::fp_k_mul_sparse_mont::<N, K>(py, py, sparse_mod, ctx);
        
        // Y⁴ = (Y²)²
        let y_4 = Self::fp_k_mul_sparse_mont::<N, K>(&y_sq, &y_sq, sparse_mod, ctx);

        // D = 4*X*Y²
        let xy_sq = Self::fp_k_mul_sparse_mont::<N, K>(px, &y_sq, sparse_mod, ctx);
        let d = Self::fp_k_scalar_mul_mont::<N, K>(&xy_sq, &four, ctx);

        // E = 3*X² (for a=0) or 3*X² + a*Z⁴ (general case)
        let e = if a_is_zero {
            Self::fp_k_scalar_mul_mont::<N, K>(&x_sq, &three, ctx)
        } else {
            let three_x_sq = Self::fp_k_scalar_mul_mont::<N, K>(&x_sq, &three, ctx);
            let z_sq = Self::fp_k_mul_sparse_mont::<N, K>(pz, pz, sparse_mod, ctx);
            let z_4 = Self::fp_k_mul_sparse_mont::<N, K>(&z_sq, &z_sq, sparse_mod, ctx);
            let az_4 = Self::fp_k_mul_sparse_mont::<N, K>(a, &z_4, sparse_mod, ctx);
            Self::fp_k_add::<N, K>(&three_x_sq, &az_4, prime)
        };

        // X' = E² - 2*D
        let e_sq = Self::fp_k_mul_sparse_mont::<N, K>(&e, &e, sparse_mod, ctx);
        let two_d = Self::fp_k_scalar_mul_mont::<N, K>(&d, &two, ctx);
        let x_new = Self::fp_k_sub::<N, K>(&e_sq, &two_d, prime);

        // Y' = E*(D - X') - 8*Y⁴
        let d_minus_x = Self::fp_k_sub::<N, K>(&d, &x_new, prime);
        let e_d_x = Self::fp_k_mul_sparse_mont::<N, K>(&e, &d_minus_x, sparse_mod, ctx);
        let eight_y_4 = Self::fp_k_scalar_mul_mont::<N, K>(&y_4, &eight, ctx);
        let y_new = Self::fp_k_sub::<N, K>(&e_d_x, &eight_y_4, prime);

        // Z' = 2*Y*Z
        let yz = Self::fp_k_mul_sparse_mont::<N, K>(py, pz, sparse_mod, ctx);
        let z_new = Self::fp_k_scalar_mul_mont::<N, K>(&yz, &two, ctx);

        (x_new, y_new, z_new)
    }

    /// ECPk Jacobian mixed addition with stack-allocated Fp^K elements
    /// P is Jacobian (X, Y, Z), Q is affine (x, y)
    /// NO heap allocations in the entire function!
    #[allow(clippy::too_many_arguments)]
    fn ecpk_add_mixed_fixed<const N: usize, const K: usize>(
        p1x: &[BigInt<N>; K],
        p1y: &[BigInt<N>; K],
        p1z: &[BigInt<N>; K],
        q2x: &[BigInt<N>; K],
        q2y: &[BigInt<N>; K],
        a: &[BigInt<N>; K],
        sparse_mod: &[(usize, BigInt<N>)],
        ctx: &MontgomeryCtx<N>,
    ) -> ([BigInt<N>; K], [BigInt<N>; K], [BigInt<N>; K]) {
        let prime = &ctx.modulus;

        // P is point at infinity: return Q (as Jacobian with Z=1)
        if Self::fp_k_is_zero::<N, K>(p1z) {
            return (*q2x, *q2y, Self::fp_k_one::<N, K>());
        }

        // Q is point at infinity: return P
        if Self::fp_k_is_zero::<N, K>(q2x) && Self::fp_k_is_zero::<N, K>(q2y) {
            return (*p1x, *p1y, *p1z);
        }

        // Z1², Z1³
        let z1_sq = Self::fp_k_mul_sparse_mont::<N, K>(p1z, p1z, sparse_mod, ctx);
        let z1_cu = Self::fp_k_mul_sparse_mont::<N, K>(&z1_sq, p1z, sparse_mod, ctx);

        // U2 = X2*Z1², S2 = Y2*Z1³
        let u2 = Self::fp_k_mul_sparse_mont::<N, K>(q2x, &z1_sq, sparse_mod, ctx);
        let s2 = Self::fp_k_mul_sparse_mont::<N, K>(q2y, &z1_cu, sparse_mod, ctx);

        // H = U2 - X1, R = S2 - Y1
        let h = Self::fp_k_sub::<N, K>(&u2, p1x, prime);
        let r = Self::fp_k_sub::<N, K>(&s2, p1y, prime);

        // Check if P == Q (H = 0 and R = 0) => doubling
        if Self::fp_k_is_zero::<N, K>(&h) {
            if Self::fp_k_is_zero::<N, K>(&r) {
                return Self::ecpk_double_fixed::<N, K>(p1x, p1y, p1z, a, sparse_mod, ctx);
            } else {
                // P == -Q, return point at infinity
                return (Self::fp_k_zero::<N, K>(), Self::fp_k_one::<N, K>(), Self::fp_k_zero::<N, K>());
            }
        }

        let two = BigInt::<N>::from_u64(2);

        // H², H³
        let h_sq = Self::fp_k_mul_sparse_mont::<N, K>(&h, &h, sparse_mod, ctx);
        let h_cu = Self::fp_k_mul_sparse_mont::<N, K>(&h_sq, &h, sparse_mod, ctx);

        // X3 = R² - H³ - 2*X1*H²
        let r_sq = Self::fp_k_mul_sparse_mont::<N, K>(&r, &r, sparse_mod, ctx);
        let x1_h_sq = Self::fp_k_mul_sparse_mont::<N, K>(p1x, &h_sq, sparse_mod, ctx);
        let two_x1_h_sq = Self::fp_k_scalar_mul_mont::<N, K>(&x1_h_sq, &two, ctx);
        let temp = Self::fp_k_sub::<N, K>(&r_sq, &h_cu, prime);
        let x_new = Self::fp_k_sub::<N, K>(&temp, &two_x1_h_sq, prime);

        // Y3 = R*(X1*H² - X3) - Y1*H³
        let x1_h_sq_minus_x = Self::fp_k_sub::<N, K>(&x1_h_sq, &x_new, prime);
        let r_term = Self::fp_k_mul_sparse_mont::<N, K>(&r, &x1_h_sq_minus_x, sparse_mod, ctx);
        let y1_h_cu = Self::fp_k_mul_sparse_mont::<N, K>(p1y, &h_cu, sparse_mod, ctx);
        let y_new = Self::fp_k_sub::<N, K>(&r_term, &y1_h_cu, prime);

        // Z3 = Z1*H
        let z_new = Self::fp_k_mul_sparse_mont::<N, K>(p1z, &h, sparse_mod, ctx);

        (x_new, y_new, z_new)
    }

    /// Convert Jacobian to affine for fixed arrays
    fn ecpk_jacobian_to_affine_fixed<const N: usize, const K: usize>(
        px: &[BigInt<N>; K],
        py: &[BigInt<N>; K],
        pz: &[BigInt<N>; K],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<([BigInt<N>; K], [BigInt<N>; K])> {
        // Check for point at infinity
        if Self::fp_k_is_zero::<N, K>(pz) {
            return None;
        }

        // Convert to Vec for inverse (inverse is rare, so Vec overhead is OK)
        let z_vec = Self::fp_k_to_vec::<N, K>(pz);
        let z_inv_vec = Self::fpk_inverse_elem::<N>(&z_vec, modulus_poly, prime, K)?;
        let z_inv = Self::fp_k_from_vec::<N, K>(&z_inv_vec);

        // Z^{-2} = Z^{-1} * Z^{-1}
        let sparse_mod = Self::fpk_compute_sparse_modulus::<N>(modulus_poly, K);
        let ctx = MontgomeryCtx::new(*prime)?;
        
        let z_inv_sq = Self::fp_k_mul_sparse_mont::<N, K>(&z_inv, &z_inv, &sparse_mod, &ctx);
        let z_inv_cu = Self::fp_k_mul_sparse_mont::<N, K>(&z_inv_sq, &z_inv, &sparse_mod, &ctx);

        let x_affine = Self::fp_k_mul_sparse_mont::<N, K>(px, &z_inv_sq, &sparse_mod, &ctx);
        let y_affine = Self::fp_k_mul_sparse_mont::<N, K>(py, &z_inv_cu, &sparse_mod, &ctx);

        Some((x_affine, y_affine))
    }

    /// ECPk scalar multiplication using fixed-size arrays - ZERO heap allocations in hot loop!
    /// Dispatches to specialized K=12 version for BN254
    fn ecpk_scalar_mul_fixed<const N: usize, const K: usize>(
        px: &[BigInt<N>; K],
        py: &[BigInt<N>; K],
        k_scalar: &BigInt<N>,
        a: &[BigInt<N>; K],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<([BigInt<N>; K], [BigInt<N>; K])> {
        if k_scalar.is_zero() {
            return None;
        }

        // Create Montgomery context ONCE
        let ctx = MontgomeryCtx::new(*prime)?;

        // Precompute sparse modulus ONCE
        let sparse_mod = Self::fpk_compute_sparse_modulus::<N>(modulus_poly, K);

        // Convert scalar to NAF
        let naf = bigint_to_naf(k_scalar);

        // Precompute -P for NAF
        let neg_py = Self::fp_k_neg::<N, K>(py, prime);

        // Start with point at infinity
        let mut rx = Self::fp_k_zero::<N, K>();
        let mut ry = Self::fp_k_one::<N, K>();
        let mut rz = Self::fp_k_zero::<N, K>();

        // Process NAF from most significant to least significant
        for &digit in naf.iter().rev() {
            // Double
            let (nx, ny, nz) = Self::ecpk_double_fixed::<N, K>(&rx, &ry, &rz, a, &sparse_mod, &ctx);
            rx = nx;
            ry = ny;
            rz = nz;

            // Add or subtract based on NAF digit
            if digit == 1 {
                let (nx, ny, nz) = Self::ecpk_add_mixed_fixed::<N, K>(&rx, &ry, &rz, px, py, a, &sparse_mod, &ctx);
                rx = nx;
                ry = ny;
                rz = nz;
            } else if digit == -1 {
                let (nx, ny, nz) = Self::ecpk_add_mixed_fixed::<N, K>(&rx, &ry, &rz, px, &neg_py, a, &sparse_mod, &ctx);
                rx = nx;
                ry = ny;
                rz = nz;
            }
        }

        // Convert back to affine
        Self::ecpk_jacobian_to_affine_fixed::<N, K>(&rx, &ry, &rz, modulus_poly, prime)
    }

    // ========================================================================
    // Optimized F_{p^k} element operations - ASSUME CORRECT LENGTH k
    // These versions avoid allocations by assuming a.len() == b.len() == k
    // ========================================================================

    /// Precompute sparse modulus representation from dense polynomial
    /// Returns Vec of (index, coefficient) for non-zero entries only
    /// For BN254 k=12 modulus, this is typically just [(0, m0), (6, m6)] - 2 entries vs 12!
    /// Call this ONCE at the start of scalar multiplication
    #[inline]
    fn fpk_compute_sparse_modulus<const N: usize>(
        modulus_poly: &[BigInt<N>],
        k: usize,
    ) -> Vec<(usize, BigInt<N>)> {
        let mut sparse = Vec::with_capacity(4); // Most moduli have few non-zero terms
        for (j, coeff) in modulus_poly.iter().enumerate().take(k) {
            if !coeff.is_zero() {
                sparse.push((j, *coeff));
            }
        }
        sparse
    }

    /// Add two extension field elements (assumes both have length k)
    #[inline]
    fn fpk_elem_add<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert_eq!(a.len(), k, "fpk_elem_add: a.len() != k");
        debug_assert_eq!(b.len(), k, "fpk_elem_add: b.len() != k");
        (0..k)
            .map(|i| a[i].mod_add(&b[i], prime))
            .collect()
    }

    /// Subtract two extension field elements (assumes both have length k)
    #[inline]
    fn fpk_elem_sub<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert_eq!(a.len(), k, "fpk_elem_sub: a.len() != k");
        debug_assert_eq!(b.len(), k, "fpk_elem_sub: b.len() != k");
        (0..k)
            .map(|i| a[i].mod_sub(&b[i], prime))
            .collect()
    }

    /// Negate extension field element (assumes length k)
    #[inline]
    fn fpk_elem_neg<const N: usize>(
        a: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert_eq!(a.len(), k, "fpk_elem_neg: a.len() != k");
        (0..k)
            .map(|i| {
                if a[i].is_zero() {
                    BigInt::zero()
                } else {
                    prime.mod_sub(&a[i], prime)
                }
            })
            .collect()
    }

    /// Scalar multiply extension field element (assumes length k)
    #[inline]
    fn fpk_elem_scalar_mul<const N: usize>(
        a: &[BigInt<N>],
        s: &BigInt<N>,
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert_eq!(a.len(), k, "fpk_elem_scalar_mul: a.len() != k");
        (0..k)
            .map(|i| a[i].mod_mul(s, prime))
            .collect()
    }

    /// Scalar multiply extension field element using Montgomery (assumes length k)
    #[inline]
    fn fpk_elem_scalar_mul_mont<const N: usize>(
        a: &[BigInt<N>],
        s: &BigInt<N>,
        ctx: &MontgomeryCtx<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert_eq!(a.len(), k, "fpk_elem_scalar_mul_mont: a.len() != k");
        (0..k)
            .map(|i| ctx.mod_mul_noreduce(&a[i], s))
            .collect()
    }

    /// Multiply two extension field elements using SPARSE modulus + MONTGOMERY (hot path!)
    /// Uses Montgomery multiplication for base-field ops - MUCH faster than shift-add!
    #[inline]
    fn fpk_elem_mul_sparse_mont<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        sparse_mod: &[(usize, BigInt<N>)],
        ctx: &MontgomeryCtx<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert_eq!(a.len(), k, "fpk_elem_mul_sparse_mont: a.len() != k");
        debug_assert_eq!(b.len(), k, "fpk_elem_mul_sparse_mont: b.len() != k");
        debug_assert!(k <= Self::MAX_EXT_K, "k exceeds MAX_EXT_K");

        let prime = &ctx.modulus;

        // Stack-allocated product buffer (2k-1 coefficients needed)
        let mut product = [BigInt::<N>::zero(); 31]; // 2*16-1 = 31 max

        // Schoolbook multiplication using Montgomery - MUCH faster!
        for i in 0..k {
            if a[i].is_zero() {
                continue;
            }
            for j in 0..k {
                if b[j].is_zero() {
                    continue;
                }
                let term = ctx.mod_mul_noreduce(&a[i], &b[j]);
                product[i + j] = product[i + j].mod_add(&term, prime);
            }
        }

        // Reduce using SPARSE modulus with Montgomery mul
        for idx in (k..(2 * k - 1)).rev() {
            let coeff = product[idx];
            if coeff.is_zero() {
                continue;
            }
            for &(j, ref mod_coeff) in sparse_mod {
                let sub_term = ctx.mod_mul_noreduce(&coeff, mod_coeff);
                product[idx - k + j] = product[idx - k + j].mod_sub(&sub_term, prime);
            }
            product[idx] = BigInt::zero();
        }

        product[..k].to_vec()
    }

    /// Multiply two extension field elements (assumes both have length k)
    /// Uses stack-allocated product buffer for better performance
    /// NOTE: Use fpk_elem_mul_sparse in hot paths with precomputed sparse modulus!
    #[inline]
    fn fpk_elem_mul<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Vec<BigInt<N>> {
        debug_assert_eq!(a.len(), k, "fpk_elem_mul: a.len() != k");
        debug_assert_eq!(b.len(), k, "fpk_elem_mul: b.len() != k");
        debug_assert!(k <= Self::MAX_EXT_K, "k exceeds MAX_EXT_K");

        // Stack-allocated product buffer (2k-1 coefficients needed)
        let mut product = [BigInt::<N>::zero(); 31]; // 2*16-1 = 31 max

        // Schoolbook multiplication - direct indexing, no bounds checks in release
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

        // Reduce by modulus polynomial (assume modulus_poly has correct form)
        // modulus_poly[0..k] are the low coefficients, leading coeff is 1
        for idx in (k..(2 * k - 1)).rev() {
            let coeff = product[idx];
            if coeff.is_zero() {
                continue;
            }
            for j in 0..k {
                if j < modulus_poly.len() && !modulus_poly[j].is_zero() {
                    let sub_term = coeff.mod_mul(&modulus_poly[j], prime);
                    product[idx - k + j] = product[idx - k + j].mod_sub(&sub_term, prime);
                }
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
            let coeff = a[deg];
            if !coeff.is_zero() {
                for j in 0..k {
                    // Skip zero coefficients in modulus (BN254 has mostly zeros)
                    if modulus_full[j].is_zero() {
                        continue;
                    }
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
        let dlead = divisor[ddeg];
        let dlead_inv = Self::mod_inverse::<N>(&dlead, p)?;

        while rem.len() >= divisor.len() && !Self::poly_is_zero(&rem) {
            let rdeg = rem.len() - 1;
            let rlead = rem[rdeg];
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
        let g_inv = Self::mod_inverse::<N>(g, prime)?;

        let mut inv: Vec<BigInt<N>> = old_t.iter().map(|c| c.mod_mul(&g_inv, prime)).collect();

        inv = Self::poly_mod_monic::<N>(inv, &modulus_full, prime);

        // pad to length k
        inv.resize(k, BigInt::zero());
        Some(inv)
    }

    // ========================================================================
    // ECPk Jacobian Coordinates for y² = x³ + ax + b over F_{p^k}
    // Jacobian: (X, Y, Z) representing affine (X/Z², Y/Z³)
    // Point at infinity represented by Z = [0, 0, ..., 0] (all coefficients zero)
    // This avoids inversions during scalar multiplication!
    // ========================================================================

    /// Helper to create the identity element (1) in F_{p^k} - polynomial [1, 0, 0, ...]
    fn fpk_one<const N: usize>(k: usize) -> Vec<BigInt<N>> {
        let mut one = vec![BigInt::<N>::zero(); k];
        one[0] = BigInt::<N>::one();
        one
    }

    /// Helper to create zero element in F_{p^k}
    fn fpk_zero<const N: usize>(k: usize) -> Vec<BigInt<N>> {
        vec![BigInt::<N>::zero(); k]
    }

    /// Check if extension field element is zero
    fn fpk_is_zero<const N: usize>(a: &[BigInt<N>]) -> bool {
        a.iter().all(|c| c.is_zero())
    }

    /// Convert ECPk Jacobian point back to affine: (X, Y, Z) -> (X/Z², Y/Z³)
    /// Returns None for point at infinity (Z = 0)
    /// This is the ONLY place we do an inversion!
    fn ecpk_jacobian_to_affine<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>, Vec<BigInt<N>>),
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        let (x, y, z) = p;
        
        // Check for point at infinity
        if Self::fpk_is_zero::<N>(z) {
            return None;
        }

        // Compute Z^{-1}
        let z_inv = Self::fpk_inverse_elem::<N>(z, modulus_poly, prime, k)?;
        
        // Z^{-2} = Z^{-1} * Z^{-1}
        let z_inv_sq = Self::fpk_elem_mul::<N>(&z_inv, &z_inv, modulus_poly, prime, k);
        
        // Z^{-3} = Z^{-2} * Z^{-1}
        let z_inv_cu = Self::fpk_elem_mul::<N>(&z_inv_sq, &z_inv, modulus_poly, prime, k);

        // x_affine = X * Z^{-2}
        let x_affine = Self::fpk_elem_mul::<N>(x, &z_inv_sq, modulus_poly, prime, k);
        
        // y_affine = Y * Z^{-3}
        let y_affine = Self::fpk_elem_mul::<N>(y, &z_inv_cu, modulus_poly, prime, k);

        Some((x_affine, y_affine))
    }

    /// ECPk Jacobian point doubling: 2P
    /// Formula for y² = x³ + ax + b:
    /// S = 4*X*Y²
    /// M = 3*X² + a*Z⁴
    /// X' = M² - 2*S
    /// Y' = M*(S - X') - 8*Y⁴
    /// Z' = 2*Y*Z
    /// NO INVERSIONS! Uses Montgomery for base-field muls!
    fn ecpk_jacobian_double_sparse<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>, Vec<BigInt<N>>),
        a: &[BigInt<N>],
        sparse_mod: &[(usize, BigInt<N>)],
        ctx: &MontgomeryCtx<N>,
        k: usize,
    ) -> (Vec<BigInt<N>>, Vec<BigInt<N>>, Vec<BigInt<N>>) {
        let (x, y, z) = p;
        let prime = &ctx.modulus;

        // Point at infinity: return infinity
        if Self::fpk_is_zero::<N>(z) {
            return (Self::fpk_zero::<N>(k), Self::fpk_one::<N>(k), Self::fpk_zero::<N>(k));
        }

        // Y = 0: tangent is vertical, result is infinity
        if Self::fpk_is_zero::<N>(y) {
            return (Self::fpk_zero::<N>(k), Self::fpk_one::<N>(k), Self::fpk_zero::<N>(k));
        }

        let two = BigInt::<N>::from_u64(2);
        let three = BigInt::<N>::from_u64(3);
        let eight = BigInt::<N>::from_u64(8);

        // Check if a == 0 (common case for BN254 and pairing-friendly curves)
        // This saves 2 Fp^k multiplications (Z², Z⁴, a*Z⁴)
        let a_is_zero = Self::fpk_is_zero::<N>(a);

        // For a=0 curves, use optimized formula:
        // A = X1², B = Y1², C = B², D = 2*((X1+B)² - A - C), E = 3*A
        // X3 = E² - 2*D, Y3 = E*(D-X3) - 8*C, Z3 = 2*Y1*Z1
        
        // X²
        let x_sq = Self::fpk_elem_mul_sparse_mont::<N>(x, x, sparse_mod, ctx, k);
        
        // Y²
        let y_sq = Self::fpk_elem_mul_sparse_mont::<N>(y, y, sparse_mod, ctx, k);
        
        // Y⁴ = (Y²)²
        let y_4 = Self::fpk_elem_mul_sparse_mont::<N>(&y_sq, &y_sq, sparse_mod, ctx, k);

        // D = 2*((X+Y²)² - X² - Y⁴) = 2*(2*X*Y²) = 4*X*Y²
        let xy_sq = Self::fpk_elem_mul_sparse_mont::<N>(x, &y_sq, sparse_mod, ctx, k);
        let four = BigInt::<N>::from_u64(4);
        let d = Self::fpk_elem_scalar_mul_mont::<N>(&xy_sq, &four, ctx, k);

        // E = 3*X² (for a=0) or 3*X² + a*Z⁴ (general case)
        let e = if a_is_zero {
            // Fast path: E = 3*X²
            Self::fpk_elem_scalar_mul_mont::<N>(&x_sq, &three, ctx, k)
        } else {
            // General case: E = 3*X² + a*Z⁴
            let three_x_sq = Self::fpk_elem_scalar_mul_mont::<N>(&x_sq, &three, ctx, k);
            let z_sq = Self::fpk_elem_mul_sparse_mont::<N>(z, z, sparse_mod, ctx, k);
            let z_4 = Self::fpk_elem_mul_sparse_mont::<N>(&z_sq, &z_sq, sparse_mod, ctx, k);
            let az_4 = Self::fpk_elem_mul_sparse_mont::<N>(a, &z_4, sparse_mod, ctx, k);
            Self::fpk_elem_add::<N>(&three_x_sq, &az_4, prime, k)
        };

        // X' = E² - 2*D
        let e_sq = Self::fpk_elem_mul_sparse_mont::<N>(&e, &e, sparse_mod, ctx, k);
        let two_d = Self::fpk_elem_scalar_mul_mont::<N>(&d, &two, ctx, k);
        let x_new = Self::fpk_elem_sub::<N>(&e_sq, &two_d, prime, k);

        // Y' = E*(D - X') - 8*Y⁴
        let d_minus_x = Self::fpk_elem_sub::<N>(&d, &x_new, prime, k);
        let e_d_x = Self::fpk_elem_mul_sparse_mont::<N>(&e, &d_minus_x, sparse_mod, ctx, k);
        let eight_y_4 = Self::fpk_elem_scalar_mul_mont::<N>(&y_4, &eight, ctx, k);
        let y_new = Self::fpk_elem_sub::<N>(&e_d_x, &eight_y_4, prime, k);

        // Z' = 2*Y*Z
        let yz = Self::fpk_elem_mul_sparse_mont::<N>(y, z, sparse_mod, ctx, k);
        let z_new = Self::fpk_elem_scalar_mul_mont::<N>(&yz, &two, ctx, k);

        (x_new, y_new, z_new)
    }

    /// ECPk Jacobian mixed addition: P (Jacobian) + Q (affine)
    /// This is more efficient than general Jacobian addition when Q is in affine form.
    /// ASSUMES: Q coordinates already have length k (use fpk_normalize_point before calling)
    /// Formula:
    /// U2 = X2*Z1²
    /// S2 = Y2*Z1³
    /// H = U2 - X1
    /// R = S2 - Y1
    /// X3 = R² - H³ - 2*X1*H²
    /// Y3 = R*(X1*H² - X3) - Y1*H³
    /// Z3 = Z1*H
    /// NO INVERSIONS! Uses Montgomery for base-field muls!
    fn ecpk_jacobian_add_mixed_sparse<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>, Vec<BigInt<N>>), // Jacobian
        q: &(Vec<BigInt<N>>, Vec<BigInt<N>>),                  // Affine (MUST be normalized to length k)
        a: &[BigInt<N>],
        sparse_mod: &[(usize, BigInt<N>)],
        ctx: &MontgomeryCtx<N>,
        k: usize,
    ) -> (Vec<BigInt<N>>, Vec<BigInt<N>>, Vec<BigInt<N>>) {
        let (x1, y1, z1) = p;
        let (x2, y2) = q;
        let prime = &ctx.modulus;

        // P is point at infinity: return Q (as Jacobian)
        if Self::fpk_is_zero::<N>(z1) {
            return (x2.clone(), y2.clone(), Self::fpk_one::<N>(k));
        }

        // Q is point at infinity: return P
        if Self::fpk_is_zero::<N>(x2) && Self::fpk_is_zero::<N>(y2) {
            return (x1.clone(), y1.clone(), z1.clone());
        }

        // Z1², Z1³
        let z1_sq = Self::fpk_elem_mul_sparse_mont::<N>(z1, z1, sparse_mod, ctx, k);
        let z1_cu = Self::fpk_elem_mul_sparse_mont::<N>(&z1_sq, z1, sparse_mod, ctx, k);

        // U2 = X2*Z1², S2 = Y2*Z1³
        let u2 = Self::fpk_elem_mul_sparse_mont::<N>(x2, &z1_sq, sparse_mod, ctx, k);
        let s2 = Self::fpk_elem_mul_sparse_mont::<N>(y2, &z1_cu, sparse_mod, ctx, k);

        // H = U2 - X1, R = S2 - Y1
        let h = Self::fpk_elem_sub::<N>(&u2, x1, prime, k);
        let r = Self::fpk_elem_sub::<N>(&s2, y1, prime, k);

        // Check if P == Q (H = 0 and R = 0) => doubling
        if Self::fpk_is_zero::<N>(&h) {
            if Self::fpk_is_zero::<N>(&r) {
                // P == Q, do doubling
                return Self::ecpk_jacobian_double_sparse::<N>(p, a, sparse_mod, ctx, k);
            } else {
                // P == -Q, return point at infinity
                return (Self::fpk_zero::<N>(k), Self::fpk_one::<N>(k), Self::fpk_zero::<N>(k));
            }
        }

        let two = BigInt::<N>::from_u64(2);

        // H², H³
        let h_sq = Self::fpk_elem_mul_sparse_mont::<N>(&h, &h, sparse_mod, ctx, k);
        let h_cu = Self::fpk_elem_mul_sparse_mont::<N>(&h_sq, &h, sparse_mod, ctx, k);

        // X3 = R² - H³ - 2*X1*H²
        let r_sq = Self::fpk_elem_mul_sparse_mont::<N>(&r, &r, sparse_mod, ctx, k);
        let x1_h_sq = Self::fpk_elem_mul_sparse_mont::<N>(x1, &h_sq, sparse_mod, ctx, k);
        let two_x1_h_sq = Self::fpk_elem_scalar_mul_mont::<N>(&x1_h_sq, &two, ctx, k);
        let temp = Self::fpk_elem_sub::<N>(&r_sq, &h_cu, prime, k);
        let x_new = Self::fpk_elem_sub::<N>(&temp, &two_x1_h_sq, prime, k);

        // Y3 = R*(X1*H² - X3) - Y1*H³
        let x1_h_sq_minus_x = Self::fpk_elem_sub::<N>(&x1_h_sq, &x_new, prime, k);
        let r_term = Self::fpk_elem_mul_sparse_mont::<N>(&r, &x1_h_sq_minus_x, sparse_mod, ctx, k);
        let y1_h_cu = Self::fpk_elem_mul_sparse_mont::<N>(y1, &h_cu, sparse_mod, ctx, k);
        let y_new = Self::fpk_elem_sub::<N>(&r_term, &y1_h_cu, prime, k);

        // Z3 = Z1*H
        let z_new = Self::fpk_elem_mul_sparse_mont::<N>(z1, &h, sparse_mod, ctx, k);

        (x_new, y_new, z_new)
    }

    /// Helper to normalize an extension field element to exactly length k
    #[inline]
    fn fpk_normalize<const N: usize>(a: &[BigInt<N>], k: usize) -> Vec<BigInt<N>> {
        (0..k).map(|i| a.get(i).cloned().unwrap_or_else(BigInt::zero)).collect()
    }

    /// ECPk scalar multiplication using Jacobian coordinates
    /// Only ONE inversion at the very end to convert back to affine!
    fn ecpk_scalar_mul_jacobian<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>),
        k_scalar: &BigInt<N>,
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
        k: usize,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        if k_scalar.is_zero() {
            return None;
        }

        // OPTIMIZATION 1: Create Montgomery context ONCE for all base-field muls!
        // Montgomery mul is MUCH faster than shift-and-add mod_mul
        let ctx = MontgomeryCtx::new(*prime)?;

        // OPTIMIZATION 2: Precompute sparse modulus ONCE for all multiplications!
        // For BN254 k=12 with only 2 non-zero terms, this is 6x faster per mul
        let sparse_mod = Self::fpk_compute_sparse_modulus::<N>(modulus_poly, k);

        // Normalize inputs once at the start - avoid repeated normalization in inner loops
        let p_norm = (
            Self::fpk_normalize::<N>(&p.0, k),
            Self::fpk_normalize::<N>(&p.1, k),
        );
        let a_norm = Self::fpk_normalize::<N>(a, k);

        // Convert scalar to NAF for fewer additions
        let naf = bigint_to_naf(k_scalar);

        // Precompute -P for NAF: negate y coordinate
        let neg_p = (
            p_norm.0.clone(),
            Self::fpk_elem_neg::<N>(&p_norm.1, prime, k),
        );

        // Start with point at infinity in Jacobian coords
        let mut result: (Vec<BigInt<N>>, Vec<BigInt<N>>, Vec<BigInt<N>>) = 
            (Self::fpk_zero::<N>(k), Self::fpk_one::<N>(k), Self::fpk_zero::<N>(k));

        // Process NAF from most significant to least significant
        for &digit in naf.iter().rev() {
            // Double - uses sparse modulus + Montgomery for fast muls!
            result = Self::ecpk_jacobian_double_sparse::<N>(&result, &a_norm, &sparse_mod, &ctx, k);

            // Add or subtract based on NAF digit - also uses sparse + Montgomery!
            if digit == 1 {
                result = Self::ecpk_jacobian_add_mixed_sparse::<N>(&result, &p_norm, &a_norm, &sparse_mod, &ctx, k);
            } else if digit == -1 {
                result = Self::ecpk_jacobian_add_mixed_sparse::<N>(&result, &neg_p, &a_norm, &sparse_mod, &ctx, k);
            }
        }

        // Convert back to affine - this is the ONLY inversion!
        Self::ecpk_jacobian_to_affine::<N>(&result, modulus_poly, prime, k)
    }

    // Type alias for ECPk points: None = infinity, Some((x, y)) = affine point
    // This replaces the old convention of all-zero coords meaning infinity
    // LEGACY: kept for compatibility, but ecpk_scalar_mul now uses Jacobian

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
        let point = p?;
        
        // DISPATCH to specialized versions
        match k {
            12 => {
                // BN254 k=12 - use MONTGOMERY DOMAIN throughout (4x faster than before!)
                let px = Self::fp_k_from_vec::<N, 12>(&point.0);
                let py = Self::fp_k_from_vec::<N, 12>(&point.1);
                let result = Self::ec_fp12_mont_scalar_mul::<N>(&px, &py, k_scalar, modulus_poly, prime)?;
                Some((Self::fp_k_to_vec::<N, 12>(&result.0), Self::fp_k_to_vec::<N, 12>(&result.1)))
            }
            6 => {
                // BLS12-381 sextic twist
                let px = Self::fp_k_from_vec::<N, 6>(&point.0);
                let py = Self::fp_k_from_vec::<N, 6>(&point.1);
                let a_fixed = Self::fp_k_from_vec::<N, 6>(a);
                let result = Self::ecpk_scalar_mul_fixed::<N, 6>(&px, &py, k_scalar, &a_fixed, modulus_poly, prime)?;
                Some((Self::fp_k_to_vec::<N, 6>(&result.0), Self::fp_k_to_vec::<N, 6>(&result.1)))
            }
            2 => {
                // Quadratic extension
                let px = Self::fp_k_from_vec::<N, 2>(&point.0);
                let py = Self::fp_k_from_vec::<N, 2>(&point.1);
                let a_fixed = Self::fp_k_from_vec::<N, 2>(a);
                let result = Self::ecpk_scalar_mul_fixed::<N, 2>(&px, &py, k_scalar, &a_fixed, modulus_poly, prime)?;
                Some((Self::fp_k_to_vec::<N, 2>(&result.0), Self::fp_k_to_vec::<N, 2>(&result.1)))
            }
            _ => {
                // Fallback to Vec-based Jacobian for other k values
                Self::ecpk_scalar_mul_jacobian::<N>(point, k_scalar, a, modulus_poly, prime, k)
            }
        }
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
