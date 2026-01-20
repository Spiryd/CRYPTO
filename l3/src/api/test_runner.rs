//! Challenge test runner for validating DH and Schnorr implementations
//!
//! This module contains the ChallengeTestRunner which runs all the crypto
//! implementations against the remote API for validation.

use crate::bigint::BigInt;
use crate::montgomery::MontgomeryCtx;

use super::client::CryptoApiClient;
use super::error::ApiError;
use super::helpers::{
    BIGINT_LIMBS, bigint_to_padded_hex, bigint_to_padded_hex_upper, bytes_to_hex,
    generate_random_bigint, hash_to_scalar, hex_bit_length_str, hex_to_bytes,
    select_limbs_from_bits,
};
use super::types::*;

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
    fn test_modp_dh_with_limbs<const N: usize>(&self, params: &ModPParams) -> Result<(), ApiError> {
        let order = BigInt::<N>::from_hex(&params.order);
        let generator = BigInt::<N>::from_hex(&params.generator);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let ctx = MontgomeryCtx::<N>::new(modulus).expect("odd modulus required");
        let modulus = &ctx.modulus;

        // Generate random private key
        let private_key = generate_random_bigint(&order);

        // Compute public key
        let public_key = ctx.mod_pow_noreduce(&generator, &private_key);

        // Format for API
        let modulus_byte_len = modulus.bit_length().div_ceil(8);
        let client_public_hex = bigint_to_padded_hex_upper(&public_key, modulus_byte_len);

        // Send to API
        let response = self.client.test_dh_modp(&client_public_hex)?;

        // Parse server public key
        let server_public = BigInt::<N>::from_hex(&response.server_public);

        // Compute shared secret
        let our_shared_secret = ctx.mod_pow_noreduce(&server_public, &private_key);
        let our_shared_hex = bigint_to_padded_hex_upper(&our_shared_secret, modulus_byte_len);

        // Compare (our_shared_hex is already uppercase, use case-insensitive comparison to avoid allocation)
        if our_shared_hex.eq_ignore_ascii_case(&response.shared_secret) {
            Ok(())
        } else {
            Err(ApiError::Validation(
                "DH shared secrets don't match".to_string(),
            ))
        }
    }

    /// Test ModP DH exchange (size-dispatched)
    pub fn test_modp_dh(&self, params: &ModPParams) -> Result<(), ApiError> {
        let bits = hex_bit_length_str(&params.modulus);
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_modp_dh_with_limbs::<4>(self, params),
            6 => Self::test_modp_dh_with_limbs::<6>(self, params),
            9 => Self::test_modp_dh_with_limbs::<9>(self, params),
            32 => Self::test_modp_dh_with_limbs::<32>(self, params),
            _ => Self::test_modp_dh_with_limbs::<{ BIGINT_LIMBS }>(self, params),
        }
    }

    /// Test ModP Schnorr signature verification
    fn test_modp_signature_with_limbs<const N: usize>(
        &self,
        params: &ModPParams,
        message: &str,
    ) -> Result<(), ApiError> {
        let response = self.client.test_signature(ChallengeType::Modp, message)?;

        let order = BigInt::<N>::from_hex(&params.order);
        let generator = BigInt::<N>::from_hex(&params.generator);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let ctx = MontgomeryCtx::<N>::new(modulus).expect("odd modulus required");
        let modulus = &ctx.modulus;

        let public_key_str = response
            .public
            .as_str()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let public_key = BigInt::<N>::from_hex(public_key_str);

        let sig = &response.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);

        // Verify: R' = g^s * y^e mod p
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        let g_s = ctx.mod_pow_noreduce(&generator, &s);
        let y_e = ctx.mod_pow_noreduce(&public_key, &e_scalar);
        let r_prime = ctx.mod_mul_noreduce(&g_s, &y_e);

        // Compute e' = H(R' || m) with lowercase hex encoding
        let modulus_byte_len = modulus.bit_length().div_ceil(8);
        let r_hex = bigint_to_padded_hex(&r_prime, modulus_byte_len);
        let r_encoded = format!(r#""{}""#, r_hex);

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(format!(
                "Expected: {}, Got: {}",
                bytes_to_hex(&e_bytes),
                bytes_to_hex(e_prime.as_slice())
            )))
        }
    }

    /// Test ModP signature (size-dispatched)
    pub fn test_modp_signature(&self, params: &ModPParams, message: &str) -> Result<(), ApiError> {
        let bits = hex_bit_length_str(&params.modulus);
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_modp_signature_with_limbs::<4>(self, params, message),
            6 => Self::test_modp_signature_with_limbs::<6>(self, params, message),
            9 => Self::test_modp_signature_with_limbs::<9>(self, params, message),
            32 => Self::test_modp_signature_with_limbs::<32>(self, params, message),
            _ => Self::test_modp_signature_with_limbs::<{ BIGINT_LIMBS }>(self, params, message),
        }
    }

    /// Run all tests for ModP
    pub fn run_modp_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Modp);

        // Fetch params once and reuse for both tests
        let params = match self.client.get_modp_params() {
            Ok(p) => p,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(format!("Failed to fetch params: {}", e));
                result.signature_success = false;
                result.signature_error = Some(format!("Failed to fetch params: {}", e));
                return result;
            }
        };

        match self.test_modp_dh(params) {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }

        match self.test_modp_signature(params, "test message") {
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
    fn f2m_mul<const N: usize>(
        a: &BigInt<N>,
        b: &BigInt<N>,
        reduction_poly: &BigInt<N>,
        m: usize,
    ) -> BigInt<N> {
        // Polynomial multiplication using shift-and-XOR
        let mut result = BigInt::<N>::zero();
        let mut a_shifted = *a;

        // Multiply: for each bit of b, if set, XOR the shifted a
        for i in 0..m {
            // Check if bit i of b is set
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            if limb_idx < N && (b.limbs()[limb_idx] >> bit_idx) & 1 == 1 {
                result = result ^ a_shifted;
            }

            // Shift a left by 1 (multiply by x)
            a_shifted = a_shifted << 1;

            // Reduce if degree reaches m (bit m is set)
            let m_limb_idx = m / 64;
            let m_bit_idx = m % 64;
            if m_limb_idx < N && (a_shifted.limbs()[m_limb_idx] >> m_bit_idx) & 1 == 1 {
                // Clear bit m and XOR with reduction polynomial
                // x^m ≡ reduction_poly (mod irreducible)
                a_shifted = a_shifted ^ (BigInt::<N>::one() << m);
                a_shifted = a_shifted ^ *reduction_poly;
            }
        }

        // Final reduction of result (it may have degree up to 2m-2 before reduction)
        Self::f2m_reduce::<N>(&result, reduction_poly, m)
    }

    /// Reduce a polynomial modulo x^m + reduction_poly
    fn f2m_reduce<const N: usize>(
        a: &BigInt<N>,
        reduction_poly: &BigInt<N>,
        m: usize,
    ) -> BigInt<N> {
        let mut result = *a;

        // Reduce from highest possible degree down to m-1
        // After multiplication, max degree is 2*(m-1) = 2m-2
        for i in (m..2 * m).rev() {
            let limb_idx = i / 64;
            let bit_idx = i % 64;

            if limb_idx < N && (result.limbs()[limb_idx] >> bit_idx) & 1 == 1 {
                // Bit i is set, need to reduce
                // x^i = x^(i-m) * x^m ≡ x^(i-m) * reduction_poly
                let shift = i - m;
                result = result ^ (BigInt::<N>::one() << i); // Clear bit i
                result = result ^ (*reduction_poly << shift); // Add shifted reduction poly
            }
        }

        result
    }

    /// Binary field exponentiation
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

    /// Test F2m DH exchange
    fn test_f2m_dh_with_limbs<const N: usize>(&self, params: &F2mParams) -> Result<(), ApiError> {
        let generator = BigInt::<N>::from_hex(&params.generator);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let m = params.extension;

        // Generate private key - use small fixed key for faster testing
        let private_key = BigInt::<N>::from_u64(0xFF);
        let public_key = Self::f2m_pow::<N>(&generator, &private_key, &modulus, m);

        // Format for API
        let byte_len = m.div_ceil(8);
        let client_public_hex = bigint_to_padded_hex_upper(&public_key, byte_len);

        // Send to API
        let response = self.client.test_dh_f2m(&client_public_hex)?;

        // Parse server public key
        let server_public = BigInt::<N>::from_hex(&response.server_public);

        // Compute shared secret
        let our_shared_secret = Self::f2m_pow::<N>(&server_public, &private_key, &modulus, m);
        let our_shared_hex = bigint_to_padded_hex_upper(&our_shared_secret, byte_len);

        // Compare (our_shared_hex is already uppercase from bigint_to_padded_hex_upper)
        if our_shared_hex.eq_ignore_ascii_case(&response.shared_secret) {
            Ok(())
        } else {
            Err(ApiError::Validation(
                "F2m DH shared secrets don't match".to_string(),
            ))
        }
    }

    /// Test F2m DH (size-dispatched)
    pub fn test_f2m_dh(&self, params: &F2mParams) -> Result<(), ApiError> {
        // Use 2*m bits capacity to accommodate intermediate degrees up to 2m-2
        let bits = params.extension * 2;
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_f2m_dh_with_limbs::<4>(self, params),
            6 => Self::test_f2m_dh_with_limbs::<6>(self, params),
            9 => Self::test_f2m_dh_with_limbs::<9>(self, params),
            32 => Self::test_f2m_dh_with_limbs::<32>(self, params),
            _ => Self::test_f2m_dh_with_limbs::<{ BIGINT_LIMBS }>(self, params),
        }
    }

    /// Test F2m Schnorr signature verification
    fn test_f2m_signature_with_limbs<const N: usize>(
        &self,
        params: &F2mParams,
        message: &str,
    ) -> Result<(), ApiError> {
        let response = self.client.test_signature(ChallengeType::F2m, message)?;

        let order = BigInt::<N>::from_hex(&params.order);
        let generator = BigInt::<N>::from_hex(&params.generator);
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let m = params.extension;

        let public_key_str = response
            .public
            .as_str()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let public_key = BigInt::<N>::from_hex(public_key_str);

        let sig = &response.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);

        // Verify: R' = g^s * y^e in F_2^m
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        let g_s = Self::f2m_pow::<N>(&generator, &s, &modulus, m);
        let y_e = Self::f2m_pow::<N>(&public_key, &e_scalar, &modulus, m);
        let r_prime = Self::f2m_mul::<N>(&g_s, &y_e, &modulus, m);

        // Compute e' = H(R' || m) with lowercase hex encoding
        let byte_len = m.div_ceil(8);
        let r_hex = bigint_to_padded_hex(&r_prime, byte_len);
        let r_encoded = format!(r#""{}""#, r_hex);

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(format!(
                "Expected: {}, Got: {}",
                bytes_to_hex(&e_bytes),
                bytes_to_hex(e_prime.as_slice())
            )))
        }
    }

    /// Test F2m signature (size-dispatched)
    pub fn test_f2m_signature(&self, params: &F2mParams, message: &str) -> Result<(), ApiError> {
        // Use 2*m bits capacity to accommodate intermediate degrees up to 2m-2
        let bits = params.extension * 2;
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_f2m_signature_with_limbs::<4>(self, params, message),
            6 => Self::test_f2m_signature_with_limbs::<6>(self, params, message),
            9 => Self::test_f2m_signature_with_limbs::<9>(self, params, message),
            32 => Self::test_f2m_signature_with_limbs::<32>(self, params, message),
            _ => Self::test_f2m_signature_with_limbs::<{ BIGINT_LIMBS }>(self, params, message),
        }
    }

    /// Run all tests for F2m
    pub fn run_f2m_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::F2m);

        // Fetch params once and reuse for both tests
        let params = match self.client.get_f2m_params() {
            Ok(p) => p,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(format!("Failed to fetch params: {}", e));
                result.signature_success = false;
                result.signature_error = Some(format!("Failed to fetch params: {}", e));
                return result;
            }
        };

        match self.test_f2m_dh(params) {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }

        match self.test_f2m_signature(params, "test message") {
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
    /// Naive polynomial multiplication O(n²) - fallback
    fn fpk_mul_naive<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
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
        product
    }

    /// Karatsuba polynomial multiplication O(n^1.585) - for k >= 3
    fn fpk_mul_karatsuba<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        let k = a.len();

        // Base case: use naive for small inputs
        if k <= 2 {
            return Self::fpk_mul_naive::<N>(a, b, prime);
        }

        let m = k.div_ceil(2);

        // Split: a = a_h * x^m + a_l,  b = b_h * x^m + b_l
        let (a_l, a_h) = a.split_at(m);
        let (b_l, b_h) = b.split_at(m);

        // Pad to same length
        let mut a_h_padded = a_h.to_vec();
        let mut b_h_padded = b_h.to_vec();
        while a_h_padded.len() < m {
            a_h_padded.push(BigInt::zero());
        }
        while b_h_padded.len() < m {
            b_h_padded.push(BigInt::zero());
        }

        // Three recursive multiplications
        let z0 = Self::fpk_mul_karatsuba::<N>(a_l, b_l, prime);
        let z2 = Self::fpk_mul_karatsuba::<N>(&a_h_padded, &b_h_padded, prime);

        // (a_l + a_h) * (b_l + b_h)
        let mut a_sum = vec![BigInt::<N>::zero(); m];
        let mut b_sum = vec![BigInt::<N>::zero(); m];
        for i in 0..m {
            a_sum[i] = a_l[i].mod_add(&a_h_padded[i], prime);
            b_sum[i] = b_l[i].mod_add(&b_h_padded[i], prime);
        }
        let z1_raw = Self::fpk_mul_karatsuba::<N>(&a_sum, &b_sum, prime);

        // z1 = (a_l + a_h)(b_l + b_h) - z0 - z2
        let mut z1 = vec![BigInt::<N>::zero(); z1_raw.len()];
        for i in 0..z1_raw.len() {
            z1[i] = z1_raw[i];
            if i < z0.len() {
                z1[i] = z1[i].mod_sub(&z0[i], prime);
            }
            if i < z2.len() {
                z1[i] = z1[i].mod_sub(&z2[i], prime);
            }
        }

        // Combine: result = z2*x^(2m) + z1*x^m + z0
        let mut result = vec![BigInt::<N>::zero(); 2 * k - 1];

        // Add z0
        for i in 0..z0.len() {
            result[i] = result[i].mod_add(&z0[i], prime);
        }

        // Add z1 * x^m
        for i in 0..z1.len() {
            if i + m < result.len() {
                result[i + m] = result[i + m].mod_add(&z1[i], prime);
            }
        }

        // Add z2 * x^(2m)
        for i in 0..z2.len() {
            if i + 2 * m < result.len() {
                result[i + 2 * m] = result[i + 2 * m].mod_add(&z2[i], prime);
            }
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

        // Use Karatsuba for polynomial multiplication
        let product = Self::fpk_mul_karatsuba::<N>(a, b, prime);

        // Reduce mod irreducible polynomial
        // modulus_poly represents x^k + c_{k-1}*x^{k-1} + ... + c_0
        // We reduce by replacing x^k with -(c_{k-1}*x^{k-1} + ... + c_0)
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

    /// Extension field exponentiation
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

    /// Test Fpk DH exchange
    fn test_fpk_dh_with_limbs<const N: usize>(&self, params: &FpkParams) -> Result<(), ApiError> {
        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let _k = params.extension;

        // Parse generator and modulus polynomial
        let generator: Vec<BigInt<N>> = params
            .generator
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        let modulus_poly: Vec<BigInt<N>> =
            params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();

        // Generate private key - use small fixed key for faster testing
        let private_key = BigInt::<N>::from_u64(0xFF);

        // Compute public key: g^sk in F_p^k
        let public_key = Self::fpk_pow::<N>(&generator, &private_key, &modulus_poly, &prime);

        // Format for API
        let prime_byte_len = prime.bit_length().div_ceil(8);
        let client_public: Vec<String> = public_key
            .iter()
            .map(|c| bigint_to_padded_hex_upper(c, prime_byte_len))
            .collect();

        // Send to API
        let response = self.client.test_dh_fpk(client_public)?;

        // Parse server public key
        let server_public: Vec<BigInt<N>> = response
            .server_public
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();

        // Compute shared secret
        let our_shared_secret =
            Self::fpk_pow::<N>(&server_public, &private_key, &modulus_poly, &prime);
        let our_shared_hex: Vec<String> = our_shared_secret
            .iter()
            .map(|c| bigint_to_padded_hex_upper(c, prime_byte_len))
            .collect();

        // Compare (use case-insensitive comparison to avoid allocations)
        let expected: Vec<&str> = response.shared_secret.iter().map(|s| s.as_str()).collect();
        let got: Vec<&str> = our_shared_hex.iter().map(|s| s.as_str()).collect();

        if expected.len() == got.len()
            && expected
                .iter()
                .zip(got.iter())
                .all(|(e, g)| e.eq_ignore_ascii_case(g))
        {
            Ok(())
        } else {
            Err(ApiError::Validation(format!(
                "Fpk DH shared secrets don't match: expected {:?}, got {:?}",
                expected, got
            )))
        }
    }

    /// Test Fpk Schnorr signature verification
    fn test_fpk_signature_with_limbs<const N: usize>(
        &self,
        params: &FpkParams,
        message: &str,
    ) -> Result<(), ApiError> {
        let response = self.client.test_signature(ChallengeType::Fpk, message)?;

        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let order = BigInt::<N>::from_hex(&params.order);
        let _k = params.extension;

        let generator: Vec<BigInt<N>> = params
            .generator
            .iter()
            .map(|s| BigInt::from_hex(s))
            .collect();
        let modulus_poly: Vec<BigInt<N>> =
            params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();

        // Parse public key (array of coefficients)
        let public_key_arr = response
            .public
            .as_array()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let public_key: Vec<BigInt<N>> = public_key_arr
            .iter()
            .map(|v| BigInt::from_hex(v.as_str().unwrap_or("0")))
            .collect();

        let sig = &response.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);

        // Verify: R' = g^s * y^e in F_p^k
        let e_scalar = hash_to_scalar(&e_bytes, &order);
        let g_s = Self::fpk_pow::<N>(&generator, &s, &modulus_poly, &prime);
        let y_e = Self::fpk_pow::<N>(&public_key, &e_scalar, &modulus_poly, &prime);
        let r_prime = Self::fpk_mul::<N>(&g_s, &y_e, &modulus_poly, &prime);

        // Compute e' = H(R' || m) with lowercase hex encoding
        let prime_byte_len = prime.bit_length().div_ceil(8);
        let r_hex: Vec<String> = r_prime
            .iter()
            .map(|c| bigint_to_padded_hex(c, prime_byte_len))
            .collect();
        let r_encoded = serde_json::to_string(&r_hex).unwrap();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(format!(
                "Expected: {}, Got: {}",
                bytes_to_hex(&e_bytes),
                bytes_to_hex(e_prime.as_slice())
            )))
        }
    }

    /// Test Fpk DH (size-dispatched)
    pub fn test_fpk_dh(&self, params: &FpkParams) -> Result<(), ApiError> {
        let bits = hex_bit_length_str(&params.prime_base);
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_fpk_dh_with_limbs::<4>(self, params),
            6 => Self::test_fpk_dh_with_limbs::<6>(self, params),
            9 => Self::test_fpk_dh_with_limbs::<9>(self, params),
            32 => Self::test_fpk_dh_with_limbs::<32>(self, params),
            _ => Self::test_fpk_dh_with_limbs::<{ BIGINT_LIMBS }>(self, params),
        }
    }

    /// Test Fpk signature (size-dispatched)
    pub fn test_fpk_signature(&self, params: &FpkParams, message: &str) -> Result<(), ApiError> {
        // Size by the larger of prime and order to ensure scalar reduction correctness
        let prime_bits = hex_bit_length_str(&params.prime_base);
        let order_bits = hex_bit_length_str(&params.order);
        let limbs = select_limbs_from_bits(prime_bits.max(order_bits));
        match limbs {
            4 => Self::test_fpk_signature_with_limbs::<4>(self, params, message),
            6 => Self::test_fpk_signature_with_limbs::<6>(self, params, message),
            9 => Self::test_fpk_signature_with_limbs::<9>(self, params, message),
            32 => Self::test_fpk_signature_with_limbs::<32>(self, params, message),
            _ => Self::test_fpk_signature_with_limbs::<{ BIGINT_LIMBS }>(self, params, message),
        }
    }

    /// Run all tests for Fpk
    pub fn run_fpk_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Fpk);

        // Fetch params once and reuse for both tests
        let params = match self.client.get_fpk_params() {
            Ok(p) => p,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(format!("Failed to fetch params: {}", e));
                result.signature_success = false;
                result.signature_error = Some(format!("Failed to fetch params: {}", e));
                return result;
            }
        };

        match self.test_fpk_dh(params) {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }

        match self.test_fpk_signature(params, "test message") {
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
    fn ecp_add<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        q: &(BigInt<N>, BigInt<N>),
        a: &BigInt<N>,
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
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
            let three = BigInt::<N>::from_u64(3);
            let two = BigInt::<N>::from_u64(2);
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
        let y3 = lambda
            .mod_mul(&x1.mod_sub(&x3, modulus), modulus)
            .mod_sub(y1, modulus);

        Some((x3, y3))
    }

    /// Modular inverse using extended Euclidean algorithm
    fn mod_inverse<const N: usize>(a: &BigInt<N>, modulus: &BigInt<N>) -> Option<BigInt<N>> {
        // Extended Euclidean algorithm using signed representation
        // We track t0, t1 and compute inverse
        let mut old_r = *modulus;
        let mut r = a.modulo(modulus);

        // Track t as (value, is_negative)
        let mut old_t: (BigInt<N>, bool) = (BigInt::zero(), false);
        let mut t: (BigInt<N>, bool) = (BigInt::one(), false);

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

    // ========================================================================
    // Jacobian Coordinates for Elliptic Curves (ECP)
    // ========================================================================
    // In Jacobian coordinates, a point (x,y) is represented as (X,Y,Z) where:
    // x = X/Z², y = Y/Z³, and point at infinity has Z = 0
    // This eliminates costly modular inversions during scalar multiplication

    /// Convert affine point to Jacobian coordinates
    fn affine_to_jacobian<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
    ) -> (BigInt<N>, BigInt<N>, BigInt<N>) {
        (p.0, p.1, BigInt::<N>::one())
    }

    /// Convert Jacobian point back to affine coordinates
    fn jacobian_to_affine<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        let (x, y, z) = p;

        if z.is_zero() {
            return None; // Point at infinity
        }

        // z_inv = 1/Z (mod p)
        let z_inv = Self::mod_inverse::<N>(z, modulus)?;

        // z_inv² and z_inv³
        let z_inv_sq = z_inv.mod_mul(&z_inv, modulus);
        let z_inv_cu = z_inv_sq.mod_mul(&z_inv, modulus);

        // x = X * z_inv²
        let affine_x = x.mod_mul(&z_inv_sq, modulus);
        // y = Y * z_inv³
        let affine_y = y.mod_mul(&z_inv_cu, modulus);

        Some((affine_x, affine_y))
    }

    /// Jacobian point doubling: faster than addition when doubling same point
    fn jacobian_double<const N: usize>(
        p: &(BigInt<N>, BigInt<N>, BigInt<N>),
        a: &BigInt<N>,
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>, BigInt<N>)> {
        let (x, y, z) = p;

        if z.is_zero() {
            return None; // Point at infinity
        }

        if y.is_zero() {
            return None; // Point at infinity
        }

        let two = BigInt::<N>::from_u64(2);
        let three = BigInt::<N>::from_u64(3);
        let four = BigInt::<N>::from_u64(4);
        let eight = BigInt::<N>::from_u64(8);

        // S = 4*X*Y²
        let y_sq = y.mod_mul(y, modulus);
        let four_x_y_sq = four.mod_mul(&x.mod_mul(&y_sq, modulus), modulus);

        // M = 3*X² + a*Z⁴
        let x_sq = x.mod_mul(x, modulus);
        let z_sq = z.mod_mul(z, modulus);
        let z_fourth = z_sq.mod_mul(&z_sq, modulus);
        let three_x_sq = three.mod_mul(&x_sq, modulus);
        let m = three_x_sq.mod_add(&a.mod_mul(&z_fourth, modulus), modulus);

        // X' = M² - 2*S
        let m_sq = m.mod_mul(&m, modulus);
        let two_s = two.mod_mul(&four_x_y_sq, modulus);
        let x_new = m_sq.mod_sub(&two_s, modulus);

        // Y' = M*(S - X') - 8*Y⁴
        let y_fourth = y_sq.mod_mul(&y_sq, modulus);
        let eight_y_fourth = eight.mod_mul(&y_fourth, modulus);
        let y_new = m
            .mod_mul(&four_x_y_sq.mod_sub(&x_new, modulus), modulus)
            .mod_sub(&eight_y_fourth, modulus);

        // Z' = 2*Y*Z
        let z_new = two.mod_mul(&y.mod_mul(z, modulus), modulus);

        Some((x_new, y_new, z_new))
    }

    /// Jacobian point addition: optimized for different points
    fn jacobian_add<const N: usize>(
        p1: &(BigInt<N>, BigInt<N>, BigInt<N>),
        p2: &(BigInt<N>, BigInt<N>, BigInt<N>),
        a: &BigInt<N>,
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>, BigInt<N>)> {
        let (x1, y1, z1) = p1;
        let (x2, y2, z2) = p2;

        // Handle point at infinity cases
        if z1.is_zero() {
            return Some(*p2);
        }
        if z2.is_zero() {
            return Some(*p1);
        }

        let two = BigInt::<N>::from_u64(2);

        // Z1Z1 = Z1²
        let z1_sq = z1.mod_mul(z1, modulus);
        // Z2Z2 = Z2²
        let z2_sq = z2.mod_mul(z2, modulus);

        // U1 = X1*Z2Z2
        let u1 = x1.mod_mul(&z2_sq, modulus);
        // U2 = X2*Z1Z1
        let u2 = x2.mod_mul(&z1_sq, modulus);

        // S1 = Y1*Z2*Z2Z2
        let s1 = y1.mod_mul(&z2.mod_mul(&z2_sq, modulus), modulus);
        // S2 = Y2*Z1*Z1Z1
        let s2 = y2.mod_mul(&z1.mod_mul(&z1_sq, modulus), modulus);

        // H = U2-U1
        let h = u2.mod_sub(&u1, modulus);
        // R = S2-S1
        let r = s2.mod_sub(&s1, modulus);

        // If H = 0
        if h.is_zero() {
            if r.is_zero() {
                // Points are equal, use doubling
                return Self::jacobian_double::<N>(p1, a, modulus);
            } else {
                // Points are negatives, return infinity
                return None;
            }
        }

        // HH = H²
        let hh = h.mod_mul(&h, modulus);
        // HHH = H*HH
        let hhh = h.mod_mul(&hh, modulus);
        // V = U1*HH
        let v = u1.mod_mul(&hh, modulus);

        // X3 = R² - HHH - 2*V
        let r_sq = r.mod_mul(&r, modulus);
        let two_v = two.mod_mul(&v, modulus);
        let x3 = r_sq.mod_sub(&hhh, modulus).mod_sub(&two_v, modulus);

        // Y3 = R*(V - X3) - S1*HHH
        let y3 = r
            .mod_mul(&v.mod_sub(&x3, modulus), modulus)
            .mod_sub(&s1.mod_mul(&hhh, modulus), modulus);

        // Z3 = Z1*Z2*H
        let z3 = z1.mod_mul(&z2.mod_mul(&h, modulus), modulus);

        Some((x3, y3, z3))
    }

    /// EC scalar multiplication over prime field using Jacobian coordinates (no inversions until end)
    fn ecp_scalar_mul<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        k: &BigInt<N>,
        a: &BigInt<N>,
        modulus: &BigInt<N>,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
        if k.is_zero() {
            return None; // Point at infinity
        }

        // Convert to Jacobian coordinates
        let mut result: Option<(BigInt<N>, BigInt<N>, BigInt<N>)> = None;
        let mut base = Self::affine_to_jacobian::<N>(p);
        let mut k = *k;

        while !k.is_zero() {
            if k.limbs()[0] & 1 == 1 {
                result = match result {
                    None => Some(base),
                    Some(r) => Self::jacobian_add::<N>(&r, &base, a, modulus),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::jacobian_double::<N>(&base, a, modulus)?;
            }
        }

        // Convert back to affine coordinates
        result.and_then(|p| Self::jacobian_to_affine::<N>(&p, modulus))
    }

    /// Test ECP DH exchange
    fn test_ecp_dh_with_limbs<const N: usize>(&self, params: &ECPParams) -> Result<(), ApiError> {
        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let _order = BigInt::<N>::from_hex(&params.order);
        let a = BigInt::<N>::from_hex(&params.a);
        let gx = BigInt::<N>::from_hex(&params.generator.x);
        let gy = BigInt::<N>::from_hex(&params.generator.y);
        let generator = (gx, gy);

        // Use a small private key for faster testing (0xFF = 255, only 8 bits set)
        let private_key = BigInt::<N>::from_u64(0xFF);

        // Compute public key: [sk]G
        let public_key = Self::ecp_scalar_mul::<N>(&generator, &private_key, &a, &modulus)
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
            BigInt::<N>::from_hex(&response.server_public.x),
            BigInt::<N>::from_hex(&response.server_public.y),
        );

        // Compute shared secret
        let our_shared = Self::ecp_scalar_mul::<N>(&server_public, &private_key, &a, &modulus)
            .ok_or_else(|| ApiError::Validation("Failed to compute shared secret".to_string()))?;
        let our_shared_x = bigint_to_padded_hex_upper(&our_shared.0, byte_len);
        let our_shared_y = bigint_to_padded_hex_upper(&our_shared.1, byte_len);

        // Compare (use case-insensitive comparison to avoid allocations)
        if our_shared_x.eq_ignore_ascii_case(&response.shared_secret.x)
            && our_shared_y.eq_ignore_ascii_case(&response.shared_secret.y)
        {
            Ok(())
        } else {
            Err(ApiError::Validation(
                "ECP DH shared secrets don't match".to_string(),
            ))
        }
    }

    /// Test ECP DH (size-dispatched)
    pub fn test_ecp_dh(&self, params: &ECPParams) -> Result<(), ApiError> {
        let bits = hex_bit_length_str(&params.modulus);
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_ecp_dh_with_limbs::<4>(self, params),
            6 => Self::test_ecp_dh_with_limbs::<6>(self, params),
            9 => Self::test_ecp_dh_with_limbs::<9>(self, params),
            32 => Self::test_ecp_dh_with_limbs::<32>(self, params),
            _ => Self::test_ecp_dh_with_limbs::<{ BIGINT_LIMBS }>(self, params),
        }
    }

    /// Test ECP Schnorr signature verification
    fn test_ecp_signature_with_limbs<const N: usize>(
        &self,
        params: &ECPParams,
        message: &str,
    ) -> Result<(), ApiError> {
        let response = self.client.test_signature(ChallengeType::Ecp, message)?;

        let modulus = BigInt::<N>::from_hex(&params.modulus);
        let order = BigInt::<N>::from_hex(&params.order);
        let a = BigInt::<N>::from_hex(&params.a);
        let gx = BigInt::<N>::from_hex(&params.generator.x);
        let gy = BigInt::<N>::from_hex(&params.generator.y);
        let generator = (gx, gy);

        // Parse public key
        let public_obj = response
            .public
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let pub_x = public_obj
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing x in public key".to_string()))?;
        let pub_y = public_obj
            .get("y")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing y in public key".to_string()))?;
        let public_key = (BigInt::<N>::from_hex(pub_x), BigInt::<N>::from_hex(pub_y));

        let sig = &response.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        // Verify: R' = [s]G + [e]Y
        let g_s = Self::ecp_scalar_mul::<N>(&generator, &s, &a, &modulus);
        let y_e = Self::ecp_scalar_mul::<N>(&public_key, &e_scalar, &a, &modulus);

        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecp_add::<N>(&gs, &ye, &a, &modulus),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        }
        .ok_or_else(|| ApiError::Validation("R' is point at infinity".to_string()))?;

        // Compute e' = H(R' || m) with lowercase hex encoding
        let byte_len = modulus.bit_length().div_ceil(8);
        let r_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&r_prime.0, byte_len),
            "y": bigint_to_padded_hex(&r_prime.1, byte_len)
        });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(format!(
                "Expected: {}, Got: {}",
                bytes_to_hex(&e_bytes),
                bytes_to_hex(e_prime.as_slice())
            )))
        }
    }

    /// Test ECP signature (size-dispatched)
    pub fn test_ecp_signature(&self, params: &ECPParams, message: &str) -> Result<(), ApiError> {
        let bits = hex_bit_length_str(&params.modulus);
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_ecp_signature_with_limbs::<4>(self, params, message),
            6 => Self::test_ecp_signature_with_limbs::<6>(self, params, message),
            9 => Self::test_ecp_signature_with_limbs::<9>(self, params, message),
            32 => Self::test_ecp_signature_with_limbs::<32>(self, params, message),
            _ => Self::test_ecp_signature_with_limbs::<{ BIGINT_LIMBS }>(self, params, message),
        }
    }

    /// Run all tests for ECP
    pub fn run_ecp_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Ecp);

        // Fetch params once and reuse for both tests
        let params = match self.client.get_ecp_params() {
            Ok(p) => p,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(format!("Failed to fetch params: {}", e));
                result.signature_success = false;
                result.signature_error = Some(format!("Failed to fetch params: {}", e));
                return result;
            }
        };

        match self.test_ecp_dh(params) {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }

        match self.test_ecp_signature(params, "test message") {
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
    fn ec2m_add<const N: usize>(
        p: &(BigInt<N>, BigInt<N>),
        q: &(BigInt<N>, BigInt<N>),
        a: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<(BigInt<N>, BigInt<N>)> {
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
            let y_over_x = Self::f2m_div::<N>(y1, x1, red_poly, m)?;
            let lambda = *x1 ^ y_over_x;

            // x₃ = λ² + λ + a
            let lambda_sq = Self::f2m_mul::<N>(&lambda, &lambda, red_poly, m);
            let x3 = lambda_sq ^ lambda ^ *a;

            // y₃ = x₁² + (λ + 1)x₃
            let x1_sq = Self::f2m_mul::<N>(x1, x1, red_poly, m);
            let lambda_plus_1 = lambda ^ BigInt::one();
            let y3 = x1_sq ^ Self::f2m_mul::<N>(&lambda_plus_1, &x3, red_poly, m);

            Some((x3, y3))
        } else {
            // Point addition
            // λ = (y₁ + y₂) / (x₁ + x₂)
            let y_sum = *y1 ^ *y2;
            let x_sum = *x1 ^ *x2;
            let lambda = Self::f2m_div::<N>(&y_sum, &x_sum, red_poly, m)?;

            // x₃ = λ² + λ + x₁ + x₂ + a
            let lambda_sq = Self::f2m_mul::<N>(&lambda, &lambda, red_poly, m);
            let x3 = lambda_sq ^ lambda ^ *x1 ^ *x2 ^ *a;

            // y₃ = λ(x₁ + x₃) + x₃ + y₁
            let y3 = Self::f2m_mul::<N>(&lambda, &(*x1 ^ x3), red_poly, m) ^ x3 ^ *y1;

            Some((x3, y3))
        }
    }

    /// Binary field division
    fn f2m_div<const N: usize>(
        a: &BigInt<N>,
        b: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<BigInt<N>> {
        let b_inv = Self::f2m_inverse::<N>(b, red_poly, m)?;
        Some(Self::f2m_mul::<N>(a, &b_inv, red_poly, m))
    }

    /// Binary field inverse using extended Euclidean algorithm for polynomials over GF(2)
    fn f2m_inverse<const N: usize>(
        a: &BigInt<N>,
        red_poly: &BigInt<N>,
        m: usize,
    ) -> Option<BigInt<N>> {
        if a.is_zero() {
            return None;
        }

        // The full modulus is x^m + red_poly
        let full_modulus = (BigInt::<N>::one() << m) ^ *red_poly;

        // Extended Euclidean algorithm for polynomials over GF(2)
        let mut u = *a;
        let mut v = full_modulus;
        let mut g1 = BigInt::<N>::one();
        let mut g2 = BigInt::<N>::zero();

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
            Some(Self::f2m_reduce::<N>(&g1, red_poly, m))
        } else if v.is_one() {
            Some(Self::f2m_reduce::<N>(&g2, red_poly, m))
        } else {
            // GCD is not 1, no inverse exists
            None
        }
    }

    /// EC scalar multiplication over binary field
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

    /// Test EC2m DH exchange
    fn test_ec2m_dh_with_limbs<const N: usize>(&self, params: &EC2mParams) -> Result<(), ApiError> {
        let m = params.extension;
        let red_poly = BigInt::<N>::from_hex(&params.modulus);
        let a = BigInt::<N>::from_hex(&params.a);
        let gx = BigInt::<N>::from_hex(&params.generator.x);
        let gy = BigInt::<N>::from_hex(&params.generator.y);
        let generator = (gx, gy);

        // Generate private key - use small fixed key for faster testing
        let private_key = BigInt::<N>::from_u64(0xFF);

        // Compute public key: [sk]G
        let public_key = Self::ec2m_scalar_mul::<N>(&generator, &private_key, &a, &red_poly, m)
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
            BigInt::<N>::from_hex(&response.server_public.x),
            BigInt::<N>::from_hex(&response.server_public.y),
        );

        // Compute shared secret
        let our_shared = Self::ec2m_scalar_mul::<N>(&server_public, &private_key, &a, &red_poly, m)
            .ok_or_else(|| {
                ApiError::Validation("Failed to compute EC2m shared secret".to_string())
            })?;
        let our_shared_x = bigint_to_padded_hex_upper(&our_shared.0, byte_len);
        let our_shared_y = bigint_to_padded_hex_upper(&our_shared.1, byte_len);

        // Compare (use case-insensitive comparison to avoid allocations)
        if our_shared_x.eq_ignore_ascii_case(&response.shared_secret.x)
            && our_shared_y.eq_ignore_ascii_case(&response.shared_secret.y)
        {
            Ok(())
        } else {
            Err(ApiError::Validation(
                "EC2m DH shared secrets don't match".to_string(),
            ))
        }
    }

    /// Test EC2m DH (size-dispatched)
    pub fn test_ec2m_dh(&self, params: &EC2mParams) -> Result<(), ApiError> {
        let bits = params.extension;
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_ec2m_dh_with_limbs::<4>(self, params),
            6 => Self::test_ec2m_dh_with_limbs::<6>(self, params),
            9 => Self::test_ec2m_dh_with_limbs::<9>(self, params),
            32 => Self::test_ec2m_dh_with_limbs::<32>(self, params),
            _ => Self::test_ec2m_dh_with_limbs::<{ BIGINT_LIMBS }>(self, params),
        }
    }

    /// Test EC2m Schnorr signature verification
    fn test_ec2m_signature_with_limbs<const N: usize>(
        &self,
        params: &EC2mParams,
        message: &str,
    ) -> Result<(), ApiError> {
        let response = self.client.test_signature(ChallengeType::Ec2m, message)?;

        let m = params.extension;
        let red_poly = BigInt::<N>::from_hex(&params.modulus);
        let order = BigInt::<N>::from_hex(&params.order);
        let a = BigInt::<N>::from_hex(&params.a);
        let gx = BigInt::<N>::from_hex(&params.generator.x);
        let gy = BigInt::<N>::from_hex(&params.generator.y);
        let generator = (gx, gy);

        // Parse public key
        let public_obj = response
            .public
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let pub_x = public_obj
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing x in public key".to_string()))?;
        let pub_y = public_obj
            .get("y")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::Validation("Missing y in public key".to_string()))?;
        let public_key = (BigInt::<N>::from_hex(pub_x), BigInt::<N>::from_hex(pub_y));

        let sig = &response.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        // Verify: R' = [s]G + [e]Y
        let g_s = Self::ec2m_scalar_mul::<N>(&generator, &s, &a, &red_poly, m);
        let y_e = Self::ec2m_scalar_mul::<N>(&public_key, &e_scalar, &a, &red_poly, m);

        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ec2m_add::<N>(&gs, &ye, &a, &red_poly, m),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        }
        .ok_or_else(|| ApiError::Validation("R' is point at infinity".to_string()))?;

        // Compute e' = H(R' || m)
        let byte_len = m.div_ceil(8);
        let r_obj = serde_json::json!({
            "x": bigint_to_padded_hex(&r_prime.0, byte_len),
            "y": bigint_to_padded_hex(&r_prime.1, byte_len)
        });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(format!(
                "Expected: {}, Got: {}",
                bytes_to_hex(&e_bytes),
                bytes_to_hex(e_prime.as_slice())
            )))
        }
    }

    /// Test EC2m signature (size-dispatched)
    pub fn test_ec2m_signature(&self, params: &EC2mParams, message: &str) -> Result<(), ApiError> {
        let bits = params.extension;
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_ec2m_signature_with_limbs::<4>(self, params, message),
            6 => Self::test_ec2m_signature_with_limbs::<6>(self, params, message),
            9 => Self::test_ec2m_signature_with_limbs::<9>(self, params, message),
            32 => Self::test_ec2m_signature_with_limbs::<32>(self, params, message),
            _ => Self::test_ec2m_signature_with_limbs::<{ BIGINT_LIMBS }>(self, params, message),
        }
    }

    /// Run all tests for EC2m
    pub fn run_ec2m_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Ec2m);

        // Fetch params once and reuse for both tests
        let params = match self.client.get_ec2m_params() {
            Ok(p) => p,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(format!("Failed to fetch params: {}", e));
                result.signature_success = false;
                result.signature_error = Some(format!("Failed to fetch params: {}", e));
                return result;
            }
        };

        match self.test_ec2m_dh(params) {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }

        match self.test_ec2m_signature(params, "test message") {
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
    fn ecpk_add<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>),
        q: &(Vec<BigInt<N>>, Vec<BigInt<N>>),
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        let (x1, y1) = p;
        let (x2, y2) = q;
        let _k = x1.len();

        // Check for point at infinity
        let is_inf = |v: &[BigInt<N>]| v.iter().all(|c| c.is_zero());
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
            let three = BigInt::<N>::from_u64(3);
            let two = BigInt::<N>::from_u64(2);

            let x1_sq = Self::fpk_mul::<N>(x1, x1, modulus_poly, prime);
            let three_x1_sq: Vec<_> = x1_sq.iter().map(|c| three.mod_mul(c, prime)).collect();
            let numerator = Self::fpk_add::<N>(&three_x1_sq, a, prime);

            let two_y1: Vec<_> = y1.iter().map(|c| two.mod_mul(c, prime)).collect();
            let denom_inv = Self::fpk_inverse::<N>(&two_y1, modulus_poly, prime)?;
            Self::fpk_mul::<N>(&numerator, &denom_inv, modulus_poly, prime)
        } else {
            // Point addition
            let y_diff = Self::fpk_sub::<N>(y2, y1, prime);
            let x_diff = Self::fpk_sub::<N>(x2, x1, prime);
            let denom_inv = Self::fpk_inverse::<N>(&x_diff, modulus_poly, prime)?;
            Self::fpk_mul::<N>(&y_diff, &denom_inv, modulus_poly, prime)
        };

        // x₃ = λ² - x₁ - x₂
        let lambda_sq = Self::fpk_mul::<N>(&lambda, &lambda, modulus_poly, prime);
        let x3 = Self::fpk_sub::<N>(&Self::fpk_sub::<N>(&lambda_sq, x1, prime), x2, prime);

        // y₃ = λ(x₁ - x₃) - y₁
        let x1_minus_x3 = Self::fpk_sub::<N>(x1, &x3, prime);
        let y3 = Self::fpk_sub::<N>(
            &Self::fpk_mul::<N>(&lambda, &x1_minus_x3, modulus_poly, prime),
            y1,
            prime,
        );

        Some((x3, y3))
    }

    /// Extension field addition
    fn fpk_add<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        a.iter()
            .zip(b.iter())
            .map(|(ai, bi)| ai.mod_add(bi, prime))
            .collect()
    }

    /// Extension field subtraction
    fn fpk_sub<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        a.iter()
            .zip(b.iter())
            .map(|(ai, bi)| ai.mod_sub(bi, prime))
            .collect()
    }

    /// Extension field inverse using extended Euclidean algorithm for polynomials
    fn fpk_inverse<const N: usize>(
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<Vec<BigInt<N>>> {
        let k = a.len();

        // Check if a is zero
        if a.iter().all(|c| c.is_zero()) {
            return None;
        }

        // Extended Euclidean algorithm for polynomials over F_p
        // We need to find b such that a * b ≡ 1 mod modulus_poly

        // Build full modulus polynomial: x^k + modulus_poly[k-1]*x^{k-1} + ... + modulus_poly[0]
        let mut full_mod = vec![BigInt::<N>::zero(); k + 1];
        full_mod[..k].copy_from_slice(&modulus_poly[..k]);
        full_mod[k] = BigInt::one();

        let mut r0 = full_mod;
        let mut r1: Vec<BigInt<N>> = a.to_vec();
        let mut s0 = vec![BigInt::<N>::zero(); k];
        let mut s1 = vec![BigInt::<N>::zero(); k];
        s1[0] = BigInt::one();

        while !r1.iter().all(|c| c.is_zero()) {
            // Polynomial division
            let (q, r) = Self::fpk_poly_divmod::<N>(&r0, &r1, prime);

            // s_new = s0 - q * s1
            let qs1 = Self::fpk_poly_mul_mod::<N>(&q, &s1, k, modulus_poly, prime);
            let s_new = Self::fpk_sub::<N>(&s0, &qs1, prime);

            r0 = r1;
            r1 = r;
            s0 = s1;
            s1 = s_new;
        }

        // r0 should be a constant (degree 0)
        // Normalize s0 by dividing by r0[0]
        if r0.iter().skip(1).all(|c| c.is_zero()) && !r0[0].is_zero() {
            let inv = Self::mod_inverse::<N>(&r0[0], prime)?;
            let result: Vec<_> = s0.iter().map(|c| c.mod_mul(&inv, prime)).collect();
            Some(result)
        } else {
            None
        }
    }

    /// Polynomial division with remainder
    fn fpk_poly_divmod<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> (Vec<BigInt<N>>, Vec<BigInt<N>>) {
        // Find degrees
        let deg_a = a.iter().rposition(|c| !c.is_zero()).unwrap_or(0);
        let deg_b = b.iter().rposition(|c| !c.is_zero()).unwrap_or(0);

        if deg_a < deg_b {
            return (vec![BigInt::zero()], a.to_vec());
        }

        let mut remainder = a.to_vec();
        let mut quotient = vec![BigInt::<N>::zero(); deg_a - deg_b + 1];
        let b_lead_inv = Self::mod_inverse::<N>(&b[deg_b], prime).unwrap_or(BigInt::one());

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
    fn fpk_poly_mul_mod<const N: usize>(
        a: &[BigInt<N>],
        b: &[BigInt<N>],
        _k: usize,
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Vec<BigInt<N>> {
        Self::fpk_mul::<N>(a, b, modulus_poly, prime)
    }

    /// EC scalar multiplication over extension field with optimized cloning
    fn ecpk_scalar_mul<const N: usize>(
        p: &(Vec<BigInt<N>>, Vec<BigInt<N>>),
        k_scalar: &BigInt<N>,
        a: &[BigInt<N>],
        modulus_poly: &[BigInt<N>],
        prime: &BigInt<N>,
    ) -> Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> {
        if k_scalar.is_zero() {
            return None;
        }

        let ext_k = p.0.len();
        let mut result: Option<(Vec<BigInt<N>>, Vec<BigInt<N>>)> = None;
        let mut base = p.clone();
        let mut k = *k_scalar;

        while !k.is_zero() {
            if k.limbs()[0] & 1 == 1 {
                result = match result {
                    None => Some(base.clone()),
                    Some(r) => Self::ecpk_add::<N>(&r, &base, a, modulus_poly, prime),
                };
            }
            k = k >> 1;
            if !k.is_zero() {
                base = Self::ecpk_add::<N>(&base, &base, a, modulus_poly, prime)
                    .unwrap_or((vec![BigInt::zero(); ext_k], vec![BigInt::zero(); ext_k]));
            }
        }

        result
    }

    /// Test ECPk DH exchange
    fn test_ecpk_dh_with_limbs<const N: usize>(&self, params: &ECPkParams) -> Result<(), ApiError> {
        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let _k = params.extension;

        let modulus_poly: Vec<BigInt<N>> =
            params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();
        let a: Vec<BigInt<N>> = params.a.iter().map(|s| BigInt::from_hex(s)).collect();
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
        let generator = (gx, gy);

        // Generate private key - use small fixed key for much faster testing
        let private_key = BigInt::<N>::from_u64(0xFF);

        // Compute public key: [sk]G
        let public_key =
            Self::ecpk_scalar_mul::<N>(&generator, &private_key, &a, &modulus_poly, &prime)
                .ok_or_else(|| {
                    ApiError::Validation("Failed to compute ECPk public key".to_string())
                })?;

        // Format for API
        let byte_len = prime.bit_length().div_ceil(8);
        let client_public = ECPkPoint {
            x: public_key
                .0
                .iter()
                .map(|c| bigint_to_padded_hex_upper(c, byte_len))
                .collect(),
            y: public_key
                .1
                .iter()
                .map(|c| bigint_to_padded_hex_upper(c, byte_len))
                .collect(),
        };

        // Send to API
        let response = self.client.test_dh_ecpk(client_public)?;

        // Parse server public key
        let server_public = (
            response
                .server_public
                .x
                .iter()
                .map(|s| BigInt::<N>::from_hex(s))
                .collect::<Vec<_>>(),
            response
                .server_public
                .y
                .iter()
                .map(|s| BigInt::<N>::from_hex(s))
                .collect::<Vec<_>>(),
        );

        // Compute shared secret
        let our_shared =
            Self::ecpk_scalar_mul::<N>(&server_public, &private_key, &a, &modulus_poly, &prime)
                .ok_or_else(|| {
                    ApiError::Validation("Failed to compute ECPk shared secret".to_string())
                })?;
        let our_shared_x: Vec<String> = our_shared
            .0
            .iter()
            .map(|c| bigint_to_padded_hex_upper(c, byte_len))
            .collect();
        let our_shared_y: Vec<String> = our_shared
            .1
            .iter()
            .map(|c| bigint_to_padded_hex_upper(c, byte_len))
            .collect();

        // Compare
        let exp_x: Vec<String> = response
            .shared_secret
            .x
            .iter()
            .map(|s| s.to_uppercase())
            .collect();
        let exp_y: Vec<String> = response
            .shared_secret
            .y
            .iter()
            .map(|s| s.to_uppercase())
            .collect();
        let got_x: Vec<String> = our_shared_x.iter().map(|s| s.to_uppercase()).collect();
        let got_y: Vec<String> = our_shared_y.iter().map(|s| s.to_uppercase()).collect();

        if exp_x == got_x && exp_y == got_y {
            Ok(())
        } else {
            Err(ApiError::Validation(
                "ECPk DH shared secrets don't match".to_string(),
            ))
        }
    }

    /// Test ECPk DH (size-dispatched)
    pub fn test_ecpk_dh(&self, params: &ECPkParams) -> Result<(), ApiError> {
        let bits = hex_bit_length_str(&params.prime_base);
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_ecpk_dh_with_limbs::<4>(self, params),
            6 => Self::test_ecpk_dh_with_limbs::<6>(self, params),
            9 => Self::test_ecpk_dh_with_limbs::<9>(self, params),
            32 => Self::test_ecpk_dh_with_limbs::<32>(self, params),
            _ => Self::test_ecpk_dh_with_limbs::<{ BIGINT_LIMBS }>(self, params),
        }
    }

    /// Test ECPk Schnorr signature verification
    fn test_ecpk_signature_with_limbs<const N: usize>(
        &self,
        params: &ECPkParams,
        message: &str,
    ) -> Result<(), ApiError> {
        let response = self.client.test_signature(ChallengeType::Ecpk, message)?;

        let prime = BigInt::<N>::from_hex(&params.prime_base);
        let order = BigInt::<N>::from_hex(&params.order);
        let _k = params.extension;

        let modulus_poly: Vec<BigInt<N>> =
            params.modulus.iter().map(|s| BigInt::from_hex(s)).collect();
        let a: Vec<BigInt<N>> = params.a.iter().map(|s| BigInt::from_hex(s)).collect();
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
        let generator = (gx, gy);

        // Parse public key
        let public_obj = response
            .public
            .as_object()
            .ok_or_else(|| ApiError::Validation("Invalid public key format".to_string()))?;
        let pub_x_arr = public_obj
            .get("x")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ApiError::Validation("Missing x in public key".to_string()))?;
        let pub_y_arr = public_obj
            .get("y")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ApiError::Validation("Missing y in public key".to_string()))?;
        let public_key = (
            pub_x_arr
                .iter()
                .map(|v| BigInt::<N>::from_hex(v.as_str().unwrap_or("0")))
                .collect::<Vec<_>>(),
            pub_y_arr
                .iter()
                .map(|v| BigInt::<N>::from_hex(v.as_str().unwrap_or("0")))
                .collect::<Vec<_>>(),
        );

        let sig = &response.signature;
        let s = BigInt::<N>::from_hex(&sig.s);
        let e_bytes = hex_to_bytes(&sig.e);
        let e_scalar = hash_to_scalar(&e_bytes, &order);

        // Verify: R' = [s]G + [e]Y (using optimized windowed multiplication)
        let g_s = Self::ecpk_scalar_mul::<N>(&generator, &s, &a, &modulus_poly, &prime);
        let y_e = Self::ecpk_scalar_mul::<N>(&public_key, &e_scalar, &a, &modulus_poly, &prime);

        let r_prime = match (g_s, y_e) {
            (Some(gs), Some(ye)) => Self::ecpk_add::<N>(&gs, &ye, &a, &modulus_poly, &prime),
            (Some(gs), None) => Some(gs),
            (None, Some(ye)) => Some(ye),
            (None, None) => None,
        }
        .ok_or_else(|| ApiError::Validation("R' is point at infinity".to_string()))?;

        // Compute e' = H(R' || m)
        let byte_len = prime.bit_length().div_ceil(8);
        let r_x: Vec<String> = r_prime
            .0
            .iter()
            .map(|c| bigint_to_padded_hex(c, byte_len))
            .collect();
        let r_y: Vec<String> = r_prime
            .1
            .iter()
            .map(|c| bigint_to_padded_hex(c, byte_len))
            .collect();
        let r_obj = serde_json::json!({ "x": r_x, "y": r_y });
        let r_encoded = serde_json::to_string(&r_obj).unwrap();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(r_encoded.as_bytes());
        hasher.update(message.as_bytes());
        let e_prime = hasher.finalize();

        if e_prime.as_slice() == e_bytes.as_slice() {
            Ok(())
        } else {
            Err(ApiError::SignatureVerification(format!(
                "Expected: {}, Got: {}",
                bytes_to_hex(&e_bytes),
                bytes_to_hex(e_prime.as_slice())
            )))
        }
    }

    /// Test ECPk signature (size-dispatched)
    pub fn test_ecpk_signature(&self, params: &ECPkParams, message: &str) -> Result<(), ApiError> {
        let bits = hex_bit_length_str(&params.prime_base);
        let limbs = select_limbs_from_bits(bits);
        match limbs {
            4 => Self::test_ecpk_signature_with_limbs::<4>(self, params, message),
            6 => Self::test_ecpk_signature_with_limbs::<6>(self, params, message),
            9 => Self::test_ecpk_signature_with_limbs::<9>(self, params, message),
            32 => Self::test_ecpk_signature_with_limbs::<32>(self, params, message),
            _ => Self::test_ecpk_signature_with_limbs::<{ BIGINT_LIMBS }>(self, params, message),
        }
    }

    /// Run all tests for ECPk
    pub fn run_ecpk_tests(&self) -> ChallengeTestResult {
        let mut result = ChallengeTestResult::success(ChallengeType::Ecpk);

        // Fetch params once and reuse for both tests
        let params = match self.client.get_ecpk_params() {
            Ok(p) => p,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(format!("Failed to fetch params: {}", e));
                result.signature_success = false;
                result.signature_error = Some(format!("Failed to fetch params: {}", e));
                return result;
            }
        };

        match self.test_ecpk_dh(params) {
            Ok(()) => result.dh_success = true,
            Err(e) => {
                result.dh_success = false;
                result.dh_error = Some(e.to_string());
            }
        }

        match self.test_ecpk_signature(params, "test message") {
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
