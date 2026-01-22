use crate::bigint::BigInt;
use std::cmp::Ordering;

/// Montgomery context for a fixed modulus.
/// Supports Montgomery multiplication and exponentiation.
pub struct MontgomeryCtx<const N: usize> {
    pub modulus: BigInt<N>,
    n0: u64,       // n0 = -m^{-1} mod 2^64
    r2: BigInt<N>, // R^2 mod m, where R = 2^(64N)
}

impl<const N: usize> MontgomeryCtx<N> {
    /// Create a Montgomery context. Returns None if modulus is zero or even (needs odd modulus).
    pub fn new(modulus: BigInt<N>) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        if (modulus.limbs()[0] & 1) == 0 {
            return None; // must be odd for inverse mod 2^64
        }

        let n0 = mont_n0(modulus.limbs()[0]);
        let r2 = compute_r2::<N>(&modulus);

        Some(Self { modulus, n0, r2 })
    }

    /// Convert x (normal) into Montgomery domain: x*R mod m
    #[inline]
    pub fn to_mont(&self, x: &BigInt<N>) -> BigInt<N> {
        let x = x.modulo(&self.modulus);
        // mont_mul(x, R^2) = x*R (because mont_mul returns (a*b*R^{-1}) mod m)
        self.mont_mul(&x, &self.r2)
    }

    /// Convert x (normal, caller promises x < modulus) into Montgomery domain without a full modulo.
    #[inline(always)]
    pub fn to_mont_noreduce(&self, x: &BigInt<N>) -> BigInt<N> {
        self.mont_mul(x, &self.r2)
    }

    /// Convert x with a single compare-sub reduction, then to Montgomery domain.
    #[inline(always)]
    pub fn to_mont_reduce_once(&self, x: &BigInt<N>) -> BigInt<N> {
        let reduced = reduce_once(x, &self.modulus);
        self.mont_mul(&reduced, &self.r2)
    }

    /// Convert x (Montgomery) back to normal: x*R^{-1} mod m
    #[inline]
    pub fn from_mont(&self, x: &BigInt<N>) -> BigInt<N> {
        self.mont_mul(x, &BigInt::<N>::one())
    }

    /// Montgomery representation of 1, i.e. R mod m
    #[inline]
    pub fn one_mont(&self) -> BigInt<N> {
        self.to_mont(&BigInt::<N>::one())
    }

    /// Montgomery representation of 1 without full reduction (1 < modulus always).
    #[inline(always)]
    pub fn one_mont_fast(&self) -> BigInt<N> {
        self.to_mont_noreduce(&BigInt::<N>::one())
    }

    /// Core Montgomery multiplication:
    /// returns (a*b*R^{-1}) mod m.
    ///
    /// Requirements:
    /// - modulus is odd
    /// - a,b are in [0, m)
    /// 
    /// Uses a linear array with explicit shifting to avoid circular buffer overhead.
    #[inline(always)]
    pub fn mont_mul(&self, a: &BigInt<N>, b: &BigInt<N>) -> BigInt<N> {
        self.mont_mul_internal(a, b, false)
    }
    
    /// Internal mont_mul with optional debug
    fn mont_mul_internal(&self, a: &BigInt<N>, b: &BigInt<N>, _debug: bool) -> BigInt<N> {
        debug_assert!((self.modulus.limbs()[0] & 1) == 1);

        // Use stack-allocated array for the accumulator
        // We need N+1 limbs but Rust const generics don't allow N+1 yet
        // Use 65 which is enough for all practical cases (up to 64 limbs = 4096 bits)
        let mut t = [0u64; 65];

        let m_limbs = self.modulus.limbs();
        let a_limbs = a.limbs();
        let b_limbs = b.limbs();
        let n0 = self.n0;

        for &bi in b_limbs.iter().take(N) {
            // 1) t += a * b[i]
            let mut carry: u64 = 0;
            for j in 0..N {
                let (lo, hi) = mul_add_carry(a_limbs[j], bi, t[j], carry);
                t[j] = lo;
                carry = hi;
            }
            // Propagate carry into t[N]
            let sum = (t[N] as u128) + (carry as u128);
            t[N] = sum as u64;

            // 2) m_i = t[0] * n0 mod 2^64
            let mi = t[0].wrapping_mul(n0);

            // 3) t += mi * m, then shift right by 64 bits
            // First handle j=0: lo0 should be 0 (that's the point of Montgomery reduction)
            let (_lo0, hi0) = mul_add_carry(m_limbs[0], mi, t[0], 0);
            let mut carry = hi0;
            
            for j in 1..N {
                let (lo, hi) = mul_add_carry(m_limbs[j], mi, t[j], carry);
                t[j - 1] = lo;
                carry = hi;
            }
            // Handle t[N] + carry
            let sum = (t[N] as u128) + (carry as u128);
            t[N - 1] = sum as u64;
            t[N] = (sum >> 64) as u64;
        }

        // Copy result to output limbs
        let mut limbs = [0u64; N];
        limbs[..N].copy_from_slice(&t[..N]);
        let mut out = BigInt::<N>::from_limbs_internal(limbs);

        // Conditional subtraction: if t >= m, subtract once
        // t[N] being non-zero means we definitely need to subtract
        if t[N] != 0 || out.compare(&self.modulus) != Ordering::Less {
            out = out.sub_with_borrow(&self.modulus).0;
        }

        out
    }
    
    /// Debug version of mont_mul that prints intermediate values
    #[allow(dead_code)]
    pub fn mont_mul_debug(&self, a: &BigInt<N>, b: &BigInt<N>) -> BigInt<N> {
        self.mont_mul_internal(a, b, true)
    }

    /// Normal modular multiplication using Montgomery under the hood.
    pub fn mod_mul(&self, a: &BigInt<N>, b: &BigInt<N>) -> BigInt<N> {
        let am = self.to_mont(a);
        let bm = self.to_mont(b);
        let cm = self.mont_mul(&am, &bm);
        self.from_mont(&cm)
    }

    /// Modular multiplication when caller guarantees a,b < modulus (skips full reduction on entry).
    pub fn mod_mul_noreduce(&self, a: &BigInt<N>, b: &BigInt<N>) -> BigInt<N> {
        let am = self.to_mont_noreduce(a);
        let bm = self.to_mont_noreduce(b);
        let cm = self.mont_mul(&am, &bm);
        self.from_mont(&cm)
    }

    /// Normal modular exponentiation using Montgomery (square-and-multiply, LSB-first).
    pub fn mod_pow(&self, base: &BigInt<N>, exp: &BigInt<N>) -> BigInt<N> {
        if self.modulus.is_one() {
            return BigInt::<N>::zero();
        }

        let mut result = self.one_mont();
        let mut base_m = self.to_mont(base);

        let exp_bits = exp.bit_length();
        for i in 0..exp_bits {
            if exp.get_bit(i) {
                result = self.mont_mul(&result, &base_m);
            }
            base_m = self.mont_mul(&base_m, &base_m);
        }

        self.from_mont(&result)
    }

    /// Modular exponentiation when caller guarantees base < modulus (skips full reduction on entry).
    pub fn mod_pow_noreduce(&self, base: &BigInt<N>, exp: &BigInt<N>) -> BigInt<N> {
        if self.modulus.is_one() {
            return BigInt::<N>::zero();
        }

        let mut result = self.one_mont_fast();
        let mut base_m = self.to_mont_noreduce(base);

        let exp_bits = exp.bit_length();
        for i in 0..exp_bits {
            if exp.get_bit(i) {
                result = self.mont_mul(&result, &base_m);
            }
            base_m = self.mont_mul(&base_m, &base_m);
        }

        self.from_mont(&result)
    }
}

/// Compute a*b + c + d, returning (lo, hi) where result = lo + hi*2^64
/// This is the core operation for Montgomery multiplication.
#[inline(always)]
fn mul_add_carry(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let product = (a as u128) * (b as u128) + (c as u128) + (d as u128);
    (product as u64, (product >> 64) as u64)
}

/// Compute n0 = -m^{-1} mod 2^64 (requires m odd).
#[inline(always)]
fn mont_n0(m0: u64) -> u64 {
    debug_assert!(m0 & 1 == 1);
    inv_mod_2_64_odd(m0).wrapping_neg()
}

/// Inverse of odd a modulo 2^64 using Newton iteration.
#[inline(always)]
fn inv_mod_2_64_odd(a: u64) -> u64 {
    debug_assert!(a & 1 == 1);
    // x <- x(2 - ax) mod 2^64
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    }
    x
}

/// Compute R^2 mod m by repeated doubling from 1:
/// After 2*64N doublings: 1 * 2^(128N) mod m == R^2 mod m.
fn compute_r2<const N: usize>(m: &BigInt<N>) -> BigInt<N> {
    let mut r = BigInt::<N>::one();
    for _ in 0..(2 * 64 * N) {
        r = r.mod_add(&r, m);
    }
    r
}

#[inline(always)]
fn reduce_once<const N: usize>(x: &BigInt<N>, m: &BigInt<N>) -> BigInt<N> {
    if x.compare(m) != Ordering::Less {
        x.sub_with_borrow(m).0
    } else {
        *x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_matches_old() {
        type B = BigInt<4>;
        let m = B::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        let ctx = MontgomeryCtx::<4>::new(m).unwrap();

        let a = B::from_u64(1_234_567);
        let b = B::from_u64(7_654_321);

        let old = a.mod_mul(&b, &ctx.modulus);
        let new = ctx.mod_mul(&a, &b);

        assert_eq!(old, new);
    }
    
    #[test]
    fn montgomery_z_squared() {
        // The failing case from ECP debugging - tests the t[N] overflow fix
        type B = BigInt<4>;
        let m = B::from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        let ctx = MontgomeryCtx::<4>::new(m).unwrap();
        
        // Z² value that previously failed when squared
        let z_sq = B::from_hex("710b36fcf4c72e5b8d0cf5ae66f613bf56bda4a8d9f16260c2439ee0ca8cf0fd");
        
        // Expected Z⁴ = Z² * Z² using standard mod_mul
        let z_4_expected = z_sq.mod_mul(&z_sq, &m);
        
        // Convert z_sq to Montgomery domain
        let z_sq_mont = ctx.to_mont(&z_sq);
        
        // Montgomery Z⁴ in Montgomery domain
        let z_4_mont_domain = ctx.mont_mul(&z_sq_mont, &z_sq_mont);
        
        // Convert back and compare
        let z_4_mont = ctx.from_mont(&z_4_mont_domain);
        
        assert_eq!(z_4_expected, z_4_mont, "Montgomery Z⁴ mismatch!");
    }
}
