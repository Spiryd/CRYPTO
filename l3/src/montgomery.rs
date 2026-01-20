use crate::bigint::BigInt;
use std::cell::RefCell;
use std::cmp::Ordering;

/// Montgomery context for a fixed modulus.
/// Supports Montgomery multiplication and exponentiation.
pub struct MontgomeryCtx<const N: usize> {
    pub modulus: BigInt<N>,
    n0: u64,                    // n0 = -m^{-1} mod 2^64
    r2: BigInt<N>,              // R^2 mod m, where R = 2^(64N)
    scratch: RefCell<Vec<u64>>, // reusable buffer of length N+1
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
        let scratch = RefCell::new(vec![0u64; N + 1]);

        Some(Self {
            modulus,
            n0,
            r2,
            scratch,
        })
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
    pub fn mont_mul(&self, a: &BigInt<N>, b: &BigInt<N>) -> BigInt<N> {
        debug_assert!((self.modulus.limbs()[0] & 1) == 1);

        // Reuse scratch buffer to avoid per-call allocation.
        let mut t = self.scratch.borrow_mut();
        t.fill(0);
        let len = N + 1;
        let mut head = 0usize; // logical index 0 within t

        let m = &self.modulus;
        let n0 = self.n0;

        for i in 0..N {
            // 1) t += a * b[i]
            let bi = b.limbs()[i];
            let mut carry: u128 = 0;
            for j in 0..N {
                let idx = head + j;
                let idx = if idx >= len { idx - len } else { idx };
                let uv = (t[idx] as u128) + (a.limbs()[j] as u128) * (bi as u128) + carry;
                t[idx] = uv as u64;
                carry = uv >> 64;
            }
            // add carry into t[N]
            let idx_n = head + N;
            let idx_n = if idx_n >= len { idx_n - len } else { idx_n };
            t[idx_n] = t[idx_n].wrapping_add(carry as u64);

            // 2) m_i = t[0] * n0 mod 2^64
            let mi = t[head].wrapping_mul(n0);

            // 3) t += mi * m
            carry = 0;
            for j in 0..N {
                let idx = head + j;
                let idx = if idx >= len { idx - len } else { idx };
                let uv = (t[idx] as u128) + (mi as u128) * (m.limbs()[j] as u128) + carry;
                t[idx] = uv as u64;
                carry = uv >> 64;
            }
            let idx_n = head + N;
            let idx_n = if idx_n >= len { idx_n - len } else { idx_n };
            t[idx_n] = t[idx_n].wrapping_add(carry as u64);

            // 4) Logical shift: advance head by 1 and zero new top limb
            head += 1;
            if head == len {
                head = 0;
            }
            let idx_top = head + N;
            let idx_top = if idx_top >= len {
                idx_top - len
            } else {
                idx_top
            };
            t[idx_top] = 0;
        }

        // Conditional subtraction: if t >= m, subtract once.
        // Here t is only N limbs effectively (t[N] == 0 after shifting),
        // but we keep the robust check.
        let mut limbs = [0u64; N];
        for (k, limb) in limbs.iter_mut().enumerate().take(N) {
            let idx = head + k;
            let idx = if idx >= len { idx - len } else { idx };
            *limb = t[idx];
        }
        let mut out = BigInt::<N>::from_limbs_internal(limbs);

        if out.compare(m) != Ordering::Less {
            out = out.sub_with_borrow(m).0;
        }

        out
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

/// Compute n0 = -m^{-1} mod 2^64 (requires m odd).
fn mont_n0(m0: u64) -> u64 {
    debug_assert!(m0 & 1 == 1);
    inv_mod_2_64_odd(m0).wrapping_neg()
}

/// Inverse of odd a modulo 2^64 using Newton iteration.
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
}
