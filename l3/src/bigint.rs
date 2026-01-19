//! Big Integer implementation with compile-time sizing
//!
//! This module provides a generic big integer type `BigInt<N>` where N is the number
//! of 64-bit limbs. This allows compile-time configuration for different bit sizes:
//! - BigInt<4> for 256-bit integers
//! - BigInt<8> for 512-bit integers
//! - BigInt<16> for 1024-bit integers
//!
//! The implementation uses little-endian limb ordering (least significant limb first)
//! internally for efficient arithmetic, but provides methods for big-endian byte conversion
//! when needed for standard integer representation.

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, BitAnd, BitOr, BitXor, Mul, Neg, Shl, Shr, Sub};

/// A big integer with N 64-bit limbs (N * 64 bits total)
///
/// Limbs are stored in little-endian order (limbs[0] is least significant).
/// This is efficient for multi-precision arithmetic algorithms.
///
/// # Examples
/// ```
/// use l3::bigint::BigInt;
/// // Create a 256-bit integer (4 * 64 = 256 bits)
/// let a = BigInt::<4>::from_u64(42);
/// let b = BigInt::<4>::from_u64(100);
/// let sum = a + b;
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BigInt<const N: usize> {
    /// Limbs in little-endian order (limbs[0] is least significant)
    limbs: [u64; N],
}

impl<const N: usize> BigInt<N> {
    /// Number of bits this BigInt can represent
    pub const BITS: usize = N * 64;

    /// Creates a BigInt with value zero
    ///
    /// # Examples
    /// ```
    /// use l3::bigint::BigInt;
    /// let zero = BigInt::<4>::zero();
    /// ```
    #[inline]
    pub const fn zero() -> Self {
        Self { limbs: [0; N] }
    }

    /// Creates a BigInt with value one
    ///
    /// # Examples
    /// ```
    /// use l3::bigint::BigInt;
    /// let one = BigInt::<4>::one();
    /// ```
    #[inline]
    pub const fn one() -> Self {
        let mut limbs = [0; N];
        limbs[0] = 1;
        Self { limbs }
    }

    /// Creates a BigInt from a u64 value
    ///
    /// # Examples
    /// ```
    /// use l3::bigint::BigInt;
    /// let num = BigInt::<4>::from_u64(12345);
    /// ```
    #[inline]
    pub const fn from_u64(val: u64) -> Self {
        let mut limbs = [0; N];
        limbs[0] = val;
        Self { limbs }
    }

    /// Creates a BigInt from a hexadecimal string (big-endian encoding)
    ///
    /// Parses a hex string like "1A2B3C" into its numeric value.
    /// Supports both uppercase and lowercase hex digits.
    ///
    /// # Arguments
    /// * `hex` - Hex string without "0x" prefix
    ///
    /// # Panics
    /// Panics if the hex string contains invalid characters or is too large.
    pub fn from_hex(hex: &str) -> Self {
        let hex = hex.trim();
        if hex.is_empty() {
            return Self::zero();
        }

        // Parse hex string into bytes (big-endian)
        let hex_bytes: Vec<u8> = hex.as_bytes().to_vec();
        let mut bytes = Vec::new();

        // Pad to even length
        let padded = if hex_bytes.len() % 2 == 1 {
            let mut p = vec![b'0'];
            p.extend_from_slice(&hex_bytes);
            p
        } else {
            hex_bytes
        };

        for chunk in padded.chunks(2) {
            let s = std::str::from_utf8(chunk).expect("Invalid UTF8 in hex");
            let byte = u8::from_str_radix(s, 16).expect("Invalid hex digit");
            bytes.push(byte);
        }

        Self::from_be_bytes(&bytes)
    }

    /// Creates a BigInt from big-endian bytes
    ///
    /// # Arguments
    /// * `bytes` - Byte slice in big-endian order (most significant byte first)
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; N];

        // Process bytes from end (least significant) to start (most significant)
        for (i, &byte) in bytes.iter().rev().enumerate() {
            let limb_idx = i / 8;
            let byte_idx = i % 8;
            if limb_idx < N {
                limbs[limb_idx] |= (byte as u64) << (byte_idx * 8);
            }
        }

        Self { limbs }
    }

    /// Creates a BigInt from little-endian bytes
    ///
    /// # Arguments  
    /// * `bytes` - Byte slice in little-endian order (least significant byte first)
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; N];

        for (i, &byte) in bytes.iter().enumerate() {
            let limb_idx = i / 8;
            let byte_idx = i % 8;
            if limb_idx < N {
                limbs[limb_idx] |= (byte as u64) << (byte_idx * 8);
            }
        }

        Self { limbs }
    }

    /// Returns the value as little-endian bytes
    pub fn to_le_bytes_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * 8);
        for &limb in self.limbs.iter() {
            for byte_idx in 0..8 {
                bytes.push(((limb >> (byte_idx * 8)) & 0xFF) as u8);
            }
        }
        bytes
    }

    /// Gets a reference to the internal limbs array
    ///
    /// Limbs are in little-endian order (least significant limb first).
    ///
    /// # Returns
    /// Reference to the limbs array
    #[inline]
    pub const fn limbs(&self) -> &[u64; N] {
        &self.limbs
    }

    /// Creates a BigInt from an array of limbs (internal use)
    ///
    /// Unlike `from_limbs`, this takes an array directly for const contexts.
    ///
    /// # Arguments
    /// * `limbs` - Array of N limbs in little-endian order
    ///
    /// # Returns
    /// A BigInt with the given limbs
    pub const fn from_limbs_internal(limbs: [u64; N]) -> Self {
        Self { limbs }
    }

    /// Creates a BigInt from big-endian bytes
    ///
    /// Returns exactly N * 8 bytes in big-endian order (most significant byte first).
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * 8);

        for limb_idx in (0..N).rev() {
            let limb = self.limbs[limb_idx];
            for byte_idx in (0..8).rev() {
                bytes.push(((limb >> (byte_idx * 8)) & 0xFF) as u8);
            }
        }

        bytes
    }

    /// Returns true if this BigInt is zero
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&limb| limb == 0)
    }

    /// Returns true if this BigInt is one
    #[inline]
    pub fn is_one(&self) -> bool {
        self.limbs[0] == 1 && self.limbs[1..].iter().all(|&limb| limb == 0)
    }

    /// Returns the bit length (position of highest set bit + 1)
    ///
    /// Returns 0 for zero.
    pub fn bit_length(&self) -> usize {
        for i in (0..N).rev() {
            if self.limbs[i] != 0 {
                let leading_zeros = self.limbs[i].leading_zeros() as usize;
                return (i + 1) * 64 - leading_zeros;
            }
        }
        0
    }

    /// Converts to hexadecimal string (big-endian, without 0x prefix)
    ///
    /// Returns uppercase hex string with no leading zeros.
    pub fn to_hex(&self) -> String {
        // Find the most significant non-zero limb
        let mut start = N;
        for i in (0..N).rev() {
            if self.limbs[i] != 0 {
                start = i;
                break;
            }
        }

        // If all limbs are zero
        if start == N {
            return "00".to_string();
        }

        // Build hex string from most significant limb to least
        let mut hex = format!("{:X}", self.limbs[start]);
        for i in (0..start).rev() {
            hex.push_str(&format!("{:016X}", self.limbs[i]));
        }

        hex
    }

    /// Compares this BigInt with another
    ///
    /// Returns Ordering::Less, Ordering::Equal, or Ordering::Greater
    pub fn compare(&self, other: &Self) -> Ordering {
        // Compare from most significant to least significant
        for i in (0..N).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }

    /// Addition with carry detection
    ///
    /// Returns (result, overflow) where overflow is true if addition overflowed
    pub fn add_with_carry(&self, other: &Self) -> (Self, bool) {
        let mut result = Self::zero();
        let mut carry = 0u64;

        for i in 0..N {
            let (sum1, overflow1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum2, overflow2) = sum1.overflowing_add(carry);

            result.limbs[i] = sum2;
            carry = (overflow1 || overflow2) as u64;
        }

        (result, carry != 0)
    }

    /// Subtraction with borrow detection
    ///
    /// Returns (result, underflow) where underflow is true if subtraction underflowed
    pub fn sub_with_borrow(&self, other: &Self) -> (Self, bool) {
        let mut result = Self::zero();
        let mut borrow = 0u64;

        for i in 0..N {
            let (diff1, underflow1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (diff2, underflow2) = diff1.overflowing_sub(borrow);

            result.limbs[i] = diff2;
            borrow = (underflow1 || underflow2) as u64;
        }

        (result, borrow != 0)
    }

    /// Multiplication with modular reduction (result mod 2^(N*64))
    ///
    /// This is regular multiplication but discards overflow, keeping only the lower N limbs
    pub fn mul_mod(&self, other: &Self) -> Self {
        let mut result = Self::zero();

        for i in 0..N {
            let mut carry = 0u128;

            for j in 0..N {
                if i + j >= N {
                    break;
                }

                let product = (self.limbs[i] as u128) * (other.limbs[j] as u128);
                let sum = (result.limbs[i + j] as u128) + product + carry;

                result.limbs[i + j] = sum as u64;
                carry = sum >> 64;
            }
        }

        result
    }

    /// Left shift by a number of bits
    ///
    /// Returns (result, overflow_bits). overflow_bits is only meaningful for shifts < 64;
    /// it contains the bits shifted out of the most significant limb.
    pub fn shl(&self, bits: usize) -> (Self, u64) {
        if bits == 0 {
            return (*self, 0);
        }

        if bits >= Self::BITS {
            return (Self::zero(), 0);
        }

        let limb_shift = bits / 64;
        let bit_shift = bits % 64;

        let mut result = Self::zero();

        if bit_shift == 0 {
            // Pure limb shift
            for i in (0..N).rev() {
                if i >= limb_shift {
                    result.limbs[i] = self.limbs[i - limb_shift];
                }
            }
            // Returning overflow for limb shifts isn't very helpful; keep 0.
            return (result, 0);
        }

        // Bit shift within limbs
        // We build from high to low to avoid overwriting issues (though we read from self).
        for i in (0..N).rev() {
            // Source limb that lands in i after limb_shift
            if i < limb_shift {
                continue;
            }
            let src = i - limb_shift;

            let mut v = self.limbs[src] << bit_shift;

            // Carry comes from the *less significant* source limb (src-1)
            if src > 0 {
                v |= self.limbs[src - 1] >> (64 - bit_shift);
            }

            result.limbs[i] = v;
        }

        // Bits shifted out of the top limb (pre-shift)
        let overflow = self.limbs[N - 1] >> (64 - bit_shift);

        (result, overflow)
    }

    /// Right shift by a number of bits
    pub fn shr(&self, bits: usize) -> Self {
        if bits == 0 {
            return *self;
        }

        if bits >= Self::BITS {
            return Self::zero();
        }

        let limb_shift = bits / 64;
        let bit_shift = bits % 64;

        let mut result = Self::zero();

        if bit_shift == 0 {
            // Simple limb shift
            for i in 0..(N - limb_shift) {
                result.limbs[i] = self.limbs[i + limb_shift];
            }
        } else {
            // Bit shift within limbs
            for i in 0..(N - limb_shift) {
                let src_idx = i + limb_shift;
                result.limbs[i] = self.limbs[src_idx] >> bit_shift;

                if src_idx + 1 < N {
                    result.limbs[i] |= self.limbs[src_idx + 1] << (64 - bit_shift);
                }
            }
        }

        result
    }

    /// Division with remainder: self / other = (quotient, remainder)
    ///
    /// Uses long division algorithm.
    ///
    /// # Panics
    /// Panics if dividing by zero
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "Division by zero");

        if self.compare(divisor) == Ordering::Less {
            return (Self::zero(), *self);
        }

        if divisor.is_one() {
            return (*self, Self::zero());
        }

        // Long division algorithm
        let mut quotient = Self::zero();
        let mut remainder = Self::zero();

        // Process bits from most significant to least significant
        for i in (0..Self::BITS).rev() {
            // Shift remainder left by 1 using the method directly
            remainder = Self::shl(&remainder, 1).0;

            // Set the lowest bit of remainder to the current bit of dividend
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            if (self.limbs[limb_idx] >> bit_idx) & 1 == 1 {
                remainder.limbs[0] |= 1;
            }

            // If remainder >= divisor, subtract divisor and set quotient bit
            if remainder.compare(divisor) != Ordering::Less {
                remainder = remainder.sub_with_borrow(divisor).0;
                let q_limb_idx = i / 64;
                let q_bit_idx = i % 64;
                quotient.limbs[q_limb_idx] |= 1u64 << q_bit_idx;
            }
        }

        (quotient, remainder)
    }

    /// Modular reduction: self mod modulus
    pub fn modulo(&self, modulus: &Self) -> Self {
        self.div_rem(modulus).1
    }

    /// (self + other) mod modulus, assuming self < modulus and other < modulus
    pub fn mod_add(&self, other: &Self, modulus: &Self) -> Self {
        let (sum, carry) = self.add_with_carry(other);
        if carry || sum.compare(modulus) != Ordering::Less {
            sum.sub_with_borrow(modulus).0
        } else {
            sum
        }
    }

    /// (self - other) mod modulus, assuming self < modulus and other < modulus
    pub fn mod_sub(&self, other: &Self, modulus: &Self) -> Self {
        if self.compare(other) != Ordering::Less {
            self.sub_with_borrow(other).0
        } else {
            let (tmp, _) = self.add_with_carry(modulus); // self + m
            tmp.sub_with_borrow(other).0
        }
    }

    /// Modular multiplication: (self * other) mod modulus
    /// Uses schoolbook multiplication with reduction
    pub fn mod_mul(&self, other: &Self, modulus: &Self) -> Self {
        // Use double-width multiplication for correctness
        // We'll do it with the shift-and-add method to handle overflow
        let mut result = Self::zero();
        let mut temp = other.modulo(modulus);

        // Only iterate up to actual bit length for performance
        let max_bits = self.bit_length();

        for i in 0..max_bits {
            let limb_idx = i / 64;
            let bit_idx = i % 64;

            if (self.limbs[limb_idx] >> bit_idx) & 1 == 1 {
                result = result.mod_add(&temp, modulus);
            }

            // Double temp
            temp = temp.mod_add(&temp, modulus);
        }

        result
    }

    /// Modular exponentiation: self^exp mod modulus using square-and-multiply
    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_one() {
            return Self::zero();
        }

        let mut result = Self::one();
        let mut base = self.modulo(modulus);

        // Only process up to actual bit length of exponent for performance
        let exp_bits = exp.bit_length();

        for i in 0..exp_bits {
            let limb_idx = i / 64;
            let bit_idx = i % 64;

            if (exp.limbs[limb_idx] >> bit_idx) & 1 == 1 {
                result = result.mod_mul(&base, modulus);
            }

            base = base.mod_mul(&base, modulus);
        }

        result
    }

    /// Extended Euclidean algorithm: returns (gcd, x, y) where gcd = a*x + b*y
    /// Note: x and y may be negative (represented as positive remainders mod appropriate values)
    pub fn extended_gcd(a: &Self, b: &Self) -> (Self, Self, Self, bool, bool) {
        // Returns (gcd, |x|, |y|, x_negative, y_negative)
        if b.is_zero() {
            return (*a, Self::one(), Self::zero(), false, false);
        }

        let (q, r) = a.div_rem(b);
        let (gcd, x1, y1, x1_neg, y1_neg) = Self::extended_gcd(b, &r);

        // x = y1
        // y = x1 - q * y1
        let qy1 = q.mul_mod(&y1);

        let (y, y_neg) = if x1_neg == y1_neg {
            // x1 and q*y1 have same sign, subtract magnitudes
            if x1.compare(&qy1) != Ordering::Less {
                (x1.sub_with_borrow(&qy1).0, x1_neg)
            } else {
                (qy1.sub_with_borrow(&x1).0, !x1_neg)
            }
        } else {
            // Different signs, add magnitudes
            (x1.add_with_carry(&qy1).0, x1_neg)
        };

        (gcd, y1, y, y1_neg, y_neg)
    }

    /// Modular inverse: self^(-1) mod modulus
    /// Returns None if gcd(self, modulus) != 1
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        let a = self.modulo(modulus);
        if a.is_zero() {
            return None;
        }

        let (gcd, x, _, x_neg, _) = Self::extended_gcd(&a, modulus);

        if !gcd.is_one() {
            return None;
        }

        if x_neg {
            Some(modulus.sub_with_borrow(&x.modulo(modulus)).0)
        } else {
            Some(x.modulo(modulus))
        }
    }

    /// Get a specific bit (0-indexed from least significant)
    pub fn get_bit(&self, idx: usize) -> bool {
        if idx >= Self::BITS {
            return false;
        }
        let limb_idx = idx / 64;
        let bit_idx = idx % 64;
        (self.limbs[limb_idx] >> bit_idx) & 1 == 1
    }

    /// Bitwise NOT operation
    pub fn bitnot(&self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.limbs[i] = !self.limbs[i];
        }
        result
    }
}

// Implement Add trait
impl<const N: usize> Add for BigInt<N> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.add_with_carry(&other).0
    }
}

// Implement Sub trait
impl<const N: usize> Sub for BigInt<N> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.sub_with_borrow(&other).0
    }
}

// Implement Mul trait (wrapping multiplication)
impl<const N: usize> Mul for BigInt<N> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self.mul_mod(&other)
    }
}

// Implement Neg trait (two's complement negation)
impl<const N: usize> Neg for BigInt<N> {
    type Output = Self;

    fn neg(self) -> Self {
        let inverted = self.bitnot();
        inverted + Self::one()
    }
}

// Implement BitAnd trait for AND operation
impl<const N: usize> BitAnd for BigInt<N> {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.limbs[i] = self.limbs[i] & other.limbs[i];
        }
        result
    }
}

// Implement BitOr trait for OR operation
impl<const N: usize> BitOr for BigInt<N> {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.limbs[i] = self.limbs[i] | other.limbs[i];
        }
        result
    }
}

// Implement BitXor trait for XOR operation
impl<const N: usize> BitXor for BigInt<N> {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.limbs[i] = self.limbs[i] ^ other.limbs[i];
        }
        result
    }
}

// Implement Shl trait for left shift
impl<const N: usize> Shl<usize> for BigInt<N> {
    type Output = Self;

    fn shl(self, shift: usize) -> Self {
        // Call the method that returns (result, overflow)
        let (result, _overflow) = BigInt::shl(&self, shift);
        result
    }
}

// Implement Shr trait for right shift
impl<const N: usize> Shr<usize> for BigInt<N> {
    type Output = Self;

    fn shr(self, shift: usize) -> Self {
        BigInt::shr(&self, shift)
    }
}

// Implement Debug and Display for readable output
impl<const N: usize> fmt::Debug for BigInt<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigInt<{}>(0x", N)?;
        for &limb in self.limbs.iter().rev() {
            write!(f, "{:016x}", limb)?;
        }
        write!(f, ")")
    }
}

impl<const N: usize> fmt::Display for BigInt<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as hexadecimal for clarity
        write!(f, "0x")?;
        let mut started = false;
        for &limb in self.limbs.iter().rev() {
            if started {
                write!(f, "{:016x}", limb)?;
            } else if limb != 0 {
                write!(f, "{:x}", limb)?;
                started = true;
            }
        }
        if !started {
            write!(f, "0")?;
        }
        Ok(())
    }
}

// Type aliases for common sizes
/// 256-bit big integer (4 limbs × 64 bits)
pub type BigInt256 = BigInt<4>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_and_one() {
        let zero = BigInt256::zero();
        let one = BigInt256::one();

        assert!(zero.is_zero());
        assert!(!one.is_zero());
        assert!(one.is_one());
        assert!(!zero.is_one());
    }

    #[test]
    fn test_from_u64() {
        let num = BigInt256::from_u64(12345);
        assert_eq!(num.limbs[0], 12345);
        assert_eq!(num.limbs[1], 0);
    }

    #[test]
    fn test_addition() {
        let a = BigInt256::from_u64(100);
        let b = BigInt256::from_u64(200);
        let sum = a + b;

        assert_eq!(sum.limbs[0], 300);
    }

    #[test]
    fn test_addition_with_carry() {
        let a = BigInt256::from_u64(u64::MAX);
        let b = BigInt256::from_u64(1);
        let (sum, overflow) = a.add_with_carry(&b);

        assert_eq!(sum.limbs[0], 0);
        assert_eq!(sum.limbs[1], 1);
        assert!(!overflow);
    }

    #[test]
    fn test_subtraction() {
        let a = BigInt256::from_u64(300);
        let b = BigInt256::from_u64(100);
        let diff = a - b;

        assert_eq!(diff.limbs[0], 200);
    }

    #[test]
    fn test_multiplication() {
        let a = BigInt256::from_u64(123);
        let b = BigInt256::from_u64(456);
        let prod = a * b;

        assert_eq!(prod.limbs[0], 123 * 456);
    }

    #[test]
    fn test_division() {
        let a = BigInt256::from_u64(100);
        let b = BigInt256::from_u64(7);
        let (quot, rem) = a.div_rem(&b);

        assert_eq!(quot.limbs[0], 14);
        assert_eq!(rem.limbs[0], 2);
    }

    #[test]
    fn test_modulo() {
        let a = BigInt256::from_u64(100);
        let b = BigInt256::from_u64(7);
        let rem = a.modulo(&b);

        assert_eq!(rem.limbs[0], 2);
    }

    #[test]
    fn test_shift_left() {
        let a = BigInt256::from_u64(1);
        let shifted = a << 8;

        assert_eq!(shifted.limbs[0], 256);
    }

    #[test]
    fn test_shift_right() {
        let a = BigInt256::from_u64(256);
        let shifted = a.shr(8);

        assert_eq!(shifted.limbs[0], 1);
    }

    #[test]
    fn test_comparison() {
        let a = BigInt256::from_u64(100);
        let b = BigInt256::from_u64(200);

        assert_eq!(a.compare(&b), Ordering::Less);
        assert_eq!(b.compare(&a), Ordering::Greater);
        assert_eq!(a.compare(&a), Ordering::Equal);
    }

    #[test]
    fn test_bitwise_xor() {
        let a = BigInt256::from_u64(0b1010);
        let b = BigInt256::from_u64(0b1100);
        let result = a ^ b;

        assert_eq!(result.limbs[0], 0b0110);
    }

    #[test]
    fn test_be_bytes_conversion() {
        let num = BigInt256::from_u64(0x123456789ABCDEF0);
        let bytes = num.to_be_bytes();

        // Verify the bytes are in big-endian format
        assert_eq!(bytes.len(), 32); // 256 bits = 32 bytes
        // Last 8 bytes should contain our value in big-endian
        let last_8 = &bytes[bytes.len() - 8..];
        assert_eq!(last_8, &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    }

    #[test]
    fn test_shift_left_cross_limb_carry() {
        // Put a 1 in the top bit of limb 0 (bit 63), shift left by 1.
        // It should become bit 0 of limb 1.
        let mut limbs = [0u64; 4];
        limbs[0] = 1u64 << 63;
        let a = BigInt::<4>::from_limbs_internal(limbs);

        let shifted = a << 1;

        assert_eq!(shifted.limbs()[0], 0);
        assert_eq!(shifted.limbs()[1], 1);
    }
}
