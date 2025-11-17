use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Sub, Mul, Div, Rem, Shl, Shr, BitAnd, BitOr, BitXor};

/// Big unsigned integer with configurable size in bits
/// Stored in little-endian format (least significant word first)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigUint {
    // Store as array of u64 words (little-endian)
    words: Vec<u64>,
}

impl BigUint {
    const WORD_BITS: usize = 64;

    /// Create a new BigUint with specified number of bits capacity
    pub fn new(bits: usize) -> Self {
        let words = (bits + Self::WORD_BITS - 1) / Self::WORD_BITS;
        BigUint {
            words: vec![0; words],
        }
    }

    /// Create from a u64 value
    pub fn from_u64(value: u64) -> Self {
        BigUint {
            words: vec![value],
        }
    }

    /// Create from a slice of bytes (big-endian)
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let words = (bytes.len() + 7) / 8;
        let mut result = BigUint {
            words: vec![0; words],
        };

        for (i, &byte) in bytes.iter().rev().enumerate() {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            result.words[word_idx] |= (byte as u64) << (byte_idx * 8);
        }

        result.normalize();
        result
    }

    /// Create from a slice of bytes (little-endian)
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let words = (bytes.len() + 7) / 8;
        let mut result = BigUint {
            words: vec![0; words],
        };

        for (i, &byte) in bytes.iter().enumerate() {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            result.words[word_idx] |= (byte as u64) << (byte_idx * 8);
        }

        result.normalize();
        result
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::new();
        for &word in self.words.iter().rev() {
            for i in (0..8).rev() {
                let byte = ((word >> (i * 8)) & 0xFF) as u8;
                if !bytes.is_empty() || byte != 0 {
                    bytes.push(byte);
                }
            }
        }

        if bytes.is_empty() {
            bytes.push(0);
        }

        bytes
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes_le(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::new();
        for &word in &self.words {
            for i in 0..8 {
                bytes.push(((word >> (i * 8)) & 0xFF) as u8);
            }
        }

        // Remove trailing zeros
        while bytes.len() > 1 && bytes[bytes.len() - 1] == 0 {
            bytes.pop();
        }

        bytes
    }

    /// Create zero
    pub fn zero() -> Self {
        BigUint { words: vec![0] }
    }

    /// Create one
    pub fn one() -> Self {
        BigUint { words: vec![1] }
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Check if one
    pub fn is_one(&self) -> bool {
        self.words.len() == 1 && self.words[0] == 1
            || (self.words.len() > 1 && self.words[0] == 1 && self.words[1..].iter().all(|&w| w == 0))
    }

    /// Check if even
    pub fn is_even(&self) -> bool {
        self.words[0] & 1 == 0
    }

    /// Remove leading zero words
    fn normalize(&mut self) {
        while self.words.len() > 1 && self.words[self.words.len() - 1] == 0 {
            self.words.pop();
        }
    }

    /// Get bit length
    pub fn bit_len(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let last_word = self.words[self.words.len() - 1];
        (self.words.len() - 1) * Self::WORD_BITS + (64 - last_word.leading_zeros() as usize)
    }

    /// Get bit at position
    pub fn get_bit(&self, pos: usize) -> bool {
        let word_idx = pos / Self::WORD_BITS;
        if word_idx >= self.words.len() {
            return false;
        }
        let bit_idx = pos % Self::WORD_BITS;
        (self.words[word_idx] >> bit_idx) & 1 == 1
    }

    /// Set bit at position
    pub fn set_bit(&mut self, pos: usize) {
        let word_idx = pos / Self::WORD_BITS;
        if word_idx >= self.words.len() {
            self.words.resize(word_idx + 1, 0);
        }
        let bit_idx = pos % Self::WORD_BITS;
        self.words[word_idx] |= 1 << bit_idx;
    }

    /// Compare with another BigUint
    pub fn cmp(&self, other: &BigUint) -> Ordering {
        if self.words.len() != other.words.len() {
            return self.words.len().cmp(&other.words.len());
        }

        for i in (0..self.words.len()).rev() {
            match self.words[i].cmp(&other.words[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }

        Ordering::Equal
    }

    /// Modular addition: (self + other) % modulus
    pub fn add_mod(&self, other: &BigUint, modulus: &BigUint) -> BigUint {
        let sum = self + other;
        &sum % modulus
    }

    /// Modular subtraction: (self - other) % modulus
    pub fn sub_mod(&self, other: &BigUint, modulus: &BigUint) -> BigUint {
        if self >= other {
            let diff = self - other;
            &diff % modulus
        } else {
            let temp = other - self;
            let result = modulus - &temp;
            &result % modulus
        }
    }

    /// Modular multiplication: (self * other) % modulus
    pub fn mul_mod(&self, other: &BigUint, modulus: &BigUint) -> BigUint {
        let prod = self * other;
        &prod % modulus
    }

    /// Modular exponentiation: self^exp % modulus (using square-and-multiply)
    pub fn pow_mod(&self, exp: &BigUint, modulus: &BigUint) -> BigUint {
        if modulus.is_one() {
            return BigUint::zero();
        }

        let mut result = BigUint::one();
        let mut base = self % modulus;
        let mut e = exp.clone();

        while !e.is_zero() {
            if e.get_bit(0) {
                result = result.mul_mod(&base, modulus);
            }
            base = base.mul_mod(&base, modulus);
            e = &e >> 1;
        }

        result
    }

    /// Modular inverse using Extended Euclidean Algorithm
    /// Returns None if inverse doesn't exist
    pub fn inv_mod(&self, modulus: &BigUint) -> Option<BigUint> {
        if self.is_zero() || modulus.is_zero() {
            return None;
        }

        // Extended Euclidean Algorithm for BigUint
        let mut t = BigUint::zero();
        let mut newt = BigUint::one();
        let mut r = modulus.clone();
        let mut newr = self % modulus;

        while !newr.is_zero() {
            let quotient = &r / &newr;
            
            // Update r
            let temp_r = newr.clone();
            newr = if &r >= &(&quotient * &newr) {
                &r - &(&quotient * &temp_r)
            } else {
                // This shouldn't happen in proper extended gcd
                return None;
            };
            r = temp_r;
            
            // Update t (with modular arithmetic to handle "negative" values)
            let temp_t = newt.clone();
            let qt = quotient.mul_mod(&newt, modulus);
            newt = if &t >= &qt {
                &t - &qt
            } else {
                // t is "negative", so we compute modulus - (qt - t)
                let diff = &qt - &t;
                modulus - &diff
            };
            t = temp_t;
        }

        if !r.is_one() {
            return None; // No inverse exists
        }

        Some(t)
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        BigUint::cmp(self, other)
    }
}

// Addition
impl Add for &BigUint {
    type Output = BigUint;

    fn add(self, other: &BigUint) -> BigUint {
        let max_len = self.words.len().max(other.words.len());
        let mut result = BigUint {
            words: vec![0; max_len + 1],
        };

        let mut carry = 0u64;
        for i in 0..max_len {
            let a = if i < self.words.len() { self.words[i] } else { 0 };
            let b = if i < other.words.len() { other.words[i] } else { 0 };
            
            let (sum1, overflow1) = a.overflowing_add(b);
            let (sum2, overflow2) = sum1.overflowing_add(carry);
            
            result.words[i] = sum2;
            carry = (overflow1 as u64) + (overflow2 as u64);
        }

        if carry > 0 {
            result.words[max_len] = carry;
        }

        result.normalize();
        result
    }
}

impl Add for BigUint {
    type Output = BigUint;

    fn add(self, other: BigUint) -> BigUint {
        &self + &other
    }
}

// Subtraction
impl Sub for &BigUint {
    type Output = BigUint;

    fn sub(self, other: &BigUint) -> BigUint {
        if self < other {
            panic!("Attempt to subtract with underflow");
        }

        let mut result = BigUint {
            words: vec![0; self.words.len()],
        };

        let mut borrow = 0u64;
        for i in 0..self.words.len() {
            let a = self.words[i];
            let b = if i < other.words.len() { other.words[i] } else { 0 };
            
            let (diff1, underflow1) = a.overflowing_sub(b);
            let (diff2, underflow2) = diff1.overflowing_sub(borrow);
            
            result.words[i] = diff2;
            borrow = (underflow1 as u64) + (underflow2 as u64);
        }

        result.normalize();
        result
    }
}

impl Sub for BigUint {
    type Output = BigUint;

    fn sub(self, other: BigUint) -> BigUint {
        &self - &other
    }
}

// Multiplication
impl Mul for &BigUint {
    type Output = BigUint;

    fn mul(self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::zero();
        }

        let mut result = BigUint {
            words: vec![0; self.words.len() + other.words.len()],
        };

        for i in 0..self.words.len() {
            let mut carry = 0u128;
            for j in 0..other.words.len() {
                let product = (self.words[i] as u128) * (other.words[j] as u128)
                    + (result.words[i + j] as u128)
                    + carry;
                
                result.words[i + j] = product as u64;
                carry = product >> 64;
            }
            if carry > 0 {
                result.words[i + other.words.len()] = carry as u64;
            }
        }

        result.normalize();
        result
    }
}

impl Mul for BigUint {
    type Output = BigUint;

    fn mul(self, other: BigUint) -> BigUint {
        &self * &other
    }
}

// Division and Remainder
impl Div for &BigUint {
    type Output = BigUint;

    fn div(self, other: &BigUint) -> BigUint {
        let (quotient, _) = self.div_rem(other);
        quotient
    }
}

impl Div for BigUint {
    type Output = BigUint;

    fn div(self, other: BigUint) -> BigUint {
        &self / &other
    }
}

impl Rem for &BigUint {
    type Output = BigUint;

    fn rem(self, other: &BigUint) -> BigUint {
        let (_, remainder) = self.div_rem(other);
        remainder
    }
}

impl Rem for BigUint {
    type Output = BigUint;

    fn rem(self, other: BigUint) -> BigUint {
        &self % &other
    }
}

impl BigUint {
    /// Division with remainder
    fn div_rem(&self, divisor: &BigUint) -> (BigUint, BigUint) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        if self < divisor {
            return (BigUint::zero(), self.clone());
        }

        if divisor.is_one() {
            return (self.clone(), BigUint::zero());
        }

        // Long division algorithm
        let mut quotient = BigUint::zero();
        let mut remainder = BigUint::zero();

        for i in (0..self.bit_len()).rev() {
            remainder = &remainder << 1;
            if self.get_bit(i) {
                remainder.set_bit(0);
            }

            if remainder >= *divisor {
                remainder = &remainder - divisor;
                quotient.set_bit(i);
            }
        }

        quotient.normalize();
        remainder.normalize();
        (quotient, remainder)
    }
}

// Shift operations
impl Shl<usize> for &BigUint {
    type Output = BigUint;

    fn shl(self, shift: usize) -> BigUint {
        if shift == 0 || self.is_zero() {
            return self.clone();
        }

        let word_shift = shift / BigUint::WORD_BITS;
        let bit_shift = shift % BigUint::WORD_BITS;

        let mut result = BigUint {
            words: vec![0; self.words.len() + word_shift + 1],
        };

        if bit_shift == 0 {
            for i in 0..self.words.len() {
                result.words[i + word_shift] = self.words[i];
            }
        } else {
            let mut carry = 0u64;
            for i in 0..self.words.len() {
                let word = self.words[i];
                result.words[i + word_shift] = (word << bit_shift) | carry;
                carry = word >> (BigUint::WORD_BITS - bit_shift);
            }
            if carry > 0 {
                result.words[self.words.len() + word_shift] = carry;
            }
        }

        result.normalize();
        result
    }
}

impl Shl<usize> for BigUint {
    type Output = BigUint;

    fn shl(self, shift: usize) -> BigUint {
        &self << shift
    }
}

impl Shr<usize> for &BigUint {
    type Output = BigUint;

    fn shr(self, shift: usize) -> BigUint {
        if shift == 0 || self.is_zero() {
            return self.clone();
        }

        let word_shift = shift / BigUint::WORD_BITS;
        if word_shift >= self.words.len() {
            return BigUint::zero();
        }

        let bit_shift = shift % BigUint::WORD_BITS;
        let mut result = BigUint {
            words: vec![0; self.words.len() - word_shift],
        };

        if bit_shift == 0 {
            for i in 0..result.words.len() {
                result.words[i] = self.words[i + word_shift];
            }
        } else {
            for i in 0..result.words.len() {
                let word = self.words[i + word_shift];
                let next_word = if i + word_shift + 1 < self.words.len() {
                    self.words[i + word_shift + 1]
                } else {
                    0
                };
                result.words[i] = (word >> bit_shift) | (next_word << (BigUint::WORD_BITS - bit_shift));
            }
        }

        result.normalize();
        result
    }
}

impl Shr<usize> for BigUint {
    type Output = BigUint;

    fn shr(self, shift: usize) -> BigUint {
        &self >> shift
    }
}

// Bitwise operations
impl BitAnd for &BigUint {
    type Output = BigUint;

    fn bitand(self, other: &BigUint) -> BigUint {
        let min_len = self.words.len().min(other.words.len());
        let mut result = BigUint {
            words: vec![0; min_len],
        };

        for i in 0..min_len {
            result.words[i] = self.words[i] & other.words[i];
        }

        result.normalize();
        result
    }
}

impl BitOr for &BigUint {
    type Output = BigUint;

    fn bitor(self, other: &BigUint) -> BigUint {
        let max_len = self.words.len().max(other.words.len());
        let mut result = BigUint {
            words: vec![0; max_len],
        };

        for i in 0..max_len {
            let a = if i < self.words.len() { self.words[i] } else { 0 };
            let b = if i < other.words.len() { other.words[i] } else { 0 };
            result.words[i] = a | b;
        }

        result.normalize();
        result
    }
}

impl BitXor for &BigUint {
    type Output = BigUint;

    fn bitxor(self, other: &BigUint) -> BigUint {
        let max_len = self.words.len().max(other.words.len());
        let mut result = BigUint {
            words: vec![0; max_len],
        };

        for i in 0..max_len {
            let a = if i < self.words.len() { self.words[i] } else { 0 };
            let b = if i < other.words.len() { other.words[i] } else { 0 };
            result.words[i] = a ^ b;
        }

        result.normalize();
        result
    }
}

impl fmt::Display for BigUint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }

        // Convert to decimal string
        let mut num = self.clone();
        let mut digits = Vec::new();
        let ten = BigUint::from_u64(10);

        while !num.is_zero() {
            let (quotient, remainder) = num.div_rem(&ten);
            digits.push((remainder.words[0] as u8 + b'0') as char);
            num = quotient;
        }

        digits.reverse();
        write!(f, "{}", digits.iter().collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let a = BigUint::from_u64(100);
        let b = BigUint::from_u64(50);

        assert_eq!(&a + &b, BigUint::from_u64(150));
        assert_eq!(&a - &b, BigUint::from_u64(50));
        assert_eq!(&a * &b, BigUint::from_u64(5000));
        assert_eq!(&a / &b, BigUint::from_u64(2));
        assert_eq!(&a % &b, BigUint::from_u64(0));
    }

    #[test]
    fn test_pow_mod() {
        let base = BigUint::from_u64(2);
        let exp = BigUint::from_u64(10);
        let modulus = BigUint::from_u64(1000);

        let result = base.pow_mod(&exp, &modulus);
        assert_eq!(result, BigUint::from_u64(24)); // 2^10 = 1024 ≡ 24 (mod 1000)
    }
}
