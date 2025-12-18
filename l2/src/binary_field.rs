use crate::bigint::BigUint;
use crate::field::Field;
use std::fmt;
use std::ops::{Add, Sub, Mul, Div, Neg, BitXor};

/// Binary field F_{2^k} (also written as F_{2^m})
/// Elements represented as bit strings (polynomials over F_2)
/// Uses little-endian bit ordering (LSB first in first byte)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryFieldElement {
    /// Bit string representation stored as bytes (little-endian)
    bits: Vec<u8>,
    /// Irreducible polynomial for field reduction (as bit string)
    irreducible: Vec<u8>,
    /// Extension degree k (field has 2^k elements)
    degree: usize,
}

impl BinaryFieldElement {
    /// Create a new binary field element from bit vector
    /// bits should have length <= degree
    pub fn new(bits: Vec<u8>, irreducible: Vec<u8>, degree: usize) -> Self {
        let mut elem = BinaryFieldElement {
            bits,
            irreducible,
            degree,
        };
        elem.reduce();
        elem
    }
    
    /// Create from a BigUint
    pub fn from_biguint(value: BigUint, irreducible: Vec<u8>, degree: usize) -> Self {
        let bits = value.to_bytes_le();
        Self::new(bits, irreducible, degree)
    }
    
    /// Create from u64
    pub fn from_u64(value: u64, irreducible: Vec<u8>, degree: usize) -> Self {
        let bits = value.to_le_bytes().to_vec();
        Self::new(bits, irreducible, degree)
    }
    
    /// Create zero element
    pub fn zero(irreducible: Vec<u8>, degree: usize) -> Self {
        BinaryFieldElement {
            bits: vec![0],
            irreducible,
            degree,
        }
    }
    
    /// Create one element
    pub fn one(irreducible: Vec<u8>, degree: usize) -> Self {
        BinaryFieldElement {
            bits: vec![1],
            irreducible,
            degree,
        }
    }
    
    /// Check if element is zero
    pub fn is_zero(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }
    
    /// Get the irreducible polynomial
    pub fn irreducible(&self) -> &Vec<u8> {
        &self.irreducible
    }
    
    /// Get the extension degree
    pub fn degree(&self) -> usize {
        self.degree
    }
    
    /// Convert to bytes (little-endian)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bits.clone()
    }
    
    /// Get bit at position i
    fn get_bit(&self, i: usize) -> bool {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        
        if byte_idx >= self.bits.len() {
            return false;
        }
        
        (self.bits[byte_idx] >> bit_idx) & 1 == 1
    }
    
    /// Set bit at position i
    fn set_bit(&mut self, i: usize, value: bool) {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        
        // Ensure we have enough bytes
        while self.bits.len() <= byte_idx {
            self.bits.push(0);
        }
        
        if value {
            self.bits[byte_idx] |= 1 << bit_idx;
        } else {
            self.bits[byte_idx] &= !(1 << bit_idx);
        }
    }
    
    /// Get the degree of the polynomial (highest bit set)
    fn poly_degree(&self) -> Option<usize> {
        (0..self.degree).rev().find(|&i| self.get_bit(i))
    }
    
    /// Reduce modulo irreducible polynomial
    fn reduce(&mut self) {
        let irred_degree = self.irreducible_degree();
        
        while let Some(deg) = self.poly_degree() {
            if deg < irred_degree {
                break;
            }
            
            // Subtract (XOR) irreducible polynomial shifted by (deg - irred_degree)
            let shift = deg - irred_degree;
            for i in 0..=irred_degree {
                if self.get_irreducible_bit(i) {
                    let current = self.get_bit(i + shift);
                    self.set_bit(i + shift, !current);
                }
            }
        }
        
        // Remove trailing zero bytes
        while self.bits.len() > 1 && self.bits[self.bits.len() - 1] == 0 {
            self.bits.pop();
        }
    }
    
    /// Get the degree of irreducible polynomial
    fn irreducible_degree(&self) -> usize {
        for i in (0..self.irreducible.len() * 8).rev() {
            if self.get_irreducible_bit(i) {
                return i;
            }
        }
        0
    }
    
    /// Get bit from irreducible polynomial
    fn get_irreducible_bit(&self, i: usize) -> bool {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        
        if byte_idx >= self.irreducible.len() {
            return false;
        }
        
        (self.irreducible[byte_idx] >> bit_idx) & 1 == 1
    }
    
    /// Addition in F_{2^k} is XOR
    pub fn add(&self, other: &Self) -> Self {
        self.xor(other)
    }
    
    /// Negation in F_{2^k} is identity (since -x = x in characteristic 2)
    pub fn neg(&self) -> Self {
        self.clone()
    }
    
    /// Subtraction in F_{2^k} is also XOR
    pub fn sub(&self, other: &Self) -> Self {
        self.xor(other)
    }
    
    /// XOR operation (addition in F_2)
    fn xor(&self, other: &Self) -> Self {
        if self.irreducible != other.irreducible || self.degree != other.degree {
            panic!("Cannot XOR elements from different fields");
        }
        
        let max_len = self.bits.len().max(other.bits.len());
        let mut result = vec![0u8; max_len];
        
        for (i, item) in result.iter_mut().enumerate().take(max_len) {
            let a = if i < self.bits.len() { self.bits[i] } else { 0 };
            let b = if i < other.bits.len() { other.bits[i] } else { 0 };
            *item = a ^ b;
        }
        
        BinaryFieldElement {
            bits: result,
            irreducible: self.irreducible.clone(),
            degree: self.degree,
        }
    }
    
    /// Multiplication in F_{2^k}
    /// Use shift-and-add algorithm (like peasant multiplication)
    pub fn mul(&self, other: &Self) -> Self {
        if self.irreducible != other.irreducible || self.degree != other.degree {
            panic!("Cannot multiply elements from different fields");
        }
        
        let mut result = Self::zero(self.irreducible.clone(), self.degree);
        let mut temp = self.clone();
        
        for i in 0..self.degree {
            if other.get_bit(i) {
                result = BinaryFieldElement::add(&result, &temp);
            }
            
            // Multiply temp by X (shift left by 1)
            let overflow = temp.get_bit(self.degree - 1);
            temp = temp.shift_left(1);
            
            if overflow {
                // Reduce by subtracting (XOR) irreducible polynomial
                for j in 0..=self.irreducible_degree() {
                    if self.get_irreducible_bit(j) {
                        let current = temp.get_bit(j);
                        temp.set_bit(j, current ^ true);
                    }
                }
            }
            
            temp.reduce();
        }
        
        result.reduce();
        result
    }
    
    /// Shift left by n bits
    fn shift_left(&self, n: usize) -> Self {
        if n == 0 {
            return self.clone();
        }
        
        let byte_shift = n / 8;
        let bit_shift = n % 8;
        
        let new_len = self.bits.len() + byte_shift + 1;
        let mut result = vec![0u8; new_len];
        
        if bit_shift == 0 {
            result[byte_shift..(self.bits.len() + byte_shift)].copy_from_slice(&self.bits[..]);
        } else {
            let mut carry = 0u8;
            for i in 0..self.bits.len() {
                result[i + byte_shift] = (self.bits[i] << bit_shift) | carry;
                carry = self.bits[i] >> (8 - bit_shift);
            }
            if carry > 0 {
                result[self.bits.len() + byte_shift] = carry;
            }
        }
        
        BinaryFieldElement {
            bits: result,
            irreducible: self.irreducible.clone(),
            degree: self.degree,
        }
    }
    
    /// Multiplicative inverse using Extended Euclidean Algorithm
    pub fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        
        // Extended GCD in F_2[X]
        let mut r0 = self.to_biguint();
        let mut r1 = self.irreducible_to_biguint();
        let mut s0 = BigUint::one();
        let mut s1 = BigUint::zero();
        
        while !r1.is_zero() {
            let (q, r) = Self::poly_div_mod_f2(&r0, &r1);
            
            // r0, r1 = r1, r0 - q*r1 (but subtraction is XOR in F_2)
            r0 = r1;
            r1 = r;
            
            // s0, s1 = s1, s0 XOR (q * s1)
            let qs1 = Self::poly_mul_f2(&q, &s1);
            let new_s = Self::poly_xor(&s0, &qs1);
            s0 = s1;
            s1 = new_s;
        }
        
        // r0 should be 1 (constant polynomial)
        if !r0.is_one() {
            return None;
        }
        
        Some(Self::from_biguint(s0, self.irreducible.clone(), self.degree))
    }
    
    /// Convert to BigUint
    fn to_biguint(&self) -> BigUint {
        BigUint::from_bytes_le(&self.bits)
    }
    
    /// Convert irreducible to BigUint
    fn irreducible_to_biguint(&self) -> BigUint {
        BigUint::from_bytes_le(&self.irreducible)
    }
    
    /// Polynomial division in F_2\[X\]
    fn poly_div_mod_f2(dividend: &BigUint, divisor: &BigUint) -> (BigUint, BigUint) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }
        
        let mut remainder = dividend.clone();
        let mut quotient = BigUint::zero();
        
        let divisor_degree = divisor.bit_len();
        
        while !remainder.is_zero() && remainder.bit_len() >= divisor_degree {
            let deg_diff = remainder.bit_len() - divisor_degree;
            quotient.set_bit(deg_diff);
            
            let shifted_divisor = divisor << deg_diff;
            remainder = &remainder ^ &shifted_divisor;
        }
        
        (quotient, remainder)
    }
    
    /// Polynomial multiplication in F_2\[X\] (without reduction)
    fn poly_mul_f2(a: &BigUint, b: &BigUint) -> BigUint {
        let mut result = BigUint::zero();
        
        for i in 0..b.bit_len() {
            if b.get_bit(i) {
                let shifted = a << i;
                result = &result ^ &shifted;
            }
        }
        
        result
    }
    
    /// XOR two BigUints
    fn poly_xor(a: &BigUint, b: &BigUint) -> BigUint {
        a ^ b
    }
}

impl Field for BinaryFieldElement {
    fn add(&self, other: &Self) -> Self {
        BinaryFieldElement::add(self, other)
    }
    
    fn neg(&self) -> Self {
        BinaryFieldElement::neg(self)
    }
    
    fn mul(&self, other: &Self) -> Self {
        BinaryFieldElement::mul(self, other)
    }
    
    fn inv(&self) -> Option<Self> {
        BinaryFieldElement::inv(self)
    }
    
    fn pow(&self, exp: &BigUint) -> Self {
        if exp.is_zero() {
            return Self::one(self.irreducible.clone(), self.degree);
        }
        
        let mut result = Self::one(self.irreducible.clone(), self.degree);
        let mut base = self.clone();
        let mut e = exp.clone();
        
        while !e.is_zero() {
            if e.get_bit(0) {
                result = Field::mul(&result, &base);
            }
            base = Field::mul(&base, &base);
            e = &e >> 1;
        }
        
        result
    }
    
    fn zero() -> Self {
        panic!("Use zero() with irreducible polynomial instead");
    }
    
    fn one() -> Self {
        panic!("Use one() with irreducible polynomial instead");
    }
    
    fn is_zero(&self) -> bool {
        BinaryFieldElement::is_zero(self)
    }
}

// Implement standard operators
impl Add for &BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn add(self, other: &BinaryFieldElement) -> BinaryFieldElement {
        BinaryFieldElement::add(self, other)
    }
}

impl Add for BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn add(self, other: BinaryFieldElement) -> BinaryFieldElement {
        BinaryFieldElement::add(&self, &other)
    }
}

impl Sub for &BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn sub(self, other: &BinaryFieldElement) -> BinaryFieldElement {
        BinaryFieldElement::sub(self, other)
    }
}

impl Sub for BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn sub(self, other: BinaryFieldElement) -> BinaryFieldElement {
        BinaryFieldElement::sub(&self, &other)
    }
}

impl Mul for &BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn mul(self, other: &BinaryFieldElement) -> BinaryFieldElement {
        BinaryFieldElement::mul(self, other)
    }
}

impl Mul for BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn mul(self, other: BinaryFieldElement) -> BinaryFieldElement {
        BinaryFieldElement::mul(&self, &other)
    }
}

impl Div for &BinaryFieldElement {
    type Output = Option<BinaryFieldElement>;
    
    fn div(self, other: &BinaryFieldElement) -> Option<BinaryFieldElement> {
        Field::div(self, other)
    }
}

impl Div for BinaryFieldElement {
    type Output = Option<BinaryFieldElement>;
    
    fn div(self, other: BinaryFieldElement) -> Option<BinaryFieldElement> {
        Field::div(&self, &other)
    }
}

impl Neg for &BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn neg(self) -> BinaryFieldElement {
        BinaryFieldElement::neg(self)
    }
}

impl Neg for BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn neg(self) -> BinaryFieldElement {
        BinaryFieldElement::neg(&self)
    }
}

impl BitXor for &BinaryFieldElement {
    type Output = BinaryFieldElement;
    
    fn bitxor(self, other: &BinaryFieldElement) -> BinaryFieldElement {
        self.xor(other)
    }
}

impl fmt::Display for BinaryFieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0b")?;
        let mut found_one = false;
        for i in (0..self.degree).rev() {
            if self.get_bit(i) {
                write!(f, "1")?;
                found_one = true;
            } else if found_one {
                write!(f, "0")?;
            }
        }
        if !found_one {
            write!(f, "0")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_field_arithmetic() {
        // F_{2^8} with irreducible polynomial X^8 + X^4 + X^3 + X + 1
        // This is the AES polynomial: 0x11B in hex = 0b100011011
        let irreducible = vec![0b00011011, 0b00000001]; // Little-endian: bit 0-7, then bit 8
        let degree = 8;
        
        let a = BinaryFieldElement::from_u64(0b00000011, irreducible.clone(), degree); // X + 1
        let b = BinaryFieldElement::from_u64(0b00000101, irreducible.clone(), degree); // X^2 + 1
        
        // Test addition (XOR)
        let sum = &a + &b;
        assert_eq!(sum.bits[0], 0b00000110); // (X + 1) + (X^2 + 1) = X^2 + X
        
        // Test multiplication
        let prod = &a * &b;
        // (X + 1)(X^2 + 1) = X^3 + X^2 + X + 1
        assert!(!prod.is_zero());
        
        // Test that addition is self-inverse
        let zero = &a + &a;
        assert!(zero.is_zero());
    }
    
    #[test]
    fn test_binary_field_inverse() {
        // F_{2^4} with irreducible polynomial X^4 + X + 1 = 0b10011
        let irreducible = vec![0b00010011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(0b0011, irreducible.clone(), degree); // X + 1
        
        if let Some(inv) = a.inv() {
            let product = &a * &inv;
            // Product should be 1
            assert_eq!(product.bits[0] & 0x0F, 1);
        }
    }
    
    #[test]
    fn test_binary_field_exponentiation() {
        // F_{2^4} with irreducible polynomial X^4 + X + 1 = 0b10011
        let irreducible = vec![0b00010011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(0b0011, irreducible.clone(), degree); // X + 1
        
        // Test a^0 = 1
        let result = a.pow(&BigUint::from_u64(0));
        assert_eq!(result.bits[0] & 0x0F, 1);
        
        // Test a^1 = a
        let result = a.pow(&BigUint::from_u64(1));
        assert_eq!(result.bits[0] & 0x0F, 0b0011);
        
        // Test a^2 = a * a
        let result = a.pow(&BigUint::from_u64(2));
        let expected = &a * &a;
        assert_eq!(result.bits[0] & 0x0F, expected.bits[0] & 0x0F);
        
        // Test that a^(2^k - 1) = 1 for non-zero a (Fermat's Little Theorem)
        // In F_{2^4}, order is 2^4 - 1 = 15
        let result = a.pow(&BigUint::from_u64(15));
        assert_eq!(result.bits[0] & 0x0F, 1);
        
        // Test larger exponent
        let result = a.pow(&BigUint::from_u64(7));
        let mut expected = a.clone();
        for _ in 0..6 {
            expected = &expected * &a;
        }
        assert_eq!(result.bits[0] & 0x0F, expected.bits[0] & 0x0F);
    }
}
