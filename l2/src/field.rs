use crate::bigint::BigUint;
use std::ops::{Add, Sub, Mul, Div, Neg};
use std::fmt;

/// Trait for field operations
pub trait Field: Sized + Clone + PartialEq {
    /// Addition
    fn add(&self, other: &Self) -> Self;
    
    /// Negation
    fn neg(&self) -> Self;
    
    /// Subtraction (a - b = a + (-b))
    fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }
    
    /// Multiplication
    fn mul(&self, other: &Self) -> Self;
    
    /// Multiplicative inverse
    fn inv(&self) -> Option<Self>;
    
    /// Division (a / b = a * b^(-1))
    fn div(&self, other: &Self) -> Option<Self> {
        other.inv().map(|inv| self.mul(&inv))
    }
    
    /// Exponentiation with efficient square-and-multiply algorithm
    /// Complexity: O(log(exp)) multiplications
    fn pow(&self, exp: &BigUint) -> Self {
        if exp.is_zero() {
            return Self::one();
        }
        
        let mut result = Self::one();
        let mut base = self.clone();
        let mut e = exp.clone();
        
        while !e.is_zero() {
            if e.get_bit(0) {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            e = &e >> 1;
        }
        
        result
    }
    
    /// Additive identity (0)
    fn zero() -> Self;
    
    /// Multiplicative identity (1)
    fn one() -> Self;
    
    /// Check if zero
    fn is_zero(&self) -> bool;
}

/// Element of the prime field Fp (k=1 case)
/// Represents integers modulo a prime p
#[derive(Clone, Debug)]
pub struct FieldElement {
    value: BigUint,
    modulus: BigUint, // prime p
}

impl FieldElement {
    /// Create a new field element
    pub fn new(value: BigUint, modulus: BigUint) -> Self {
        let val = &value % &modulus;
        FieldElement {
            value: val,
            modulus,
        }
    }
    
    /// Create from u64
    pub fn from_u64(value: u64, modulus: BigUint) -> Self {
        Self::new(BigUint::from_u64(value), modulus)
    }
    
    /// Get the value
    pub fn value(&self) -> &BigUint {
        &self.value
    }
    
    /// Get the modulus
    pub fn modulus(&self) -> &BigUint {
        &self.modulus
    }
    
    /// Create a field element with value 0
    pub fn zero_with_modulus(modulus: BigUint) -> Self {
        FieldElement {
            value: BigUint::zero(),
            modulus,
        }
    }
    
    /// Create a field element with value 1
    pub fn one_with_modulus(modulus: BigUint) -> Self {
        FieldElement {
            value: BigUint::one(),
            modulus,
        }
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        if self.modulus != other.modulus {
            panic!("Cannot compare field elements with different moduli");
        }
        self.value == other.value
    }
}

impl Eq for FieldElement {}

impl Field for FieldElement {
    fn add(&self, other: &Self) -> Self {
        if self.modulus != other.modulus {
            panic!("Cannot add field elements with different moduli");
        }
        FieldElement {
            value: self.value.add_mod(&other.value, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }
    
    fn neg(&self) -> Self {
        if self.value.is_zero() {
            return self.clone();
        }
        FieldElement {
            value: &self.modulus - &self.value,
            modulus: self.modulus.clone(),
        }
    }
    
    fn mul(&self, other: &Self) -> Self {
        if self.modulus != other.modulus {
            panic!("Cannot multiply field elements with different moduli");
        }
        FieldElement {
            value: self.value.mul_mod(&other.value, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }
    
    fn inv(&self) -> Option<Self> {
        if self.value.is_zero() {
            return None;
        }
        
        self.value.inv_mod(&self.modulus).map(|inv| FieldElement {
            value: inv,
            modulus: self.modulus.clone(),
        })
    }
    
    fn pow(&self, exp: &BigUint) -> Self {
        FieldElement {
            value: self.value.pow_mod(exp, &self.modulus),
            modulus: self.modulus.clone(),
        }
    }
    
    fn zero() -> Self {
        panic!("Cannot create zero without modulus. Use zero_with_modulus instead.");
    }
    
    fn one() -> Self {
        panic!("Cannot create one without modulus. Use one_with_modulus instead.");
    }
    
    fn is_zero(&self) -> bool {
        self.value.is_zero()
    }
}

// Implement standard operators for convenience
impl Add for &FieldElement {
    type Output = FieldElement;
    
    fn add(self, other: &FieldElement) -> FieldElement {
        Field::add(self, other)
    }
}

impl Add for FieldElement {
    type Output = FieldElement;
    
    fn add(self, other: FieldElement) -> FieldElement {
        Field::add(&self, &other)
    }
}

impl Sub for &FieldElement {
    type Output = FieldElement;
    
    fn sub(self, other: &FieldElement) -> FieldElement {
        Field::sub(self, other)
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;
    
    fn sub(self, other: FieldElement) -> FieldElement {
        Field::sub(&self, &other)
    }
}

impl Mul for &FieldElement {
    type Output = FieldElement;
    
    fn mul(self, other: &FieldElement) -> FieldElement {
        Field::mul(self, other)
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;
    
    fn mul(self, other: FieldElement) -> FieldElement {
        Field::mul(&self, &other)
    }
}

impl Div for &FieldElement {
    type Output = Option<FieldElement>;
    
    fn div(self, other: &FieldElement) -> Option<FieldElement> {
        Field::div(self, other)
    }
}

impl Div for FieldElement {
    type Output = Option<FieldElement>;
    
    fn div(self, other: FieldElement) -> Option<FieldElement> {
        Field::div(&self, &other)
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;
    
    fn neg(self) -> FieldElement {
        Field::neg(self)
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;
    
    fn neg(self) -> FieldElement {
        Field::neg(&self)
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} (mod {})", self.value, self.modulus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_arithmetic() {
        // Work in F_7
        let p = BigUint::from_u64(7);
        
        let a = FieldElement::from_u64(3, p.clone());
        let b = FieldElement::from_u64(5, p.clone());
        
        // 3 + 5 = 8 ≡ 1 (mod 7)
        let sum = &a + &b;
        assert_eq!(sum.value(), &BigUint::from_u64(1));
        
        // 3 - 5 = -2 ≡ 5 (mod 7)
        let diff = &a - &b;
        assert_eq!(diff.value(), &BigUint::from_u64(5));
        
        // 3 * 5 = 15 ≡ 1 (mod 7)
        let prod = &a * &b;
        assert_eq!(prod.value(), &BigUint::from_u64(1));
        
        // 3^(-1) ≡ 5 (mod 7) because 3*5 = 15 ≡ 1 (mod 7)
        let inv = a.inv().unwrap();
        assert_eq!(inv.value(), &BigUint::from_u64(5));
        
        // 3 / 5 = 3 * 5^(-1) = 3 * 3 = 9 ≡ 2 (mod 7)
        let div = (&a / &b).unwrap();
        assert_eq!(div.value(), &BigUint::from_u64(2));
    }
    
    #[test]
    fn test_exponentiation() {
        // Work in F_11
        let p = BigUint::from_u64(11);
        let a = FieldElement::from_u64(2, p.clone());
        
        // 2^10 ≡ 1 (mod 11) by Fermat's Little Theorem
        let result = a.pow(&BigUint::from_u64(10));
        assert_eq!(result.value(), &BigUint::from_u64(1));
        
        // 2^5 = 32 ≡ 10 (mod 11)
        let result = a.pow(&BigUint::from_u64(5));
        assert_eq!(result.value(), &BigUint::from_u64(10));
    }
}
