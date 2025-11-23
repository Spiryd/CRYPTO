use crate::field::{Field, FieldElement};
use std::fmt;
use std::ops::{Add, Sub, Mul};

/// Polynomial with coefficients in a field F
/// Coefficients stored from lowest to highest degree: [a0, a1, a2, ...] = a0 + a1*X + a2*X^2 + ...
#[derive(Clone, Debug)]
pub struct Polynomial<F: Field> {
    coeffs: Vec<F>,
}

impl<F: Field> Polynomial<F> {
    /// Create a new polynomial from coefficients
    pub fn new(coeffs: Vec<F>) -> Self {
        let mut poly = Polynomial { coeffs };
        poly.normalize();
        poly
    }
    
    /// Create zero polynomial
    pub fn zero() -> Self {
        Polynomial { coeffs: vec![] }
    }
    
    /// Create polynomial from a single coefficient (constant)
    pub fn constant(coeff: F) -> Self {
        if coeff.is_zero() {
            Polynomial::zero()
        } else {
            Polynomial { coeffs: vec![coeff] }
        }
    }
    
    /// Get degree of polynomial (-1 for zero polynomial)
    pub fn degree(&self) -> i32 {
        if self.coeffs.is_empty() {
            -1
        } else {
            (self.coeffs.len() - 1) as i32
        }
    }
    
    /// Check if polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.coeffs.is_empty()
    }
    
    /// Get coefficient at index (0 if out of bounds)
    pub fn get_coeff(&self, index: usize) -> Option<&F> {
        self.coeffs.get(index)
    }
    
    /// Get all coefficients
    pub fn coeffs(&self) -> &[F] {
        &self.coeffs
    }
    
    /// Remove leading zero coefficients
    fn normalize(&mut self) {
        while !self.coeffs.is_empty() && self.coeffs.last().unwrap().is_zero() {
            self.coeffs.pop();
        }
    }
    
    /// Polynomial addition
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);
        
        for i in 0..max_len {
            let a = self.coeffs.get(i);
            let b = other.coeffs.get(i);
            
            let sum = match (a, b) {
                (Some(a), Some(b)) => a.add(b),
                (Some(a), None) => a.clone(),
                (None, Some(b)) => b.clone(),
                (None, None) => unreachable!(),
            };
            
            result.push(sum);
        }
        
        Polynomial::new(result)
    }
    
    /// Polynomial negation
    pub fn neg(&self) -> Self {
        let coeffs = self.coeffs.iter().map(|c| c.neg()).collect();
        Polynomial::new(coeffs)
    }
    
    /// Polynomial subtraction
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }
    
    /// Polynomial multiplication
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Polynomial::zero();
        }
        
        let result_len = self.coeffs.len() + other.coeffs.len() - 1;
        
        // Create zero by subtracting a coefficient from itself
        let zero = self.coeffs[0].sub(&self.coeffs[0]);
        let mut result = vec![zero; result_len];
        
        for i in 0..self.coeffs.len() {
            for j in 0..other.coeffs.len() {
                let prod = self.coeffs[i].mul(&other.coeffs[j]);
                result[i + j] = result[i + j].add(&prod);
            }
        }
        
        Polynomial::new(result)
    }
    
    /// Polynomial division with remainder
    /// Returns (quotient, remainder) such that self = quotient * divisor + remainder
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        if divisor.is_zero() {
            panic!("Division by zero polynomial");
        }
        
        if self.degree() < divisor.degree() {
            return (Polynomial::zero(), self.clone());
        }
        
        let mut remainder = self.clone();
        let mut quotient_coeffs = vec![];
        
        let divisor_lead = divisor.coeffs.last().unwrap();
        let divisor_lead_inv = divisor_lead.inv().expect("Leading coefficient must be invertible");
        
        // Create zero element
        let zero = divisor_lead.sub(divisor_lead);
        
        while remainder.degree() >= divisor.degree() && !remainder.is_zero() {
            let degree_diff = (remainder.degree() - divisor.degree()) as usize;
            let remainder_lead = remainder.coeffs.last().unwrap();
            let coeff = remainder_lead.mul(&divisor_lead_inv);
            
            // Ensure quotient_coeffs has enough space
            while quotient_coeffs.len() <= degree_diff {
                quotient_coeffs.push(zero.clone());
            }
            quotient_coeffs[degree_diff] = coeff.clone();
            
            // Subtract coeff * X^degree_diff * divisor from remainder
            for i in 0..divisor.coeffs.len() {
                let idx = i + degree_diff;
                if idx < remainder.coeffs.len() {
                    let sub_val = divisor.coeffs[i].mul(&coeff);
                    remainder.coeffs[idx] = remainder.coeffs[idx].sub(&sub_val);
                }
            }
            
            remainder.normalize();
        }
        
        (Polynomial::new(quotient_coeffs), remainder)
    }
    
    /// Polynomial modulo
    pub fn modulo(&self, divisor: &Self) -> Self {
        self.div_rem(divisor).1
    }
    
    /// Evaluate polynomial at a point
    pub fn eval(&self, x: &F) -> F {
        if self.is_zero() {
            return x.clone().mul(&x.inv().unwrap()); // zero
        }
        
        // Horner's method for efficient evaluation
        let mut result = self.coeffs.last().unwrap().clone();
        for i in (0..self.coeffs.len() - 1).rev() {
            result = result.mul(x).add(&self.coeffs[i]);
        }
        result
    }
}

impl<F: Field> PartialEq for Polynomial<F> {
    fn eq(&self, other: &Self) -> bool {
        if self.coeffs.len() != other.coeffs.len() {
            return false;
        }
        self.coeffs.iter().zip(other.coeffs.iter()).all(|(a, b)| a == b)
    }
}

impl<F: Field> Eq for Polynomial<F> {}

impl<F: Field> Add for &Polynomial<F> {
    type Output = Polynomial<F>;
    
    fn add(self, other: &Polynomial<F>) -> Polynomial<F> {
        Polynomial::add(self, other)
    }
}

impl<F: Field> Sub for &Polynomial<F> {
    type Output = Polynomial<F>;
    
    fn sub(self, other: &Polynomial<F>) -> Polynomial<F> {
        Polynomial::sub(self, other)
    }
}

impl<F: Field> Mul for &Polynomial<F> {
    type Output = Polynomial<F>;
    
    fn mul(self, other: &Polynomial<F>) -> Polynomial<F> {
        Polynomial::mul(self, other)
    }
}

impl fmt::Display for Polynomial<FieldElement> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        
        let mut terms = Vec::new();
        for (i, coeff) in self.coeffs.iter().enumerate() {
            if coeff.is_zero() {
                continue;
            }
            
            let term = if i == 0 {
                format!("{}", coeff.value())
            } else if i == 1 {
                if coeff.value().is_one() {
                    "X".to_string()
                } else {
                    format!("{}*X", coeff.value())
                }
            } else if coeff.value().is_one() {
                format!("X^{}", i)
            } else {
                format!("{}*X^{}", coeff.value(), i)
            };
            
            terms.push(term);
        }
        
        write!(f, "{}", terms.join(" + "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigUint;

    #[test]
    fn test_polynomial_arithmetic() {
        // Work in F_7
        let p = BigUint::from_u64(7);
        
        // P(X) = 2 + 3X + X^2
        let p1 = Polynomial::new(vec![
            FieldElement::from_u64(2, p.clone()),
            FieldElement::from_u64(3, p.clone()),
            FieldElement::from_u64(1, p.clone()),
        ]);
        
        // Q(X) = 1 + X
        let p2 = Polynomial::new(vec![
            FieldElement::from_u64(1, p.clone()),
            FieldElement::from_u64(1, p.clone()),
        ]);
        
        // Test addition
        let sum = &p1 + &p2;
        assert_eq!(sum.degree(), 2);
        
        // Test multiplication
        let prod = &p1 * &p2;
        assert_eq!(prod.degree(), 3);
        
        // Test evaluation: P(2) = 2 + 3*2 + 2^2 = 2 + 6 + 4 = 12 ≡ 5 (mod 7)
        let x = FieldElement::from_u64(2, p.clone());
        let result = p1.eval(&x);
        assert_eq!(result.value(), &BigUint::from_u64(5));
    }
    
    #[test]
    fn test_polynomial_division() {
        // Work in F_5
        let p = BigUint::from_u64(5);
        
        // Dividend: X^2 + 2X + 3
        let dividend = Polynomial::new(vec![
            FieldElement::from_u64(3, p.clone()),
            FieldElement::from_u64(2, p.clone()),
            FieldElement::from_u64(1, p.clone()),
        ]);
        
        // Divisor: X + 1
        let divisor = Polynomial::new(vec![
            FieldElement::from_u64(1, p.clone()),
            FieldElement::from_u64(1, p.clone()),
        ]);
        
        let (quotient, remainder) = dividend.div_rem(&divisor);
        
        // Verify: dividend = quotient * divisor + remainder
        let reconstructed = &(&quotient * &divisor) + &remainder;
        assert_eq!(dividend, reconstructed);
    }
}
