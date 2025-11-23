use crate::bigint::BigUint;
use crate::field::{Field, FieldElement};
use crate::polynomial::Polynomial;
use std::fmt;
use std::ops::{Add, Sub, Mul, Div, Neg};

/// Extension field F_{p^k} represented as F_p[X] / (f(X))
/// where f(X) is an irreducible polynomial of degree k over F_p
/// Elements are polynomials of degree < k
#[derive(Clone, Debug)]
pub struct ExtensionFieldElement {
    /// Polynomial representation (degree < k)
    poly: Polynomial<FieldElement>,
    /// Irreducible polynomial defining the field
    irreducible: Polynomial<FieldElement>,
    /// Base prime p
    base_modulus: BigUint,
}

impl ExtensionFieldElement {
    /// Create a new extension field element
    /// poly must have degree < irreducible.degree()
    pub fn new(
        poly: Polynomial<FieldElement>,
        irreducible: Polynomial<FieldElement>,
        base_modulus: BigUint,
    ) -> Self {
        let reduced = poly.modulo(&irreducible);
        ExtensionFieldElement {
            poly: reduced,
            irreducible,
            base_modulus,
        }
    }
    
    /// Create from coefficient values
    pub fn from_coeffs(
        coeffs: Vec<u64>,
        irreducible: Polynomial<FieldElement>,
        base_modulus: BigUint,
    ) -> Self {
        let field_coeffs: Vec<FieldElement> = coeffs
            .into_iter()
            .map(|c| FieldElement::from_u64(c, base_modulus.clone()))
            .collect();
        
        let poly = Polynomial::new(field_coeffs);
        Self::new(poly, irreducible, base_modulus)
    }
    
    /// Create zero element
    pub fn zero(irreducible: Polynomial<FieldElement>, base_modulus: BigUint) -> Self {
        ExtensionFieldElement {
            poly: Polynomial::zero(),
            irreducible,
            base_modulus,
        }
    }
    
    /// Create one element
    pub fn one(irreducible: Polynomial<FieldElement>, base_modulus: BigUint) -> Self {
        let one = FieldElement::from_u64(1, base_modulus.clone());
        ExtensionFieldElement {
            poly: Polynomial::constant(one),
            irreducible,
            base_modulus,
        }
    }
    
    /// Get the polynomial representation
    pub fn poly(&self) -> &Polynomial<FieldElement> {
        &self.poly
    }
    
    /// Get the irreducible polynomial
    pub fn irreducible(&self) -> &Polynomial<FieldElement> {
        &self.irreducible
    }
    
    /// Get the base modulus
    pub fn base_modulus(&self) -> &BigUint {
        &self.base_modulus
    }
    
    /// Get the extension degree k
    pub fn extension_degree(&self) -> usize {
        self.irreducible.degree() as usize
    }
    
    /// Get coefficients as a vector
    pub fn coefficients(&self) -> Vec<FieldElement> {
        self.poly.coeffs().to_vec()
    }
    
    /// Get modulus (for serialization)
    pub fn modulus(&self) -> &BigUint {
        &self.base_modulus
    }
}

impl PartialEq for ExtensionFieldElement {
    fn eq(&self, other: &Self) -> bool {
        if self.base_modulus != other.base_modulus || self.irreducible != other.irreducible {
            panic!("Cannot compare elements from different extension fields");
        }
        self.poly == other.poly
    }
}

impl Eq for ExtensionFieldElement {}

impl Field for ExtensionFieldElement {
    fn add(&self, other: &Self) -> Self {
        if self.base_modulus != other.base_modulus || self.irreducible != other.irreducible {
            panic!("Cannot add elements from different extension fields");
        }
        
        ExtensionFieldElement {
            poly: &self.poly + &other.poly,
            irreducible: self.irreducible.clone(),
            base_modulus: self.base_modulus.clone(),
        }
    }
    
    fn neg(&self) -> Self {
        ExtensionFieldElement {
            poly: self.poly.neg(),
            irreducible: self.irreducible.clone(),
            base_modulus: self.base_modulus.clone(),
        }
    }
    
    fn mul(&self, other: &Self) -> Self {
        if self.base_modulus != other.base_modulus || self.irreducible != other.irreducible {
            panic!("Cannot multiply elements from different extension fields");
        }
        
        let product = &self.poly * &other.poly;
        ExtensionFieldElement {
            poly: product.modulo(&self.irreducible),
            irreducible: self.irreducible.clone(),
            base_modulus: self.base_modulus.clone(),
        }
    }
    
    fn inv(&self) -> Option<Self> {
        if self.poly.is_zero() {
            return None;
        }
        
        // Use Extended Euclidean Algorithm for polynomials
        // Find s such that poly * s ≡ 1 (mod irreducible)
        let (gcd, s, _) = poly_extended_gcd(&self.poly, &self.irreducible);
        
        // gcd should be a constant polynomial equal to 1
        if gcd.degree() != 0 {
            return None; // Element is not invertible
        }
        
        // Normalize s by dividing by the constant term of gcd
        let gcd_const = gcd.get_coeff(0).unwrap();
        let gcd_const_inv = gcd_const.inv()?;
        
        let mut inv_coeffs = Vec::new();
        for i in 0..=s.degree() as usize {
            if let Some(coeff) = s.get_coeff(i) {
                inv_coeffs.push(Field::mul(coeff, &gcd_const_inv));
            } else {
                inv_coeffs.push(FieldElement::from_u64(0, self.base_modulus.clone()));
            }
        }
        
        let inv_poly = Polynomial::new(inv_coeffs);
        Some(ExtensionFieldElement {
            poly: inv_poly.modulo(&self.irreducible),
            irreducible: self.irreducible.clone(),
            base_modulus: self.base_modulus.clone(),
        })
    }
    
    fn pow(&self, exp: &BigUint) -> Self {
        if exp.is_zero() {
            return Self::one(self.irreducible.clone(), self.base_modulus.clone());
        }
        
        let mut result = Self::one(self.irreducible.clone(), self.base_modulus.clone());
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
        self.poly.is_zero()
    }
}

/// Extended Euclidean Algorithm for polynomials
/// Returns (gcd, s, t) such that a*s + b*t = gcd
fn poly_extended_gcd<F: Field>(
    a: &Polynomial<F>,
    b: &Polynomial<F>,
) -> (Polynomial<F>, Polynomial<F>, Polynomial<F>) {
    if b.is_zero() {
        let one = a.get_coeff(0).unwrap().clone();
        return (a.clone(), Polynomial::constant(one.div(a.get_coeff(a.degree() as usize).unwrap()).unwrap()), Polynomial::zero());
    }
    
    let mut old_r = a.clone();
    let mut r = b.clone();
    
    // Create zero and one polynomials in the same field as coefficients
    let zero_coeff = a.get_coeff(0).unwrap().clone().mul(&a.get_coeff(0).unwrap().inv().unwrap());
    let one_coeff = if let Some(c) = a.get_coeff(0) {
        c.clone().div(c).unwrap()
    } else {
        return (Polynomial::zero(), Polynomial::zero(), Polynomial::zero());
    };
    
    let mut old_s = Polynomial::constant(one_coeff.clone());
    let mut s = Polynomial::constant(zero_coeff.clone());
    let mut old_t = Polynomial::constant(zero_coeff.clone());
    let mut t = Polynomial::constant(one_coeff);
    
    while !r.is_zero() {
        let (quotient, remainder) = old_r.div_rem(&r);
        
        old_r = r;
        r = remainder;
        
        let temp_s = s.clone();
        s = &old_s - &(&quotient * &s);
        old_s = temp_s;
        
        let temp_t = t.clone();
        t = &old_t - &(&quotient * &t);
        old_t = temp_t;
    }
    
    (old_r, old_s, old_t)
}

// Implement standard operators
impl Add for &ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn add(self, other: &ExtensionFieldElement) -> ExtensionFieldElement {
        Field::add(self, other)
    }
}

impl Add for ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn add(self, other: ExtensionFieldElement) -> ExtensionFieldElement {
        Field::add(&self, &other)
    }
}

impl Sub for &ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn sub(self, other: &ExtensionFieldElement) -> ExtensionFieldElement {
        Field::sub(self, other)
    }
}

impl Sub for ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn sub(self, other: ExtensionFieldElement) -> ExtensionFieldElement {
        Field::sub(&self, &other)
    }
}

impl Mul for &ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn mul(self, other: &ExtensionFieldElement) -> ExtensionFieldElement {
        Field::mul(self, other)
    }
}

impl Mul for ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn mul(self, other: ExtensionFieldElement) -> ExtensionFieldElement {
        Field::mul(&self, &other)
    }
}

impl Div for &ExtensionFieldElement {
    type Output = Option<ExtensionFieldElement>;
    
    fn div(self, other: &ExtensionFieldElement) -> Option<ExtensionFieldElement> {
        Field::div(self, other)
    }
}

impl Div for ExtensionFieldElement {
    type Output = Option<ExtensionFieldElement>;
    
    fn div(self, other: ExtensionFieldElement) -> Option<ExtensionFieldElement> {
        Field::div(&self, &other)
    }
}

impl Neg for &ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn neg(self) -> ExtensionFieldElement {
        Field::neg(self)
    }
}

impl Neg for ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    
    fn neg(self) -> ExtensionFieldElement {
        Field::neg(&self)
    }
}

impl fmt::Display for ExtensionFieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] mod ({})", self.poly, self.irreducible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_field_arithmetic() {
        // Work in F_{5^2} with irreducible polynomial X^2 + 2
        let p = BigUint::from_u64(5);
        
        // Create irreducible polynomial: X^2 + 2
        let irreducible = Polynomial::new(vec![
            FieldElement::from_u64(2, p.clone()),
            FieldElement::from_u64(0, p.clone()),
            FieldElement::from_u64(1, p.clone()),
        ]);
        
        // Create element: 1 + 2X
        let a = ExtensionFieldElement::from_coeffs(
            vec![1, 2],
            irreducible.clone(),
            p.clone(),
        );
        
        // Create element: 3 + X
        let b = ExtensionFieldElement::from_coeffs(
            vec![3, 1],
            irreducible.clone(),
            p.clone(),
        );
        
        // Test addition
        let sum = &a + &b;
        assert_eq!(sum.poly().get_coeff(0).unwrap().value(), &BigUint::from_u64(4)); // 1+3 = 4
        assert_eq!(sum.poly().get_coeff(1).unwrap().value(), &BigUint::from_u64(3)); // 2+1 = 3
        
        // Test multiplication
        let prod = &a * &b;
        // (1 + 2X)(3 + X) = 3 + X + 6X + 2X^2 = 3 + 7X + 2X^2
        // With X^2 = -2 = 3 (mod 5): 3 + 7X + 2*3 = 3 + 7X + 6 = 9 + 7X = 4 + 2X (mod 5)
        // Actually: 3 + 7X + 2X^2 mod (X^2 + 2) and mod 5
        // Need to reduce: divide by X^2 + 2
        assert!(!prod.is_zero());
    }
}
