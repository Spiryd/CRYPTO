//! Extension field F_p^k implementation
//!
//! This module implements elements of extension fields F_p^k where k > 1.
//! Elements are represented as polynomials of degree < k with coefficients in F_p,
//! reduced modulo an irreducible polynomial of degree k.

use super::config::FieldConfig;
use crate::bigint::BigInt;
use crate::field_trait::FieldElement;
use std::marker::PhantomData;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// Polynomial representation for extension field elements
///
/// Coefficients are stored in increasing degree order: [a_0, a_1, ..., a_{k-1}]
/// representing the polynomial a_0 + a_1*x + ... + a_{k-1}*x^{k-1}
///
/// # Type Parameters
/// - `N`: Number of limbs for BigInt (coefficient size)
/// - `K`: Polynomial degree (number of coefficients)
#[derive(Clone, Debug)]
pub struct Poly<const N: usize, const K: usize> {
    /// Polynomial coefficients (in F_p), coeffs[i] is the coefficient of x^i
    pub coeffs: [BigInt<N>; K],
}

impl<const N: usize, const K: usize> Poly<N, K> {
    /// Creates a zero polynomial (all coefficients are zero)
    pub fn zero() -> Self {
        Self {
            coeffs: [BigInt::zero(); K],
        }
    }

    /// Reduces all coefficients modulo p
    ///
    /// Ensures all coefficients are in the range [0, p-1]
    ///
    /// # Arguments
    /// * `modulus` - The prime modulus p
    pub fn reduce(&mut self, modulus: &BigInt<N>) {
        for coeff in &mut self.coeffs {
            *coeff = coeff.modulo(modulus);
        }
    }

    /// Adds two polynomials (coefficient-wise addition mod p)
    ///
    /// # Arguments
    /// * `other` - The polynomial to add
    /// * `modulus` - The prime modulus p
    ///
    /// # Returns
    /// The sum of the two polynomials
    pub fn add(&self, other: &Self, modulus: &BigInt<N>) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.coeffs[i] = (self.coeffs[i] + other.coeffs[i]).modulo(modulus);
        }
        result
    }

    /// Negates polynomial (coefficient-wise negation mod p)
    ///
    /// For each coefficient a, computes -a ≡ p - a (mod p)
    ///
    /// # Arguments
    /// * `modulus` - The prime modulus p
    ///
    /// # Returns
    /// The negated polynomial
    pub fn neg(&self, modulus: &BigInt<N>) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            if self.coeffs[i].is_zero() {
                result.coeffs[i] = BigInt::zero();
            } else {
                result.coeffs[i] = modulus.sub_with_borrow(&self.coeffs[i]).0;
            }
        }
        result
    }

    /// Multiplies two polynomials and reduces modulo irreducible polynomial
    ///
    /// Performs polynomial multiplication in F_p[x], then reduces the result
    /// modulo the irreducible polynomial to keep the degree < k.
    ///
    /// # Arguments
    /// * `other` - The polynomial to multiply with
    /// * `modulus` - The prime modulus p
    /// * `irreducible` - Coefficients of the irreducible polynomial
    ///
    /// # Returns
    /// The product reduced modulo the irreducible polynomial
    pub fn mul(&self, other: &Self, modulus: &BigInt<N>, irreducible: &[BigInt<N>]) -> Self {
        // First, perform polynomial multiplication (degree can go up to 2*K-2)
        let mut temp = vec![BigInt::zero(); 2 * K - 1];

        for i in 0..K {
            for j in 0..K {
                if i + j < temp.len() {
                    let prod = self.coeffs[i] * other.coeffs[j];
                    temp[i + j] = (temp[i + j] + prod).modulo(modulus);
                }
            }
        }

        // Now reduce modulo the irreducible polynomial
        // irreducible polynomial: x^K + c_{K-1}*x^{K-1} + ... + c_1*x + c_0
        // So x^K ≡ -(c_{K-1}*x^{K-1} + ... + c_0) mod irreducible
        // i.e., x^K ≡ (p - c_{K-1})*x^{K-1} + ... + (p - c_0) if we want positive coefficients
        if irreducible.len() == K + 1 {
            // Process from highest degree down to K
            for i in (K..(2 * K - 1)).rev() {
                if !temp[i].is_zero() {
                    let lead_coeff = temp[i];
                    temp[i] = BigInt::zero(); // Clear this term

                    // x^i = x^(i-K) * x^K ≡ x^(i-K) * (-(c_0 + c_1*x + ... + c_{K-1}*x^{K-1}))
                    // So add -lead_coeff * c_j to temp[i - K + j] for j = 0..K-1
                    for (j, &irr_coeff) in irreducible.iter().enumerate().take(K) {
                        // We subtract lead_coeff * irreducible[j] from temp[i - K + j]
                        let target_idx = i - K + j;
                        let sub_val = (lead_coeff * irr_coeff).modulo(modulus);

                        // temp[target_idx] = temp[target_idx] - sub_val (mod p)
                        if temp[target_idx].compare(&sub_val) != std::cmp::Ordering::Less {
                            temp[target_idx] = temp[target_idx].sub_with_borrow(&sub_val).0;
                        } else {
                            // Need to add p first
                            temp[target_idx] =
                                (temp[target_idx] + *modulus).sub_with_borrow(&sub_val).0;
                        }
                        temp[target_idx] = temp[target_idx].modulo(modulus);
                    }
                }
            }
        }

        // Copy result back
        let mut result = Self::zero();
        result.coeffs[..K.min(temp.len())].copy_from_slice(&temp[..K.min(temp.len())]);

        result
    }
}

impl<const N: usize, const K: usize> PartialEq for Poly<N, K> {
    fn eq(&self, other: &Self) -> bool {
        self.coeffs
            .iter()
            .zip(other.coeffs.iter())
            .all(|(a, b)| a == b)
    }
}

impl<const N: usize, const K: usize> Eq for Poly<N, K> {}

/// Element of an extension field F_p^k (k > 1)
///
/// Represents a polynomial of degree < k with coefficients in F_p,
/// reduced modulo an irreducible polynomial of degree k.
///
/// # Type Parameters
/// - `C`: Field configuration (defines p and irreducible polynomial)
/// - `N`: Number of limbs for BigInt
/// - `K`: Extension degree
///
/// # Compile-time Safety
/// The type system ensures field compatibility at compile time.
/// Different extension fields cannot be mixed in operations.
///
/// # Example
/// ```
/// use l3::bigint::BigInt;
/// use l3::field::{FieldConfig, ExtensionField};
///
/// // Define F_5^2 with irreducible polynomial x^2 + x + 2
/// #[derive(Clone, Debug)]
/// struct F5_2;
///
/// static F5_MOD: BigInt<4> = BigInt::from_u64(5);
/// static F5_2_IRRED: [BigInt<4>; 3] = [
///     BigInt::from_u64(2),  // constant term
///     BigInt::from_u64(1),  // x coefficient
///     BigInt::from_u64(1),  // x^2 coefficient
/// ];
///
/// impl FieldConfig<4> for F5_2 {
///     fn modulus() -> &'static BigInt<4> { &F5_MOD }
///     fn irreducible() -> &'static [BigInt<4>] { &F5_2_IRRED }
/// }
///
/// type F5_2_Field = ExtensionField<F5_2, 4, 2>;
/// ```
#[derive(Clone, Debug)]
pub struct ExtensionField<C: FieldConfig<N>, const N: usize, const K: usize> {
    /// Polynomial representation
    pub poly: Poly<N, K>,
    /// Phantom data for field configuration
    _config: PhantomData<C>,
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> ExtensionField<C, N, K> {
    /// Creates an extension field element from polynomial coefficients
    ///
    /// Automatically reduces all coefficients modulo p.
    ///
    /// # Arguments
    /// * `poly` - The polynomial to create the element from
    ///
    /// # Returns
    /// A new extension field element
    pub fn new(mut poly: Poly<N, K>) -> Self {
        poly.reduce(C::modulus());
        Self {
            poly,
            _config: PhantomData,
        }
    }

    /// Creates element from coefficient array
    ///
    /// # Arguments
    /// * `coeffs` - Array of coefficients in increasing degree order
    ///
    /// # Returns
    /// A new extension field element
    pub fn from_coeffs(coeffs: [BigInt<N>; K]) -> Self {
        Self::new(Poly { coeffs })
    }

    /// Gets the polynomial coefficients
    ///
    /// # Returns
    /// A reference to the array of coefficients
    pub fn coefficients(&self) -> &[BigInt<N>; K] {
        &self.poly.coeffs
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> PartialEq for ExtensionField<C, N, K> {
    fn eq(&self, other: &Self) -> bool {
        self.poly == other.poly
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Eq for ExtensionField<C, N, K> {}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Add for ExtensionField<C, N, K> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            poly: self.poly.add(&other.poly, C::modulus()),
            _config: PhantomData,
        }
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Neg for ExtensionField<C, N, K> {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            poly: self.poly.neg(C::modulus()),
            _config: PhantomData,
        }
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Sub for ExtensionField<C, N, K> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self + (-other)
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Mul for ExtensionField<C, N, K> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self {
            poly: self.poly.mul(&other.poly, C::modulus(), C::irreducible()),
            _config: PhantomData,
        }
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Div for ExtensionField<C, N, K> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, other: Self) -> Self {
        self * other.inverse()
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> FieldElement for ExtensionField<C, N, K> {
    fn zero() -> Self {
        Self {
            poly: Poly::zero(),
            _config: PhantomData,
        }
    }

    fn one() -> Self {
        let mut poly = Poly::zero();
        poly.coeffs[0] = BigInt::one();
        Self {
            poly,
            _config: PhantomData,
        }
    }

    fn is_zero(&self) -> bool {
        self.poly.coeffs.iter().all(|c| c.is_zero())
    }

    /// Computes the multiplicative inverse using Fermat's Little Theorem
    ///
    /// For an extension field F_p^k, we use: a^(p^k - 2) ≡ a^(-1)
    /// This is less efficient than Extended Euclidean Algorithm for polynomials
    /// but simpler and correct.
    ///
    /// # Panics
    /// Panics if called on the zero element
    fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "Cannot invert zero");

        // Calculate p^k - 2
        let p = C::modulus();
        let mut pk_minus_2 = *p;
        for _ in 1..K {
            pk_minus_2 = pk_minus_2 * *p;
        }
        pk_minus_2 = pk_minus_2 - BigInt::from_u64(2);

        // Compute self^(p^k - 2) using the pow method from FieldElement
        let exp_bytes = pk_minus_2.to_be_bytes();
        self.pow(&exp_bytes)
    }
}
