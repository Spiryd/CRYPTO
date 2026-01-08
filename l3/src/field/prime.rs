//! Prime field F_p implementation
//!
//! This module implements elements of prime fields F_p, where p is prime.
//! All arithmetic is performed modulo p.

use super::config::FieldConfig;
use crate::bigint::BigInt;
use crate::field_trait::FieldElement;
use std::marker::PhantomData;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// Element of a prime field F_p (k=1)
///
/// Represents an integer modulo prime p. All arithmetic is performed modulo p.
///
/// # Type Parameters
/// - `C`: Field configuration (defines p via `FieldConfig` trait)
/// - `N`: Number of limbs for BigInt representation
///
/// # Compile-time Safety
/// The type system ensures that elements from different fields (different C types)
/// cannot be mixed in operations. This prevents errors like adding an element
/// from F_5 to an element from F_7.
///
/// # Example
/// ```
/// use crate::bigint::BigInt;
/// use crate::field::{FieldConfig, PrimeField};
///
/// // Define configuration for F_97
/// #[derive(Clone, Debug)]
/// struct F97;
///
/// static F97_MODULUS: BigInt<4> = BigInt::from_u64(97);
///
/// impl FieldConfig<4> for F97 {
///     fn modulus() -> &'static BigInt<4> { &F97_MODULUS }
///     fn irreducible() -> &'static [BigInt<4>] { &[] }
/// }
///
/// let a = PrimeField::<F97, 4>::from_u64(10);
/// let b = PrimeField::<F97, 4>::from_u64(20);
/// let sum = a + b; // OK: same field
///
/// // Compile-time error: cannot mix different fields
/// // let c = PrimeField::<F101, 4>::from_u64(5);
/// // let bad = a + c; // Type error!
/// ```
#[derive(Clone, Debug)]
pub struct PrimeField<C: FieldConfig<N>, const N: usize> {
    /// Value in F_p (reduced modulo p)
    pub value: BigInt<N>,
    /// Phantom data to tie this element to its field configuration
    _config: PhantomData<C>,
}

impl<C: FieldConfig<N>, const N: usize> PrimeField<C, N> {
    /// Creates a prime field element from a BigInt value
    ///
    /// The value is automatically reduced modulo p.
    ///
    /// # Arguments
    /// * `value` - The integer value to create the field element from
    ///
    /// # Returns
    /// A new field element with value reduced modulo p
    pub fn new(value: BigInt<N>) -> Self {
        let reduced = value.modulo(C::modulus());
        Self {
            value: reduced,
            _config: PhantomData,
        }
    }

    /// Creates a prime field element from a u64 value
    ///
    /// Convenience method for creating field elements from small integers.
    ///
    /// # Arguments
    /// * `val` - The u64 value to convert to a field element
    ///
    /// # Returns
    /// A new field element
    pub fn from_u64(val: u64) -> Self {
        Self::new(BigInt::from_u64(val))
    }

    /// Gets a reference to the underlying BigInt value
    ///
    /// # Returns
    /// A reference to the internal BigInt representation
    pub fn value(&self) -> &BigInt<N> {
        &self.value
    }
}

// Implement equality
impl<C: FieldConfig<N>, const N: usize> PartialEq for PrimeField<C, N> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<C: FieldConfig<N>, const N: usize> Eq for PrimeField<C, N> {}

// Implement addition: a + b (mod p)
impl<C: FieldConfig<N>, const N: usize> Add for PrimeField<C, N> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let sum = self.value + other.value;
        Self::new(sum)
    }
}

// Implement negation: -a ≡ p - a (mod p)
impl<C: FieldConfig<N>, const N: usize> Neg for PrimeField<C, N> {
    type Output = Self;

    fn neg(self) -> Self {
        if self.value.is_zero() {
            return self;
        }
        let modulus = C::modulus();
        let neg_value = modulus.sub_with_borrow(&self.value).0;
        Self {
            value: neg_value,
            _config: PhantomData,
        }
    }
}

// Implement subtraction: a - b = a + (-b) (mod p)
impl<C: FieldConfig<N>, const N: usize> Sub for PrimeField<C, N> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self + (-other)
    }
}

// Implement multiplication: a * b (mod p)
impl<C: FieldConfig<N>, const N: usize> Mul for PrimeField<C, N> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let product = self.value * other.value;
        Self::new(product)
    }
}

// Implement division: a / b = a * b^(-1) (mod p)
#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: FieldConfig<N>, const N: usize> Div for PrimeField<C, N> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        self * other.inverse()
    }
}

// Implement FieldElement trait
impl<C: FieldConfig<N>, const N: usize> FieldElement for PrimeField<C, N> {
    fn zero() -> Self {
        Self {
            value: BigInt::zero(),
            _config: PhantomData,
        }
    }

    fn one() -> Self {
        Self {
            value: BigInt::one(),
            _config: PhantomData,
        }
    }

    fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    /// Computes the multiplicative inverse using the Extended Euclidean Algorithm
    ///
    /// Finds x such that: a * x ≡ 1 (mod p)
    ///
    /// # Panics
    /// Panics if called on the zero element
    fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "Cannot invert zero");

        // Extended Euclidean Algorithm to find modular inverse
        let modulus = C::modulus();

        let mut t = BigInt::zero();
        let mut new_t = BigInt::one();
        let mut r = *modulus;
        let mut new_r = self.value;

        while !new_r.is_zero() {
            let (quotient, _) = r.div_rem(&new_r);

            // Update t: new_t = t - quotient * new_t
            let temp_t = t;
            let q_times_new_t = quotient * new_t;
            t = new_t;

            // Handle subtraction with potential underflow
            new_t = if q_times_new_t.cmp(&temp_t) != std::cmp::Ordering::Greater {
                temp_t.sub_with_borrow(&q_times_new_t).0
            } else {
                let diff = q_times_new_t.sub_with_borrow(&temp_t).0;
                modulus.sub_with_borrow(&diff).0
            };

            // Update r: new_r = r - quotient * new_r
            let temp_r = r;
            r = new_r;
            new_r = temp_r.sub_with_borrow(&(quotient * r)).0;
        }

        Self {
            value: t.modulo(modulus),
            _config: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test configuration for F_5
    #[derive(Clone, Debug)]
    struct F5Config;
    static F5_MOD: BigInt<4> = BigInt::from_u64(5);

    impl FieldConfig<4> for F5Config {
        fn modulus() -> &'static BigInt<4> {
            &F5_MOD
        }

        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }

    type F5 = PrimeField<F5Config, 4>;

    #[test]
    fn test_prime_field_basic() {
        let zero = F5::zero();
        let one = F5::one();

        assert!(zero.is_zero());
        assert_eq!(one, F5::one());
    }

    #[test]
    fn test_prime_field_addition() {
        let a = F5::from_u64(3);
        let b = F5::from_u64(4);
        let sum = a + b;

        assert_eq!(sum, F5::from_u64(2)); // 3 + 4 = 7 ≡ 2 (mod 5)
    }

    #[test]
    fn test_prime_field_multiplication() {
        let a = F5::from_u64(3);
        let b = F5::from_u64(4);
        let prod = a * b;

        assert_eq!(prod, F5::from_u64(2)); // 3 * 4 = 12 ≡ 2 (mod 5)
    }

    #[test]
    fn test_prime_field_inverse() {
        let a = F5::from_u64(3);
        let a_inv = a.inverse();
        let prod = a.clone() * a_inv;

        assert_eq!(prod, F5::one());
    }

    #[test]
    fn test_prime_field_exponentiation() {
        let a = F5::from_u64(2);
        let result = a.pow(&[3]); // Use pow with byte array

        assert_eq!(result, F5::from_u64(3)); // 2^3 = 8 ≡ 3 (mod 5)
    }
}
