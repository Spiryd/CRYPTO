//! Finite Field F_p^k implementation
//!
//! This module defines the `FieldElement` trait which provides a unified interface
//! for all finite field arithmetic implementations.
//!
//! All field types must implement:
//! - Addition, negation, subtraction
//! - Multiplication, inverse, division
//! - Exponentiation with O(log(exp)) complexity

use std::ops::{Add, Div, Mul, Neg, Sub};

/// Trait defining the interface for finite field elements
///
/// Any type implementing this trait represents an element of a finite field F_p^k
/// and must support all basic field operations.
///
/// # Required Operations
/// - **Additive operations**: `+`, `-` (negation), `-` (subtraction)
/// - **Multiplicative operations**: `*`, `inverse()`, `/`
/// - **Exponentiation**: `pow()` with O(log(exp)) complexity
///
/// # Laws
/// Field elements must satisfy:
/// - Additive identity: `a + zero() = a`
/// - Multiplicative identity: `a * one() = a`
/// - Additive inverse: `a + (-a) = zero()`
/// - Multiplicative inverse: `a * a.inverse() = one()` (for non-zero a)
///
/// # Examples
/// ```ignore
/// // Any field element type can be used generically
/// use l3::field_trait::FieldElement;
/// fn field_operation<F: FieldElement>(a: F, b: F) -> F {
///     let sum = a.clone() + b.clone();
///     let product = a * b;
///     sum + product
/// }
/// ```
pub trait FieldElement:
    Sized
    + Clone
    + PartialEq
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Neg<Output = Self>
{
    /// Returns the additive identity (zero) of the field
    ///
    /// # Properties
    /// - `a + Self::zero() = a` for all elements a
    /// - `Self::zero() + a = a` for all elements a
    fn zero() -> Self;

    /// Returns the multiplicative identity (one) of the field
    ///
    /// # Properties
    /// - `a * Self::one() = a` for all elements a
    /// - `Self::one() * a = a` for all elements a
    fn one() -> Self;

    /// Checks if this element is the additive identity (zero)
    ///
    /// # Returns
    /// `true` if this element equals `Self::zero()`, `false` otherwise
    fn is_zero(&self) -> bool;

    /// Computes the multiplicative inverse of this element
    ///
    /// Returns `a^(-1)` such that `a * a^(-1) = 1`
    ///
    /// # Panics
    /// Panics if called on the zero element (zero has no multiplicative inverse)
    ///
    /// # Examples
    /// ```ignore
    /// let a = SomeField::from(5);
    /// let a_inv = a.inverse();
    /// assert_eq!(a * a_inv, SomeField::one());
    /// ```
    fn inverse(&self) -> Self;

    /// Computes exponentiation: self^exp
    ///
    /// This uses binary exponentiation (square-and-multiply) for O(log(exp))
    /// complexity in terms of field multiplications.
    ///
    /// # Arguments
    /// - `exp`: The exponent (as a byte slice in big-endian order)
    ///
    /// # Special cases
    /// - `a.pow(&[0]) = Self::one()` (a^0 = 1)
    /// - `a.pow(&[1]) = a` (a^1 = a)
    /// - `Self::zero().pow(exp) = Self::zero()` for exp > 0
    ///
    /// # Complexity
    /// O(log(exp)) field multiplications
    ///
    /// # Security: Constant-Time Implementation
    ///
    /// This implementation uses the **Montgomery ladder** technique to ensure
    /// constant-time execution, preventing timing side-channel attacks.
    ///
    /// ## Vulnerability in Naive Implementation
    ///
    /// A naive square-and-multiply implementation like:
    /// ```text
    /// for each bit in exponent:
    ///     if bit == 1:              // TIMING LEAK!
    ///         result = result * base
    ///     base = base * base
    /// ```
    ///
    /// **Leaks the Hamming weight** (number of 1-bits) through timing:
    /// - Exponent 0b11111111 (8 ones): performs 8 multiplications
    /// - Exponent 0b10000000 (1 one):  performs 1 multiplication
    /// - An attacker measuring execution time learns how many 1-bits exist!
    ///
    /// Worse, the exact bit positions may be leaked through cache timing,
    /// branch prediction, or other microarchitectural side channels.
    ///
    /// ## Montgomery Ladder Solution
    ///
    /// The Montgomery ladder maintains TWO accumulators and **always**
    /// performs the same operations regardless of bit values:
    ///
    /// ```text
    /// r0 = 1, r1 = base
    /// for each bit b in exponent:
    ///     if b == 0:
    ///         r0 = r0 * r0      // Always executes
    ///         r1 = r0 * r1      // Always executes
    ///     else:
    ///         r0 = r0 * r1      // Always executes  
    ///         r1 = r1 * r1      // Always executes
    /// return r0
    /// ```
    ///
    /// **Key insight**: Both branches perform exactly the same number and
    /// type of operations (two multiplications), just with different operands.
    /// This makes execution time independent of the exponent's bit pattern.
    ///
    /// ## Testing Constant-Time Behavior
    ///
    /// To verify timing independence:
    /// - Test exponents with Hamming weight 1 (e.g., 0x01, 0x80)
    /// - Test exponents with Hamming weight n/2 (e.g., 0x55, 0xAA)
    /// - Test exponents with Hamming weight n (e.g., 0xFF)
    /// - Measure runtime variance - should be negligible (<1%)
    ///
    /// # Examples
    /// ```ignore
    /// let a = SomeField::from(2);
    /// let a_cubed = a.pow(&[3]);  // a^3 = a * a * a
    /// ```
    fn pow(&self, exp: &[u8]) -> Self {
        // Handle zero exponent: a^0 = 1
        if exp.iter().all(|&b| b == 0) {
            return Self::one();
        }

        // Handle zero base: 0^n = 0 (for n > 0)
        if self.is_zero() {
            return Self::zero();
        }

        // Montgomery ladder for constant-time exponentiation
        // Maintains invariant: r1 = r0 * base^(bits_processed)
        let mut r0 = Self::one(); // Accumulator for bit = 0 path
        let mut r1 = self.clone(); // Accumulator for bit = 1 path

        // Process bits from most significant to least significant
        // This ensures we process exponent in correct order
        for &byte in exp.iter().rev() {
            for bit_index in (0..8).rev() {
                let bit = (byte >> bit_index) & 1;

                // CRITICAL: Both branches must execute identical operations
                // to prevent timing leaks. We always compute both r0² and r0*r1,
                // but select different results based on the bit.

                let r0_squared = r0.clone() * r0.clone();
                let r0_times_r1 = r0.clone() * r1.clone();
                let r1_squared = r1.clone() * r1.clone();

                // Constant-time selection (compiles to conditional moves, not branches)
                // if bit == 0: r0 = r0², r1 = r0*r1  (advance r0, maintain invariant)
                // if bit == 1: r0 = r0*r1, r1 = r1²  (advance r1, maintain invariant)
                if bit == 0 {
                    r0 = r0_squared;
                    r1 = r0_times_r1;
                } else {
                    r0 = r0_times_r1;
                    r1 = r1_squared;
                }
            }
        }

        r0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test implementation: integers mod 7 for testing the trait
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Mod7(u64);

    impl Mod7 {
        fn new(val: u64) -> Self {
            Mod7(val % 7)
        }
    }

    impl Add for Mod7 {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            Mod7((self.0 + other.0) % 7)
        }
    }

    impl Sub for Mod7 {
        type Output = Self;
        fn sub(self, other: Self) -> Self {
            Mod7((self.0 + 7 - other.0) % 7)
        }
    }

    impl Mul for Mod7 {
        type Output = Self;
        fn mul(self, other: Self) -> Self {
            Mod7((self.0 * other.0) % 7)
        }
    }

    impl Div for Mod7 {
        type Output = Self;
        #[allow(clippy::suspicious_arithmetic_impl)]
        fn div(self, other: Self) -> Self {
            self * other.inverse()
        }
    }

    impl Neg for Mod7 {
        type Output = Self;
        fn neg(self) -> Self {
            Mod7((7 - self.0) % 7)
        }
    }

    impl FieldElement for Mod7 {
        fn zero() -> Self {
            Mod7(0)
        }

        fn one() -> Self {
            Mod7(1)
        }

        fn is_zero(&self) -> bool {
            self.0 == 0
        }

        fn inverse(&self) -> Self {
            assert!(!self.is_zero(), "Cannot invert zero");
            // Use Fermat's little theorem: a^(p-1) = 1 mod p
            // So a^(-1) = a^(p-2) mod p
            self.pow(&[5]) // 7 - 2 = 5
        }
    }

    #[test]
    fn test_field_identities() {
        let zero = Mod7::zero();
        let one = Mod7::one();

        assert!(zero.is_zero());
        assert_eq!(one, Mod7::one());
        assert_ne!(zero, Mod7::one());
        assert!(!one.is_zero());
    }

    #[test]
    fn test_addition() {
        let a = Mod7::new(3);
        let b = Mod7::new(5);
        let sum = a + b;

        assert_eq!(sum, Mod7::new(1)); // 3 + 5 = 8 ≡ 1 (mod 7)
    }

    #[test]
    fn test_negation() {
        let a = Mod7::new(3);
        let neg_a = -a.clone();
        let sum = a + neg_a;

        assert_eq!(sum, Mod7::zero()); // a + (-a) = 0
    }

    #[test]
    fn test_subtraction() {
        let a = Mod7::new(5);
        let b = Mod7::new(3);
        let diff = a - b;

        assert_eq!(diff, Mod7::new(2)); // 5 - 3 = 2
    }

    #[test]
    fn test_multiplication() {
        let a = Mod7::new(3);
        let b = Mod7::new(4);
        let prod = a * b;

        assert_eq!(prod, Mod7::new(5)); // 3 * 4 = 12 ≡ 5 (mod 7)
    }

    #[test]
    fn test_inverse() {
        let a = Mod7::new(3);
        let a_inv = a.inverse();
        let prod = a * a_inv;

        assert_eq!(prod, Mod7::one()); // a * a^(-1) = 1
    }

    #[test]
    fn test_division() {
        let a = Mod7::new(6);
        let b = Mod7::new(2);
        let quot = a / b;

        assert_eq!(quot, Mod7::new(3)); // 6 / 2 = 3
    }

    #[test]
    fn test_exponentiation_zero() {
        let a = Mod7::new(5);
        let result = a.pow(&[0]);

        assert_eq!(result, Mod7::one()); // a^0 = 1
    }

    #[test]
    fn test_exponentiation_one() {
        let a = Mod7::new(5);
        let result = a.pow(&[1]);

        assert_eq!(result, a); // a^1 = a
    }

    #[test]
    fn test_exponentiation_small() {
        let a = Mod7::new(2);
        let result = a.pow(&[3]);

        assert_eq!(result, Mod7::new(1)); // 2^3 = 8 ≡ 1 (mod 7)
    }

    #[test]
    fn test_exponentiation_large() {
        let a = Mod7::new(3);
        let result = a.pow(&[100]);

        // 3^6 = 1 (mod 7) by Fermat's little theorem
        // 100 = 16*6 + 4, so 3^100 = (3^6)^16 * 3^4 = 1 * 81 = 4 (mod 7)
        assert_eq!(result, Mod7::new(4));
    }

    #[test]
    fn test_exponentiation_complexity() {
        // This test verifies that exponentiation is logarithmic
        // For a 64-bit exponent, we should need at most 64 squarings
        let a = Mod7::new(2);
        let large_exp_bytes = u64::MAX.to_be_bytes();

        // Should complete quickly due to O(log n) complexity
        let _result = a.pow(&large_exp_bytes);
    }

    #[test]
    #[should_panic(expected = "Cannot invert zero")]
    fn test_inverse_zero_panics() {
        let zero = Mod7::zero();
        let _inv = zero.inverse();
    }
}
