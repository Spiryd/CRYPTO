//! Binary field F_2^k implementation (also known as F_2^m or GF(2^m))
//!
//! This module implements elements of binary extension fields F_2^k where the base
//! field is F_2 = {0, 1}. Elements are represented as bit strings, making operations
//! highly efficient.
//!
//! # Representation
//! Each element is a polynomial over F_2 with degree < k, represented as a bit string
//! where bit i corresponds to the coefficient of x^i.
//!
//! # Operations
//! - Addition: XOR (⊕) - coefficient-wise addition mod 2
//! - Multiplication: Polynomial multiplication modulo an irreducible polynomial
//! - No modular reduction needed for coefficients (they're already in {0,1})

use super::config::FieldConfig;
use crate::bigint::BigInt;
use crate::field_trait::FieldElement;
use std::marker::PhantomData;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// Element of a binary field F_2^k
///
/// Represents a polynomial of degree < k with coefficients in F_2 = {0, 1},
/// reduced modulo an irreducible polynomial of degree k.
///
/// The polynomial a_{k-1}*x^{k-1} + ... + a_1*x + a_0 is stored as a bit string
/// where bit i represents the coefficient a_i.
///
/// # Type Parameters
/// - `C`: Field configuration (defines irreducible polynomial)
/// - `N`: Number of limbs for BigInt (must be sufficient for k bits)
/// - `K`: Extension degree (number of bits in the field)
///
/// # Compile-time Safety
/// Different binary fields cannot be mixed in operations due to type system.
///
/// # Example
/// ```
/// use l3::bigint::BigInt;
/// use l3::field::{FieldConfig, BinaryField};
///
/// // Define F_2^8 with AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
/// #[derive(Clone, Debug)]
/// struct F2_8_AES;
///
/// static F2_MOD: BigInt<4> = BigInt::from_u64(2);
/// // Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B in binary
/// static F2_8_IRRED: [BigInt<4>; 9] = [
///     BigInt::from_u64(1),  // x^0
///     BigInt::from_u64(1),  // x^1
///     BigInt::from_u64(0),  // x^2
///     BigInt::from_u64(1),  // x^3
///     BigInt::from_u64(1),  // x^4
///     BigInt::from_u64(0),  // x^5
///     BigInt::from_u64(0),  // x^6
///     BigInt::from_u64(0),  // x^7
///     BigInt::from_u64(1),  // x^8
/// ];
///
/// impl FieldConfig<4> for F2_8_AES {
///     fn modulus() -> &'static BigInt<4> { &F2_MOD }
///     fn irreducible() -> &'static [BigInt<4>] { &F2_8_IRRED }
/// }
///
/// type GF256 = BinaryField<F2_8_AES, 4, 8>;  // GF(2^8) used in AES
/// ```
#[derive(Clone, Debug)]
pub struct BinaryField<C: FieldConfig<N>, const N: usize, const K: usize> {
    /// Bit string representation of the polynomial
    /// bits[i] = 1 means x^i has coefficient 1
    bits: BigInt<N>,
    /// Phantom data for field configuration
    _config: PhantomData<C>,
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> BinaryField<C, N, K> {
    /// Creates a binary field element from a BigInt bit pattern
    ///
    /// The BigInt should have bits set corresponding to polynomial coefficients.
    /// Automatically masks to K bits and reduces modulo irreducible if necessary.
    ///
    /// # Arguments
    /// * `bits` - Bit pattern representing polynomial coefficients
    ///
    /// # Returns
    /// A new binary field element
    pub fn new(bits: BigInt<N>) -> Self {
        let mut result = Self {
            bits,
            _config: PhantomData,
        };
        result.reduce();
        result
    }

    /// Creates element from a u64 value (for small fields)
    ///
    /// # Arguments
    /// * `value` - The value to convert (low K bits used)
    ///
    /// # Returns
    /// A new binary field element
    pub fn from_u64(value: u64) -> Self {
        Self::new(BigInt::from_u64(value))
    }

    /// Gets the underlying BigInt representation
    ///
    /// # Returns
    /// A reference to the bit pattern as a BigInt
    pub fn to_bigint(&self) -> &BigInt<N> {
        &self.bits
    }

    /// Gets the underlying bit representation
    ///
    /// # Returns
    /// A reference to the bit pattern as a BigInt
    pub fn bits(&self) -> &BigInt<N> {
        &self.bits
    }

    /// Gets the bit at position i (coefficient of x^i)
    ///
    /// # Arguments
    /// * `i` - The bit position to query
    ///
    /// # Returns
    /// true if bit i is set (coefficient is 1), false otherwise
    pub fn get_bit(&self, i: usize) -> bool {
        // Allow checking bits beyond K during intermediate computations (e.g., multiplication)
        // The reduce() method will ensure final result has degree < K
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        if limb_idx < N {
            (self.bits.limbs()[limb_idx] & (1u64 << bit_idx)) != 0
        } else {
            false
        }
    }

    /// Sets the bit at position i
    ///
    /// # Arguments
    /// * `i` - The bit position to set
    /// * `value` - true to set bit to 1, false to set to 0
    pub fn set_bit(&mut self, i: usize, value: bool) {
        // Allow setting bits beyond K during intermediate computations
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        if limb_idx < N {
            let mut limbs = *self.bits.limbs();
            if value {
                limbs[limb_idx] |= 1u64 << bit_idx;
            } else {
                limbs[limb_idx] &= !(1u64 << bit_idx);
            }
            self.bits = BigInt::from_limbs_internal(limbs);
        }
    }

    /// Reduces the element to ensure degree < K
    ///
    /// Reduces modulo the irreducible polynomial first, then masks to K bits.
    fn reduce(&mut self) {
        // Use compact bitstring representation if available (much more efficient for binary fields)
        let irred_bits = C::irreducible_bitstring();
        
        if !irred_bits.is_empty() {
            // Efficient bitstring-based reduction
            while self.degree() >= K {
                let deg = self.degree();
                let shift = deg - K;

                // XOR with the shifted irreducible polynomial bits
                for (byte_idx, &byte) in irred_bits.iter().enumerate() {
                    if byte == 0 {
                        continue;
                    }
                    
                    for bit_idx in 0..8 {
                        if (byte & (1u8 << bit_idx)) != 0 {
                            let bit_pos = byte_idx * 8 + bit_idx;
                            if bit_pos < K {
                                let target = bit_pos + shift;
                                let current = self.get_bit(target);
                                self.set_bit(target, !current); // XOR: flip the bit
                            } else if bit_pos == K {
                                // The x^K coefficient cancels with the bit at deg
                                self.set_bit(deg, false);
                            }
                        }
                    }
                }
            }
        } else {
            // Fallback to legacy array-based reduction
            let irreducible = C::irreducible();
            if irreducible.len() == K + 1 {
                // Reduce modulo the irreducible polynomial
                // For each bit position >= K, if it's set, XOR with the irreducible polynomial
                while self.degree() >= K {
                    let deg = self.degree();
                    // We have a bit at position deg >= K
                    // XOR with irreducible shifted so its x^K term aligns with x^deg
                    let shift = deg - K;

                    // XOR with the shifted irreducible polynomial (excluding the x^K coefficient which is always 1)
                    for (i, coeff) in irreducible.iter().enumerate().take(K) {
                        if !coeff.is_zero() {
                            let bit_pos = i + shift;
                            let current = self.get_bit(bit_pos);
                            self.set_bit(bit_pos, !current); // XOR: flip the bit
                        }
                    }
                    // The x^K coefficient (which is 1) cancels with the bit at deg
                    self.set_bit(deg, false);
                }
            }
        }

        // THEN mask to K bits (to clean up any bits beyond K-1)
        let mask = if K >= 64 * N {
            // All bits valid
            return;
        } else {
            let full_limbs = K / 64;
            let remaining_bits = K % 64;

            let mut mask_limbs = [0u64; N];
            for limb in mask_limbs.iter_mut().take(full_limbs) {
                *limb = u64::MAX;
            }
            if remaining_bits > 0 && full_limbs < N {
                mask_limbs[full_limbs] = (1u64 << remaining_bits) - 1;
            }

            BigInt::from_limbs_internal(mask_limbs)
        };

        self.bits = self.bits & mask;
    }

    /// Returns the degree of the polynomial (position of highest set bit)
    ///
    /// Returns 0 for the zero polynomial by convention.
    /// Checks up to 2*K bits to handle unreduced multiplication results.
    fn degree(&self) -> usize {
        // Check up to 2*K bits (max degree after multiplication is 2*(K-1) < 2*K)
        let max_check = (2 * K).min(N * 64);
        for i in (0..max_check).rev() {
            if self.get_bit(i) {
                return i;
            }
        }
        0
    }

    /// Multiplies two binary field elements
    ///
    /// Performs polynomial multiplication in F_2[x] (using XOR for addition),
    /// then reduces modulo the irreducible polynomial.
    ///
    /// # Arguments
    /// * `other` - The element to multiply with
    ///
    /// # Returns
    /// The product reduced to the field
    fn multiply(&self, other: &Self) -> Self {
        let mut result = BigInt::zero();

        // Polynomial multiplication using shift-and-add (XOR)
        for i in 0..K {
            if other.get_bit(i) {
                // Add (XOR) self shifted by i positions
                let shifted = self.bits << i;
                result = result ^ shifted;
            }
        }

        Self::new(result)
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> PartialEq for BinaryField<C, N, K> {
    fn eq(&self, other: &Self) -> bool {
        // Compare only the low K bits
        for i in 0..K {
            if self.get_bit(i) != other.get_bit(i) {
                return false;
            }
        }
        true
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Eq for BinaryField<C, N, K> {}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: FieldConfig<N>, const N: usize, const K: usize> Add for BinaryField<C, N, K> {
    type Output = Self;

    /// Addition in F_2^k is just XOR
    fn add(self, other: Self) -> Self {
        Self {
            bits: self.bits ^ other.bits,
            _config: PhantomData,
        }
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Neg for BinaryField<C, N, K> {
    type Output = Self;

    /// Negation in F_2^k is identity (since -1 = 1 in F_2)
    fn neg(self) -> Self {
        self
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: FieldConfig<N>, const N: usize, const K: usize> Sub for BinaryField<C, N, K> {
    type Output = Self;

    /// Subtraction in F_2^k is same as addition (XOR)
    fn sub(self, other: Self) -> Self {
        self + other // In F_2, a - b = a + b
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> Mul for BinaryField<C, N, K> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self.multiply(&other)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<C: FieldConfig<N>, const N: usize, const K: usize> Div for BinaryField<C, N, K> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        self * other.inverse()
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> FieldElement for BinaryField<C, N, K> {
    fn zero() -> Self {
        Self {
            bits: BigInt::zero(),
            _config: PhantomData,
        }
    }

    fn one() -> Self {
        Self {
            bits: BigInt::one(),
            _config: PhantomData,
        }
    }

    fn is_zero(&self) -> bool {
        for i in 0..K {
            if self.get_bit(i) {
                return false;
            }
        }
        true
    }

    /// Computes the multiplicative inverse using Fermat's Little Theorem
    ///
    /// In F_2^k, we have a^(2^k - 1) = 1 for all non-zero a,
    /// so a^(-1) = a^(2^k - 2)
    ///
    /// # Panics
    /// Panics if called on the zero element
    fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "Cannot invert zero");

        // Calculate 2^k - 2
        // For small k, compute directly as u64
        if K <= 63 {
            // 2^k - 2 fits in a u64
            let exp_val = (1u64 << K) - 2;
            // Convert to minimal byte representation (no leading zeros)
            let bytes = exp_val.to_be_bytes();
            // Skip leading zero bytes
            let first_nonzero = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            return self.pow(&bytes[first_nonzero..]);
        }

        // For larger k, use BigInt but create minimal representation
        let mut exp = BigInt::zero();
        let limb_idx = K / 64;
        let bit_idx = K % 64;

        if limb_idx < N {
            let mut limbs = [0u64; N];
            limbs[limb_idx] = 1u64 << bit_idx;
            exp = BigInt::from_limbs_internal(limbs);
        }
        exp = exp - BigInt::from_u64(2);

        // Convert to bytes and skip leading zeros
        let bytes = exp.to_be_bytes();
        let first_nonzero = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        self.pow(&bytes[first_nonzero..])
    }
}

impl<C: FieldConfig<N>, const N: usize, const K: usize> BinaryField<C, N, K> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigInt256;

    // F_2^4 with irreducible polynomial x^4 + x + 1
    #[derive(Clone, Debug)]
    struct F2_4;

    static F2_MOD: BigInt256 = BigInt::from_u64(2);
    
    // Compact bitstring: x^4 + x + 1 = 0b10011 = 0x13
    static F2_4_IRRED_BITS: [u8; 1] = [0x13];
    
    // Legacy array format (kept for compatibility)
    static F2_4_IRRED: [BigInt256; 5] = [
        BigInt::from_u64(1), // x^0
        BigInt::from_u64(1), // x^1
        BigInt::from_u64(0), // x^2
        BigInt::from_u64(0), // x^3
        BigInt::from_u64(1), // x^4
    ];

    impl FieldConfig<4> for F2_4 {
        fn modulus() -> &'static BigInt256 {
            &F2_MOD
        }
        fn irreducible() -> &'static [BigInt256] {
            &F2_4_IRRED
        }
        fn irreducible_bitstring() -> &'static [u8] {
            &F2_4_IRRED_BITS
        }
    }

    type GF16 = BinaryField<F2_4, 4, 4>;

    #[test]
    fn test_binary_field_basic() {
        let zero = GF16::zero();
        let one = GF16::one();

        assert!(zero.is_zero());
        assert!(!one.is_zero());
        assert_eq!(one, GF16::one());
        assert_ne!(zero, GF16::one());
    }

    #[test]
    fn test_binary_field_addition() {
        // In F_2^k, addition is XOR
        let a = GF16::from_u64(0b0101); // x^2 + 1
        let b = GF16::from_u64(0b0011); // x + 1
        let c = a.clone() + b.clone();

        // 0101 XOR 0011 = 0110 = x^2 + x
        assert_eq!(c, GF16::from_u64(0b0110));

        // Addition is commutative
        assert_eq!(a.clone() + b.clone(), b.clone() + a.clone());

        // a + a = 0 in F_2^k
        assert!((a.clone() + a.clone()).is_zero());
    }

    #[test]
    fn test_binary_field_negation() {
        let a = GF16::from_u64(0b0101);

        // In F_2^k, -a = a
        assert_eq!(-a.clone(), a.clone());
    }

    #[test]
    fn test_binary_field_subtraction() {
        let a = GF16::from_u64(0b0101);
        let b = GF16::from_u64(0b0011);

        // In F_2^k, subtraction is same as addition
        assert_eq!(a.clone() - b.clone(), a.clone() + b.clone());
    }

    #[test]
    fn test_binary_field_multiplication() {
        let a = GF16::from_u64(0b0010); // x
        let b = GF16::from_u64(0b0100); // x^2
        let c = a.clone() * b.clone();

        // x * x^2 = x^3
        assert_eq!(c, GF16::from_u64(0b1000));

        // Multiplication is commutative
        assert_eq!(a.clone() * b.clone(), b.clone() * a.clone());

        // Multiply by one
        assert_eq!(a.clone() * GF16::one(), a.clone());
    }

    #[test]
    fn test_binary_field_inverse() {
        let a = GF16::from_u64(0b0010); // x in GF(2^4)

        // Use the inverse() method
        let a_inv = a.inverse();

        // a * a^(-1) = 1
        let product = a.clone() * a_inv.clone();
        assert_eq!(product, GF16::one(), "a * a^(-1) should equal 1");
    }

    #[test]
    #[should_panic(expected = "Cannot invert zero")]
    fn test_binary_field_inverse_zero_panics() {
        let zero = GF16::zero();
        let _ = zero.inverse();
    }

    #[test]
    fn test_binary_field_division() {
        let a = GF16::from_u64(0b1000); // x^3
        let b = GF16::from_u64(0b0010); // x
        let c = a.clone() / b.clone();

        // c * b should equal a
        assert_eq!(c.clone() * b.clone(), a.clone());
    }
}
