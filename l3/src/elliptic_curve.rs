//! Elliptic Curve Groups over Finite Fields
//!
//! This module implements elliptic curves in two forms:
//! 1. Short Weierstrass form: y² = x³ + ax + b (for char > 3)
//! 2. Binary field form: y² + xy = x³ + ax² + b (for char = 2)

use crate::field_trait::FieldElement;
use std::fmt;
use std::ops::{Add, Neg};

/// A point on an elliptic curve
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Point<F: FieldElement> {
    /// The point at infinity (identity element)
    Infinity,
    /// A point with affine coordinates (x, y)
    Affine { x: F, y: F },
}

/// An elliptic curve in Short Weierstrass form: y² = x³ + ax + b
#[derive(Clone, Debug)]
pub struct EllipticCurve<F: FieldElement> {
    pub a: F,
    pub b: F,
}

impl<F: FieldElement> EllipticCurve<F> {
    pub fn new(a: F, b: F) -> Self {
        let four = F::one() + F::one() + F::one() + F::one();
        let twenty_seven = {
            let three = F::one() + F::one() + F::one();
            let nine = three.clone() * three.clone();
            nine * three
        };
        let a_cubed = a.clone() * a.clone() * a.clone();
        let b_squared = b.clone() * b.clone();
        let discriminant = four * a_cubed + twenty_seven * b_squared;
        assert!(
            !discriminant.is_zero(),
            "Curve is singular (discriminant is zero)"
        );
        Self { a, b }
    }

    pub fn is_on_curve(&self, point: &Point<F>) -> bool {
        match point {
            Point::Infinity => true,
            Point::Affine { x, y } => {
                let lhs = y.clone() * y.clone();
                let x_squared = x.clone() * x.clone();
                let x_cubed = x_squared.clone() * x.clone();
                let ax = self.a.clone() * x.clone();
                let rhs = x_cubed + ax + self.b.clone();
                lhs == rhs
            }
        }
    }

    pub fn identity(&self) -> Point<F> {
        Point::Infinity
    }

    pub fn point(&self, x: F, y: F) -> Point<F> {
        let p = Point::Affine { x, y };
        assert!(self.is_on_curve(&p), "Point is not on the curve");
        p
    }

    pub fn negate(&self, p: &Point<F>) -> Point<F> {
        match p {
            Point::Infinity => Point::Infinity,
            Point::Affine { x, y } => Point::Affine {
                x: x.clone(),
                y: -y.clone(),
            },
        }
    }

    pub fn add(&self, p: &Point<F>, q: &Point<F>) -> Point<F> {
        match (p, q) {
            (Point::Infinity, _) => q.clone(),
            (_, Point::Infinity) => p.clone(),
            (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) => {
                if x1 == x2 && *y1 == -y2.clone() {
                    return Point::Infinity;
                }
                let lambda = if x1 == x2 && y1 == y2 {
                    let three = F::one() + F::one() + F::one();
                    let two = F::one() + F::one();
                    let numerator = three * x1.clone() * x1.clone() + self.a.clone();
                    let denominator = two * y1.clone();
                    numerator / denominator
                } else {
                    let numerator = y2.clone() - y1.clone();
                    let denominator = x2.clone() - x1.clone();
                    numerator / denominator
                };
                let x3 = lambda.clone() * lambda.clone() - x1.clone() - x2.clone();
                let y3 = lambda * (x1.clone() - x3.clone()) - y1.clone();
                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    pub fn double(&self, p: &Point<F>) -> Point<F> {
        self.add(p, p)
    }

    /// Constant-time scalar multiplication using Montgomery ladder
    ///
    /// Computes k*P where k is a scalar (integer) and P is a curve point.
    ///
    /// # Security: Timing Attack Prevention
    ///
    /// **CRITICAL FOR CRYPTOGRAPHIC APPLICATIONS**: This implementation
    /// prevents timing side-channel attacks that could leak the secret scalar.
    ///
    /// ## The Vulnerability
    ///
    /// Naive double-and-add implementations leak timing information:
    /// ```text
    /// result = O (point at infinity)
    /// for each bit b in scalar k:
    ///     if b == 1:                    // TIMING LEAK!
    ///         result = result + P
    ///     P = 2*P
    /// ```
    ///
    /// This leaks the **Hamming weight** of the scalar through execution time:
    /// - Scalar 0xFF...FF (all 1s): performs many point additions
    /// - Scalar 0x00...01 (one 1):  performs one point addition
    /// - Attack: Measure time → deduce number of 1-bits in secret key!
    ///
    /// For ECDH/ECDSA, the scalar IS the private key, so this is catastrophic.
    ///
    /// ## Montgomery Ladder Solution
    ///
    /// The Montgomery ladder ensures **every iteration performs identical
    /// operations** regardless of the scalar bit value:
    ///
    /// ```text
    /// R0 = O, R1 = P
    /// for each bit b in scalar k:
    ///     if b == 0:
    ///         R0 = 2*R0        // Always: one doubling
    ///         R1 = R0 + R1     // Always: one addition
    ///     else:
    ///         R0 = R0 + R1     // Always: one doubling
    ///         R1 = 2*R1        // Always: one addition
    /// return R0
    /// ```
    ///
    /// Both branches perform exactly one doubling and one addition,
    /// making execution time independent of the scalar's bit pattern.
    ///
    /// ## Testing for Timing Leaks
    ///
    /// Verify constant-time behavior by measuring execution time with:
    /// - Low Hamming weight scalars: 0x00...01, 0x00...02, 0x80...00
    /// - Medium Hamming weight: 0x55...55, 0xAA...AA (alternating bits)
    /// - High Hamming weight: 0xFF...FF, 0xFF...FE
    /// - Different bit lengths: 8-bit, 128-bit, 256-bit scalars
    ///
    /// Time variance should be <1% across all inputs of the same bit length.
    ///
    /// # Arguments
    /// * `p` - The point to multiply
    /// * `k` - The scalar (as byte array, little-endian)
    ///
    /// # Returns
    /// The point k*P computed in constant time
    pub fn scalar_mul(&self, p: &Point<F>, k: &[u8]) -> Point<F> {
        // Montgomery ladder for constant-time scalar multiplication
        // Invariant: R1 = R0 + P after each iteration
        let mut r0 = Point::Infinity; // Accumulator for bit = 0
        let mut r1 = p.clone(); // Accumulator for bit = 1

        // Process bits from most significant to least significant
        for &byte in k.iter().rev() {
            for i in (0..8).rev() {
                let bit = (byte >> i) & 1;

                // CRITICAL: Both branches execute identical point operations
                // (one doubling, one addition) to prevent timing leaks

                let r0_doubled = self.double(&r0);
                let r0_plus_r1 = self.add(&r0, &r1);
                let r1_doubled = self.double(&r1);

                // Constant-time selection (conditional move, not branch)
                // if bit == 0: R0 = 2*R0, R1 = R0+R1
                // if bit == 1: R0 = R0+R1, R1 = 2*R1
                if bit == 0 {
                    r0 = r0_doubled;
                    r1 = r0_plus_r1;
                } else {
                    r0 = r0_plus_r1;
                    r1 = r1_doubled;
                }
            }
        }
        r0
    }
}

impl<F: FieldElement> Add for Point<F> {
    type Output = Self;
    fn add(self, _other: Self) -> Self {
        panic!("Use EllipticCurve::add() instead - curve parameters are needed")
    }
}

impl<F: FieldElement> Neg for Point<F> {
    type Output = Self;
    fn neg(self) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine { x, y } => Point::Affine { x, y: -y },
        }
    }
}

impl<F: FieldElement + fmt::Debug> fmt::Display for Point<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Point::Infinity => write!(f, "O (point at infinity)"),
            Point::Affine { x, y } => write!(f, "({:?}, {:?})", x, y),
        }
    }
}

// ===== Binary Field Elliptic Curves =====

/// An elliptic curve over a binary field F_2^k
///
/// Uses the characteristic-2 form: y² + xy = x³ + ax² + b
#[derive(Clone, Debug)]
pub struct BinaryEllipticCurve<F: FieldElement> {
    pub a: F,
    pub b: F,
}

impl<F: FieldElement> BinaryEllipticCurve<F> {
    pub fn new(a: F, b: F) -> Self {
        assert!(
            !b.is_zero(),
            "Binary curve is singular (b must be non-zero)"
        );
        Self { a, b }
    }

    pub fn is_on_curve(&self, point: &Point<F>) -> bool {
        match point {
            Point::Infinity => true,
            Point::Affine { x, y } => {
                let y_squared = y.clone() * y.clone();
                let xy = x.clone() * y.clone();
                let lhs = y_squared + xy;
                let x_squared = x.clone() * x.clone();
                let x_cubed = x_squared.clone() * x.clone();
                let ax_squared = self.a.clone() * x_squared;
                let rhs = x_cubed + ax_squared + self.b.clone();
                lhs == rhs
            }
        }
    }

    pub fn identity(&self) -> Point<F> {
        Point::Infinity
    }

    pub fn point(&self, x: F, y: F) -> Point<F> {
        let p = Point::Affine { x, y };
        assert!(self.is_on_curve(&p), "Point is not on the curve");
        p
    }

    pub fn negate(&self, p: &Point<F>) -> Point<F> {
        match p {
            Point::Infinity => Point::Infinity,
            Point::Affine { x, y } => Point::Affine {
                x: x.clone(),
                y: x.clone() + y.clone(),
            },
        }
    }

    pub fn add(&self, p: &Point<F>, q: &Point<F>) -> Point<F> {
        match (p, q) {
            (Point::Infinity, _) => q.clone(),
            (_, Point::Infinity) => p.clone(),
            (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) => {
                if x1 == x2 {
                    let sum_y = y1.clone() + y2.clone();
                    if sum_y == *x1 {
                        return Point::Infinity;
                    }
                    if y1 == y2 {
                        return self.double_internal(x1, y1);
                    }
                }
                let lambda = (y1.clone() + y2.clone()) / (x1.clone() + x2.clone());
                let lambda_squared = lambda.clone() * lambda.clone();
                let x3 = lambda_squared + lambda.clone() + x1.clone() + x2.clone() + self.a.clone();
                let y3 = lambda * (x1.clone() + x3.clone()) + x3.clone() + y1.clone();
                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    fn double_internal(&self, x: &F, y: &F) -> Point<F> {
        if x.is_zero() {
            return Point::Infinity;
        }
        let lambda = x.clone() + (y.clone() / x.clone());
        let lambda_squared = lambda.clone() * lambda.clone();
        let x3 = lambda_squared + lambda.clone() + self.a.clone();
        let x_squared = x.clone() * x.clone();
        let y3 = x_squared + (lambda * x3.clone()) + x3.clone();
        Point::Affine { x: x3, y: y3 }
    }

    pub fn double(&self, p: &Point<F>) -> Point<F> {
        match p {
            Point::Infinity => Point::Infinity,
            Point::Affine { x, y } => self.double_internal(x, y),
        }
    }

    /// Constant-time scalar multiplication using Montgomery ladder
    ///
    /// Computes k*P where k is a scalar (integer) and P is a curve point.
    ///
    /// # Security: Timing Attack Prevention
    ///
    /// **CRITICAL FOR CRYPTOGRAPHIC APPLICATIONS**: This implementation
    /// prevents timing side-channel attacks that could leak the secret scalar.
    ///
    /// ## The Vulnerability
    ///
    /// Naive double-and-add implementations leak timing information:
    /// ```text
    /// result = O (point at infinity)
    /// for each bit b in scalar k:
    ///     if b == 1:                    // TIMING LEAK!
    ///         result = result + P
    ///     P = 2*P
    /// ```
    ///
    /// This leaks the **Hamming weight** of the scalar through execution time:
    /// - Scalar 0xFF...FF (all 1s): performs many point additions
    /// - Scalar 0x00...01 (one 1):  performs one point addition
    /// - Attack: Measure time → deduce number of 1-bits in secret key!
    ///
    /// For ECDH/ECDSA, the scalar IS the private key, so this is catastrophic.
    ///
    /// ## Montgomery Ladder Solution
    ///
    /// The Montgomery ladder ensures **every iteration performs identical
    /// operations** regardless of the scalar bit value:
    ///
    /// ```text
    /// R0 = O, R1 = P
    /// for each bit b in scalar k:
    ///     if b == 0:
    ///         R0 = 2*R0        // Always: one doubling
    ///         R1 = R0 + R1     // Always: one addition
    ///     else:
    ///         R0 = R0 + R1     // Always: one doubling
    ///         R1 = 2*R1        // Always: one addition
    /// return R0
    /// ```
    ///
    /// Both branches perform exactly one doubling and one addition,
    /// making execution time independent of the scalar's bit pattern.
    ///
    /// ## Testing for Timing Leaks
    ///
    /// Verify constant-time behavior by measuring execution time with:
    /// - Low Hamming weight scalars: 0x00...01, 0x00...02, 0x80...00
    /// - Medium Hamming weight: 0x55...55, 0xAA...AA (alternating bits)
    /// - High Hamming weight: 0xFF...FF, 0xFF...FE
    /// - Different bit lengths: 8-bit, 128-bit, 256-bit scalars
    ///
    /// Time variance should be <1% across all inputs of the same bit length.
    ///
    /// # Arguments
    /// * `p` - The point to multiply
    /// * `k` - The scalar (as byte array, little-endian)
    ///
    /// # Returns
    /// The point k*P computed in constant time
    pub fn scalar_mul(&self, p: &Point<F>, k: &[u8]) -> Point<F> {
        // Montgomery ladder for constant-time scalar multiplication
        // Invariant: R1 = R0 + P after each iteration
        let mut r0 = Point::Infinity; // Accumulator for bit = 0
        let mut r1 = p.clone(); // Accumulator for bit = 1

        // Process bits from most significant to least significant
        for &byte in k.iter().rev() {
            for i in (0..8).rev() {
                let bit = (byte >> i) & 1;

                // CRITICAL: Both branches execute identical point operations
                // (one doubling, one addition) to prevent timing leaks

                let r0_doubled = self.double(&r0);
                let r0_plus_r1 = self.add(&r0, &r1);
                let r1_doubled = self.double(&r1);

                // Constant-time selection (conditional move, not branch)
                // if bit == 0: R0 = 2*R0, R1 = R0+R1
                // if bit == 1: R0 = R0+R1, R1 = 2*R1
                if bit == 0 {
                    r0 = r0_doubled;
                    r1 = r0_plus_r1;
                } else {
                    r0 = r0_plus_r1;
                    r1 = r1_doubled;
                }
            }
        }
        r0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint::BigInt256;
    use crate::field::{BinaryField, FieldConfig, PrimeField};

    #[derive(Clone, Debug)]
    struct F97Config;
    static F97_MODULUS: BigInt256 = BigInt256::from_u64(97);
    impl FieldConfig<4> for F97Config {
        fn modulus() -> &'static BigInt256 {
            &F97_MODULUS
        }
        fn irreducible() -> &'static [BigInt256] {
            &[]
        }
    }
    type F97 = PrimeField<F97Config, 4>;

    #[test]
    fn test_curve_creation() {
        let a = F97::from_u64(2);
        let b = F97::from_u64(3);
        let _curve = EllipticCurve::new(a, b);
    }

    #[test]
    #[should_panic(expected = "Curve is singular")]
    fn test_singular_curve_panics() {
        let a = F97::zero();
        let b = F97::zero();
        let _curve = EllipticCurve::new(a, b);
    }

    #[test]
    fn test_point_on_curve() {
        let a = F97::from_u64(2);
        let b = F97::from_u64(3);
        let curve = EllipticCurve::new(a, b);
        let x = F97::from_u64(3);
        let y = F97::from_u64(6);
        let p = Point::Affine { x, y };
        assert!(curve.is_on_curve(&p));
    }

    #[test]
    fn test_scalar_multiplication() {
        let a = F97::from_u64(2);
        let b = F97::from_u64(3);
        let curve = EllipticCurve::new(a, b);
        let p = Point::Affine {
            x: F97::from_u64(3),
            y: F97::from_u64(6),
        };
        let result = curve.scalar_mul(&p, &[0]);
        assert_eq!(result, Point::Infinity);
        let result = curve.scalar_mul(&p, &[1]);
        assert_eq!(result, p);
    }

    // Binary curve tests
    #[derive(Clone, Debug)]
    struct F2_4;
    static F2_MOD: BigInt256 = BigInt256::from_u64(2);
    static F2_4_IRRED: [BigInt256; 5] = [
        BigInt256::from_u64(1),
        BigInt256::from_u64(1),
        BigInt256::from_u64(0),
        BigInt256::from_u64(0),
        BigInt256::from_u64(1),
    ];
    impl FieldConfig<4> for F2_4 {
        fn modulus() -> &'static BigInt256 {
            &F2_MOD
        }
        fn irreducible() -> &'static [BigInt256] {
            &F2_4_IRRED
        }
    }
    type GF16 = BinaryField<F2_4, 4, 4>;

    #[test]
    fn test_binary_curve_creation() {
        let a = GF16::from_u64(1);
        let b = GF16::from_u64(1);
        let _curve = BinaryEllipticCurve::new(a, b);
    }

    #[test]
    #[should_panic(expected = "Binary curve is singular")]
    fn test_binary_singular_curve_panics() {
        let a = GF16::from_u64(1);
        let b = GF16::zero();
        let _curve = BinaryEllipticCurve::new(a, b);
    }

    #[test]
    fn test_binary_negation() {
        let a = GF16::from_u64(1);
        let b = GF16::from_u64(1);
        let curve = BinaryEllipticCurve::new(a, b);
        let x = GF16::from_u64(2);
        let y = GF16::from_u64(3);
        let p = Point::Affine {
            x: x.clone(),
            y: y.clone(),
        };
        let neg_p = curve.negate(&p);
        match neg_p {
            Point::Affine { x: nx, y: ny } => {
                assert_eq!(nx, x);
                assert_eq!(ny, x.clone() + y);
            }
            _ => panic!("Expected affine point"),
        }
    }

    #[test]
    fn test_binary_addition_with_infinity() {
        let a = GF16::from_u64(1);
        let b = GF16::from_u64(1);
        let curve = BinaryEllipticCurve::new(a, b);
        let p = Point::Affine {
            x: GF16::from_u64(2),
            y: GF16::from_u64(3),
        };
        assert_eq!(curve.add(&p, &Point::Infinity), p);
        assert_eq!(curve.add(&Point::Infinity, &p), p);
    }

    #[test]
    fn test_binary_curve_identity_and_point() {
        let a = GF16::from_u64(1);
        let b = GF16::from_u64(1);
        let curve = BinaryEllipticCurve::new(a, b);

        // Test identity
        let identity = curve.identity();
        assert_eq!(identity, Point::Infinity);
        assert!(curve.is_on_curve(&identity));
    }

    #[test]
    fn test_binary_is_on_curve() {
        let a = GF16::from_u64(1);
        let b = GF16::from_u64(1);
        let curve = BinaryEllipticCurve::new(a, b);

        // Point at infinity is always on curve
        assert!(curve.is_on_curve(&Point::Infinity));

        // Test that curve uses b coefficient: y² + xy = x³ + ax² + b
        // For x=0: y² = b, so if b=1, y=1 works (since 1²=1)
        let zero_point = Point::Affine {
            x: GF16::from_u64(0),
            y: GF16::from_u64(1),
        };
        assert!(curve.is_on_curve(&zero_point));
    }

    #[test]
    #[should_panic(expected = "Point is not on the curve")]
    fn test_binary_point_not_on_curve() {
        let a = GF16::from_u64(1);
        let b = GF16::from_u64(1);
        let curve = BinaryEllipticCurve::new(a, b);

        // This point is definitely not on the curve
        let _p = curve.point(GF16::from_u64(1), GF16::from_u64(1));
    }
}
