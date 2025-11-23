/// Elliptic Curve implementation using Short Weierstrass form: y^2 = x^3 + ax + b
/// Generic over finite fields F that implement the Field trait
/// 
/// Implements the Chord-Tangent Law for group operations:
/// - For distinct points P, Q: the line through P and Q intersects the curve at -R, so P + Q = R
/// - For P = Q: the tangent line at P intersects the curve at -R, so 2P = R
/// - Point at infinity O is the identity element

use crate::field::Field;
use crate::bigint::BigUint;

/// Represents a point on an elliptic curve over a finite field
/// Points are either (x, y) coordinates or the point at infinity
#[derive(Debug, Clone, PartialEq)]
pub enum EllipticCurvePoint<F: Field> {
    /// Point at infinity (identity element)
    Infinity,
    /// Affine point (x, y) on the curve
    Point { x: F, y: F },
}

/// Elliptic curve structure holding curve parameters
/// Represents curves of the form y^2 = x^3 + ax + b
#[derive(Debug, Clone)]
pub struct EllipticCurve<F: Field> {
    pub a: F,
    pub b: F,
}

impl<F: Field> EllipticCurve<F> {
    /// Create a new elliptic curve with parameters a and b
    /// Note: This doesn't validate the curve (e.g., checking discriminant)
    pub fn new(a: F, b: F) -> Self {
        Self { a, b }
    }

    /// Check if a point (x, y) satisfies the curve equation y^2 = x^3 + ax + b
    pub fn is_on_curve(&self, point: &EllipticCurvePoint<F>) -> bool {
        match point {
            EllipticCurvePoint::Infinity => true,
            EllipticCurvePoint::Point { x, y } => {
                // Compute y^2
                let y_squared = y.mul(y);
                
                // Compute x^3 + ax + b
                let x_squared = x.mul(x);
                let x_cubed = x_squared.mul(x);
                let ax = self.a.mul(x);
                let right = x_cubed.add(&ax).add(&self.b);
                
                y_squared == right
            }
        }
    }

    /// Create a point on this curve (doesn't verify it's on the curve)
    pub fn point(&self, x: F, y: F) -> EllipticCurvePoint<F> {
        EllipticCurvePoint::Point { x, y }
    }

    /// Return the point at infinity
    pub fn infinity(&self) -> EllipticCurvePoint<F> {
        EllipticCurvePoint::Infinity
    }

    /// Add two points on the curve using the Chord-Tangent Law
    /// 
    /// For distinct points P and Q:
    /// - Compute slope m = (y2 - y1) / (x2 - x1)
    /// - x3 = m^2 - x1 - x2
    /// - y3 = m(x1 - x3) - y1
    /// 
    /// For P = Q (point doubling):
    /// - Compute slope m = (3x1^2 + a) / (2y1)
    /// - x3 = m^2 - 2x1
    /// - y3 = m(x1 - x3) - y1
    pub fn add(&self, p: &EllipticCurvePoint<F>, q: &EllipticCurvePoint<F>) -> EllipticCurvePoint<F> {
        match (p, q) {
            // Identity cases: O + P = P
            (EllipticCurvePoint::Infinity, _) => q.clone(),
            (_, EllipticCurvePoint::Infinity) => p.clone(),
            
            (EllipticCurvePoint::Point { x: x1, y: y1 }, 
             EllipticCurvePoint::Point { x: x2, y: y2 }) => {
                
                // Case: P + (-P) = O (points with same x, opposite y)
                if x1 == x2 && y1 == &y2.neg() {
                    return EllipticCurvePoint::Infinity;
                }
                
                // Case: P = Q (point doubling)
                if x1 == x2 && y1 == y2 {
                    return self.double(&EllipticCurvePoint::Point { 
                        x: x1.clone(), 
                        y: y1.clone() 
                    });
                }
                
                // Case: P != Q (point addition using chord)
                // Compute slope m = (y2 - y1) / (x2 - x1)
                let numerator = y2.sub(y1);
                let denominator = x2.sub(x1);
                let m = numerator.div(&denominator).expect("Division by zero in point addition");
                
                // Compute x3 = m^2 - x1 - x2
                let m_squared = m.mul(&m);
                let x3 = m_squared.sub(x1).sub(x2);
                
                // Compute y3 = m(x1 - x3) - y1
                let y3 = m.mul(&x1.sub(&x3)).sub(y1);
                
                EllipticCurvePoint::Point { x: x3, y: y3 }
            }
        }
    }

    /// Double a point on the curve (compute 2P) using the Tangent Law
    /// 
    /// For P = (x1, y1):
    /// - Compute slope m = (3x1^2 + a) / (2y1)
    /// - x3 = m^2 - 2x1
    /// - y3 = m(x1 - x3) - y1
    pub fn double(&self, p: &EllipticCurvePoint<F>) -> EllipticCurvePoint<F> {
        match p {
            EllipticCurvePoint::Infinity => EllipticCurvePoint::Infinity,
            EllipticCurvePoint::Point { x, y } => {
                // If y = 0, then the tangent is vertical and 2P = O
                let zero = y.sub(y); // Create zero
                if y == &zero {
                    return EllipticCurvePoint::Infinity;
                }
                
                // Compute slope m = (3x^2 + a) / (2y)
                let three = y.add(y).add(y).div(y).expect("Division to create 3"); // Create 3 from field elements
                let two = y.add(y).div(y).expect("Division to create 2"); // Create 2
                
                let x_squared = x.mul(x);
                let numerator = three.mul(&x_squared).add(&self.a);
                let denominator = two.mul(y);
                let m = numerator.div(&denominator).expect("Division by zero in point doubling");
                
                // Compute x3 = m^2 - 2x
                let m_squared = m.mul(&m);
                let two_x = x.add(x);
                let x3 = m_squared.sub(&two_x);
                
                // Compute y3 = m(x - x3) - y
                let y3 = m.mul(&x.sub(&x3)).sub(y);
                
                EllipticCurvePoint::Point { x: x3, y: y3 }
            }
        }
    }

    /// Negate a point on the curve (compute -P)
    /// For P = (x, y), -P = (x, -y)
    pub fn negate(&self, p: &EllipticCurvePoint<F>) -> EllipticCurvePoint<F> {
        match p {
            EllipticCurvePoint::Infinity => EllipticCurvePoint::Infinity,
            EllipticCurvePoint::Point { x, y } => {
                EllipticCurvePoint::Point { 
                    x: x.clone(), 
                    y: y.neg() 
                }
            }
        }
    }

    /// Scalar multiplication: compute n*P using double-and-add algorithm
    /// This is efficient O(log n) operation
    pub fn scalar_mul(&self, n: &crate::bigint::BigUint, p: &EllipticCurvePoint<F>) -> EllipticCurvePoint<F> {
        if n.is_zero() {
            return EllipticCurvePoint::Infinity;
        }

        let mut result = EllipticCurvePoint::Infinity;
        let mut base = p.clone();
        let mut scalar = n.clone();

        // Double-and-add algorithm
        while !scalar.is_zero() {
            // If the least significant bit is 1, add base to result
            if &scalar & &BigUint::from_u64(1) == BigUint::from_u64(1) {
                result = self.add(&result, &base);
            }
            
            // Double the base
            base = self.double(&base);
            
            // Right shift scalar by 1
            scalar = &scalar >> 1;
        }

        result
    }
}

impl<F: Field> EllipticCurvePoint<F> {
    /// Check if this is the point at infinity
    pub fn is_infinity(&self) -> bool {
        matches!(self, EllipticCurvePoint::Infinity)
    }

    /// Get the x-coordinate if this is a point (not infinity)
    pub fn x(&self) -> Option<&F> {
        match self {
            EllipticCurvePoint::Infinity => None,
            EllipticCurvePoint::Point { x, .. } => Some(x),
        }
    }

    /// Get the y-coordinate if this is a point (not infinity)
    pub fn y(&self) -> Option<&F> {
        match self {
            EllipticCurvePoint::Infinity => None,
            EllipticCurvePoint::Point { y, .. } => Some(y),
        }
    }
}

// Implement Add trait for convenience (requires curve context, so limited use)
// Note: This requires the curve parameters to be known at compile time
// In practice, you'd use curve.add(p, q) instead

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldElement;
    use crate::bigint::BigUint;

    #[test]
    fn test_point_at_infinity() {
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a, b);

        let inf = curve.infinity();
        assert!(inf.is_infinity());
        assert!(curve.is_on_curve(&inf));
    }

    #[test]
    fn test_point_on_curve() {
        // Example: curve y^2 = x^3 + 2x + 2 over F_17
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a, b);

        // Point (6, 3): verify 3^2 = 6^3 + 2*6 + 2 (mod 17)
        // 9 = 216 + 12 + 2 = 230 = 13*17 + 9 ✓
        let x = FieldElement::new(BigUint::from_u64(6), p.clone());
        let y = FieldElement::new(BigUint::from_u64(3), p.clone());
        let point = curve.point(x, y);
        
        assert!(curve.is_on_curve(&point));
    }

    #[test]
    fn test_point_addition() {
        // Using curve y^2 = x^3 + 2x + 2 over F_17
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a, b);

        // P = (5, 1), Q = (6, 3)
        let p1 = curve.point(
            FieldElement::new(BigUint::from_u64(5), p.clone()),
            FieldElement::new(BigUint::from_u64(1), p.clone())
        );
        let p2 = curve.point(
            FieldElement::new(BigUint::from_u64(6), p.clone()),
            FieldElement::new(BigUint::from_u64(3), p.clone())
        );

        let p3 = curve.add(&p1, &p2);
        
        // Result should be on the curve
        assert!(curve.is_on_curve(&p3));
    }

    #[test]
    fn test_point_doubling() {
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a, b);

        // P = (5, 1)
        let point = curve.point(
            FieldElement::new(BigUint::from_u64(5), p.clone()),
            FieldElement::new(BigUint::from_u64(1), p.clone())
        );

        let doubled = curve.double(&point);
        
        // 2P should be on the curve
        assert!(curve.is_on_curve(&doubled));
        
        // 2P should equal P + P
        let added = curve.add(&point, &point);
        assert_eq!(doubled, added);
    }

    #[test]
    fn test_identity_element() {
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a, b);

        let point = curve.point(
            FieldElement::new(BigUint::from_u64(5), p.clone()),
            FieldElement::new(BigUint::from_u64(1), p.clone())
        );
        let inf = curve.infinity();

        // P + O = P
        let result = curve.add(&point, &inf);
        assert_eq!(result, point);

        // O + P = P
        let result = curve.add(&inf, &point);
        assert_eq!(result, point);
    }

    #[test]
    fn test_inverse_element() {
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a, b);

        let point = curve.point(
            FieldElement::new(BigUint::from_u64(5), p.clone()),
            FieldElement::new(BigUint::from_u64(1), p.clone())
        );

        let neg_point = curve.negate(&point);
        
        // -P should be on the curve
        assert!(curve.is_on_curve(&neg_point));
        
        // P + (-P) = O
        let result = curve.add(&point, &neg_point);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_scalar_multiplication() {
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a.clone(), b.clone());

        let point = curve.point(
            FieldElement::new(BigUint::from_u64(5), p.clone()),
            FieldElement::new(BigUint::from_u64(1), p.clone())
        );

        // 0*P = O
        let result = curve.scalar_mul(&BigUint::from_u64(0), &point);
        assert!(result.is_infinity());

        // 1*P = P
        let result = curve.scalar_mul(&BigUint::from_u64(1), &point);
        assert_eq!(result, point);

        // 2*P should equal P + P
        let result = curve.scalar_mul(&BigUint::from_u64(2), &point);
        let expected = curve.add(&point, &point);
        assert_eq!(result, expected);

        // 3*P should equal P + P + P
        let result = curve.scalar_mul(&BigUint::from_u64(3), &point);
        let temp = curve.add(&point, &point);
        let expected = curve.add(&temp, &point);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_associativity() {
        let p = BigUint::from_u64(17);
        let a = FieldElement::new(BigUint::from_u64(2), p.clone());
        let b = FieldElement::new(BigUint::from_u64(2), p.clone());
        let curve = EllipticCurve::new(a, b);

        let p1 = curve.point(
            FieldElement::new(BigUint::from_u64(5), p.clone()),
            FieldElement::new(BigUint::from_u64(1), p.clone())
        );
        let p2 = curve.point(
            FieldElement::new(BigUint::from_u64(6), p.clone()),
            FieldElement::new(BigUint::from_u64(3), p.clone())
        );
        let p3 = curve.point(
            FieldElement::new(BigUint::from_u64(10), p.clone()),
            FieldElement::new(BigUint::from_u64(6), p.clone())
        );

        // (P1 + P2) + P3 = P1 + (P2 + P3)
        let left = curve.add(&curve.add(&p1, &p2), &p3);
        let right = curve.add(&p1, &curve.add(&p2, &p3));
        
        assert_eq!(left, right);
    }
}
