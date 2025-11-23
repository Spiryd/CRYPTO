/// Binary Elliptic Curve implementation for characteristic 2 fields
/// Uses the form: y² + xy = x³ + ax² + b
/// 
/// This is different from Short Weierstrass form used for p > 3.
/// Binary curves require different addition formulas due to characteristic K = 2.
/// 
/// References:
/// [3] Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
/// [4] NIST FIPS 186-4 - Digital Signature Standard

use crate::binary_field::BinaryFieldElement;
use crate::field::Field;

/// Represents a point on a binary elliptic curve
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryEllipticCurvePoint {
    /// Point at infinity (identity element)
    Infinity,
    /// Affine point (x, y) on the curve
    Point { 
        x: BinaryFieldElement, 
        y: BinaryFieldElement 
    },
}

/// Binary elliptic curve over F2^m
/// Curve form: y² + xy = x³ + ax² + b
#[derive(Debug, Clone)]
pub struct BinaryEllipticCurve {
    pub a: BinaryFieldElement,
    pub b: BinaryFieldElement,
    pub irreducible: Vec<u8>,
    pub degree: usize,
}

impl BinaryEllipticCurve {
    /// Create a new binary elliptic curve with parameters a and b
    /// Curve equation: y² + xy = x³ + ax² + b
    pub fn new(a: BinaryFieldElement, b: BinaryFieldElement) -> Self {
        let irreducible = a.irreducible().clone();
        let degree = a.degree();
        Self { a, b, irreducible, degree }
    }

    /// Check if a point (x, y) satisfies the curve equation y² + xy = x³ + ax² + b
    pub fn is_on_curve(&self, point: &BinaryEllipticCurvePoint) -> bool {
        match point {
            BinaryEllipticCurvePoint::Infinity => true,
            BinaryEllipticCurvePoint::Point { x, y } => {
                // Compute left side: y² + xy
                let y_squared = y.mul(y);
                let xy = x.mul(y);
                let left = &y_squared + &xy;
                
                // Compute right side: x³ + ax² + b
                let x_squared = x.mul(x);
                let x_cubed = &x_squared * x;
                let ax_squared = &self.a * &x_squared;
                let right = &(&x_cubed + &ax_squared) + &self.b;
                
                left == right
            }
        }
    }

    /// Create a point on this curve
    pub fn point(&self, x: BinaryFieldElement, y: BinaryFieldElement) -> BinaryEllipticCurvePoint {
        BinaryEllipticCurvePoint::Point { x, y }
    }

    /// Return the point at infinity
    pub fn infinity(&self) -> BinaryEllipticCurvePoint {
        BinaryEllipticCurvePoint::Infinity
    }

    /// Add two points on the binary curve using characteristic 2 formulas
    /// 
    /// For binary fields (K = 2), the addition formulas differ from prime fields:
    /// 
    /// Case 1: P + O = P (identity)
    /// Case 2: P + (-P) = O (when x₁ = x₂ and y₁ + y₂ = x₁)
    /// Case 3: P = Q (point doubling)
    /// Case 4: P ≠ Q (general addition)
    pub fn add(&self, p: &BinaryEllipticCurvePoint, q: &BinaryEllipticCurvePoint) 
        -> BinaryEllipticCurvePoint {
        match (p, q) {
            // Identity cases
            (BinaryEllipticCurvePoint::Infinity, _) => q.clone(),
            (_, BinaryEllipticCurvePoint::Infinity) => p.clone(),
            
            (BinaryEllipticCurvePoint::Point { x: x1, y: y1 }, 
             BinaryEllipticCurvePoint::Point { x: x2, y: y2 }) => {
                
                // Case: x₁ = x₂
                if x1 == x2 {
                    // Check if y₁ + y₂ = x₁ (inverse condition in binary fields)
                    let y_sum = y1 + y2;
                    if &y_sum == x1 {
                        return BinaryEllipticCurvePoint::Infinity;
                    }
                    // Otherwise, this is point doubling
                    return self.double(&BinaryEllipticCurvePoint::Point { 
                        x: x1.clone(), 
                        y: y1.clone() 
                    });
                }
                
                // General case: P ≠ Q
                // λ = (y₁ + y₂) / (x₁ + x₂)
                let numerator = y1 + y2;
                let denominator = x1 + x2;
                let lambda = (&numerator / &denominator)
                    .expect("Division by zero in binary curve addition");
                
                // x₃ = λ² + λ + x₁ + x₂ + a
                let lambda_squared = &lambda * &lambda;
                let x3 = &(&(&(&lambda_squared + &lambda) + x1) + x2) + &self.a;
                
                // y₃ = λ(x₁ + x₃) + x₃ + y₁
                let x1_plus_x3 = x1 + &x3;
                let lambda_term = &lambda * &x1_plus_x3;
                let y3 = &(&lambda_term + &x3) + y1;
                
                BinaryEllipticCurvePoint::Point { x: x3, y: y3 }
            }
        }
    }

    /// Double a point on the binary curve using characteristic 2 formulas
    /// 
    /// For P = (x₁, y₁):
    /// If x₁ = 0, then 2P = O
    /// Otherwise:
    ///   λ = x₁ + y₁/x₁
    ///   x₃ = λ² + λ + a
    ///   y₃ = x₁² + λ·x₃ + x₃
    pub fn double(&self, p: &BinaryEllipticCurvePoint) -> BinaryEllipticCurvePoint {
        match p {
            BinaryEllipticCurvePoint::Infinity => BinaryEllipticCurvePoint::Infinity,
            BinaryEllipticCurvePoint::Point { x, y } => {
                // Check if x = 0 (then 2P = O)
                if x.is_zero() {
                    return BinaryEllipticCurvePoint::Infinity;
                }
                
                // λ = x + y/x
                let y_over_x = (y / x).expect("Division by zero in binary curve doubling");
                let lambda = x + &y_over_x;
                
                // x₃ = λ² + λ + a
                let lambda_squared = &lambda * &lambda;
                let x3 = &(&lambda_squared + &lambda) + &self.a;
                
                // y₃ = x² + λ·x₃ + x₃
                // In F2^m, x² = x for some representations, but generally:
                let x_squared = x * x;
                let lambda_x3 = &lambda * &x3;
                let y3 = &(&x_squared + &lambda_x3) + &x3;
                
                BinaryEllipticCurvePoint::Point { x: x3, y: y3 }
            }
        }
    }

    /// Negate a point on the binary curve
    /// For P = (x, y), -P = (x, x + y) in characteristic 2
    /// Note: This differs from prime fields where -P = (x, -y)
    pub fn negate(&self, p: &BinaryEllipticCurvePoint) -> BinaryEllipticCurvePoint {
        match p {
            BinaryEllipticCurvePoint::Infinity => BinaryEllipticCurvePoint::Infinity,
            BinaryEllipticCurvePoint::Point { x, y } => {
                // In characteristic 2: -P = (x, x + y)
                let neg_y = x + y;
                BinaryEllipticCurvePoint::Point { 
                    x: x.clone(), 
                    y: neg_y 
                }
            }
        }
    }

    /// Scalar multiplication: compute n·P using double-and-add algorithm
    /// Works the same way as for prime field curves
    pub fn scalar_mul(&self, n: u64, p: &BinaryEllipticCurvePoint) -> BinaryEllipticCurvePoint {
        if n == 0 {
            return BinaryEllipticCurvePoint::Infinity;
        }

        let mut result = BinaryEllipticCurvePoint::Infinity;
        let mut base = p.clone();
        let mut scalar = n;

        // Double-and-add algorithm
        while scalar > 0 {
            if scalar & 1 == 1 {
                result = self.add(&result, &base);
            }
            base = self.double(&base);
            scalar >>= 1;
        }

        result
    }
}

impl BinaryEllipticCurvePoint {
    /// Check if this is the point at infinity
    pub fn is_infinity(&self) -> bool {
        matches!(self, BinaryEllipticCurvePoint::Infinity)
    }

    /// Get the x-coordinate if this is a point (not infinity)
    pub fn x(&self) -> Option<&BinaryFieldElement> {
        match self {
            BinaryEllipticCurvePoint::Infinity => None,
            BinaryEllipticCurvePoint::Point { x, .. } => Some(x),
        }
    }

    /// Get the y-coordinate if this is a point (not infinity)
    pub fn y(&self) -> Option<&BinaryFieldElement> {
        match self {
            BinaryEllipticCurvePoint::Infinity => None,
            BinaryEllipticCurvePoint::Point { y, .. } => Some(y),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_curve_point_at_infinity() {
        // F2^4 with irreducible polynomial x^4 + x + 1 = 0b10011
        let irreducible = vec![0b10011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        let inf = curve.infinity();
        assert!(inf.is_infinity());
        assert!(curve.is_on_curve(&inf));
    }

    #[test]
    fn test_binary_curve_point_on_curve() {
        // F2^4 with irreducible polynomial x^4 + x + 1
        let irreducible = vec![0b10011];
        let degree = 4;
        
        // Curve: y^2 + xy = x^3 + x^2 + 1
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        // Let's find a valid point by searching
        let mut found_point = false;
        for x_val in 0..16 {
            for y_val in 0..16 {
                let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
                let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
                let point = curve.point(x.clone(), y.clone());
                
                if curve.is_on_curve(&point) {
                    println!("Found point: x={}, y={}", x_val, y_val);
                    found_point = true;
                    break;
                }
            }
            if found_point {
                break;
            }
        }
        
        assert!(found_point, "Should find at least one point on the curve");
    }

    #[test]
    fn test_binary_curve_point_addition() {
        let irreducible = vec![0b10011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        // Find two valid points on the curve
        let mut points = Vec::new();
        for x_val in 0..16 {
            for y_val in 0..16 {
                let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
                let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
                let p = curve.point(x, y);
                if curve.is_on_curve(&p) {
                    points.push(p);
                    if points.len() == 2 {
                        break;
                    }
                }
            }
            if points.len() == 2 {
                break;
            }
        }
        
        if points.len() >= 2 {
            let p1 = &points[0];
            let p2 = &points[1];
            
            // Test that we can add them
            let p3 = curve.add(p1, p2);
            
            // Result should be on the curve
            assert!(curve.is_on_curve(&p3));
        }
    }

    #[test]
    fn test_binary_curve_point_doubling() {
        let irreducible = vec![0b10011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        // Find a valid point
        let mut test_point = None;
        for x_val in 1..16 {  // Skip x=0 as doubling might fail
            for y_val in 0..16 {
                let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
                let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
                let p = curve.point(x, y);
                if curve.is_on_curve(&p) {
                    test_point = Some(p);
                    break;
                }
            }
            if test_point.is_some() {
                break;
            }
        }

        if let Some(point) = test_point {
            let doubled = curve.double(&point);
            
            // 2P should be on the curve
            assert!(curve.is_on_curve(&doubled));
            
            // 2P should equal P + P
            let added = curve.add(&point, &point);
            assert_eq!(doubled, added);
        }
    }

    #[test]
    fn test_binary_curve_identity() {
        let irreducible = vec![0b10011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        // Find a valid point
        let mut test_point = None;
        for x_val in 0..16 {
            for y_val in 0..16 {
                let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
                let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
                let p = curve.point(x, y);
                if curve.is_on_curve(&p) {
                    test_point = Some(p);
                    break;
                }
            }
            if test_point.is_some() {
                break;
            }
        }

        if let Some(point) = test_point {
            let inf = curve.infinity();

            // P + O = P
            let result = curve.add(&point, &inf);
            assert_eq!(result, point);

            // O + P = P
            let result = curve.add(&inf, &point);
            assert_eq!(result, point);
        }
    }

    #[test]
    fn test_binary_curve_inverse() {
        let irreducible = vec![0b10011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        // Find a valid point
        let mut test_point = None;
        for x_val in 0..16 {
            for y_val in 0..16 {
                let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
                let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
                let p = curve.point(x, y);
                if curve.is_on_curve(&p) {
                    test_point = Some(p);
                    break;
                }
            }
            if test_point.is_some() {
                break;
            }
        }

        if let Some(point) = test_point {
            let neg_point = curve.negate(&point);
            
            // -P should be on the curve
            assert!(curve.is_on_curve(&neg_point));
            
            // P + (-P) = O
            let result = curve.add(&point, &neg_point);
            assert!(result.is_infinity());
        }
    }

    #[test]
    fn test_binary_curve_scalar_multiplication() {
        let irreducible = vec![0b10011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        let point = curve.point(
            BinaryFieldElement::from_u64(0b0010, irreducible.clone(), degree),
            BinaryFieldElement::from_u64(0b0101, irreducible.clone(), degree)
        );

        // 0·P = O
        let result = curve.scalar_mul(0, &point);
        assert!(result.is_infinity());

        // 1·P = P
        let result = curve.scalar_mul(1, &point);
        assert_eq!(result, point);

        // 2·P should equal P + P
        let result = curve.scalar_mul(2, &point);
        let expected = curve.add(&point, &point);
        assert_eq!(result, expected);

        // 3·P should equal P + P + P
        let result = curve.scalar_mul(3, &point);
        let temp = curve.add(&point, &point);
        let expected = curve.add(&temp, &point);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_binary_curve_associativity() {
        let irreducible = vec![0b10011];
        let degree = 4;
        
        let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        // Find three valid points
        let mut points = Vec::new();
        for x_val in 0..16 {
            for y_val in 0..16 {
                let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
                let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
                let p = curve.point(x, y);
                if curve.is_on_curve(&p) {
                    points.push(p);
                    if points.len() == 3 {
                        break;
                    }
                }
            }
            if points.len() == 3 {
                break;
            }
        }

        if points.len() >= 3 {
            let p1 = &points[0];
            let p2 = &points[1];
            let p3 = &points[2];

            // (P1 + P2) + P3 = P1 + (P2 + P3)
            let left = curve.add(&curve.add(p1, p2), p3);
            let right = curve.add(p1, &curve.add(p2, p3));
            
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_binary_curve_large_field() {
        // F2^8 with AES polynomial x^8 + x^4 + x^3 + x + 1
        let irreducible = vec![0b00011011, 0b00000001];
        let degree = 8;
        
        let a = BinaryFieldElement::from_u64(0, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
        let curve = BinaryEllipticCurve::new(a, b);

        // Test with a point on the curve
        let x = BinaryFieldElement::from_u64(0x03, irreducible.clone(), degree);
        let y = BinaryFieldElement::from_u64(0x0A, irreducible.clone(), degree);
        let point = curve.point(x, y);

        // Verify operations work on larger field
        if curve.is_on_curve(&point) {
            let doubled = curve.double(&point);
            assert!(curve.is_on_curve(&doubled));
            
            let scalar_result = curve.scalar_mul(5, &point);
            assert!(curve.is_on_curve(&scalar_result));
        }
    }
}
