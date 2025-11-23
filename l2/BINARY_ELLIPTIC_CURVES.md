# Binary Elliptic Curves over F₂ᵐ

## Overview

This module implements elliptic curves over binary fields (characteristic 2) using the specialized Weierstrass form required for characteristic-2 fields.

**Curve Equation:** y² + xy = x³ + ax² + b

This differs from the Short Weierstrass form (y² = x³ + ax + b) used for prime fields because division by 2 is undefined in characteristic-2 fields.

## Mathematical Background

### Why a Different Form?

In prime fields (p > 3), we use the Short Weierstrass form:
- y² = x³ + ax + b

However, in characteristic-2 fields (F₂ᵐ), the field has unique properties:
- 2 ≡ 0, so division by 2 is undefined
- x + x = 0 for all x (doubling equals zero)
- Squaring is a linear operation: (x + y)² = x² + y²

These properties necessitate a different curve equation:
- **Binary Weierstrass Form:** y² + xy = x³ + ax² + b

This form avoids the need to divide by 2 in point addition formulas.

### Point Addition Formulas

Unlike prime fields, binary curves use different formulas for point operations.

#### Case 1: P + O = P (Identity)
The point at infinity O is the identity element.

#### Case 2: P + (-P) = O (Inverse)
For P = (x, y), the inverse is -P = (x, x + y)

To verify: if y₁ + y₂ = x₁ where x₁ = x₂, then P + Q = O

#### Case 3: P ≠ Q (General Addition)
For P₁ = (x₁, y₁) and P₂ = (x₂, y₂) where x₁ ≠ x₂:

```
λ = (y₁ + y₂) / (x₁ + x₂)
x₃ = λ² + λ + x₁ + x₂ + a
y₃ = λ(x₁ + x₃) + x₃ + y₁
```

Result: P₃ = (x₃, y₃)

#### Case 4: P = Q (Point Doubling)
For P = (x, y) where x ≠ 0:

```
λ = x + y/x
x₃ = λ² + λ + a
y₃ = x² + λ·x₃ + x₃
```

Result: 2P = (x₃, y₃)

**Special case:** If x = 0, then 2P = O

### Key Differences from Prime Field Curves

| Aspect | Prime Fields (p > 3) | Binary Fields (F₂ᵐ) |
|--------|---------------------|---------------------|
| Equation | y² = x³ + ax + b | y² + xy = x³ + ax² + b |
| Negation | -P = (x, -y) | -P = (x, x + y) |
| Doubling | Uses 2y in denominator | Uses y/x formula |
| Efficiency | Similar | Potentially faster (no division by constants) |
| Hardware | General | Optimized for binary operations |

## Implementation Details

### Structure

```rust
pub struct BinaryEllipticCurve {
    pub a: BinaryFieldElement,
    pub b: BinaryFieldElement,
    pub irreducible: Vec<u8>,
    pub degree: usize,
}

pub enum BinaryEllipticCurvePoint {
    Infinity,
    Point { x: BinaryFieldElement, y: BinaryFieldElement },
}
```

### Operations

All operations are implemented following the characteristic-2 formulas:

- **Point Addition:** `add(P, Q) -> R`
- **Point Doubling:** `double(P) -> 2P`
- **Point Negation:** `negate(P) -> -P`
- **Scalar Multiplication:** `scalar_mul(k, P) -> kP` (using double-and-add)

### Curve Validation

The `is_on_curve` method verifies that a point (x, y) satisfies:
```
y² + xy = x³ + ax² + b
```

All arithmetic is performed in the binary field F₂ᵐ.

## Usage Examples

### Example 1: Small Binary Field (F₂⁴)

```rust
use binary_field::BinaryFieldElement;
use binary_elliptic_curve::BinaryEllipticCurve;

// F₂⁴ with irreducible polynomial x⁴ + x + 1
let irreducible = vec![0b10011];
let degree = 4;

// Curve: y² + xy = x³ + x² + 1
let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
let curve = BinaryEllipticCurve::new(a, b);

// Create a point
let x = BinaryFieldElement::from_u64(0b0001, irreducible.clone(), degree);
let y = BinaryFieldElement::from_u64(0b0110, irreducible.clone(), degree);
let p = curve.point(x, y);

// Verify it's on the curve
assert!(curve.is_on_curve(&p));

// Compute 2P
let p2 = curve.double(&p);
assert!(curve.is_on_curve(&p2));

// Scalar multiplication
let p3 = curve.scalar_mul(3, &p);
assert!(curve.is_on_curve(&p3));
```

### Example 2: AES Field (F₂⁸)

```rust
// F₂⁸ with AES polynomial x⁸ + x⁴ + x³ + x + 1
let irreducible = vec![0b00011011, 0b00000001];
let degree = 8;

// Curve: y² + xy = x³ + 1 (where a = 0)
let a = BinaryFieldElement::from_u64(0, irreducible.clone(), degree);
let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
let curve = BinaryEllipticCurve::new(a, b);

// Find points on the curve
for x_val in 0..256 {
    for y_val in 0..256 {
        let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
        let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
        let p = curve.point(x, y);
        
        if curve.is_on_curve(&p) {
            // Found a valid point!
            let doubled = curve.double(&p);
            let scalar = curve.scalar_mul(100, &p);
            // Both are guaranteed to be on the curve
        }
    }
}
```

## Group Properties

Binary elliptic curves form an abelian group under point addition:

1. **Closure:** P + Q is on the curve
2. **Associativity:** (P + Q) + R = P + (Q + R)
3. **Identity:** P + O = P
4. **Inverse:** P + (-P) = O
5. **Commutativity:** P + Q = Q + P

All these properties are verified in the test suite.

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Point Addition | O(m²) | Dominated by field multiplication |
| Point Doubling | O(m²) | Similar to addition |
| Scalar Multiplication | O(log k · m²) | Using double-and-add |
| Curve Validation | O(m²) | One field equation check |

where m is the field extension degree and k is the scalar.

### Space Complexity

- Each point: O(m) bits for x and y coordinates
- Curve parameters: O(m) bits for a, b, and irreducible polynomial
- Scalar multiplication: O(1) additional space (iterative algorithm)

### Optimization Opportunities

1. **Point representation:** Could use projective coordinates to avoid division
2. **Field operations:** Binary field operations can be optimized with lookup tables
3. **Scalar multiplication:** Could use windowing methods for larger scalars
4. **Hardware acceleration:** Binary operations are efficient in hardware (XOR, shift)

## Cryptographic Applications

Binary elliptic curves are used in:

1. **NIST Standard Curves:** B-163, B-233, B-283, B-409, B-571 (FIPS 186-4)
2. **SEC2 Standards:** sect163k1, sect233r1, etc.
3. **Lightweight Cryptography:** Efficient on constrained devices
4. **Hardware Implementations:** Natural fit for digital circuits

### Advantages

- **Hardware Efficiency:** Binary operations (XOR, AND) are simple in hardware
- **No Carry Propagation:** Addition is bitwise XOR
- **Constant Time:** Easier to implement constant-time operations
- **Compact:** Good security-per-bit ratio

### Considerations

- **Patents:** Some binary curve techniques were historically patented (now expired)
- **Side Channels:** Still requires careful implementation
- **Standardization:** NIST curves are widely supported

## Test Coverage

The implementation includes comprehensive tests:

1. ✅ Point at infinity
2. ✅ Point validation (is_on_curve)
3. ✅ Point addition (general case)
4. ✅ Point doubling
5. ✅ Identity element (P + O = P)
6. ✅ Inverse element (P + (-P) = O)
7. ✅ Scalar multiplication (0·P through 5·P)
8. ✅ Associativity
9. ✅ Large field operations (F₂⁸)

All tests pass, verifying correctness of the implementation.

## References

1. **NIST FIPS 186-4:** Digital Signature Standard (DSS)
   - Specifies binary elliptic curves for cryptography
   
2. **Guide to Elliptic Curve Cryptography** by Hankerson, Menezes, Vanstone
   - Chapter 3: Binary field arithmetic
   - Chapter 13: Elliptic curves over binary fields
   
3. **SEC 2: Recommended Elliptic Curve Domain Parameters**
   - Standards for Efficient Cryptography
   - Defines sect* binary curves
   
4. **IEEE P1363:** Standard Specifications for Public Key Cryptography
   - Includes binary curve specifications

## Comparison with Short Weierstrass

This implementation complements the `elliptic_curve.rs` module which implements Short Weierstrass curves over prime fields. Together, they provide:

- **Prime Fields (p > 3):** Short Weierstrass form y² = x³ + ax + b
- **Binary Fields (F₂ᵐ):** Characteristic-2 form y² + xy = x³ + ax² + b

Both use the same conceptual approach (chord-tangent law) but require different formulas due to the characteristic of the underlying field.

## Future Enhancements

Potential improvements:

1. **Projective Coordinates:** Avoid expensive field inversions
2. **NAF Representation:** Non-adjacent form for scalar multiplication
3. **Point Compression:** Store only x-coordinate and sign bit
4. **Batch Operations:** Simultaneous multiple scalar multiplications
5. **Standard Curves:** Implement specific NIST/SEC2 curves
6. **Point Counting:** Compute curve order using Schoof's algorithm
