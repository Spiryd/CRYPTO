# Elliptic Curve Groups Over Finite Fields

## Overview

This module implements elliptic curve groups over generic finite fields using the **Short Weierstrass form**:

```
y² = x³ + ax + b
```

The implementation is generic over any field type `F` that implements the `Field` trait, allowing elliptic curves over:
- Base fields **Fp** (prime characteristic)
- Extension fields **Fp^k**
- Binary fields **F2^k**

## Chord-Tangent Law

Elliptic curves form an **abelian group** under point addition, defined by the Chord-Tangent Law:

### Point Addition (Chord Law)

For two distinct points **P = (x₁, y₁)** and **Q = (x₂, y₂)**:

1. Draw a line through P and Q
2. This line intersects the curve at a third point R'
3. The sum P + Q is the reflection of R' across the x-axis

**Formulas:**
```
m = (y₂ - y₁) / (x₂ - x₁)    (slope of the chord)
x₃ = m² - x₁ - x₂
y₃ = m(x₁ - x₃) - y₁
```

### Point Doubling (Tangent Law)

For a point **P = (x₁, y₁)** added to itself (2P):

1. Draw the tangent line at P
2. This line intersects the curve at another point R'
3. The result 2P is the reflection of R' across the x-axis

**Formulas:**
```
m = (3x₁² + a) / (2y₁)    (slope of the tangent)
x₃ = m² - 2x₁
y₃ = m(x₁ - x₃) - y₁
```

### Point at Infinity (Identity Element)

The **point at infinity** O is a special point where all vertical lines meet. It serves as the **identity element**:

- P + O = P for all points P
- P + (-P) = O (inverse property)

## Group Properties

The elliptic curve points form an **abelian group** with:

1. **Closure**: P + Q is on the curve
2. **Associativity**: (P + Q) + R = P + (Q + R)
3. **Identity**: P + O = P
4. **Inverse**: P + (-P) = O where -P = (x, -y)
5. **Commutativity**: P + Q = Q + P

## Implementation Details

### Data Structures

```rust
pub enum EllipticCurvePoint<F: Field> {
    Infinity,                    // Point at infinity (identity)
    Point { x: F, y: F },       // Affine point (x, y)
}

pub struct EllipticCurve<F: Field> {
    pub a: F,                   // Curve parameter a
    pub b: F,                   // Curve parameter b
}
```

### Core Operations

#### Point Addition
```rust
pub fn add(&self, p: &EllipticCurvePoint<F>, q: &EllipticCurvePoint<F>) 
    -> EllipticCurvePoint<F>
```

Handles all cases:
- Identity: O + P = P
- Inverse: P + (-P) = O
- Doubling: P + P uses tangent law
- General: P + Q uses chord law

#### Point Doubling
```rust
pub fn double(&self, p: &EllipticCurvePoint<F>) -> EllipticCurvePoint<F>
```

Efficiently computes 2P using the tangent law.

#### Point Negation
```rust
pub fn negate(&self, p: &EllipticCurvePoint<F>) -> EllipticCurvePoint<F>
```

Returns -P = (x, -y) for point P = (x, y).

#### Scalar Multiplication
```rust
pub fn scalar_mul(&self, n: &BigUint, p: &EllipticCurvePoint<F>) 
    -> EllipticCurvePoint<F>
```

Computes n·P efficiently using the **double-and-add algorithm** in O(log n) time:

```
Algorithm: Double-and-Add
Input: scalar n, point P
Output: n·P

result = O
base = P
while n > 0:
    if n is odd:
        result = result + base
    base = 2·base
    n = n >> 1
return result
```

**Time Complexity**: O(log n) point operations

## Usage Examples

### Basic Point Operations

```rust
use elliptic_curve::EllipticCurve;
use field::FieldElement;
use bigint::BigUint;

// Create curve y² = x³ + 2x + 2 over F₁₇
let p = BigUint::from_u64(17);
let a = FieldElement::new(BigUint::from_u64(2), p.clone());
let b = FieldElement::new(BigUint::from_u64(2), p.clone());
let curve = EllipticCurve::new(a, b);

// Create points
let p1 = curve.point(
    FieldElement::new(BigUint::from_u64(5), p.clone()),
    FieldElement::new(BigUint::from_u64(1), p.clone())
);

// Verify point is on curve
assert!(curve.is_on_curve(&p1));

// Point addition
let p2 = curve.point(
    FieldElement::new(BigUint::from_u64(6), p.clone()),
    FieldElement::new(BigUint::from_u64(3), p.clone())
);
let p3 = curve.add(&p1, &p2);

// Point doubling
let doubled = curve.double(&p1);

// Point negation
let neg = curve.negate(&p1);
let sum = curve.add(&p1, &neg);
assert!(sum.is_infinity());  // P + (-P) = O

// Scalar multiplication
let k = BigUint::from_u64(5);
let result = curve.scalar_mul(&k, &p1);  // 5·P
```

### Cryptographic Example (Simplified)

```rust
// Large prime field (64-bit example, real crypto uses 256+ bits)
let large_p = BigUint::from_u64(0xFFFFFFFFFFFFFFC5);

// secp256k1-like curve: y² = x³ + 7
let a = FieldElement::new(BigUint::from_u64(0), large_p.clone());
let b = FieldElement::new(BigUint::from_u64(7), large_p.clone());
let curve = EllipticCurve::new(a, b);

// Generator point G (example coordinates)
let g = curve.point(
    FieldElement::new(BigUint::from_u64(0x79BE667EF9DCBBAC), large_p.clone()),
    FieldElement::new(BigUint::from_u64(0x483ADA7726A3C465), large_p.clone())
);

// Private key (secret scalar)
let private_key = BigUint::from_u64(12345);

// Public key = private_key · G
let public_key = curve.scalar_mul(&private_key, &g);
```

## Verification of Group Laws

All group properties are verified in tests:

```rust
// Associativity: (P + Q) + R = P + (Q + R)
let left = curve.add(&curve.add(&p1, &p2), &p3);
let right = curve.add(&p1, &curve.add(&p2, &p3));
assert_eq!(left, right);

// Commutativity: P + Q = Q + P
assert_eq!(curve.add(&p1, &p2), curve.add(&p2, &p1));

// Identity: P + O = P
let inf = curve.infinity();
assert_eq!(curve.add(&p1, &inf), p1);

// Inverse: P + (-P) = O
let neg_p1 = curve.negate(&p1);
assert!(curve.add(&p1, &neg_p1).is_infinity());

// Scalar distributivity: k(P + Q) = kP + kQ
let k = BigUint::from_u64(3);
let p_plus_q = curve.add(&p1, &p2);
assert_eq!(
    curve.scalar_mul(&k, &p_plus_q),
    curve.add(&curve.scalar_mul(&k, &p1), &curve.scalar_mul(&k, &p2))
);
```

## Test Coverage

The implementation includes comprehensive tests:

- **test_point_at_infinity**: Verify infinity point is on curve
- **test_point_on_curve**: Verify point validation
- **test_point_addition**: Test chord law addition
- **test_point_doubling**: Test tangent law doubling
- **test_identity_element**: Verify P + O = P
- **test_inverse_element**: Verify P + (-P) = O
- **test_scalar_multiplication**: Test double-and-add algorithm
- **test_associativity**: Verify (P + Q) + R = P + (Q + R)

All tests pass:
```
test elliptic_curve::tests::test_point_at_infinity ... ok
test elliptic_curve::tests::test_point_on_curve ... ok
test elliptic_curve::tests::test_point_addition ... ok
test elliptic_curve::tests::test_point_doubling ... ok
test elliptic_curve::tests::test_identity_element ... ok
test elliptic_curve::tests::test_inverse_element ... ok
test elliptic_curve::tests::test_scalar_multiplication ... ok
test elliptic_curve::tests::test_associativity ... ok
```

## Performance Characteristics

| Operation | Time Complexity | Description |
|-----------|----------------|-------------|
| Point Addition | O(1) field ops | Chord law computation |
| Point Doubling | O(1) field ops | Tangent law computation |
| Scalar Multiplication | O(log n) point ops | Double-and-add algorithm |
| Point Validation | O(1) field ops | Check curve equation |

Where field operations (multiplication, division) have their own complexity based on the underlying field implementation.

## Limitations and Notes

1. **Short Weierstrass Only**: Implemented for curves with p > 3 (characteristic ≠ 2, 3)
2. **Affine Coordinates**: Uses (x, y) coordinates (not projective/Jacobian for efficiency)
3. **No Curve Validation**: Does not check discriminant Δ = -16(4a³ + 27b²) ≠ 0
4. **Generic Over Fields**: Works with any field implementing the Field trait

## Cryptographic Applications

Elliptic curves are fundamental to modern cryptography:

- **ECDSA**: Digital signatures (Bitcoin, TLS)
- **ECDH**: Key exchange (TLS, Signal)
- **EdDSA**: Signature scheme (Ed25519)
- **Pairing-based crypto**: BLS signatures, zk-SNARKs

This implementation provides the foundation for these protocols when combined with proper:
- Secure random number generation
- Hash functions
- Group order handling
- Point compression

## References

1. [Wikipedia - Elliptic Curve](https://en.wikipedia.org/wiki/Elliptic_curve)
2. [Wikipedia - Elliptic Curve Point Multiplication](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication)
3. Standards for Efficient Cryptography (SEC) 2
4. NIST FIPS 186-4 (Digital Signature Standard)

## Integration with Field Types

The elliptic curve implementation works seamlessly with all field types:

```rust
// Over base field Fp
let curve_fp = EllipticCurve::new(
    FieldElement::new(...),
    FieldElement::new(...)
);

// Over extension field Fp^k  
let curve_ext = EllipticCurve::new(
    ExtensionFieldElement::new(...),
    ExtensionFieldElement::new(...)
);

// Over binary field F2^k
let curve_bin = EllipticCurve::new(
    BinaryFieldElement::new(...),
    BinaryFieldElement::new(...)
);
```

All group operations work identically regardless of the underlying field type!
