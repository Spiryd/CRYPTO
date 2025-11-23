# Finite Field Cryptography Library

A comprehensive Rust implementation of finite field arithmetic and elliptic curve groups for public-key cryptography, supporting arbitrary field sizes including cryptographic standards (256, 512, 1024+ bits).

## Overview

This library implements the fundamental building blocks for public-key cryptography:

- **Base Fields (Fp)**: Prime fields with efficient modular arithmetic
- **Extension Fields (Fp^k)**: Polynomial rings over Fp modulo an irreducible polynomial
- **Binary Fields (F2^k)**: Optimized fields of characteristic 2 using bit string representation
- **Elliptic Curves (Prime Fields)**: Group operations using Short Weierstrass form (y² = x³ + ax + b)
- **Elliptic Curves (Binary Fields)**: Group operations using characteristic-2 form (y² + xy = x³ + ax² + b)
- **Big Integer Arithmetic**: Support for 256, 512, 1024+ bit operations

## Features

### 1. Big Integer Arithmetic (`bigint.rs`)

Configurable-size unsigned integers supporting:
- Addition, subtraction, multiplication, division
- Modular operations (add_mod, mul_mod, pow_mod, inv_mod)
- Bitwise operations (shift, AND, OR, XOR)
- Support for 256, 512, 1024+ bit elements
- Little-endian word storage for efficiency

### 2. Prime Field Fp (`field.rs`)

The k=1 case - arithmetic in finite fields of prime order:

```rust
let p = BigUint::from_u64(17);
let a = FieldElement::from_u64(5, p.clone());
let b = FieldElement::from_u64(12, p.clone());

// All basic operations
let sum = &a + &b;           // Addition
let neg = -&a;               // Negation
let diff = &a - &b;          // Subtraction (a + (-b))
let prod = &a * &b;          // Multiplication
let inv = a.inv().unwrap();  // Multiplicative inverse
let quot = (&a / &b).unwrap(); // Division (a * b^(-1))

// Efficient exponentiation: O(log exp) using square-and-multiply
let power = a.pow(&BigUint::from_u64(1000000));
```

### 3. Extension Fields Fp^k (`extension_field.rs`)

Fields as polynomial rings Fp[X] / (f(X)) where f is irreducible of degree k:

```rust
// F_{7^2} with irreducible polynomial X^2 + 1
let p = BigUint::from_u64(7);
let irreducible = Polynomial::new(vec![
    FieldElement::from_u64(1, p.clone()),  // constant
    FieldElement::from_u64(0, p.clone()),  // X
    FieldElement::from_u64(1, p.clone()),  // X^2
]);

let a = ExtensionFieldElement::from_coeffs(vec![2, 3], irreducible.clone(), p.clone());
let b = ExtensionFieldElement::from_coeffs(vec![4, 5], irreducible.clone(), p.clone());

let sum = &a + &b;
let prod = &a * &b;
let inv = a.inv().unwrap();
let power = a.pow(&BigUint::from_u64(100));
```

### 4. Binary Fields F2^k (`binary_field.rs`)

Optimized implementation for characteristic 2 using bit strings:

```rust
// F_{2^8} with AES irreducible polynomial: X^8 + X^4 + X^3 + X + 1
let irreducible = vec![0b00011011, 0b00000001]; // Little-endian
let degree = 8;

let a = BinaryFieldElement::from_u64(0x53, irreducible.clone(), degree);
let b = BinaryFieldElement::from_u64(0xCA, irreducible.clone(), degree);

let sum = &a + &b;  // XOR in binary fields
let prod = &a * &b; // Polynomial multiplication mod irreducible
let inv = a.inv().unwrap();
```

**Note**: Binary fields use little-endian bit ordering (LSB first in first byte) as per standard practice for bit strings.

### 5. Elliptic Curve Groups over Prime Fields (`elliptic_curve.rs`)

Elliptic curves over finite fields using Short Weierstrass form: **y² = x³ + ax + b**

```rust
// Curve y² = x³ + 2x + 2 over F₁₇
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

// Point operations using Chord-Tangent Law
let p2 = curve.point(...);
let sum = curve.add(&p1, &p2);        // Point addition (Chord)
let doubled = curve.double(&p1);      // Point doubling (Tangent)
let negated = curve.negate(&p1);      // Point negation
let identity = curve.infinity();      // Point at infinity

// Efficient scalar multiplication: O(log n)
let k = BigUint::from_u64(12345);
let result = curve.scalar_mul(&k, &p1);  // k·P using double-and-add
```

**Key Features:**
- **Generic over field types**: Works with Fp, Fp^k, F2^k
- **Chord-Tangent Law**: Proper group operations with geometric interpretation
- **Point at infinity**: Correct identity element handling
- **Efficient scalar multiplication**: O(log n) double-and-add algorithm
- **Group law verification**: All group properties tested and verified

See [ELLIPTIC_CURVES.md](ELLIPTIC_CURVES.md) for detailed documentation.

### 6. Elliptic Curve Groups over Binary Fields (`binary_elliptic_curve.rs`)

Binary elliptic curves using characteristic-2 Weierstrass form: **y² + xy = x³ + ax² + b**

```rust
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

// Point operations (using characteristic-2 formulas)
let doubled = curve.double(&p);       // Point doubling
let sum = curve.add(&p, &doubled);    // Point addition
let negated = curve.negate(&p);       // -P = (x, x + y)
let scalar = curve.scalar_mul(5, &p); // 5·P using double-and-add
```

**Key Features:**
- **Characteristic-2 specific formulas**: Different from Short Weierstrass
- **NIST standard curves**: Compatible with B-163, B-233, B-283, etc.
- **Hardware efficient**: Binary operations (XOR) are simple in circuits
- **Constant-time operations**: Easier to implement side-channel resistant code

**Why different?** In characteristic-2 fields, 2 ≡ 0, so division by 2 is undefined. The curve equation y² + xy = x³ + ax² + b avoids this issue with modified point addition formulas.

See [BINARY_ELLIPTIC_CURVES.md](BINARY_ELLIPTIC_CURVES.md) for detailed documentation.

## Implementation Details

### Efficient Exponentiation

All field types implement O(log exp) exponentiation using the square-and-multiply algorithm:

```rust
fn pow(&self, exp: &BigUint) -> Self {
    let mut result = Self::one();
    let mut base = self.clone();
    let mut e = exp.clone();
    
    while !e.is_zero() {
        if e.get_bit(0) {
            result = result.mul(&base);
        }
        base = base.mul(&base);
        e = &e >> 1;
    }
    result
}
```

This ensures that even very large exponents (e.g., 2^256) can be computed efficiently.

### Field Operations

All field types implement the `Field` trait:

```rust
pub trait Field {
    fn add(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn inv(&self) -> Option<Self>;
    fn div(&self, other: &Self) -> Option<Self>;
    fn pow(&self, exp: &BigUint) -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;
}
```

### Inverse Computation

- **Prime fields**: Extended Euclidean Algorithm
- **Extension fields**: Polynomial Extended GCD
- **Binary fields**: Extended GCD in F2[X] using XOR for subtraction

## Byte Order Conventions

Following cryptographic standards:

- **Big Integers**: Big-endian for display/input (most significant digit first)
- **Internal Storage**: Little-endian words for efficiency
- **Binary Fields**: Little-endian bit ordering (first bit of first byte = bit 0)

## Cryptographic Sizes

The implementation supports:

- **256 bits**: Standard for elliptic curve cryptography (e.g., secp256k1)
- **512 bits**: Enhanced security applications
- **1024+ bits**: RSA-level security
- **Arbitrary sizes**: Compile-time configurable

Example with 256-bit field:

```rust
let p_256_bytes = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").unwrap();
let p_256 = BigUint::from_bytes_be(&p_256_bytes);
let a = FieldElement::from_u64(12345, p_256.clone());
let large_exp = BigUint::from_u64(1_000_000);
let power = a.pow(&large_exp); // Efficient!
```

## Module Structure

```
src/
├── main.rs                    # Examples and demonstrations
├── bigint.rs                  # Big integer arithmetic
├── field.rs                   # Base field Fp and Field trait
├── polynomial.rs              # Polynomial arithmetic over fields
├── extension_field.rs         # Extension field Fp^k
├── binary_field.rs            # Binary field F2^k
├── elliptic_curve.rs          # Elliptic curves (Short Weierstrass)
└── binary_elliptic_curve.rs   # Binary elliptic curves (Characteristic-2)
```

## Building and Running

```bash
# Build the project
cargo build

# Run examples
cargo run

# Run tests
cargo test

# Run with optimizations
cargo run --release
```

## Examples Output

The main program demonstrates:

1. **Base Field Operations**: Arithmetic in F_17
2. **Extension Field Operations**: Arithmetic in F_{7^2}
3. **Binary Field Operations**: Arithmetic in F_{2^8} (AES field)
4. **Large Field Operations**: 256-bit prime field operations
5. **Elliptic Curve Groups (Prime Fields)**: Chord-Tangent Law operations, scalar multiplication
6. **Elliptic Curve Groups (Binary Fields)**: Characteristic-2 operations, group properties

## Tests

Comprehensive test suite covering:

- Basic arithmetic operations
- Modular operations
- Inverse computation
- Exponentiation efficiency
- Field-specific edge cases
- 256-bit field operations
- **Elliptic curve point operations (prime fields)**
- **Elliptic curve group laws (prime fields)**
- **Efficient scalar multiplication (prime fields)**
- **Binary elliptic curve operations (F₂ᵐ)**
- **Binary curve group laws and properties**

Run tests with: `cargo test`

**Test Results**: 31/31 tests passing ✓
- 14 field arithmetic tests
- 8 Short Weierstrass elliptic curve tests
- 9 binary elliptic curve tests

## Performance Characteristics

- **Addition/Subtraction**: O(n) where n = number of words
- **Multiplication**: O(n²) using schoolbook multiplication
- **Division**: O(n²) using long division
- **Modular Operations**: O(n²)
- **Exponentiation**: O(log exp) multiplications
- **Inverse**: O(n²) using Extended Euclidean Algorithm

## Future Enhancements

Potential optimizations:
- Karatsuba multiplication for large numbers
- Montgomery multiplication for repeated modular operations
- Precomputed lookup tables for binary field multiplication
- Parallel processing for independent operations
- SIMD optimizations for bit operations

## License

Educational implementation for cryptography coursework.
