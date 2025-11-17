# Finite Field Cryptography Library

A comprehensive Rust implementation of finite field arithmetic for public-key cryptography, supporting arbitrary field sizes including cryptographic standards (256, 512, 1024+ bits).

## Overview

This library implements the basic building blocks for public-key cryptography:

- **Base Fields (Fp)**: Prime fields with efficient modular arithmetic
- **Extension Fields (Fp^k)**: Polynomial rings over Fp modulo an irreducible polynomial
- **Binary Fields (F2^k)**: Optimized fields of characteristic 2 using bit string representation
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
├── main.rs              # Examples and demonstrations
├── bigint.rs            # Big integer arithmetic
├── field.rs             # Base field Fp and Field trait
├── polynomial.rs        # Polynomial arithmetic over fields
├── extension_field.rs   # Extension field Fp^k
└── binary_field.rs      # Binary field F2^k
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

## Tests

Comprehensive test suite covering:

- Basic arithmetic operations
- Modular operations
- Inverse computation
- Exponentiation efficiency
- Field-specific edge cases
- 256-bit field operations

Run tests with: `cargo test`

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
