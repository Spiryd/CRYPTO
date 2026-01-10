# L3 - Finite Field Arithmetic Library

A Rust library for finite field arithmetic supporting prime fields (F_p), extension fields (F_p^k), and binary fields (F_2^k) with elliptic curve support and GHASH implementation.

## Features

- ✅ **Generic F_p^k Structure**: Configurable prime and irreducible polynomial
- ✅ **All Field Operations**: Addition, subtraction, multiplication, division, inverse, negation
- ✅ **Efficient Exponentiation**: O(log n) binary method
- ✅ **Big Integer Support**: 256, 512, 1024+ bit elements
- ✅ **Specialized Implementations**:
  - `PrimeField` for k=1 (optimized prime fields)
  - `BinaryField` for p=2 (XOR-based bit string arithmetic)
- ✅ **Elliptic Curves**: Short Weierstrass and binary field curves
- ✅ **GHASH Algorithm**: GF(2^128) authentication for AES-GCM

## Project Structure

```
src/
├── lib.rs              # Library entry point
├── main.rs             # Simple binary showing how to use the library
├── bigint.rs           # Big integer arithmetic
├── field_trait.rs      # Generic field operations trait
├── field/
│   ├── mod.rs          # Field module exports
│   ├── config.rs       # Field configuration trait
│   ├── prime.rs        # Prime field implementation (F_p)
│   ├── extension.rs    # Extension field implementation (F_p^k)
│   └── binary.rs       # Binary field implementation (F_2^k)
├── elliptic_curve.rs   # Elliptic curve groups
└── ghash.rs            # GHASH algorithm for GCM/GMAC

examples/
├── field_basics.rs         # Creating and using fields
├── field_operations.rs     # All 6 field operations
├── exponentiation.rs       # Efficient O(log n) exponentiation
├── big_integers.rs         # Working with large fields
├── specialized_fields.rs   # PrimeField and BinaryField
├── elliptic_curves.rs      # Elliptic curve cryptography
└── ghash.rs                # GHASH authentication
```

## Usage

### As a Library

Add to your `Cargo.toml`:
```toml
[dependencies]
l3 = { path = "path/to/l3" }
```

Then use in your code:
```rust
use l3::bigint::BigInt;
use l3::field::{FieldConfig, PrimeField};
use l3::field_trait::FieldElement;

// Define a field configuration
#[derive(Clone, Debug)]
struct F101;

static F101_MOD: BigInt<4> = BigInt::from_u64(101);

impl FieldConfig<4> for F101 {
    fn modulus() -> &'static BigInt<4> {
        &F101_MOD
    }
    fn irreducible() -> &'static [BigInt<4>] {
        &[]
    }
}

type F101Field = PrimeField<F101, 4>;

// Use the field
let a = F101Field::from_u64(45);
let b = F101Field::from_u64(67);
let sum = a + b;
let product = a * b;
let inverse = a.inverse();
```

### Running Examples

The library includes comprehensive examples demonstrating all features:

```bash
# Field basics - prime and extension fields
cargo run --example field_basics

# All field operations
cargo run --example field_operations

# O(log n) exponentiation
cargo run --example exponentiation

# Big integer support
cargo run --example big_integers

# Specialized field implementations
cargo run --example specialized_fields

# Elliptic curve cryptography
cargo run --example elliptic_curves

# GHASH algorithm
cargo run --example ghash
```

## Examples

### Prime Field (F_p)

```rust
use l3::field::PrimeField;

// Work in F_97
let a = F97::from_u64(50);
let b = F97::from_u64(60);
let sum = a + b;  // 13 (mod 97)
```

### Extension Field (F_p^k)

```rust
use l3::field::ExtensionField;

// F_5^2 with irreducible x² + x + 2
let a = F25::from_coeffs([3, 2]);  // 3 + 2x
let b = F25::from_coeffs([1, 4]);  // 1 + 4x
let product = a * b;  // Reduced modulo irreducible
```

### Binary Field (F_2^k)

```rust
use l3::field::BinaryField;

// GF(2^4) with bit strings
let a = GF16::from_u64(0b1010);  // x³ + x
let b = GF16::from_u64(0b1100);  // x³ + x²
let sum = a + b;  // XOR operation
```

### Elliptic Curves

```rust
use l3::elliptic_curve::EllipticCurve;

// Curve: y² = x³ + 2x + 3 over F_97
let curve = EllipticCurve::new(a, b);
let p = curve.point(x, y);

// Scalar multiplication (O(log k))
let result = curve.scalar_mul(&p, &[100]);
```

### GHASH

```rust
use l3::ghash::{ghash, bytes_to_gf128, gf128_to_bytes};

let h = bytes_to_gf128(&hash_key);
let tag = ghash(h, aad, ciphertext);
let tag_bytes = gf128_to_bytes(&tag);
```

## Testing

Run all tests:
```bash
cargo test
```

All 56 unit tests pass:
- 13 BigInt tests
- 13 FieldElement trait tests  
- 5 PrimeField tests
- 8 BinaryField tests
- 11 EllipticCurve tests
- 6 GHASH tests

## Performance

- **Addition/Subtraction**: O(1) for prime fields, O(1) XOR for binary fields
- **Multiplication**: O(k²) for extension fields
- **Inversion**: O(k³) using Fermat's Little Theorem
- **Exponentiation**: O(log n) using binary method
- **Scalar Multiplication**: O(log k) double-and-add for elliptic curves

## Documentation

See the individual example files for detailed demonstrations:
- [field_basics.rs](examples/field_basics.rs) - Getting started with fields
- [field_operations.rs](examples/field_operations.rs) - All 6 operations
- [exponentiation.rs](examples/exponentiation.rs) - Efficient exponentiation
- [big_integers.rs](examples/big_integers.rs) - Large field elements
- [specialized_fields.rs](examples/specialized_fields.rs) - PrimeField & BinaryField
- [elliptic_curves.rs](examples/elliptic_curves.rs) - Elliptic curve groups
- [ghash.rs](examples/ghash.rs) - GHASH authentication

Also see:
- [GHASH_README.md](GHASH_README.md) - Detailed GHASH documentation
- [GHASH_QUICK_REFERENCE.md](GHASH_QUICK_REFERENCE.md) - GHASH quick reference

## License

This is educational code for cryptographic algorithm implementation.
