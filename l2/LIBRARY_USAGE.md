# Using L2 as a Library

The `l2` crate can now be used both as a library and as a standalone binary.

## Library Structure

- **Library name**: `l2`
- **Binary name**: `l2-demo` (demo/CLI tool)

## Using as a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
l2 = { path = "../l2" }
```

Or from a git repository:

```toml
[dependencies]
l2 = { git = "https://github.com/yourusername/l2" }
```

## Example Usage

```rust
use l2::{BigUint, Field, FieldElement, EllipticCurve, EllipticCurvePoint};

fn main() {
    // Create a prime field F_17
    let p = BigUint::from_u64(17);
    let a = FieldElement::from_u64(5, p.clone());
    let b = FieldElement::from_u64(12, p.clone());

    // Field arithmetic
    let sum = &a + &b;
    let product = &a * &b;
    let inverse = a.inv().unwrap();
    
    println!("5 + 12 = {} (mod 17)", sum.value);
    println!("5 * 12 = {} (mod 17)", product.value);
    println!("5^(-1) = {} (mod 17)", inverse.value);

    // Elliptic curve operations
    let curve = EllipticCurve::new(
        BigUint::from_u64(2),  // a
        BigUint::from_u64(3),  // b
        BigUint::from_u64(97)  // p
    );

    let x = FieldElement::from_u64(3, BigUint::from_u64(97));
    let y = FieldElement::from_u64(6, BigUint::from_u64(97));
    
    let point = EllipticCurvePoint::Point { x, y };
    
    if curve.is_on_curve(&point) {
        println!("Point is on the curve!");
    }
}
```

## Available Modules

All modules are publicly exported:

- **`l2::bigint`** - Arbitrary precision unsigned integers
- **`l2::field`** - Prime field arithmetic (𝔽_p)
- **`l2::polynomial`** - Polynomial operations over fields
- **`l2::extension_field`** - Extension field arithmetic (𝔽_p^k)
- **`l2::binary_field`** - Binary field arithmetic (𝔽₂ᵐ)
- **`l2::elliptic_curve`** - Elliptic curves over prime fields
- **`l2::binary_elliptic_curve`** - Elliptic curves over binary fields
- **`l2::serialization`** - Serialization and deserialization utilities

## Re-exported Types

For convenience, commonly used types are re-exported at the crate root:

```rust
// Core types
use l2::{BigUint, Field, FieldElement};

// Polynomial types
use l2::{Polynomial, ExtensionFieldElement};

// Binary field types
use l2::BinaryFieldElement;

// Elliptic curve types
use l2::{EllipticCurve, EllipticCurvePoint};
use l2::{BinaryEllipticCurve, BinaryEllipticCurvePoint};

// Serialization types
use l2::{
    SerializableFieldElement,
    SerializableBinaryFieldElement,
    SerializableExtensionFieldElement,
    SerializableECPoint,
    SerializableBinaryECPoint,
    SerializableEllipticCurve,
    SerializableBinaryEllipticCurve,
};
```

## Running the Demo Binary

To run the included demo application:

```bash
cargo run --bin l2-demo
```

## Building

```bash
# Build library only
cargo build --lib

# Build binary only
cargo build --bin l2-demo

# Build everything
cargo build

# Run tests
cargo test

# Run doctests
cargo test --doc
```

## Test Results

- **Library tests**: 34 passing unit tests
- **Binary tests**: 5 passing unit tests  
- **Doc tests**: 1 passing documentation example
- **Total**: 40 tests, all passing ✅
