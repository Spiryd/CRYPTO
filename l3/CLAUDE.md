# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build the project
cargo build

# Build with optimizations (recommended for crypto operations)
cargo build --release

# Run all tests
cargo test

# Run a specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run the main binary (API challenge test runner)
cargo run --release

# Run examples
cargo run --example field_basics
cargo run --example elliptic_curves
cargo run --example ghash
```

## Architecture Overview

This is a finite field arithmetic library supporting cryptographic operations. The key architectural layers are:

### Core Types

- **`BigInt<N>`** (`src/bigint.rs`): Generic big integer with N 64-bit limbs. Uses little-endian limb ordering internally. Common alias: `BigInt256` = `BigInt<4>` for 256-bit integers.

- **`MontgomeryCtx<N>`** (`src/montgomery.rs`): Montgomery modular arithmetic context for efficient modular multiplication and exponentiation. Requires odd modulus.

### Field Implementations (`src/field/`)

All field types implement the `FieldElement` trait (`src/field_trait.rs`) which defines: `zero()`, `one()`, `is_zero()`, `inverse()`, `pow()`, and arithmetic operators.

- **`PrimeField<C, N>`** (`src/field/prime.rs`): Prime field F_p for k=1 case
- **`ExtensionField<C, N, K>`** (`src/field/extension.rs`): Extension field F_p^k with polynomial arithmetic
- **`BinaryField<C, N, K>`** (`src/field/binary.rs`): Binary field F_2^k using XOR-based arithmetic

Fields are configured via the `FieldConfig<N>` trait which provides `modulus()` and `irreducible()` polynomial coefficients.

### Elliptic Curves (`src/elliptic_curve.rs`)

- **`EllipticCurve<F>`**: Short Weierstrass form (y² = x³ + ax + b) for characteristic > 3
- **`BinaryEllipticCurve<F>`**: Characteristic-2 form (y² + xy = x³ + ax² + b)
- **`Point<F>`**: Enum with `Infinity` and `Affine { x, y }` variants

### Cryptographic Protocols

- **`diffie_hellman.rs`**: DH key exchange for F_p, F_2^k, F_p^k, and elliptic curves
- **`schnorr.rs`**: Schnorr signatures using SHA256, with `SchnorrField` and `SchnorrEC` traits
- **`ghash.rs`**: GHASH algorithm for GF(2^128) authentication (AES-GCM)

### API Client (`src/api/`)

Client for `crypto25.random-oracle.xyz` challenge service. The main binary (`src/main.rs`) runs test challenges against this API for 6 challenge types: ModP, F2m, Fpk, ECP, EC2m, ECPk.

Module structure:
- **`client.rs`**: `CryptoApiClient` HTTP client with cached parameter fetching
- **`types.rs`**: Request/response data structures (params, points, signatures)
- **`error.rs`**: `ApiError` type
- **`helpers.rs`**: Hex encoding, BigInt padding, random generation utilities
- **`test_runner.rs`**: `ChallengeTestRunner` with DH and Schnorr implementations for all field types

## Security Notes

- Exponentiation uses Montgomery ladder for constant-time execution
- Scalar multiplication uses double-and-add (note: not constant-time)
- Never reuse nonces in Schnorr signatures
