# MD5 (Educational Implementation)

Minimal Rust implementation of MD5 for learning and experimentation only.

> ⚠️ MD5 is broken. Do not use this for passwords, signatures, integrity, or anything security‑relevant.

## Quick Start

Hash some bytes:
```rust
use l1::md5;
let h = md5(b"hello");
assert_eq!(h, "5d41402abc4b2a76b9719d911017c592");
```

Run demo:
```bash
cargo run
```

Run tests (includes comparison against a reference implementation):
```bash
cargo test
cargo test comparison_tests
```

## What This Gives You
- Straightforward, commented MD5 rounds (for study)
- Deterministic output matching the popular `md5` crate
- Integration tests covering RFC vectors, edge cases, binary data

## What This Is NOT
- Not constant‑time
- Not optimized
- Not safe for production or cryptographic use

## Reference
- RFC 1321
- Wang et al. (2004/2005) collision papers
