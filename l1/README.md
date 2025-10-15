# MD5 (Educational Implementation)

Minimal Rust implementation of MD5 for learning and experimentation only.

> ⚠️ MD5 is broken. Do not use this for passwords, signatures, integrity, or anything security‑relevant.

## Quick Start

Hash some bytes:
```rust
use l1::{md5, md5_to_hex};
let hash = md5(b"hello");
let hex = md5_to_hex(&hash);
assert_eq!(hex, "5d41402abc4b2a76b9719d911017c592");
```

Run examples:
```bash
cargo run --example demo               # Basic MD5 demonstration
cargo run --example perf_test -r       # Sequential performance analysis
cargo run --example perf_parallel -r   # Parallel performance (Rayon)
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
