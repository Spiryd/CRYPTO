# L1 - Cryptography Learning Library

Educational Rust implementations of MD5 and GPU compute.

> ⚠️ **Educational Only**: MD5 is cryptographically broken.

## Features

- MD5 hash function with collision verification
- GPU compute using WGPU
- Wang et al. collision examples

## Usage

### MD5
```rust
use l1::{md5, md5_to_hex};

let hash = md5(b"hello");
assert_eq!(md5_to_hex(&hash), "5d41402abc4b2a76b9719d911017c592");
```

### GPU Compute
```rust
use l1::gpu::{GpuContext, ComputePipeline};

let ctx = GpuContext::new().await?;
let shader = include_str!("shader.wgsl");
let pipeline = ComputePipeline::new(&ctx, shader, "main")?;
let output = pipeline.execute(&ctx, &[1.0, 2.0, 3.0]).await?;
```

## Examples

```bash
cargo run --example verify_wang_collision  # MD5 collision verification
cargo run --example simple_compute         # GPU compute demo
cargo test                                 # Run tests
cargo bench                                # Run benchmarks
```

## Structure

```
src/
├── md5/        # MD5 implementation
├── gpu/        # GPU compute
└── collision/  # Collision verification
examples/       # Example programs
tests/          # Tests
benches/        # Benchmarks
```

## References

- RFC 1321: MD5 Message-Digest Algorithm
- Wang et al. "How to Break MD5 and Other Hash Functions" (2005)
- [WGPU Documentation](https://wgpu.rs/)
