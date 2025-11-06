# MD5 Cryptanalysis

GPU-accelerated Wang's MD5 collision attack in Rust/WGPU.

**Educational Only** - MD5 is cryptographically broken.

## Tasks

**Task 1: MD5 Implementation**
- Pure Rust MD5 (RFC 1321)
- Custom IV support
- `cargo run --example demo`

**Task 2: Known Collision Verification**
- Wang's collision constants
- `cargo run --release --example verify_known_collisions`

**Task 3: Phase 2 GPU Collision Search**
- GPU-accelerated search (WGPU/WGSL)
- Wang's differential path
- `cargo run --release --example test_phase2`

## Quick Start

```bash
# Run all tests
cargo test

# Build and run
cargo build --release
cargo run --release --example test_phase2
```

## Structure

```
src/
├── md5/mod.rs                  # Task 1: MD5 algorithm
├── collision.rs                # Task 2 & 3: Collision search
└── gpu/shaders/collision_search.wgsl  # Task 3: GPU shader

examples/
├── demo.rs                     # Task 1 demo
├── verify_known_collisions.rs # Task 2
└── test_phase2.rs              # Task 3
```

## Status

✅ Task 1: Complete (16 tests)  
✅ Task 2: Complete (10 tests)  
✅ Task 3: :<


## References

- Wang et al. (2005) - "How to Break MD5 and Other Hash Functions"
- RFC 1321 - MD5 Message-Digest Algorithm
- WGPU - https://wgpu.rs/
