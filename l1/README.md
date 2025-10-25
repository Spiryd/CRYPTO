# L1 - Cryptography Learning Library

A Rust library for cryptography education featuring MD5 implementation and GPU compute capabilities.

> ⚠️ **Educational Use Only**: MD5 is cryptographically broken. This library is for learning purposes only.

## Features

- 🔐 **MD5 Hash Function**: Educational implementation of MD5 with detailed documentation
- 🚀 **GPU Compute**: Clean WGPU-based API for GPU-accelerated computation
- 📚 **Well-Documented**: Extensive comments and examples for learning
- ✅ **Comprehensive Tests**: Full test coverage for both MD5 and GPU operations

## Quick Start

### MD5 Hashing

Hash some bytes:
```rust
use l1::{md5, md5_to_hex};

let hash = md5(b"hello");
let hex = md5_to_hex(&hash);
assert_eq!(hex, "5d41402abc4b2a76b9719d911017c592");
```

### GPU Compute

Run computations on the GPU:
```rust
use l1::gpu::{GpuContext, ComputePipeline};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize GPU
    let ctx = GpuContext::new().await?;
    
    // Load shader
    let shader = include_str!("src/gpu/shaders/square.wgsl");
    let pipeline = ComputePipeline::new(&ctx, shader, "main")?;
    
    // Execute computation
    let input = vec![1.0, 2.0, 3.0, 4.0];
    let output = pipeline.execute(&ctx, &input).await?;
    
    println!("Results: {:?}", output); // [1.0, 4.0, 9.0, 16.0]
    Ok(())
}
```

## Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
l1 = { path = "." }
```

## Examples

Run the included examples:
```bash
# GPU compute example
cargo run --example simple_compute

# MD5 examples
cargo run --example demo               # Basic MD5 demonstration
cargo run --example perf_test -r       # Sequential performance
cargo run --example perf_parallel -r   # Parallel performance
```

## Testing

Run all tests:
```bash
# All tests
cargo test

# GPU tests only
cargo test gpu_compute_tests

# MD5 tests only
cargo test md5_tests

# With output
cargo test -- --nocapture
```

## Project Structure

```
l1/
├── src/
│   ├── lib.rs              # Main library entry point
│   ├── gpu/                # GPU compute module
│   │   ├── mod.rs          # Module exports and error types
│   │   ├── context.rs      # GPU context management
│   │   ├── pipeline.rs     # Compute pipeline abstraction
│   │   └── shaders/        # WGSL shaders
│   │       └── square.wgsl # Example square shader
│   └── (MD5 implementation)
├── examples/               # Example programs
│   └── simple_compute.rs   # GPU compute example
├── tests/                  # Integration tests
│   ├── gpu_compute_tests.rs
│   └── md5_tests.rs
└── Cargo.toml
```

## GPU Module

### GpuContext

Manages the WGPU device, queue, and adapter:

```rust
// Create with default settings (high performance)
let ctx = GpuContext::new().await?;

// Create with specific power preference
let ctx = GpuContext::with_options(PowerPreference::LowPower).await?;

// Get GPU info
let info = ctx.adapter_info();
println!("Using: {}", info.name);
```

### ComputePipeline

Execute GPU compute shaders:

```rust
// Create pipeline
let pipeline = ComputePipeline::new(&ctx, shader_source, "main")?;

// Execute with custom workgroup size
let pipeline = ComputePipeline::with_workgroup_size(&ctx, shader, "main", 128)?;

// Run computation
let output = pipeline.execute(&ctx, &input_data).await?;
```

### Writing Custom Shaders

Create WGSL shaders for your computations:

```wgsl
@group(0) @binding(0)
var<storage, read> input: array<f32>;

@group(0) @binding(1)
var<storage, read_write> output: array<f32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let index = global_id.x;
    
    // Your computation here
    output[index] = input[index] * 2.0;
}
```

## MD5 Implementation

### What This Gives You
- Straightforward, commented MD5 rounds (for study)
- Deterministic output matching the reference `md5` crate
- Integration tests covering RFC vectors, edge cases, binary data
- Educational documentation explaining vulnerabilities

### What This Is NOT
- Not constant-time
- Not optimized for production
- Not safe for cryptographic use

## Requirements

- Rust 1.70 or later
- GPU with Vulkan, DirectX 12, or Metal support (for GPU features)
- Windows, macOS, or Linux

## Development

### Building
```bash
cargo build
cargo build --release
```

### Running Benchmarks
```bash
cargo bench
```

### Documentation
```bash
cargo doc --open
```

## References

### MD5
- RFC 1321: The MD5 Message-Digest Algorithm
- Xiaoyun Wang et al. "Collisions for Hash Functions MD4, MD5, HAVAL-128 and RIPEMD" (2004)
- Xiaoyun Wang and Hongbo Yu. "How to Break MD5 and Other Hash Functions" (2005)

### GPU/WGPU
- [WGPU Documentation](https://wgpu.rs/)
- [WebGPU Specification](https://gpuweb.github.io/gpuweb/)
- [Learn WGPU](https://sotrh.github.io/learn-wgpu/)

## License

Educational use only. See LICENSE file for details.

## Contributing

This is an educational project. Contributions that improve clarity, add educational value, or fix bugs are welcome.
