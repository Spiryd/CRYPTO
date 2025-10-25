//! Simple compute shader that squares numbers
//!
//! This shader demonstrates basic GPU compute operations.
//! It takes an array of floating-point numbers and squares each one.
//!
//! Workgroup size: 64 threads per workgroup
//! This is a good default for most GPUs.

@group(0) @binding(0)
var<storage, read> input: array<f32>;

@group(0) @binding(1)
var<storage, read_write> output: array<f32>;

/// Main compute shader entry point
/// Each thread processes one element
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let index = global_id.x;
    
    // Bounds check (important for safety)
    if (index < arrayLength(&input)) {
        output[index] = input[index] * input[index];
    }
}
