//! Simple GPU compute example using the clean L1 API
//!
//! This example demonstrates how to use the GPU compute capabilities
//! to square an array of numbers.

use l1::gpu::{GpuContext, ComputePipeline};
use pollster::FutureExt;

async fn run_compute() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize GPU context (one line!)
    println!("Initializing GPU...");
    let ctx = GpuContext::new().await?;
    let info = ctx.adapter_info();
    println!("✓ Using GPU: {} ({:?})\n", info.name, info.backend);

    // 2. Create compute pipeline with our shader
    let shader = include_str!("../src/gpu/shaders/square.wgsl");
    let pipeline = ComputePipeline::new(&ctx, shader, "main")?;
    println!("✓ Compute pipeline created\n");

    // 3. Prepare input data
    let numbers: Vec<f32> = (1..=256).map(|x| x as f32).collect();
    println!("Input data (first 10): {:?}\n", &numbers[..10]);

    // 4. Execute computation on GPU (one line!)
    println!("Running computation on GPU...");
    let results = pipeline.execute(&ctx, &numbers).await?;
    println!("✓ Computation complete\n");

    // 5. Display and verify results
    println!("Results (first 10):");
    for (i, &value) in results.iter().take(10).enumerate() {
        let input = (i + 1) as f32;
        println!("  {}² = {}", input, value);
    }

    // Verify correctness
    println!("\n✓ Verification:");
    let correct = results.iter().enumerate().all(|(i, &val)| {
        let expected = ((i + 1) as f32).powi(2);
        (val - expected).abs() < 0.001
    });

    if correct {
        println!("  All {} results are correct! ✓", results.len());
    } else {
        println!("  ✗ Some results are incorrect!");
    }

    Ok(())
}

fn main() {
    println!("=== Simple GPU Compute Example ===\n");
    println!("This example uses GPU to square numbers from 1 to 256\n");

    match run_compute().block_on() {
        Ok(_) => println!("\n✓ Success!"),
        Err(e) => {
            eprintln!("\n✗ Error: {}", e);
            std::process::exit(1);
        }
    }
}
