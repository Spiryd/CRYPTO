//! Comprehensive GPU compute tests using the L1 API

use l1::gpu::{GpuContext, ComputePipeline};

// Square shader used for testing
const SQUARE_SHADER: &str = include_str!("../src/gpu/shaders/square.wgsl");

// Helper function to setup GPU context
async fn setup_gpu() -> (GpuContext, ComputePipeline) {
    let ctx = GpuContext::new().await.expect("Failed to create GPU context");
    let pipeline = ComputePipeline::new(&ctx, SQUARE_SHADER, "main")
        .expect("Failed to create compute pipeline");
    (ctx, pipeline)
}

#[test]
fn test_gpu_context_creation() {
    pollster::block_on(async {
        let result = GpuContext::new().await;
        assert!(result.is_ok(), "Failed to create GPU context");

        if let Ok(ctx) = result {
            let info = ctx.adapter_info();
            println!("GPU: {} ({:?})", info.name, info.backend);
        }
    });
}

#[test]
fn test_simple_compute_small_dataset() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        let input = vec![1.0, 2.0, 3.0, 4.0];
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 4);
        assert!((output[0] - 1.0).abs() < 0.001, "1² should be 1");
        assert!((output[1] - 4.0).abs() < 0.001, "2² should be 4");
        assert!((output[2] - 9.0).abs() < 0.001, "3² should be 9");
        assert!((output[3] - 16.0).abs() < 0.001, "4² should be 16");
    });
}

#[test]
fn test_compute_single_element() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        let input = vec![5.0];
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 1);
        assert!((output[0] - 25.0).abs() < 0.001, "5² should be 25");
    });
}

#[test]
fn test_compute_zeros() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        let input = vec![0.0, 0.0, 0.0];
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 3);
        for &val in &output {
            assert!((val - 0.0).abs() < 0.001, "0² should be 0");
        }
    });
}

#[test]
fn test_compute_negative_numbers() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        let input = vec![-2.0, -3.0, -4.0];
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 3);
        assert!((output[0] - 4.0).abs() < 0.001, "(-2)² should be 4");
        assert!((output[1] - 9.0).abs() < 0.001, "(-3)² should be 9");
        assert!((output[2] - 16.0).abs() < 0.001, "(-4)² should be 16");
    });
}

#[test]
fn test_compute_fractional_numbers() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        let input = vec![0.5, 1.5, 2.5];
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 3);
        assert!((output[0] - 0.25).abs() < 0.001, "(0.5)² should be 0.25");
        assert!((output[1] - 2.25).abs() < 0.001, "(1.5)² should be 2.25");
        assert!((output[2] - 6.25).abs() < 0.001, "(2.5)² should be 6.25");
    });
}

#[test]
fn test_compute_larger_dataset() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        let input: Vec<f32> = (1..=100).map(|x| x as f32).collect();
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 100);

        // Verify a few values
        assert!((output[0] - 1.0).abs() < 0.001);
        assert!((output[9] - 100.0).abs() < 0.001); // 10²
        assert!((output[49] - 2500.0).abs() < 0.001); // 50²
        assert!((output[99] - 10000.0).abs() < 0.001); // 100²

        // Verify all values
        for (i, &val) in output.iter().enumerate() {
            let expected = ((i + 1) as f32).powi(2);
            assert!(
                (val - expected).abs() < 0.001,
                "Mismatch at index {}: expected {}, got {}",
                i,
                expected,
                val
            );
        }
    });
}

#[test]
fn test_compute_exact_workgroup_size() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        // Test with exactly 64 elements (one workgroup)
        let input: Vec<f32> = (1..=64).map(|x| x as f32).collect();
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 64);

        for (i, &val) in output.iter().enumerate() {
            let expected = ((i + 1) as f32).powi(2);
            assert!((val - expected).abs() < 0.001);
        }
    });
}

#[test]
fn test_compute_multiple_workgroups() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        // Test with 256 elements (4 workgroups)
        let input: Vec<f32> = (1..=256).map(|x| x as f32).collect();
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 256);

        for (i, &val) in output.iter().enumerate() {
            let expected = ((i + 1) as f32).powi(2);
            assert!((val - expected).abs() < 0.001);
        }
    });
}

#[test]
fn test_pipeline_reuse() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        // Execute multiple times with same pipeline
        for run in 1..=3 {
            let input = vec![1.0, 2.0, 3.0];
            let output = pipeline
                .execute(&ctx, &input)
                .await
                .unwrap_or_else(|_| panic!("Failed on run {}", run));

            assert_eq!(output.len(), 3);
            assert!((output[0] - 1.0).abs() < 0.001);
            assert!((output[1] - 4.0).abs() < 0.001);
            assert!((output[2] - 9.0).abs() < 0.001);
        }
    });
}

#[test]
fn test_compute_very_large_numbers() {
    pollster::block_on(async {
        let (ctx, pipeline) = setup_gpu().await;

        let input = vec![100.0, 1000.0, 10000.0];
        let output = pipeline
            .execute(&ctx, &input)
            .await
            .expect("Failed to execute pipeline");

        assert_eq!(output.len(), 3);
        assert!((output[0] - 10000.0).abs() < 0.1);
        assert!((output[1] - 1000000.0).abs() < 1.0);
        assert!((output[2] - 100000000.0).abs() < 10.0);
    });
}
