//! Compute pipeline management
//!
//! Provides a high-level API for creating and executing GPU compute pipelines.

use super::{GpuContext, GpuError, GpuResult};
use wgpu::util::DeviceExt;

/// A compute pipeline that can execute GPU compute shaders.
///
/// This struct manages the shader module, pipeline, and bind group layout.
pub struct ComputePipeline {
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    workgroup_size: u32,
}

impl ComputePipeline {
    /// Create a new compute pipeline from WGSL shader source.
    ///
    /// # Arguments
    ///
    /// * `ctx` - GPU context
    /// * `shader_source` - WGSL shader source code
    /// * `entry_point` - Entry point function name (usually "main")
    ///
    /// # Example
    ///
    /// ```rust
    /// use l1::gpu::{GpuContext, ComputePipeline};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ctx = GpuContext::new().await?;
    /// let shader = r#"
    ///     @group(0) @binding(0) var<storage, read> input: array<f32>;
    ///     @group(0) @binding(1) var<storage, read_write> output: array<f32>;
    ///     
    ///     @compute @workgroup_size(64)
    ///     fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    ///         output[global_id.x] = input[global_id.x] * 2.0;
    ///     }
    /// "#;
    /// let pipeline = ComputePipeline::new(&ctx, shader, "main")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(ctx: &GpuContext, shader_source: &str, entry_point: &str) -> GpuResult<Self> {
        Self::with_workgroup_size(ctx, shader_source, entry_point, 64)
    }

    /// Create a new compute pipeline with a specific workgroup size.
    ///
    /// # Arguments
    ///
    /// * `ctx` - GPU context
    /// * `shader_source` - WGSL shader source code
    /// * `entry_point` - Entry point function name
    /// * `workgroup_size` - Size of each workgroup (must match shader)
    pub fn with_workgroup_size(
        ctx: &GpuContext,
        shader_source: &str,
        entry_point: &str,
        workgroup_size: u32,
    ) -> GpuResult<Self> {
        // Create shader module
        let shader = ctx
            .device
            .create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("Compute Shader"),
                source: wgpu::ShaderSource::Wgsl(shader_source.into()),
            });

        // Create bind group layout for input/output buffers
        let bind_group_layout =
            ctx.device
                .create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                    label: Some("Compute Bind Group Layout"),
                    entries: &[
                        // Input buffer (read-only)
                        wgpu::BindGroupLayoutEntry {
                            binding: 0,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Storage { read_only: true },
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                        // Output buffer (read-write)
                        wgpu::BindGroupLayoutEntry {
                            binding: 1,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Storage { read_only: false },
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                    ],
                });

        // Create pipeline layout
        let pipeline_layout =
            ctx.device
                .create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                    label: Some("Compute Pipeline Layout"),
                    bind_group_layouts: &[&bind_group_layout],
                    push_constant_ranges: &[],
                });

        // Create compute pipeline
        let pipeline = ctx
            .device
            .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some("Compute Pipeline"),
                layout: Some(&pipeline_layout),
                module: &shader,
                entry_point: Some(entry_point),
                compilation_options: Default::default(),
                cache: None,
            });

        Ok(Self {
            pipeline,
            bind_group_layout,
            workgroup_size,
        })
    }

    /// Execute the compute pipeline on input data.
    ///
    /// This method handles buffer creation, data transfer, execution, and result retrieval.
    ///
    /// # Arguments
    ///
    /// * `ctx` - GPU context
    /// * `input` - Input data as slice of f32
    ///
    /// # Returns
    ///
    /// A vector containing the output data from GPU computation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use l1::gpu::{GpuContext, ComputePipeline};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ctx = GpuContext::new().await?;
    /// let pipeline = ComputePipeline::new(&ctx, include_str!("shaders/square.wgsl"), "main")?;
    ///
    /// let input = vec![1.0, 2.0, 3.0, 4.0];
    /// let output = pipeline.execute(&ctx, &input).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn execute(&self, ctx: &GpuContext, input: &[f32]) -> GpuResult<Vec<f32>> {
        let size = input.len();

        // Create input buffer
        let input_buffer =
            ctx.device
                .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                    label: Some("Input Buffer"),
                    contents: bytemuck::cast_slice(input),
                    usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                });

        // Create output buffer
        let output_buffer = ctx.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Output Buffer"),
            size: (std::mem::size_of_val(input)) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        // Create staging buffer for reading results
        let staging_buffer = ctx.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Staging Buffer"),
            size: (std::mem::size_of_val(input)) as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Create bind group
        let bind_group = ctx.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Compute Bind Group"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: input_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: output_buffer.as_entire_binding(),
                },
            ],
        });

        // Create command encoder
        let mut encoder = ctx
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("Compute Encoder"),
            });

        // Compute pass
        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Compute Pass"),
                timestamp_writes: None,
            });

            compute_pass.set_pipeline(&self.pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);

            // Calculate number of workgroups needed
            let workgroup_count = ((size as f32) / (self.workgroup_size as f32)).ceil() as u32;
            compute_pass.dispatch_workgroups(workgroup_count, 1, 1);
        }

        // Copy output to staging buffer
        encoder.copy_buffer_to_buffer(
            &output_buffer,
            0,
            &staging_buffer,
            0,
            (std::mem::size_of_val(input)) as u64,
        );

        // Submit commands
        ctx.queue.submit(Some(encoder.finish()));

        // Read results back from GPU
        let buffer_slice = staging_buffer.slice(..);
        let (sender, receiver) = flume::unbounded();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            sender.send(result).unwrap();
        });

        ctx.device
            .poll(wgpu::PollType::Wait {
                submission_index: None,
                timeout: None,
            })
            .unwrap();
        receiver
            .recv_async()
            .await
            .map_err(|e| GpuError::BufferError(e.to_string()))??;

        let data = buffer_slice.get_mapped_range();
        let result: Vec<f32> = bytemuck::cast_slice(&data).to_vec();

        drop(data);
        staging_buffer.unmap();

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQUARE_SHADER: &str = r#"
@group(0) @binding(0)
var<storage, read> input: array<f32>;

@group(0) @binding(1)
var<storage, read_write> output: array<f32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let index = global_id.x;
    output[index] = input[index] * input[index];
}
"#;

    #[test]
    fn test_pipeline_creation() {
        pollster::block_on(async {
            let ctx = GpuContext::new().await.expect("Failed to create GPU context");
            let pipeline = ComputePipeline::new(&ctx, SQUARE_SHADER, "main");
            assert!(pipeline.is_ok(), "Failed to create compute pipeline");
        });
    }

    #[test]
    fn test_pipeline_execution() {
        pollster::block_on(async {
            let ctx = GpuContext::new().await.expect("Failed to create GPU context");
            let pipeline = ComputePipeline::new(&ctx, SQUARE_SHADER, "main")
                .expect("Failed to create compute pipeline");

            let input = vec![1.0, 2.0, 3.0, 4.0];
            let output = pipeline
                .execute(&ctx, &input)
                .await
                .expect("Failed to execute pipeline");

            assert_eq!(output.len(), 4);
            assert!((output[0] - 1.0).abs() < 0.001);
            assert!((output[1] - 4.0).abs() < 0.001);
            assert!((output[2] - 9.0).abs() < 0.001);
            assert!((output[3] - 16.0).abs() < 0.001);
        });
    }
}
