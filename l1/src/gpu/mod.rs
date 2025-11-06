//! GPU compute module for WGPU-based computation
//!
//! This module provides a clean, easy-to-use API for GPU compute operations using WGPU.
//! It abstracts away the complexity of WGPU setup while maintaining flexibility.
//!
//! # Example
//!
//! ```rust
//! use l1::gpu::{GpuContext, ComputePipeline};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize GPU context
//! let ctx = GpuContext::new().await?;
//!
//! // Create a compute pipeline with your shader
//! let pipeline = ComputePipeline::new(&ctx, include_str!("shaders/square.wgsl"), "main")?;
//!
//! // Run computation
//! let input: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];
//! let output = pipeline.execute(&ctx, &input).await?;
//!
//! println!("Results: {:?}", output);
//! # Ok(())
//! # }
//! ```

mod context;
mod pipeline;

pub use context::GpuContext;
pub use pipeline::ComputePipeline;

/// Result type for GPU operations
pub type GpuResult<T> = Result<T, GpuError>;

/// Error types for GPU operations
#[derive(Debug)]
pub enum GpuError {
    /// Failed to find a suitable GPU adapter
    NoAdapter,
    /// Failed to create device or queue
    DeviceCreation(String),
    /// Shader compilation error
    ShaderError(String),
    /// Buffer operation error
    BufferError(String),
    /// Validation error
    ValidationError(String),
    /// General WGPU error
    WgpuError(String),
}

impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuError::NoAdapter => write!(f, "Failed to find a suitable GPU adapter"),
            GpuError::DeviceCreation(msg) => write!(f, "Device creation failed: {}", msg),
            GpuError::ShaderError(msg) => write!(f, "Shader error: {}", msg),
            GpuError::BufferError(msg) => write!(f, "Buffer operation failed: {}", msg),
            GpuError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            GpuError::WgpuError(msg) => write!(f, "WGPU error: {}", msg),
        }
    }
}

impl std::error::Error for GpuError {}

impl From<wgpu::RequestDeviceError> for GpuError {
    fn from(err: wgpu::RequestDeviceError) -> Self {
        GpuError::DeviceCreation(err.to_string())
    }
}

impl From<wgpu::BufferAsyncError> for GpuError {
    fn from(err: wgpu::BufferAsyncError) -> Self {
        GpuError::BufferError(err.to_string())
    }
}
