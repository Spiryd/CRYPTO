//! GPU context management
//!
//! Provides a simple wrapper around WGPU's device, queue, and adapter.

use super::{GpuError, GpuResult};
use wgpu;

/// GPU context that manages the device, queue, and adapter.
///
/// This struct encapsulates all the WGPU state needed for compute operations.
/// It should be created once and reused for multiple compute operations.
pub struct GpuContext {
    pub device: wgpu::Device,
    pub queue: wgpu::Queue,
    pub adapter: wgpu::Adapter,
}

impl GpuContext {
    /// Create a new GPU context with default settings.
    ///
    /// This will automatically select the best available GPU adapter.
    ///
    /// # Errors
    ///
    /// Returns `GpuError::NoAdapter` if no suitable GPU is found.
    /// Returns `GpuError::DeviceCreation` if device creation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use l1::gpu::GpuContext;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ctx = GpuContext::new().await?;
    /// println!("GPU: {}", ctx.adapter.get_info().name);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new() -> GpuResult<Self> {
        Self::with_options(wgpu::PowerPreference::HighPerformance).await
    }

    /// Create a new GPU context with specific power preference.
    ///
    /// # Arguments
    ///
    /// * `power_preference` - Power preference for adapter selection
    ///
    /// # Example
    ///
    /// ```rust
    /// use l1::gpu::GpuContext;
    /// use wgpu::PowerPreference;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ctx = GpuContext::with_options(PowerPreference::LowPower).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_options(power_preference: wgpu::PowerPreference) -> GpuResult<Self> {
        // Create WGPU instance
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        // Request adapter (GPU)
        let adapter = match instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
        {
            Ok(adapter) => adapter,
            Err(_) => return Err(GpuError::NoAdapter),
        };

        // Log adapter info
        let info = adapter.get_info();
        log::info!("Selected GPU: {} ({:?})", info.name, info.backend);

        // Request device and queue
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor::default())
            .await?;

        Ok(Self {
            device,
            queue,
            adapter,
        })
    }

    /// Get information about the selected GPU adapter.
    pub fn adapter_info(&self) -> wgpu::AdapterInfo {
        self.adapter.get_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_context_creation() {
        pollster::block_on(async {
            let ctx = GpuContext::new().await;
            assert!(ctx.is_ok(), "Failed to create GPU context");

            if let Ok(ctx) = ctx {
                let info = ctx.adapter_info();
                println!("GPU: {} ({:?})", info.name, info.backend);
            }
        });
    }
}
