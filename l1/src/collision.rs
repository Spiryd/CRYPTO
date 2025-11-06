use crate::gpu::{GpuContext, GpuError, GpuResult};
use crate::md5::{InitialValues, process_raw_block};
use wgpu::util::DeviceExt;

/// Known MD5 collision example from Wang et al.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WangCollisionExample {
    /// First message block M0
    pub m0: [u32; 16],
    /// Second message block M1
    pub m1: [u32; 16],
    /// First message block prime M0'
    pub m0_prime: [u32; 16],
    /// Second message block prime M1'
    pub m1_prime: [u32; 16],
}

/// First known Wang collision (from "How to Break MD5 and Other Hash Functions", 2005)
pub const WANG_COLLISION_0: WangCollisionExample = WangCollisionExample {
    m0: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x87b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a417125, 0xe8255108, 0x9fc9cdf7,
        0xf2bd1dd9, 0x5b3c3780,
    ],
    m1: [
        0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 0xc79a7335, 0xcfdebf0, 0x66f12930,
        0x8fb109d1, 0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 0xddcb74ed, 0x6dd3c55f,
        0xd80a9bb1, 0xe3a7cc35,
    ],
    m0_prime: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x7b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a41f125, 0xe8255108, 0x9fc9cdf7,
        0x72bd1dd9, 0x5b3c3780,
    ],
    m1_prime: [
        0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 0x479a7335, 0xcfdebf0, 0x66f12930,
        0x8fb109d1, 0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c154c79, 0xddcb74ed, 0x6dd3c55f,
        0x580a9bb1, 0xe3a7cc35,
    ],
};

/// Second known Wang collision
pub const WANG_COLLISION_1: WangCollisionExample = WangCollisionExample {
    m0: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x87b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a417125, 0xe8255108, 0x9fc9cdf7,
        0xf2bd1dd9, 0x5b3c3780,
    ],
    m1: [
        0x313e82d8, 0x5b8f3456, 0xd4ac6dae, 0xc619c936, 0xb4e253dd, 0xfd03da87, 0x6633902,
        0xa0cd48d2, 0x42339fe9, 0xe87e570f, 0x70b654ce, 0x1e0da880, 0xbc2198c6, 0x9383a8b6,
        0x2b65f996, 0x702af76f,
    ],
    m0_prime: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x7b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a41f125, 0xe8255108, 0x9fc9cdf7,
        0x72bd1dd9, 0x5b3c3780,
    ],
    m1_prime: [
        0x313e82d8, 0x5b8f3456, 0xd4ac6dae, 0xc619c936, 0x34e253dd, 0xfd03da87, 0x6633902,
        0xa0cd48d2, 0x42339fe9, 0xe87e570f, 0x70b654ce, 0x1e0d2880, 0xbc2198c6, 0x9383a8b6,
        0xab65f996, 0x702af76f,
    ],
};

impl WangCollisionExample {
    /// Verify that this collision example actually produces a collision
    pub fn verify(&self) -> bool {
        let iv = InitialValues::STANDARD;
        
        // Process M0 and M0'
        let iv0 = process_raw_block(iv, &self.m0);
        let iv0_prime = process_raw_block(iv, &self.m0_prime);
        
        // Process M1 and M1' with their respective IVs
        let h = process_raw_block(iv0, &self.m1);
        let h_prime = process_raw_block(iv0_prime, &self.m1_prime);
        
        // Check if hashes match
        h.a == h_prime.a && h.b == h_prime.b && h.c == h_prime.c && h.d == h_prime.d
    }
    
    /// Get the collision hash value
    pub fn hash(&self) -> [u32; 4] {
        let iv = InitialValues::STANDARD;
        let iv0 = process_raw_block(iv, &self.m0);
        let h = process_raw_block(iv0, &self.m1);
        [h.a, h.b, h.c, h.d]
    }
    
    /// Get the intermediate state after M0
    pub fn intermediate_state_0(&self) -> [u32; 4] {
        let iv = InitialValues::STANDARD;
        let iv0 = process_raw_block(iv, &self.m0);
        [iv0.a, iv0.b, iv0.c, iv0.d]
    }
    
    /// Get the intermediate state after M0'
    pub fn intermediate_state_0_prime(&self) -> [u32; 4] {
        let iv = InitialValues::STANDARD;
        let iv0_prime = process_raw_block(iv, &self.m0_prime);
        [iv0_prime.a, iv0_prime.b, iv0_prime.c, iv0_prime.d]
    }
}

/// Delta for Wang's attack: ΔM0 = M0' - M0
pub const DELTA_M0: [u32; 16] = [
    0, 0, 0, 0,
    0x80000000, // 2^31 at position 4
    0, 0, 0,
    0, 0, 0,
    0x00008000, // 2^15 at position 11
    0, 0,
    0x80000000, // 2^31 at position 14
    0,
];

/// Input for collision search
#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct SearchInput {
    /// IV from first block hash
    pub iv: [u32; 4],
    /// Random seed
    pub seed: u32,
    /// Iterations per thread
    pub iterations: u32,
    /// Padding to align to 16 bytes
    pub _padding: [u32; 2],
}

/// Collision candidate result
#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct Candidate {
    /// Message block (16 words)
    pub words: [u32; 16],
    /// Whether this candidate satisfies conditions
    pub found: u32,
    /// Padding
    pub _padding: [u32; 3],
}

/// Complete collision pair
#[derive(Debug, Clone)]
pub struct Collision {
    /// First message block
    pub m1: [u8; 64],
    /// Second message block (M1' = M1 ⊕ ΔM0)
    pub m1_prime: [u8; 64],
    /// Resulting hash (same for both)
    pub hash: [u8; 16],
}

/// GPU-accelerated collision search engine
pub struct CollisionSearch {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
}

impl CollisionSearch {
    /// Create a new collision search engine
    pub async fn new(ctx: &GpuContext) -> GpuResult<Self> {
        let shader_src = include_str!("gpu/shaders/collision_search.wgsl");
        
        let shader = ctx.device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Collision Search Shader"),
            source: wgpu::ShaderSource::Wgsl(shader_src.into()),
        });

        let bind_group_layout = ctx.device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("Collision Search Bind Group Layout"),
            entries: &[
                // Binding 0: Input (read-only)
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
                // Binding 1: Candidates (read-write)
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

        let pipeline_layout = ctx.device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Collision Search Pipeline Layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = ctx.device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Collision Search Pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("search_collision"),
            compilation_options: Default::default(),
            cache: None,
        });

        Ok(Self {
            device: ctx.device.clone(),
            queue: ctx.queue.clone(),
            pipeline,
            bind_group_layout,
        })
    }

    /// Search for collision candidates
    ///
    /// # Arguments
    /// * `iv` - MD5 state after processing M0
    /// * `batch_size` - Number of parallel GPU threads
    /// * `iterations` - Iterations per thread before giving up
    /// * `seed` - Random seed
    pub async fn search_batch(
        &self,
        iv: [u32; 4],
        batch_size: u32,
        iterations: u32,
        seed: u32,
    ) -> GpuResult<Vec<Candidate>> {
        let input = SearchInput {
            iv,
            seed,
            iterations,
            _padding: [0, 0],
        };

        // Create input buffer
        let input_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Search Input Buffer"),
            contents: bytemuck::bytes_of(&input),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });

        // Create candidates buffer
        let candidates_size = (batch_size as usize) * std::mem::size_of::<Candidate>();
        let candidates_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Candidates Buffer"),
            size: candidates_size as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        // Create staging buffer
        let staging_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Staging Buffer"),
            size: candidates_size as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Create bind group
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Collision Search Bind Group"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: input_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: candidates_buffer.as_entire_binding(),
                },
            ],
        });

        // Create command encoder and dispatch
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("Collision Search Encoder"),
        });

        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Collision Search Pass"),
                timestamp_writes: None,
            });

            compute_pass.set_pipeline(&self.pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            
            // Workgroup size is 256, calculate number of workgroups
            let workgroups = batch_size.div_ceil(256);
            compute_pass.dispatch_workgroups(workgroups, 1, 1);
        }

        // Copy results to staging
        encoder.copy_buffer_to_buffer(
            &candidates_buffer,
            0,
            &staging_buffer,
            0,
            candidates_size as u64,
        );

        self.queue.submit(Some(encoder.finish()));

        // Read back results
        let buffer_slice = staging_buffer.slice(..);
        let (sender, receiver) = flume::unbounded();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });

        self.device.poll(wgpu::PollType::Wait {
            submission_index: None,
            timeout: None,
        }).unwrap();
        
        receiver.recv_async().await
            .map_err(|_| GpuError::BufferError("Failed to receive buffer mapping result".into()))?
            .map_err(|e| GpuError::BufferError(format!("Buffer mapping failed: {:?}", e)))?;

        let data = buffer_slice.get_mapped_range();
        let candidates: Vec<Candidate> = bytemuck::cast_slice(&data).to_vec();
        
        drop(data);
        staging_buffer.unmap();

        Ok(candidates)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wang_collision_0_verify() {
        assert!(WANG_COLLISION_0.verify(), 
                "Wang collision 0 should be valid");
    }

    #[test]
    fn test_wang_collision_1_verify() {
        assert!(WANG_COLLISION_1.verify(), 
                "Wang collision 1 should be valid");
    }

    #[test]
    fn test_wang_collision_0_produces_same_hash() {
        let iv = InitialValues::STANDARD;
        
        // Hash path 1: M0 -> M1
        let iv0 = process_raw_block(iv, &WANG_COLLISION_0.m0);
        let h1 = process_raw_block(iv0, &WANG_COLLISION_0.m1);
        
        // Hash path 2: M0' -> M1'
        let iv0_prime = process_raw_block(iv, &WANG_COLLISION_0.m0_prime);
        let h2 = process_raw_block(iv0_prime, &WANG_COLLISION_0.m1_prime);
        
        assert_eq!(h1.a, h2.a, "Hash component A should match");
        assert_eq!(h1.b, h2.b, "Hash component B should match");
        assert_eq!(h1.c, h2.c, "Hash component C should match");
        assert_eq!(h1.d, h2.d, "Hash component D should match");
    }

    #[test]
    fn test_wang_collision_1_produces_same_hash() {
        let iv = InitialValues::STANDARD;
        
        // Hash path 1: M0 -> M1
        let iv0 = process_raw_block(iv, &WANG_COLLISION_1.m0);
        let h1 = process_raw_block(iv0, &WANG_COLLISION_1.m1);
        
        // Hash path 2: M0' -> M1'
        let iv0_prime = process_raw_block(iv, &WANG_COLLISION_1.m0_prime);
        let h2 = process_raw_block(iv0_prime, &WANG_COLLISION_1.m1_prime);
        
        assert_eq!(h1.a, h2.a, "Hash component A should match");
        assert_eq!(h1.b, h2.b, "Hash component B should match");
        assert_eq!(h1.c, h2.c, "Hash component C should match");
        assert_eq!(h1.d, h2.d, "Hash component D should match");
    }
}
