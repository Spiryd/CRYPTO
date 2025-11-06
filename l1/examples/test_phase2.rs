use l1::collision::{CollisionSearch, DELTA_M0, WANG_COLLISION_0};
use l1::gpu::GpuContext;
use l1::{md5, md5_to_hex, md5_with_iv, print_box, InitialValues};

fn print_hex(label: &str, data: &[u8]) {
    print!("{}: ", label);
    for byte in data {
        print!("{:02x}", byte);
    }
    println!();
}

async fn second_step() -> Result<(), Box<dyn std::error::Error>> {
    print_box("Phase 2 (Task 3) - MD5 Collision Search");

    println!("Step 1: Load M0 and M0' from Wang collision data");
    let m0_words = WANG_COLLISION_0.m0;
    let m0_prime_words = WANG_COLLISION_0.m0_prime;
    
    // Convert u32 arrays to byte arrays
    let mut m0 = [0u8; 64];
    let mut m0_prime = [0u8; 64];
    for i in 0..16 {
        let offset = i * 4;
        m0[offset..offset + 4].copy_from_slice(&m0_words[i].to_le_bytes());
        m0_prime[offset..offset + 4].copy_from_slice(&m0_prime_words[i].to_le_bytes());
    }
    
    print_hex("  M0    ", &m0);
    print_hex("  M0'   ", &m0_prime);
    
    println!("\nStep 2: Check delta - M0 ⊕ M0' must equal ΔM0");
    let mut computed_delta = [0u32; 16];
    for i in 0..16 {
        computed_delta[i] = m0_words[i] ^ m0_prime_words[i];
    }
    
    if computed_delta != DELTA_M0 {
        eprintln!("❌ ERROR: M0 and M0' do not satisfy delta requirements!");
        eprintln!("   Cannot proceed with collision search.");
        return Err("Delta mismatch".into());
    }
    println!("  ✓ Delta verified: M0 ⊕ M0' = ΔM0");
    
    println!("\nStep 3: Hash M0 and M0' to get intermediate states (IVs)");
    let m0_state = md5(&m0);
    let m0_prime_state = md5(&m0_prime);
    
    println!("  M0_state:      {}", md5_to_hex(&m0_state));
    println!("  M0_prime_state: {}", md5_to_hex(&m0_prime_state));
    
    // Convert to u32 IVs
    let m0_state_32 = [
        u32::from_le_bytes([m0_state[0], m0_state[1], m0_state[2], m0_state[3]]),
        u32::from_le_bytes([m0_state[4], m0_state[5], m0_state[6], m0_state[7]]),
        u32::from_le_bytes([m0_state[8], m0_state[9], m0_state[10], m0_state[11]]),
        u32::from_le_bytes([m0_state[12], m0_state[13], m0_state[14], m0_state[15]]),
    ];
    
    let m0_prime_state_32 = [
        u32::from_le_bytes([m0_prime_state[0], m0_prime_state[1], m0_prime_state[2], m0_prime_state[3]]),
        u32::from_le_bytes([m0_prime_state[4], m0_prime_state[5], m0_prime_state[6], m0_prime_state[7]]),
        u32::from_le_bytes([m0_prime_state[8], m0_prime_state[9], m0_prime_state[10], m0_prime_state[11]]),
        u32::from_le_bytes([m0_prime_state[12], m0_prime_state[13], m0_prime_state[14], m0_prime_state[15]]),
    ];
    
    println!("\nStep 4: Initialize GPU and collision search");
    let ctx = GpuContext::new().await?;
    let info = ctx.adapter_info();
    println!("  GPU: {} ({:?})", info.name, info.backend);
    
    let search = CollisionSearch::new(&ctx).await?;
    println!("  ✓ GPU initialized");
    
    // Search parameters
    let iterations = 1_000_000; // 1M iterations per thread per batch
    let threads_per_block = 32;
    let block_dim = 256;
    let batch_size = threads_per_block * block_dim; // 8192
    
    println!("\nStep 5: GPU Collision Search Loop");
    println!("  Parameters:");
    println!("    - Batch size: {} threads", batch_size);
    println!("    - Iterations per thread: {}", iterations);
    println!("    - Attempts per batch: ~{:.1}B", (batch_size as f64 * iterations as f64) / 1e9);
    println!("  Searching...\n");
    
    let mut loop_count = 0u64;
    let search_start = std::time::Instant::now();
    
    loop {
        loop_count += 1;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;
        
        // GPU search
        let candidates = search.search_batch(m0_state_32, batch_size as u32, iterations as u32, seed).await?;
        
        // Check each thread's result
        for (i, candidate) in candidates.iter().enumerate() {
            if candidate.found == 1 {
                println!("  → Candidate found in thread {}!", i);
                
                // Extract candidate message (M1)
                let candidate_m1 = candidate.words;
                
                // Convert to bytes
                let mut candidate_bytes = [0u8; 64];
                for (j, &word) in candidate_m1.iter().enumerate() {
                    let offset = j * 4;
                    candidate_bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
                }
                
                // Generate candidate_prim by applying delta
                let mut candidate_prim_bytes = [0u8; 64];
                for j in 0..16 {
                    let delta_bytes = DELTA_M0[j].to_le_bytes();
                    candidate_prim_bytes[j * 4] = candidate_bytes[j * 4] ^ delta_bytes[0];
                    candidate_prim_bytes[j * 4 + 1] = candidate_bytes[j * 4 + 1] ^ delta_bytes[1];
                    candidate_prim_bytes[j * 4 + 2] = candidate_bytes[j * 4 + 2] ^ delta_bytes[2];
                    candidate_prim_bytes[j * 4 + 3] = candidate_bytes[j * 4 + 3] ^ delta_bytes[3];
                }
                
                // Hash with custom IVs
                let iv_m0 = InitialValues {
                    a: m0_state_32[0],
                    b: m0_state_32[1],
                    c: m0_state_32[2],
                    d: m0_state_32[3],
                };
                
                let iv_m0_prime = InitialValues {
                    a: m0_prime_state_32[0],
                    b: m0_prime_state_32[1],
                    c: m0_prime_state_32[2],
                    d: m0_prime_state_32[3],
                };
                
                let h1 = md5_with_iv(&candidate_bytes, iv_m0);
                let h2 = md5_with_iv(&candidate_prim_bytes, iv_m0_prime);
                
                // Check if collision found
                if h1 == h2 {
                    let elapsed = search_start.elapsed();
                    print_box("🎉 COLLISION FOUND! Gloria, Hallelujah! 🎉");
                    
                    println!("Search Statistics:");
                    println!("  Loops: {}", loop_count);
                    println!("  Time: {:.2}s", elapsed.as_secs_f64());
                    println!("  Attempts: ~{:.2}B", (loop_count * batch_size as u64 * iterations as u64) as f64 / 1e9);
                    println!("  Rate: ~{:.2}B attempts/sec\n", 
                        (loop_count * batch_size as u64 * iterations as u64) as f64 / elapsed.as_secs_f64() / 1e9);
                    
                    println!("Collision Details:");
                    print_hex("  M1      ", &candidate_bytes);
                    print_hex("  M1'     ", &candidate_prim_bytes);
                    print_hex("  H1      ", &h1);
                    print_hex("  H2      ", &h2);
                    
                    // Verify full collision: MD5(M0||M1) = MD5(M0'||M1')
                    println!("\nFull Collision Verification:");
                    let mut full_msg = [0u8; 128];
                    let mut full_msg_prime = [0u8; 128];
                    full_msg[..64].copy_from_slice(&m0);
                    full_msg[64..].copy_from_slice(&candidate_bytes);
                    full_msg_prime[..64].copy_from_slice(&m0_prime);
                    full_msg_prime[64..].copy_from_slice(&candidate_prim_bytes);
                    
                    let final_hash = md5(&full_msg);
                    let final_hash_prime = md5(&full_msg_prime);
                    
                    println!("  MD5(M0||M1):  {}", md5_to_hex(&final_hash));
                    println!("  MD5(M0'||M1'): {}", md5_to_hex(&final_hash_prime));
                    
                    if final_hash == final_hash_prime {
                        println!("\n  ✓✓✓ FULL COLLISION CONFIRMED! ✓✓✓\n");
                    } else {
                        println!("\n  ⚠ Warning: Intermediate collision but not full collision\n");
                    }
                    
                    return Ok(());
                }
            }
        }
        
        // Progress update every loop (like C code)
        let elapsed = search_start.elapsed().as_secs_f64();
        let attempts = (loop_count * batch_size as u64 * iterations as u64) as f64 / 1e9;
        let rate = attempts / elapsed;
        print!("\r  Loop: {} | Time: {:.1}s | Attempts: {:.2}B | Rate: {:.2}B/s", 
            loop_count, elapsed, attempts, rate);
        use std::io::Write;
        std::io::stdout().flush()?;
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = second_step().await {
        eprintln!("\n❌ Collision search failed: {}", e);
        eprintln!("\nDetails: {:?}", e);
        std::process::exit(1);
    }
}
