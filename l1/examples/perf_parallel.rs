use std::time::Instant;
use rayon::prelude::*;
use l1::{md5, print_box};

fn main() {
    println!("=== Parallel MD5 Performance Test (using Rayon) ===\n");

    // Get number of CPU cores
    let num_threads = rayon::current_num_threads();
    println!("System information:");
    println!("  CPU cores available: {}", num_threads);
    println!();

    let test_message = b"The quick brown fox jumps over the lazy dog";
    
    // Warm-up
    println!("Running warm-up...");
    (0..1000).into_par_iter().for_each(|_| {
        let _ = md5(test_message);
    });
    (0..1000).into_par_iter().for_each(|_| {
        let _ = reference_md5::compute(test_message);
    });
    
    // Test with 2^20 iterations (about 1 million)
    let count = 1 << 20;
    println!("Testing with 2^20 = {} iterations", count);
    println!();
    
    // ═══════════════════════════════════════════════════════════
    // Sequential Tests (baseline)
    // ═══════════════════════════════════════════════════════════
    print_box("SEQUENTIAL (Single-threaded Baseline)");
    
    println!("Our implementation (sequential):");
    let start = Instant::now();
    for i in 0..count {
        let msg = format!("{}{}", i, "test");
        let _ = md5(msg.as_bytes());
    }
    let our_seq_duration = start.elapsed();
    let our_seq_per_hash = our_seq_duration.as_secs_f64() / (count as f64);
    println!("  Total time:  {:.3} seconds", our_seq_duration.as_secs_f64());
    println!("  Per hash:    {:.3} μs", our_seq_per_hash * 1_000_000.0);
    println!("  Rate:        {:.0} hashes/sec", 1.0 / our_seq_per_hash);
    println!();
    
    println!("Reference implementation (sequential):");
    let start = Instant::now();
    for i in 0..count {
        let msg = format!("{}{}", i, "test");
        let _ = reference_md5::compute(msg.as_bytes());
    }
    let ref_seq_duration = start.elapsed();
    let ref_seq_per_hash = ref_seq_duration.as_secs_f64() / (count as f64);
    println!("  Total time:  {:.3} seconds", ref_seq_duration.as_secs_f64());
    println!("  Per hash:    {:.3} μs", ref_seq_per_hash * 1_000_000.0);
    println!("  Rate:        {:.0} hashes/sec", 1.0 / ref_seq_per_hash);
    println!();
    
    // ═══════════════════════════════════════════════════════════
    // Parallel Tests (using Rayon)
    // ═══════════════════════════════════════════════════════════
    print_box("PARALLEL (Multi-threaded with Rayon)");
    
    println!("Our implementation (parallel on {} cores):", num_threads);
    let start = Instant::now();
    (0..count).into_par_iter().for_each(|i| {
        let msg = format!("{}{}", i, "test");
        let _ = md5(msg.as_bytes());
    });
    let our_par_duration = start.elapsed();
    let our_par_per_hash = our_par_duration.as_secs_f64() / (count as f64);
    println!("  Total time:  {:.3} seconds", our_par_duration.as_secs_f64());
    println!("  Per hash:    {:.3} μs", our_par_per_hash * 1_000_000.0);
    println!("  Rate:        {:.0} hashes/sec", 1.0 / our_par_per_hash);
    println!("  Speedup:     {:.2}x", our_seq_duration.as_secs_f64() / our_par_duration.as_secs_f64());
    println!("  Efficiency:  {:.1}% ({:.2}x / {} cores)", 
        (our_seq_duration.as_secs_f64() / our_par_duration.as_secs_f64() / num_threads as f64) * 100.0,
        our_seq_duration.as_secs_f64() / our_par_duration.as_secs_f64(),
        num_threads);
    println!();
    
    println!("Reference implementation (parallel on {} cores):", num_threads);
    let start = Instant::now();
    (0..count).into_par_iter().for_each(|i| {
        let msg = format!("{}{}", i, "test");
        let _ = reference_md5::compute(msg.as_bytes());
    });
    let ref_par_duration = start.elapsed();
    let ref_par_per_hash = ref_par_duration.as_secs_f64() / (count as f64);
    println!("  Total time:  {:.3} seconds", ref_par_duration.as_secs_f64());
    println!("  Per hash:    {:.3} μs", ref_par_per_hash * 1_000_000.0);
    println!("  Rate:        {:.0} hashes/sec", 1.0 / ref_par_per_hash);
    println!("  Speedup:     {:.2}x", ref_seq_duration.as_secs_f64() / ref_par_duration.as_secs_f64());
    println!("  Efficiency:  {:.1}% ({:.2}x / {} cores)", 
        (ref_seq_duration.as_secs_f64() / ref_par_duration.as_secs_f64() / num_threads as f64) * 100.0,
        ref_seq_duration.as_secs_f64() / ref_par_duration.as_secs_f64(),
        num_threads);
    println!();
    
    // ═══════════════════════════════════════════════════════════
    // Extrapolation to 2^40
    // ═══════════════════════════════════════════════════════════
    print_box("Extrapolation to 2^40 Operations");
    
    let target = 1u64 << 40;
    println!("2^40 = {} hashes", format_number(target));
    println!();
    
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│                   SEQUENTIAL                            │");
    println!("├─────────────────────────────────────────────────────────┤");
    let our_seq_time_2_40 = our_seq_per_hash * (target as f64);
    let ref_seq_time_2_40 = ref_seq_per_hash * (target as f64);
    println!("│ Our implementation:  {:>32}   │", format_time(our_seq_time_2_40));
    println!("│ Reference:           {:>32}   │", format_time(ref_seq_time_2_40));
    println!("└─────────────────────────────────────────────────────────┘");
    println!();
    
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│         PARALLEL ({} cores)                             │", num_threads);
    println!("├─────────────────────────────────────────────────────────┤");
    let our_par_time_2_40 = our_par_per_hash * (target as f64);
    let ref_par_time_2_40 = ref_par_per_hash * (target as f64);
    println!("│ Our implementation:  {:>32}   │", format_time(our_par_time_2_40));
    println!("│ Reference:           {:>32}   │", format_time(ref_par_time_2_40));
    println!("└─────────────────────────────────────────────────────────┘");
    println!();
    
    // ═══════════════════════════════════════════════════════════
    // Improvement Summary
    // ═══════════════════════════════════════════════════════════
    print_box("Parallelization Impact");
    
    let our_speedup = our_seq_time_2_40 / our_par_time_2_40;
    let ref_speedup = ref_seq_time_2_40 / ref_par_time_2_40;
    
    println!("Time reduction for 2^40 hashes:");
    println!("  Our implementation:");
    println!("    Sequential: {}", format_time(our_seq_time_2_40));
    println!("    Parallel:   {}", format_time(our_par_time_2_40));
    println!("    Speedup:    {:.2}x faster", our_speedup);
    println!("    Time saved: {}", format_time(our_seq_time_2_40 - our_par_time_2_40));
    println!();
    
    println!("  Reference implementation:");
    println!("    Sequential: {}", format_time(ref_seq_time_2_40));
    println!("    Parallel:   {}", format_time(ref_par_time_2_40));
    println!("    Speedup:    {:.2}x faster", ref_speedup);
    println!("    Time saved: {}", format_time(ref_seq_time_2_40 - ref_par_time_2_40));
    println!();
    
    // ═══════════════════════════════════════════════════════════
    // Cryptographic Context
    // ═══════════════════════════════════════════════════════════
    print_box("Implications");
    
    println!("Wang et al. collision attack (2004): ~2^39 MD5 calculations");
    let wang_ops = 1u64 << 39;
    let wang_time_seq = ref_seq_per_hash * (wang_ops as f64);
    let wang_time_par = ref_par_per_hash * (wang_ops as f64);
    
    println!("  With optimized reference implementation:");
    println!("    Sequential: {}", format_time(wang_time_seq));
    println!("    Parallel:   {} (on {} cores)", format_time(wang_time_par), num_threads);
    println!();
    
    println!("Key insight:");
    println!("  Parallelization makes Wang's attack {:.0}x faster,", wang_time_seq / wang_time_par);
    println!("  reducing time from {} to {}",
        format_time(wang_time_seq), format_time(wang_time_par));
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (count, c) in s.chars().rev().enumerate() {
        if count > 0 && count % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_time(seconds: f64) -> String {
    if seconds < 0.001 {
        format!("{:.2} microseconds", seconds * 1_000_000.0)
    } else if seconds < 1.0 {
        format!("{:.2} milliseconds", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.2} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.2} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.2} hours", seconds / 3600.0)
    } else if seconds < 31536000.0 {
        format!("{:.2} days", seconds / 86400.0)
    } else {
        format!("{:.2} years", seconds / 31536000.0)
    }
}
