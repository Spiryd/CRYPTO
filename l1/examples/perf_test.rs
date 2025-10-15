use std::time::Instant;
use l1::md5;

fn main() {
    println!("=== Quick MD5 Performance Test ===\n");

    let test_message = b"The quick brown fox jumps over the lazy dog";
    
    // Warm-up
    for _ in 0..1000 {
        let _ = md5(test_message);
        let _ = reference_md5::compute(test_message);
    }
    
    // Test with 2^20 iterations (about 1 million)
    let count = 1 << 20;
    println!("Testing with 2^20 = {} iterations", count);
    println!();
    
    // Our implementation
    println!("Our implementation:");
    let start = Instant::now();
    for i in 0..count {
        let msg = format!("{}{}", i, "test");
        let _ = md5(msg.as_bytes());
    }
    let our_duration = start.elapsed();
    let our_per_hash = our_duration.as_secs_f64() / (count as f64);
    println!("  Total time:  {:.3} seconds", our_duration.as_secs_f64());
    println!("  Per hash:    {:.3} μs", our_per_hash * 1_000_000.0);
    println!("  Rate:        {:.0} hashes/sec", 1.0 / our_per_hash);
    println!();
    
    // Reference implementation
    println!("Reference implementation:");
    let start = Instant::now();
    for i in 0..count {
        let msg = format!("{}{}", i, "test");
        let _ = reference_md5::compute(msg.as_bytes());
    }
    let ref_duration = start.elapsed();
    let ref_per_hash = ref_duration.as_secs_f64() / (count as f64);
    println!("  Total time:  {:.3} seconds", ref_duration.as_secs_f64());
    println!("  Per hash:    {:.3} μs", ref_per_hash * 1_000_000.0);
    println!("  Rate:        {:.0} hashes/sec", 1.0 / ref_per_hash);
    println!();
    
    println!("Performance ratio: {:.2}x (our/ref)", our_per_hash / ref_per_hash);
    println!();
    
    // Extrapolate to 2^40
    let target = 1u64 << 40;
    let our_time_2_40 = our_per_hash * (target as f64);
    let ref_time_2_40 = ref_per_hash * (target as f64);
    
    println!("═══ Extrapolation to 2^40 ═══");
    println!("2^40 = 1,099,511,627,776 hashes");
    println!();
    println!("Estimated time:");
    println!("  Our implementation:  {}", format_time(our_time_2_40));
    println!("  Reference:           {}", format_time(ref_time_2_40));
    println!();
    println!("Context:");
    println!("• Wang et al. collision: ~2^39 MD5 calculations (2004)");
    println!("• 2^40 is slightly above Wang's complexity");
}

fn format_time(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.2} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.2} minutes ({:.0} seconds)", seconds / 60.0, seconds)
    } else if seconds < 86400.0 {
        format!("{:.2} hours ({:.0} minutes)", seconds / 3600.0, seconds / 60.0)
    } else if seconds < 31536000.0 {
        format!("{:.2} days ({:.1} hours)", seconds / 86400.0, seconds / 3600.0)
    } else {
        format!("{:.2} years ({:.0} days)", seconds / 31536000.0, seconds / 86400.0)
    }
}
