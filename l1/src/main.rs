use l1::md5;

fn main() {
    println!("=== MD5 Hash Function Demo ===");
    println!("⚠️  Educational Use Only - MD5 is Cryptographically Broken ⚠️");
    println!();

    // Example: Convert string to bytes for hashing
    let message = "Hello, world!";
    let digest = md5(message.as_bytes());
    println!("MD5('{}') = {}", message, digest);

    // Example: Direct byte array usage
    let byte_data = b"Hello, world!";
    let digest2 = md5(byte_data);
    println!("MD5(b'Hello, world!') = {}", digest2);

    // Example: Custom byte array
    let custom_bytes = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello" in ASCII
    let digest3 = md5(&custom_bytes);
    println!("MD5([0x48, 0x65, 0x6c, 0x6c, 0x6f]) = {}", digest3);

    // Quick verification against reference implementation
    #[cfg(debug_assertions)]
    {
        use reference_md5;
        println!();
        println!("=== Quick Verification ===");
        let test_cases = [
            b"" as &[u8],
            b"a",
            b"abc",
            b"The quick brown fox jumps over the lazy dog",
        ];

        for input in &test_cases {
            let our_result = md5(input);
            let reference_result = format!("{:x}", reference_md5::compute(input));
            let status = if our_result == reference_result {
                "✓"
            } else {
                "✗"
            };
            println!("{} MD5({:?})", status, String::from_utf8_lossy(input));
            println!("  Our result: {}", our_result);
            println!("  Reference:  {}", reference_result);
        }
    }

    // Demonstrate collision vulnerability context
    println!();
    println!("=== Collision Attack Context ===");
    println!("This implementation can be used to study:");
    println!("• Wang et al. collision attacks (2004)");
    println!("• Differential cryptanalysis techniques");
    println!("• Hash function vulnerability research");

    // Example of different inputs producing different hashes (no collision demo here)
    let msg1 = b"message1";
    let msg2 = b"message2";
    println!();
    println!("MD5('message1') = {}", md5(msg1));
    println!("MD5('message2') = {}", md5(msg2));
    println!("(Different inputs should produce different hashes)");
}
