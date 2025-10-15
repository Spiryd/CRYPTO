use l1::{md5, md5_to_hex};

/// Comprehensive comparison tests between our MD5 implementation and the official md5 crate.
/// This ensures our educational implementation produces identical results to the reference implementation.

#[cfg(test)]
mod comparison_tests {
    use super::*;

    /// Helper function to compare our implementation with the reference md5 crate
    fn compare_implementations(input: &[u8]) {
        let our_result = md5_to_hex(&md5(input));
        let reference_result = format!("{:x}", reference_md5::compute(input));

        assert_eq!(
            our_result, reference_result,
            "Mismatch for input: {:?}. Our: {}, Reference: {}",
            input, our_result, reference_result
        );
    }

    #[test]
    fn test_rfc1321_official_vectors() {
        // These are the official test vectors from RFC 1321

        // Test vector 1: Empty string
        compare_implementations(b"");

        // Test vector 2: Single character
        compare_implementations(b"a");

        // Test vector 3: Three characters
        compare_implementations(b"abc");

        // Test vector 4: Message digest string
        compare_implementations(b"message digest");

        // Test vector 5: Alphabet
        compare_implementations(b"abcdefghijklmnopqrstuvwxyz");

        // Test vector 6: Alphanumeric
        compare_implementations(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");

        // Test vector 7: 80 digit string
        compare_implementations(b"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
    }

    #[test]
    fn test_boundary_conditions() {
        // Test various message lengths around padding boundaries

        // Messages that test padding behavior
        let test_cases: &[&[u8]] = &[
            b"",                                                                      // 0 bytes
            b"a",                                                                     // 1 byte
            b"ab",                                                                    // 2 bytes
            b"abc",                                                                   // 3 bytes
            b"abcd",                                                                  // 4 bytes
            b"abcdefghijklmnopqrstuvwxyz",                                            // 26 bytes
            b"The quick brown fox jumps over the lazy dog",                           // 43 bytes
            b"1234567890123456789012345678901234567890123456789012345",               // 55 bytes
            b"1234567890123456789012345678901234567890123456789012345678", // 56 bytes (448 bits)
            b"123456789012345678901234567890123456789012345678901234567890", // 57 bytes
            b"12345678901234567890123456789012345678901234567890123456789012345678", // 64 bytes (512 bits)
            b"123456789012345678901234567890123456789012345678901234567890123456789", // 65 bytes
        ];

        for input in test_cases {
            compare_implementations(input);
        }
    }

    #[test]
    fn test_binary_data() {
        // Test with various binary data patterns

        // All zeros
        let zeros = vec![0u8; 64];
        compare_implementations(&zeros);

        // All ones
        let ones = vec![0xFFu8; 64];
        compare_implementations(&ones);

        // Alternating pattern
        let alternating: Vec<u8> = (0..64)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect();
        compare_implementations(&alternating);

        // Sequential bytes
        let sequential: Vec<u8> = (0..=255).collect();
        compare_implementations(&sequential);

        // Random-looking but deterministic pattern
        let pattern: Vec<u8> = (0..100).map(|i| ((i * 17 + 42) % 256) as u8).collect();
        compare_implementations(&pattern);
    }

    #[test]
    fn test_null_bytes_and_special_chars() {
        // Test with null bytes and special characters

        compare_implementations(b"\x00");
        compare_implementations(b"\x00\x00\x00\x00");
        compare_implementations(b"\x01\x02\x03\x04");
        compare_implementations(b"\xFF\xFE\xFD\xFC");
        compare_implementations(b"Hello\x00World");
        compare_implementations(
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        );
    }

    #[test]
    fn test_unicode_strings() {
        // Test with UTF-8 encoded strings (converted to bytes)

        let test_strings = [
            "Hello, 世界!",        // Mixed ASCII and Chinese
            "🦀 Rust Programming", // Emoji
            "Café résumé naïve",   // Accented characters
            "Здравствуй мир",      // Cyrillic
            "مرحبا بالعالم",       // Arabic
            "שלום עולם",           // Hebrew
        ];

        for s in &test_strings {
            compare_implementations(s.as_bytes());
        }
    }

    #[test]
    fn test_large_messages() {
        // Test with larger messages to ensure multi-block processing works correctly

        // 1KB message
        let kb_message = "A".repeat(1024);
        compare_implementations(kb_message.as_bytes());

        // 4KB message
        let large_message = "The quick brown fox jumps over the lazy dog. ".repeat(100);
        compare_implementations(large_message.as_bytes());

        // Message with multiple 512-bit blocks
        let multi_block = "0123456789".repeat(200); // 2000 bytes
        compare_implementations(multi_block.as_bytes());
    }

    #[test]
    fn test_edge_cases_for_collision_research() {
        // Test cases specifically useful for collision attack research

        // Messages that might be used in collision attack studies
        let collision_research_vectors: &[&[u8]] = &[
            b"collision",
            b"different",
            b"message1",
            b"message2",
            b"prefix_a",
            b"prefix_b",
            b"test_vector_1",
            b"test_vector_2",
        ];

        for input in collision_research_vectors {
            compare_implementations(input);
        }

        // Test with structured data that might appear in collision attacks
        let structured_data = b"\x4d\x7a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";
        compare_implementations(structured_data);
    }

    #[test]
    fn test_performance_comparison() {
        // Not a correctness test, but useful for performance analysis
        use std::time::Instant;

        let test_data = b"The quick brown fox jumps over the lazy dog";
        let iterations = 1000;

        // Time our implementation
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = md5(test_data);
        }
        let our_duration = start.elapsed();

        // Time reference implementation
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = reference_md5::compute(test_data);
        }
        let ref_duration = start.elapsed();

        println!("Performance comparison ({}x iterations):", iterations);
        println!("Our implementation: {:?}", our_duration);
        println!("Reference md5 crate: {:?}", ref_duration);
        println!(
            "Ratio: {:.2}x",
            our_duration.as_nanos() as f64 / ref_duration.as_nanos() as f64
        );

        // Ensure both produce the same result
        compare_implementations(test_data);
    }

    #[test]
    fn test_deterministic_behavior() {
        // Ensure our implementation is deterministic (always produces same output for same input)

        let test_inputs: &[&[u8]] = &[
            b"deterministic test 1",
            b"deterministic test 2",
            b"deterministic test 3",
        ];

        for input in test_inputs {
            let result1 = md5(input);
            let result2 = md5(input);
            let result3 = md5(input);

            assert_eq!(result1, result2);
            assert_eq!(result2, result3);

            // Also compare with reference
            compare_implementations(input);
        }
    }

    #[test]
    fn test_known_md5_hashes() {
        // Test against some well-known MD5 hashes for extra verification

        struct KnownHash {
            input: &'static [u8],
            expected: &'static str,
        }

        let known_hashes = [
            KnownHash {
                input: b"",
                expected: "d41d8cd98f00b204e9800998ecf8427e",
            },
            KnownHash {
                input: b"The quick brown fox jumps over the lazy dog",
                expected: "9e107d9d372bb6826bd81d3542a419d6",
            },
            KnownHash {
                input: b"The quick brown fox jumps over the lazy dog.",
                expected: "e4d909c290d0fb1ca068ffaddf22cbd0",
            },
            KnownHash {
                input: b"abc",
                expected: "900150983cd24fb0d6963f7d28e17f72",
            },
        ];

        for hash in &known_hashes {
            let our_result = md5_to_hex(&md5(hash.input));
            let ref_result = format!("{:x}", reference_md5::compute(hash.input));

            assert_eq!(
                our_result, hash.expected,
                "Our result doesn't match expected for: {:?}",
                hash.input
            );
            assert_eq!(
                ref_result, hash.expected,
                "Reference result doesn't match expected for: {:?}",
                hash.input
            );
            assert_eq!(
                our_result, ref_result,
                "Our result doesn't match reference for: {:?}",
                hash.input
            );
        }
    }

    #[test]
    fn test_comprehensive_verification_summary() {
        // A summary test that demonstrates key verification points

        println!("\n=== COMPREHENSIVE VERIFICATION SUMMARY ===");

        // RFC 1321 official test vectors
        let rfc_vectors = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
        ];

        println!("✓ RFC 1321 Test Vectors:");
        for (input, expected) in &rfc_vectors {
            let our_result = md5_to_hex(&md5(input.as_bytes()));
            let ref_result = format!("{:x}", reference_md5::compute(input.as_bytes()));

            assert_eq!(our_result, *expected);
            assert_eq!(ref_result, *expected);
            assert_eq!(our_result, ref_result);

            println!("  MD5('{}') = {} ✓", input, our_result);
        }

        // Edge cases
        println!("\n✓ Boundary Conditions:");
        let boundary_cases = [
            (55, "55 bytes (just before 448-bit boundary)"),
            (56, "56 bytes (exactly 448 bits)"),
            (64, "64 bytes (exactly 512 bits)"),
        ];

        for (length, description) in &boundary_cases {
            let input = "A".repeat(*length);
            let our_result = md5_to_hex(&md5(input.as_bytes()));
            let ref_result = format!("{:x}", reference_md5::compute(input.as_bytes()));

            assert_eq!(our_result, ref_result);
            println!("  {} = {} ✓", description, &our_result[..16]);
        }

        // Binary data
        println!("\n✓ Binary Data:");
        let binary_tests = [
            (vec![0u8; 32], "32 zero bytes"),
            (vec![0xFFu8; 32], "32 0xFF bytes"),
            ((0..=255u8).collect::<Vec<u8>>(), "Sequential 0-255"),
        ];

        for (input, description) in &binary_tests {
            let our_result = md5_to_hex(&md5(input));
            let ref_result = format!("{:x}", reference_md5::compute(input));

            assert_eq!(our_result, ref_result);
            println!("  {} = {} ✓", description, &our_result[..16]);
        }

        println!(
            "\n🎉 ALL TESTS PASSED! Our implementation matches the reference MD5 crate perfectly."
        );
        println!("📚 This validates the correctness of our educational MD5 implementation.");
        println!("🔬 Ready for collision attack research and cryptographic analysis!");
    }
}
