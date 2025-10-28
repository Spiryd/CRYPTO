use l1::{md5, md5_to_hex, md5_with_iv, InitialValues};

#[test]
fn test_empty_input() {
    let result = md5_to_hex(&md5(b""));
    assert_eq!(result, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn test_custom_initial_values() {
    let input = b"test";
    
    // Standard IV should produce standard MD5
    let standard = md5(input);
    let with_standard_iv = md5_with_iv(input, InitialValues::STANDARD);
    assert_eq!(standard, with_standard_iv, "Standard IV should match regular md5()");
    
    // Custom IV should produce different result
    let custom_iv = InitialValues::custom(0x12345678, 0x9abcdef0, 0x11111111, 0x22222222);
    let with_custom_iv = md5_with_iv(input, custom_iv);
    assert_ne!(standard, with_custom_iv, "Custom IV should produce different hash");
    
    // Same custom IV should be deterministic
    let with_custom_iv2 = md5_with_iv(input, custom_iv);
    assert_eq!(with_custom_iv, with_custom_iv2, "Custom IV should be deterministic");
}

#[test]
fn test_initial_values_struct() {
    // Test standard IV
    let standard = InitialValues::STANDARD;
    assert_eq!(standard.a, 0x67452301);
    assert_eq!(standard.b, 0xefcdab89);
    assert_eq!(standard.c, 0x98badcfe);
    assert_eq!(standard.d, 0x10325476);
    
    // Test custom IV
    let custom = InitialValues::custom(1, 2, 3, 4);
    assert_eq!(custom.a, 1);
    assert_eq!(custom.b, 2);
    assert_eq!(custom.c, 3);
    assert_eq!(custom.d, 4);
    
    // Test default
    let default = InitialValues::default();
    assert_eq!(default, InitialValues::STANDARD);
}

#[test]
fn test_different_ivs_different_outputs() {
    let input = b"collision research";
    
    let iv1 = InitialValues::custom(0x00000000, 0x00000000, 0x00000000, 0x00000000);
    let iv2 = InitialValues::custom(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
    let iv3 = InitialValues::STANDARD;
    
    let hash1 = md5_with_iv(input, iv1);
    let hash2 = md5_with_iv(input, iv2);
    let hash3 = md5_with_iv(input, iv3);
    
    // All should be different
    assert_ne!(hash1, hash2);
    assert_ne!(hash2, hash3);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_single_character() {
    let result = md5_to_hex(&md5(b"a"));
    assert_eq!(result, "0cc175b9c0f1b6a831c399e269772661");
}

#[test]
fn test_abc() {
    let result = md5_to_hex(&md5(b"abc"));
    assert_eq!(result, "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn test_hello_world() {
    let result = md5_to_hex(&md5(b"Hello, world!"));
    assert_eq!(result, "6cd3556deb0da54bca060b4c39479839");
}

#[test]
fn test_longer_message() {
    let result = md5_to_hex(&md5(b"The quick brown fox jumps over the lazy dog"));
    assert_eq!(result, "9e107d9d372bb6826bd81d3542a419d6");
}

#[test]
fn test_56_bytes() {
    // Test padding boundary condition (56 bytes = 448 bits)
    let input = b"1234567890123456789012345678901234567890123456789012345678";
    let result = md5_to_hex(&md5(input));
    assert_eq!(result, "69328a851f0c7bc2a581a841f50a3bf2");
}

#[test]
fn test_numeric_data() {
    let data: Vec<u8> = (0..=255u8).collect();
    let result = md5_to_hex(&md5(&data));
    // This should produce a consistent hash for bytes 0-255
    assert_eq!(result, "e2c865db4162bed963bfaa9ef6ac18f0");
}

#[test]
fn test_null_bytes() {
    let result = md5_to_hex(&md5(b"\x00\x00\x00\x00"));
    assert_eq!(result, "f1d3ff8443297732862df21dc4e57262");
}

#[test]
fn test_binary_data() {
    let binary_data = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
    let result = md5_to_hex(&md5(&binary_data));
    assert_eq!(result, "fb7bc54a30997169c1d8f751046dfb69");
}

#[test]
fn test_consistency() {
    let data = b"test message";
    let result1 = md5(data);
    let result2 = md5(data);
    assert_eq!(result1, result2, "MD5 should be deterministic");
}

#[test]
fn test_from_string_conversion() {
    let message = "Hello, Rust!";
    let result = md5_to_hex(&md5(message.as_bytes()));
    // Users should convert strings to bytes like this
    assert_eq!(result, "9369f0626346def098fb689eb26cc34f");
}

#[test]
fn test_bit_padding() {
    // Internal functions are intentionally kept private; this test validates
    // padding behavior indirectly via known hash outputs for varying lengths.
    
    // Test that different length inputs are properly handled
    let input1 = b"a"; // 1 byte
    let input2 = b"ab"; // 2 bytes  
    let input3 = b"abc"; // 3 bytes (our test case)
    
    // All should produce valid hashes
    assert_eq!(md5_to_hex(&md5(input1)), "0cc175b9c0f1b6a831c399e269772661");
    assert_eq!(md5_to_hex(&md5(input2)), "187ef4436122d1cc2f40dc2b92f0eba0");
    assert_eq!(md5_to_hex(&md5(input3)), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn test_collision_research_vectors() {
    // Test vectors useful for studying collision attacks
    
    // Known MD5 test vectors from RFC 1321
    assert_eq!(md5_to_hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5_to_hex(&md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
    assert_eq!(md5_to_hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(md5_to_hex(&md5(b"message digest")), "f96b697d7cb7938d525a2f31aaf161d0");
    assert_eq!(md5_to_hex(&md5(b"abcdefghijklmnopqrstuvwxyz")), "c3fcd3d76192e4007dfb496cca67e13b");
    
    // These vectors are important for understanding MD5's behavior
    // and can be used as baseline for collision attack studies
}