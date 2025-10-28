use l1::collision::{verify_collision, CollisionVerifier, parse_hex_block};
use l1::InitialValues;

#[test]
fn test_collision_same_messages() {
    // Same messages should always collide
    let iv = InitialValues::STANDARD;
    let m0 = b"test1";
    let m1 = b"test2";
    
    let result = verify_collision(iv, m0, m0, m1, m1);
    assert!(result.is_collision);
    assert_eq!(result.h_hex, result.h_prime_hex);
}

#[test]
fn test_collision_different_random_messages() {
    // Random different messages should not collide
    let iv = InitialValues::STANDARD;
    let m0 = b"message A";
    let m0_prime = b"message B";
    let m1 = b"continuation";
    let m1_prime = b"different";
    
    let result = verify_collision(iv, m0, m0_prime, m1, m1_prime);
    assert!(!result.is_collision);
    assert_ne!(result.h_hex, result.h_prime_hex);
}

#[test]
fn test_known_single_block_collision() {
    // This is a known single-block MD5 collision from Wang's attack
    // M0 and M'0 differ in only 2 bytes but produce the same MD5 hash
    let iv = InitialValues::STANDARD;
    
    let m0_hex = "4dc968ff0ee35c209572d4777b721587\
                  d36fa7b21bdc56b74a3dc0783e7b9518\
                  afbfa200a8284bf36e8e4b55b35f4275\
                  93d849676da0d1555d8360fb5f07fea2";
    
    let m0_prime_hex = "4dc968ff0ee35c209572d4777b721587\
                        d36fa7b21bdc56b74a3dc0783e7b9518\
                        afbfa202a8284bf36e8e4b55b35f4275\
                        93d849676da0d1d55d8360fb5f07fea2";
    
    let m0 = parse_hex_block(m0_hex).unwrap();
    let m0_prime = parse_hex_block(m0_prime_hex).unwrap();
    
    // For a single-block collision, we verify that MD5(IV, M0) == MD5(IV, M'0)
    let verifier = CollisionVerifier::new(iv);
    let iv0 = verifier.compute_iv(&m0);
    let iv0_prime = verifier.compute_iv(&m0_prime);
    
    // The intermediate values should be identical
    assert_eq!(iv0.a, iv0_prime.a);
    assert_eq!(iv0.b, iv0_prime.b);
    assert_eq!(iv0.c, iv0_prime.c);
    assert_eq!(iv0.d, iv0_prime.d);
}

#[test]
fn test_two_block_collision() {
    // Test the full two-block collision: MD5(MD5(IV, M0), M1) == MD5(MD5(IV, M'0), M'1)
    let iv = InitialValues::STANDARD;
    
    let m0_hex = "4dc968ff0ee35c209572d4777b721587\
                  d36fa7b21bdc56b74a3dc0783e7b9518\
                  afbfa200a8284bf36e8e4b55b35f4275\
                  93d849676da0d1555d8360fb5f07fea2";
    
    let m0_prime_hex = "4dc968ff0ee35c209572d4777b721587\
                        d36fa7b21bdc56b74a3dc0783e7b9518\
                        afbfa202a8284bf36e8e4b55b35f4275\
                        93d849676da0d1d55d8360fb5f07fea2";
    
    // Use same M1 and M'1 (since M0/M'0 already collide, any second block will maintain the collision)
    let m1_hex = "00000000000000000000000000000000\
                  00000000000000000000000000000000\
                  00000000000000000000000000000000\
                  00000000000000000000000000000000";
    
    let m0 = parse_hex_block(m0_hex).unwrap();
    let m0_prime = parse_hex_block(m0_prime_hex).unwrap();
    let m1 = parse_hex_block(m1_hex).unwrap();
    let m1_prime = m1.clone();
    
    let result = verify_collision(iv, &m0, &m0_prime, &m1, &m1_prime);
    
    assert!(result.is_collision);
    assert_eq!(result.h_hex, result.h_prime_hex);
}

#[test]
fn test_parse_hex_block_success() {
    let hex = "0123456789abcdef0123456789abcdef\
               0123456789abcdef0123456789abcdef\
               0123456789abcdef0123456789abcdef\
               0123456789abcdef0123456789abcdef";
    
    let bytes = parse_hex_block(hex).unwrap();
    assert_eq!(bytes.len(), 64);
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1], 0x23);
    assert_eq!(bytes[2], 0x45);
}

#[test]
fn test_parse_hex_block_with_whitespace() {
    let hex = "4d c9 68 ff 0e e3 5c 20\n\
               95 72 d4 77 7b 72 15 87\n\
               d3 6f a7 b2 1b dc 56 b7\n\
               4a 3d c0 78 3e 7b 95 18\n\
               af bf a2 00 a8 28 4b f3\n\
               6e 8e 4b 55 b3 5f 42 75\n\
               93 d8 49 67 6d a0 d1 55\n\
               5d 83 60 fb 5f 07 fe a2";
    
    let bytes = parse_hex_block(hex).unwrap();
    assert_eq!(bytes.len(), 64);
}

#[test]
fn test_parse_hex_block_invalid() {
    let invalid_hex = "not a hex string";
    let result = parse_hex_block(invalid_hex);
    assert!(result.is_err());
}

#[test]
fn test_collision_verifier_step_by_step() {
    let iv = InitialValues::STANDARD;
    let verifier = CollisionVerifier::new(iv);
    
    let m0 = b"block 1";
    let m1 = b"block 2";
    
    // Test step-by-step computation
    let iv0 = verifier.compute_iv(m0);
    let h = verifier.compute_hash(iv0, m1);
    
    // Verify the hash is a valid 128-bit value
    assert_ne!(h, [0, 0, 0, 0]);
    
    // Verify determinism
    let iv0_again = verifier.compute_iv(m0);
    let h_again = verifier.compute_hash(iv0_again, m1);
    assert_eq!(h, h_again);
}

#[test]
fn test_custom_iv_collision_verification() {
    // Test with custom initial values
    let custom_iv = InitialValues::custom(0x12345678, 0x9abcdef0, 0x11111111, 0x22222222);
    
    let m0 = b"test message";
    let m1 = b"second part";
    
    let result = verify_collision(custom_iv, m0, m0, m1, m1);
    
    // Same messages with custom IV should still collide
    assert!(result.is_collision);
    assert_eq!(result.h_hex, result.h_prime_hex);
}
