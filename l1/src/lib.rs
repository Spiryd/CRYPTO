//! # MD5 Hash Function Implementation
//!
//! This is an educational implementation of the MD5 message-digest algorithm
//! as specified in RFC 1321. This implementation is designed for cryptography
//! students studying hash function vulnerabilities and collision attacks.
//!
//! ## ⚠️ Security Warning
//!
//! MD5 is cryptographically broken and unsuitable for further use. This
//! implementation is specifically created for educational purposes to demonstrate:
//! - Hash function internals and implementation details
//! - Vulnerabilities discovered by Xiaoyun Wang et al. in 2004
//! - Collision attack techniques on weak hash functions
//!
//! ## References
//!
//! - RFC 1321: The MD5 Message-Digest Algorithm
//! - Xiaoyun Wang et al. "Collisions for Hash Functions MD4, MD5, HAVAL-128 and RIPEMD" (2004)
//! - Xiaoyun Wang and Hongbo Yu. "How to Break MD5 and Other Hash Functions"
//!
//! ## Implementation Notes
//!
//! This implementation follows RFC 1321 exactly and is designed to be:
//! - Educational and easy to understand
//! - Byte-oriented (works with `&[u8]` input)
//! - Well-documented for learning purposes
//! - Suitable for collision attack research

use std::convert::TryInto;

/// Generate the MD5 constant table using the sine function as specified in RFC 1321.
///
/// The MD5 algorithm uses a 64-element table T where T[i] = floor(2^32 * abs(sin(i+1))).
/// This provides a "random" but reproducible set of constants for the hash rounds.
///
/// # Mathematical Background
///
/// The sine function provides a simple way to generate pseudo-random constants
/// that are reproducible across implementations. The choice of sine is arbitrary
/// but ensures the constants have good statistical properties.
fn table_construction_function(i: u32) -> u32 {
    let x: f64 = i as f64;
    let sin_eval = x.sin().abs();
    // Note: 2^32 = 4294967296
    (4294967296.0 * sin_eval) as u32
}

/// MD5 auxiliary function F used in rounds 1-16.
///
/// F(X,Y,Z) = (X ∧ Y) ∨ (¬X ∧ Z)
///
/// This function acts as a conditional: if X then Y else Z.
/// It's designed to create avalanche effects where small input changes
/// cause large output changes.
fn f(x: u32, y: u32, z: u32) -> u32 {
    x & y | !x & z
}

/// MD5 auxiliary function G used in rounds 17-32.
///
/// G(X,Y,Z) = (X ∧ Z) ∨ (Y ∧ ¬Z)
///
/// This is equivalent to F(Z,X,Y), providing a different mixing pattern
/// to increase diffusion across rounds.
fn g(x: u32, y: u32, z: u32) -> u32 {
    x & z | y & !z
}

/// MD5 auxiliary function H used in rounds 33-48.
///
/// H(X,Y,Z) = X ⊕ Y ⊕ Z
///
/// Simple XOR operation providing linear mixing. This is the fastest
/// of the auxiliary functions but provides less security than F and G.
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// MD5 auxiliary function I used in rounds 49-64.
///
/// I(X,Y,Z) = Y ⊕ (X ∨ ¬Z)
///
/// The most complex auxiliary function, designed to provide maximum
/// diffusion in the final rounds of the hash computation.
fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

/// Utility function to convert a Vec<T> to [T; N].
///
/// This is used internally to convert dynamic vectors to fixed-size arrays
/// required by certain operations. Panics if sizes don't match.
fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|_v: Vec<T>| panic!("error converting vector to array - sizes don't match"))
}

/// Perform MD5 Round 1 operations (steps 1-16).
///
/// Round 1 uses auxiliary function F and specific shift amounts.
/// Each operation follows the pattern:
/// a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
///
/// # Security Note
///
/// Round 1 is particularly vulnerable to differential cryptanalysis
/// due to the properties of function F and the message scheduling.
fn round_one_operations(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    table: &[u32],
    x: &[u32],
) -> [u32; 4] {
    macro_rules! round1 {
        ( $a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i: expr ) => {
            $a = $b.wrapping_add(
                ($a.wrapping_add(f($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(table[$i]))
                .rotate_left($s),
            )
        };
    }

    // Round 1: 16 operations with F function
    // Shift amounts: 7, 12, 17, 22 (repeated 4 times)
    round1!(a, b, c, d, 0, 7, 1);
    round1!(d, a, b, c, 1, 12, 2);
    round1!(c, d, a, b, 2, 17, 3);
    round1!(b, c, d, a, 3, 22, 4);
    round1!(a, b, c, d, 4, 7, 5);
    round1!(d, a, b, c, 5, 12, 6);
    round1!(c, d, a, b, 6, 17, 7);
    round1!(b, c, d, a, 7, 22, 8);
    round1!(a, b, c, d, 8, 7, 9);
    round1!(d, a, b, c, 9, 12, 10);
    round1!(c, d, a, b, 10, 17, 11);
    round1!(b, c, d, a, 11, 22, 12);
    round1!(a, b, c, d, 12, 7, 13);
    round1!(d, a, b, c, 13, 12, 14);
    round1!(c, d, a, b, 14, 17, 15);
    round1!(b, c, d, a, 15, 22, 16);

    [a, b, c, d]
}

/// Perform MD5 Round 2 operations (steps 17-32).
///
/// Round 2 uses auxiliary function G with different message word access pattern.
/// Message words are accessed in the pattern: 1, 6, 11, 0, 5, 10, 15, 4, ...
fn round_two_operations(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    table: &[u32],
    x: &[u32],
) -> [u32; 4] {
    macro_rules! round2 {
        ( $a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i:expr) => {
            $a = $b.wrapping_add(
                ($a.wrapping_add(g($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(table[$i]))
                .rotate_left($s),
            )
        };
    }

    // Round 2: 16 operations with G function
    // Shift amounts: 5, 9, 14, 20 (repeated 4 times)
    round2!(a, b, c, d, 1, 5, 17);
    round2!(d, a, b, c, 6, 9, 18);
    round2!(c, d, a, b, 11, 14, 19);
    round2!(b, c, d, a, 0, 20, 20);
    round2!(a, b, c, d, 5, 5, 21);
    round2!(d, a, b, c, 10, 9, 22);
    round2!(c, d, a, b, 15, 14, 23);
    round2!(b, c, d, a, 4, 20, 24);
    round2!(a, b, c, d, 9, 5, 25);
    round2!(d, a, b, c, 14, 9, 26);
    round2!(c, d, a, b, 3, 14, 27);
    round2!(b, c, d, a, 8, 20, 28);
    round2!(a, b, c, d, 13, 5, 29);
    round2!(d, a, b, c, 2, 9, 30);
    round2!(c, d, a, b, 7, 14, 31);
    round2!(b, c, d, a, 12, 20, 32);

    [a, b, c, d]
}

/// Perform MD5 Round 3 operations (steps 33-48).
///
/// Round 3 uses auxiliary function H with another distinct message access pattern.
/// This round provides linear mixing through XOR operations.
fn round_three_operations(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    table: &[u32],
    x: &[u32],
) -> [u32; 4] {
    macro_rules! round3 {
        ( $a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i:expr  ) => {
            $a = $b.wrapping_add(
                ($a.wrapping_add(h($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(table[$i]))
                .rotate_left($s),
            )
        };
    }

    // Round 3: 16 operations with H function
    // Shift amounts: 4, 11, 16, 23 (repeated 4 times)
    round3!(a, b, c, d, 5, 4, 33);
    round3!(d, a, b, c, 8, 11, 34);
    round3!(c, d, a, b, 11, 16, 35);
    round3!(b, c, d, a, 14, 23, 36);
    round3!(a, b, c, d, 1, 4, 37);
    round3!(d, a, b, c, 4, 11, 38);
    round3!(c, d, a, b, 7, 16, 39);
    round3!(b, c, d, a, 10, 23, 40);
    round3!(a, b, c, d, 13, 4, 41);
    round3!(d, a, b, c, 0, 11, 42);
    round3!(c, d, a, b, 3, 16, 43);
    round3!(b, c, d, a, 6, 23, 44);
    round3!(a, b, c, d, 9, 4, 45);
    round3!(d, a, b, c, 12, 11, 46);
    round3!(c, d, a, b, 15, 16, 47);
    round3!(b, c, d, a, 2, 23, 48);

    [a, b, c, d]
}

/// Perform MD5 Round 4 operations (steps 49-64).
///
/// Round 4 uses auxiliary function I, the most complex function.
/// This final round aims to eliminate any remaining patterns in the hash state.
fn round_four_operations(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    table: &[u32],
    x: &[u32],
) -> [u32; 4] {
    macro_rules! round4 {
        ( $a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i:expr ) => {
            $a = $b.wrapping_add(
                ($a.wrapping_add(i($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(table[$i]))
                .rotate_left($s),
            )
        };
    }

    // Round 4: 16 operations with I function
    // Shift amounts: 6, 10, 15, 21 (repeated 4 times)
    round4!(a, b, c, d, 0, 6, 49);
    round4!(d, a, b, c, 7, 10, 50);
    round4!(c, d, a, b, 14, 15, 51);
    round4!(b, c, d, a, 5, 21, 52);
    round4!(a, b, c, d, 12, 6, 53);
    round4!(d, a, b, c, 3, 10, 54);
    round4!(c, d, a, b, 10, 15, 55);
    round4!(b, c, d, a, 1, 21, 56);
    round4!(a, b, c, d, 8, 6, 57);
    round4!(d, a, b, c, 15, 10, 58);
    round4!(c, d, a, b, 6, 15, 59);
    round4!(b, c, d, a, 13, 21, 60);
    round4!(a, b, c, d, 4, 6, 61);
    round4!(d, a, b, c, 11, 10, 62);
    round4!(c, d, a, b, 2, 15, 63);
    round4!(b, c, d, a, 9, 21, 64);

    [a, b, c, d]
}

/// Convert a chunk of bytes to 32-bit words in little-endian format.
///
/// MD5 processes messages in 512-bit (64-byte) blocks, which are divided
/// into sixteen 32-bit words. This function handles the byte-to-word conversion.
fn convert_u8_chunk_to_u32(chunk: &mut [u8]) -> Vec<u32> {
    let mut x: Vec<u32> = Vec::new();
    let mut count = 0;
    let mut temporary_vec: Vec<u8> = Vec::new();

    // Process 4 bytes at a time to create 32-bit words
    for byte in chunk.iter() {
        temporary_vec.push(*byte);
        count += 1;
        if count == 4 {
            let temp_arr: [u8; 4] = vec_to_array(temporary_vec.clone());
            let value = u32::from_le_bytes(temp_arr); // Little-endian as per RFC
            x.push(value);
            count = 0;
            temporary_vec.clear();
        }
    }
    x
}

/// Core MD5 digest computation function.
///
/// This function processes the padded message in 512-bit blocks and applies
/// the four rounds of MD5 operations to produce the final hash value.
///
/// # Algorithm Overview
///
/// 1. Initialize MD buffer with RFC 1321 constants
/// 2. Process each 512-bit block through 4 rounds (64 operations total)
/// 3. Add the original buffer values (Davies-Meyer construction)
/// 4. Return the final 128-bit result as a byte array
fn compute_md5_digest(mut v: Vec<u8>) -> [u8; 16] {
    // RFC 1321 specified initialization vectors
    // These provide the initial hash state
    let mut word_a: u32 = 0x67452301;
    let mut word_b: u32 = 0xefcdab89;
    let mut word_c: u32 = 0x98badcfe;
    let mut word_d: u32 = 0x10325476;

    // Generate the 64-element constant table
    let table = construct_value_table();

    // Process message in 512-bit (64-byte) chunks
    for chunk in v.chunks_exact_mut(64) {
        let x = convert_u8_chunk_to_u32(chunk);

        // Save original values for Davies-Meyer construction
        let word_aa = word_a;
        let word_bb = word_b;
        let word_cc = word_c;
        let word_dd = word_d;

        // Execute the four rounds of MD5
        let result = round_one_operations(word_a, word_b, word_c, word_d, &table, &x);
        word_a = result[0];
        word_b = result[1];
        word_c = result[2];
        word_d = result[3];

        let result = round_two_operations(word_a, word_b, word_c, word_d, &table, &x);
        word_a = result[0];
        word_b = result[1];
        word_c = result[2];
        word_d = result[3];

        let result = round_three_operations(word_a, word_b, word_c, word_d, &table, &x);
        word_a = result[0];
        word_b = result[1];
        word_c = result[2];
        word_d = result[3];

        let result = round_four_operations(word_a, word_b, word_c, word_d, &table, &x);
        word_a = result[0];
        word_b = result[1];
        word_c = result[2];
        word_d = result[3];

        // Davies-Meyer construction: add original values
        word_a = word_a.wrapping_add(word_aa);
        word_b = word_b.wrapping_add(word_bb);
        word_c = word_c.wrapping_add(word_cc);
        word_d = word_d.wrapping_add(word_dd);
    }

    // Return as 128-bit byte array (little-endian byte order)
    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&word_a.swap_bytes().to_be_bytes());
    result[4..8].copy_from_slice(&word_b.swap_bytes().to_be_bytes());
    result[8..12].copy_from_slice(&word_c.swap_bytes().to_be_bytes());
    result[12..16].copy_from_slice(&word_d.swap_bytes().to_be_bytes());
    result
}

/// Apply MD5 padding to the input message.
///
/// # Padding Algorithm (RFC 1321)
///
/// 1. Append a single '1' bit to the message
/// 2. Append '0' bits until message length ≡ 448 (mod 512)
/// 3. Append the original message length as a 64-bit little-endian integer
///
/// # Security Implications
///
/// The padding scheme ensures messages are always a multiple of 512 bits,
/// but also creates vulnerabilities exploited in length extension attacks
/// and collision generation techniques.
fn bit_padding(input: &[u8]) -> Vec<u8> {
    let mut input_vector: Vec<u8> = input.to_vec();
    let bit_length: u64 = (input.len() as u64) * 8u64;

    // Step 1: Append the '1' bit (0x80 = 10000000 in binary)
    input_vector.push(0x80);

    // Step 2: Pad with zeros until length ≡ 448 (mod 512) bits
    while (input_vector.len() * 8) % 512 != 448 {
        input_vector.push(0x00);
    }

    // Step 3: Append original length as 64-bit little-endian
    let length_bits_as_u8_array = split_u64_to_u8_array(bit_length);
    input_vector.extend(length_bits_as_u8_array);

    input_vector
}

/// Split a 64-bit integer into 8 bytes in little-endian order.
///
/// This is used for appending the message length in the padding step.
fn split_u64_to_u8_array(s: u64) -> [u8; 8] {
    [
        s as u8, // Least significant byte
        (s >> 8) as u8,
        (s >> 16) as u8,
        (s >> 24) as u8,
        (s >> 32) as u8,
        (s >> 40) as u8,
        (s >> 48) as u8,
        (s >> 56) as u8, // Most significant byte
    ]
}

/// Construct the MD5 constant table using the sine function.
///
/// The table T has 65 elements (T[0] = 0, T[1] through T[64] from sine).
/// This provides the additive constants used in each of the 64 MD5 operations.
fn construct_value_table() -> Vec<u32> {
    let mut t: Vec<u32> = Vec::new();
    t.push(0x00000000); // T[0] is not used, but we include it for indexing convenience
    for i in 1..=64 {
        t.push(table_construction_function(i));
    }
    t
}

/// Compute the MD5 hash of a byte slice.
///
/// This is the main public interface for the MD5 hash function.
///
/// # Parameters
///
/// * `input` - A byte slice containing the data to hash
///
/// # Returns
///
/// A 16-byte array representing the 128-bit MD5 hash
///
/// # Example
///
/// ```rust
/// use l1::{md5, md5_to_hex};
///
/// let hash = md5(b"Hello, world!");
/// println!("MD5: {}", md5_to_hex(&hash));
/// // Or use raw bytes for comparison, etc.
/// assert_eq!(hash.len(), 16);
/// ```
///
/// # Educational Use
///
/// This implementation is designed for studying:
/// - Hash function construction and properties
/// - Merkle-Damgård construction vulnerabilities
/// - Collision attack techniques (Wang et al., 2004)
/// - Differential cryptanalysis of hash functions
///
/// # Security Note
///
/// **DO NOT USE FOR CRYPTOGRAPHIC PURPOSES**
///
/// MD5 is broken and has known collision attacks. This implementation
/// exists solely for educational purposes in cryptography courses.
pub fn md5(input: &[u8]) -> [u8; 16] {
    let input_vec = bit_padding(input);
    compute_md5_digest(input_vec)
}

/// Convert MD5 hash bytes to hexadecimal string.
///
/// # Parameters
///
/// * `hash` - A 16-byte MD5 hash
///
/// # Returns
///
/// A 32-character lowercase hexadecimal string
///
/// # Example
///
/// ```rust
/// use l1::{md5, md5_to_hex};
///
/// let hash = md5(b"abc");
/// assert_eq!(md5_to_hex(&hash), "900150983cd24fb0d6963f7d28e17f72");
/// ```
pub fn md5_to_hex(hash: &[u8; 16]) -> String {
    hash.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}
