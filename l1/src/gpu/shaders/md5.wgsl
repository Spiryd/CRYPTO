//! MD5 Hash Function in WGSL for GPU Acceleration
//!
//! Complete implementation of RFC 1321 MD5 algorithm for GPU-accelerated
//! collision search in Wang's attack Step 2.
//!
//! This shader can process millions of MD5 computations per second,
//! significantly faster than CPU-only implementations.

// ============================================================================
// MD5 Constants
// ============================================================================

// MD5 round constants (T[i] = floor(2^32 * abs(sin(i)))) precomputed
const T: array<u32, 65> = array<u32, 65>(
    0x00000000u, // T[0] unused
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, // Round 1
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, // Round 2
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, // Round 3
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, // Round 4
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
);

// MD5 standard initial values (IV)
const IV_A: u32 = 0x67452301u;
const IV_B: u32 = 0xefcdab89u;
const IV_C: u32 = 0x98badcfeu;
const IV_D: u32 = 0x10325476u;

// ============================================================================
// MD5 Auxiliary Functions
// ============================================================================

// F(X,Y,Z) = (X & Y) | (~X & Z)
fn md5_f(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) | (~x & z);
}

// G(X,Y,Z) = (X & Z) | (Y & ~Z)
fn md5_g(x: u32, y: u32, z: u32) -> u32 {
    return (x & z) | (y & ~z);
}

// H(X,Y,Z) = X ^ Y ^ Z
fn md5_h(x: u32, y: u32, z: u32) -> u32 {
    return x ^ y ^ z;
}

// I(X,Y,Z) = Y ^ (X | ~Z)
fn md5_i(x: u32, y: u32, z: u32) -> u32 {
    return y ^ (x | ~z);
}

// ============================================================================
// MD5 Core Computation
// ============================================================================

struct MD5State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

// Process a single 512-bit block through MD5
fn md5_process_block(iv: MD5State, block: array<u32, 16>) -> MD5State {
    var a = iv.a;
    var b = iv.b;
    var c = iv.c;
    var d = iv.d;
    
    // Save original values for Davies-Meyer
    let aa = a;
    let bb = b;
    let cc = c;
    let dd = d;
    
    // ========================================================================
    // Round 1: F function, shift amounts [7, 12, 17, 22]
    // ========================================================================
    
    // Operations 1-4
    a = b + ((a + md5_f(b, c, d) + block[0] + T[1]) << 7u | (a + md5_f(b, c, d) + block[0] + T[1]) >> 25u);
    d = a + ((d + md5_f(a, b, c) + block[1] + T[2]) << 12u | (d + md5_f(a, b, c) + block[1] + T[2]) >> 20u);
    c = d + ((c + md5_f(d, a, b) + block[2] + T[3]) << 17u | (c + md5_f(d, a, b) + block[2] + T[3]) >> 15u);
    b = c + ((b + md5_f(c, d, a) + block[3] + T[4]) << 22u | (b + md5_f(c, d, a) + block[3] + T[4]) >> 10u);
    
    // Operations 5-8
    a = b + ((a + md5_f(b, c, d) + block[4] + T[5]) << 7u | (a + md5_f(b, c, d) + block[4] + T[5]) >> 25u);
    d = a + ((d + md5_f(a, b, c) + block[5] + T[6]) << 12u | (d + md5_f(a, b, c) + block[5] + T[6]) >> 20u);
    c = d + ((c + md5_f(d, a, b) + block[6] + T[7]) << 17u | (c + md5_f(d, a, b) + block[6] + T[7]) >> 15u);
    b = c + ((b + md5_f(c, d, a) + block[7] + T[8]) << 22u | (b + md5_f(c, d, a) + block[7] + T[8]) >> 10u);
    
    // Operations 9-12
    a = b + ((a + md5_f(b, c, d) + block[8] + T[9]) << 7u | (a + md5_f(b, c, d) + block[8] + T[9]) >> 25u);
    d = a + ((d + md5_f(a, b, c) + block[9] + T[10]) << 12u | (d + md5_f(a, b, c) + block[9] + T[10]) >> 20u);
    c = d + ((c + md5_f(d, a, b) + block[10] + T[11]) << 17u | (c + md5_f(d, a, b) + block[10] + T[11]) >> 15u);
    b = c + ((b + md5_f(c, d, a) + block[11] + T[12]) << 22u | (b + md5_f(c, d, a) + block[11] + T[12]) >> 10u);
    
    // Operations 13-16
    a = b + ((a + md5_f(b, c, d) + block[12] + T[13]) << 7u | (a + md5_f(b, c, d) + block[12] + T[13]) >> 25u);
    d = a + ((d + md5_f(a, b, c) + block[13] + T[14]) << 12u | (d + md5_f(a, b, c) + block[13] + T[14]) >> 20u);
    c = d + ((c + md5_f(d, a, b) + block[14] + T[15]) << 17u | (c + md5_f(d, a, b) + block[14] + T[15]) >> 15u);
    b = c + ((b + md5_f(c, d, a) + block[15] + T[16]) << 22u | (b + md5_f(c, d, a) + block[15] + T[16]) >> 10u);
    
    // ========================================================================
    // Round 2: G function, shift amounts [5, 9, 14, 20]
    // ========================================================================
    
    // Operations 17-20
    a = b + ((a + md5_g(b, c, d) + block[1] + T[17]) << 5u | (a + md5_g(b, c, d) + block[1] + T[17]) >> 27u);
    d = a + ((d + md5_g(a, b, c) + block[6] + T[18]) << 9u | (d + md5_g(a, b, c) + block[6] + T[18]) >> 23u);
    c = d + ((c + md5_g(d, a, b) + block[11] + T[19]) << 14u | (c + md5_g(d, a, b) + block[11] + T[19]) >> 18u);
    b = c + ((b + md5_g(c, d, a) + block[0] + T[20]) << 20u | (b + md5_g(c, d, a) + block[0] + T[20]) >> 12u);
    
    // Operations 21-24
    a = b + ((a + md5_g(b, c, d) + block[5] + T[21]) << 5u | (a + md5_g(b, c, d) + block[5] + T[21]) >> 27u);
    d = a + ((d + md5_g(a, b, c) + block[10] + T[22]) << 9u | (d + md5_g(a, b, c) + block[10] + T[22]) >> 23u);
    c = d + ((c + md5_g(d, a, b) + block[15] + T[23]) << 14u | (c + md5_g(d, a, b) + block[15] + T[23]) >> 18u);
    b = c + ((b + md5_g(c, d, a) + block[4] + T[24]) << 20u | (b + md5_g(c, d, a) + block[4] + T[24]) >> 12u);
    
    // Operations 25-28
    a = b + ((a + md5_g(b, c, d) + block[9] + T[25]) << 5u | (a + md5_g(b, c, d) + block[9] + T[25]) >> 27u);
    d = a + ((d + md5_g(a, b, c) + block[14] + T[26]) << 9u | (d + md5_g(a, b, c) + block[14] + T[26]) >> 23u);
    c = d + ((c + md5_g(d, a, b) + block[3] + T[27]) << 14u | (c + md5_g(d, a, b) + block[3] + T[27]) >> 18u);
    b = c + ((b + md5_g(c, d, a) + block[8] + T[28]) << 20u | (b + md5_g(c, d, a) + block[8] + T[28]) >> 12u);
    
    // Operations 29-32
    a = b + ((a + md5_g(b, c, d) + block[13] + T[29]) << 5u | (a + md5_g(b, c, d) + block[13] + T[29]) >> 27u);
    d = a + ((d + md5_g(a, b, c) + block[2] + T[30]) << 9u | (d + md5_g(a, b, c) + block[2] + T[30]) >> 23u);
    c = d + ((c + md5_g(d, a, b) + block[7] + T[31]) << 14u | (c + md5_g(d, a, b) + block[7] + T[31]) >> 18u);
    b = c + ((b + md5_g(c, d, a) + block[12] + T[32]) << 20u | (b + md5_g(c, d, a) + block[12] + T[32]) >> 12u);
    
    // ========================================================================
    // Round 3: H function, shift amounts [4, 11, 16, 23]
    // ========================================================================
    
    // Operations 33-36
    a = b + ((a + md5_h(b, c, d) + block[5] + T[33]) << 4u | (a + md5_h(b, c, d) + block[5] + T[33]) >> 28u);
    d = a + ((d + md5_h(a, b, c) + block[8] + T[34]) << 11u | (d + md5_h(a, b, c) + block[8] + T[34]) >> 21u);
    c = d + ((c + md5_h(d, a, b) + block[11] + T[35]) << 16u | (c + md5_h(d, a, b) + block[11] + T[35]) >> 16u);
    b = c + ((b + md5_h(c, d, a) + block[14] + T[36]) << 23u | (b + md5_h(c, d, a) + block[14] + T[36]) >> 9u);
    
    // Operations 37-40
    a = b + ((a + md5_h(b, c, d) + block[1] + T[37]) << 4u | (a + md5_h(b, c, d) + block[1] + T[37]) >> 28u);
    d = a + ((d + md5_h(a, b, c) + block[4] + T[38]) << 11u | (d + md5_h(a, b, c) + block[4] + T[38]) >> 21u);
    c = d + ((c + md5_h(d, a, b) + block[7] + T[39]) << 16u | (c + md5_h(d, a, b) + block[7] + T[39]) >> 16u);
    b = c + ((b + md5_h(c, d, a) + block[10] + T[40]) << 23u | (b + md5_h(c, d, a) + block[10] + T[40]) >> 9u);
    
    // Operations 41-44
    a = b + ((a + md5_h(b, c, d) + block[13] + T[41]) << 4u | (a + md5_h(b, c, d) + block[13] + T[41]) >> 28u);
    d = a + ((d + md5_h(a, b, c) + block[0] + T[42]) << 11u | (d + md5_h(a, b, c) + block[0] + T[42]) >> 21u);
    c = d + ((c + md5_h(d, a, b) + block[3] + T[43]) << 16u | (c + md5_h(d, a, b) + block[3] + T[43]) >> 16u);
    b = c + ((b + md5_h(c, d, a) + block[6] + T[44]) << 23u | (b + md5_h(c, d, a) + block[6] + T[44]) >> 9u);
    
    // Operations 45-48
    a = b + ((a + md5_h(b, c, d) + block[9] + T[45]) << 4u | (a + md5_h(b, c, d) + block[9] + T[45]) >> 28u);
    d = a + ((d + md5_h(a, b, c) + block[12] + T[46]) << 11u | (d + md5_h(a, b, c) + block[12] + T[46]) >> 21u);
    c = d + ((c + md5_h(d, a, b) + block[15] + T[47]) << 16u | (c + md5_h(d, a, b) + block[15] + T[47]) >> 16u);
    b = c + ((b + md5_h(c, d, a) + block[2] + T[48]) << 23u | (b + md5_h(c, d, a) + block[2] + T[48]) >> 9u);
    
    // ========================================================================
    // Round 4: I function, shift amounts [6, 10, 15, 21]
    // ========================================================================
    
    // Operations 49-52
    a = b + ((a + md5_i(b, c, d) + block[0] + T[49]) << 6u | (a + md5_i(b, c, d) + block[0] + T[49]) >> 26u);
    d = a + ((d + md5_i(a, b, c) + block[7] + T[50]) << 10u | (d + md5_i(a, b, c) + block[7] + T[50]) >> 22u);
    c = d + ((c + md5_i(d, a, b) + block[14] + T[51]) << 15u | (c + md5_i(d, a, b) + block[14] + T[51]) >> 17u);
    b = c + ((b + md5_i(c, d, a) + block[5] + T[52]) << 21u | (b + md5_i(c, d, a) + block[5] + T[52]) >> 11u);
    
    // Operations 53-56
    a = b + ((a + md5_i(b, c, d) + block[12] + T[53]) << 6u | (a + md5_i(b, c, d) + block[12] + T[53]) >> 26u);
    d = a + ((d + md5_i(a, b, c) + block[3] + T[54]) << 10u | (d + md5_i(a, b, c) + block[3] + T[54]) >> 22u);
    c = d + ((c + md5_i(d, a, b) + block[10] + T[55]) << 15u | (c + md5_i(d, a, b) + block[10] + T[55]) >> 17u);
    b = c + ((b + md5_i(c, d, a) + block[1] + T[56]) << 21u | (b + md5_i(c, d, a) + block[1] + T[56]) >> 11u);
    
    // Operations 57-60
    a = b + ((a + md5_i(b, c, d) + block[8] + T[57]) << 6u | (a + md5_i(b, c, d) + block[8] + T[57]) >> 26u);
    d = a + ((d + md5_i(a, b, c) + block[15] + T[58]) << 10u | (d + md5_i(a, b, c) + block[15] + T[58]) >> 22u);
    c = d + ((c + md5_i(d, a, b) + block[6] + T[59]) << 15u | (c + md5_i(d, a, b) + block[6] + T[59]) >> 17u);
    b = c + ((b + md5_i(c, d, a) + block[13] + T[60]) << 21u | (b + md5_i(c, d, a) + block[13] + T[60]) >> 11u);
    
    // Operations 61-64
    a = b + ((a + md5_i(b, c, d) + block[4] + T[61]) << 6u | (a + md5_i(b, c, d) + block[4] + T[61]) >> 26u);
    d = a + ((d + md5_i(a, b, c) + block[11] + T[62]) << 10u | (d + md5_i(a, b, c) + block[11] + T[62]) >> 22u);
    c = d + ((c + md5_i(d, a, b) + block[2] + T[63]) << 15u | (c + md5_i(d, a, b) + block[2] + T[63]) >> 17u);
    b = c + ((b + md5_i(c, d, a) + block[9] + T[64]) << 21u | (b + md5_i(c, d, a) + block[9] + T[64]) >> 11u);
    
    // Davies-Meyer construction
    return MD5State(
        a + aa,
        b + bb,
        c + cc,
        d + dd
    );
}

// ============================================================================
// GPU Buffers and Compute Shader
// ============================================================================

struct MD5Input {
    block: array<u32, 16>,
    iv_a: u32,
    iv_b: u32,
    iv_c: u32,
    iv_d: u32,
}

struct MD5Output {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

@group(0) @binding(0)
var<storage, read> inputs: array<MD5Input>;

@group(0) @binding(1)
var<storage, read_write> outputs: array<MD5Output>;

/// Main GPU MD5 compute kernel
/// Each thread computes one MD5 hash
@compute @workgroup_size(64)
fn compute_md5(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;
    
    // Bounds check
    if (idx >= arrayLength(&inputs)) {
        return;
    }
    
    // Get input
    let input = inputs[idx];
    
    // Create IV
    let iv = MD5State(input.iv_a, input.iv_b, input.iv_c, input.iv_d);
    
    // Process block
    let result = md5_process_block(iv, input.block);
    
    // Store result
    outputs[idx] = MD5Output(result.a, result.b, result.c, result.d);
}
