// ============================================================================
// MD5 Constants
// ============================================================================

const T: array<u32, 65> = array<u32, 65>(
    0x00000000u, 0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
);

// ============================================================================
// Differential Path Bit Conditions (Wang et al. 2005)
// ============================================================================

// Round 1 conditions
const A1_ONE_BITS: u32       = 0x84200000u;
const A1_ZERO_BITS: u32      = 0x0A000820u;
const D1_ONE_BITS: u32       = 0x8C000800u;
const D1_ZERO_BITS: u32      = 0x02208026u;
const D1_A1_SAME_BITS: u32   = 0x701F10C0u;
const C1_ONE_BITS: u32       = 0xBE1F0966u;
const C1_ZERO_BITS: u32      = 0x40201080u;
const C1_D1_SAME_BITS: u32   = 0x00000018u;
const B1_ONE_BITS: u32       = 0xBA040010u;
const B1_ZERO_BITS: u32      = 0x443B19EEu;
const B1_C1_SAME_BITS: u32   = 0x00000601u;

const A2_ONE_BITS: u32       = 0x482F0E50u;
const A2_ZERO_BITS: u32      = 0xB41011AFu;
const D2_ONE_BITS: u32       = 0x04220C56u;
const D2_ZERO_BITS: u32      = 0x9A1113A9u;
const C2_ONE_BITS: u32       = 0x96011E01u;
const C2_ZERO_BITS: u32      = 0x083201C0u;
const C2_D2_SAME_BITS: u32   = 0x01808000u;
const B2_ONE_BITS: u32       = 0x843283C0u;
const B2_ZERO_BITS: u32      = 0x1B810001u;
const B2_C2_SAME_BITS: u32   = 0x00000002u;

const A3_ONE_BITS: u32       = 0x9C0101C1u;
const A3_ZERO_BITS: u32      = 0x03828202u;
const A3_B2_SAME_BITS: u32   = 0x00001000u;
const D3_ONE_BITS: u32       = 0x878383C0u;
const D3_ZERO_BITS: u32      = 0x00041003u;
const C3_ONE_BITS: u32       = 0x800583C3u;
const C3_ZERO_BITS: u32      = 0x00021000u;
const C3_D3_SAME_BITS: u32   = 0x00086000u;
const B3_ONE_BITS: u32       = 0x80081080u;
const B3_ZERO_BITS: u32      = 0x0007E000u;
const B3_C3_SAME_BITS: u32   = 0x7F000000u;

const A4_ONE_BITS: u32       = 0x3F0FE008u;
const A4_ZERO_BITS: u32      = 0xC0000080u;
const D4_ONE_BITS: u32       = 0x400BE088u;
const D4_ZERO_BITS: u32      = 0xBF040000u;
const C4_ONE_BITS: u32       = 0x7D000000u;
const C4_ZERO_BITS: u32      = 0x82008008u;
const B4_ONE_BITS: u32       = 0x20000000u;
const B4_ZERO_BITS: u32      = 0x80000000u;

// Round 2 conditions
const A5_ZERO_BITS: u32      = 0x80020000u;
const A5_B4_SAME_BITS: u32   = 0x00008008u;
const D5_ONE_BITS: u32       = 0x00020000u;
const D5_ZERO_BITS: u32      = 0x80000000u;
const D5_A5_SAME_BITS: u32   = 0x20000000u;
const C5_ZERO_BITS: u32      = 0x80020000u;
const B5_ZERO_BITS: u32      = 0x80000000u;
const A6_ZERO_BITS: u32      = 0x80000000u;
const A6_B5_SAME_BITS: u32   = 0x00020000u;
const D6_ZERO_BITS: u32      = 0x80000000u;
const C6_ZERO_BITS: u32      = 0x80000000u;
const B6_C6_DIFFERENT_BITS: u32 = 0x80000000u;

// Round 3 conditions
const B12_D12_SAME_BITS: u32    = 0x80000000u;

// Round 4 conditions
const A13_C12_SAME_BITS: u32    = 0x80000000u;
const D13_B12_DIFFERENT_BITS: u32 = 0x80000000u;
const C13_A13_SAME_BITS: u32    = 0x80000000u;
const B13_D13_SAME_BITS: u32    = 0x80000000u;
const A14_C13_SAME_BITS: u32    = 0x80000000u;
const D14_B13_SAME_BITS: u32    = 0x80000000u;
const C14_A14_SAME_BITS: u32    = 0x80000000u;
const B14_D14_SAME_BITS: u32    = 0x80000000u;
const A15_C14_SAME_BITS: u32    = 0x80000000u;
const D15_B14_SAME_BITS: u32    = 0x80000000u;
const C15_A15_SAME_BITS: u32    = 0x80000000u;
const B15_D15_DIFFERENT_BITS: u32 = 0x80000000u;
const A16_ONE_BITS: u32         = 0x02000000u;
const A16_C15_SAME_BITS: u32    = 0x80000000u;
const D16_ONE_BITS: u32         = 0x02000000u;
const D16_B15_SAME_BITS: u32    = 0x80000000u;

// ============================================================================
// MD5 Auxiliary Functions
// ============================================================================

fn md5_f(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) | (~x & z);
}

fn md5_g(x: u32, y: u32, z: u32) -> u32 {
    return (x & z) | (y & ~z);
}

fn md5_h(x: u32, y: u32, z: u32) -> u32 {
    return x ^ y ^ z;
}

fn md5_i(x: u32, y: u32, z: u32) -> u32 {
    return y ^ (x | ~z);
}

// ============================================================================
// Bit Manipulation Helpers
// ============================================================================

fn rotl(value: u32, shift: u32) -> u32 {
    return (value << shift) | (value >> (32u - shift));
}

fn rotr(value: u32, shift: u32) -> u32 {
    return (value >> shift) | (value << (32u - shift));
}

fn apply_one_bits(v: u32, mask: u32) -> u32 {
    return v | mask;
}

fn apply_zero_bits(v: u32, mask: u32) -> u32 {
    return v & (~mask);
}

fn apply_same_bits(v: u32, u: u32, mask: u32) -> u32 {
    return (v | (u & mask)) & (u | (~mask));
}

fn verify_one_bits(v: u32, mask: u32) -> bool {
    return (v & mask) == mask;
}

fn verify_zero_bits(v: u32, mask: u32) -> bool {
    return (v & mask) == 0u;
}

fn verify_same_bits(v: u32, u: u32, mask: u32) -> bool {
    return (v & mask) == (u & mask);
}

fn verify_different_bits(v: u32, u: u32, mask: u32) -> bool {
    return (v & mask) != (u & mask);
}

// ============================================================================
// Message Modification (Reverse Operations)
// ============================================================================

fn ff_step(a: u32, b: u32, c: u32, d: u32, word: u32, k: u32, s: u32) -> u32 {
    return rotl(a + md5_f(b, c, d) + word + k, s) + b;
}

fn gg_step(a: u32, b: u32, c: u32, d: u32, word: u32, k: u32, s: u32) -> u32 {
    return rotl(a + md5_g(b, c, d) + word + k, s) + b;
}

fn hh_step(a: u32, b: u32, c: u32, d: u32, word: u32, k: u32, s: u32) -> u32 {
    return rotl(a + md5_h(b, c, d) + word + k, s) + b;
}

fn ii_step(a: u32, b: u32, c: u32, d: u32, word: u32, k: u32, s: u32) -> u32 {
    return rotl(a + md5_i(b, c, d) + word + k, s) + b;
}

// Reverse FF operation to find required message word
fn reverse_ff(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, orig: u32) -> u32 {
    return rotr(a - b, s) - md5_f(b, c, d) - orig - k;
}

// ============================================================================
// PRNG (LCG for GPU)
// ============================================================================

struct RngState {
    state: u32,
}

fn rng_init(seed: u32, id: u32) -> RngState {
    let s = seed ^ (id * 747796405u + 2891336453u);
    return RngState(s);
}

fn rng_next(rng: ptr<function, RngState>) -> u32 {
    (*rng).state = (*rng).state * 1664525u + 1013904223u;
    return (*rng).state;
}

// ============================================================================
// GPU Buffers
// ============================================================================

struct SearchInput {
    iv: array<u32, 4>,     // Initial MD5 state from first block
    seed: u32,              // Random seed
    iterations: u32,        // Iterations per thread
}

struct Candidate {
    words: array<u32, 16>,  // Message block candidate
    found: u32,             // 1 if valid candidate, 0 otherwise
}

@group(0) @binding(0)
var<storage, read> input: SearchInput;

@group(0) @binding(1)
var<storage, read_write> candidates: array<Candidate>;

// ============================================================================
// Main Collision Search Kernel
// ============================================================================

@compute @workgroup_size(256)
fn search_collision(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;
    
    if (idx >= arrayLength(&candidates)) {
        return;
    }
    
    // Initialize RNG
    var rng = rng_init(input.seed, idx);
    
    // Try multiple random starting points
    for (var iter = 0u; iter < input.iterations; iter++) {
        // Generate random message block
        var words: array<u32, 16>;
        for (var i = 0u; i < 16u; i++) {
            words[i] = rng_next(&rng);
        }
        
        // Load IV from first block hash
        var a = input.iv[0];
        var b = input.iv[1];
        var c = input.iv[2];
        var d = input.iv[3];
        
        var orig: u32;
        
        // ====================================================================
        // ROUND 1: Apply conditions via message modification
        // ====================================================================
        
        // a1
        orig = a;
        a = ff_step(a, b, c, d, words[0], T[1], 7u);
        a = apply_one_bits(a, A1_ONE_BITS);
        a = apply_zero_bits(a, A1_ZERO_BITS);
        words[0] = reverse_ff(a, b, c, d, T[1], 7u, orig);
        
        // d1
        orig = d;
        d = ff_step(d, a, b, c, words[1], T[2], 12u);
        d = apply_one_bits(d, D1_ONE_BITS);
        d = apply_zero_bits(d, D1_ZERO_BITS);
        d = apply_same_bits(d, a, D1_A1_SAME_BITS);
        words[1] = reverse_ff(d, a, b, c, T[2], 12u, orig);
        
        // c1
        orig = c;
        c = ff_step(c, d, a, b, words[2], T[3], 17u);
        c = apply_one_bits(c, C1_ONE_BITS);
        c = apply_zero_bits(c, C1_ZERO_BITS);
        c = apply_same_bits(c, d, C1_D1_SAME_BITS);
        words[2] = reverse_ff(c, d, a, b, T[3], 17u, orig);
        
        // b1
        orig = b;
        b = ff_step(b, c, d, a, words[3], T[4], 22u);
        b = apply_one_bits(b, B1_ONE_BITS);
        b = apply_zero_bits(b, B1_ZERO_BITS);
        b = apply_same_bits(b, c, B1_C1_SAME_BITS);
        words[3] = reverse_ff(b, c, d, a, T[4], 22u, orig);
        
        // a2
        orig = a;
        a = ff_step(a, b, c, d, words[4], T[5], 7u);
        a = apply_one_bits(a, A2_ONE_BITS);
        a = apply_zero_bits(a, A2_ZERO_BITS);
        words[4] = reverse_ff(a, b, c, d, T[5], 7u, orig);
        
        // d2
        orig = d;
        d = ff_step(d, a, b, c, words[5], T[6], 12u);
        d = apply_one_bits(d, D2_ONE_BITS);
        d = apply_zero_bits(d, D2_ZERO_BITS);
        words[5] = reverse_ff(d, a, b, c, T[6], 12u, orig);
        
        // c2
        orig = c;
        c = ff_step(c, d, a, b, words[6], T[7], 17u);
        c = apply_one_bits(c, C2_ONE_BITS);
        c = apply_zero_bits(c, C2_ZERO_BITS);
        c = apply_same_bits(c, d, C2_D2_SAME_BITS);
        words[6] = reverse_ff(c, d, a, b, T[7], 17u, orig);
        
        // b2
        orig = b;
        b = ff_step(b, c, d, a, words[7], T[8], 22u);
        b = apply_one_bits(b, B2_ONE_BITS);
        b = apply_zero_bits(b, B2_ZERO_BITS);
        b = apply_same_bits(b, c, B2_C2_SAME_BITS);
        words[7] = reverse_ff(b, c, d, a, T[8], 22u, orig);
        
        // a3
        orig = a;
        a = ff_step(a, b, c, d, words[8], T[9], 7u);
        a = apply_one_bits(a, A3_ONE_BITS);
        a = apply_zero_bits(a, A3_ZERO_BITS);
        a = apply_same_bits(a, b, A3_B2_SAME_BITS);
        words[8] = reverse_ff(a, b, c, d, T[9], 7u, orig);
        
        // d3
        orig = d;
        d = ff_step(d, a, b, c, words[9], T[10], 12u);
        d = apply_one_bits(d, D3_ONE_BITS);
        d = apply_zero_bits(d, D3_ZERO_BITS);
        words[9] = reverse_ff(d, a, b, c, T[10], 12u, orig);
        
        // c3
        orig = c;
        c = ff_step(c, d, a, b, words[10], T[11], 17u);
        c = apply_one_bits(c, C3_ONE_BITS);
        c = apply_zero_bits(c, C3_ZERO_BITS);
        c = apply_same_bits(c, d, C3_D3_SAME_BITS);
        words[10] = reverse_ff(c, d, a, b, T[11], 17u, orig);
        
        // b3
        orig = b;
        b = ff_step(b, c, d, a, words[11], T[12], 22u);
        b = apply_one_bits(b, B3_ONE_BITS);
        b = apply_zero_bits(b, B3_ZERO_BITS);
        b = apply_same_bits(b, c, B3_C3_SAME_BITS);
        words[11] = reverse_ff(b, c, d, a, T[12], 22u, orig);
        
        // a4
        orig = a;
        a = ff_step(a, b, c, d, words[12], T[13], 7u);
        a = apply_one_bits(a, A4_ONE_BITS);
        a = apply_zero_bits(a, A4_ZERO_BITS);
        words[12] = reverse_ff(a, b, c, d, T[13], 7u, orig);
        
        // d4
        orig = d;
        d = ff_step(d, a, b, c, words[13], T[14], 12u);
        d = apply_one_bits(d, D4_ONE_BITS);
        d = apply_zero_bits(d, D4_ZERO_BITS);
        words[13] = reverse_ff(d, a, b, c, T[14], 12u, orig);
        
        // c4
        orig = c;
        c = ff_step(c, d, a, b, words[14], T[15], 17u);
        c = apply_one_bits(c, C4_ONE_BITS);
        c = apply_zero_bits(c, C4_ZERO_BITS);
        words[14] = reverse_ff(c, d, a, b, T[15], 17u, orig);
        
        // b4
        orig = b;
        b = ff_step(b, c, d, a, words[15], T[16], 22u);
        b = apply_one_bits(b, B4_ONE_BITS);
        b = apply_zero_bits(b, B4_ZERO_BITS);
        words[15] = reverse_ff(b, c, d, a, T[16], 22u, orig);
        
        // ====================================================================
        // ROUND 2: Verify conditions
        // ====================================================================
        
        // a5
        a = gg_step(a, b, c, d, words[1], T[17], 5u);
        if (!verify_zero_bits(a, A5_ZERO_BITS)) { continue; }
        if (!verify_same_bits(a, b, A5_B4_SAME_BITS)) { continue; }
        
        // d5
        d = gg_step(d, a, b, c, words[6], T[18], 9u);
        if (!verify_zero_bits(d, D5_ZERO_BITS)) { continue; }
        if (!verify_one_bits(d, D5_ONE_BITS)) { continue; }
        if (!verify_same_bits(d, a, D5_A5_SAME_BITS)) { continue; }
        
        // c5
        c = gg_step(c, d, a, b, words[11], T[19], 14u);
        if (!verify_zero_bits(c, C5_ZERO_BITS)) { continue; }
        
        // b5
        b = gg_step(b, c, d, a, words[0], T[20], 20u);
        if (!verify_zero_bits(b, B5_ZERO_BITS)) { continue; }
        
        // a6
        a = gg_step(a, b, c, d, words[5], T[21], 5u);
        if (!verify_zero_bits(a, A6_ZERO_BITS)) { continue; }
        if (!verify_same_bits(a, b, A6_B5_SAME_BITS)) { continue; }
        
        // d6
        d = gg_step(d, a, b, c, words[10], T[22], 9u);
        if (!verify_zero_bits(d, D6_ZERO_BITS)) { continue; }
        
        // c6
        c = gg_step(c, d, a, b, words[15], T[23], 14u);
        if (!verify_zero_bits(c, C6_ZERO_BITS)) { continue; }
        
        // b6
        b = gg_step(b, c, d, a, words[4], T[24], 20u);
        if (!verify_different_bits(b, c, B6_C6_DIFFERENT_BITS)) { continue; }
        
        // Remaining Round 2 operations (no conditions)
        a = gg_step(a, b, c, d, words[9], T[25], 5u);
        d = gg_step(d, a, b, c, words[14], T[26], 9u);
        c = gg_step(c, d, a, b, words[3], T[27], 14u);
        b = gg_step(b, c, d, a, words[8], T[28], 20u);
        
        a = gg_step(a, b, c, d, words[13], T[29], 5u);
        d = gg_step(d, a, b, c, words[2], T[30], 9u);
        c = gg_step(c, d, a, b, words[7], T[31], 14u);
        b = gg_step(b, c, d, a, words[12], T[32], 20u);
        
        // ====================================================================
        // ROUND 3
        // ====================================================================
        
        a = hh_step(a, b, c, d, words[5], T[33], 4u);
        d = hh_step(d, a, b, c, words[8], T[34], 11u);
        c = hh_step(c, d, a, b, words[11], T[35], 16u);
        b = hh_step(b, c, d, a, words[14], T[36], 23u);
        
        a = hh_step(a, b, c, d, words[1], T[37], 4u);
        d = hh_step(d, a, b, c, words[4], T[38], 11u);
        c = hh_step(c, d, a, b, words[7], T[39], 16u);
        b = hh_step(b, c, d, a, words[10], T[40], 23u);
        
        a = hh_step(a, b, c, d, words[13], T[41], 4u);
        d = hh_step(d, a, b, c, words[0], T[42], 11u);
        c = hh_step(c, d, a, b, words[3], T[43], 16u);
        b = hh_step(b, c, d, a, words[6], T[44], 23u);
        
        a = hh_step(a, b, c, d, words[9], T[45], 4u);
        let d12 = hh_step(d, a, b, c, words[12], T[46], 11u);
        let c12 = hh_step(c, d12, a, b, words[15], T[47], 16u);
        
        // b12
        let b12 = hh_step(b, c12, d12, a, words[2], T[48], 23u);
        if (!verify_same_bits(b12, d12, B12_D12_SAME_BITS)) { continue; }
        
        d = d12;
        c = c12;
        b = b12;
        
        // ====================================================================
        // ROUND 4
        // ====================================================================
        
        // a13
        a = ii_step(a, b, c, d, words[0], T[49], 6u);
        if (!verify_same_bits(a, c, A13_C12_SAME_BITS)) { continue; }
        
        // d13
        d = ii_step(d, a, b, c, words[7], T[50], 10u);
        if (!verify_different_bits(d, b, D13_B12_DIFFERENT_BITS)) { continue; }
        
        // c13
        c = ii_step(c, d, a, b, words[14], T[51], 15u);
        if (!verify_same_bits(c, a, C13_A13_SAME_BITS)) { continue; }
        
        // b13
        b = ii_step(b, c, d, a, words[5], T[52], 21u);
        if (!verify_same_bits(b, d, B13_D13_SAME_BITS)) { continue; }
        
        // a14
        a = ii_step(a, b, c, d, words[12], T[53], 6u);
        if (!verify_same_bits(a, c, A14_C13_SAME_BITS)) { continue; }
        
        // d14
        d = ii_step(d, a, b, c, words[3], T[54], 10u);
        if (!verify_same_bits(d, b, D14_B13_SAME_BITS)) { continue; }
        
        // c14
        c = ii_step(c, d, a, b, words[10], T[55], 15u);
        if (!verify_same_bits(c, a, C14_A14_SAME_BITS)) { continue; }
        
        // b14
        b = ii_step(b, c, d, a, words[1], T[56], 21u);
        if (!verify_same_bits(b, d, B14_D14_SAME_BITS)) { continue; }
        
        // a15
        a = ii_step(a, b, c, d, words[8], T[57], 6u);
        if (!verify_same_bits(a, c, A15_C14_SAME_BITS)) { continue; }
        
        // d15
        d = ii_step(d, a, b, c, words[15], T[58], 10u);
        if (!verify_same_bits(d, b, D15_B14_SAME_BITS)) { continue; }
        
        // c15
        c = ii_step(c, d, a, b, words[6], T[59], 15u);
        if (!verify_same_bits(c, a, C15_A15_SAME_BITS)) { continue; }
        
        // b15
        b = ii_step(b, c, d, a, words[13], T[60], 21u);
        if (!verify_different_bits(b, d, B15_D15_DIFFERENT_BITS)) { continue; }
        
        // a16
        a = ii_step(a, b, c, d, words[4], T[61], 6u);
        if (!verify_one_bits(a, A16_ONE_BITS)) { continue; }
        if (!verify_same_bits(a, c, A16_C15_SAME_BITS)) { continue; }
        
        // d16
        d = ii_step(d, a, b, c, words[11], T[62], 10u);
        if (!verify_one_bits(d, D16_ONE_BITS)) { continue; }
        if (!verify_same_bits(d, b, D16_B15_SAME_BITS)) { continue; }
        
        // SUCCESS! Found valid candidate
        for (var i = 0u; i < 16u; i++) {
            candidates[idx].words[i] = words[i];
        }
        candidates[idx].found = 1u;
        return;
    }
    
    // No candidate found in this thread
    candidates[idx].found = 0u;
}
