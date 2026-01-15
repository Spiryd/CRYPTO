//! Schnorr Signature Benchmark - Security Level Comparison
//!
//! This example benchmarks Schnorr signature performance at different security levels:
//! - TOY: Small fields for testing only (~7-bit)
//! - 128-bit security: EC-256 (secp256k1) vs MODP-3072 (RFC 3526 Group 15)
//! - ~170-bit security: MODP-6144 (RFC 3526 Group 17) - between 128 and 192-bit
//! - 192-bit security: EC-384 (P-384)
//! - 256-bit security: EC-521 (P-521) - MODP-15360 omitted (too slow)
//!
//! MODP = multiplicative group of F_p* (security from discrete log problem)
//! EC = elliptic curve group (security from elliptic curve discrete log problem)
//!
//! Security level equivalences follow NIST SP 800-57 / keylength.com guidelines.
//!
//! The benchmark measures:
//! - Key generation time
//! - Signing time (with unique nonce per iteration!)
//! - Verification time

use l3::bigint::BigInt;
use l3::elliptic_curve::{EllipticCurve, Point};
use l3::field::PrimeField;
use l3::field::config::FieldConfig;
use l3::field_trait::FieldElement;
use l3::schnorr::{
    SchnorrEC, SchnorrECImpl, SchnorrField, SchnorrFieldImpl, SchnorrParamsEC, SchnorrParamsField,
};
use std::time::{Duration, Instant};

// ============================================================================
// Type aliases for different security levels
// ============================================================================

// 256-bit (secp256k1): 4 limbs * 64 = 256 bits
type BigInt256 = BigInt<4>;

// 384-bit (P-384): 6 limbs * 64 = 384 bits
type BigInt384 = BigInt<6>;

// 521-bit (P-521): 9 limbs * 64 = 576 bits (covers 521)
type BigInt576 = BigInt<9>;

// 3072-bit DL (128-bit security): 48 limbs * 64 = 3072 bits
type BigInt3072 = BigInt<48>;

// 6144-bit DL (~170-bit security): 96 limbs * 64 = 6144 bits
type BigInt6144 = BigInt<96>;

// ============================================================================
// Field Configurations - TOY
// ============================================================================

/// Small prime field F_97 for testing (TOY security - NOT cryptographic!)
#[derive(Clone, Debug)]
struct F97Config;
static F97_MOD: BigInt256 = BigInt::from_u64(97);
impl FieldConfig<4> for F97Config {
    fn modulus() -> &'static BigInt256 {
        &F97_MOD
    }
    fn irreducible() -> &'static [BigInt256] {
        &[]
    }
}
type Fp97 = PrimeField<F97Config, 4>;

// ============================================================================
// Field Configurations - 128-bit Security (EC-256 + DL-3072)
// ============================================================================

/// secp256k1 field: p = 2^256 - 2^32 - 977
#[derive(Clone, Debug)]
struct Secp256k1FieldConfig;
static SECP256K1_P: BigInt256 = BigInt::from_limbs_internal([
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]);
impl FieldConfig<4> for Secp256k1FieldConfig {
    fn modulus() -> &'static BigInt256 {
        &SECP256K1_P
    }
    fn irreducible() -> &'static [BigInt256] {
        &[]
    }
}
type Fp256 = PrimeField<Secp256k1FieldConfig, 4>;

/// RFC 3526 Group 15: 3072-bit MODP prime (128-bit security)
#[derive(Clone, Debug)]
struct F3072Config;

/// Pre-computed little-endian limbs for RFC 3526 Group 15
static RFC3526_GROUP15_LIMBS: [u64; 48] = [
    0xFFFFFFFFFFFFFFFF,
    0x4B82D120A93AD2CA,
    0x43DB5BFCE0FD108E,
    0x08E24FA074E5AB31,
    0x770988C0BAD946E2,
    0xBBE117577A615D6C,
    0x521F2B18177B200C,
    0xD87602733EC86A64,
    0xF12FFA06D98A0864,
    0xCEE3D2261AD2EE6B,
    0x1E8C94E04A25619D,
    0xABF5AE8CDB0933D7,
    0xB3970F85A6E1E4C7,
    0x8AEA71575D060C7D,
    0xECFB850458DBEF0A,
    0xA85521ABDF1CBA64,
    0xAD33170D04507A33,
    0x15728E5A8AAAC42D,
    0x15D2261898FA0510,
    0x3995497CEA956AE5,
    0xDE2BCBF695581718,
    0xB5C55DF06F4C52C9,
    0x9B2783A2EC07A28F,
    0xE39E772C180E8603,
    0x32905E462E36CE3B,
    0xF1746C08CA18217C,
    0x670C354E4ABC9804,
    0x9ED529077096966D,
    0x1C62F356208552BB,
    0x83655D23DCA3AD96,
    0x69163FA8FD24CF5F,
    0x98DA48361C55D39A,
    0xC2007CB8A163BF05,
    0x49286651ECE45B3D,
    0xAE9F24117C4B1FE6,
    0xEE386BFB5A899FA5,
    0x0BFF5CB6F406B7ED,
    0xF44C42E9A637ED6B,
    0xE485B576625E7EC6,
    0x4FE1356D6D51C245,
    0x302B0A6DF25F1437,
    0xEF9519B3CD3A431B,
    0x514A08798E3404DD,
    0x020BBEA63B139B22,
    0x29024E088A67CC74,
    0xC4C6628B80DC1CD1,
    0xC90FDAA22168C234,
    0xFFFFFFFFFFFFFFFF,
];

static F3072_MOD: BigInt3072 = BigInt::from_limbs_internal(RFC3526_GROUP15_LIMBS);

impl FieldConfig<48> for F3072Config {
    fn modulus() -> &'static BigInt3072 {
        &F3072_MOD
    }
    fn irreducible() -> &'static [BigInt3072] {
        &[]
    }
}
type Fp3072 = PrimeField<F3072Config, 48>;

// ============================================================================
// Field Configurations - ~170-bit Security (DL-6144)
// ============================================================================

/// RFC 3526 Group 17: 6144-bit MODP prime (~170-bit security)
/// p = 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 }
#[derive(Clone, Debug)]
struct F6144Config;

/// Pre-computed little-endian limbs for RFC 3526 Group 17
static RFC3526_GROUP17_LIMBS: [u64; 96] = [
    0xFFFFFFFFFFFFFFFF,
    0xE694F91E6DCC4024,
    0x12BF2D5B0B7474D6,
    0x043E8F663F4860EE,
    0x387FE8D76E3C0468,
    0xDA56C9EC2EF29632,
    0xEB19CCB1A313D55C,
    0xF550AA3D8A1FBFF0,
    0x06A1D58BB7C5DA76,
    0xA79715EEF29BE328,
    0x14CC5ED20F8037E0,
    0xCC8F6D7EBF48E1D8,
    0x4BD407B22B4154AA,
    0x0F1D45B7FF585AC5,
    0x23A97A7E36CC88BE,
    0x59E7C97FBEC7E8F3,
    0xB5A84031900B1C9E,
    0xD55E702F46980C82,
    0xF482D7CE6E74FEF6,
    0xF032EA15D1721D03,
    0x5983CA01C64B92EC,
    0x6FB8F401378CD2BF,
    0x332051512BD7AF42,
    0xDB7F1447E6CC254B,
    0x44CE6CBACED4BB1B,
    0xDA3EDBEBCF9B14ED,
    0x179727B0865A8918,
    0xB06A53ED9027D831,
    0xE5DB382F413001AE,
    0xF8FF9406AD9E530E,
    0xC9751E763DBA37BD,
    0xC1D4DCB2602646DE,
    0x36C3FAB4D27C7026,
    0x4DF435C934028492,
    0x86FFB7DC90A6C08F,
    0x93B4EA988D8FDDC1,
    0xD0069127D5B05AA9,
    0xB81BDD762170481C,
    0x1F612970CEE2D7AF,
    0x233BA186515BE7ED,
    0x99B2964FA090C3A2,
    0x287C59474E6BC05D,
    0x2E8EFC141FBECAA6,
    0xDBBBC2DB04DE8EF9,
    0x2583E9CA2AD44CE8,
    0x1A946834B6150BDA,
    0x99C327186AF4E23C,
    0x88719A10BDBA5B26,
    0x1A723C12A787E6D7,
    0x4B82D120A9210801,
    0x43DB5BFCE0FD108E,
    0x08E24FA074E5AB31,
    0x770988C0BAD946E2,
    0xBBE117577A615D6C,
    0x521F2B18177B200C,
    0xD87602733EC86A64,
    0xF12FFA06D98A0864,
    0xCEE3D2261AD2EE6B,
    0x1E8C94E04A25619D,
    0xABF5AE8CDB0933D7,
    0xB3970F85A6E1E4C7,
    0x8AEA71575D060C7D,
    0xECFB850458DBEF0A,
    0xA85521ABDF1CBA64,
    0xAD33170D04507A33,
    0x15728E5A8AAAC42D,
    0x15D2261898FA0510,
    0x3995497CEA956AE5,
    0xDE2BCBF695581718,
    0xB5C55DF06F4C52C9,
    0x9B2783A2EC07A28F,
    0xE39E772C180E8603,
    0x32905E462E36CE3B,
    0xF1746C08CA18217C,
    0x670C354E4ABC9804,
    0x9ED529077096966D,
    0x1C62F356208552BB,
    0x83655D23DCA3AD96,
    0x69163FA8FD24CF5F,
    0x98DA48361C55D39A,
    0xC2007CB8A163BF05,
    0x49286651ECE45B3D,
    0xAE9F24117C4B1FE6,
    0xEE386BFB5A899FA5,
    0x0BFF5CB6F406B7ED,
    0xF44C42E9A637ED6B,
    0xE485B576625E7EC6,
    0x4FE1356D6D51C245,
    0x302B0A6DF25F1437,
    0xEF9519B3CD3A431B,
    0x514A08798E3404DD,
    0x020BBEA63B139B22,
    0x29024E088A67CC74,
    0xC4C6628B80DC1CD1,
    0xC90FDAA22168C234,
    0xFFFFFFFFFFFFFFFF,
];

static F6144_MOD: BigInt6144 = BigInt::from_limbs_internal(RFC3526_GROUP17_LIMBS);

impl FieldConfig<96> for F6144Config {
    fn modulus() -> &'static BigInt6144 {
        &F6144_MOD
    }
    fn irreducible() -> &'static [BigInt6144] {
        &[]
    }
}
type Fp6144 = PrimeField<F6144Config, 96>;

// RFC 3526 Group 17 hex representation (kept for reference)
#[allow(dead_code)]
const RFC3526_GROUP17_HEX: &str = concat!(
    "FFFFFFFF", "FFFFFFFF", "C90FDAA2", "2168C234", "C4C6628B", "80DC1CD1", "29024E08", "8A67CC74",
    "020BBEA6", "3B139B22", "514A0879", "8E3404DD", "EF9519B3", "CD3A431B", "302B0A6D", "F25F1437",
    "4FE1356D", "6D51C245", "E485B576", "625E7EC6", "F44C42E9", "A637ED6B", "0BFF5CB6", "F406B7ED",
    "EE386BFB", "5A899FA5", "AE9F2411", "7C4B1FE6", "49286651", "ECE45B3D", "C2007CB8", "A163BF05",
    "98DA4836", "1C55D39A", "69163FA8", "FD24CF5F", "83655D23", "DCA3AD96", "1C62F356", "208552BB",
    "9ED52907", "7096966D", "670C354E", "4ABC9804", "F1746C08", "CA18217C", "32905E46", "2E36CE3B",
    "E39E772C", "180E8603", "9B2783A2", "EC07A28F", "B5C55DF0", "6F4C52C9", "DE2BCBF6", "95581718",
    "3995497C", "EA956AE5", "15D22618", "98FA0510", "15728E5A", "8AAAC42D", "AD33170D", "04507A33",
    "A85521AB", "DF1CBA64", "ECFB8504", "58DBEF0A", "8AEA7157", "5D060C7D", "B3970F85", "A6E1E4C7",
    "ABF5AE8C", "DB0933D7", "1E8C94E0", "4A25619D", "CEE3D226", "1AD2EE6B", "F12FFA06", "D98A0864",
    "D8760273", "3EC86A64", "521F2B18", "177B200C", "BBE11757", "7A615D6C", "770988C0", "BAD946E2",
    "08E24FA0", "74E5AB31", "43DB5BFC", "E0FD108E", "4B82D120", "A9210801", "1A723C12", "A787E6D7",
    "88719A10", "BDBA5B26", "99C32718", "6AF4E23C", "1A946834", "B6150BDA", "2583E9CA", "2AD44CE8",
    "DBBBC2DB", "04DE8EF9", "2E8EFC14", "1FBECAA6", "287C5947", "4E6BC05D", "99B2964F", "A090C3A2",
    "233BA186", "515BE7ED", "1F612970", "CEE2D7AF", "B81BDD76", "2170481C", "D0069127", "D5B05AA9",
    "93B4EA98", "8D8FDDC1", "86FFB7DC", "90A6C08F", "4DF435C9", "34028492", "36C3FAB4", "D27C7026",
    "C1D4DCB2", "602646DE", "C9751E76", "3DBA37BD", "F8FF9406", "AD9E530E", "E5DB382F", "413001AE",
    "B06A53ED", "9027D831", "179727B0", "865A8918", "DA3EDBEB", "CF9B14ED", "44CE6CBA", "CED4BB1B",
    "DB7F1447", "E6CC254B", "33205151", "2BD7AF42", "6FB8F401", "378CD2BF", "5983CA01", "C64B92EC",
    "F032EA15", "D1721D03", "F482D7CE", "6E74FEF6", "D55E702F", "46980C82", "B5A84031", "900B1C9E",
    "59E7C97F", "BEC7E8F3", "23A97A7E", "36CC88BE", "0F1D45B7", "FF585AC5", "4BD407B2", "2B4154AA",
    "CC8F6D7E", "BF48E1D8", "14CC5ED2", "0F8037E0", "A79715EE", "F29BE328", "06A1D58B", "B7C5DA76",
    "F550AA3D", "8A1FBFF0", "EB19CCB1", "A313D55C", "DA56C9EC", "2EF29632", "387FE8D7", "6E3C0468",
    "043E8F66", "3F4860EE", "12BF2D5B", "0B7474D6", "E694F91E", "6DCC4024", "FFFFFFFF", "FFFFFFFF"
);

#[allow(dead_code)]
fn get_rfc3526_group17_prime() -> BigInt6144 {
    BigInt6144::from_hex(RFC3526_GROUP17_HEX)
}

// ============================================================================
// Field Configurations - 192-bit Security (EC-384)
// ============================================================================

/// NIST P-384 field prime
/// p = 2^384 - 2^128 - 2^96 + 2^32 - 1
#[derive(Clone, Debug)]
struct P384FieldConfig;
static P384_P: BigInt384 = BigInt::from_limbs_internal([
    0x00000000FFFFFFFF,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]);
impl FieldConfig<6> for P384FieldConfig {
    fn modulus() -> &'static BigInt384 {
        &P384_P
    }
    fn irreducible() -> &'static [BigInt384] {
        &[]
    }
}
type Fp384 = PrimeField<P384FieldConfig, 6>;

// ============================================================================
// Field Configurations - 256-bit Security (EC-521)
// ============================================================================

/// NIST P-521 field prime: p = 2^521 - 1 (Mersenne prime)
#[derive(Clone, Debug)]
struct P521FieldConfig;

// P-521 prime: 2^521 - 1
// 521 bits needs 9 limbs (576 bits covers it)
// Top limb has 521 - 8*64 = 9 bits set, so 0x1FF
static P521_P: BigInt576 = BigInt::from_limbs_internal([
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x00000000000001FF, // Top 9 bits: 2^521 - 1 = 0x1FF in MSB limb
]);

impl FieldConfig<9> for P521FieldConfig {
    fn modulus() -> &'static BigInt576 {
        &P521_P
    }
    fn irreducible() -> &'static [BigInt576] {
        &[]
    }
}
type Fp521 = PrimeField<P521FieldConfig, 9>;

// ============================================================================
// Benchmark Result
// ============================================================================

struct BenchmarkResult {
    name: String,
    keygen_time: Duration,
    sign_time: Duration,
    verify_time: Duration,
    iterations: u32,
    security_bits: u32,
}

impl BenchmarkResult {
    fn print(&self) {
        println!("+-----------------------------------------------------------------+");
        println!(
            "| {:^63} |",
            format!("{} (~{}-bit)", self.name, self.security_bits)
        );
        println!("+-----------------------------------------------------------------+");
        println!(
            "| Key Generation:  {:>12.3?} ({:>6} ops)                      |",
            self.keygen_time / self.iterations,
            self.iterations
        );
        println!(
            "| Signing:         {:>12.3?} ({:>6} ops)                      |",
            self.sign_time / self.iterations,
            self.iterations
        );
        println!(
            "| Verification:    {:>12.3?} ({:>6} ops)                      |",
            self.verify_time / self.iterations,
            self.iterations
        );
        println!(
            "| Total:           {:>12.3?}                                   |",
            (self.keygen_time + self.sign_time + self.verify_time) / self.iterations
        );
        println!("+-----------------------------------------------------------------+");
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute q = (p-1)/2 for safe primes
fn compute_subgroup_order<const N: usize>(p: &BigInt<N>) -> BigInt<N> {
    let one = BigInt::<N>::from_u64(1);
    let (p_minus_1, _) = p.sub_with_borrow(&one);
    p_minus_1.shr(1)
}

/// Derive nonce with iteration offset
fn derive_nonce<const N: usize>(
    base_nonce: &BigInt<N>,
    iteration: u32,
    order: &BigInt<N>,
) -> BigInt<N> {
    let offset = BigInt::<N>::from_u64(iteration as u64);
    base_nonce.mod_add(&offset, order)
}

/// Generate full-size scalar by hashing a seed
fn generate_full_size_scalar<const N: usize>(seed: &[u8], order: &BigInt<N>) -> BigInt<N> {
    use sha2::{Digest, Sha256};

    let byte_len = N * 8;
    let mut bytes = vec![0u8; byte_len];
    let chunks = (byte_len + 31) / 32;

    for i in 0..chunks {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&(i as u32).to_le_bytes());
        let hash = hasher.finalize();
        let start = i * 32;
        let end = std::cmp::min(start + 32, byte_len);
        let copy_len = end - start;
        bytes[start..end].copy_from_slice(&hash[..copy_len]);
    }

    let mut limbs = [0u64; N];
    for i in 0..N {
        let offset = i * 8;
        if offset + 8 <= bytes.len() {
            limbs[i] = u64::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
    }
    let raw = BigInt::<N>::from_limbs_internal(limbs);
    raw.modulo(order)
}

// ============================================================================
// Generic Benchmark Functions
// ============================================================================

/// Benchmark Schnorr over DL groups (prime fields)
fn benchmark_schnorr_field<F, const N: usize>(
    name: &str,
    params: SchnorrParamsField<F, N>,
    private_key: BigInt<N>,
    base_nonce: BigInt<N>,
    iterations: u32,
    security_bits: u32,
) -> BenchmarkResult
where
    F: FieldElement + l3::schnorr::SchnorrEncodable + Clone + std::fmt::Debug,
{
    let message = b"Benchmark message for Schnorr signature testing";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = SchnorrFieldImpl::<F, N>::generate_public_key(&params, &private_key);
    }
    let keygen_time = start.elapsed();

    let public_key = SchnorrFieldImpl::<F, N>::generate_public_key(&params, &private_key);

    let start = Instant::now();
    for i in 0..iterations {
        let nonce_i = derive_nonce(&base_nonce, i, &params.order);
        let _ = SchnorrFieldImpl::<F, N>::sign(&params, &private_key, message, &nonce_i);
    }
    let sign_time = start.elapsed();

    let nonce = derive_nonce(&base_nonce, 0, &params.order);
    let signature = SchnorrFieldImpl::<F, N>::sign(&params, &private_key, message, &nonce);

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = SchnorrFieldImpl::<F, N>::verify(&params, &public_key, message, &signature);
    }
    let verify_time = start.elapsed();

    BenchmarkResult {
        name: name.to_string(),
        keygen_time,
        sign_time,
        verify_time,
        iterations,
        security_bits,
    }
}

/// Benchmark Schnorr over elliptic curves
fn benchmark_schnorr_ec<F, const N: usize>(
    name: &str,
    params: SchnorrParamsEC<F, N>,
    private_key: BigInt<N>,
    base_nonce: BigInt<N>,
    iterations: u32,
    security_bits: u32,
) -> BenchmarkResult
where
    F: FieldElement + l3::schnorr::SchnorrEncodable + Clone + std::fmt::Debug,
{
    let message = b"Benchmark message for Schnorr signature testing";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = SchnorrECImpl::<F, N>::generate_public_key(&params, &private_key);
    }
    let keygen_time = start.elapsed();

    let public_key = SchnorrECImpl::<F, N>::generate_public_key(&params, &private_key);

    let start = Instant::now();
    for i in 0..iterations {
        let nonce_i = derive_nonce(&base_nonce, i, &params.order);
        let _ = SchnorrECImpl::<F, N>::sign(&params, &private_key, message, &nonce_i);
    }
    let sign_time = start.elapsed();

    let nonce = derive_nonce(&base_nonce, 0, &params.order);
    let signature = SchnorrECImpl::<F, N>::sign(&params, &private_key, message, &nonce);

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = SchnorrECImpl::<F, N>::verify(&params, &public_key, message, &signature);
    }
    let verify_time = start.elapsed();

    BenchmarkResult {
        name: name.to_string(),
        keygen_time,
        sign_time,
        verify_time,
        iterations,
        security_bits,
    }
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    println!();
    println!("+===================================================================+");
    println!("|     Schnorr Signature Benchmark - Multi-Security Comparison       |");
    println!("+===================================================================+");
    println!();

    let iterations_toy = 100;
    let iterations_128 = 10;
    let iterations_192_ec = 5;
    let iterations_256_ec = 3;

    let mut results: Vec<BenchmarkResult> = Vec::new();

    // ========================================================================
    // TOY: F_97 (~7-bit security)
    // ========================================================================
    println!("[TOY SECURITY (~7-bit) - For Testing Only]");
    println!();

    // MODP = multiplicative group of F_p (discrete log based)
    {
        let generator = Fp97::new(BigInt::from_u64(5));
        let order = BigInt256::from_u64(96);
        let params: SchnorrParamsField<Fp97, 4> = SchnorrParamsField { generator, order };
        let result = benchmark_schnorr_field(
            "MODP: F_97",
            params,
            BigInt256::from_u64(42),
            BigInt256::from_u64(73),
            iterations_toy,
            7,
        );
        result.print();
        results.push(result);
    }

    // ========================================================================
    // 128-bit Security: EC-256 (secp256k1) vs MODP-3072
    // ========================================================================
    println!();
    println!("[128-BIT SECURITY: EC-256 (secp256k1) vs MODP-3072 (RFC 3526)]");
    println!("(MODP = finite-field multiplicative group; security from discrete log problem)");
    println!();

    // EC-256: secp256k1
    {
        let curve = EllipticCurve::new(
            Fp256::new(BigInt::from_u64(0)),
            Fp256::new(BigInt::from_u64(7)),
        );
        let gx =
            BigInt256::from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        let gy =
            BigInt256::from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        let generator = Point::Affine {
            x: Fp256::new(gx),
            y: Fp256::new(gy),
        };
        let order =
            BigInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        let params: SchnorrParamsEC<Fp256, 4> = SchnorrParamsEC {
            curve,
            generator,
            order,
        };
        let private_key =
            BigInt256::from_hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        let base_nonce =
            BigInt256::from_hex("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210");
        let result = benchmark_schnorr_ec(
            "EC: secp256k1",
            params,
            private_key,
            base_nonce,
            iterations_128,
            128,
        );
        result.print();
        results.push(result);
    }

    // MODP-3072: RFC 3526 Group 15
    // Generator selection: start with g=2; if g^q = 1 it's already in the
    // order-q subgroup; if g^q = -1, use g^2 to enter the order-q subgroup.
    {
        let order = compute_subgroup_order(&F3072_MOD);
        let one_field = Fp3072::new(BigInt3072::from_u64(1));
        let p_minus_1 = {
            let one = BigInt3072::from_u64(1);
            let (pm1, _) = F3072_MOD.sub_with_borrow(&one);
            pm1
        };
        let minus_one_field = Fp3072::new(p_minus_1);

        let g = Fp3072::new(BigInt3072::from_u64(2));
        let g_to_q = g.pow(&order.to_le_bytes_vec());
        let generator = if g_to_q == one_field {
            g
        } else if g_to_q == minus_one_field {
            g.clone() * g.clone()
        } else {
            panic!("Generator has unexpected order!");
        };

        let params: SchnorrParamsField<Fp3072, 48> = SchnorrParamsField {
            generator,
            order: order.clone(),
        };
        let private_key = generate_full_size_scalar(b"benchmark_private_key_128", &order);
        let base_nonce = generate_full_size_scalar(b"benchmark_nonce_128", &order);
        let result = benchmark_schnorr_field(
            "MODP: RFC3526-3072",
            params,
            private_key,
            base_nonce,
            iterations_128,
            128,
        );
        result.print();
        results.push(result);
    }

    // ========================================================================
    // ~170-bit Security: MODP-6144 (RFC 3526 Group 17)
    // Provides a second DL security level for comparison
    // ========================================================================
    println!();
    println!("[~170-BIT SECURITY: MODP-6144 (RFC 3526 Group 17)]");
    println!("(Between 128-bit and 192-bit; closest standardized MODP group)");
    println!("(Note: Single iteration due to very slow 6144-bit arithmetic)");
    println!();

    // MODP-6144: RFC 3526 Group 17
    // Using full SchnorrFieldImpl (field arithmetic, proper Schnorr protocol)
    {
        let iterations_170 = 1; // Very slow - single iteration only

        // Safe prime: p = 2q + 1, so order of subgroup = q = (p-1)/2
        let order = {
            let one = BigInt6144::from_u64(1);
            let (pm1, _) = F6144_MOD.sub_with_borrow(&one);
            pm1.shr(1) // q = (p-1)/2
        };

        // Generator selection: start with g=2; if g^q = 1 it's already in the
        // order-q subgroup; if g^q = -1, use g^2 to enter the order-q subgroup.
        let one_field = Fp6144::new(BigInt6144::from_u64(1));
        let p_minus_1 = {
            let one = BigInt6144::from_u64(1);
            let (pm1, _) = F6144_MOD.sub_with_borrow(&one);
            pm1
        };
        let minus_one_field = Fp6144::new(p_minus_1);

        let g = Fp6144::new(BigInt6144::from_u64(2));
        let g_to_q = g.pow(&order.to_le_bytes_vec());
        let generator = if g_to_q == one_field {
            g
        } else if g_to_q == minus_one_field {
            g.clone() * g.clone()
        } else {
            panic!("Generator has unexpected order!");
        };

        let params: SchnorrParamsField<Fp6144, 96> = SchnorrParamsField {
            generator,
            order: order.clone(),
        };
        let private_key = generate_full_size_scalar(b"benchmark_private_key_170", &order);
        let base_nonce = generate_full_size_scalar(b"benchmark_nonce_170", &order);
        let result = benchmark_schnorr_field(
            "MODP: RFC3526-6144",
            params,
            private_key,
            base_nonce,
            iterations_170,
            170,
        );
        result.print();
        results.push(result);
    }

    // ========================================================================
    // 192-bit Security: EC-384 (P-384)
    // ========================================================================
    println!();
    println!("[192-BIT SECURITY: EC-384 (P-384)]");
    println!();

    // EC-384: NIST P-384
    {
        let a = BigInt384::from_hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        );
        let b = BigInt384::from_hex(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        );
        let curve = EllipticCurve::new(Fp384::new(a), Fp384::new(b));
        let gx = BigInt384::from_hex(
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        );
        let gy = BigInt384::from_hex(
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
        );
        let generator = Point::Affine {
            x: Fp384::new(gx),
            y: Fp384::new(gy),
        };
        let order = BigInt384::from_hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        );
        let params: SchnorrParamsEC<Fp384, 6> = SchnorrParamsEC {
            curve,
            generator,
            order,
        };
        let private_key = generate_full_size_scalar(b"benchmark_private_key_192", &order);
        let base_nonce = generate_full_size_scalar(b"benchmark_nonce_192", &order);
        let result = benchmark_schnorr_ec(
            "EC: P-384",
            params,
            private_key,
            base_nonce,
            iterations_192_ec,
            192,
        );
        result.print();
        results.push(result);
    }

    // ========================================================================
    // 256-bit Security: EC-521 (P-521)
    // MODP-15360 omitted as impractically slow
    // ========================================================================
    println!();
    println!("[256-BIT SECURITY: EC-521 (P-521)]");
    println!("(MODP-15360 omitted - would need ~240 limbs, impractical runtime)");
    println!();

    // EC-521: NIST P-521
    {
        let a = BigInt576::from_hex(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
        );
        let b = BigInt576::from_hex(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        );
        let curve = EllipticCurve::new(Fp521::new(a), Fp521::new(b));
        let gx = BigInt576::from_hex(
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        );
        let gy = BigInt576::from_hex(
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
        );
        let generator = Point::Affine {
            x: Fp521::new(gx),
            y: Fp521::new(gy),
        };
        let order = BigInt576::from_hex(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        );
        let params: SchnorrParamsEC<Fp521, 9> = SchnorrParamsEC {
            curve,
            generator,
            order,
        };
        let private_key = generate_full_size_scalar(b"benchmark_private_key_256", &order);
        let base_nonce = generate_full_size_scalar(b"benchmark_nonce_256", &order);
        let result = benchmark_schnorr_ec(
            "EC: P-521",
            params,
            private_key,
            base_nonce,
            iterations_256_ec,
            256,
        );
        result.print();
        results.push(result);
    }

    // ========================================================================
    // Summary Table
    // ========================================================================
    println!();
    println!("+============================================================================+");
    println!("|                    Performance Comparison Summary                          |");
    println!("+============================================================================+");
    println!("| Implementation              | Sec | Iter |   Sign      |    Verify        |");
    println!("+-----------------------------+-----+------+-------------+------------------+");
    for result in &results {
        println!(
            "| {:27} | {:>3} | {:>4} | {:>11.3?} | {:>16.3?} |",
            if result.name.len() > 27 {
                &result.name[..27]
            } else {
                &result.name
            },
            result.security_bits,
            result.iterations,
            result.sign_time / result.iterations,
            result.verify_time / result.iterations
        );
    }
    println!("+============================================================================+");
}
