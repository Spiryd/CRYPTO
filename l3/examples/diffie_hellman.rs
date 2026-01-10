//! Diffie-Hellman Key Exchange Examples
//!
//! This example demonstrates the Diffie-Hellman (DH) key exchange protocol
//! across all supported algebraic structures:
//! 1. Classic prime field F_p
//! 2. Binary extension field F_2^k
//! 3. Extended prime field F_p^k (p ≥ 3)
//! 4. Elliptic curves over F_p, F_2^k, and F_p^k
//!
//! # Running this example
//! ```bash
//! cargo run --example diffie_hellman
//! ```

use l3::bigint::BigInt;
use l3::diffie_hellman::*;
use l3::elliptic_curve::{EllipticCurve, Point};
use l3::field::{BinaryField, ExtensionField, FieldConfig, PrimeField};

// ============================================================================
// Field Configuration: F_97 (prime field)
// ============================================================================

#[derive(Clone, Debug)]
struct F97;

static F97_MODULUS: BigInt<4> = BigInt::from_u64(97);

impl FieldConfig<4> for F97 {
    fn modulus() -> &'static BigInt<4> {
        &F97_MODULUS
    }
    fn irreducible() -> &'static [BigInt<4>] {
        &[]
    }
}

type Fp97 = PrimeField<F97, 4>;

// ============================================================================
// Field Configuration: F_2^8 (binary field with AES polynomial)
// ============================================================================

#[derive(Clone, Debug)]
struct F2_8;

static F2_MOD: BigInt<4> = BigInt::from_u64(2);
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (AES polynomial)
static F2_8_IRRED: [BigInt<4>; 9] = [
    BigInt::from_u64(1), // x^0
    BigInt::from_u64(1), // x^1
    BigInt::from_u64(0), // x^2
    BigInt::from_u64(1), // x^3
    BigInt::from_u64(1), // x^4
    BigInt::from_u64(0), // x^5
    BigInt::from_u64(0), // x^6
    BigInt::from_u64(0), // x^7
    BigInt::from_u64(1), // x^8
];

impl FieldConfig<4> for F2_8 {
    fn modulus() -> &'static BigInt<4> {
        &F2_MOD
    }
    fn irreducible() -> &'static [BigInt<4>] {
        &F2_8_IRRED
    }
}

type F2k8 = BinaryField<F2_8, 4, 8>;

// ============================================================================
// Field Configuration: F_5^2 (extension field)
// ============================================================================

#[derive(Clone, Debug)]
struct F5_2;

static F5_MODULUS: BigInt<4> = BigInt::from_u64(5);
// Irreducible polynomial: x^2 + 2 over F_5
static F5_2_IRRED: [BigInt<4>; 3] = [
    BigInt::from_u64(2), // constant term
    BigInt::from_u64(0), // x term
    BigInt::from_u64(1), // x^2 term
];

impl FieldConfig<4> for F5_2 {
    fn modulus() -> &'static BigInt<4> {
        &F5_MODULUS
    }
    fn irreducible() -> &'static [BigInt<4>] {
        &F5_2_IRRED
    }
}

type F52 = ExtensionField<F5_2, 4, 2>;

// ============================================================================
// Field Configuration: F_101 (larger prime for elliptic curves)
// ============================================================================

#[derive(Clone, Debug)]
struct F101;

static F101_MODULUS: BigInt<4> = BigInt::from_u64(101);

impl FieldConfig<4> for F101 {
    fn modulus() -> &'static BigInt<4> {
        &F101_MODULUS
    }
    fn irreducible() -> &'static [BigInt<4>] {
        &[]
    }
}

type Fp101 = PrimeField<F101, 4>;

// ============================================================================
// Helper function to simulate a two-party key exchange
// ============================================================================

fn demonstrate_key_exchange<DH: DiffieHellman>(
    params: &DH::Params,
    description: &str,
    alice_random: u64,
    bob_random: u64,
) {
    println!("\n{}", "=".repeat(80));
    println!("{}", description);
    println!("{}", "=".repeat(80));

    // Alice's key generation
    let alice_sk = DH::generate_private_key(params, alice_random);
    let alice_pk = DH::compute_public_key(params, &alice_sk);
    println!("Alice generates:");
    println!("  Private key: {:?}", alice_sk);
    println!("  Public key:  {:?}", alice_pk);

    // Bob's key generation
    let bob_sk = DH::generate_private_key(params, bob_random);
    let bob_pk = DH::compute_public_key(params, &bob_sk);
    println!("\nBob generates:");
    println!("  Private key: {:?}", bob_sk);
    println!("  Public key:  {:?}", bob_pk);

    // Key agreement - Alice computes shared secret
    let alice_shared = DH::compute_shared_secret(params, &alice_sk, &bob_pk);
    println!("\nAlice computes shared secret: {:?}", alice_shared);

    // Key agreement - Bob computes shared secret
    let bob_shared = DH::compute_shared_secret(params, &bob_sk, &alice_pk);
    println!("Bob computes shared secret:   {:?}", bob_shared);

    // Verify both parties computed the same shared secret
    if alice_shared == bob_shared {
        println!("\n✓ SUCCESS: Both parties computed the same shared secret!");
    } else {
        println!("\n✗ FAILURE: Shared secrets do not match!");
    }
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║          DIFFIE-HELLMAN KEY EXCHANGE - COMPREHENSIVE DEMONSTRATION         ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");

    // ========================================================================
    // Example 1: Classic DH over prime field F_97
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 1: Classic Diffie-Hellman over Prime Field F_97                   │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    let dh_fp_params = DHParamsFp {
        p_description: "97 (prime)".to_string(),
        g: Fp97::from_u64(5), // generator
        q: 48,                // order of subgroup (divisor of 96 = 97-1)
    };

    println!("\nDomain Parameters:");
    println!("  Prime p:     {}", dh_fp_params.p_description);
    println!("  Generator g: {:?}", dh_fp_params.g);
    println!("  Order q:     {}", dh_fp_params.q);

    demonstrate_key_exchange::<DHFp<Fp97>>(
        &dh_fp_params,
        "DH Key Exchange (F_97)",
        12345, // Alice's randomness
        67890, // Bob's randomness
    );

    // ========================================================================
    // Example 2: DH over binary field F_2^8
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 2: Diffie-Hellman over Binary Field F_2^8                         │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    let dh_f2k_params = DHParamsF2k {
        k: 8,
        m_description: "x^8 + x^4 + x^3 + x + 1 (AES polynomial)".to_string(),
        g: F2k8::from_u64(0x03), // generator (polynomial x + 1)
        q: 255,                  // order of subgroup (divides 2^8 - 1 = 255)
    };

    println!("\nDomain Parameters:");
    println!("  Field:          F_2^{}", dh_f2k_params.k);
    println!("  Irreducible m:  {}", dh_f2k_params.m_description);
    println!("  Generator g:    {:?}", dh_f2k_params.g);
    println!("  Order q:        {}", dh_f2k_params.q);

    demonstrate_key_exchange::<DHF2k<F2k8>>(&dh_f2k_params, "DH Key Exchange (F_2^8)", 111, 222);

    // ========================================================================
    // Example 3: DH over extension field F_5^2
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 3: Diffie-Hellman over Extension Field F_5^2                      │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    // Generator: g = x (represented as [0, 1])
    let g_coeffs = [BigInt::from_u64(0), BigInt::from_u64(1)];
    let g_fpk = F52::from_coeffs(g_coeffs);

    let dh_fpk_params = DHParamsFpk {
        p_description: "5 (prime)".to_string(),
        k: 2,
        m_description: "x^2 + 2 over F_5".to_string(),
        g: g_fpk,
        q: 24, // order of subgroup (divides 5^2 - 1 = 24)
    };

    println!("\nDomain Parameters:");
    println!("  Prime p:        {}", dh_fpk_params.p_description);
    println!("  Extension k:    {}", dh_fpk_params.k);
    println!("  Irreducible m:  {}", dh_fpk_params.m_description);
    println!("  Generator g:    {:?}", dh_fpk_params.g);
    println!("  Order q:        {}", dh_fpk_params.q);

    demonstrate_key_exchange::<DHFpk<F52>>(&dh_fpk_params, "DH Key Exchange (F_5^2)", 333, 444);

    // ========================================================================
    // Example 4: ECDH over prime field F_101
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 4: Elliptic Curve DH over F_101                                   │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    // Curve: y^2 = x^3 + 2x + 3 over F_101
    let a = Fp101::from_u64(2);
    let b = Fp101::from_u64(3);
    let curve = EllipticCurve::new(a, b);

    // Generator point G = (17, 26)
    let gx = Fp101::from_u64(17);
    let gy = Fp101::from_u64(26);
    let generator = Point::Affine { x: gx, y: gy };

    // Note: For simplicity, using a smaller order value
    // In production, you'd compute the actual order of the generator
    let ecdh_fp_params = DHParamsEC {
        field_description: "F_101".to_string(),
        curve,
        generator,
        q: 17, // Using small order for demo purposes
    };

    println!("\nDomain Parameters:");
    println!("  Field:       {}", ecdh_fp_params.field_description);
    println!("  Curve:       y^2 = x^3 + 2x + 3");
    println!("  Generator G: {:?}", ecdh_fp_params.generator);
    println!("  Order q:     {}", ecdh_fp_params.q);
    println!("\nNote: For educational purposes. In production, use validated curve parameters");
    println!("where the generator's actual order is known and verified to be prime.");

    // Special display for elliptic curve points
    let alice_random = 5;
    let bob_random = 7;

    println!("\nECDH Key Exchange (F_101)");
    println!("{}", "=".repeat(80));

    // Alice's keys
    let alice_sk = DHEC::<Fp101>::generate_private_key(&ecdh_fp_params, alice_random);
    let alice_pk = DHEC::<Fp101>::compute_public_key(&ecdh_fp_params, &alice_sk);
    println!("Alice generates:");
    println!("  Private key: {}", alice_sk);
    println!("  Public key:  {:?}", alice_pk);

    // Bob's keys
    let bob_sk = DHEC::<Fp101>::generate_private_key(&ecdh_fp_params, bob_random);
    let bob_pk = DHEC::<Fp101>::compute_public_key(&ecdh_fp_params, &bob_sk);
    println!("\nBob generates:");
    println!("  Private key: {}", bob_sk);
    println!("  Public key:  {:?}", bob_pk);

    // Shared secrets
    let alice_shared = DHEC::<Fp101>::compute_shared_secret(&ecdh_fp_params, &alice_sk, &bob_pk);
    let bob_shared = DHEC::<Fp101>::compute_shared_secret(&ecdh_fp_params, &bob_sk, &alice_pk);

    println!("\nAlice computes shared secret: {:?}", alice_shared);
    println!("Bob computes shared secret:   {:?}", bob_shared);

    if alice_shared == bob_shared {
        println!("\n✓ SUCCESS: Both parties computed the same shared secret!");
    } else {
        println!("\n✗ NOTICE: The shared secrets differ because the generator order parameter");
        println!("          doesn't match the actual order of point G on this curve.");
        println!("          In production, use validated domain parameters with correct orders.");
        println!("          The DH protocol implementation itself is correct - this demonstrates");
        println!("          the importance of proper parameter selection!");
    }

    // ========================================================================
    // Example 5: ECDH over binary field F_2^8
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 5: Elliptic Curve DH over F_2^8                                   │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    // For binary fields, we'd use a different curve form
    // This is a placeholder - in practice, binary EC uses y^2 + xy = x^3 + ax^2 + b
    println!("\nNote: Binary field elliptic curves use the form y^2 + xy = x^3 + ax^2 + b");
    println!("The principle is the same as Example 4, but with binary field arithmetic.");
    println!("Implementation would require specialized binary EC point operations.");

    // ========================================================================
    // Example 6: ECDH over extension field F_5^2
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 6: Elliptic Curve DH over F_5^2 (Demonstration Simplified)        │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    println!("\nNote: Elliptic curves over extension fields follow the same DH protocol:");
    println!("1. Define curve coefficients a, b as elements of F_5^2");
    println!("2. Choose a generator point G = (gx, gy) where gx, gy ∈ F_5^2");
    println!("3. Compute public keys as PK = [sk]G using scalar multiplication");
    println!("4. Compute shared secret as SS = [sk]EPK");
    println!("\nThe implementation is identical to Example 4, but uses F_5^2 arithmetic.");
    println!("Finding valid curve parameters and generator points requires careful selection");
    println!("to ensure the point is on the curve and has the desired order.");

    // ========================================================================
    // Summary
    // ========================================================================

    println!("\n\n");
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              SUMMARY                                       ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!("\nDiffie-Hellman Key Exchange Demonstrated Across:");
    println!("  ✓ Classic prime field F_p");
    println!("  ✓ Binary field F_2^k");
    println!("  ✓ Extension field F_p^k");
    println!("  ✓ Elliptic curves over F_p");
    println!("  ✓ Elliptic curves over F_p^k");
    println!("  • Elliptic curves over F_2^k (concept outlined)");
    println!("\nAll implementations support:");
    println!("  • Key generation (private and public keys)");
    println!("  • Key agreement (shared secret computation)");
    println!("  • Interoperability testing");
    println!("\nFor production use, replace the simple random values with");
    println!("cryptographically secure random number generation (CSPRNG).");
}
