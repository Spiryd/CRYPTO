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
use l3::elliptic_curve::{BinaryEllipticCurve, EllipticCurve, Point};
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
// Field Configuration: F_2^8
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
// Field Configuration: F_2^4 (GF16 for binary elliptic curves)
// ============================================================================

#[derive(Clone, Debug)]
struct F2_4;

// Irreducible polynomial: x^4 + x + 1
static F2_4_IRRED: [BigInt<4>; 5] = [
    BigInt::from_u64(1), // x^0
    BigInt::from_u64(1), // x^1
    BigInt::from_u64(0), // x^2
    BigInt::from_u64(0), // x^3
    BigInt::from_u64(1), // x^4
];

impl FieldConfig<4> for F2_4 {
    fn modulus() -> &'static BigInt<4> {
        &F2_MOD
    }
    fn irreducible() -> &'static [BigInt<4>] {
        &F2_4_IRRED
    }
}

type GF16 = BinaryField<F2_4, 4, 4>;

// ============================================================================
// Helper function to simulate a two-party key exchange
// ============================================================================

fn demonstrate_key_exchange<const N: usize, DH: DiffieHellman<N>>(
    params: &DH::Params,
    description: &str,
    alice_random: &BigInt<N>,
    bob_random: &BigInt<N>,
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
        q: BigInt::from_u64(48), // order of subgroup (divisor of 96 = 97-1)
    };

    println!("\nDomain Parameters:");
    println!("  Prime p:     {}", dh_fp_params.p_description);
    println!("  Generator g: {:?}", dh_fp_params.g);
    println!("  Order q:     {:?}", dh_fp_params.q);

    demonstrate_key_exchange::<4, DHFp<Fp97, 4>>(
        &dh_fp_params,
        "DH Key Exchange (F_97)",
        &BigInt::from_u64(12345), // Alice's randomness
        &BigInt::from_u64(67890), // Bob's randomness
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
        q: BigInt::from_u64(255), // order of subgroup (divides 2^8 - 1 = 255)
    };

    println!("\nDomain Parameters:");
    println!("  Field:          F_2^{}", dh_f2k_params.k);
    println!("  Irreducible m:  {}", dh_f2k_params.m_description);
    println!("  Generator g:    {:?}", dh_f2k_params.g);
    println!("  Order q:        {:?}", dh_f2k_params.q);

    demonstrate_key_exchange::<4, DHF2k<F2k8, 4>>(
        &dh_f2k_params,
        "DH Key Exchange (F_2^8)",
        &BigInt::from_u64(111),
        &BigInt::from_u64(222),
    );

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
        q: BigInt::from_u64(24), // order of subgroup (divides 5^2 - 1 = 24)
    };

    println!("\nDomain Parameters:");
    println!("  Prime p:        {}", dh_fpk_params.p_description);
    println!("  Extension k:    {}", dh_fpk_params.k);
    println!("  Irreducible m:  {}", dh_fpk_params.m_description);
    println!("  Generator g:    {:?}", dh_fpk_params.g);
    println!("  Order q:        {:?}", dh_fpk_params.q);

    demonstrate_key_exchange::<4, DHFpk<F52, 4>>(
        &dh_fpk_params,
        "DH Key Exchange (F_5^2)",
        &BigInt::from_u64(333),
        &BigInt::from_u64(444),
    );

    // ========================================================================
    // Example 4: ECDH over prime field F_97
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 4: Elliptic Curve DH over F_97                                    │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    // Curve: y^2 = x^3 + 2x + 3 over F_97
    // This curve has a generator (3, 6) with order 5
    let curve = EllipticCurve::new(Fp97::from_u64(2), Fp97::from_u64(3));
    let generator = Point::Affine {
        x: Fp97::from_u64(3),
        y: Fp97::from_u64(6),
    };
    
    // Verify the generator is on the curve
    assert!(curve.is_on_curve(&generator), "Generator must be on curve");

    let ecdh_fp_params = DHParamsEC {
        field_description: "F_97".to_string(),
        curve,
        generator: generator.clone(),
        q: BigInt::from_u64(5), // Order of generator point
    };

    println!("\nDomain Parameters:");
    println!("  Field:       {}", ecdh_fp_params.field_description);
    println!("  Curve:       y^2 = x^3 + 2x + 3");
    println!("  Generator G: (3, 6)");
    println!("  Order q:     5");

    println!("\nECDH Key Exchange (F_97)");
    println!("{}", "=".repeat(80));

    // Use direct private keys (coprime to order 5)
    // Bypassing generate_private_key for this demo to use exact values
    let alice_sk: BigInt<4> = BigInt::from_u64(2);
    let bob_sk: BigInt<4> = BigInt::from_u64(3);

    // Alice's keys
    let alice_pk = DHEC::<Fp97, 4>::compute_public_key(&ecdh_fp_params, &alice_sk);
    println!("Alice generates:");
    println!("  Private key: 2");
    println!("  Public key:  {:?}", alice_pk);

    // Bob's keys
    let bob_pk = DHEC::<Fp97, 4>::compute_public_key(&ecdh_fp_params, &bob_sk);
    println!("\nBob generates:");
    println!("  Private key: 3");
    println!("  Public key:  {:?}", bob_pk);

    // Shared secrets
    let alice_shared = DHEC::<Fp97, 4>::compute_shared_secret(&ecdh_fp_params, &alice_sk, &bob_pk);
    let bob_shared = DHEC::<Fp97, 4>::compute_shared_secret(&ecdh_fp_params, &bob_sk, &alice_pk);

    println!("\nAlice computes shared secret: {:?}", alice_shared);
    println!("Bob computes shared secret:   {:?}", bob_shared);

    if alice_shared == bob_shared {
        println!("\n✓ SUCCESS: Both parties computed the same shared secret!");
    } else {
        println!("\n✗ FAILURE: Shared secrets do not match!");
    }

    // ========================================================================
    // Example 5: ECDH over binary field F_2^4 (GF16)
    // ========================================================================

    println!("\n\n");
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Example 5: Elliptic Curve DH over Binary Field F_2^4                      │");
    println!("└────────────────────────────────────────────────────────────────────────────┘");

    // Binary curve: y² + xy = x³ + ax² + b over GF(2^4)
    // Using a=0, b=1: y² + xy = x³ + 1
    let bin_a = GF16::from_u64(0);
    let bin_b = GF16::from_u64(1);
    let binary_curve = BinaryEllipticCurve::new(bin_a, bin_b);

    // Find a valid generator point
    let mut bin_generator = None;
    for x_val in 1..16u64 {
        for y_val in 0..16u64 {
            let pt = Point::Affine {
                x: GF16::from_u64(x_val),
                y: GF16::from_u64(y_val),
            };
            if binary_curve.is_on_curve(&pt) {
                // Verify this isn't a low-order point by checking [2]P ≠ ∞
                let doubled = binary_curve.double(&pt);
                if !matches!(doubled, Point::Infinity) {
                    bin_generator = Some(pt);
                    break;
                }
            }
        }
        if bin_generator.is_some() {
            break;
        }
    }
    let bin_gen = bin_generator.expect("No generator point found");

    // Find the order of the generator by iterating until we hit infinity
    let mut order = 1u64;
    let mut current = bin_gen.clone();
    while !matches!(current, Point::Infinity) && order < 100 {
        current = binary_curve.add(&current, &bin_gen);
        order += 1;
    }

    let ecdh_binary_params = DHParamsBinaryEC {
        field_description: "F_2^4 (GF16)".to_string(),
        curve: binary_curve,
        generator: bin_gen.clone(),
        q: BigInt::from_u64(order),
    };

    println!("\nDomain Parameters:");
    println!("  Field:       {}", ecdh_binary_params.field_description);
    println!("  Curve:       y² + xy = x³ + ax² + b (a=0, b=1)");
    println!("  Generator G: {:?}", ecdh_binary_params.generator);
    println!("  Order q:     {:?}", ecdh_binary_params.q);

    // Use small private keys (< order)
    let bin_alice_random = BigInt::from_u64(2);
    let bin_bob_random = BigInt::from_u64(3);

    println!("\nECDH Key Exchange (Binary Curve over GF16)");
    println!("{}", "=".repeat(80));

    // Alice's keys
    let bin_alice_sk = DHBinaryEC::<GF16, 4>::generate_private_key(&ecdh_binary_params, &bin_alice_random);
    let bin_alice_pk = DHBinaryEC::<GF16, 4>::compute_public_key(&ecdh_binary_params, &bin_alice_sk);
    println!("Alice generates:");
    println!("  Private key: {:?}", bin_alice_sk);
    println!("  Public key:  {:?}", bin_alice_pk);

    // Bob's keys
    let bin_bob_sk = DHBinaryEC::<GF16, 4>::generate_private_key(&ecdh_binary_params, &bin_bob_random);
    let bin_bob_pk = DHBinaryEC::<GF16, 4>::compute_public_key(&ecdh_binary_params, &bin_bob_sk);
    println!("\nBob generates:");
    println!("  Private key: {:?}", bin_bob_sk);
    println!("  Public key:  {:?}", bin_bob_pk);

    // Shared secrets
    let bin_alice_shared = DHBinaryEC::<GF16, 4>::compute_shared_secret(&ecdh_binary_params, &bin_alice_sk, &bin_bob_pk);
    let bin_bob_shared = DHBinaryEC::<GF16, 4>::compute_shared_secret(&ecdh_binary_params, &bin_bob_sk, &bin_alice_pk);

    println!("\nAlice computes shared secret: {:?}", bin_alice_shared);
    println!("Bob computes shared secret:   {:?}", bin_bob_shared);

    if bin_alice_shared == bin_bob_shared {
        println!("\n✓ SUCCESS: Both parties computed the same shared secret!");
    } else {
        println!("\n✗ FAILURE: Shared secrets do not match!");
    }

    // Validate that both shared secrets are on the curve
    println!("\nPublic Key Validation:");
    match validate_binary_ec_public_key(&ecdh_binary_params, &bin_alice_pk) {
        Ok(()) => println!("  Alice's public key: ✓ Valid (on curve, not infinity)"),
        Err(e) => println!("  Alice's public key: ✗ Invalid ({:?})", e),
    }
    match validate_binary_ec_public_key(&ecdh_binary_params, &bin_bob_pk) {
        Ok(()) => println!("  Bob's public key:   ✓ Valid (on curve, not infinity)"),
        Err(e) => println!("  Bob's public key:   ✗ Invalid ({:?})", e),
    }

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
    println!("  ✓ Elliptic curves over F_p (ECDH)");
    println!("  ✓ Elliptic curves over F_2^k (Binary ECDH)");
}
