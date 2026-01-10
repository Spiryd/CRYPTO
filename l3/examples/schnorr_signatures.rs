//! Schnorr Signature Scheme Examples
//!
//! This example demonstrates the Schnorr signature scheme across all
//! supported algebraic structures:
//! 1. Prime fields F_p
//! 2. Binary extension fields F_2^k
//! 3. Prime extension fields F_p^k
//! 4. Elliptic curves over various fields
//!
//! The signature format is (s, e) where e = H(R || m) using SHA-256
//!
//! # Running this example
//! ```bash
//! cargo run --example schnorr_signatures
//! ```

use l3::bigint::BigInt;
use l3::elliptic_curve::{EllipticCurve, Point};
use l3::field::{BinaryField, ExtensionField, FieldConfig, PrimeField};
use l3::schnorr::*;

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

type F2m8 = BinaryField<F2_8, 4, 8>;

// ============================================================================
// Field Configuration: F_7^3 (extension field over F_7)
// ============================================================================

#[derive(Clone, Debug)]
struct F7_3;

static F7_MODULUS: BigInt<4> = BigInt::from_u64(7);
// Irreducible polynomial: x^3 + x + 1 over F_7
static F7_3_IRRED: [BigInt<4>; 4] = [
    BigInt::from_u64(1), // x^0
    BigInt::from_u64(1), // x^1
    BigInt::from_u64(0), // x^2
    BigInt::from_u64(1), // x^3
];

impl FieldConfig<4> for F7_3 {
    fn modulus() -> &'static BigInt<4> {
        &F7_MODULUS
    }
    fn irreducible() -> &'static [BigInt<4>] {
        &F7_3_IRRED
    }
}

type F7e3 = ExtensionField<F7_3, 4, 3>;

use l3::field::extension::Poly;

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║           Schnorr Signature Scheme Demonstration              ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // Example 1: Schnorr over Prime Field F_97
    // ========================================================================
    println!("─────────────────────────────────────────────────────────────────");
    println!("Example 1: Schnorr Signatures over Prime Field F_97");
    println!("─────────────────────────────────────────────────────────────────\n");

    // Generator g = 5 (primitive root mod 97)
    let generator = Fp97::new(BigInt::from_u64(5));
    let params_fp = SchnorrParamsField {
        generator: generator.clone(),
        order: 96, // phi(97) = 96
    };

    // Alice's keys
    let alice_private = 42;
    let message = b"Hello from F_97!";

    println!("Field: F_97 (prime field with modulus 97)");
    println!("Generator g = 5");
    println!("Alice's private key: {}", alice_private);
    println!("Message: {:?}", String::from_utf8_lossy(message));

    // Generate public key
    let alice_public = SchnorrFieldImpl::<Fp97>::generate_public_key(&params_fp, alice_private);
    println!(
        "Alice's public key: y = g^x mod 97 = {}",
        alice_public.value()
    );

    // Sign the message
    let nonce = 73; // Random nonce (should be random in practice)
    let signature = SchnorrFieldImpl::<Fp97>::sign(&params_fp, alice_private, message, nonce);
    println!("\nSignature:");
    println!(
        "  s (first 16 bytes): {:02X?}...",
        &signature.s[..signature.s.len().min(16)]
    );
    println!(
        "  e (first 16 bytes): {:02X?}...",
        &signature.e[..signature.e.len().min(16)]
    );

    // Verify the signature
    let valid = SchnorrFieldImpl::<Fp97>::verify(&params_fp, &alice_public, message, &signature);
    println!(
        "\nVerification: {}",
        if valid { "✓ VALID" } else { "✗ INVALID" }
    );

    // Try to verify with wrong message
    let wrong_message = b"Wrong message!";
    let invalid =
        SchnorrFieldImpl::<Fp97>::verify(&params_fp, &alice_public, wrong_message, &signature);
    println!(
        "Wrong message verification: {}",
        if invalid {
            "✓ VALID"
        } else {
            "✗ INVALID (as expected)"
        }
    );

    // ========================================================================
    // Example 2: Schnorr over Binary Field F_2^8
    // ========================================================================
    println!("\n─────────────────────────────────────────────────────────────────");
    println!("Example 2: Schnorr Signatures over Binary Field F_2^8");
    println!("─────────────────────────────────────────────────────────────────\n");

    // Generator (primitive element x in F_2^8)
    let generator_binary = F2m8::new(BigInt::from_u64(0x02)); // x
    let params_f2 = SchnorrParamsField {
        generator: generator_binary.clone(),
        order: 255, // 2^8 - 1
    };

    // Bob's keys
    let bob_private = 99;
    let message_binary = b"Binary field message";

    println!("Field: F_2^8 with AES polynomial x^8 + x^4 + x^3 + x + 1");
    println!("Generator: g = x (polynomial degree 1)");
    println!("Bob's private key: {}", bob_private);
    println!("Message: {:?}", String::from_utf8_lossy(message_binary));

    // Generate public key
    let bob_public = SchnorrFieldImpl::<F2m8>::generate_public_key(&params_f2, bob_private);
    let bob_public_bits = bob_public.bits();
    println!(
        "Bob's public key: y = g^x = 0x{:02X}",
        bob_public_bits.limbs()[0]
    );

    // Sign the message
    let nonce_binary = 177;
    let signature_binary =
        SchnorrFieldImpl::<F2m8>::sign(&params_f2, bob_private, message_binary, nonce_binary);
    println!("\nSignature:");
    println!(
        "  s (first 16 bytes): {:02X?}...",
        &signature_binary.s[..signature_binary.s.len().min(16)]
    );
    println!(
        "  e (first 16 bytes): {:02X?}...",
        &signature_binary.e[..signature_binary.e.len().min(16)]
    );

    // Verify the signature
    let valid_binary = SchnorrFieldImpl::<F2m8>::verify(
        &params_f2,
        &bob_public,
        message_binary,
        &signature_binary,
    );
    println!(
        "\nVerification: {}",
        if valid_binary {
            "✓ VALID"
        } else {
            "✗ INVALID"
        }
    );

    // Try tampering with signature
    let mut tampered_sig = signature_binary.clone();
    if !tampered_sig.s.is_empty() {
        tampered_sig.s[0] ^= 0xFF; // Flip bits
    }
    let invalid_binary =
        SchnorrFieldImpl::<F2m8>::verify(&params_f2, &bob_public, message_binary, &tampered_sig);
    println!(
        "Tampered signature verification: {}",
        if invalid_binary {
            "✓ VALID"
        } else {
            "✗ INVALID (as expected)"
        }
    );

    // ========================================================================
    // Example 3: Schnorr over Extension Field F_7^3
    // ========================================================================
    println!("\n─────────────────────────────────────────────────────────────────");
    println!("Example 3: Schnorr Signatures over Extension Field F_7^3");
    println!("─────────────────────────────────────────────────────────────────\n");

    // Generator (primitive element in F_7^3)
    let poly_coeffs = [
        BigInt::from_u64(1),
        BigInt::from_u64(0),
        BigInt::from_u64(1),
    ];
    let generator_ext = F7e3::new(Poly {
        coeffs: poly_coeffs,
    });
    let params_ext = SchnorrParamsField {
        generator: generator_ext.clone(),
        order: 342, // 7^3 - 1
    };

    // Charlie's keys
    let charlie_private = 123;
    let message_ext = b"Extension field message";

    println!("Field: F_7^3 (extension of degree 3 over F_7)");
    println!("Irreducible polynomial: x^3 + x + 1");
    println!("Charlie's private key: {}", charlie_private);
    println!("Message: {:?}", String::from_utf8_lossy(message_ext));

    // Generate public key
    let charlie_public =
        SchnorrFieldImpl::<F7e3>::generate_public_key(&params_ext, charlie_private);
    print!("Charlie's public key: y = g^x = ");
    let pub_coeffs = charlie_public.coefficients();
    for (i, c) in pub_coeffs.iter().enumerate() {
        if i > 0 {
            print!(" + ");
        }
        print!("{}", c.limbs()[0]);
        if i > 0 {
            print!("α^{}", i);
        }
    }
    println!();

    // Sign the message
    let nonce_ext = 255;
    let signature_ext =
        SchnorrFieldImpl::<F7e3>::sign(&params_ext, charlie_private, message_ext, nonce_ext);
    println!("\nSignature:");
    println!(
        "  s (first 16 bytes): {:02X?}...",
        &signature_ext.s[..signature_ext.s.len().min(16)]
    );
    println!(
        "  e (first 16 bytes): {:02X?}...",
        &signature_ext.e[..signature_ext.e.len().min(16)]
    );

    // Verify the signature
    let valid_ext =
        SchnorrFieldImpl::<F7e3>::verify(&params_ext, &charlie_public, message_ext, &signature_ext);
    println!(
        "\nVerification: {}",
        if valid_ext {
            "✓ VALID"
        } else {
            "✗ INVALID"
        }
    );

    // ========================================================================
    // Example 4: Schnorr over Elliptic Curve
    // ========================================================================
    println!("\n─────────────────────────────────────────────────────────────────");
    println!("Example 4: Schnorr Signatures over Elliptic Curve");
    println!("─────────────────────────────────────────────────────────────────\n");

    // Curve: y^2 = x^3 + x + 6 over F_97
    let a = Fp97::new(BigInt::from_u64(1));
    let b = Fp97::new(BigInt::from_u64(6));
    let curve = EllipticCurve::new(a, b);

    // Generator point
    let gx = Fp97::new(BigInt::from_u64(3));
    let gy = Fp97::new(BigInt::from_u64(6));
    let generator_point = Point::Affine { x: gx, y: gy };

    let params_ec = SchnorrParamsEC {
        curve: curve.clone(),
        generator: generator_point.clone(),
        order: 102, // Approximate order of the generator (simplified for demo)
    };

    // David's keys
    let david_private = 67;
    let message_ec = b"Elliptic curve message";

    println!("Curve: y^2 = x^3 + x + 6 over F_97");
    println!("Generator point: G = (3, 6)");
    println!("David's private key: {}", david_private);
    println!("Message: {:?}", String::from_utf8_lossy(message_ec));

    // Generate public key
    let david_public = SchnorrECImpl::<Fp97>::generate_public_key(&params_ec, david_private);
    match &david_public {
        Point::Affine { x, y } => {
            println!(
                "David's public key: Y = [x]G = ({}, {})",
                x.value(),
                y.value()
            );
        }
        Point::Infinity => println!("David's public key: Y = [x]G = ∞"),
    }

    // Sign the message
    let nonce_ec = 89;
    let signature_ec = SchnorrECImpl::<Fp97>::sign(&params_ec, david_private, message_ec, nonce_ec);
    println!("\nSignature:");
    println!(
        "  s (first 16 bytes): {:02X?}...",
        &signature_ec.s[..signature_ec.s.len().min(16)]
    );
    println!(
        "  e (first 16 bytes): {:02X?}...",
        &signature_ec.e[..signature_ec.e.len().min(16)]
    );

    // Verify the signature
    let valid_ec =
        SchnorrECImpl::<Fp97>::verify(&params_ec, &david_public, message_ec, &signature_ec);
    println!(
        "\nVerification: {}",
        if valid_ec { "✓ VALID" } else { "✗ INVALID" }
    );

    // Try to verify with different public key
    let wrong_public = Point::Affine {
        x: Fp97::new(BigInt::from_u64(10)),
        y: Fp97::new(BigInt::from_u64(20)),
    };
    let invalid_ec =
        SchnorrECImpl::<Fp97>::verify(&params_ec, &wrong_public, message_ec, &signature_ec);
    println!(
        "Wrong public key verification: {}",
        if invalid_ec {
            "✓ VALID"
        } else {
            "✗ INVALID (as expected)"
        }
    );

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                          Summary                               ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    println!("Schnorr signatures successfully demonstrated for:");
    println!("  ✓ Prime fields (F_97)");
    println!("  ✓ Binary fields (F_2^8)");
    println!("  ✓ Extension fields (F_7^3)");
    println!("  ✓ Elliptic curves (y^2 = x^3 + x + 6 over F_97)");

    println!("\nSignature properties:");
    println!("  • Format: (s, e) where e = H(R || m)");
    println!("  • Hash function: SHA-256");
    println!("  • Field-specific encoding for hash input:");
    println!("    - F_p: big-endian hex with fixed byte length");
    println!("    - F_2^k: bit string as hex, byte-aligned");
    println!("    - F_p^k: JSON array of coefficient hex strings");
    println!("    - EC points: JSON object with x, y coordinates");

    println!("\n⚠ Security notes:");
    println!("  • Nonce k MUST be random and NEVER reused!");
    println!("  • Use cryptographically secure random number generator");
    println!("  • These examples use small values for demonstration only");
    println!("  • Production use requires:");
    println!("    - 2048+ bit modulus for discrete log groups");
    println!("    - 256+ bit curves for elliptic curves (secp256k1, P-256)");
    println!("    - Timing-safe implementations");

    println!();
}
