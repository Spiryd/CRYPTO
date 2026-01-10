//! Example: Elliptic Curves over Finite Fields
//!
//! Demonstrates elliptic curve groups in both prime and binary fields

use l3::bigint::{BigInt, BigInt256};
use l3::elliptic_curve::{BinaryEllipticCurve, EllipticCurve, Point};
use l3::field::{BinaryField, FieldConfig, PrimeField};

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  Elliptic Curves over Finite Fields                           ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    // ===== PRIME FIELD CURVES =====
    println!("\n┌─ Prime Field Curves (y² = x³ + ax + b) ─────────────────────┐\n");

    #[derive(Clone, Debug)]
    struct F97Config;
    static F97_MODULUS: BigInt<4> = BigInt::from_u64(97);
    impl FieldConfig<4> for F97Config {
        fn modulus() -> &'static BigInt<4> {
            &F97_MODULUS
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }
    type F97 = PrimeField<F97Config, 4>;

    fn format_point(p: &Point<F97>) -> String {
        match p {
            Point::Infinity => "𝒪".to_string(),
            Point::Affine { x, y } => format!("({}, {})", x.value(), y.value()),
        }
    }

    let a = F97::from_u64(2);
    let b = F97::from_u64(3);
    let curve = EllipticCurve::new(a, b);

    println!("  Curve: y² = x³ + 2x + 3 over F_97\n");

    let p = curve.point(F97::from_u64(3), F97::from_u64(6));
    println!("  Point P: {}", format_point(&p));
    println!("  -P: {}", format_point(&curve.negate(&p)));
    println!("  2P: {}", format_point(&curve.double(&p)));
    println!("  3P: {}", format_point(&curve.scalar_mul(&p, &[3])));
    println!("  10P: {}", format_point(&curve.scalar_mul(&p, &[10])));

    // ===== BINARY FIELD CURVES =====
    println!("\n┌─ Binary Field Curves (y² + xy = x³ + ax² + b) ──────────────┐\n");

    #[derive(Clone, Debug)]
    struct GF2_8;
    static GF2_MOD: BigInt256 = BigInt256::from_u64(2);
    static GF2_8_IRRED: [BigInt256; 9] = [
        BigInt256::from_u64(1), // x^0
        BigInt256::from_u64(1), // x^1
        BigInt256::from_u64(0), // x^2
        BigInt256::from_u64(1), // x^3
        BigInt256::from_u64(1), // x^4
        BigInt256::from_u64(0), // x^5
        BigInt256::from_u64(0), // x^6
        BigInt256::from_u64(0), // x^7
        BigInt256::from_u64(1), // x^8
    ];
    impl FieldConfig<4> for GF2_8 {
        fn modulus() -> &'static BigInt256 {
            &GF2_MOD
        }
        fn irreducible() -> &'static [BigInt256] {
            &GF2_8_IRRED
        }
    }
    type GF256 = BinaryField<GF2_8, 4, 8>;

    let a_bin = GF256::from_u64(1);
    let b_bin = GF256::from_u64(1);
    let bin_curve = BinaryEllipticCurve::new(a_bin, b_bin);

    println!("  Binary Curve: y² + xy = x³ + x² + 1 over GF(2^8)\n");

    let p_bin = Point::Affine {
        x: GF256::from_u64(0x02),
        y: GF256::from_u64(0x03),
    };

    println!("  Point P: (0x02, 0x03)");

    let neg_p = bin_curve.negate(&p_bin);
    match &neg_p {
        Point::Affine { x, y } => {
            println!(
                "  -P: (0x{:02x}, 0x{:02x})",
                x.to_bigint().limbs()[0] & 0xFF,
                y.to_bigint().limbs()[0] & 0xFF
            );
        }
        _ => println!("  -P: 𝒪"),
    }

    let double_p = bin_curve.double(&p_bin);
    match &double_p {
        Point::Affine { x, y } => {
            println!(
                "  2P: (0x{:02x}, 0x{:02x})",
                x.to_bigint().limbs()[0] & 0xFF,
                y.to_bigint().limbs()[0] & 0xFF
            );
        }
        _ => println!("  2P: 𝒪"),
    }

    let scalar_10 = bin_curve.scalar_mul(&p_bin, &[10]);
    match &scalar_10 {
        Point::Affine { x, y } => {
            println!(
                "  10P: (0x{:02x}, 0x{:02x})",
                x.to_bigint().limbs()[0] & 0xFF,
                y.to_bigint().limbs()[0] & 0xFF
            );
        }
        _ => println!("  10P: 𝒪"),
    }

    println!("\n  ✓ Elliptic curve cryptography ready!");
    println!("  ✓ Supports both prime and binary field curves");
    println!("  ✓ Efficient O(log k) scalar multiplication\n");
}
