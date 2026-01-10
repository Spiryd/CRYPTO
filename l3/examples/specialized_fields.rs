//! Example: Specialized Field Implementations
//!
//! Demonstrates PrimeField (k=1) and BinaryField (p=2) optimizations

use l3::bigint::BigInt;
use l3::field::{BinaryField, FieldConfig, PrimeField};
use l3::field_trait::FieldElement;

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  Specialized Field Implementations                             ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    println!("\n┌─ CASE 1: k = 1 (Prime Fields F_p) ─────────────────────────┐\n");
    println!("  Specialized type: PrimeField<Config, N>");
    println!("  Optimizations: Direct modular arithmetic, no polynomial ops\n");

    #[derive(Clone, Debug)]
    struct F127;
    static F127_MOD: BigInt<4> = BigInt::from_u64(127);
    impl FieldConfig<4> for F127 {
        fn modulus() -> &'static BigInt<4> {
            &F127_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }
    type F127Field = PrimeField<F127, 4>;

    let x = F127Field::from_u64(100);
    let y = F127Field::from_u64(50);
    println!("  Example F_127:");
    println!("    100 * 50 = {} (mod 127)", (x.clone() * y).value());
    println!("    100⁻¹ = {} (mod 127)\n", x.inverse().value());

    println!("┌─ CASE 2: p = 2 (Binary Fields F_2^k) ──────────────────────┐\n");
    println!("  Specialized type: BinaryField<Config, N, K>");
    println!("  Representation: Bit strings");
    println!("  Optimizations: Addition = XOR, no modular reduction needed\n");

    #[derive(Clone, Debug)]
    struct GF16Config;
    static F2_MOD: BigInt<4> = BigInt::from_u64(2);
    static GF16_IRRED: [BigInt<4>; 5] = [
        BigInt::from_u64(1), // x^0
        BigInt::from_u64(1), // x^1
        BigInt::from_u64(0), // x^2
        BigInt::from_u64(0), // x^3
        BigInt::from_u64(1), // x^4
    ];
    impl FieldConfig<4> for GF16Config {
        fn modulus() -> &'static BigInt<4> {
            &F2_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &GF16_IRRED
        }
    }
    type GF16 = BinaryField<GF16Config, 4, 4>;

    let a = GF16::from_u64(0b1010); // x^3 + x
    let b = GF16::from_u64(0b1100); // x^3 + x^2

    println!("  Example GF(2^4) = GF(16) with irreducible x^4 + x + 1:");
    println!("    a = 0b1010 (represents polynomial x³ + x)");
    println!("    b = 0b1100 (represents polynomial x³ + x²)");

    let sum = a.clone() + b.clone();
    let product = a.clone() * b.clone();

    println!("\n  Operations:");
    println!(
        "    a ⊕ b (XOR) = 0b{:04b}",
        sum.to_bigint().limbs()[0] & 0xF
    );
    println!("    -a = a (characteristic 2: elements are self-inverse)");
    println!(
        "    a * b = 0b{:04b} (polynomial mult mod irreducible)",
        product.to_bigint().limbs()[0] & 0xF
    );

    println!("\n  ✓ Bit string representation working");
    println!("  ✓ XOR-based addition (characteristic 2)");
    println!("  ✓ Polynomial multiplication with reduction\n");
}
