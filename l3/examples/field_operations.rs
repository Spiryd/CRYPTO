//! Example: All Field Operations
//!
//! Demonstrates the six required field operations

use l3::bigint::BigInt;
use l3::field::{FieldConfig, PrimeField};
use l3::field_trait::FieldElement;

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  All Field Operations Demo                                    ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    #[derive(Clone, Debug)]
    struct F101;
    static F101_MOD: BigInt<4> = BigInt::from_u64(101);
    impl FieldConfig<4> for F101 {
        fn modulus() -> &'static BigInt<4> {
            &F101_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }
    type F101Field = PrimeField<F101, 4>;

    let a = F101Field::from_u64(45);
    let b = F101Field::from_u64(67);

    println!("\n  Working in F_101 with a = 45, b = 67:\n");

    // ✓ Addition
    let sum = a.clone() + b.clone();
    println!("  ✓ Addition:       a + b = {} (mod 101)", sum.value());

    // ✓ Negation
    let neg_a = -a.clone();
    println!("  ✓ Negation:       -a = {} (mod 101)", neg_a.value());
    println!(
        "                    Verify: a + (-a) = {} ✓",
        (a.clone() + neg_a.clone()).value()
    );

    // ✓ Subtraction
    let diff = a.clone() - b.clone();
    println!("  ✓ Subtraction:    a - b = {} (mod 101)", diff.value());

    // ✓ Multiplication
    let prod = a.clone() * b.clone();
    println!("  ✓ Multiplication: a * b = {} (mod 101)", prod.value());

    // ✓ Inverse
    let a_inv = a.inverse();
    println!("  ✓ Inverse:        a⁻¹ = {} (mod 101)", a_inv.value());
    println!(
        "                    Verify: a * a⁻¹ = {} ✓",
        (a.clone() * a_inv.clone()).value()
    );

    // ✓ Division
    let quot = a.clone() / b.clone();
    println!("  ✓ Division:       a / b = {} (mod 101)", quot.value());
    println!(
        "                    Verify: (a/b) * b = {} ✓",
        (quot * b.clone()).value()
    );

    println!("\n  ✅ All 6 required operations implemented!\n");
}
