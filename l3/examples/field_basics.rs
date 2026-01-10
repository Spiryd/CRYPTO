//! Example: Generic F_p^k Structure
//!
//! Demonstrates creating and using prime fields and extension fields

use l3::bigint::BigInt;
use l3::field::{ExtensionField, FieldConfig, PrimeField};
use l3::field_trait::FieldElement;

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  Generic F_p^k Structure - Field Basics                       ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    println!("\n📌 Implementing F_97 (prime field, k=1):");
    println!("   Input: p = 97, no irreducible needed for k=1\n");

    // Define F_97 configuration
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

    let a = F97::from_u64(50);
    let b = F97::from_u64(60);
    println!("  Created elements: a = 50, b = 60 in F_97");
    println!("  a + b = {} (mod 97)", (a.clone() + b.clone()).value());
    println!("  a * b = {} (mod 97)", (a * b).value());

    println!("\n📌 Implementing F_5^2 (extension field, k=2):");
    println!("   Input: p = 5, irreducible polynomial x² + x + 2\n");

    // Define F_5^2 configuration
    #[derive(Clone, Debug)]
    struct F5_2Config;

    static F5_MODULUS: BigInt<4> = BigInt::from_u64(5);
    static F5_2_IRRED: [BigInt<4>; 3] = [
        BigInt::from_u64(2), // constant term (x^0)
        BigInt::from_u64(1), // x^1 coefficient
        BigInt::from_u64(1), // x^2 coefficient
    ];

    impl FieldConfig<4> for F5_2Config {
        fn modulus() -> &'static BigInt<4> {
            &F5_MODULUS
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &F5_2_IRRED
        }
    }

    type F25 = ExtensionField<F5_2Config, 4, 2>;

    let coeffs_a: [BigInt<4>; 2] = [BigInt::from_u64(3), BigInt::from_u64(2)];
    let coeffs_b: [BigInt<4>; 2] = [BigInt::from_u64(1), BigInt::from_u64(4)];

    let elem_a = F25::from_coeffs(coeffs_a);
    let elem_b = F25::from_coeffs(coeffs_b);

    println!("  Created elements in F_5^2 (25 elements total):");
    println!("    a = 3 + 2x (polynomial representation)");
    println!("    b = 1 + 4x\n");

    let sum = elem_a.clone() + elem_b.clone();
    println!(
        "  Addition: a + b = {} + {}x",
        sum.poly.coeffs[0], sum.poly.coeffs[1]
    );

    let prod = elem_a.clone() * elem_b.clone();
    println!(
        "  Multiplication: a * b = {} + {}x",
        prod.poly.coeffs[0], prod.poly.coeffs[1]
    );

    let inv_a = elem_a.inverse();
    println!(
        "  Inverse: a⁻¹ = {} + {}x",
        inv_a.poly.coeffs[0], inv_a.poly.coeffs[1]
    );

    println!(
        "\n  ✓ Extension field F_5^2 with {} elements working!\n",
        5u32.pow(2)
    );
}
