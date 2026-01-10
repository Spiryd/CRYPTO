//! Example: O(log n) Exponentiation
//!
//! Demonstrates efficient binary exponentiation

use l3::bigint::{BigInt, BigInt256};
use l3::field::{FieldConfig, PrimeField};
use l3::field_trait::FieldElement;

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  Efficient O(log n) Exponentiation                            ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    #[derive(Clone, Debug)]
    struct F97;
    static F97_MOD: BigInt<4> = BigInt::from_u64(97);
    impl FieldConfig<4> for F97 {
        fn modulus() -> &'static BigInt<4> {
            &F97_MOD
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }
    type F97Field = PrimeField<F97, 4>;

    let base = F97Field::from_u64(5);

    println!("\n  Computing 5^exp (mod 97) using binary exponentiation:\n");

    // Small exponent
    let exp_10 = BigInt256::from_u64(10);
    let result_10 = base.pow(&exp_10.to_be_bytes());
    println!("  5^10 = {} (mod 97)", result_10.value());
    println!("  Complexity: O(log 10) = ~3-4 multiplications\n");

    // Large exponent
    let exp_large = BigInt256::from_u64(123456);
    let result_large = base.pow(&exp_large.to_be_bytes());
    println!("  5^123456 = {} (mod 97)", result_large.value());
    println!("  Complexity: O(log 123456) ≈ 17 multiplications");
    println!("  (vs. 123,456 multiplications for naive method!)\n");

    // Verify with Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p)
    let exp_96 = BigInt256::from_u64(96); // p - 1 = 96
    let result_96 = base.pow(&exp_96.to_be_bytes());
    println!("  Verification (Fermat's Little Theorem):");
    println!("  5^96 = {} (mod 97) - should be 1 ✓\n", result_96.value());
}
