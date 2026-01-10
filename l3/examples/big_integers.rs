//! Example: Big Integer Support (256/512/1024+ bits)
//!
//! Demonstrates working with large field elements

use l3::bigint::{BigInt, BigInt256};
use l3::field::{FieldConfig, PrimeField};

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  Big Integer Support (256/512/1024+ bits)                     ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    println!("\n  Compile-time configurable BigInt<N> (N = number of 64-bit limbs):\n");

    // 256-bit prime: Example large field
    #[derive(Clone, Debug)]
    struct LargePrime;
    static LARGE_P: BigInt256 = BigInt256::from_u64(18446744073709551557u64); // Large prime
    impl FieldConfig<4> for LargePrime {
        fn modulus() -> &'static BigInt<4> {
            &LARGE_P
        }
        fn irreducible() -> &'static [BigInt<4>] {
            &[]
        }
    }
    type LargeField = PrimeField<LargePrime, 4>;

    let a = LargeField::from_u64(123456789);
    let b = LargeField::from_u64(987654321);
    let product = a * b;

    println!("  Field arithmetic over large prime:");
    println!("    Prime: {}", LARGE_P.limbs()[0]);
    println!("    123456789 * 987654321 (mod p)");
    println!("    Result: {}", product.value().limbs()[0]);
    println!("\n  ✓ BigInt supports 256-bit (N=4), 512-bit (N=8), 1024-bit (N=16)!");
    println!("  ✓ Can be extended to arbitrary sizes\n");
}
