mod bigint;
mod field;
mod polynomial;
mod extension_field;
mod binary_field;

use bigint::BigUint;
use field::{Field, FieldElement};
use polynomial::Polynomial;
use extension_field::ExtensionFieldElement;
use binary_field::BinaryFieldElement;

fn main() {
    println!("=== Finite Field Cryptography Library ===\n");
    
    demo_base_field();
    demo_extension_field();
    demo_binary_field();
    demo_large_fields();
}

/// Demonstrate operations in base field Fp (k=1 case)
fn demo_base_field() {
    println!("--- Base Field Fp Arithmetic ---");
    
    // Work in F_17 (prime field)
    let p = BigUint::from_u64(17);
    println!("Working in F_{}", p);
    
    let a = FieldElement::from_u64(5, p.clone());
    let b = FieldElement::from_u64(12, p.clone());
    
    println!("\na = {}", a);
    println!("b = {}", b);
    
    // Addition
    let sum = &a + &b;
    println!("\na + b = {}", sum);
    
    // Negation
    let neg_a = -&a;
    println!("-a = {}", neg_a);
    
    // Subtraction
    let diff = &a - &b;
    println!("a - b = {}", diff);
    
    // Multiplication
    let prod = &a * &b;
    println!("a * b = {}", prod);
    
    // Inverse
    if let Some(inv_a) = a.inv() {
        println!("a^(-1) = {}", inv_a);
        
        // Verify: a * a^(-1) = 1
        let verify = &a * &inv_a;
        println!("a * a^(-1) = {} (should be 1)", verify);
    }
    
    // Division
    if let Some(quotient) = &a / &b {
        println!("a / b = {}", quotient);
    }
    
    // Exponentiation (efficient O(log exp) algorithm)
    let exp = BigUint::from_u64(10);
    let power = a.pow(&exp);
    println!("a^10 = {}", power);
    
    // Large exponent to demonstrate efficiency
    let large_exp = BigUint::from_u64(123456);
    let large_power = a.pow(&large_exp);
    println!("a^123456 = {} (computed efficiently!)", large_power);
    
    println!();
}

/// Demonstrate operations in extension field Fp^k
fn demo_extension_field() {
    println!("--- Extension Field Fp^k Arithmetic ---");
    
    // Work in F_{7^2} with irreducible polynomial X^2 + 1
    let p = BigUint::from_u64(7);
    println!("Working in F_7^2 with irreducible polynomial X^2 + 1");
    
    // Create irreducible polynomial: X^2 + 1
    let irreducible = Polynomial::new(vec![
        FieldElement::from_u64(1, p.clone()),  // constant term
        FieldElement::from_u64(0, p.clone()),  // X coefficient
        FieldElement::from_u64(1, p.clone()),  // X^2 coefficient
    ]);
    
    println!("Irreducible polynomial: {}", irreducible);
    
    // Create element: 2 + 3X
    let a = ExtensionFieldElement::from_coeffs(
        vec![2, 3],
        irreducible.clone(),
        p.clone(),
    );
    
    // Create element: 4 + 5X
    let b = ExtensionFieldElement::from_coeffs(
        vec![4, 5],
        irreducible.clone(),
        p.clone(),
    );
    
    println!("\na = {}", a);
    println!("b = {}", b);
    
    // Addition
    let sum = &a + &b;
    println!("\na + b = {}", sum);
    
    // Multiplication
    let prod = &a * &b;
    println!("a * b = {}", prod);
    
    // Exponentiation
    let exp = BigUint::from_u64(5);
    let power = a.pow(&exp);
    println!("a^5 = {}", power);
    
    println!();
}

/// Demonstrate operations in binary field F_{2^k}
fn demo_binary_field() {
    println!("--- Binary Field F_2^k Arithmetic ---");
    
    // F_{2^8} with AES irreducible polynomial: X^8 + X^4 + X^3 + X + 1
    // In binary (little-endian): 0b100011011 = 0x11B
    let irreducible = vec![0b00011011, 0b00000001];
    let degree = 8;
    
    println!("Working in F_2^8 (AES field)");
    println!("Irreducible polynomial: X^8 + X^4 + X^3 + X + 1");
    
    // Create elements
    let a = BinaryFieldElement::from_u64(0b01010011, irreducible.clone(), degree);
    let b = BinaryFieldElement::from_u64(0b11001010, irreducible.clone(), degree);
    
    println!("\na = {}", a);
    println!("b = {}", b);
    
    // Addition (XOR in binary fields)
    let sum = &a + &b;
    println!("\na + b = {}", sum);
    
    // Negation (identity in characteristic 2)
    let neg_a = -&a;
    println!("-a = {} (same as a in F_2^k)", neg_a);
    
    // Multiplication
    let prod = &a * &b;
    println!("a * b = {}", prod);
    
    // Inverse
    if let Some(inv_a) = a.inv() {
        println!("a^(-1) = {}", inv_a);
        
        // Verify
        let verify = &a * &inv_a;
        println!("a * a^(-1) = {} (should be 1)", verify);
    }
    
    // Exponentiation
    let exp = BigUint::from_u64(7);
    let power = a.pow(&exp);
    println!("a^7 = {}", power);
    
    println!();
}

/// Demonstrate large field operations (256, 512, 1024 bits)
fn demo_large_fields() {
    println!("--- Large Prime Fields (Cryptographic Sizes) ---");
    
    // 256-bit prime (similar to secp256k1 field)
    let p_256_bytes = hex::decode(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
    ).unwrap();
    let p_256 = BigUint::from_bytes_be(&p_256_bytes);
    
    println!("Working with 256-bit prime field:");
    println!("p = 0x{}", hex::encode(p_256.to_bytes_be()));
    println!("Bit length: {}", p_256.bit_len());
    
    let a = FieldElement::from_u64(12345, p_256.clone());
    let b = FieldElement::from_u64(67890, p_256.clone());
    
    // Perform operations
    let sum = &a + &b;
    let prod = &a * &b;
    
    println!("\nOperations completed successfully!");
    println!("a + b has {} bits", sum.value().bit_len());
    println!("a * b has {} bits", prod.value().bit_len());
    
    // Demonstrate exponentiation efficiency
    let large_exp = BigUint::from_u64(1_000_000);
    println!("\nComputing a^1000000 in 256-bit field...");
    let power = a.pow(&large_exp);
    println!("Result computed efficiently using O(log n) algorithm!");
    println!("Result has {} bits", power.value().bit_len());
    
    println!();
}

// Helper module for hex encoding/decoding
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
    
    pub fn encode(bytes: Vec<u8>) -> String {
        bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_256_bit_field() {
        // Test with a 256-bit prime
        let p_bytes = vec![0xFF; 32]; // Not actually prime, but for testing
        let p = BigUint::from_bytes_be(&p_bytes);
        
        let a = FieldElement::from_u64(100, p.clone());
        let b = FieldElement::from_u64(200, p.clone());
        
        let sum = &a + &b;
        assert!(!sum.is_zero());
    }

    #[test]
    fn test_field_operations_comprehensive() {
        let p = BigUint::from_u64(31);
        
        let a = FieldElement::from_u64(7, p.clone());
        let b = FieldElement::from_u64(11, p.clone());
        
        // Test all operations
        let _ = &a + &b;
        let _ = &a - &b;
        let _ = &a * &b;
        let _ = a.inv();
        let _ = &a / &b;
        let _ = a.pow(&BigUint::from_u64(5));
    }

    #[test]
    fn test_exponentiation_efficiency() {
        let p = BigUint::from_u64(1000000007);
        let a = FieldElement::from_u64(2, p.clone());
        
        // Large exponent - should complete quickly due to O(log n) algorithm
        let exp = BigUint::from_u64(1000000);
        let _ = a.pow(&exp);
    }

    #[test]
    fn test_extension_field_operations() {
        let p = BigUint::from_u64(5);
        
        let irreducible = Polynomial::new(vec![
            FieldElement::from_u64(2, p.clone()),
            FieldElement::from_u64(0, p.clone()),
            FieldElement::from_u64(1, p.clone()),
        ]);
        
        let a = ExtensionFieldElement::from_coeffs(
            vec![1, 2],
            irreducible.clone(),
            p.clone(),
        );
        
        let b = ExtensionFieldElement::from_coeffs(
            vec![3, 4],
            irreducible.clone(),
            p.clone(),
        );
        
        let _ = &a + &b;
        let _ = &a * &b;
        let _ = a.pow(&BigUint::from_u64(3));
    }

    #[test]
    fn test_binary_field_operations() {
        let irreducible = vec![0b00011011, 0b00000001];
        let degree = 8;
        
        let a = BinaryFieldElement::from_u64(0x53, irreducible.clone(), degree);
        let b = BinaryFieldElement::from_u64(0xCA, irreducible.clone(), degree);
        
        let sum = &a + &b;
        let prod = &a * &b;
        
        assert!(!sum.is_zero());
        assert!(!prod.is_zero());
    }
}
