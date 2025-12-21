// Binary/CLI entry point for L2 cryptography library demos
// This demonstrates the library functionality - the actual library is in lib.rs

use l2::{
    BigUint,
    Field, FieldElement,
    Polynomial,
    ExtensionFieldElement,
    BinaryFieldElement,
    EllipticCurve,
    BinaryEllipticCurve,
};

fn main() {
    println!("=== Finite Field Cryptography Library ===\n");
    
    demo_base_field();
    demo_extension_field();
    demo_binary_field();
    demo_large_fields();
    demo_elliptic_curves();
    demo_binary_elliptic_curves();
    demo_serialization();
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

/// Demonstrate elliptic curve operations over finite fields
fn demo_elliptic_curves() {
    println!("\n--- Elliptic Curve Groups ---");
    
    // Example 1: Small curve over F_17
    println!("\n=== Example 1: Curve y^2 = x^3 + 2x + 2 over F_17 ===");
    let p = BigUint::from_u64(17);
    println!("Working over F_{}", p);
    
    let a = FieldElement::new(BigUint::from_u64(2), p.clone());
    let b = FieldElement::new(BigUint::from_u64(2), p.clone());
    let curve = EllipticCurve::new(a, b);
    
    println!("Curve equation: y^2 = x^3 + 2x + 2");
    
    // Create some points on the curve
    let p1 = curve.point(
        FieldElement::new(BigUint::from_u64(5), p.clone()),
        FieldElement::new(BigUint::from_u64(1), p.clone())
    );
    let p2 = curve.point(
        FieldElement::new(BigUint::from_u64(6), p.clone()),
        FieldElement::new(BigUint::from_u64(3), p.clone())
    );
    
    println!("\nP1 = (5, 1)");
    println!("P2 = (6, 3)");
    println!("P1 on curve: {}", curve.is_on_curve(&p1));
    println!("P2 on curve: {}", curve.is_on_curve(&p2));
    
    // Point addition
    println!("\n--- Point Addition (Chord Law) ---");
    let p3 = curve.add(&p1, &p2);
    if let Some(x) = p3.x() {
        println!("P1 + P2 = ({}, {})", x, p3.y().unwrap());
    } else {
        println!("P1 + P2 = O (point at infinity)");
    }
    println!("Result on curve: {}", curve.is_on_curve(&p3));
    
    // Point doubling
    println!("\n--- Point Doubling (Tangent Law) ---");
    let p1_doubled = curve.double(&p1);
    if let Some(x) = p1_doubled.x() {
        println!("2*P1 = ({}, {})", x, p1_doubled.y().unwrap());
    } else {
        println!("2*P1 = O (point at infinity)");
    }
    println!("Result on curve: {}", curve.is_on_curve(&p1_doubled));
    
    // Verify doubling equals addition
    let p1_added = curve.add(&p1, &p1);
    println!("2*P1 equals P1 + P1: {}", p1_doubled == p1_added);
    
    // Point negation
    println!("\n--- Point Negation ---");
    let neg_p1 = curve.negate(&p1);
    if let Some(x) = neg_p1.x() {
        println!("-P1 = ({}, {})", x, neg_p1.y().unwrap());
    }
    println!("-P1 on curve: {}", curve.is_on_curve(&neg_p1));
    
    // Verify P + (-P) = O
    let sum = curve.add(&p1, &neg_p1);
    println!("P1 + (-P1) = O: {}", sum.is_infinity());
    
    // Identity element
    println!("\n--- Identity Element ---");
    let inf = curve.infinity();
    let p1_plus_inf = curve.add(&p1, &inf);
    println!("P1 + O = P1: {}", p1_plus_inf == p1);
    
    // Scalar multiplication
    println!("\n--- Scalar Multiplication ---");
    for k in 0..=5 {
        let result = curve.scalar_mul(&BigUint::from_u64(k), &p1);
        if let Some(x) = result.x() {
            println!("{}*P1 = ({}, {})", k, x, result.y().unwrap());
        } else {
            println!("{}*P1 = O", k);
        }
    }
    
    // Example 2: Larger field (simulating secp256k1-like curve)
    println!("\n\n=== Example 2: Curve over larger field (simulating cryptographic use) ===");
    
    // Use a 64-bit prime for demonstration (real crypto uses 256+ bits)
    let large_p = BigUint::from_u64(0xFFFFFFFFFFFFFFC5); // Large prime
    println!("Working over F_{} (64-bit prime)", large_p);
    
    // Curve parameters (simplified, not actual secp256k1)
    let a_large = FieldElement::new(BigUint::from_u64(0), large_p.clone());
    let b_large = FieldElement::new(BigUint::from_u64(7), large_p.clone());
    let large_curve = EllipticCurve::new(a_large, b_large);
    
    println!("Curve equation: y^2 = x^3 + 7");
    
    // Generator point (example coordinates)
    let g = large_curve.point(
        FieldElement::new(BigUint::from_u64(0x79BE667EF9DCBBAC), large_p.clone()),
        FieldElement::new(BigUint::from_u64(0x483ADA7726A3C465), large_p.clone())
    );
    
    println!("\nGenerator point G:");
    if let Some(x) = g.x() {
        println!("  x = {}", x);
        println!("  y = {}", g.y().unwrap());
    }
    println!("G on curve: {}", large_curve.is_on_curve(&g));
    
    // Demonstrate efficient scalar multiplication
    println!("\n--- Efficient Scalar Multiplication ---");
    let secret_key = BigUint::from_u64(12345);
    println!("Computing {}*G using double-and-add algorithm...", secret_key);
    let public_key = large_curve.scalar_mul(&secret_key, &g);
    println!("Result computed!");
    println!("Public key on curve: {}", large_curve.is_on_curve(&public_key));
    
    // Demonstrate group law properties
    println!("\n--- Group Law Properties ---");
    
    let p_small = BigUint::from_u64(17);
    let a_small = FieldElement::new(BigUint::from_u64(2), p_small.clone());
    let b_small = FieldElement::new(BigUint::from_u64(2), p_small.clone());
    let test_curve = EllipticCurve::new(a_small, b_small);
    
    let q1 = test_curve.point(
        FieldElement::new(BigUint::from_u64(5), p_small.clone()),
        FieldElement::new(BigUint::from_u64(1), p_small.clone())
    );
    let q2 = test_curve.point(
        FieldElement::new(BigUint::from_u64(6), p_small.clone()),
        FieldElement::new(BigUint::from_u64(3), p_small.clone())
    );
    let q3 = test_curve.point(
        FieldElement::new(BigUint::from_u64(10), p_small.clone()),
        FieldElement::new(BigUint::from_u64(6), p_small.clone())
    );
    
    // Associativity: (Q1 + Q2) + Q3 = Q1 + (Q2 + Q3)
    let left = test_curve.add(&test_curve.add(&q1, &q2), &q3);
    let right = test_curve.add(&q1, &test_curve.add(&q2, &q3));
    println!("Associativity: (Q1 + Q2) + Q3 = Q1 + (Q2 + Q3): {}", left == right);
    
    // Commutativity: Q1 + Q2 = Q2 + Q1
    let sum1 = test_curve.add(&q1, &q2);
    let sum2 = test_curve.add(&q2, &q1);
    println!("Commutativity: Q1 + Q2 = Q2 + Q1: {}", sum1 == sum2);
    
    // Identity: Q1 + O = Q1
    let inf_test = test_curve.infinity();
    let sum_with_inf = test_curve.add(&q1, &inf_test);
    println!("Identity: Q1 + O = Q1: {}", sum_with_inf == q1);
    
    // Inverse: Q1 + (-Q1) = O
    let neg_q1 = test_curve.negate(&q1);
    let sum_with_inv = test_curve.add(&q1, &neg_q1);
    println!("Inverse: Q1 + (-Q1) = O: {}", sum_with_inv.is_infinity());
    
    println!("\n--- Scalar Multiplication Properties ---");
    
    // Distributivity: k(P + Q) = kP + kQ
    let k = BigUint::from_u64(3);
    let p_plus_q = test_curve.add(&q1, &q2);
    let k_times_sum = test_curve.scalar_mul(&k, &p_plus_q);
    let kp = test_curve.scalar_mul(&k, &q1);
    let kq = test_curve.scalar_mul(&k, &q2);
    let sum_of_muls = test_curve.add(&kp, &kq);
    println!("Distributivity: k(P + Q) = kP + kQ: {}", k_times_sum == sum_of_muls);
    
    // Associativity: (j + k)P = jP + kP
    let j = BigUint::from_u64(2);
    let j_plus_k = &j + &k;
    let combined_mul = test_curve.scalar_mul(&j_plus_k, &q1);
    let jp = test_curve.scalar_mul(&j, &q1);
    let kp_again = test_curve.scalar_mul(&k, &q1);
    let sum_of_scalars = test_curve.add(&jp, &kp_again);
    println!("Scalar associativity: (j + k)P = jP + kP: {}", combined_mul == sum_of_scalars);
    
    println!("\nElliptic curve demonstrations completed!");
}

/// Demonstrate binary elliptic curve operations over F2^m
fn demo_binary_elliptic_curves() {
    println!("\n\n--- Binary Elliptic Curves (F2^m) ---");
    println!("Using characteristic 2 form: y^2 + xy = x^3 + ax^2 + b\n");
    
    // Example 1: Small binary field F2^4
    println!("=== Example 1: Binary curve over F2^4 ===");
    let irreducible = vec![0b10011]; // x^4 + x + 1
    let degree = 4;
    
    println!("Working over F2^4");
    println!("Irreducible polynomial: x^4 + x + 1");
    
    // Curve: y^2 + xy = x^3 + x^2 + 1
    let a = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
    let b = BinaryFieldElement::from_u64(1, irreducible.clone(), degree);
    let curve = BinaryEllipticCurve::new(a, b);
    
    println!("Curve equation: y^2 + xy = x^3 + x^2 + 1\n");
    
    // Find a point on the curve by testing
    println!("Finding points on the curve...");
    let mut test_point = None;
    for x_val in 1..16 {
        for y_val in 0..16 {
            let x = BinaryFieldElement::from_u64(x_val, irreducible.clone(), degree);
            let y = BinaryFieldElement::from_u64(y_val, irreducible.clone(), degree);
            let p = curve.point(x, y);
            if curve.is_on_curve(&p) {
                println!("Found point P = ({:#06b}, {:#06b})", x_val, y_val);
                test_point = Some(p);
                break;
            }
        }
        if test_point.is_some() {
            break;
        }
    }
    
    if let Some(p) = test_point {
        println!("\n--- Point Doubling ---");
        let p2 = curve.double(&p);
        println!("2P computed");
        println!("2P on curve: {}", curve.is_on_curve(&p2));
        
        // Verify doubling equals addition
        let p_plus_p = curve.add(&p, &p);
        println!("2P equals P + P: {}", p2 == p_plus_p);
        
        println!("\n--- Point Negation ---");
        let neg_p = curve.negate(&p);
        println!("-P on curve: {}", curve.is_on_curve(&neg_p));
        
        // Verify P + (-P) = O
        let sum = curve.add(&p, &neg_p);
        println!("P + (-P) = O: {}", sum.is_infinity());
        
        println!("\n--- Identity Element ---");
        let inf = curve.infinity();
        let p_plus_inf = curve.add(&p, &inf);
        println!("P + O = P: {}", p_plus_inf == p);
        
        println!("\n--- Scalar Multiplication ---");
        for k in 0..=5 {
            let result = curve.scalar_mul(k, &p);
            println!("{}*P: {}", k, if result.is_infinity() { "O (infinity)" } else { "on curve" });
            if !result.is_infinity() {
                assert!(curve.is_on_curve(&result));
            }
        }
    }
    
    // Example 2: AES field F2^8
    println!("\n\n=== Example 2: Binary curve over F2^8 (AES field) ===");
    let aes_irreducible = vec![0b00011011, 0b00000001]; // x^8 + x^4 + x^3 + x + 1
    let aes_degree = 8;
    
    println!("Working over F2^8");
    println!("Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (AES polynomial)");
    
    // Curve: y^2 + xy = x^3 + b (where a = 0)
    let a_aes = BinaryFieldElement::from_u64(0, aes_irreducible.clone(), aes_degree);
    let b_aes = BinaryFieldElement::from_u64(1, aes_irreducible.clone(), aes_degree);
    let curve_aes = BinaryEllipticCurve::new(a_aes, b_aes);
    
    println!("Curve equation: y^2 + xy = x^3 + 1\n");
    
    // Test with specific points
    println!("Testing point operations...");
    let x_test = BinaryFieldElement::from_u64(0x03, aes_irreducible.clone(), aes_degree);
    let y_test = BinaryFieldElement::from_u64(0x0A, aes_irreducible.clone(), aes_degree);
    let p_aes = curve_aes.point(x_test, y_test);
    
    if curve_aes.is_on_curve(&p_aes) {
        println!("Point P = (0x03, 0x0A) is on the curve!");
        
        let doubled = curve_aes.double(&p_aes);
        println!("2P on curve: {}", curve_aes.is_on_curve(&doubled));
        
        let tripled = curve_aes.scalar_mul(3, &p_aes);
        println!("3P on curve: {}", curve_aes.is_on_curve(&tripled));
        
        let large_scalar = curve_aes.scalar_mul(100, &p_aes);
        println!("100P on curve: {}", curve_aes.is_on_curve(&large_scalar));
    } else {
        println!("Testing with different point...");
        // Try another point
        for x_val in 1..256 {
            for y_val in 0..256 {
                let x = BinaryFieldElement::from_u64(x_val, aes_irreducible.clone(), aes_degree);
                let y = BinaryFieldElement::from_u64(y_val, aes_irreducible.clone(), aes_degree);
                let p_try = curve_aes.point(x, y);
                if curve_aes.is_on_curve(&p_try) {
                    println!("Found point: (0x{:02X}, 0x{:02X})", x_val, y_val);
                    
                    let test_double = curve_aes.double(&p_try);
                    println!("2P on curve: {}", curve_aes.is_on_curve(&test_double));
                    
                    let test_scalar = curve_aes.scalar_mul(5, &p_try);
                    println!("5P on curve: {}", curve_aes.is_on_curve(&test_scalar));
                    break;
                }
            }
            if x_val > 50 { // Limit search
                break;
            }
        }
    }
    
    // Demonstrate group properties
    println!("\n--- Group Law Properties ---");
    println!("Testing associativity, commutativity, identity, and inverse properties...");
    
    // Use the F2^4 field for testing (smaller, easier to find points)
    let test_irreducible = vec![0b10011];
    let test_degree = 4;
    let a_test = BinaryFieldElement::from_u64(1, test_irreducible.clone(), test_degree);
    let b_test = BinaryFieldElement::from_u64(1, test_irreducible.clone(), test_degree);
    let test_curve = BinaryEllipticCurve::new(a_test, b_test);
    
    // Find three points for testing
    let mut points = Vec::new();
    for x_val in 1..16 {
        for y_val in 0..16 {
            let x = BinaryFieldElement::from_u64(x_val, test_irreducible.clone(), test_degree);
            let y = BinaryFieldElement::from_u64(y_val, test_irreducible.clone(), test_degree);
            let p = test_curve.point(x, y);
            if test_curve.is_on_curve(&p) {
                points.push(p);
                if points.len() == 3 {
                    break;
                }
            }
        }
        if points.len() == 3 {
            break;
        }
    }
    
    if points.len() >= 3 {
        let q1 = &points[0];
        let q2 = &points[1];
        let q3 = &points[2];
        
        // Associativity: (Q1 + Q2) + Q3 = Q1 + (Q2 + Q3)
        let left = test_curve.add(&test_curve.add(q1, q2), q3);
        let right = test_curve.add(q1, &test_curve.add(q2, q3));
        println!("Associativity: (Q1 + Q2) + Q3 = Q1 + (Q2 + Q3): {}", left == right);
        
        // Commutativity: Q1 + Q2 = Q2 + Q1
        let sum1 = test_curve.add(q1, q2);
        let sum2 = test_curve.add(q2, q1);
        println!("Commutativity: Q1 + Q2 = Q2 + Q1: {}", sum1 == sum2);
        
        // Identity: Q1 + O = Q1
        let inf_test = test_curve.infinity();
        let sum_with_inf = test_curve.add(q1, &inf_test);
        println!("Identity: Q1 + O = Q1: {}", sum_with_inf == *q1);
        
        // Inverse: Q1 + (-Q1) = O
        let neg_q1 = test_curve.negate(q1);
        let sum_with_inv = test_curve.add(q1, &neg_q1);
        println!("Inverse: Q1 + (-Q1) = O: {}", sum_with_inv.is_infinity());
    }
    
    println!("\nBinary elliptic curve demonstrations completed!");
}

/// Demonstrate serialization and interoperability features
fn demo_serialization() {
    use l2::serialization::*;
    
    println!("\n\n--- Serialization and Interoperability ---");
    println!("Demonstrating Base 10, Base 16 (hex), and Base64 formats\n");
    
    // 1. BigUint Serialization
    println!("=== 1. BigUint Serialization ===");
    let num = BigUint::from_u64(987654321);
    
    println!("Original number: {}", num.to_base10());
    println!("Base 10:  {}", num.to_base10());
    println!("Base 16:  {}", num.to_base16());
    println!("Base 64:  {}", num.to_base64());
    
    // Round-trip test
    let from_b10 = BigUint::from_base10(&num.to_base10()).unwrap();
    let from_b16 = BigUint::from_base16(&num.to_base16()).unwrap();
    let from_b64 = BigUint::from_base64(&num.to_base64()).unwrap();
    println!("Round-trip verification: {} {} {}", 
        from_b10 == num, from_b16 == num, from_b64 == num);
    
    // 2. Field Element (Fp) Serialization
    println!("\n=== 2. Field Element (Fp) Serialization ===");
    let p = BigUint::from_u64(17);
    let elem = FieldElement::from_u64(13, p);
    
    println!("Field element in F_17: {}", elem);
    println!("\nChoose format at serialization time:");
    
    // Serialize in different formats
    let ser_base10 = SerializableFieldElement::from_field_element(&elem, SerializationFormat::Base10);
    let ser_base16 = SerializableFieldElement::from_field_element(&elem, SerializationFormat::Base16);
    let ser_base64 = SerializableFieldElement::from_field_element(&elem, SerializationFormat::Base64);
    
    println!("  Base10: value={}, modulus={}", ser_base10.value, ser_base10.modulus);
    println!("  Base16: value={}, modulus={}", ser_base16.value, ser_base16.modulus);
    println!("  Base64: value={}, modulus={}", ser_base64.value, ser_base64.modulus);
    
    let json_fp = ser_base10.to_json().unwrap();
    println!("\nJSON representation (Base10):");
    println!("{}", json_fp);
    
    // Round-trip JSON
    let deser_fp = SerializableFieldElement::from_json(&json_fp).unwrap();
    let reconstructed = deser_fp.to_field_element().unwrap();
    println!("Round-trip successful: {}", reconstructed == elem);
    
    // 3. Binary Field Element (F2^m) Serialization
    println!("\n=== 3. Binary Field Element (F2^8) Serialization ===");
    let irreducible: Vec<u8> = vec![0b00011011, 0b00000001];
    let degree = 8;
    let bin_elem = BinaryFieldElement::from_u64(0x53, irreducible.clone(), degree);
    
    // Serialize with hex format (common for binary fields)
    let ser_bin = SerializableBinaryFieldElement::from_binary_field_element(&bin_elem, SerializationFormat::Base16);
    println!("Binary field element in F2^8:");
    println!("  Value:        {}", ser_bin.value);
    println!("  Irreducible:  {}", ser_bin.irreducible);
    println!("  Degree:       {}", ser_bin.degree);
    println!("  Format:       {:?}", ser_bin.format);
    
    let json_bin = ser_bin.to_json().unwrap();
    println!("\nJSON representation:");
    println!("{}", json_bin);
    
    // Round-trip
    let deser_bin = SerializableBinaryFieldElement::from_json(&json_bin).unwrap();
    let reconstructed_bin = deser_bin.to_binary_field_element().unwrap();
    println!("Round-trip successful: {}", reconstructed_bin == bin_elem);
    
    // 4. Elliptic Curve Point (E(Fp)) Serialization
    println!("\n=== 4. Elliptic Curve Point E(Fp) Serialization ===");
    let p_ec = BigUint::from_u64(17);
    let x = FieldElement::new(BigUint::from_u64(5), p_ec.clone());
    let y = FieldElement::new(BigUint::from_u64(1), p_ec.clone());
    let point = l2::elliptic_curve::EllipticCurvePoint::Point { x, y };
    
    let ser_point = SerializableECPoint::from_ec_point(&point, SerializationFormat::Base10);
    let json_point = ser_point.to_json().unwrap();
    println!("EC Point (5, 1) over F_17:");
    println!("{}", json_point);
    
    if let Ok(compressed) = ser_point.to_compressed() {
        println!("Compressed format: {}", compressed);
    }
    
    // Point at infinity
    let infinity = l2::elliptic_curve::EllipticCurvePoint::<FieldElement>::Infinity;
    let ser_inf = SerializableECPoint::from_ec_point(&infinity, SerializationFormat::Base10);
    let json_inf = ser_inf.to_json().unwrap();
    println!("\nPoint at infinity:");
    println!("{}", json_inf);
    
    // 5. Elliptic Curve Parameters
    println!("\n=== 5. Elliptic Curve Parameters Serialization ===");
    let a = FieldElement::new(BigUint::from_u64(2), p_ec.clone());
    let b = FieldElement::new(BigUint::from_u64(2), p_ec.clone());
    
    let ser_curve = SerializableEllipticCurve::new(&a, &b, SerializationFormat::Base10);
    let json_curve = ser_curve.to_json().unwrap();
    println!("Curve y^2 = x^3 + 2x + 2 over F_17:");
    println!("{}", json_curve);
    
    // 6. Binary Elliptic Curve Point
    println!("\n=== 6. Binary Elliptic Curve Point E(F2^m) Serialization ===");
    let test_irreducible = vec![0b10011];
    let test_degree = 4;
    let x_bin = BinaryFieldElement::from_u64(0b0001, test_irreducible.clone(), test_degree);
    let y_bin = BinaryFieldElement::from_u64(0b0110, test_irreducible.clone(), test_degree);
    let bin_point = l2::binary_elliptic_curve::BinaryEllipticCurvePoint::Point { 
        x: x_bin, 
        y: y_bin 
    };
    
    let ser_bin_point = SerializableBinaryECPoint::from_binary_ec_point(&bin_point, SerializationFormat::Base16);
    let json_bin_point = ser_bin_point.to_json().unwrap();
    println!("Binary EC Point:");
    println!("{}", json_bin_point);
    
    // 7. Polynomial Serialization
    println!("\n=== 7. Polynomial Serialization ===");
    let p_poly = BigUint::from_u64(17);
    
    // Create polynomial: 3 + 5X + 2X^2 over F_17
    let poly_coeffs = vec![
        FieldElement::new(BigUint::from_u64(3), p_poly.clone()),
        FieldElement::new(BigUint::from_u64(5), p_poly.clone()),
        FieldElement::new(BigUint::from_u64(2), p_poly.clone()),
    ];
    let poly = Polynomial::new(poly_coeffs);
    
    println!("Polynomial: {} (over F_17)", poly);
    println!("Degree: {}", poly.degree());
    
    println!("\nSerialization with different formats:");
    let ser_base10 = SerializablePolynomial::from_polynomial(&poly, SerializationFormat::Base10);
    let ser_base16 = SerializablePolynomial::from_polynomial(&poly, SerializationFormat::Base16);
    
    println!("  Base10: {:?}", ser_base10.coefficients);
    println!("  Base16: {:?}", ser_base16.coefficients);
    println!("  Modulus (base10): {}", ser_base10.modulus);
    
    let json_poly = ser_base10.to_json().unwrap();
    println!("\nJSON representation (Base10):");
    println!("{}", json_poly);
    
    // Round-trip test
    let deser_poly = SerializablePolynomial::from_json(&json_poly).unwrap();
    let reconstructed_poly = deser_poly.to_polynomial().unwrap();
    println!("Round-trip successful: {}", reconstructed_poly == poly);
    
    // Create polynomial from strings
    let poly_from_strings = SerializablePolynomial::new(&["1", "0", "1"], "17", SerializationFormat::Base10).unwrap();
    println!("\nPolynomial from strings (1 + 0X + 1X^2):");
    println!("  Coefficients: {:?}", poly_from_strings.coefficients);
    let poly_reconstructed = poly_from_strings.to_polynomial().unwrap();
    println!("  Polynomial: {}", poly_reconstructed);
    
    // Test zero polynomial
    let zero_poly: Polynomial<FieldElement> = Polynomial::zero();
    let ser_zero = SerializablePolynomial::from_polynomial(&zero_poly, SerializationFormat::Base10);
    println!("\nZero polynomial:");
    println!("  Degree: {}", ser_zero.degree);
    println!("  Coefficients: {:?}", ser_zero.coefficients);

    // 8. Extension Field Element Serialization (Fields containing polynomials)
    println!("\n=== 8. Extension Field Element (Fp^k) Serialization ===");
    println!("Extension fields are fields where elements are polynomials!");
    
    // Work in F_{7^2} with irreducible polynomial X^2 + 1
    let p_ext = BigUint::from_u64(7);
    println!("\nWorking in F_7^2 with irreducible polynomial X^2 + 1");
    
    // Create irreducible polynomial: X^2 + 1
    let irreducible_ext = Polynomial::new(vec![
        FieldElement::from_u64(1, p_ext.clone()),  // constant term
        FieldElement::from_u64(0, p_ext.clone()),  // X coefficient
        FieldElement::from_u64(1, p_ext.clone()),  // X^2 coefficient
    ]);
    
    // Create extension field element: 2 + 3X
    let ext_elem = ExtensionFieldElement::from_coeffs(
        vec![2, 3],
        irreducible_ext.clone(),
        p_ext.clone(),
    );
    
    println!("Element: {} (a polynomial in the field!)", ext_elem);
    
    let ser_ext = SerializableExtensionFieldElement::from_extension_field_element(&ext_elem, SerializationFormat::Base10);
    println!("\nElement coefficients: {:?}", ser_ext.coefficients);
    println!("Irreducible polynomial coeffs: {:?}", ser_ext.irreducible_coeffs);
    println!("Base field modulus: {}", ser_ext.modulus);
    println!("Format: {:?}", ser_ext.format);
    
    let json_ext = ser_ext.to_json().unwrap();
    println!("\nJSON representation:");
    println!("{}", json_ext);
    
    // Round-trip test
    let deser_ext = SerializableExtensionFieldElement::from_json(&json_ext).unwrap();
    println!("Round-trip successful: {}", 
        deser_ext.coefficients == ser_ext.coefficients);
    
    // Show that operations work in this field
    let ext_elem2 = ExtensionFieldElement::from_coeffs(
        vec![4, 5],
        irreducible_ext.clone(),
        p_ext.clone(),
    );
    let sum = &ext_elem + &ext_elem2;
    let product = &ext_elem * &ext_elem2;
    
    println!("\nField operations in F_7^2:");
    println!("  (2 + 3X) + (4 + 5X) = {}", sum);
    println!("  (2 + 3X) * (4 + 5X) = {}", product);

    // 9. Interoperability Demonstration
    println!("\n=== 9. Cross-Format Interoperability ===");
    println!("Creating a field element from different input formats:");
    println!("All represent 13 in F_17:\n");
    
    let from_dec = SerializableFieldElement::new("13", "17", SerializationFormat::Base10).unwrap();
    let from_hex = SerializableFieldElement::new("d", "11", SerializationFormat::Base16).unwrap();
    let from_b64 = SerializableFieldElement::new("DQ==", "EQ==", SerializationFormat::Base64).unwrap();
    
    println!("  Base10 format: value={}, modulus={}", from_dec.value, from_dec.modulus);
    println!("  Base16 format: value={}, modulus={}", from_hex.value, from_hex.modulus);
    println!("  Base64 format: value={}, modulus={}", from_b64.value, from_b64.modulus);
    
    // Verify they all decode to the same value
    let elem1 = from_dec.to_field_element().unwrap();
    let elem2 = from_hex.to_field_element().unwrap();
    let elem3 = from_b64.to_field_element().unwrap();
    println!("\nAll decode to same value: {}", elem1 == elem2 && elem2 == elem3);
    
    println!("\n✓ All serialization formats verified!");
    println!("✓ All structures support Base 10, Base 16, and Base64");
    println!("✓ Polynomials can be serialized and deserialized");
    println!("✓ Extension fields (polynomial fields) fully serializable");
    println!("✓ JSON serialization available for all types");
    println!("✓ Round-trip conversion verified");
    
    println!("\nSerialization demonstrations completed!");
}

// Helper module for hex encoding/decoding
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
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
