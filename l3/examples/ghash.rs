//! Example: GHASH Algorithm for GCM/GMAC
//!
//! Demonstrates the GHASH authentication function over GF(2^128)

use l3::ghash::{bytes_to_gf128, gf128_to_bytes, ghash};

fn main() {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║              GHASH Algorithm (GCM/GMAC) Demo                  ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    println!("🔐 GHASH operates over GF(2^128) with irreducible polynomial:");
    println!("   x^128 + x^7 + x^2 + x + 1\n");

    // Example hash key (in practice, derived from AES encryption of zero block)
    let h_bytes = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];
    let h = bytes_to_gf128(&h_bytes);

    println!("📌 Hash Key H:");
    println!("   {:02x?}\n", h_bytes);

    // Example 1: Empty AAD and ciphertext
    println!("Example 1: Empty inputs");
    let tag1 = ghash(h.clone(), b"", b"");
    println!("   AAD: (empty)");
    println!("   Ciphertext: (empty)");
    println!("   Tag: {:02x?}\n", gf128_to_bytes(&tag1));

    // Example 2: AAD only
    println!("Example 2: AAD only");
    let aad = b"metadata";
    let tag2 = ghash(h.clone(), aad, b"");
    println!("   AAD: {:?}", std::str::from_utf8(aad).unwrap());
    println!("   Ciphertext: (empty)");
    println!("   Tag: {:02x?}\n", gf128_to_bytes(&tag2));

    // Example 3: Ciphertext only
    println!("Example 3: Ciphertext only");
    let ct = b"encrypted";
    let tag3 = ghash(h.clone(), b"", ct);
    println!("   AAD: (empty)");
    println!("   Ciphertext: {:?}", std::str::from_utf8(ct).unwrap());
    println!("   Tag: {:02x?}\n", gf128_to_bytes(&tag3));

    // Example 4: Both AAD and ciphertext
    println!("Example 4: AAD and ciphertext");
    let aad = b"Additional Authenticated Data";
    let ct = b"This is the encrypted message content.";
    let tag4 = ghash(h.clone(), aad, ct);
    println!("   AAD: {:?}", std::str::from_utf8(aad).unwrap());
    println!("   Ciphertext: {:?}", std::str::from_utf8(ct).unwrap());
    println!("   Tag: {:02x?}\n", gf128_to_bytes(&tag4));

    // Example 5: Multiple blocks
    println!("Example 5: Multiple blocks (longer inputs)");
    let aad = b"This is a longer AAD that spans multiple 128-bit blocks for testing";
    let ct = b"And this is a longer ciphertext message that also requires multiple blocks";
    let tag5 = ghash(h.clone(), aad, ct);
    println!(
        "   AAD length: {} bytes ({} blocks)",
        aad.len(),
        aad.len().div_ceil(16)
    );
    println!(
        "   Ciphertext length: {} bytes ({} blocks)",
        ct.len(),
        ct.len().div_ceil(16)
    );
    println!("   Tag: {:02x?}\n", gf128_to_bytes(&tag5));

    // Demonstrate determinism
    println!("Example 6: Determinism verification");
    let tag6a = ghash(h.clone(), aad, ct);
    let tag6b = ghash(h.clone(), aad, ct);
    println!("   Same inputs produce identical tags:");
    println!("   Tag A: {:02x?}", gf128_to_bytes(&tag6a));
    println!("   Tag B: {:02x?}", gf128_to_bytes(&tag6b));
    println!(
        "   Match: {}\n",
        gf128_to_bytes(&tag6a) == gf128_to_bytes(&tag6b)
    );

    // Demonstrate sensitivity
    println!("Example 7: Input sensitivity");
    let tag7a = ghash(h.clone(), b"AAD1", b"CT1");
    let tag7b = ghash(h.clone(), b"AAD2", b"CT1");
    println!("   Changing AAD slightly produces different tag:");
    println!("   AAD 'AAD1': {:02x?}", gf128_to_bytes(&tag7a));
    println!("   AAD 'AAD2': {:02x?}", gf128_to_bytes(&tag7b));
    println!(
        "   Different: {}\n",
        gf128_to_bytes(&tag7a) != gf128_to_bytes(&tag7b)
    );

    println!("✅ GHASH algorithm successfully demonstrated!");
    println!("   - Operates in GF(2^128)");
    println!("   - Processes variable-length AAD and ciphertext");
    println!("   - Produces 128-bit authentication tags");
    println!("   - Used in AES-GCM for authenticated encryption\n");
}
