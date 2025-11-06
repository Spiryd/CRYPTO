use l1::{print_box, WangCollisionExample, WANG_COLLISION_0, WANG_COLLISION_1};

fn show_differences(name0: &str, arr0: &[u32; 16], name1: &str, arr1: &[u32; 16]) {
    println!("Comparing {} vs {}:", name0, name1);
    for i in 0..16 {
        if arr0[i] != arr1[i] {
            println!("  Word[{}]: 0x{:08x} vs 0x{:08x} (diff: 0x{:08x})", 
                     i, arr0[i], arr1[i], arr0[i] ^ arr1[i]);
        }
    }
}

fn verify_collision_example(name: &str, collision: &WangCollisionExample) {
    println!("\n{}", name);
    println!("{}", "═".repeat(65));
    
    show_differences("M0", &collision.m0, "M'0", &collision.m0_prime);
    println!();
    show_differences("M1", &collision.m1, "M'1", &collision.m1_prime);
    
    let iv0 = collision.intermediate_state_0();
    let iv0_prime = collision.intermediate_state_0_prime();
    let hash = collision.hash();
    
    println!("\nIntermediate states after M0:");
    println!("  IV0  = {:08x} {:08x} {:08x} {:08x}", iv0[0], iv0[1], iv0[2], iv0[3]);
    println!("  IV'0 = {:08x} {:08x} {:08x} {:08x}", iv0_prime[0], iv0_prime[1], iv0_prime[2], iv0_prime[3]);
    
    println!("\nFinal collision hash:");
    println!("  Hash = {:08x} {:08x} {:08x} {:08x}", hash[0], hash[1], hash[2], hash[3]);
    
    let is_collision = collision.verify();
    println!("\n{} Collision: {}", 
             if is_collision { "✓" } else { "✗" },
             if is_collision { "VERIFIED" } else { "FAILED" });
}

fn main() {
    print_box("Wang MD5 Collision Verification");
    
    verify_collision_example("WANG_COLLISION_0", &WANG_COLLISION_0);
    verify_collision_example("\nWANG_COLLISION_1", &WANG_COLLISION_1);
}
