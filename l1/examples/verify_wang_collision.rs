use l1::{InitialValues, process_raw_block};

/// Real MD5 collision data from Wang et al. "How to Break MD5 and Other Hash Functions"
/// These u32 values represent MD5's internal 16-word message blocks (512 bits each)
struct Md5CollisionExample {
    m0: [u32; 16],
    m1: [u32; 16],
    m0_prime: [u32; 16],
    m1_prime: [u32; 16],
}

const COLLISION_0: Md5CollisionExample = Md5CollisionExample {
    m0: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x87b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a417125, 0xe8255108, 0x9fc9cdf7,
        0xf2bd1dd9, 0x5b3c3780,
    ],
    m1: [
        0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 0xc79a7335, 0xcfdebf0, 0x66f12930,
        0x8fb109d1, 0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 0xddcb74ed, 0x6dd3c55f,
        0xd80a9bb1, 0xe3a7cc35,
    ],
    m0_prime: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x7b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a41f125, 0xe8255108, 0x9fc9cdf7,
        0x72bd1dd9, 0x5b3c3780,
    ],
    m1_prime: [
        0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 0x479a7335, 0xcfdebf0, 0x66f12930,
        0x8fb109d1, 0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c154c79, 0xddcb74ed, 0x6dd3c55f,
        0x580a9bb1, 0xe3a7cc35,
    ],
};

const COLLISION_1: Md5CollisionExample = Md5CollisionExample {
    m0: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x87b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a417125, 0xe8255108, 0x9fc9cdf7,
        0xf2bd1dd9, 0x5b3c3780,
    ],
    m1: [
        0x313e82d8, 0x5b8f3456, 0xd4ac6dae, 0xc619c936, 0xb4e253dd, 0xfd03da87, 0x6633902,
        0xa0cd48d2, 0x42339fe9, 0xe87e570f, 0x70b654ce, 0x1e0da880, 0xbc2198c6, 0x9383a8b6,
        0x2b65f996, 0x702af76f,
    ],
    m0_prime: [
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98, 0x7b5ca2f, 0xab7e4612, 0x3e580440,
        0x897ffbb8, 0x634ad55, 0x2b3f409, 0x8388e483, 0x5a41f125, 0xe8255108, 0x9fc9cdf7,
        0x72bd1dd9, 0x5b3c3780,
    ],
    m1_prime: [
        0x313e82d8, 0x5b8f3456, 0xd4ac6dae, 0xc619c936, 0x34e253dd, 0xfd03da87, 0x6633902,
        0xa0cd48d2, 0x42339fe9, 0xe87e570f, 0x70b654ce, 0x1e0d2880, 0xbc2198c6, 0x9383a8b6,
        0xab65f996, 0x702af76f,
    ],
};

/// Display differences between two u32 arrays
fn show_differences(name0: &str, arr0: &[u32; 16], name1: &str, arr1: &[u32; 16]) {
    println!("Comparing {} vs {}:", name0, name1);
    for i in 0..16 {
        if arr0[i] != arr1[i] {
            println!("  Word[{}]: 0x{:08x} vs 0x{:08x} (diff: 0x{:08x})", 
                     i, arr0[i], arr1[i], arr0[i] ^ arr1[i]);
        }
    }
}

fn verify_collision_example(name: &str, collision: &Md5CollisionExample) {
    println!("\n{}", name);
    show_differences("M0", &collision.m0, "M'0", &collision.m0_prime);
    println!();
    show_differences("M1", &collision.m1, "M'1", &collision.m1_prime);
    
    let iv = InitialValues::STANDARD;
    let iv0 = process_raw_block(iv, &collision.m0);
    let iv0_prime = process_raw_block(iv, &collision.m0_prime);
    let h = process_raw_block(iv0, &collision.m1);
    let h_prime = process_raw_block(iv0_prime, &collision.m1_prime);
    
    println!("\nIV0  = {:08x} {:08x} {:08x} {:08x}", iv0.a, iv0.b, iv0.c, iv0.d);
    println!("IV'0 = {:08x} {:08x} {:08x} {:08x}", iv0_prime.a, iv0_prime.b, iv0_prime.c, iv0_prime.d);
    println!("\nH    = {:08x} {:08x} {:08x} {:08x}", h.a, h.b, h.c, h.d);
    println!("H'   = {:08x} {:08x} {:08x} {:08x}", h_prime.a, h_prime.b, h_prime.c, h_prime.d);
    
    let is_collision = h.a == h_prime.a && h.b == h_prime.b && h.c == h_prime.c && h.d == h_prime.d;
    println!("\nCollision: {}", if is_collision { "✓ YES" } else { "✗ NO" });
}

fn main() {
    println!("Wang MD5 Collision Verification\n");
    verify_collision_example("COLLISION_0", &COLLISION_0);
    verify_collision_example("\nCOLLISION_1", &COLLISION_1);
}
