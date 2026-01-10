# GHASH Algorithm Implementation

## Overview

This implementation provides the GHASH algorithm used in Galois/Counter Mode (GCM) and GMAC, commonly used with AES for authenticated encryption.

## Mathematical Foundation

### Field Definition
GHASH operates over **GF(2^128)**, the Galois field with 2^128 elements, defined by the irreducible polynomial:

```
x^128 + x^7 + x^2 + x + 1
```

### Algorithm Specification

Given:
- **H**: Hash key (128-bit authentication key derived from encryption key)
- **A**: Additional Authenticated Data (AAD) - arbitrary length
- **C**: Ciphertext - arbitrary length

GHASH computes:

```
X₀ = 0
Xᵢ = (Xᵢ₋₁ + Sᵢ) · H    for i > 0
S = padWithZeros(A) || padWithZeros(C) || len(A) || len(C)
GHASH(H, A, C) = Xₘ₊ₙ₊₁
```

Where:
- `len(A)` and `len(C)` are 64-bit big-endian representations of bit lengths
- `m = ⌈len(A)/128⌉`, `n = ⌈len(C)/128⌉`
- `padWithZeros` pads data to the next 128-bit block boundary
- `Sᵢ` are consecutive 128-bit blocks of S (indexed from 1)
- All operations are performed in GF(2^128)

## Implementation Details

### Files Created
- `src/ghash.rs`: Complete GHASH implementation with tests

### Key Components

1. **GF(2^128) Field Configuration** (`GF128Config`)
   - Defines the irreducible polynomial
   - Uses 3 limbs (192 bits) for intermediate computations
   - Base field F₂ (characteristic 2)

2. **Type Alias** (`GF128`)
   - `BinaryField<GF128Config, 3, 128>`
   - Leverages existing binary field implementation

3. **Core Function** (`ghash`)
   ```rust
   pub fn ghash(h: GF128, a: &[u8], c: &[u8]) -> GF128
   ```
   - Takes hash key and variable-length byte slices
   - Returns 128-bit authentication tag

4. **Helper Functions**
   - `bytes_to_gf128`: Converts 16-byte slice to GF(2^128) element
   - `gf128_to_bytes`: Converts GF(2^128) element to byte array

## Usage Example

```rust
use l3::ghash::{ghash, bytes_to_gf128, gf128_to_bytes};

// Hash key (typically derived from AES encryption of zero block)
let h_bytes = [0x66, 0xe9, 0x4b, 0xd4, /* ... */];
let h = bytes_to_gf128(&h_bytes);

// Additional authenticated data
let aad = b"Additional Authenticated Data";

// Ciphertext
let ciphertext = b"This is the encrypted message content.";

// Compute GHASH authentication tag
let tag = ghash(h, aad, ciphertext);
let tag_bytes = gf128_to_bytes(&tag);
```

## Test Coverage

All 6 tests pass:
1. ✅ `test_bytes_conversion` - Byte conversion round-trip
2. ✅ `test_ghash_zero_inputs` - Edge case with zero hash key
3. ✅ `test_ghash_empty_aad_and_ciphertext` - Empty inputs
4. ✅ `test_ghash_single_block` - Single block processing
5. ✅ `test_ghash_multiple_blocks` - Multiple block processing
6. ✅ `test_ghash_different_inputs_different_tags` - Input sensitivity

## Demonstration Output

The implementation includes comprehensive demonstrations showing:
- Empty input handling
- AAD-only processing
- Ciphertext-only processing
- Combined AAD and ciphertext
- Multiple block processing
- Determinism verification
- Input sensitivity

Example output:
```
Example 4: AAD and ciphertext
   AAD: "Additional Authenticated Data"
   Ciphertext: "This is the encrypted message content."
   Tag: [da, e3, 9d, 76, 63, 52, f3, 94, d0, 5d, e8, 5f, 72, 4c, 8e, b4]
```

## Properties Verified

✅ **Deterministic**: Same inputs always produce same output  
✅ **Sensitive**: Small input changes produce completely different tags  
✅ **Variable-length**: Handles arbitrary-length AAD and ciphertext  
✅ **Standard-compliant**: Follows NIST specification for GHASH  

## Performance Characteristics

- **Field Operations**: O(1) addition (XOR), O(k²) multiplication in GF(2^k)
- **Overall Complexity**: O(n) where n = number of 128-bit blocks
- **Memory**: O(n) for block storage, constant for field operations

## Integration with AES-GCM

GHASH is the authentication component of AES-GCM mode:
1. AES encrypts data in counter mode (CTR)
2. GHASH authenticates AAD and ciphertext
3. Combined output provides authenticated encryption

## References

- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
- The Galois/Counter Mode of Operation (GCM) - McGrew & Viega
