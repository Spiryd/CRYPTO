# MD5 Collision Verification

## Overview

This implementation verifies MD5 collisions from Wang et al.'s 2005 paper "How to Break MD5 and Other Hash Functions". We successfully demonstrate two complete collision pairs where different messages produce identical MD5 hashes.

## The Collision Structure

Wang's attack produces collisions of the form:

```
MD5(MD5(IV, M0), M1) == MD5(MD5(IV, M'0), M'1) = H
```

Where:
- `IV` = Standard MD5 initial values
- `M0, M'0` = First message block pair (512 bits each)
- `M1, M'1` = Second message block pair (512 bits each)
- `H` = Final identical hash (128 bits)

## Key Implementation Details

### 1. Raw Block Processing

The critical insight: collision data represents MD5's **internal message words**, not byte-level data with padding.

Standard MD5 processing adds padding, which creates extra blocks that destroy the collision. We implemented `process_raw_block()` to process single 512-bit blocks directly:

```rust
pub fn process_raw_block(iv: InitialValues, block_words: &[u32; 16]) -> InitialValues
```

This function:
- Takes IV and 16 u32 words (512 bits)
- Executes MD5 rounds directly
- Returns new state (no padding, no extra blocks)

### 2. No Endianness Conversion

The u32 values in collision data are MD5's internal representation. They require **no byte order conversion** - they're used directly as the 16-word message block that MD5 processes internally.

### 3. Two-Block Collision

Each collision uses two 512-bit blocks:

```
Step 1: IV0  = process_raw_block(IV, M0)
        IV'0 = process_raw_block(IV, M'0)
        
Step 2: H    = process_raw_block(IV0, M1)
        H'   = process_raw_block(IV'0, M'1)
        
Result: H == H' (collision!)
```

## Verified Collisions

### Collision 0
- **H** = `9603161f a30f9dbf 9f65ffbc f41fc7ef`
- **H'** = `9603161f a30f9dbf 9f65ffbc f41fc7ef` ✓

Message differences (bit flips):
- M0 words 4, 11, 14
- M1 words 4, 11, 14

### Collision 1
- **H** = `8d5e7019 61804e08 715d6b58 6324c015`
- **H'** = `8d5e7019 61804e08 715d6b58 6324c015` ✓

Same differential pattern, different M1 values.

## Differential Characteristics

Both collisions use controlled bit differences:
- Word[4]: XOR with `0x80000000` (MSB flip)
- Word[11]: XOR with `0x00008000` (bit 15 flip)
- Word[14]: XOR with `0x80000000` (MSB flip)

These specific differences propagate through MD5 rounds in a way that cancels out, producing identical final states.

## Running the Verification

```bash
cargo run --example verify_wang_collision
```

Output shows:
1. Message differences between M0/M'0 and M1/M'1
2. Intermediate states IV0/IV'0 (different)
3. Final hashes H/H' (identical)
4. Collision confirmation

## References

- Xiaoyun Wang and Hongbo Yu. "How to Break MD5 and Other Hash Functions", EUROCRYPT 2005
- RFC 1321: The MD5 Message-Digest Algorithm