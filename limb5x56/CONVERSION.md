# limb5x56 — Conversion from limb5x54

Fork of limb5x54 with W=56 instead of W=54. Same K=5, same SLOT=40, same
128-bit accumulator arch — but **byte-aligned** decode and a cleaner
signed cP.

## Why 56 over 54

| | 5×54 | 5×56 |
|---|---|---|
| K·W | 270 | 280 |
| Decode stride | 54 bits (shrd trick) | **7 bytes exactly** |
| m0inv_p | 1 | 1 (p has 96 low 1-bits, W≤96 all get this) |
| m0inv_n | `0x11c8aaee00bc4f` (53-bit) | `0xd1c8aaee00bc4f` (56-bit) |
| Top limb bits | 256 − 4·54 = 40 | 256 − 4·56 = 32 |
| MASK | (1<<54)−1 | (1<<56)−1 |

## Signed cP — cleaner

p = 2^256 − 2^224 + 2^192 + 2^96 − 1 in 56-bit limbs:

| limb | bit range | terms landing here | value |
|---|---|---|---|
| 0 | [0,55]   | −1 | **−1** |
| 1 | [56,111] | +2^96 at offset 40 | **2^40** |
| 2 | [112,167] | — | 0 |
| 3 | [168,223] | +2^192 at offset 24 | **2^24** |
| 4 | [224,279] | −2^224@0, +2^256@32 | **2^32 − 1 = 0xFFFFFFFF** |

Builder (after zero-fill, rdi past slot):
```asm
dec  qword [rdi-40]       ; limb 0 = −1      4 B
inc  byte  [rdi-27]       ; limb 1 byte 5    3 B  (2^40)
inc  byte  [rdi-13]       ; limb 3 byte 3    3 B  (2^24)
dec  dword [rdi-8]        ; limb 4 low dword 3 B  (0→0xFFFFFFFF, no REX)
```
= 13 B patches vs limb5x54's ~14 B (limb 4 has two merged terms there).

## Decode — no shrd needed

fe_from_le loop body:
```asm
lodsq                ; 8 bytes → rax, rsi += 8
dec  rsi             ; net +7
and  rax, r13        ; MASK in r13
stosq
```
= 10 B body. limb5x54's shrd body is ~13 B with the cross-qword fetch.

Top limb (32 bits) tail: `xor eax,eax; lodsd; stosq` — lodsd advances rsi
by 4 to complete the +32 byte chain.

## Range proof

Run `make check` — KW=280 should converge with more headroom than 270.
Accumulator: 5 × (2^56)² ≈ 2^115 < 2^127. Fits signed-128.

## Constants to regenerate

- cR2_n = 2^(2·280) mod n = 2^560 mod n
- m0inv_n = 0xd1c8aaee00bc4f

The cN, cGX, cGY rodata bytes don't change (they're 32-byte integers,
limb-agnostic). Only the decode and the derived R²_n change.

## Files to touch

- `tv_ecdsa.S`: `.equ W,56`, MASK, m0inv_n constant, fe_from_le/be body,
  cP builder, any hardcoded 54 or MASK bit ops.
- `gen_bytecode.py`: K=5 stays; slot layout may be reusable as-is.
- `gen_vectors.py` / `vectors_mul.h`: regenerate for 56-bit fe_mul test.
- `fe_mul.S`: W=56, MASK.
