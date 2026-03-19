# 5×54 track — plan

**Target:** < 928 B (Thomas's number, same architecture).
**Reference:** `../limb11/` at 1244 B with 11×24 Montgomery.
**Key question:** Does 5×54 beat 11×24's structural floor?

---

## Why 5×54 MIGHT beat 11×24

| | 11×24 | 5×54 |
|---|---|---|
| SLOT | 88 B | **40 B** |
| Slots in disp8 | 0,1 | **0,1,2,3** |
| p m0inv | 1 | 1 (same — p's low W bits all-ones for any W≤96) |
| n m0inv | 0xBC4F (fits imm32 imul) | 0x11c8aaee00bc4f (needs movabs) |
| MASK | 0xFFFFFF (fits imm32) | 0x3FFFFFFFFFFFFF (**needs movabs**) |
| Product bits | 48 (fits 64) | **108 (needs 128-bit acc)** |
| Inner loop | `imul; add [rdi],rax` | `imul; add;adc` or `mulx;adcx;adox` |
| Convergence (KW) | 264 (> 263.2, tight) | 270 (comfortable) |

**The disp8 win is REAL but the MASK/m0inv/128-bit costs offset it.**
Thomas found something. We don't know what.

## Structural tax (SAME as 11×24)

Both pay Montgomery-n: neither's top limb is all-ones.
- cR2_n: 32 B
- cR2_p: 32 B
- Conversion bc ops: ~16 B
- Two decoders: ~25 B

The disp32 tax is SMALLER (4 slots in disp8 vs 2).

## Constants (W=54, K=5, R=2^270)

```
p m0inv = 1
n m0inv = 0x11c8aaee00bc4f

p limbs: [0x3fffffffffffff, 0x3ffffffffff, 0, 0x40000000, 0xffffffff00]
n limbs: [0x39cac2fc632551, 0x2ab69c5e7a13ce, 0x3ffffffffbce6f, 0x3fffffff, 0xffffffff00]
  ↑ p[4] == n[4] — share top limb (same as 11×24's limb9,10 share)

R²_p = 0x4fffffffdfffffffffffffffefffffffbffffffff00000000000000030000000
R²_n = 0x55aba83afc16484a92b6bec59619076a9ea8ca2ae130785e017644694887ac57
Gx_mont = 0x17ddaf71d571985adccaddd889441d6ea57f11d76d805e79cc35062a450f0624
Gy_mont = 0x7fc62abe1761535e21a237487cc962d2a3e90d2a7917377c94d5f3a55582a15c
```

p limb structure — buildable but chunky:
- limb 0: all-ones (MASK)
- limb 1: 0x3ffffffffff — low 42 bits set
- limb 2: zero
- limb 3: 0x40000000 — one bit
- limb 4: 0xffffffff00 — middle 32 bits set

## Phase 1: baseline (no golf)

Same as limb11's Phase 1: get 607/607 FIRST, measure, then grind.

| Step | Piece | Blocks |
|---|---|---|
| 1.1 | fe_mul5 — adapt `../limb11/fe_mul_5x54.S` (230 B first draft) | — |
| 1.2 | MASK register discipline — movabs once, preserve through loops | — |
| 1.3 | Decoders — 54-bit limbs = 6.75 bytes. NOT byte-aligned. Needs shift-and-mask per limb. | — |
| 1.4 | 128-bit accumulator — add;adc or mulx;adcx;adox (BMI2+ADX) | 1.1 |
| 1.5 | Rest mirrors limb11: bc_run, handlers, NORM, INV, pt_mul | 1.1-1.4 |
| 1.6 | 607/607 | all |

### Decoder subtlety

54 bits = 6.75 bytes. NOT byte-aligned (unlike 24 = 3 bytes exactly).
Limb i starts at bit 54i = byte ⌊54i/8⌋, bit (54i mod 8).
So: load 8 bytes, shift right by (54i mod 8), mask.

```
limb 0: byte 0, shift 0
limb 1: byte 6, shift 6
limb 2: byte 13, shift 4
limb 3: byte 20, shift 2
limb 4: byte 27, shift 0
```

Decoder: `mov rax, [rsi+offset]; shr rax, shift; and rax, MASK; stosq`.
NOT a clean loop (different offsets and shifts). Unroll 5×? ~40 B.
Or: keep a running shift counter. Loop body ~20 B × 5 iterations worth of data.

This is HARDER than 11×24's byte-aligned 3-byte-per-limb.

## Phase 2: grind

Re-apply the limb11 trick catalog against the new shape:
- `../limb11/PLAN.md` §2 has the full list.
- disp8 wins should be BIGGER (4 slots vs 2).
- MASK preload flows through handlers — new rcx=0-style invariant to map.
- `.Lcp_shared`, `.Lasmod` xor-neg, COPYHI, etc. all port directly.

Things that might be DIFFERENT:
- `and rax, MASK` is now `and rax, r??` (3 B) if preloaded, vs `and eax, imm32` (5 B) for 11×24. If MASK is in a register that survives everything, this is a WIN, not a cost.
- Inner loop is bigger (add;adc) but K=5 means fewer iterations.

## Files

- `../limb11/fe_mul_5x54.S` — existing 230 B draft. Start here.
- `../limb11/range_proof.py` — already supports arbitrary (K,W). Verify 5×54 converges.
- `../limb11/gen_bytecode.py` — port; slot nibble range is the same (0-15).

## Don't touch

- `../limb11/` — parallel track, stays frozen at 1244 B.
- `../tv_ecdsa_tiny.S` — tiny.S reference, 933 B.

## Commit hygiene

Same as limb11. 607/607 before size claims. Push OK (repo private).
