# tv_ecdsa_limb11.S — build plan

## State

- `range_limbs.py`: proves 11×24 converges (KW=264 > 263.2 required).
  60-bit acc, 29-bit limb inputs at mul entry, output val ≤ 2^258.
- `limb11_mul.S`: fe_mul11 at 158 B, 103/103 correct (incl. signed limbs).
- Thomas at 928 B with 5×54. We're targeting < 928 with 11×24.

## Architecture

**Slots**: 88 B each (11 qwords). ~24 slots.

**Constants** (all 32 B packed BE, decoded to limbs at runtime):
- `cGX` = Gx·R mod p  (Montgomery form, precomputed)
- `cGY` = Gy·R mod p
- `cN`  = n (plain)
- `cR2` = R² mod p    (for Qx, Qy, r → Montgomery)
- p: BUILT at runtime. [FF×4, 0×4, 1, FF00, FFFF] — 4+4 trivial.

**n's m0inv = 0xBC4F** (24-bit). p's = 1.
**n and p share limbs 9-10** (0xffff00, 0xffff) — top 32 bits identical.

## Phases

1. **Skeleton** — bytecode framework, slot layout, verify entry.
   Stubs for handlers. WON'T PASS TESTS yet. Measure size.

2. **Decoder** (fe_from_be): 32 BE bytes → 11 limbs.
   24-bit = 3-byte aligned. Loop: `mov eax,[rsi-1]; bswap; shr 8; stosq`.
   Tail for top limb (2 bytes, avoids read-before-buffer).
   Est: ~31 B (+16 over current).

3. **Fadd/Fsub**: limbwise, no carry, no reduce. Est: ~32 B (−27).

4. **fe_mul11**: drop in the 158 B version. Adapt to tiny.S's
   register conventions (r14=slot base, r8=&cP). May need +few B.

5. **mod-n**: Nmul preloads m0inv=0xBC4F in a register that fe_mul11
   imul's against. Fmul preloads 1. Est: +14 B total.

6. **Normalize** (bring to [0, m)): carry-prop + while-neg-add-m +
   while-ge-sub-m. Needed for u1, u2 (before pt_mul reads bits) and
   for the final zero-check. Est: ~35 B.

7. **pt_mul**: nested loop (11 limbs × 24 bits = 264 iters) instead
   of flat 256. Scalars stay in limb form — no packer needed.
   Est: ~80 B (+6).

8. **bc_run**: slot decode via `imul r,r,88` (3 B, fits imm8). Same
   total as current per-slot, +2 B for the high-nibble variants.

9. **fe_inv**: unchanged structure (256 Nmul calls + bt on cN).
   cN stays packed for bt. Decoded copy in a slot for Nmul's modulus.

10. **Wire up**: bc_v1, bc_v3, bc_rcb adapted. Montgomery conversion
    ops (MontMul with cR2) for Qx, Qy, r.

11. **TEST**: 607/607 must pass. Checkpoint size.

12. **GRIND**: re-apply the CLAUDE.md trick catalog. Different slack:
    - Handler block: Fadd/Fsub are tiny now → fe_inv might fit
      closer to .Ljt → u8 table has more headroom.
    - rel8 reach: fe_mul11 is +15 B but at a different offset.
    - rcx=0 flow: different sources/sinks.
    - Slot shuffles: ×88 means fewer slots in disp8 but maybe
      different native-code touch points.

## Tricks deferred to grind phase

- rcx=0-on-entry for fe_mul11 (−1 B; needs m via r8)
- Carry-prop share between fe_mul11 and normalize
- Decoder tail fused with something
- cP/cN limb tails shared (both end in [..., 0xffff00, 0xffff])
- Fall-throughs: new ones possible with the new block layout

## Risk

First-pass estimate: ~1050 B. Need 1.13× shrink to hit 928.
tiny.S went 2873→933 = 3.1×. The 1.13× is achievable IF the
architecture doesn't have a fatal overhead I'm not seeing.

Biggest unknown: the normalize routine. If it can share with
fe_mul11's carry-prop (both do `& MASK; sar W; add next`), could
drop from +35 to +10. If it can't, it's the single biggest new cost.
