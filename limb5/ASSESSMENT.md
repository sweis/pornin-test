# 11×24 vs 5×54 — honest assessment (2026-03-18)

## The question

Can 11×24 reach < 928 B, or should we switch to 5×54?

## The structural fact

**Only W=32 has both p and n with all-ones top limb.** That's what
makes tiny.S's q=t[top] reduce work for both moduli without
Montgomery. Every signed-limb W needs Montgomery for mod-n:

| W | K | KW | p top limb | n top limb | q=t[top]? |
|---|---|---|---|---|---|
| 24 | 11 | 264 | 0x00ffff | 0x00ffff | no |
| 32 | 8 | 256 | 0xffffffff | 0xffffffff | **YES (both)** |
| 52 | 5 | 260 | 0x0ffffffff0000 | 0x0ffffffff0000 | no |
| 54 | 5 | 270 | 0x0000ffffffff00 | 0x0000ffffffff00 | no |

So **5×54 pays the same Montgomery tax as 11×24.** Thomas paid it too.

## The Montgomery tax (both architectures)

| Item | B |
|---|---|
| cR2_n constant | 32 |
| cR2_p constant | 32 |
| bc_v1 conversion ops (Qx,Qy,r,n,1→mont; s→mont-n) | ~16 |
| SET1/COPY for 1_mont_p | ~4 |
| Two decoders (LE for constants, BE for inputs) | ~25 |
| **Total** | **~109** |

This is **irreducible** as long as we're doing Montgomery. The only
escape is W=32 (tiny.S's choice), which doesn't converge for
signed-limb RCB (KW=256 < 263.2).

## Where 11×24 and 5×54 differ

| | 11×24 | 5×54 | Δ for 5×54 |
|---|---|---|---|
| SLOT | 88 B | 40 B | |
| disp8 slots from r14 | 0,1 | 0,1,2,3 | **−20 B** (~6 lea's) |
| MASK | fits imm32 (5 B `and`) | needs movabs/preload | **+5-10 B** |
| n m0inv | 0xBC4F (imul imm32) | 0x11c8aaee00bc4f (movabs) | **+5 B** |
| Product | 48 bits (fits 64) | 108 bits (128-bit acc) | **+40 B** (fe_mul) |
| Limb decode | 3-byte aligned | 6.75-byte, shift-per-limb | **+10-15 B** |
| p limbs sparsity | 4 all-ones, 4 zero | 1 all-ones, 1 zero | **+10 B** (cP build) |
| **Net** | | | **~+35 B for 5×54** |

**5×54's floor should be ~35 B HIGHER than 11×24's.** Yet Thomas is
at 928 and our 11×24 is at 1244. Either:

1. My floor estimates are ~150 B pessimistic for both (very possible
   — I was 400 B off on the Phase 1 baseline estimate).
2. Thomas found architectural wins I can't see from the outside.
3. The disp8 advantage cascades (more slots reachable → different
   register/slot flow → different fall-through opportunities).

## 11×24 current state (1244 B)

| Chunk | B | Notes |
|---|---|---|
| bytecode | 189 | 87 RCB + 21 v3 + 81 v1 |
| constants | 160 | 5 × 32 |
| handlers+Ljt | ~321 | |
| decoders | ~55 | |
| fe_mul11 (CIOS) | ~130 | |
| bc_run+pt_mul | ~175 | |
| verify | ~195 | |

**Estimated grind remaining: ~177 B** (based on tiny.S at 933 + 134
tax = 1067 floor). That lands us at ~1070, which is **139 B short**
of 928.

## What's been tried and ruled out (11×24)

- NORMN, MULR2, SQR — all dead code, dropped.
- r≠0, s≠0 checks — redundant with downstream, dropped.
- Fadd/Fsub via .Lasmod share — loses (dst==s2 Fsub can't commute).
- Fmul fall-through to fe_mul11 — u8 reach is binding.
- bt via slot9 reversal — fe_from_le overwrites the bytes.
- NORM before CHKNZ(Z) — Wycheproof tcId=292 says required.
- dword storage (SLOT=44) — movsxd overhead kills disp8 gain.

## What 5×54 might unlock

Unknown. Specifically:
- MASK in a register (survives handlers via invariant) might be
  **cheaper** than imm32: `and rax, r15` is 3 B vs `and eax, imm32`
  is 5 B. If MASK-register flows cleanly, the "+5-10 B MASK tax" flips
  to a **win**.
- 4-slot disp8 might enable a totally different verify decode flow.
- K=5 loops are small enough to UNROLL some places 11×24 can't.
- Thomas might be using mulx/adcx/adox (BMI2+ADX) — parallel carry
  chains for the 128-bit accumulator. fast2.S uses this; could be
  smaller than add;adc for 5-limb products.

## Recommendation

1. **Keep grinding 11×24** — ~177 B of honest work remaining. Each
   win teaches us about the problem even if 928 is out of reach.
   Realistic target: **1070-1100 B**.

2. **Build 5×54 baseline in parallel.** No golf — get 607/607 and
   measure. The first-pass number decides:
   - < 1350 B baseline → 5×54 is the horse.
   - > 1450 B baseline → 11×24's constraint shape is better.
   - Between → build both to ~1150 and compare.

3. **Accept that <928 may need a NEW idea.** Neither architecture
   obviously reaches it from where I'm standing. Thomas found
   something. The only way to find it is to build.

## Caveat

My size estimates have been 86-400 B wrong before. The assembler
tells the truth. This assessment is a HYPOTHESIS to test, not a
verdict.
