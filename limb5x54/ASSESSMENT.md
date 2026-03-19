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

## The Montgomery tax — REVISED (2026-03-18, commit d1a05bc)

**cR2_p ELIMINATED via projective scale-invariance.** See
`../limb11/NOTES.md`. RCB is homogeneous — preserves "all three
coords same scale." G at level 1 (Montgomery), Q at level 0 (plain),
b at level 1 all work. Level drifts data-dep but X,Y,Z always match.
Final check: X·1 aligns with r·Z at L−1.

| Item | B |
|---|---|
| cR2_n constant | 32 |
| ~~cR2_p constant~~ | ~~32~~ → **0** |
| bc_v1 ops: projective on-curve (+12) − Q-convert (−4) − n_mont (−2) | +6 |
| bc_v3 ops: X·1 + SET1 | +4 |
| G-scale (Z_G = Gx_mont) vs 1_mont_p | 0 (swap) |
| Two decoders | ~25 |
| **Total** | **~67** |

The trick applies EQUALLY to 5×54 — same Montgomery architecture.
**Thomas may have already found this.**

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

## VERDICT (2026-03-18, commit 6f07517)

**5×54 baseline: 1324 B, 607/607, ~3.2M cycles.** No golf.

| | Baseline | After grind | Cycles |
|---|---:|---:|---:|
| limb11 (11×24) | 1488 | 1194 (−294) | ~12.0M |
| **limb5 (5×54)** | **1324** | — | **~3.2M** |
| Thomas (5×54) | — | 928 | ~4.5M |

**5×54 is the horse.** The baseline is 164 B smaller than 11×24's
baseline AND ~4× faster (K²=25 vs 121 products per multiply). If
the limb11 grind catalogue ports at ~70% efficiency, limb5 lands
around 1120 B. With 5×54-specific wins (MASK-register flipping from
tax to win), likely lower. Thomas's 928 is ~200 B of grind away —
ambitious but the constraint shape supports it.

### Estimates corrected by the build

| Prediction | Actual | Note |
|---|---|---|
| MASK tax +5-10 B | **WASH (slight win)** | `and rax, r13` is 3 B vs imm32's 5 B. 10 B movabs recouped after 5 sites; ~10 exist. |
| Decoders +10-15 B | **+44 B** | 54-bit non-byte-aligned unroll is chunky. Real tax. |
| fe_mul +40 B | **+60 B** | 128-bit carry (shrd/sar/add/adc per row) + 128→54 final prop. |
| cP built | **stored** | 5×54 p limbs denser (only limb 2 zero). +32 B rodata, −25 B build. |

The decoders are the worst miss — PLAN.md's "(offset, shift) loop
would be nearly as bad" assumption was wrong; unrolled 5× with
hardcoded offsets is where the bytes went. Prime golf target.

### The build found (not predicted)

- **MASK register discipline**: r13 holds MASK (one movabs in verify).
  pt_mul's outer counter moved to r15. 5 pushes → FRAME +8 for
  16-alignment. This is the invariant to protect during golf.
- **54-bit decoder overread fix**: limb 4 at `(offset 27, shift 0)`
  would read 3 B past a 32-B input. `(offset 24, shift 24)` keeps
  the read in-bounds and shifts the extras out. No padding needed.
- **gen_bytecode.py ports verbatim** — slot-indexed, limb-width-agnostic.

## Next step

Port limb11's trick catalogue to limb5. Priority order (biggest
expected Δ, known-portable first):
1. enter/leave + .Lfail-in-middle (−28 B in limb11)
2. .Lcp_shared carry-prop dedup (−17 B)
3. CIOS merge in fe_mul (−7 B in limb11; may be more with 128-bit acc)
4. Decode chaining + rodata reorder (−48 B in limb11; different shape)
5. CHKZ/CHKNZ merge, rcl/inc ebp, mov al encoding wins (all portable)
6. COPYHI Shamir backup (portable)
7. **5×54-specific**: decoder loop vs unroll; disp8 slot layout.
