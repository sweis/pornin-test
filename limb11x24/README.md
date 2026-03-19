# limb11x24/ — 11×24 signed-limb Montgomery track

**1068 B / ~12.1M cyc** (607/607). `-DFAST`: 1077 B / ~4.1M cyc.
Thomas at 928 B / 4.48M with 5×54.

**Secondary track.** 5×54's baseline landed 164 B smaller AND ~4×
faster (K²=25 vs 121 products per fe_mul). This track is the trick
catalogue — wins discovered here port to limb5x54/5x56, and vice versa.

## Why 11×24

- Products fit 60 bits — pure 64-bit `imul`, no 128-bit carry chain.
- 24 bits = 3 bytes exactly — byte-aligned decode.
- MASK = 0xFFFFFF fits imm32 (`and eax, imm32` is 5 B, no preload).
- n's m0inv = 0xBC4F fits imm32 `imul`.

Cost: 88-byte slots. Only slots 0,1 reach disp8 from r14. Every other
native slot touch is `lea disp32` (7 B). 5×54's 40-byte slots get 4.

## Biggest tricks (1488→1068)

- **R² projective cancellation** (−25, d1a05bc): RCB is homogeneous
  — if each input triple (X,Y,Z) shares an R-level, the output triple
  does too. G stored at level 1 (Montgomery), Q left at level 0 (plain),
  b derived at level 1. Final check needs one `X·1` Fmul to align with
  r·Z at level L−1. cR2_p constant dropped. Applies to all Montgomery
  tracks.
- **Decode chaining** (−48, 376d2e3): rodata ordered so rdi walks
  through constant decodes with zero `lea`s between.
- **enter/leave + .Lfail-in-middle** (−28, d247ad6): five rel32
  length-check jumps became rel8.
- **.Lcp_shared** (−17, 1ab794a): fe_mul11's carry-prop body is
  byte-identical to NORM's. One subroutine, two callers.
- **NORMN drop** (−14, d234a3d): Montgomery of nonneg is nonneg;
  pt_mul handles k≥n for free since n·G=∞.
- **cqo+not single-loop NORM** (−3, 135a928): merged two loops; the
  tail's `or edx,eax` uses 32-bit form because K=11 smears the top
  limb down to ≤2^18 bits.

## What didn't port here

- **limb5's rbp-relative bt** — needs both u-slots in disp8; 88-byte
  stride only gets one.
- **Byte-aligned 7-byte decode** (limb5x56) — 3-byte decode is
  already byte-aligned; no further win.
- **.Lcp_shared 128-bit variant** — no 128-bit carry here.

## Tried and failed

- NORM-before-CHKNZ(Z) drop: Wycheproof tcId=292. RCB's Z is an Fadd
  output — can land on kp.
- bt via in-slot reversal: fe_from_le's stosq overwrites the reversed
  bytes before INV can read them.
- dword storage (SLOT=44): movsxd overhead ate the disp8 gain.

```
make test size bench20    # 607/607, bytes, 20-run median
make regen                # regenerate bytecode.inc
```
