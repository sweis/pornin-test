# limb11 notes — architectural insights

## R² elimination via projective scale-invariance (2026-03-18)

**The hint (from user, 2026-03-18):** "In projective-coordinate ECDSA
verification, R² conversion isn't needed — the missing factor cancels
through inversions."

**The key insight:** RCB is a homogeneous polynomial in (X1,Y1,Z1,
X2,Y2,Z2,b). It preserves "output triple at same scale" regardless
of what that scale is. Projective (X:Y:Z) is scale-invariant. So
R-factors are just scales, and as long as each input TRIPLE is
internally consistent (all three coords same R-level), the output
is projectively correct.

**Level tracking** (R-exponent; Fmul(a@i, b@j) = level i+j−1, Fadd
needs i==j):

- G stored Montgomery: (Gx·R, Gy·R, R) — all level 1. Consistent.
- Q stays PLAIN: (Qx, Qy, 1) — all level 0. Consistent.
- b derived from G@1: level 1.
- RCB(G@1, Q@0): cross-products → level 0. b·t2 = 1+0−1 = 0. ✓
  Output at level 0, all three coords.
- Doubles (RCB(acc, acc)): input L → output 4L−3. Level drifts
  data-dependently (G-add and Q-add give DIFFERENT output levels).
  Doesn't matter — X,Y,Z always match each other.

**Final check:** X ≡ r·Z with r plain (level 0), X,Z at unknown L.
  r·Z = Fmul(r@0, Z@L) = L−1. X is at L. Mismatch.
  **Fix:** X·1 = Fmul(X@L, 1@0) = L−1. Now both L−1. One extra Fmul.
  (r+n)·Z: r@0, n@slot9@0, Fadd gives level 0. ·Z = L−1. ✓

**On-curve** (the hard part): y²=x³−3x+b with plain Q.
  Qy²: −1. Qx³: −2. 3Qx: 0. b: 1. Four different levels.
  **Projective form:** Y²Z = X³ − 3XZ² + bZ³ with Z=1 (plain, level 0):
    Y²·Z  = (−1)+0−1 = −2.
    X³    = −2.
    Z²    = Fmul(1,1) = −1.  3X·Z² = 0+(−1)−1 = −2.
    Z³    = Fmul(Z²,Z) = −2.  b·Z³ = 1+(−2)−1 = −2.
  All at −2. ✓ The Z-multiplications are degree-balancers.

**Savings:**
| | Δ |
|---|---|
| cR2_p constant dropped | −32 B data |
| cR2_p decode call | −5 B verify |
| Qx,Qy MULR2 (2 ops) | −4 B bc |
| n_mont (bc_v3 reads n@slot9 direct) | −2 B bc |
| 1_mont_p MULR2 (plain 1 now) | −2 B bc |
| on-curve projective (+6 ops) | +12 B bc |
| bc_v3 SET1 + X·1 (+2 ops) | +4 B bc |
| **Net** | **~−29 B** |

**cR2_n stays:** u1,u2 must be plain integers for pt_mul's bit-read.
Mod-n levels don't cancel through INV — the level after 255 squares +
~128 mults is some huge negative number depending on n−2's bit pattern.
Only seeding with s_mont (level 1) keeps it stable (2·1−1 = 1 per
square, 1+1−1 = 1 per mult).

**Applies equally to 5×54** — same Montgomery architecture.

---

## Why 11×24 (vs 5×54) — original session notes

(Superseded by PLAN.md. Keeping for archaeology.)

- `range_proof.py`: proves 11×24 converges (KW=264 > 263.2).
- 5×54 needs 128-bit accumulator (add+adc). 11×24 fits 64-bit.
- MASK = 0xFFFFFF fits imm32. 5×54's MASK needs movabs.
- 24 bits = 3 bytes exact — byte-aligned decode. 54 bits = 6.75 bytes.
