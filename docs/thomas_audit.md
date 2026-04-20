# Security audit: Thomas amd64 / amd64alt (2026-04-20)

Target: `github.com/pornin/small-ecdsa` `src/ecdsa-p256-verify_amd64.S`
(5×54, 875 B) and `_amd64alt.S` (12×22, 848 B).

**Result: no demonstrable vulnerability found.**

## What was tested

| Probe | Coverage | Result |
|---|---|---|
| Our 607-test suite (33 hand + 574 Wycheproof p1363) | both variants | 607/607 pass |
| Full Wycheproof ASN.1→p1363 (258 substantive after DER-only filter) | both variants | 258/258 pass, incl. tcId 480/481/482 |
| Differential amd64 vs amd64alt | 2161 vectors: 136 valid sigs (8 keys × 17 hashes incl. e ∈ {0,n−1,n,n+1,p−n±1,p−1,2²⁵⁶−1}), 25 boundary r/s/pubkey, 2000 random | identical output on all |
| Source audit | both files end-to-end | all 6 standard pitfalls handled |

## Why the standard pitfalls don't apply

| Pitfall | His handling |
|---|---|
| `r < p−n` guard for projective check | **Doesn't use the projective trick.** Computes affine x_W = Wx · Wz⁻¹ mod p (full Fermat inversion), canonicalizes to [0,p−1], then `(x_W − r)/R mod n == 0`. The mod-n MRED handles x_W ∈ [n,p−1] naturally. |
| Coord = p exactly | `_LD _Qx ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL` — integer subtract before any modular op; Qx==p → 0 → not-neg → FAIL. |
| hv truncation | `decode_int` reads exactly 32 bytes (4×lodsq amd64, 32×lodsb alt). |
| e > n | e never bit-scanned raw; u = e/s computed via Mont-mul then `canonicalize` before storing for SKIPBITZ. |
| W = ∞ | Wz=0 → Fermat inversion → 0 → x_W=0 → x_W−r ≠ 0 (r≠0 checked) → FAIL. |
| r,s ∈ [1,n−1] | `_SKIPNZ ; _FAIL ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL`. |
| len / 0x04 prefix | `subq/cmpq` chain at L1184-1198; hv_len ∉ [32,64] caught via unsigned wrap. |

## The one asymmetry investigated

amd64alt L622-624 inserts `_NORM` ("Needed to contain limb growth")
that amd64 lacks at the equivalent T5 step in `point_add_to_W`.
Hand-checked: longest unreduced chain produces limbs ≤ ~4·2ˢ. For
5×54 (s=54) that's 2⁵⁶ with ~2⁷ headroom to imulq overflow; for
12×22 (s=22, 32-bit limbs) it's ~2²⁴ and the 12-term accumulation in
add_mul_wide approaches 2⁶² — hence the NORM. The asymmetry is
justified by the math, not a gap.

His Python range analyzer (`python/rr_ecdsa_range.py`, 266 KB)
formally proves the 5×54 case; not independently verified here.

## Side finding — OUR code

Running the same Wycheproof ASN.1 set against our tracks:

| Track | tcId 481 | |
|---|---|---|
| limb8 | **FAIL** (accepts invalid) | uses projective `(X−Zr)(X−Z(r+n))` w/o `r<p−n` guard |
| limb5x54 | **FAIL** | same |
| limb5x56 | **FAIL** | same |
| limb11x24 | **FAIL** | same |
| stupid | pass | inherited Thomas's affine-x approach |

tcId 481: r = p−n+5, constructed so x_W = 5. Spec says invalid (5 ≠
p−n+5 mod n requires r < p−n for the +n branch). Our projective
check tests both r and r+n unconditionally; r+n here wraps past p so
the second factor matches x_W = 5.

Paper §3.5 claim "the AI's productions were never fully correct" is
**confirmed for 4 of 5 current tracks**. Vector is from Wycheproof
ASN.1 set (added Jan 2026), not in the p1363 set our 607-suite uses.

## Artifacts

`/tmp/thomas-build/` — amd64.o, amd64alt.o, difftest.c, gen_vectors.py
`/tmp/wp.json`, `/tmp/wp_convert.py`, `/tmp/wp_driver.c`, `/tmp/wp_vectors.bin`
