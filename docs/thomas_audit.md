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

## Deep-dive on amd64 (round 2)

Five parallel probes + overflow instrumentation + 50K-vector reference
fuzz. Still no vulnerability, but the headroom is much tighter than the
first-pass estimate.

### Constants — verified correct

Extracted and recomputed Gx·R, Gy·R, n, n0i, p, p0i (R=2²⁷⁰). All
match. Runtime-derived Bm = (Gy²−Gx³+3Gx)·R via Mont-mul chain
matches b·R mod p. Script: `/tmp/verify_const.py`.

### decode_int — verified correct

Simulated the shldq/shrq 5-iteration split on 66 inputs incl. all
2⁵⁴-boundary values. All reconstruct exactly. The cl==10 stale-rax
case is harmless: only top-10 bits feed shldq, guaranteed zero from
prior `shrq $10`. Script: `/tmp/test_decode.py`.

### FOR/NEXT/SKIPBITZ iteration — verified correct

Simulated r8d sequence: 256 values visiting logical bits 255..0 each
exactly once. The `andb $0x3F` word-boundary adjust fires at exactly
{256,192,128,64}, jumping over the 10 padding bits per limb. FNEXT
correctly consumes bit 255 (acc pre-loaded as base; bit 255 of m−2 is
1 for both p and n). Script: `/tmp/test_forloop.py`.

### Megafuzz vs Python FIPS reference — 50000/50000 match

1000 fresh valid sigs + 49000 structured-invalid (edge r/s from
{0,1,n±1,p−n±1,p±1,2²⁵⁶−1,...}, bit-flips, wrong-key, wrong-hash,
random prefix). Jacobian-coord Python reference with full FIPS checks.
Zero divergence. Script: `/tmp/megafuzz.py`.

### Overflow trap instrumentation — never fires

Inserted `jo ud2` after every `addq` in add_mul_wide, op_add,
op_mul shift-down, normalize_limbs. Ran 607-suite + 2161 differential.
No trap.

### Range analysis re-derived — TIGHTEST margin is 0.42 bits

Independent re-derivation of limb bounds through `point_add_to_W`
(not running his Python prover):

| Value | Derivation | Limb bound | Shifted (×2⁵) | Margin to 2⁶³ |
|---|---|---:|---:|---:|
| T6 | 3·(b·t6ₘᵤₗ − T0 − 3T2) | (−12·2⁵⁴, 3·2⁵⁴) | 2⁶²·⁵⁹ | **0.42 bits** |
| T7 | T1 − 3(t6−t7) | (−3·2⁵⁴, 10·2⁵⁴) | 2⁶²·³² | 0.68 bits |
| T5 | T1 + 3(t6−t7) | (−9·2⁵⁴, 4·2⁵⁴) | 2⁶²·¹⁷ | 0.83 bits |
| d[4] (T5·T7 accum) | 4 full-mag highs | ~2⁶²·⁵⁴ | — | 0.46 bits |

The L815 `shlq $5,%rbx` on T6 is the binding constraint at 4/3×
headroom. **Provably never crossed** — bytecode is fixed and each
component is a strict-inequality bound from a normalized MUL output.

**Empirical:** instrumented to record max|rbx| at L815 across 136
valid sigs (~3.5M shifts). Observed max = 2⁵⁷·⁴⁹ = **93.6% of the
proven 12·2⁵⁴ bound**. The bound is sharp; the 4/3× margin is real.

**His Python prover (`python/rr_ecdsa_range.py`) — confirms hand-
derivation exactly.** `range_analysis(5, 54, 64, slf=True)` → OK.
Per-slot limb ranges extracted via `inspect_point_add_to_W` hook:

| Slot | His prover | Hand-derivation | |
|---|---|---|---|
| T6 | [−12, +3]·2⁵⁴ | (−12·2⁵⁴, 3·2⁵⁴) | exact |
| T7 | [−3, +10]·2⁵⁴ | (−3·2⁵⁴, 10·2⁵⁴) | exact |
| T5 | [−9, +4]·2⁵⁴ | (−9·2⁵⁴, 4·2⁵⁴) | exact |
| T0 | [−3, +3]·2⁵⁴ | ±3·2⁵⁴ | exact |
| T8 | [0, +3]·2⁵⁴ | [0, 3·2⁵⁴) | exact |

Also verified: `range_analysis(12, 22, 32, slf=True)` (amd64alt
**without** spec=4) FAILS at IP=198 `MUL 23` with limb range
[−2273312274, 1056964453] vs INT32 — confirming the L623 `_NORM` is
load-bearing for 12×22 and not needed for 5×54.

This explains the amd64alt asymmetry: at 12×22 the equivalent chain
hits ~12·2²² in 32-bit limbs, and the accumulator's 12-term sum in
add_mul_wide loses the limb-4-is-small credit, pushing past 2³¹ —
hence the extra `_NORM` at L623.

### Stale comments (cosmetic, not flaws)

- L1108 INTERPRETER_BEGIN comment "rsi points to mod_N (it follows
  the encoded Bm)" — there is no encoded Bm (it's runtime-computed);
  rsi actually points to bytecode_entry.
- curve_constants header lists Bm as a stored constant; it isn't.

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
