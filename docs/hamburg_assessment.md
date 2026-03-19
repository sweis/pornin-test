# Hamburg Signed-Binary Ladder — Refuted

**+277 B measured (prototype 1168 B), structural floor ~+110 B.** The
survey's −30 to +20 B band missed three asm cost centers.

Prototype (not in tree — throwaway branch) validated by Python model
against all 5 Wycheproof edges including tcId 204 (P=Q, expected VALID).

**Correctness (the survey's open question):** u ∈ [1,n−1] IS sufficient
for the Hamburg invariant — u=1 works (s_odd=1, every s_i=1, 2·s_i=2
satisfies 1<2<n−1). Only u1=0 needs special-casing. tcId 204 mandates
the full 3-way combine (Z=0∧X=0→double; Z=0∧X≠0→reject; Z≠0→done).

---

## Where the bytes went (measured vs limb8 891 B)

| Component | limb8 | hamburg | Δ | |
|---|--:|--:|--:|---|
| bytecode | 161 | 178 | +17 | bc_dbl(43)+bc_add(37)+setup(13)+norm(17) vs bc_rcb(87) |
| pt_mul / scalar_mult | 74 | 141 | **+67** | conditional init — see below |
| bcrun + jt | 84 | 85 | +1 | +1 handler (INVP) |
| Fadd..fe_inv_m | 99 | 114 | +15 | mod-p inversion parameterization |
| verify | 158 | 335 | **+177** | two-call tail — see below |
| **Total** | **891** | **1168** | **+277** | |

---

## The three structural costs

**1. Hamburg conditional init (~50 B, floor ~+20 B vs pt_mul).** Test
scalar bit 0; odd-path copies u→slot3 + selects Py_pos; even-path does
4× `not qword ptr [r14+96+k]` (20 B). **Bytecode can't branch** — this
is irreducibly native. RCB's init is 12 B flat (zero 3 slots, poke 1)
because completeness handles ∞+Q=Q in-formula.

**2. Two-call verify tail (floor ~+117 B).** limb8's tail is 27 B
(`rep movsq` backup → one `call pt_mul` → epilogue). Hamburg needs:
2× call setup (each with arg marshalling), R2 stash, inter-call cN
restore (bc_norm corrupts it), u1==0 check, combine (save R1 → bc_add
→ check Z → check X → restore → bc_dbl). Each piece is 8–18 B; 14
pieces. Floor estimate 144 B.

**3. Coordinate mismatch (+33 B).** CMO98 is Jacobian, RCB is
homogeneous. Combine needs one input affine → mod-p inversion → fe_inv_m
parameterized for both moduli (+15 B asm, +17 B bc_norm, +1 B jt).

---

## The survey's error mode

Each "what we'd add" bullet was estimated ~10–20 B by analogy to
similar-sounding constructs in limb8. But Hamburg's constructs are
novel — there's no conditional 256-bit arithmetic anywhere in the
current design to anchor against. "Second scalar-mult call" was
analogized to `call pt_mul` (5 B), not full arg-marshalling + inter-call
state management (~50 B).

**The deep finding:** bc_rcb (87 B, complete) vs bc_dbl+bc_add (80 B,
incomplete) — RCB's completeness costs only **7 B at the bytecode
level.** The infrastructure to avoid it costs 100+ B.

---

## Rescue attempts (all net-negative or wash)

| | Net |
|---|---|
| Keep bc_rcb for combine only | bytecode 178+87=265 B; worse |
| Full-Jacobian CMO98 combine (no mod-p inv) | ~−33 B but same P=Q cost; ~1135 B |
| Skip tcId 204 | −60 B but FIPS 186-5 violation |
| Projective-equality before bc_add (skip R1 save) | near-wash |

Structural floor ~1000 B. Doesn't beat limb8 or Thomas (928).
