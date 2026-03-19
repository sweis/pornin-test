# Literature Survey: Size-Optimized ECDSA/P-256 (2015–2025)

20 sources, 95 claims → 25 verified, 20 confirmed. Run 2026-03-19
against the ~890 B limb8 floor.

## Confirmed at the floor — stop looking

| Area | Finding | Vote |
|---|---|---|
| **RCB addition** | 43-op / 5-temp is the published floor. EFD enumerated (max year 2015). Fay 2014 has FOUR exception cases — more branches than the 3-way tree we removed. | 3-0 |
| **GLV / endomorphisms** | P-256 j-invariant ∉ {0,1728} → no CM endo. Fake-GLV (ePrint 2025/933) needs SNARK prover hints. Antipa 2005 runs EEA natively — adds code. | 3-0 |
| **Modular reduction** | q=t[top] (limb8) beats Möller-Granlund Alg 4 by one mul/step (top-dword-all-ones structure). m0i=1 Montgomery (limb5/11) matches Gueron-Krasnov 2013. Lazy-carry hits Walter 1999's zero-sub bound (R≥4p). | 3-0 |
| **wNAF** | Speed technique, not size. "−64 adds" are runtime executions; bytecode is 2 B/op regardless. Encoder + on-the-fly negate are pure overhead at our granularity. | 3-0 |

## Refuted — measured

### Shamir-free (Hamburg signed-binary ladder)

**+277 B measured** (prototype 1168 B vs limb8 891). The survey's
−30 to +20 B counted bytecode ops, missed three asm cost centers:
Hamburg conditional init (~50 B — bytecode can't branch), two-call
verify tail (+117 B — arg setup × 2 + 3-way combine for tcId 204),
coordinate mismatch (+33 B — CMO98 Jacobian vs our homogeneous).

The Hamburg invariant DOES hold for u ∈ [1,n−1] (u=1 fine; p256-m's
proof at L1098 applies) — correctness concern was unfounded, size
estimate was off. **RCB's completeness costs only 7 B at bytecode
level** (87 vs bc_dbl+bc_add=80); the infrastructure to avoid it costs
100+ B. → `docs/hamburg_assessment.md`

### WW-AMM single-iteration (s=256)

**+110 B best case.** The "m0i=1 kills call #2" premise conflated
per-LIMB m0inv (=1 for W≤96, because p's low bits are all-ones) with
full-width:
```
−p⁻¹ mod 2^256 = 0xffffffff00000002_00000000_00000000_00000001_00000000_00000000_00000001
```
Not 1. For n, unstructured at every width. Worse: CIOS already IS the
factored form — `.Lcnt` called 2×/row. Commits 6de9a83 (limb11 −7 B)
and 6ff298a (limb5 −18 B) are "CIOS merge" which eliminated the
separate loops WW-AMM reintroduces. → `docs/ww_amm_sketch.md`

## Refuted — voted

- "(X,Y)-only co-Z at 8M+6S / 6 registers" — 0-3, oversold
- "Reciprocal via table + Newton" — 0-3, we never compute reciprocals
- "P256-cortex-ecdh incomplete formulas apply" — 0-3, their scalar is
  a random private key; ECDSA verify scalars are attacker-influenceable.
  RCB is correct for verify. (Hamburg is different — the *ladder*
  carries the invariant, not scalar randomness.)

## Marginal — untried

**Co-Z ladder (ZADDC+ZADDU):** 39 ops/bit vs RCB 43. Single-scalar
only — would need Hamburg's two-call structure, which is dead.

## Open (not in corpus)

- **Q4:** can any of RCB's 12 Fmuls share intermediate products?
  Hand-analysis of bc_rcb, no literature.
- **Q5:** Karatsuba at K≤8 — speed crossover ~K=8–16; code-size
  crossover should be higher (scaffolding). Not rigorously ruled out.

## Sources

EFD; ePrint {2010/309, 2011/239, 2013/816, 2014/1014, 2015/408,
2019/1166, 2024/038, 2025/933}; Möller SAC 2001; Möller-Granlund
IEEE TC 2011; Yanik-Savaş-Koç; p256-m (mpg); P256-cortex-ecdh (Emill);
Hamburg ECC 2015 slides.
