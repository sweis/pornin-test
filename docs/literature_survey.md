# Literature Survey: Size-Optimized ECDSA/P-256 (2015–2025)

102-agent adversarial verification harness. 20 sources, 95 claims → 25
verified, 20 confirmed. Run 2026-03-19 against the 891 B floor.

## Confirmed at the floor — stop looking

| Area | Finding | Vote |
|---|---|---|
| **RCB addition** | 43-op / 5-temp is the published floor. Nothing post-2015 in EFD (verified by direct enumeration, max year = 2015). Fay's 2014 combined double-add has FOUR exception cases — more branches than the 3-way tree we removed. | 3-0 |
| **GLV / endomorphisms** | P-256 j-invariant ∉ {0,1728} → no CM endo. Fake-GLV (ePrint 2025/933) needs SNARK prover hints. Antipa 2005 runs EEA natively — adds code, saves time. | 3-0 |
| **Modular reduction** | q=t[top] (limb8) beats Möller-Granlund Alg 4 by one mul/step (the top-dword-all-ones structure). m0i=1 Montgomery (limb5/11) matches Gueron-Krasnov 2013. Lazy-carry achieves Walter 1999's zero-sub bound (R≥4p). | 3-0 |
| **wNAF** | Speed technique, not size. "−64 adds" are runtime executions; bytecode is uniform 2 B/op regardless of call count. Encoder + on-the-fly negate are pure overhead at our granularity. | 3-0 |

## Worth trying — the two untried architectures

### Shamir-free (Hamburg signed-binary ladder)

**The idea:** drop Shamir's trick entirely. Call one single-scalar
routine twice (u2·Q then u1·G). ~2× latency accepted.

**The enabler:** Hamburg ECC 2015 slides 10-14 — make the scalar odd,
initialize carefully, then the partial-scalar bound `1 < 2·s_i < n−1`
**structurally guarantees** P ∉ {O, Q, −Q} inside the loop. The
LADDER carries the invariant, not the formula. So INCOMPLETE addition
(CMO98 Jacobian, ~11M+5S, ~25 ops) runs with zero branches.

**Verified in p256-m** (github.com/mpg/p256-m): L1421+L1428 = two
separate scalar_mult calls in verify. README: "in order to minimize
code size." x86-64 i7-6500U: sign 1136µs, verify 2279µs = exactly 2×.

**What we'd drop:**
- bc_rcb: 88 B (43 ops) → ~50 B (25-op Jacobian)
- 6 Shamir backup slots → gone
- COPYHI handler → gone
- Dual-bt dispatch in pt_mul → single bt

**What we'd add:**
- Hamburg init (odd-conversion + conditional point-negate)
- Second scalar-mult call + result stash
- ONE final combining add — **this is the critical cost**

**⚠ Open question (caveats §3):** p256-m's proof (L1098-1111) is for
the scalar k, using P-256-specific "bit 1 of n = 1." ECDSA's u1, u2
are ATTACKER-INFLUENCEABLE. u=1 is possible. Wycheproof tcId 288-292
specifically target these edges. Must verify the odd-conversion
(s_odd ∈ {s, n−s}) handles all u ∈ [1, n−1].

**⚠ The final combining add:** u1·G and u2·Q outputs don't share Z.
Incomplete Jacobian addition might hit u1·G = ±u2·Q (attacker can
force). p256-m uses point_add_or_double_leaky (3-way branch, ~30 B).
**If RCB must stay for this one call, the 38 B bytecode savings
evaporate.**

~~**Net estimate: −30 to +20 B.** Worth the experiment.~~

**MEASURED: +277 B (prototype 1168 B). Dead end.** The estimate
counted bytecode ops and missed three asm cost centers — see
`docs/hamburg_assessment.md`. RCB's completeness costs only 7 B at
the bytecode level; the infrastructure to AVOID it costs 100+ B.

### ~~WW-AMM single-iteration (s=256)~~ — REFUTED

**The premise is false.** The survey's "m0i=1 kills call #2" conflated
per-LIMB m0inv (which is 1 for p at W≤96, because p's low W bits are
all-ones) with full-width m0inv at s=256. Computed:

```
−p⁻¹ mod 2^256 = 0xffffffff00000002_00000000_00000000_00000001_00000000_00000000_00000001
```

Not 1. The "free q" doesn't exist. For n, m0inv is unstructured at
every width — always needs the third kernel call.

**Worse: CIOS already IS the factored form.** `.Lcnt` is called twice
per row. Commits `6de9a83` (limb11, −7 B) and `6ff298a` (limb5, −18 B)
are "CIOS merge" — they ELIMINATED the separate-loops structure
WW-AMM would reintroduce. We'd be undoing proven wins.

**Hidden cost:** `.Lcnt` discards rdx (imul high). CIOS's per-row
`sar;add` keeps limbs bounded at ~29 bits. After a full K×K, T[k] is
~62 bits; feeding that as rbx into the next kernel loses ~22 product
bits. Inter-call carry-prop is mandatory.

**Verdict: +110 B best case. Dead end.** See `docs/ww_amm_sketch.md`.

## Marginal — only if Shamir-free runs

**Co-Z ladder (ZADDC+ZADDU):** 39 ops/bit vs RCB's 43. Meloni's
free-byproduct normalization is real (W1:A1:Z3 ∼ P at zero cost).
But: single-scalar only, DBLU init, MSB-assumption, and the final
combination still needs non-co-Z. Only a possible inner-loop swap
IF Hamburg+CMO98 is already running.

## Refuted

- "(X,Y)-only co-Z at 8M+6S with 6 registers" — 0-3. Oversold.
- "Reciprocal via table + Newton" — 0-3. We never compute reciprocals.
- "P256-cortex-ecdh's incomplete formula approach applies" — 0-3.
  Their approach relies on scalar being a random private key; ECDSA
  verify scalars are attacker-influenceable. **RCB is correct for
  our context.** (The Hamburg ladder is DIFFERENT — it's the ladder
  structure, not the scalar randomness, that carries the invariant.)

## Open questions (not in corpus)

- **Q4 strong form:** can any of RCB's 12 field mults share
  intermediate products? Hand-analysis of bc_rcb, no literature needed.
- **Q5:** sub-schoolbook at K≤8 — Karatsuba's SPEED crossover is
  K≈8-16; CODE SIZE crossover should be higher (scaffolding). Not
  rigorously ruled out.

## Sources

Primary: EFD, ePrint {2010/309, 2011/239, 2013/816, 2014/1014,
2015/408, 2019/1166, 2024/038, 2025/933}, Möller SAC 2001,
Möller-Granlund IEEE TC 2011, Yanik-Savaş-Koç, p256-m (mpg),
P256-cortex-ecdh (Emill), Hamburg ECC 2015 slides.
