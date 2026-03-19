# WW-AMM Single-Iteration (s=256) — Byte Estimate vs CIOS

**Verdict: LARGER. The premise is wrong and the tree was already
climbed in the opposite direction.**

Sketch for literature_survey.md § "WW-AMM single-iteration (s=256)",
per Gueron ePrint 2011/239 Remark 5.

---

## The premise is false

The survey claims: *"m0i=1 kills call #2 (Y = T_lo × k0 → Y = T_lo).
So it's TWO calls per mod-mult, not three."*

This conflates **per-limb** m0inv with **full-width** m0inv. They are
different objects.

| Radix | −p⁻¹ mod radix | Value |
|---|---|---|
| 2^24 (limb11 per-limb) | **1** | p ≡ −1 mod 2^24 ✓ |
| 2^32 (limb8 per-limb) | **1** | p ≡ −1 mod 2^32 ✓ |
| 2^96 | **1** | p ≡ −1 mod 2^96 ✓ (the boundary) |
| 2^256 (WW-AMM s=n) | `0xffffffff_00000002_00000000_00000000_00000001_00000000_00000000_00000001` | **≠ 1** |
| 2^264 (limb11 KW) | same as 2^256 with `0x00` prepended | **≠ 1** |

**Direct test** (5 random A,B < p): `(T + T_lo·p) mod 2^256` is
nonzero every time. The low 96 bits *do* clear (m0inv ≡ 1 mod 2^96),
but bits 96–255 don't.

So the "free q" doesn't exist. Step 2 (`q = T_lo · m0inv`) is a real
multiply — the full Gueron 3-call structure, not 2.

For **n**: `m0inv_n = 0x60d06633…ee00bc4f` — no structure at any
width. Always needs the full multiply.

---

## Baseline (limb11 current CIOS)

Measured from `objdump -d tv_ecdsa.o`, commit 559fe8d:

| | Offset | Bytes |
|---|---|---|
| `fe_mul11` body | `0xda – 0x143` | 105 |
| `.Lcnt` (inner row) | `0x143 – 0x152` | 15 |
| **Exclusive total** | | **120** |
| `.Lcp_shared` | `0x152 – 0x173` | 33 (shared with NORM) |

The `~142 B` figure in the survey is stale — current build is 120 B
after the CIOS-merge grind (6de9a83, −7 B).

**.Lcnt — the load-bearing observation:**
```
.Lcnt: mov cl,K; .Lin: lodsq; imul rbx; add [rdi],rax; scasq; loop .Lin; ret
```
15 bytes. Called **twice per CIOS row** — once with `rsi=b` (product),
once with `rsi=m` (reduce). This *is* the reusable kernel. CIOS already
has the factoring WW-AMM promises.

---

## What WW-AMM actually costs (best case, 3-call)

### The kernel (.Lfprod) — K×K accumulate

Wraps `.Lcnt` in an outer loop. Minimal form (A in r10, B in r8, dst
in r11, all survive `.Lcnt`):

| Instruction | Bytes |
|---|---|
| `mov r11, rdi` | 3 |
| `push -K*8; pop r9` | 4 |
| `.Lfr: mov rbx,[r10+r9+K*8]` | 5 |
| `lea rdi,[r11+r9+K*8]` | 5 |
| `mov rsi, r8` | 3 |
| `call .Lcnt` | 5 |
| `add r9, 8` | 4 |
| `jnz .Lfr` | 2 |
| `ret` | 1 |
| | **32** |

### Mandatory inter-call carry-prop

`.Lcnt` does `add [rdi],rax` and **discards rdx** (imul's high half).
Works in CIOS because `rbx = a[i]` ≤ ~29 bits, `rax = b[j]` ≤ ~29
bits → product ≤ ~58 bits, fits `rax`.

After a full K×K with no per-row shift, `T[k]` holds up to K≈11
products ≈ 2^62. Feed that as `rbx` into the next kernel call:
product is ~86 bits, top ~22 bits **lost**.

So between calls 1→2 and 2→3, T must be carry-propped to canonical
limbs. `.Lcp_shared` (33 B) exists but does exactly K limbs with
untruncated top — wrong shape for a 2K-limb mid-computation buffer
(carry from `T[K-1]` must land in `T[K]`, not stay in the top limb).

Options: (a) parameterize `.Lcp_shared` (+~6 B in the shared code +
call sites), (b) separate 2K-limb variant (~25 B), (c) upgrade
`.Lcnt` to 128-bit accumulate (`adc [rdi+8],rdx`, +4 B, but changes
CIOS semantics — range re-proof needed).

Cheapest estimate: **+10 B** (option a, two call sites).

### Byte totals

| Component | Bytes | Notes |
|---|---|---|
| Prologue + epilogue | 22 | same as current (push×4, enter, leave, pop×4, ret) |
| Zero T[0..2K-1] | 10 | same as current |
| `.Lfprod` kernel | 32 | new |
| Call 1: T = A·B setup | ~12 | `mov r10,rsi; mov r8,[rbp+8]; lea rdi,...; call` |
| Carry-prop T | ~10 | call site + `.Lcp_shared` tweak |
| Call 2: q = T_lo · m0inv setup | ~16 | `mov r10,T_lo; mov r8,m0inv_slot; lea rdi,q_buf; call` |
| m0inv select p-vs-n | ~8 | `cmp r11d,1; cmov/jne` (or branch to pick constant) |
| Carry-prop q | ~8 | call site |
| Call 3: T += q·m setup | ~12 | `mov r10,q; mov r8,[rbp+16]; lea rdi,T; call` |
| Final T[K..] → output | 11 | same as current (`.Lcp_shared` call) |
| `.Lcnt` (existing) | 15 | unchanged |
| **Code subtotal** | **~156** | |
| `m0inv_p` constant (32 LE bytes) | 32 | new rodata |
| `m0inv_n` constant (32 LE bytes) | 32 | new rodata |
| m0inv decode into slot | ~10 | `fe_from_le` call site (or two) |
| **Grand total** | **~230 B** | |

vs. 120 B baseline. **+110 B.**

---

## Can structured m0inv_p save it? (2-call for p, 3-call for n)

`m0inv_p = 1 + 2^96 + 2·2^192 − 2^224` (verified). So
`q = T_lo + (T_lo ≪ 96) + 2·(T_lo ≪ 192) − (T_lo ≪ 224)  mod 2^264`.

**limb11 (W=24):** 96 and 192 are 4-limb and 8-limb shifts — aligned.
But **224 / 24 = 9.333** — cross-limb. The non-aligned term needs
shld or shift+mask on each limb. In 24-bit limbs m0inv_p has 5
nonzero limbs `[1,0,0,0,1,0,0,0,2,0xffff00,0x00ffff]` — limbs 9,10
aren't ±1. Estimate: ~40–50 B for the p-specific q computation.

**limb8 (W=32):** all three shifts are limb-aligned (3, 6, 7). m0inv_p
dwords = `[1,0,0,1,0,0,2,−1]`. This is the Solinas structure — and
limb8's `SOLINAS_P` reduce **already exploits exactly this** via the
adc/sbb chain at `tv_ecdsa.S:742-768`. No new territory.

Even granting the p-case structured q: the n-case still needs the
full kernel call + `m0inv_n` constant. And the code must branch on
modulus. Net: still +60–80 B over baseline.

---

## The empirical nail

**This tree has been climbed the other way.** Two commits merged
separate product/reduce loops INTO the single CIOS loop:

- `6de9a83` (limb11): `CIOS merge (schoolbook+reduce in one loop)` — **−7 B** (1319→1312)
- `6ff298a` (limb5): `CIOS merge (schoolbook+reduce one loop)` — **−18 B** (1288→1270)

WW-AMM's scheduling is precisely the "before" state of these commits.
The savings came from **eliminating the second outer-loop counter +
tail**. The current `.Lcios` loop body at 64 B calls `.Lcnt` twice
per iteration with shared `r9` index and shared `rdi` flow between the
calls. Split it and you pay ~13 B (measured: 68 B merged vs ~81 B
split) before any of the extra plumbing above.

---

## limb8 (for completeness)

limb8 **doesn't use Montgomery** — it's the `q=t[top_dword]` direct
reduce (both moduli have top dword `0xffffffff`, so the
Barrett-quotient estimate is exact to ±1). fe_mul_m = 142 B
(`0x24f–0x2dd`, SMALL_MUL8 build).

WW-AMM is a Montgomery technique. Applying it to limb8 means first
converting to Montgomery form: +R²_p, +R²_n rodata, +conversion
glue in decode path. The `SOLINAS_P` build variant already captures
the structured-p win that WW-AMM's "structured m0inv" would provide,
via a different (and already-committed) route.

**Not applicable.**

---

## Verdict

| Scenario | Δ vs baseline | |
|---|---|---|
| 3-call WW-AMM, both moduli | **+110 B** | kills it outright |
| 2-call for p (structured q) + 3-call for n | **+60–80 B** | still dead |
| Pure deinterleave (no "free q", just two loops) | **+7–18 B** | measured, both limb11 and limb5 |

**LARGER.** The `.Lcnt`-shared CIOS is already the factored form that
WW-AMM's "one kernel, multiple call sites" pitch promises. Gueron's
technique trades K interleaved (row + reduce) iterations for 2–3
separate K-iteration passes; the op count is identical (2K² muls
either way) and the code-size tiebreaker goes to whoever has fewer
outer loops. CIOS has one.

Update literature_survey.md: move WW-AMM from "Worth trying" to
"Refuted", correct the m0i=1 claim.
