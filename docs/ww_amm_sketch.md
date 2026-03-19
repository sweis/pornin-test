# WW-AMM Single-Iteration (s=256) — Refuted

**+110 B best case.** Two independent killers: the premise is false,
and the shape is one we already climbed *away* from.

---

## Premise is false: per-limb m0inv ≠ full-width m0inv

The survey's "m0i=1 kills call #2" conflated two objects:

| Radix | −p⁻¹ mod radix | |
|---|---|---|
| 2^24, 2^32, 2^96 | **1** | p ≡ −1 mod 2^W (W ≤ 96) ✓ |
| **2^256** | `0xffffffff00000002_00000000_00000000_00000001_00000000_00000000_00000001` | ≠ 1 |

The low-96-bits-all-ones structure of p makes the per-LIMB m0inv
trivial. Full-width doesn't inherit that. Direct test (5 random A,B<p):
`(T + T_lo·p) mod 2^256` nonzero every time — low 96 bits clear, bits
96–255 don't. Step 2 (`q = T_lo · m0inv`) is a real multiply. Three
kernel calls, not two.

For **n**: `m0inv_n = 0x60d06633…ee00bc4f` — no structure at any width.

---

## CIOS is already the factored form

Gueron's WW-AMM pitch is "one kernel, multiple call sites." But the
current `.Lcnt` (15 B: `mov cl,K; lodsq; imul rbx; add [rdi],rax;
scasq; loop; ret`) **is** that kernel — called twice per CIOS row,
once with rsi=b (product), once with rsi=m (reduce).

Commits `6de9a83` (limb11, −7 B) and `6ff298a` (limb5, −18 B) are
"CIOS merge" — they **eliminated** separate product/reduce loops by
sharing the outer-loop counter. WW-AMM would reintroduce them.

Hidden cost: `.Lcnt` discards rdx (imul high). CIOS's per-row
`sar;add` keeps limbs ~29 bits, so products fit rax. After a full K×K,
T[k] is ~62 bits; feeding that back loses ~22 product bits. Inter-call
carry-prop becomes mandatory (+~10 B).

---

## Verdict

| Scenario | Δ vs 120 B CIOS baseline |
|---|---|
| 3-call WW-AMM, both moduli | **+110 B** (includes 2×32 B m0inv rodata) |
| 2-call for p (structured m0inv) + 3-call n | +60–80 B |
| Pure deinterleave (two loops, no "free q") | +7–18 B (measured, both tracks) |

limb8: not applicable (no Montgomery — q=t[top] direct reduce). The
structured-p win that WW-AMM's "structured m0inv" would give is already
captured by `-DSOLINAS_P`'s adc/sbb fold.
