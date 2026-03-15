# Cycle-count benchmarks

## Methodology

`bench.c` runs `rdtsc` around single verify calls and reports the
minimum of 50 runs. The table below is the minimum across 20 invocations
of the bench binary (best-of-50 × 20 = stable to within ~0.2%).

Vector: RFC 6979 "sample" (SHA-256 of "sample" with the RFC test key).
This exercises the full happy path — scalar multiplication, both field
inversions (mod-n and mod-p), and the final comparison.

## System

```
Intel(R) Xeon(R) Processor @ 2.10GHz
Fixed 2.1 GHz (cpu MHz: 2100.000, no turbo variance observed)
Feature flags: bmi2, adx, avx2
```

BMI2 is required for `tv_ecdsa_fast.S` (`mulx`). ADX (`adcx`/`adox`) is
available but not used — see notes below.

## Results

| Implementation | Bytes | Cycles | vs bc.S | Notes |
|---|---:|---:|---:|---|
| `tv_ecdsa_fast.S` | 1427 | **~649,000** | −65% | BMI2 `mulx`, MOVBE, Shamir |
| `tv_ecdsa_bc.S` | 1712 | ~1,832,000 | baseline | portable x86-64 |

Reproduce: `make bench`. bc.S measurements are noisy (observed ±20%
swing across sessions on the same machine); fast.S is stable to ~0.2%.
When comparing before/after a fast.S change, bench both in the same
sitting and use the fast.S-vs-fast.S delta rather than the ratio.

## Where the cycles go

Rough per-verify operation counts (RFC 6979 vector — ~128 set bits
in each scalar). Since Shamir's trick was added, one 256-bit walk
handles both u1·G and u2·Q, so doublings are halved relative to the
old two-pt_mul arrangement:

| Call | Count | Notes |
|---|---:|---|
| `bc_dbl` runs | ~256 | one walk of 256 bits |
| `bc_add1`+`bc_add2` runs | ~256 | ~128 u1-adds (G) + ~128 u2-adds (Q) |
| `fe_mul_m` | **~5,850** | 8 per bc_dbl, 16 per add, ~380 per fe_inv_m × 2 |
| `muladd4` | ~47,000 | 8 per fe_mul_m (4 outer × 2 inner) |
| `fe_sub_raw` | ~6,000 | 1 per fe_mul_m tail + Fsub handlers |
| bytecode ops decoded | ~11,000 | bc_dbl=24 × 256 + adds + setup |

At 0.65M cycles / 5,850 fe_mul_m ≈ **111 cycles per Montgomery mul**.
That's 111 / 8 ≈ **14 cycles per `muladd4`** — a 4-limb `mulx`/`add`/
`adc` chain at ~3.5 cycles per limb including memory traffic. The drop
from ~19 to ~14 cyc/muladd4 is the carry-elision change: `mulx`
preserves flags, so each limb's mem-add CF threads straight through
to the next limb's `adc`, dropping one `adc r,0` barrier per limb.

## Speed/size trades measured along the way

Cases where the cycle delta was actually measured, not estimated:

| Change | Bytes | Cycles | Verdict |
|---|---:|---:|---|
| `rep stosq` for fe_mul_m zero (count=9) | −3 | **+140K** | reverted — startup penalty ~140 cyc/call × ~1000 |
| `fe_iszero` looped vs unrolled | −3 | +~4K | kept — <0.4%, ~260 calls |
| fe_mul_m push/pop around fe_sub_raw | −2 | +~15K | kept — stack engine absorbs most, ~1.2% |
| Straight-line decoder (vs push/pop loop) | +? | −~70K | kept — paid for by consts-at-`[r14+disp8]` |

## Not-yet-exploited headroom

See [CLAUDE.md](CLAUDE.md) → "Possible next directions" for the
current detailed evaluation. Short version:

- **ADX (`adcx`/`adox`):** would interleave two carry chains, but the
  `mulx`-preserves-flags elision already dropped half the barriers
  without ADX. `adox` has no mem-dst form, so t would need to go into
  registers — big restructure for maybe −5% cycles.

- **Windowed scalar mul:** 4-bit window + precompute table (16 points ×
  96 bytes = 1.5 KB RAM, zero ROM) would quarter the doubling count.
  Big speed win but RAM cost is probably a non-starter for boot ROM.

- **Shamir's trick** — done. Was +22 B for ~30% cycles.
