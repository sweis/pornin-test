# Cycle-count benchmarks

## Methodology

`bench.c` runs `rdtsc` around single verify calls and reports the
minimum of 50 runs. The table below is the minimum across 20 invocations
of the bench binary (best-of-50 × 20 = stable to within ~0.2%).

Vector: RFC 6979 "sample" (SHA-256 of "sample" with the RFC test key).
This exercises the full happy path — both pt_mul calls, a point addition,
a field inversion, and the final comparison.

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
| `tv_ecdsa_fast.S` | 1511 | **1,197,606** | −43.7% | BMI2 `mulx` |
| `tv_ecdsa_bc.S` | 1712 | 2,129,022 | baseline | portable x86-64 |

Reproduce: `make bench`.

## Where the cycles go

Rough per-verify operation counts (RFC 6979 vector — ~128 set bits
in each scalar):

| Call | Count | Notes |
|---|---:|---|
| `bc_dbl` runs | ~640 | 256 per pt_mul × 2, plus doubling-on-add paths |
| `bc_add1`+`bc_add2` runs | ~256 | ~128 set bits × 2 scalars |
| `fe_mul_m` | **~7,900** | 8 per bc_dbl, 16 per add, ~380 per fe_inv_m × 2 |
| `muladd4` | ~63,000 | 8 per fe_mul_m (4 outer × 2 inner) |
| `fe_sub_raw` | ~8,000 | 1 per fe_mul_m tail + Fsub handlers |
| bytecode ops decoded | ~19,000 | bc_dbl=24 × 640 + adds + setup |

At 1.20M cycles / 7,900 fe_mul_m ≈ **150 cycles per Montgomery mul**.
That's 150 / 8 ≈ 19 cycles per `muladd4` — a 4-limb `mulx`/`add`/`adc`
chain, about 5 cycles per limb including memory traffic.

## Speed/size trades measured along the way

Cases where the cycle delta was actually measured, not estimated:

| Change | Bytes | Cycles | Verdict |
|---|---:|---:|---|
| `rep stosq` for fe_mul_m zero (count=9) | −3 | **+140K** | reverted — startup penalty ~140 cyc/call × ~1000 |
| `fe_iszero` looped vs unrolled | −3 | +~4K | kept — <0.4%, ~260 calls |
| fe_mul_m push/pop around fe_sub_raw | −2 | +~15K | kept — stack engine absorbs most, ~1.2% |
| Straight-line decoder (vs push/pop loop) | +? | −~70K | kept — paid for by consts-at-`[r14+disp8]` |

## Not-yet-exploited headroom

- **ADX (`adcx`/`adox`):** the dual-carry-chain ops let two independent
  carry chains interleave without `adc r,0` barriers. `muladd4` has one
  carry chain per limb pair — ADX could cut dependency depth. Likely
  −20–30% cycles in `muladd4`, so maybe −15% total. Cost: probably +10–20
  bytes (the ops are 5 bytes each vs `adc r,0` at 4).

- **Windowed scalar mul:** 4-bit window + precompute table (16 points ×
  96 bytes = 1.5 KB RAM, but zero ROM) would quarter the doubling count.
  Big speed win but RAM cost is probably a non-starter for boot ROM.

- **Shamir's trick (interleaved u1·G + u2·Q):** halves total doublings.
  Precompute G+Q (one extra pt_add). ~25% speed win. Requires either a
  third point slot and an extended `bc_dbl` that doubles the right
  accumulator, or reworking pt_mul to take two scalars. Last time this
  was investigated it looked like +30–50 bytes of bytecode/handler.
