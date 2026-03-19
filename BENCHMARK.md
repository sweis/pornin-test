# Measurement methodology

## Size: the eh_frame gotcha

GCC and Clang on amd64 emit an `.eh_frame` section by default —
unwinding info for C++ exceptions and stack traces. The `size` tool
lumps it into the `text` column. For this kind of code it runs
400-500 B. Neither feature applies to a code-golfed verifier.

**Fix for compiled C:** `-fno-asynchronous-unwind-tables`. Measured
on `tv_ecdsa_small.c`: 5664 → 5144 B (520 B of `.eh_frame`).

**Pure `.S` is clean.** Verified on `limb8/tv_ecdsa.o`: no `.eh_frame`
present, `size` = `.text` exactly (no `.rodata` anymore — constants
live in `.text`). All `.S` implementations in this project (`limb8/`,
`limb11x24/`, `limb5x54/`, `limb5x56/`, `speed/`) measure real.
Thomas's 928 B is pure assembly — also real.

---

# Cycle-count benchmarks

`common/bench.c` runs `rdtsc` around single verify calls and reports
the minimum of 50 runs. Vector is RFC 6979 "sample" — full happy path.
Intel Xeon @ 2.1 GHz (Sapphire Rapids, no turbo variance observed).
`make bench20` wraps this in a 20-run median to smooth DSB/alignment
jitter (see commit 607d9bd note — a 1-byte shift moved ±8% purely
from DSB↔MITE uop split).

| Implementation | Bytes | Cycles | Notes |
|---|---:|---:|---|
| `limb8` default | 908 | ~4,000,000 | 64-bit schoolbook, MOVBE only |
| `limb8` `-DSMALL_MUL8` | 890 | ~5,200,000 | 32-bit `scasd` inner |
| `limb5x54` | 1097 | ~2,800,000 | 5×54 Montgomery CIOS |
| `speed/fast2.S` | 3265 | ~570,000 | BMI2+ADX mulx lazy-carry |
| Thomas v7 (external) | 928 | ~4,480,000 | 5×54 — off our frontier |

## Where the cycles go in limb8

Pre-Shamir there would be 512 doublings; Shamir halves that. ~256
adds total (~128 each for u1 and u2, RFC 6979 scalars ~half-set).

The hot loop is the schoolbook-multiply inner body inside `fe_mul_m`.
Per verify: ~256 bc_dbl + ~256 bc_add + one 254-iter fe_inv_m =
~8K fe_mul_m calls, each one a full 256×256→512 product plus the
sliding 32-bit reduce.

| Build | inner-loop ops | iters/verify | cyc/iter | notes |
|---|---|---:|---:|---|
| default | `mul`/`adc`/`dec`/`jnz` | ~130K | ~1 | 4×4 qword limbs |
| SMALL_MUL8 | `mul`/`adc`/`loop`/`scasd` | ~950K | ~5 | 8×8 dword; `loop` ~7 cyc, `scasd` ~3 cyc, both microcoded |

The default build's +18 B over the floor buys back ~1.2M cycles — the
whole size/speed trade in one `#ifdef`.

## Notable measured trades along the way

| Change | Bytes | Cycles | Kept? |
|---|---:|---:|---|
| `loop`+`scasd` → `dec;jnz`+`lea` in mul8 | +18 | −1.2M | yes (as default) |
| `rep stosq` for fe_mul_m zero init | −3 | +100K | no — startup penalty |
| projective check (drop mod-p inv) | −~35 | −~0.3M | yes — win on both axes |
| .Lop3 `loop` → `dec;jnz` (`#ifndef SMALL_MUL8`) | +4 | −560K | yes — only size floor keeps `loop` |
