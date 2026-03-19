# Measurement methodology

## Size: the eh_frame gotcha

GCC and Clang on amd64 emit an `.eh_frame` section by default —
unwinding info for C++ exceptions and stack traces. The `size` tool
lumps it into the `text` column. For this kind of code it runs
400-500 B. Neither feature applies to a code-golfed verifier.

**Fix for compiled C:** `-fno-asynchronous-unwind-tables`. Measured
on `tv_ecdsa_small.c`: 5664 → 5144 B (520 B of `.eh_frame`).

**Pure `.S` is clean.** Verified on `limb11x24/tv_ecdsa.o`: no
`.eh_frame` present, `size` = `.text` + `.rodata` exactly. All `.S`
implementations in this project (`tiny.S`, `fast.S`, `fast2.S`,
`speed.S`, `limb11x24/`, `limb5x54/`, `limb5x56/`) measure real. Thomas's 928 B is pure
assembly — also real.

---

# Cycle-count benchmarks

`bench.c` runs `rdtsc` around single verify calls and reports the
minimum of 50 runs. Vector is RFC 6979 "sample" — full happy path.
Intel Xeon @ 2.1 GHz (Sapphire Rapids, no turbo variance observed).

| Implementation | Bytes | Cycles | Notes |
|---|---:|---:|---|
| `tv_ecdsa_tiny.S` default | 1108 | ~2,400,000 | 64-bit schoolbook, MOVBE only |
| `tv_ecdsa_tiny.S` `-DSMALL_MUL8` | 1088 | ~6,300,000 | 32-bit `loop`+`scasd` inner |
| `tv_ecdsa_fast.S` | 1397 | ~650,000 | Montgomery + `mulx` + Shamir |
| `tv_ecdsa_bc.S` | 1712 | ~1,850,000 | portable x86-64 baseline |
| Thomas (external) | 1046 | ~3,990,000 | holds the size corner |

## Where the cycles go in tiny.S

Pre-Shamir there would be 512 doublings; Shamir halves that. ~256
adds total (~128 each for u1 and u2, RFC 6979 scalars ~half-set).

The hot loop is the schoolbook-multiply inner body inside `fe_mul_m`.
Per verify: ~256 bc_dbl + ~256 bc_add + one 254-iter fe_inv_m =
~8K fe_mul_m calls, each one a full 256×256→512 product plus the
sliding 32-bit reduce.

| Build | inner-loop ops | iters/verify | cyc/iter | notes |
|---|---|---:|---:|---|
| default | `mul`/`adc`/`dec`/`jnz` | ~130K | ~1 | 4×4 qword limbs |
| SMALL_MUL8 | `mul`/`adc`/`loop`/`scasd` | ~950K | ~6 | 8×8 dword; `loop` ~7 cyc, `scasd` ~3 cyc, both microcoded |

The default build's +20 B over the floor buys back ~4M cycles — that's
the whole speed/size trade in one knob.

## Notable measured trades along the way

| Change | Bytes | Cycles | Kept? |
|---|---:|---:|---|
| `loop`+`scasd` → `dec;jnz`+`lea` in mul8 | +12 | −3.2M | yes (as default) |
| 32-bit → 64-bit schoolbook product | +8 | −0.5M | yes (as default) |
| `rep stosq` for fe_mul_m zero init | −3 | +100K | no — startup penalty |
| projective check (drop mod-p inv) | −~35 | −~0.3M | yes — win on both axes |
