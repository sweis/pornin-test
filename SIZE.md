# Code size tracking — ECDSA/P-256 verify

Measurements of the `tv_ecdsa.c` object file (the verification core only;
the test harness is excluded).

## Build command

```
cc -std=c99 -Os -ffreestanding -fno-strict-aliasing \
   -ffunction-sections -fdata-sections \
   -fno-asynchronous-unwind-tables -fno-ident \
   -fno-stack-protector -fno-tree-loop-distribute-patterns \
   -c -o tv_ecdsa_size.o tv_ecdsa.c
```

Run `make size` to reproduce.

## Current results

| Target                      | Compiler       | text+rodata | Notes                 |
|-----------------------------|----------------|-------------|-----------------------|
| x86-64 (amd64)              | GCC 13.3 `-Os` | **3076 B**  | zero undefined syms   |
| x86-64 (amd64)              | clang 18 `-Os` | ~3856 B     | larger; different inliner |
| ARM Cortex-M4 (Thumb-2)     | arm-none-eabi  | *(todo)*    | expected ~2000–2400 B |

The object file has **no external symbol references** — no `memcpy`, no
`memmove`, no `memset`, no libc. The only imports are the two standard
typedefs `uint32_t` / `uint64_t` from `<stdint.h>` and `size_t` from
`<stddef.h>`. On a real firmware build you would link this object
directly; nothing else is pulled in.

## Section breakdown (x86-64, GCC 13.3)

```
.text.fe_zero                   17
.text.fe_cpy                    19
.text.fe_iszero                 24
.text.fe_sub_raw                40
.text.fe_geq                    39
.text.muladd10                  69
.text.fe_mul_m                 170   Montgomery multiplication core
.text.fe_inv_m                 181   Fermat inversion (shared p / n)
.text.Fmul                      18
.text.Fsqr                      21
.text.Fto_mont                  25
.text.pt_cpy                    37
.text.pt_set_inf                26
.text.fe_from_be                28
.text.Fsub                      51
.text.Fadd                      44
.text.pt_dbl                   451   Jacobian doubling (a = -3)
.text.pt_add                   593   Jacobian add, all special cases
.text.pt_mul                    78   double-and-add
.text.tv_ecdsa_p256_verify     889   public entry point
.rodata  (7 × 32-byte const)   224   P, N, B, GX, GY, R2P, R2N
                             ──────
                              3076
```

## Optimisation journey (x86-64, GCC 13.3 `-Os`)

| Step                                            | Size   | Δ      |
|-------------------------------------------------|--------|--------|
| Initial working implementation                  | 4271 B |        |
| Wrapper functions for mod-p ops (fewer args)    | 3835 B | -436 B |
| `fe_geq` direct compare (no temp buffer)        | 3773 B | -62 B  |
| Factor `muladd10` helper from `fe_mul_m`        | 3772 B | -1 B   |
| `Fadd` via negation + `Fsub`                    | 3737 B | -35 B  |
| Skip redundant Montgomery conversions in mod-n  | 3575 B | -162 B |
| Reuse temps in `pt_add` (12 → 6 locals)         | 3558 B | -17 B  |
| Stack-frame reuse in `verify` (Q reused for G)  | 3493 B | -65 B  |
| `-fno-stack-protector` (not applicable in ROM)  | 3162 B | -331 B |
| `NOINLINE` on `pt_cpy` / `pt_set_inf`           | 3106 B | -56 B  |
| Reuse `delta` slot in `pt_dbl`                  | 3102 B | -4 B   |
| `-ffreestanding` (eliminate `memmove` ref)      | 3076 B | -26 B  |

## Design summary

- **One generic Montgomery multiplier** parameterised by modulus — shared
  between field-p arithmetic and scalar (mod-n) arithmetic. No duplicate
  reduction code.
- **One generic Fermat inverter** — exponent `m-2` is computed from the
  modulus at runtime (saves 64 bytes of rodata versus storing both
  `p-2` and `n-2`).
- **No `memcpy`/`memset`/`memmove`** — all copies are explicit 8-word
  loops; the compiler is told via `-ffreestanding` not to substitute
  libc calls.
- **Point addition handles every special case** (`P=O`, `Q=O`, `P=Q`,
  `P=-Q`). This is essential: adversary-controlled signature components
  can force these cases during the scalar-mul loop.
- **Simple double-and-add**, called twice, instead of Shamir's trick.
  Smaller code, ~2× slower — the right trade-off for a boot ROM.

## Correctness

All 33 tests pass (27 vectors + 6 length checks):

- RFC 6979 reference vectors (P-256 + SHA-256, both "sample" and "test")
- Signature malleability (`s' = n - s` must still verify)
- All-zero hash; hash numerically > n (must NOT be reduced mod n)
- 48- and 64-byte hash inputs (truncated to 32 bytes per FIPS 186-5)
- `r = 0`, `s = 0`, `r ≥ n`, `s ≥ n`, `r = n+1`, `s = 2^256-1`
- Public-key coordinates `≥ p`; point not on curve; wrong format byte
- Constructed case where `u1·G + u2·Q = O` (point at infinity) → reject
- Wrong signature / hash / public key → reject

The test harness also runs cleanly under ASAN+UBSAN.
