# archive/ — superseded implementations

One-off explorations and reference implementations no longer on the
active development path. Kept for history and comparison.

| File | What | Superseded by |
|---|---|---|
| `tv_ecdsa.c` | Portable C, 32-bit limbs, ~3076 B (with `-fno-asynchronous-unwind-tables`) | tiny.S (933 B) |
| `tv_ecdsa_small.c` | ARM-tuned C, 4-arg calls | tiny.S |
| `tv_ecdsa_amd64.S` | Original hand-asm, 2875 B | All of the bytecode-interpreter tracks |
| `tv_ecdsa_bc.S` | Portable bytecode baseline, 1712 B | tiny.S (same arch, grinded) |
| `p256_rust/` | Pure Rust port. O3 + `#[inline(never)]` on Fe::mul = 8.9KB / 461K cyc (commit 52ad853). Useful as "what does LLVM do with this" reference. | Not a size-golf track |
| `fe_mul_5x54_draft.S` | Early 5×54 multiply (230 B, had bugs). | `limb5/fe_mul.S` |
| `limb11_consts.h` | Scratch constant notes during limb11 Phase 1. | Constants inlined in `limb11/tv_ecdsa.S` |

## Top-level Makefile targets

The old `test_ecdsa` / `test_ecdsa_asm` / `size-c` targets in the
top-level Makefile reference these paths. To use them, either
`make -C .. VPATH=archive test_ecdsa` or update the Makefile paths.
The active targets (`test-tiny`, `test-fast`, `bench-*`) don't touch
these files and still work.
