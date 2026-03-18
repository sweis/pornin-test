# limb11/ — 11×24 signed-limb Montgomery track

Thomas at **928 B / 4.48M cyc** with 5×54 signed limbs.
tiny.S at 933 B no longer dominates. Target here: **< 928 B**.

## Why 11×24, not 5×54

`range_proof.py` proves both converge (KW > 263.2 required).
But 11×24 keeps products in 60 bits — pure 64-bit math. 5×54 needs
128-bit accumulation (add+adc, shrd). First-draft fe_mul:
190 B (11×24) vs 230 B (5×54). Structural 40 B gap.

## Status

| Piece | State | Size |
|---|---|---|
| `fe_mul.S` | ✅ 103/103 | 158 B (+15 vs tiny's 143) |
| `range_proof.py` | ✅ convergence + correctness | — |
| `gen_bytecode.py` | ⚠️ RCB works, bc_v1 has slot collision | — |
| `tv_ecdsa.S` | ⚠️ skeleton, not buildable | — |

**Not yet at 607/607.** See `PLAN.md` for the build order.

## Files

- `PLAN.md` — the roadmap. Read this first.
- `NOTES.md` — scratch notes from the first session (superseded by PLAN.md)
- `progress.csv` — size/cycle trajectory, one row per checkpoint
- `range_proof.py` — convergence proof + correctness oracle
- `gen_bytecode.py` — generates bc_rcb/bc_v1/bc_v3 with slot validation
- `fe_mul.S` — the standalone multiply (tested)
- `fe_mul_5x54.S` — 5×54 comparison (230 B, reference only)
- `tv_ecdsa.S` — full implementation skeleton
- `test_mul.c`, `vectors_mul.h` — unit test for fe_mul
- `consts.h` — precomputed Montgomery constants

## Workflow

```
make test-mul     # unit test fe_mul (works now)
make test         # full 607/607 (not yet)
make size         # the number
make check        # re-run range proof
make regen        # regenerate bytecode.inc from gen_bytecode.py
```

**Do not push.** Commit locally only.
