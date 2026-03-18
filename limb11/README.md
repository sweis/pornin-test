# limb11/ — 11×24 signed-limb Montgomery track

Thomas at **928 B / 4.48M cyc** with 5×54 signed limbs.
tiny.S at 933 B no longer dominates. Target here: **< 928 B**.

## State

**1312 B, 607/607 pass, ~12.2M cycles.** Phase 1 (working baseline)
done at 1488 B. Phase 2 grind ongoing. 384 B to go.

## Why 11×24, not 5×54

`range_proof.py` proves both converge (KW > 263.2 required).
But 11×24 keeps products in 60 bits — pure 64-bit math. 5×54 needs
128-bit accumulation (add+adc, shrd). First-draft fe_mul:
190 B (11×24) vs 230 B (5×54). Structural 40 B gap.

**Structural tax vs tiny.S (~55 B):** n's top limb at W=24 is 0xffff,
not 0xffffff — q=t[top] reduce fails. Montgomery-n is mandatory:
cR2_n constant + s_mont/1_mont_p/r_mont/n_mont ops in bc_v1.

## Files

- `HANDOFF.md` — **read first.** Current state + biggest untried ideas.
- `PLAN.md` — full trick catalog (tiny.S's + new-to-11×24).
- `progress.csv` — trajectory, one row per checkpoint
- `tv_ecdsa.S` — the implementation (working, 607/607)
- `bytecode.inc` — generated; regenerate via `make regen`
- `gen_bytecode.py` — bc_rcb/bc_v1/bc_v3 with slot-lifetime validation
- `range_proof.py` — convergence proof + correctness oracle
- `fe_mul.S` — standalone multiply reference (103/103)
- `test_mul.c`, `vectors_mul.h` — fe_mul unit test
- `consts.h` — Montgomery constants (BE/LE reference values)
- `NOTES.md`, `fe_mul_5x54.S` — archival

## Workflow

```
make test         # 33 hand-picked + 574 Wycheproof = 607 tests
make size         # the number
make bench        # 50-run min (use 20-run median for progress.csv)
make regen        # regenerate bytecode.inc from gen_bytecode.py
make check        # re-run range proof
```

Tests pass before size claims. 607/607 before commits.
