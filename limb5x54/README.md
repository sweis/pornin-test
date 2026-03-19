# limb5/ — 5×54 signed-limb Montgomery track

Thomas at **928 B / 4.48M cyc** with this architecture.
limb11 at 1244 B (estimated floor ~1067 B). Target: **< 928 B**.

## Why 5×54 when limb11 exists

See `ASSESSMENT.md`. Short version: 11×24 probably can't reach 928
(structural floor ~1067 B from Montgomery tax + 88-byte slot stride).
5×54 pays the SAME Montgomery tax but has 40-byte slots → 4 slots in
disp8. Thomas proved it's reachable. We don't know how.

## Status

**Not started.** Phase 1 (baseline) is the next step.

## Files

- `PLAN.md` — roadmap. Read first.
- `ASSESSMENT.md` — honest comparison of 11×24 vs 5×54 floors.
- `fe_mul.S` — 5×54 Montgomery multiply (start from `../limb11/fe_mul_5x54.S`).
- `progress.csv` — trajectory.
- `Makefile` — same targets as limb11.

## Workflow

```
make check        # verify 5×54 converges (range_proof.py)
make test-mul     # unit test fe_mul
make test         # full 607/607
make size         # the number
make bench20      # 20-run median
```

Tests pass before size claims.
