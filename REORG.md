# Directory reorganization plan

## Goal

Each implementation approach in its own `limbN/` subdirectory. Shared
test/bench infrastructure extracted. Main directory clean.

## Current state

```
pornin-test/
  tv_ecdsa_tiny.S      # 8×32 q=t[top] — 933 B size corner (was)
  tv_ecdsa_fast.S      # 64-bit Montgomery CIOS + mulx — speed track
  tv_ecdsa_fast2.S     # BMI2+ADX + lazy-carry Solinas — beats fast.S
  tv_ecdsa_speed.S     # MOVBE-only direct-dispatch
  tv_ecdsa_bc.S        # portable bytecode baseline
  tv_ecdsa_amd64.S     # original hand-asm
  tv_ecdsa_sign_zmm.S  # AVX-512 signer (separate project)
  tv_ecdsa.c           # C reference
  tv_ecdsa_small.c     # C golfed
  bench.c, test_*.c, *.h  # shared test/bench infra
  Makefile             # builds all of the above
  limb11/              # 11×24 Montgomery — 1194 B
  limb5/               # 5×54 Montgomery — 1324 B baseline
  docs/
```

## Proposed structure

```
pornin-test/
  common/                    # shared across all tracks
    bench.c
    test_ecdsa.c
    test_ecdsa_asm.c         # #include "../test_ecdsa.c" wrapper
    test_wycheproof.c
    test_wycheproof_asm.c
    wycheproof_vectors.h
    tv_ecdsa.h
    track.mk                 # Makefile fragment: test/bench/size targets

  limb8/                     # tiny.S — 8×32 q=t[top], the ONLY non-Montgomery
    tv_ecdsa.S               # renamed from tv_ecdsa_tiny.S
    Makefile                 # includes ../common/track.mk
    progress.csv             # backfill from git history or docs/plot_history TRAIL
    README.md

  limb11/                    # unchanged except PARENT=.. → COMMON=../common
  limb5/                     # unchanged except PARENT=.. → COMMON=../common

  speed/                     # fast.S, fast2.S, speed.S — different goal (cycles, not bytes)
    tv_ecdsa_fast.S
    tv_ecdsa_fast2.S
    tv_ecdsa_speed.S
    Makefile
    README.md

  reference/                 # C implementations + bc.S baseline
    tv_ecdsa.c
    tv_ecdsa_small.c
    tv_ecdsa_bc.S
    tv_ecdsa_amd64.S

  signer/                    # AVX-512 sign (separate concern)
    tv_ecdsa_sign_zmm.S
    sign_zmm.c
    sign_vectors.h

  docs/
  CLAUDE.md
  README.md
  BENCHMARK.md
  Makefile                   # top-level: make -C limb8 test, etc.
```

## Shared Makefile fragment (`common/track.mk`)

Each `limbN/Makefile` would be ~5 lines:

```make
COMMON = ../common
TRACK  = limb11
include $(COMMON)/track.mk
```

`track.mk` provides: `test`, `test-full`, `size`, `bench`, `bench20`,
`clean`. Assumes `tv_ecdsa.S` → `tv_ecdsa.o` → link with common test
harnesses. Per-track extras (`test-mul`, `regen`, `check`) stay in
the track's own Makefile.

## Shared tools

Already reusable across tracks:
- `bench.c` — takes `tv_ecdsa_p256_verify_asm` extern, no limb-specific code
- `test_ecdsa_asm.c`, `test_wycheproof_asm.c` — same
- limb11's `range_proof.py` — parameterized by `Cfg(K, W, acc_bits)`, works for any limb config. limb5 already `sys.path.insert(0,'../limb11')` to use it. Move to `common/`.

Track-specific (stays put):
- `gen_bytecode.py` — SLOT math and op numbers differ. limb5 forked limb11's.
- `fe_mul.S` standalone + `test_mul.c` + `vectors_mul.h` — limb-width-specific.

## What breaks

- All `limbN/Makefile` PARENT=.. paths → COMMON=../common
- Top-level `Makefile` targets (test-tiny, bench-tiny, etc.)
- `docs/plot_history.py` reads `limb{11,5}/progress.csv` — still works if those stay
- Any CI/scripts referencing `tv_ecdsa_tiny.S` by name

## Migration order (if/when)

1. `mkdir common/` + move shared files. `git mv` preserves history.
2. Write `common/track.mk`. Test with limb11 (most mature).
3. `mkdir limb8/`. `git mv tv_ecdsa_tiny.S limb8/tv_ecdsa.S`. Write Makefile + README. Backfill progress.csv from TRAIL data in plot_history.py (the 933 B journey is all there).
4. Update limb5, limb11 Makefiles.
5. `mkdir speed/ reference/ signer/`. Move remaining .S/.c.
6. New top-level Makefile: `for d in limb*; do make -C $d test; done`.
7. Update README.md, CLAUDE.md paths.

## Recommendation

**Do this BETWEEN grind sessions, not during.** Path breakage mid-grind
wastes cycles. The current `PARENT=..` works fine; limb11 and limb5 are
already isolated. tiny.S isn't being actively developed. The reorg is
cleanliness, not blocking anything.

When ready: step 3 (limb8/) alone gets 80% of the benefit — tiny.S's
933 B trajectory becomes a sibling track with its own progress.csv,
plottable the same way. Steps 1-2 and 4-7 are polish.
