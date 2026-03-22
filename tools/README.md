# tools/ — Analysis scripts and one-off code

Scripts that support the size-golf work but aren't part of the build.
Run from project root (paths are relative to root, not tools/).

## Chart generation

**`plot_history.py`** — generates `docs/progress.png` from
`docs/progress.csv`. Run via `make chart` from root. Contains the
hardcoded TRAIL history (pre-CSV tiny.S/fast.S era) and per-track
styling. Edit xlim/ylim here when the frontier moves.

## Gadget hunting (bytecode)

Four iterations of the same search: scan our own bytecode/constants
for useful instruction sequences that appear by accident (frameshift
reads). Findings in `docs/GADGETS.md` — net result was one 1-B win
(`stosq;ret` tail merge) across all four runs.

**`gadget_hunt.py`** — v1, exhaustive byte-offset scan of bytecode
stream for valid opcode density.

**`gadget_hunt2.py`** — v2, adds constant-block scanning (cN zero-zone).

**`gadget_hunt3.py`** — v3, frameshift decoder (read bytecode at +1/+2
offset, check if resulting ops are semantically useful).

**`gadget_hunt4.py`** — v4, targeted search for `_SUB _M;_SKIPCS;_FAIL`
and other known-repeated sequences in constants.

## Gadget hunting (native x86)

**`native_gadgets.py`** — ROP-style tail-sharing search in compiled
`.text`. Finds ret-terminated suffixes that appear ≥2× within rel8
range. Output: `stosq;ret` (applied, −1 B), INV/fe_mul11 4-B tail
(conditional on reorder, not taken).

## LaTeX build

**`tectonic`** — self-contained TeX engine (37 MB binary, untracked)
for building `docs/tinyp256.pdf`. Not in git; re-download from
tectonic-typesetting.github.io if missing.

## Related (in other dirs)

- `common/gen_bytecode.py` — build-time: generates bytecode.inc for
  limb tracks from a Python RCB schedule
- `common/range_proof.py` — build-time: verifies limb-width overflow
  bounds for Montgomery tracks
