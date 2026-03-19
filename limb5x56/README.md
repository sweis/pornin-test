# limb5x56/ — 5×56 signed-limb Montgomery track

Fork of limb5x54 with W=56. Same K=5, same 40 B slots, same 128-bit
accumulator — but **byte-aligned** decode (7 bytes/limb exactly) and
a cleaner signed cP.

## Status

**1113 B / 3.05M cyc.** 607/607. 28 B under limb5x54's working 1141 B.

Structural savings vs W=54:
- fe_from_le: 7-byte stride (no shrd) — 25 B vs 38 B (−13)
- cP limb 4 = 0xFFFFFFFF (dec dword [rdi-8]); limbs 1,3 are inc byte (−3)

Plus ports of limb5x54 tricks with a fixed packed-bit pt_mul counter
(their source has a broken `cmp bl, W` version — see fc89ce3 commit).

## Files

- `CONVERSION.md` — W=54→56 derivation. Constants, offsets, decode.
- `tv_ecdsa.S` — main source.
- `fe_mul.S` + `test_mul.c` + `gen_vectors.py` — fe_mul5 unit test.
- `progress.csv` — trajectory.

## Workflow

```
make check        # verify 5×54 converges (range_proof.py)
make test-mul     # unit test fe_mul
make test         # full 607/607
make size         # the number
make bench20      # 20-run median
```

Tests pass before size claims.
