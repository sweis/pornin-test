# stupid/ — Bytecode-VM track

**766 B / ~141M cyc** (Thomas Stupid baseline). Previous size floor was
limb8 at 890 B — this is **124 B smaller** at ~27× the cycle cost.

## The insight

Every other track has a **native multiplication routine** (80–150 B of
`mul`/`adc` carry-propagation assembly). This one doesn't. Multiplication
is a **9-byte bytecode subroutine**:

```
microcode_mul:
    _ST _F0 ; _LD _ZERO       # save operand, zero accumulator
    _FOR                      # for i = 255 to 0:
    _ADD 0                    #   acc <- 2*acc (self-add = double)
    _SKIPBITZ _F1 ; _ADD _F0  #   if F1[i]: acc <- acc + F0
    _NEXT ; _RET
```

Russian-peasant multiplication. 256 iterations, each dispatched through
the interpreter. Roughly 500K multiplies total → ~140M cycles.

## Architecture

1-byte accumulator-based VM (vs our 2-byte three-address bytecode):
- 3-bit opcode + 5-bit value index → 32 value slots × 32 bytes each
- `LD/ST/ADD/SUB/MUL/SMOD/SKIPBITZ` = parameterized (8 × 32 encodings)
- `SKIPCS/SKIPCC/RET/FOR/NEXT/OK/FAIL/CALL` = extended (8 more via 2nd table)
- **CALL/RET with nested stack** — subroutines compose (check_scalar,
  invert_mod, check_point, point_add_to_W all bytecode)
- **FOR/NEXT/SKIPBITZ** — generic 256-iteration bit-scanning loop, used for
  BOTH scalar×point AND field multiplication (structural isomorphism)

Native primitives reduce to: `z256_add` (16 B), `z256_sub` (16 B),
`rep movsb` copy, `bt` bit-test, the dispatch loop. Modular reduction is
just "subtract modulus until carry" (op_add handler, ~2 iterations max).

## Byte breakdown (766 total)

| Section                          | ~bytes |
|----------------------------------|--------|
| decode_int                       | 15     |
| curve_constants (Gx,Gy,b,n,p)    | 160    |
| bytecode (verify + 4 subroutines)| ~175   |
| translation_table + microcode    | 17     |
| z256_add + z256_sub              | 32     |
| opcode handlers (16 ops)         | ~190   |
| interpreter macros + verify()    | ~175   |

## Grind targets

- **Bytecode density** — `_ADD 0` (self-add) appears 4× in point_add_to_W
  for ×3 sequences; `_SUB _M` reduction appears 5×. Subroutine them?
- **Handler sharing** — op_skipcs/op_skipcc differ by one jcc sense.
  op_ld/op_st differ by src/dst swap.
- **Speed variant** — replace microcode_mul with native schoolbook (adds
  ~80 B, saves ~130M cyc). `-DFAST_MUL` build for speed/size knee.
- **Our x86 tricks catalog** — port `xchg eax,r32`, `cqo`, `mov cl` audit,
  `inc byte ptr` from limb8/limb11.
