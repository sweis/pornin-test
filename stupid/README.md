# stupid/ — Bytecode-VM track

**618 B / ~2.4G cyc** (SMC floor). Thomas's baseline was 766 B / ~142M —
we're **148 B smaller** (19%). The limb8 native-mul floor is 890 B.

**NO_SMC+FAST_Z256 at 642 B / ~130M dominates Thomas's 766/142M on both
axes** — 124 B smaller AND 12M cyc faster. The qword z256 halves the
carry-chain length vs Thomas's dword variant.

Four build variants:
| Flags | Bytes | Cycles | Notes |
|---|---:|---:|---|
| (default) | 618 | 2.43G | SMC floor — boot-ROM without W^X only |
| `-DFAST_Z256` | 620 | 1.84G | dec;jnz in z256 loop |
| `-DNO_SMC` | 631 | 241M | practical — no pipeline stalls |
| `-DNO_SMC -DFAST_Z256` | 642 | 130M | **dominates Thomas 766/142M** |

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

## Techniques beyond Thomas's baseline (766 → 620, −146 B)

**Constant derivation** (−48 B):
- b computed as Gy²−Gx³+3Gx via bytecode (−21)
- p built via 1-bit shr/sbb loop — 11 of 12 dwords ∈ {−1,0} (−15)
- n's top 16 B fused into p-builder (−12)

**VM un-specialization** (−23 B):
- Slot 1 = modulus VALUE, not pointer; drops dispatch-loop cmp+cmove (−4)
- SMOD handler eliminated — `_MODN`/`_MODP` expand to LD;ST bytecode (−5)
- FAILCC opcode subsumes SKIPCS/CC+FAIL; ext table 8→5 (−6)
- OK/FAIL direct unwind+ret — no exit-flag machinery (−14, session 1)
*Actually several of these overlap; net is the accumulated −23.*

**Self-modifying code** (−13 B, +8.5× cycles):
- z256 add/sub merged; patch adc/sbb byte per call
- `.selfmod` section with awx flags; `#ifdef NO_SMC` keeps +13 B alternate

**Handler tail-sharing + micro** (−62 B across ~25 tricks):
- op_for/op_next xchg-swap; op_mul tail-jump docopy; decode_int via rdx
  so rsi survives; scale-2 index fuses advance into loop; Wy init from
  check_point leftover; etc. See progress.csv.

**call+pop layout** (−2 B):
- Both `lea rbx,[rip+disp32]` (7 B each) replaced with `call label; ...;
  label: pop rbx` (5+1 B). verify() moved to front; `call Ldecoder` jumps
  over decode_int/consts/bytecode; `call Lmain` jumps over handlers.

## Floor assessment

~613-615 B is the likely architectural minimum. Remaining disp32 site:
`lea rsp,[rbp+0x440]` (7 B) in op_ok/op_fail. RCB bytecode (83 B) at
theoretical minimum for acc-VM. 30 distinct slots referenced → can't
shrink to 4-bit operand encoding.
