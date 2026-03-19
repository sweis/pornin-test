# Bytecode Gadget Hunt — Negative Result

**No free wins.** No ≥4 B bytecode sequence appears verbatim in
constants or native code. No slot remap creates a ≥3-op match. The one
structurally clean frameshift gadget is semantically useless. cN zero
zone walled by `0xff`.

Scripts: `docs/gadget_hunt{,2,3,4}.py`. Regenerate `.bin` files with
`objcopy -O binary -j .text/.rodata` on the `.o` files.

---

## The density problem

Bytecode format: 2 bytes/op, `(s2<<4)|opcode` then `(dst<<4)|s1`. END
is b0==0x00. With 10–11 valid opcodes, **random bytes decode as valid
ops 62–68% of the time**:

| | limb8 | limb11 |
|---|---|---|
| opcodes | 0–9 | 0–10 |
| valid b0 | 159/256 (62%) | 175/256 (68%) |
| E[random run] | ~2.6 ops | ~3.2 ops |

So 8–16 "valid op" runs in native code are statistical noise, not
signal. The 16-op run at limb11 cR2N→cGX (Montgomery-form constants
happen to have low nibbles ≤ 0xa) is pure entropy — five CHKZ ops
with random slot args would trash `bpl`.

**Verbatim search:** zero ≥4-B matches between bytecode and
constants/native code, both builds. Slot-remap brute force: zero
consistent bijections at ≥3 ops. At ~(1/11)³ per opcode triple ×
3600 windows per constant ≈ 3 expected opcode matches, 0 pass slot
consistency — exactly what we got.

---

## Frameshift — the interesting part

Stream lengths are **odd** (2N+1 bytes). Frameshifted read at bc_rcb
odd offset → falls through bc_rcb's END → lands on bc_v3's aligned
grid (END consumed as the last frameshifted op's b1).

**bc_rcb b1 bytes can be `0x00`** (when dst=0 ∧ s1=0) → internal
frameshift terminators. Three exist, byte offsets **31, 77, 79**:

| byte | op | |
|---|---|---|
| 31 | Fmul(0,0,1) `10 00` | blocked by adjacent `0xff` |
| 77 | Fmul(0,0,11) `b0 00` | **one clean 3-op gadget (limb8 only)** |
| 79 | Fsub(0,0,4) `42 00` | blocked by `0xdd` |

**The one gadget (limb8 byte 71→77):**
```
93 20 10 12 19 b0 00  →  Fsub(2,0,9); Fmul(1,2,1); INV(11,0,1); END
```
Verified byte-exact against current build. Useless: the final INV runs
a full ~256 Nmul Fermat inversion as garbage (~1M cycles).

**limb11: same position fails.** Byte 75 is `0x1c` (opcode nibble 12,
invalid) — the `gen_bytecode.py` 9→12 slot remap changed bc_rcb op 37
from `Fadd(1,9,1)` to `Fadd(1,12,1)`. Reverting would require moving
cN to a different slot.

**Boundary-prefix gadgets** (dispatch to last byte of stream N → one
frameshifted op → fall into stream N+1 aligned): all destroy slot 0
before the next stream reads it. limb11's `CHKLT(0,0,2)+bc_v3` also
sets a spurious fail bit. Dead.

---

## cN zero zone — unreachable

P-256 order high half: `ff×8 00×4 ff×4`. Bytes 24–27 are free END
terminators, **but walled by 8 bytes of `0xff`** (opcode nibble 15 →
invalid both builds). A 16-opcode interpreter would break the wall but
is a different architecture.

---

## Near-miss summary

| | Miss by | Fixable? |
|---|---|---|
| limb8 3-op frameshift | contains 10⁶-cycle INV | no (INV structural) |
| limb11 same | 9→12 remap broke opcode at 75 | cN move; large |
| bc_v1 Fmul(_,_,15) 1-op | wrong src/dst for bc_v3 | RCB would need X@slot2 |
| cN[24] shared END | 8-byte `0xff` wall | 16-op interpreter; out of scope |
