# Bytecode Gadget Hunt

**TL;DR: No free wins.** No ≥4 B bytecode sequence appears verbatim in
constants or native code. No slot remap creates a ≥3-op match. The one
structurally clean frameshift gadget in each build is semantically
useless. The cN zero zone is unreachable (walled by `0xff` bytes).

Analysis scripts: `docs/gadget_hunt{,2,3,4}.py`. Rebuild `.o` files
with the commands at the top of this doc to regenerate.

---

## Step 1 — bytecode format

Both builds: 2 bytes/op, `lodsw` reads them, `test al,al; jz` terminates.

```
byte 0 (b0):  (s2 << 4) | opcode     — opcode in low nibble
byte 1 (b1):  (dst << 4) | s1        — all 256 values legal
END:          b0 == 0x00             — asserted in gen_bytecode.py
```

| | limb8 | limb11x24 |
|---|---|---|
| **opcodes** | 0–9 (10 ops) | 0–10 (11 ops) |
| **op 0** | Fmul | Fmul |
| **op 1** | SQR | Fadd |
| **op 2** | Fadd | Fsub |
| **op 3** | Fsub | Nmul |
| **valid b0** | 159/256 (62%) | 175/256 (68%) |
| **E[random run]** | ~2.6 ops | ~3.2 ops |

**Consequence**: random bytes are valid ops ~⅔ of the time. Long valid
runs (8–16 ops) in native code are statistically EXPECTED, not
meaningful. The question is whether any such run is *useful*.

---

## Step 2 — byte sources enumerated

```
cd limb8      && cc -c -DSMALL_MUL8 tv_ecdsa.S -o /tmp/limb8.o
cd limb11x24  && cc -c tv_ecdsa.S -o /tmp/limb11.o
objcopy -O binary -j .text /tmp/limb8.o /tmp/limb8_text.bin        # 891 B
objcopy -O binary -j .text /tmp/limb11.o /tmp/limb11_text.bin      # 755 B
objcopy -O binary -j .rodata /tmp/limb11.o /tmp/limb11_rodata.bin  # 319 B
```

### limb8 (all in .text, 891 B)

| region | offset | bytes | notes |
|---|---|---|---|
| bc_rcb | 0x000 | 87 | 43 ops + END |
| bc_v3  | 0x057 | 15 | 7 ops + END |
| bc_v1  | 0x066 | 59 | 29 ops + END |
| native.pre | 0x0a1 | 171 | fe_from_be, pt_mul, bcrun |
| .Ljt | 0x14c | 10 | handler offsets |
| cGX | 0x156 | 32 | math constant |
| cGY | 0x176 | 32 | math constant |
| cN  | 0x196 | 32 | math constant (stores n, not n−2) |
| native.post | 0x1b6 | 453 | handlers, fe_mul_m, verify |

### limb11x24 (.rodata 319 B + .text 755 B)

| region | offset | bytes | notes |
|---|---|---|---|
| bc_rcb | .rodata+0x000 | 87 | 43 ops + END |
| bc_v3  | .rodata+0x057 | 23 | 11 ops + END |
| bc_v1  | .rodata+0x06e | 81 | 40 ops + END |
| cN   | .rodata+0x0bf | 32 | stores n−2 (low byte `4f` not `51`) |
| cR2N | .rodata+0x0df | 32 | R² mod n |
| cGX  | .rodata+0x0ff | 32 | Gx in Montgomery form |
| cGY  | .rodata+0x11f | 32 | Gy in Montgomery form |
| .Ljt | .text+0x000 | 11 | handler offsets |
| native | .text+0x00b | 744 | everything else |

**Valid-op density per region** (2-byte windows with low-nibble ∈ op range):

| region | limb8 | limb11 |
|---|---|---|
| cGX | 84% | 81% |
| cGY | 45% | 74% |
| cN  | 32% | 35% |
| cR2N | — | 68% |
| jt  | 44% | 80% |
| native | 63–65% | 62% |

cN is low because its high half is `ff ff ff ff ff ff ff ff 00 00 00 00
ff ff ff ff` — `0xff` has opcode nibble 15 (invalid both builds) and
`0x00` is END. **16 of cN's 32 bytes are structurally invalid as b0.**

---

## Step 3 — longest runs of valid ops

Top runs found in each build's non-bytecode regions:

### limb8

**13 ops @ .text+0x24a** (fe_mul_m prologue, `push rcx` stack alloc):
```
79 e0 59 5b c3 53 55 49 89 d1 49 89 f2 51 57 31 c9 51 51 51 51 51 51 51 51
INV(14,0,7); INV(5,11,5); Fsub(5,3,12); CHKLT(4,9,5); INV(13,1,8);
INV(8,9,4); Fadd(5,1,15); CHKNZ(3,1,5); INV(5,1,12);
SQR(5,1,5); SQR(5,1,5); SQR(5,1,5); SQR(5,1,5)
```

The `51 51 51 51 ...` tail is **9× `push rcx`** (stack-allocating the
72-byte product buffer). `51 51` → SQR(5,1,5) = `slot5 = slot1²`.
**Not a repeated square** — it re-squares slot1 into slot5 every time
(idempotent after first). Useless as-is.

**8 ops @ cGX+15** (`77 f2 40 a4 63 e5 e6 bc f8 47 42 2c e1 f2 d1 17`):
Pure entropy. No terminator — the run just happens to go 16 bytes
before hitting an invalid low nibble.

### limb11x24

**16 ops @ .rodata+0x0fb** (tail of cR2N spilling into cGX):
```
ba 5a 95 2d 18 3c 14 a9 18 d4 30 e7 79 01 b6 ed 47 fc 95 ba 75 10 25 62 77 2b 73 fb 61 c6 55 37
COPYHI(5,10,11); CHKZ(2,13,9); SET1(3,12,1); CHKLT(10,9,1);
SET1(13,4,1); Fmul(14,7,3); COPY(0,1,7); INV(14,13,11);
NORM(15,12,4); CHKZ(11,10,9); CHKZ(1,0,7); CHKZ(6,2,2);
NORM(2,11,7); Nmul(15,11,7); Fadd(12,6,6); CHKZ(3,7,5)
```

cGX in limb11 is Gx in Montgomery form (tiny.S's cGX is plain Gx, very
different bytes). The limb11 Montgomery representation happens to have
an enormous run of bytes with low nibble ≤ 0xa. **Entirely coincidental,
entirely useless** — five CHKZ ops with random slot arguments would
trash `bpl` irretrievably.

**16 ops @ .text+0x26a** (the param-validation `cmp`/`jne` chain in verify):
```
75 19 48 8d 72 01 48 83 f9 41 75 0f 49 83 e9 20 49 83 f9 20 77 05 80 3a 04 74 07 c9 41 5f 41 5e
```
The `48 83` REX.W prefix + immediate-group opcode is everywhere in
x86-64 (SET1/COPY with s2=4, dst=8,s1=3). Not useful.

**All long native runs are statistical noise** given ~68% b0 validity.

---

## Step 4 — verbatim subsequence matches (THE NEGATIVE RESULT)

Searched every substring of every bytecode stream against every byte of
`.text` and `.rodata`, length ≥ 4 bytes.

### limb8

**Zero matches** between bytecode and constants/native code.

**Zero matches** between different bytecode streams (bc_v1, bc_v3, bc_rcb).

Only hits: trivial self-overlaps inside bc_v1's triple-Fsub:
```
bc_v1[13..18] = aa 23 aa 23 aa  (overlaps itself +2)
bc_v1[28..32] = 03 bb 03 bb     (overlaps itself +2)
```
These are the `slot10 -= Gx` ×3 and `slot11 -= Qx` ×3 patterns. Already
maximally compressed — can't win by calling a 2-byte sequence.

### limb11x24

**Zero matches** between bytecode and constants.

**Two single-op matches** in native code:
- `b0 00` (Fmul(0,0,11), bc_rcb op 38) @ .text+0x0df — inside `enter 0xb0,0` encoding
- `02 00` (Fsub(0,0,0),  bc_v1 op 37)  @ .text+0x182 — inside `call rel32` displacement

Both are 2-byte single ops followed by garbage; neither has a clean
terminator nearby.

**Zero ≥4-byte cross-stream matches.** bc_rcb has no aligned self-repeats
either — the one repeated op `Fadd(0,2,0)` appears at op indices 9 and
21, twelve ops apart.

---

## Step 4b — slot-remap near-misses

Brute-forced: for every (bytecode window, constant window, length ≥ 3 ops),
check whether a **consistent slot bijection** σ exists such that remapping
the bytecode's slot nibbles gives the constant's bytes. (Opcodes must match
verbatim — they can't be remapped.)

**Result: zero consistent remaps ≥ 3 ops, both builds.**

Only one opcode-sequence match even gets to the consistency check:
```
limb8/cGX[4]: opcodes [CHKLT,SQR,Fmul] match bc_v1[op4..7]
  → slot conflict at op 1 (cGX forces two bc-slots to the same target)
```

Why this is so sparse: a 3-op remap needs all 3 b0 low-nibbles to match
AND the 9 slot-nibble constraints (3 per op) to form a consistent
bijection. At ~68% opcode validity, P(3 opcodes match a random triple)
≈ (1/11)³ ≈ 0.08%. Then slot consistency knocks out most survivors.
The 32 bytes of each constant give 30 windows × 3 streams × ~40 bc
positions ≈ 3600 attempts per constant — you'd expect ~3 opcode
matches, and zero of those to pass consistency. That's what we got.

---

## Step 5 — frameshift gadgets (ODD-offset reads)

A **frameshifted** read starts at an odd byte offset relative to the
stream's aligned base. Each "op" is then `(b1 of op[k]) || (b0 of op[k+1])`.

### The parity insight

Stream lengths are all **odd** (2N ops + 1 END byte):
- bc_rcb: 87 B → starts at absolute offset 0 (even parity)
- bc_v3:  23 B → starts at absolute offset 87 (odd parity, limb11)
- bc_v1:  81 B → starts at absolute offset 110 (even parity)

So a frameshifted read in bc_rcb (odd absolute offset) that falls past
bc_rcb's END **lands on bc_v3's aligned grid**. The END byte gets
consumed as a b1 in the last frameshifted op, and the next b0 is
bc_v3[0]. Same for bc_v3 → bc_v1.

### bc_rcb's internal `00` bytes as frameshift terminators

bc_rcb b0 bytes are all nonzero by construction (asserted in
`gen_bytecode.py`). But **b1 bytes** (odd positions) CAN be `0x00` —
specifically when `dst=0` AND `s1=0`. Three such bytes exist in both
builds' bc_rcb, at byte offsets **31, 77, 79**:

| byte | bc_rcb op | encodes |
|---|---|---|
| 31 | op 15: `10 00` | Fmul(0,0,1) — dst=0, s1=0 |
| 77 | op 38: `b0 00` | Fmul(0,0,11) — dst=0, s1=0 |
| 79 | op 39: `43`/`42 00` | Fsub(0,0,4) — dst=0, s1=0 |

A frameshifted run that hits one of these as its next-b0 terminates
cleanly. Back-tracing from each:

**limb8 @ byte 71 → 77 (the one clean gadget):**
```
93 20 10 12 19 b0 00
Fsub(2,0,9); Fmul(1,2,1); INV(11,0,1); END
```
Formed from: b1(op35)+b0(op36), b1(op36)+b0(op37), b1(op37)+b0(op38),
b1(op38)=END.

Not useful: the final INV(11,0,1) runs a full Fermat inversion (~256
Nmul calls) as garbage. Even if the first two ops were useful, the
~1M-cycle INV would be disqualifying.

**limb11: same position FAILS.** Byte 75 in limb11 is `0x1c` (not
`0x19` as in limb8) — the `gen_bytecode.py` slot remap 9→12 changes
bc_rcb op 37 from `Fadd(1,9,1)` (b1=`0x19`) to `Fadd(1,12,1)`
(b1=`0x1c`). `0x1c` as b0 has opcode nibble 12 → invalid. **The remap
that freed slot 9 for cN inadvertently broke this gadget.** Reverting
would require moving cN to a different slot.

**Bytes 31 and 79**: both blocked by an adjacent invalid b0 (`0xff` or
`0xdd`, opcode nibble ≥ 13). No valid ops reach them.

### The bc_v1 frameshift (limb11 only)

```
limb11 .rodata+0x0b7:  f0 02 00
Fmul(0,2,15); END
```

This is b1 of `COPYHI(15,0,0)` + b0 of `Fsub(0,0,0)`, with Fsub's
b1=`0x00` as the terminator. Fmul(0,2,15) computes `slot0 = slot2 · slot15`
— a Montgomery level-shift by the "1" in slot 15.

**Near-miss with bc_v3**: bc_v3's first op is `Fmul(5,0,15)` (X·1 for
level alignment). Same operation, different source/dest. No remap helps
— bc_v3 reads X from slot 0, and RCB hardwires X to slot 0. Would need
RCB reschedule to write X to slot 2.

### The boundary-prefix gadgets

Dispatching to the last byte of a stream executes one frameshifted op
(last-b1 + END-as-b1) then **falls into the next stream's aligned ops.**

| build | dispatch to | gadget | then runs |
|---|---|---|---|
| limb8  | .text+0x055 | Nmul(0,0,2)  | all of bc_v3 |
| limb8  | .text+0x064 | Fmul(0,0,3)  | all of bc_v1 |
| limb11 | .rodata+0x055 | CHKLT(0,0,2) | all of bc_v3 |
| limb11 | .rodata+0x06c | Fsub(0,0,1) | all of bc_v1 |

**All destroy slot 0 before the next stream reads it.** limb11's
`CHKLT(0,0,2)+bc_v3` trashes slot 0 (CHKLT's Fsub-scratch) AND sets a
spurious fail bit (X ≥ Z is meaningless). bc_v3's first op reads slot 0.

limb8's `Fmul(0,0,3)+bc_v1` turns slot 0 into garbage; bc_v1's first
op is `CHKZ(0,...)` which would then trigger. Dead.

**Could reordering bc_v3 make the prefix harmless?** bc_v3 reads slot 0
exactly once (first op). Move that op later? Doesn't help — CHKLT's
spurious fail bit still poisons `bpl`. The only escape is if the prefix
op is a genuine no-op in context (e.g. `Fsub(x,x,x)` = 0, but that
needs s1==s2 which `24 00` doesn't give).

---

## Step 6 — the cN zero zone (DEAD END)

Both builds' cN has this high-half structure (P-256 order):
```
  bytes 16-23:  ff ff ff ff ff ff ff ff
  bytes 24-27:  00 00 00 00              ← free END terminators!
  bytes 28-31:  ff ff ff ff
```

**Unreachable.** Any stream that wants its END at cN[24] must have its
final op at cN[22..23] = `ff ff`. `0xff` as b0 → opcode nibble 15 →
invalid in both builds. The `0xff` wall is 8 bytes thick.

If the opcode space were extended to 16 handlers (0–15), `0xff` would
decode as `op15(s2=15)` and the wall would disappear. But that's a
different architecture.

cN[24] as an END saves 1 byte. Even were it reachable, the layout
gymnastics (stream would need to physically overlap cN) would cost more
than that.

---

## Step 7 — jump table as ops

Jump table bytes are **build-dependent** handler offsets. Current values:

**limb8 .Ljt** (`9e 9e a0 ad 99 6a 7e 7e 92 d6`): 3/9 windows valid,
longest run 1 op. `9e` has opcode nibble 14 → invalid (ops 0 and 1 land
past `.Ljt+157`).

**limb11 .Ljt** (`d3 2a 26 da 5b 46 6c 9a 1a 13 0b`): 8/10 windows
valid, but no clean terminator (next byte after jt is `0x48`, a `REX.W`).

The jt is volatile — any handler reorder changes these bytes. Building
bytecode to depend on jt contents would be *extremely* fragile. Not
worth pursuing.

---

## Summary of near-misses

| what | where | miss by | fixable? |
|---|---|---|---|
| 3-op frameshift+END in bc_rcb | limb8 @ byte 71 | Contains INV (10⁶ cycle garbage) | No — INV position is structural |
| Same gadget in limb11 | limb11 @ byte 71 | 9→12 remap broke opcode | cN would have to move; large |
| Fmul(_,_,15) 1-op gadget in bc_v1 | limb11 @ 0x0b7 | Wrong src/dst for bc_v3's use | RCB would have to write X to slot 2 |
| CHKLT+bc_v3 boundary | limb11 @ 0x055 | Trashes slot 0 + spurious fail bit | Can't make CHKLT a no-op |
| cN[24] as shared END | Both | 8-byte `0xff` wall | opcode space to 16; out of scope |
| cGX[4] 3-opcode match | limb8 | Slot bijection fails at op 1 | — (constant is math) |

---

## What WOULD work (hypotheticals, not actionable here)

1. **If bc_rcb had a dst=0,s1=0 op earlier** (before op 15), a longer
   frameshift run could reach byte 31 as END. The RCB schedule is from
   EFD and is op-count-optimal; any dst-remap that puts more `00` b1
   bytes in would trade slot lifetimes for gadget availability.
   Probably net-negative.

2. **If the opcode count were ≤ 8** (opcodes 0–7), every low nibble
   `8–f` would be invalid. That would *reduce* gadget density, not
   increase it. Going to **16 ops** (opcodes 0–15) makes *every* b0
   valid, turning all of cN/cGX into gadget streams. But that's a
   fundamental architecture change (and probably a large binary for
   other reasons).

3. **A bytecode CALL op** (2 B: offset into some stream) would let
   bc_v1/bc_v3 share common tails — but they have none. bc_rcb has one
   repeated op, 12 ops apart. Handler cost ~10 B, saves nothing.

4. **Placing bc_v1 to overlap cN from the OTHER end**: put bc_v1's
   START at cN[24], so bc_v1 begins with cN[24..27] = `00 00 00 00`.
   But `00` as b0 is END — bc_v1 would terminate immediately. Dead.

---

## Methodology notes

- Scripts extract raw section bytes via `objcopy -O binary`, then do
  byte-level substring search + op-decode in Python.
- **Reproduce**: `python3 docs/gadget_hunt.py` (needs `/tmp/*.bin` from
  the objcopy commands above).
- The `find_substring` dedup keeps only maximal matches per position pair.
- The remap consistency check builds a bijection incrementally; fails
  fast on the first contradiction.
- Frameshift clean-END detection walks backward from each `0x00` b1
  byte, accumulating valid ops until hitting an invalid b0.
