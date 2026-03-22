# Gadget Searches — Bytecode + Native x86

**Summary: one −1 B win applied (stosq;ret tail merge, limb11).
Everything else negative.** Scripts preserved for re-runs after major
restructuring.

Scripts: `tools/gadget_hunt{,2,3,4}.py` (bytecode), `tools/native_gadgets.py`
(x86). See `tools/README.md`. Regenerate `.bin` with `objcopy -O binary
-j .text` on `.o` files.

---

## Bytecode gadgets (constants / instruction encodings)

Looks for valid bytecode sequences accidentally embedded in constant
data or native code — would let us point the interpreter there and
save bytes.

### The density problem

Bytecode format: 2 bytes/op, `(s2<<4)|opcode` then `(dst<<4)|s1`. END
is b0==0x00. With 10–11 valid opcodes, **random bytes decode valid
62–68% of the time**:

| | limb8 | limb11 |
|---|---|---|
| opcodes | 0–9 | 0–10 |
| valid b0 | 159/256 (62%) | 175/256 (68%) |
| E[random run] | ~2.6 ops | ~3.2 ops |

So 8–16 "valid op" runs in native code are statistical noise. The
16-op run at limb11 cR2N→cGX is pure entropy — five CHKZ ops with
random slot args would trash `bpl`.

**Verbatim search:** zero ≥4-B matches between bytecode and
constants/native code, both builds. Slot-remap brute force: zero
consistent bijections at ≥3 ops. (~(1/11)³ per triple × 3600 windows
≈ 3 expected opcode matches, 0 pass slot consistency.)

### Frameshift — the interesting part

Stream lengths are **odd** (2N+1 bytes). Frameshifted read at bc_rcb
odd offset → falls through bc_rcb's END → lands on bc_v3's aligned
grid. **bc_rcb b1 bytes can be 0x00** (dst=0 ∧ s1=0) → internal
frameshift terminators at byte offsets 31, 77, 79.

**The one gadget (limb8 byte 71→77):**
```
93 20 10 12 19 b0 00  →  Fsub(2,0,9); Fmul(1,2,1); INV(11,0,1); END
```
Verified byte-exact. Useless: final INV runs full ~256 Nmul Fermat
inversion as garbage (~1M cycles).

**limb11: same position fails.** Byte 75 = 0x1c (opcode nibble 12,
invalid) — the 9→12 slot remap in `gen_bytecode.py` broke it.

### cN zero zone — unreachable

P-256 order high half: `ff×8 00×4 ff×4`. Bytes 24–27 are free END
terminators, **but walled by 8 bytes of 0xff** (opcode nibble 15 →
invalid both builds). 16-opcode interpreter would break the wall —
different architecture.

---

## Native x86 gadgets (tail-sharing / ROP-style)

**Different abstraction level** than the bytecode interpreter. Looks
for byte-level coincidences — ROP-style offset decodes inside multi-
byte instructions, or exact suffix matches between ret-terminated
blocks. What's found is the residue after semantic sharing exhausted.

### The one win: stosq;ret tail merge (limb11) — APPLIED

```
48 ab c3  @ .Lcp_shared tail (after add rax,rdx)
48 ab c3  @ fe_from_le tail  (after lodsw)
```
43 B apart → rel8. SF propagates through stosq;ret unchanged.
fe_from_le callers don't check flags. **−1 B. Commit 7c4ad0e.**

### Conditional: INV/fe_mul11 4-B epilogue merge — not done

Both end `_ 58 5b c3` (pop _; pop rax; pop rbx; ret). Making INV's
pop rax→pop rcx (both caller-saved discards) makes byte-identical.
**But 169 B apart** — needs handler reorder. One existing jmp at
disp −127 (razor's edge); reorder risks rel8→rel32 blowout.
**−2 B conditional on reshuffle with ripple risk. Not taken.**

### Everything else: negative

**Hidden ret bytes:** one per build. limb8 `49 83 c3 04` (add r11,4)
— bare c3 at +3, no clean prefix. limb11 `41 0f af c3` (imul
eax,r11d) — `af c3` = scasd;ret (rdi+=4, useless for qword limbs).

**REX-drop gadgets:** 32-bit form already aligned where useful. The
re-target cases (`4c 89 f7`→`89 f7` = mov rdi,r14→mov edi,esi —
different source) never match anything needed.

**Resynchronizing off-grid decodes:** 161/216 raw hits, ~0 useful.
Dominated by `add [rax],al` (call-disp zeros), ret imm16 garbage.

### Why so little

~750–900 B with ~14 ret-blocks isn't enough tails for birthday
collisions. Code is dense with 1–2 B instructions (push/pop dominate)
— offset-decoding is fruitful on LARGE host instructions (SSE,
disp32), which we barely have. The one real hit (stosq;ret) is the
most common 3-B tail in a limb-storage codebase.

---

## Near-miss summary

| | Miss by | Fixable? |
|---|---|---|
| limb8 3-op frameshift | contains 10⁶-cycle INV | no (structural) |
| limb11 same position | 9→12 remap broke opcode at 75 | cN move; large |
| cN[24] shared END | 8-byte 0xff wall | 16-op interpreter; out of scope |
| INV/fe_mul11 4-B merge | 169 B gap, rel8 ripple risk | reorder; conditional |
