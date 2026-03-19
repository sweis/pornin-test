# Native x86 gadgets — tail sharing + offset-decoding

**One win found and applied.** Everything else negative.

Script: `docs/native_gadgets.py` (tempfile-based objdump harness).

---

## What this looks for (vs the bytecode interpreter)

**Different abstraction level.** The interpreter reuses *handlers*
(whole semantic ops). These searches look for byte-level coincidences
*below* that — either ROP-style offset decodes inside multi-byte
instructions, or exact suffix matches between ret-terminated blocks.
What's found is the residue after semantic sharing is exhausted.

---

## The one win: `stosq; ret` tail merge (limb11) — APPLIED

```
48 ab c3  @ .Lcp_shared tail (after `add rax,rdx`)
48 ab c3  @ fe_from_le tail  (after `lodsw`)
```

43 B apart → rel8. `.Lcp_shared`'s SF (from the final `add`) propagates
through `stosq;ret` unchanged — same bytes, same flags. fe_from_le's
callers don't check flags. **−1 B. Applied in commit 7c4ad0e** (source:
`.Lstret:` label, `jmp .Lstret` in fe_from_le).

---

## Conditional: INV/fe_mul11 4-B epilogue merge — not done

Both end `_ 58 5b c3` (pop _; pop rax; pop rbx; ret). INV's first pop
discards rdi; changing `pop rax`→`pop rcx` (both are caller-saved
discards) makes them byte-identical. **But 169 B apart** — needs handler
reorder to bring into rel8 range. One existing `jmp` already at disp
−127 (razor's edge); reorder risks rel8→rel32 blowout elsewhere.
**−2 B conditional on a reshuffle with ripple-effect risk. Not taken.**

---

## Everything else: negative

**Hidden `ret` bytes:** one per build. limb8 `49 83 c3 04` (add r11,4)
at 0x28f — bare `c3` at +3, no clean prefix. limb11 `41 0f af c3`
(imul eax,r11d) — `af c3` = `scasd;ret` (rdi+=4, no use: limbs are
qwords). **Offsets drift with builds; the instructions themselves are
stable.**

**REX-drop gadgets:** 32-bit form already aligned where useful. The
re-target cases (`4c 89 f7` → `89 f7` = mov rdi,r14 → mov edi,esi —
different source!) never match anything needed.

**Resynchronizing off-grid decodes:** 161/216 raw hits, ~0 useful.
Dominated by `add [rax],al` (call-disp zeros), `ret imm16` garbage,
single-iteration string-op downgrades.

**Why so little:** ~750–900 B of native code with ~14 ret-blocks isn't
enough tails for birthday collisions. The code is dense with 1–2 B
instructions (push/pop dominate) — offset-decoding is fruitful on
*large* host instructions (SSE, disp32), which we barely have. The one
real hit (`stosq;ret`) is the most common 3-B tail in a limb-storage
codebase.
