# Native x86 gadgets — offset-decoding + tail sharing

**TL;DR:** Search 1 finds nothing actionable. Search 2 finds **one real −1 B**
in limb11 (`stosq;ret` tail merge, rel8 in range) and **one conditional −2 B**
(INV/fe_mul11 epilogue merge — requires handler reorder).

Analysis script: `/tmp/native_gadgets.py` (tempfile-based objdump harness;
capstone unavailable).

---

## Direct answer: is this just what the bytecode interpreter does?

**No — different abstraction level.** The interpreter reuses *handlers*
(Fmul, Fadd, INV — whole semantic operations). These searches look for
reusable *x86 instruction sequences* below that.

Concrete distinction: the interpreter makes INV call `fe_mul11` 510 times
(handler-level reuse). It cannot know that INV's *epilogue* shares 3 bytes
with fe_mul11's epilogue (instruction-level reuse). And it certainly can't
jump to byte 3 of `imul eax,r11d` to get a free `ret` — that's pure
x86-encoding-level ROP.

The two mechanisms are complementary:
- **Interpreter** = semantic tail-calling (already heavily exploited: `.Lfmul`
  falls into `fe_mul11`, `.Laddm`→`.Lasmod`→`.Lcprop` chain, etc.)
- **Search 1** = ROP-style offset decoding (below any abstraction)
- **Search 2** = syntactic byte-level suffix matching (between handlers)

What Search 2 finds is the *leftover* after semantic sharing is exhausted —
accidental byte-level coincidences.

---

## Search 1: Offset-decoding (x86 ROP-style)

### Methodology

For each multi-byte instruction in the native region, decode at every
offset ≥1 via `objdump -D -b binary -m i386:x86-64`. Three categories:

- **A.** `0xc3` (ret) appears as a non-first byte of some instruction
- **B.** Offset-decode matches an instruction we already use (aligned)
- **C.** Offset-decode *resynchronizes* with the aligned stream after
  1+ ops (lands on a later instruction boundary)

### Category A — hidden `ret` bytes

**Exactly one per build.** Neither usable.

| build | addr | host instruction | bytes | gadget |
|---|---|---|---|---|
| limb8 | 0x28f+2 | `add r11,0x4` | `49 83 c3 04` | `c3` = ret alone |
| limb11 | 0x108+2 | `imul eax,r11d` | `41 0f af c3` | `af c3` = scasd; ret |

**limb8:** `c3` at 0x291. Backward-scan from 0x285 finds no clean multi-op
sequence ending here. At +1 (`83 c3 04`) = `add ebx,4`; next aligned byte
is `75 d3` = `jne` (conditional, not a terminator). Just a bare `ret` — we
already have 6 aligned.

**limb11:** `c3` at 0x10b. At +2 = `af c3` = **`scasd; ret`**, a clean 2-op
gadget. `scasd` compares eax to `[rdi]`, advances rdi by 4, sets flags.
We use `scasq` (rdi+=8, `48 af`) as a pure pointer increment in `.Lcnt` and
`.Lasmod`. A 4-byte advance has no use case — limbs are 8-byte qwords.
At +1 = `0f af c3` = `imul eax,ebx`, which resyncs at the aligned
`and eax,MASK` — see Category C below.

### Category B — offset-decode matching an aligned instruction

Almost everything here is single-byte opcodes hidden inside larger
instructions. A `pop rax` (`58`) hidden inside `push 0x58` buys nothing —
`pop rax` is already aligned 5×.

**The user's own example is present but trivially inert:**

```
limb11 @0x11e: 48 8b 07 = mov rax,[rdi]   (aligned)
        @0x11f:    8b 07 = mov eax,[rdi]   (hidden — user's example)
limb11 @0x106:    8b 07 = mov eax,[rdi]   (aligned — ALREADY HAVE IT)
```

We need both forms, and we *have* both forms aligned. The hidden copy
at 0x11f gains nothing.

**REX-drop catalog** (REX prefix at byte 0 — dropping it gives the 32-bit
form, or re-targets from r8-r15 to the legacy register):

| | limb8 | limb11 |
|---|---|---|
| REX-prefixed instructions | 57 | 78 |
| 32-bit form already aligned | 9 | 14 |
| Pure width change (rax→eax, same regs) | 16 | 27 |
| Register re-target (r14→esi etc.) | 32 | 37 |

The re-target cases are the interesting ones: `4c 89 f7` = `mov rdi,r14`;
at +1 = `89 f7` = `mov edi,esi`. Different source register entirely (REX.B
selected r14; without it the ModRM points at esi). None of the 32+37
re-targets match an operation we actually need. Full list in script output.

**limb11's `0x58` byte appears everywhere** (SLOT=88=0x58: `push 0x58`,
`imul r,r,0x58`, `[rsi+r9+0x58]`, `[r10+0x58]`, `[r15+0x58]` — 8 hidden
`pop rax` gadgets). All decorative.

### Category C — resynchronizing offset-decodes

An off-grid decode that lands back on an aligned instruction boundary.
161 raw hits in limb8, 216 in limb11. After filtering (no privileged ops,
no FPU/MMX, no memory writes through uncontrolled pointers, no movabs):

| | limb8 | limb11 |
|---|---|---|
| Safe resyncs to labels/ret | 2 | 12 |
| …of which useful | **0** | **0** |

**limb8 notable:**

```
@0x1e8 (Nmul+3, inside `lea rcx,[r12+0x4a]`):
  24 4a  = and al,0x4a
  → resyncs @0x1ea <Fmul>
```

This is a "free prefix" on Fmul: `and al,0x4a; jmp fe_mul_m`. The `and`
clobbers al, but fe_mul_m doesn't read al on entry. So: a harmless-prefix
entry to Fmul. No use case — Fmul is already in the jump table.

**limb11 notable:**

```
@0x109 (fe_mul11 CIOS, inside `imul eax,r11d` = 41 0f af c3):
  0f af c3  = imul eax,ebx   (3 B)
  → resyncs @0x10c = and eax,0xffffff
```

At this program point, r11d = m0inv (Montgomery inverse) and rbx = `a[i]`
(the schoolbook multiplicand). The gadget computes `eax * a[i]` and feeds
it into the Montgomery-q masking. Semantically nonsensical. Dead.

```
@0x19a (fe_from_le epilogue, inside `lodsw` = 66 ad):
  ad  = lodsd
  → resyncs @0x19b = stosq; ret
```

Gadget: `lodsd; stosq; ret` vs aligned `lodsw; stosq; ret`. Reads 4 bytes
for the top limb instead of 2. P-256 has a 16-bit top limb (256 = 10·24+16);
a 4-byte read would over-read. No use case.

**Everything else**: `add BYTE PTR [rax],al` (call-displacement zeros
decoded as instructions — segfault), `ret 0xf9e2` (stack-corrupting ret
imm16), `rep movsq`→`movsq`/`movsd` (single-iteration downgrades of the
string op). All garbage.

---

## Search 2: Suffix/prefix sharing

### Methodology

Build basic blocks (terminated by `ret` or unconditional `jmp`). For each
ret-block, hash tails of length 1..6 instructions. Report exact-match
duplicates and Hamming-distance-1 near-misses. Also check prefixes of
labelled entry points.

### Block census

| | limb8 | limb11 |
|---|---|---|
| Basic blocks | 23 | 22 |
| ret-terminated | 6 | 14 |
| jmp-terminated | 9 | 6 |
| jmps sharing a target | 0 | 0 |

No two `jmp` instructions share a target — every existing tail-call is
already unique. (limb8 has one `jmp rel32` at 0x2d8, disp −228 — fe_mul_m's
tail to `Fadd+0xd`. Closing that gap to rel8 would save 3 B but requires
moving ~100 B of code. Known; not actionable here.)

### limb8: exact-match tails

**None.** The only ≥2 B common suffix is `5b c3` (`pop rbx; ret`) between
fe_inv_m and verify — 2 B = cost of `jmp rel8`. Zero gain.

### limb8: Hamming-1 near-misses

| pair | tails | diff | dist | verdict |
|---|---|---|---|---|
| fe_from_be / Fadd | `e2 f5 c3` / `e2 f3 c3` | `loop` disp | 362 B | disp is semantic — dead |
| fe_inv_m / verify | `59 5b c3` / `5c 5b c3`* | pop rcx vs "pop rsp" | 300 B | *`5c` is byte 2 of `pop r12` (41 5c) — false positive |

*The `5c` byte is the second byte of verify's `pop r12` (REX.B + 5c). Without
REX it would decode as `pop rsp` which corrupts the stack. Not a real merge
candidate.*

**limb8 Search 2 verdict: nothing.**

### limb11: exact-match tails — ONE REAL FINDING

```
48 ab c3 = stosq; ret  (3 B)
  @0x170  .Lcp_shared tail  (final limb store after `add rax,rdx`)
  @0x19b  fe_from_le tail   (top-limb store after `lodsw`)
```

Distance 43 B → `jmp rel8` disp = −45. **In range.**

```
fe_from_le:
    ...loop...
    xor  eax, eax
    lodsw
    stosq           ┐  3 B
    ret             ┘  → replace with: jmp .Lcp_tail  (2 B)

.Lcp_shared:
    ...loop...
    lodsq
    add  rax, rdx   ← SF set here (load-bearing for .Lcprop callers)
.Lcp_tail:          ← new label
    stosq           ← preserves flags
    ret             ← preserves flags
```

**Safety:** `.Lcp_shared`'s SF (from `add rax,rdx`) propagates through
`stosq; ret` to callers NORM/CHKLT — this is the documented invariant
(source L241: "stosq/pop/ret all preserve flags"). fe_from_le's callers
(fe_from_be, verify) don't check SF. Jumping through the shared tail
can't corrupt the invariant — it's the same `stosq; ret`.

**Saving: −1 B.** Cold path (fe_from_le called 5× per verify). Branch
cost negligible.

### limb11: second exact-match tail

```
58 5b c3 = pop rax; pop rbx; ret  (3 B)
  @0x097  .Linv epilogue    (discards saved rdi; restores rbx)
  @0x140  fe_mul11 epilogue (discards saved dst; restores rbx)
```

Distance 169 B. `jmp rel8` disp +167 / −171 — **both directions out of
rel8 range.** `jmp rel32` = 5 B > 3 B. Net loss.

### limb11: Hamming-1 near-miss — CONDITIONAL FINDING

The above 3 B match *extends to 4 B* if INV's first pop changes:

```
.Linv epilogue    @0x096:  58 58 5b c3  = pop rax; pop rax; pop rbx; ret
fe_mul11 epilogue @0x13f:  59 58 5b c3  = pop rcx; pop rax; pop rbx; ret
                           ^^ differ only here
```

INV's first `pop rax` discards the saved rdi (source L196 — both pops at
lines 196-197 are discards). `rcx` is caller-saved; bc_run reloads it each
dispatch (source L97-98: "rcx high bytes are DIRTY — use push;pop").
Change INV's `pop rax`→`pop rcx`: INV epilogue becomes `59 58 5b c3`,
matching fe_mul11 @0x13f exactly. **4 B → 2 B = −2 B.**

**Still needs rel8.** fe_mul11's 4-B tail is at 0x13f; INV's epilogue is
at 0x096. 169 B apart regardless of which byte differs. Requires moving
INV to be adjacent to (but not falling into) fe_mul11.

Layout analysis if INV moves right before `.Lfmul`:
- `.Lfmul` = 7 B, falls into `fe_mul11`
- fe_mul11 body to 4-B tail = 0x13f − 0xda = 101 B
- INV-jmp → .Lfmul → fe_mul11-tail: disp ≈ 7+101−2 = **106 B. In rel8.**
- `.Ljt` u8 constraint: INV's new offset ≈ 0xd3−46 = 0xa5 = 165 < 256 ✓

**Cost:** Reordering INV shifts ~5 other handlers' positions. All jt offsets
stay u8 (none currently exceed 218). No known fall-through breaks (INV has
no fall-in, and `.Lnorm` at 0x9a is jt-indexed, not fallen-into). But every
handler reorder risks a rel8 somewhere else blowing to rel32 — the source
comment L98 already notes one at disp −127 ("razor's edge"). Would need
full re-verification.

**Marginal. 2 B conditional on a reshuffle with ripple-effect risk.**

### limb11: other Hamming-1 near-misses (all dead)

| pair | tails | diff | verdict |
|---|---|---|---|
| .Lcopy / .Lcp_shared | `48 a5` vs `48 ab` | movsq vs stosq — different opcodes | dead |
| .Lfadd / .Lcnt | `e2 ec` vs `e2 f4` | loop disp — semantic | dead |
| .Lcprop / fe_from_be | `00 5f c3` vs `00 5e c3` | `00` is a call-disp byte, not an insn | false positive |
| INV/fe_mul11 / verify | `58` vs `5e` | `5e` is byte 2 of `pop r14` (41 5e) | false positive |

### Prefix sharing

**No duplicate prefixes ≥3 B among labelled entries in either build.**
The only labelled-entry pair sharing even 2 B is limb11's `.Lfadd`/`.Lfsub`
which already share their entire body via the `push -1`/`push 1` setup
(source L121-142 — both immediately jmp to a common body).

---

## Summary

| finding | build | save | status |
|---|---|---|---|
| `stosq;ret` tail merge | limb11 | **−1 B** | **actionable** — rel8 in range, safe |
| INV/fe_mul11 4-B tail merge | limb11 | −2 B | conditional — needs handler reorder |
| hidden `scasd;ret` @0x10a | limb11 | 0 | no use case |
| hidden `ret` @0x291 | limb8 | 0 | bare ret, 6 already aligned |
| everything else | both | 0 | noise / false positives |

**Why so little:** Both builds are already near the syntactic-sharing floor.
Semantic sharing (fall-through chains, wrapper functions) was the big win
and is already done. What's left is genuinely coincidental byte-level
overlap, and at ~750-900 B of native code with ~14 ret-blocks, there just
aren't enough tails for birthday collisions. The one real hit (`stosq;ret`)
is the most common 3-B sequence in a limb-storage codebase — unsurprising
it occurs twice.

The ROP search finds almost nothing because the code is dense with
small instructions (push/pop/1-B opcodes dominate). Offset-decoding is
more fruitful when the host instructions are large (SSE, long immediates,
ModRM+SIB+disp32). Here the only ≥4-B instructions are `lea`, `movbe`,
`imul`, `call rel32` — and `call rel32`'s displacement high bytes are
`00 00 00` (forward) or `ff ff ff` (backward), both of which decode to
garbage (`add [rax],al` or invalid).
