# VM Redesign Ideas — Breaking Below 620 B

**Baseline:** `stupid/tv_ecdsa.S` at 620 B (SMC) / 633 B (NO_SMC). Floor
assessment ~615-617 B. This document brainstorms structural alternatives,
not grind targets.

**Caveat (per feedback_anchor_floor):** every estimate below is a
component-delta against a baseline that is already heavily compressed.
History says these estimates are systematically optimistic — the
unconsidered costs (handler boilerplate, encoding constraints, invariant
breakage) eat the projected savings. Treat Δ as "reason to prototype,"
not "expected outcome." The three flagged prototypes each have a smallest
thing that exercises the unknown — build that first.

---

## Ranked by expected value (Δ × confidence)

### TOP 3 — worth prototyping

#### 1. Implicit-operand "macro-op" for point-add setup  (MEASURED: ~+2 B, DEAD at current layout)

**Finding (d2c6554):** Handler needs `leaq (_Hx*32)(%rbp),%rdi` where
_Hx*32 = 352 > 127 → disp32 (7 B). Full handler is 21 B; even with
`rep movsb;ret` tail-share vs docopy it's 20 B. Bytecode savings are
−19 B (24→5), but +1 B for `_LD _Hx` at point_add_to_W entry (acc no
longer holds Hx after rep-copy). Net +2 B. Slot reshuffle to move H
into disp8 range blocked: slots 0–3 are acc/modulus/F1/Kr (all live
during FOR); F1↔H overlay fails because MUL (clobbers F0/F1) runs
while H is still live in point_add (last H read at the t4 computation,
MULs throughout). G at 28,29 is baked into init's `enter $192;rep
movsb` sequence — moving it needs a split push-loop (+~5 B init).
**Would unlock at ~−3 B IF H could reach disp8.** Bookmark.

**Original estimate:**

The FOR body does three variants of "copy triple to H, call point_add":
```
double:  LD Wy;ST Hy;LD Wz;ST Hz;LD Wx;ST Hx;CALL add    (8 B)
+G:      LD Gy;ST Hy;LD ONE;ST Hz;LD Gx;ST Hx;SKIPBITZ;CALL  (9 B)
+Q:      LD Qy;ST Hy;LD Qx;ST Hx;SKIPBITZ;CALL            (7 B, Hz reused)
```
24 B of bytecode for what is semantically three `PADD src` operations.

**Proposal:** `PADD_PROJ` (operand = base slot of X,Y,Z triple) and
`PADD_AFF` (operand = base slot of X,Y; Hz←1). Handler does 3×32 B
`rep movsb` then pushes `point_add_to_W` onto the call stack (reusing
`op_mul`'s stack-manipulation pattern). The SKIPBITZ wraps it.

- Bytecode: 24 B → ~6 B (3 ops + 2 SKIPBITZ) = **−18 B**
- Handler: ~12-16 B (96-B copy is `mov cl,96;rep movsb` + stack push)
- Net: **−6 to −2 B**
- Bonus: if PADD can be primary opcode (reclaim FAILCC's operand space,
  FAILCC only ever uses operand 0), handler table stays 8-wide.

**Risk:** slot layout — W=(8,9,10) and G/Q aren't contiguous triples
with their Z. Would need slot reshuffle: move Gx,Gy,ONE to 27,28,29 and
Qx,Qy,ONE-copy to 5,6,7. ONE-copy wastes a slot but slots aren't scarce
(29/32 used). Might cascade into disp8 constraints on `_Kr*32`.

**Smallest prototype:** reshuffle slots, keep existing 6-op copies,
verify 607/607. Then add PADD handler.

---

#### 2. `call $+5; pop rbx` instead of `lea rbx,[rip+...]`  (DONE: −2 B, commit 3f02102)

Both sites replaced. verify() moved to front of .text; `call Ldecoder`
jumps over decode_int/consts/bytecode (pushes &decode_int), `call
Lmain` jumps over translation_table/handlers (pushes &translation_table).
Each pop rbx retrieves exactly the base we need. 618 B.

**Original estimate:**

Two `lea rbx,[rip+disp32]` sites at 7 B each (confirmed in objdump:
offsets 0x201 and 0x24a). `call rel32` to next-instruction + `pop rbx`
= 5+1 = 6 B. Saves 1 B/site.

**Better variant:** the first lea sets `rbx=&decode_int`. The second
re-sets `rbx=&translation_table` (286 B later). If the code between
them is reorganized so `translation_table` is within disp8 of wherever
rbx already points, the second lea becomes `lea rbx,[rbx+N]` (4 B) or
even `add rbx,N` (4 B with imm8). **−3 B** for the second site alone.

**Best variant:** single `call`+`pop` at entry, use disp8 off rbx for
*both* decode_int and translation_table. Requires moving 190 B of
bytecode out from between them. Bytecode could go *after* the
interpreter since CALL offsets are forward-only within bytecode but the
interpreter finds the entry via rsi (set from `13(%rbx)` currently).
Feasible. **−4 to −7 B** plausible.

**Risk:** moving bytecode reorders the `.text` layout; need to re-verify
all rel8 jumps in handlers still reach. The `13(%rbx)` hardcoded
offset to bytecode-entry would change.

**Smallest prototype:** just swap `lea rip` → `call+pop` at both sites
without reorganizing. Measure −2 B. Then attempt layout shuffle.

---

#### 3. Two-accumulator VM  (Δ ≈ −5 to −10, MED-LOW)

RCB's 83 B is dominated by `LD tmp; op; ST tmp` where tmp is dead
within 3-5 ops. A second accumulator eliminates the ST/LD pair when
the next chain starts before the previous result is consumed.

**Encoding:** steal 1 bit from the 5-bit slot field → 4-bit slot (16
slots) + 1-bit acc-select. **Problem: 29 slots used, can't fit in 16.**

**Alternative encoding:** use the currently-unused FAILCC operand bits
(FAILCC operand is always 0, so encodings 0x0C..0xFC with low-3=100
are free). 31 free encodings could be: `XCHG` (swap acc0↔acc1) = 1
encoding, `ST2 x` / `LD2 x` using high-4 bits = 16 encodings each.
Handler dispatch needs a second-level check when primary-op=4 and
operand≠0.

- Bytecode: scan RCB for `ST x; ...; LD x` where x is dead after —
  estimate 6-10 such pairs. Replace with XCHG = −1 B/pair = **−6 to −10 B**
- Handler: acc-select logic + XCHG handler ≈ **+8-12 B**
- Net: **−2 to +2 B** — marginal, but the dependency-graph analysis
  might surface other restructurings.

**Risk:** the real win depends on RCB's dep-graph density. Might be
zero. Worth a paper analysis before any code.

**Smallest prototype:** annotate `point_add_to_W` bytecode with live
ranges; count ST/LD pairs where the intervening ops don't touch the
stored slot. That number × 1 B is the ceiling.

---

### SECOND TIER — plausible but thin

#### 4. BE-native VM (Δ ≈ −5, MED)

Eliminate `decode_int` (13 B) by operating on BE integers throughout.
`z256_addsub` iterates from byte 31 down (same code size — carry
propagation is direction-agnostic). Constants stored BE (same size).

**Cost:** `SKIPBITZ` uses `bt %r9d,(%rdx)` which assumes LE bit layout.
BE needs index transform: bit i of BE-256 lives at byte `31-(i>>3)`,
bit `i&7`. Transform ≈ +5 B in op_skipbitz. The n-top/p builder writes
dwords low-to-high; BE needs high-to-low or post-bswap ≈ +3 B.

- Gross: −13 B (decode_int) + caller setup savings (~−4 B, no rdx reload)
- Cost: +5 (SKIPBITZ) +3 (builder) +~2 (misc) = +10 B
- Net: **~−7 B** optimistic, **~−3 B** realistic

**Risk:** the rdx-source-reload trick in `decode_int` (source via rdx
so rsi survives 5 calls) is worth ~6 B on its own; losing decode_int
doesn't automatically recover those 6 B in the caller. Might net zero.

#### 5. TRIPLE meta-op (Δ ≈ −2, MED)

Four sites do `_OP x; _OP x; _OP x` (SUB Gx ×3, ADD Qx ×3, SUB T2 ×3,
and the `_ADD 0; _ADD tN` double-then-add pattern ×3 for tripling).
A `_TRIPLE` prefix or a `_ADD3`/`_SUB3` op saves 2 B/site = −8 B
bytecode. Handler is a 3-iter loop around the existing add/sub path
≈ +6 B. Net **~−2 B**.

**Risk:** modular reduction runs per-add inside the handler; a 3-iter
loop around `op_add` is fine but needs to preserve/restore the operand
pointer. Might cost more than +6 B.

#### 6. op_mul → docall tail share (Δ ≈ −3, MED)

`op_mul` (15 B) and `docall` (in op_call, ~10 B) both manipulate the
stack to insert a callee address between the native return and the
saved IP. `op_mul`'s sequence (`popq rdi; pushq rax; pushq rdi`) might
share `docall`'s tail (`pushq rax; pushq rdx; ret`). Needs stack-slot
analysis — they use different scratch registers.

**Risk:** already-dense region; `docall` is a fall-through target from
`op_call` which constrains ordering.

---

### DEAD — do not prototype (reasoning recorded)

| Idea | Why dead | Δ |
|---|---|---|
| **Stack-based VM** | RCB is chain-heavy (`LD;op;op;ST`); stack model adds DUP/SWAP overhead. Acc-VM is optimal for sequential dep chains. | +10..+20 |
| **2-address / 3-address** | 30 slots × 5 bits × 2-3 operands = 10-15 bits/op → 2 B/op regardless. Loses acc chain amortization (currently ~1.2 B/op effective). | +20..+40 |
| **Threaded code** | Every parameterized op (6 of 8, ~140 instances) needs a second byte for operand. | +~120 |
| **Subroutine-threaded (`call rel8` sequence)** | x86-64 has no `call rel8` — minimum `call rel32` = 5 B/op. | +600 |
| **4-bit slot encoding** | 29 slots irreducibly used (measured: MUL scratch F0/F1 can't overlay any temp live across MUL). Consolidation floor ≈ 21 even before temps. | N/A |
| **Register-window / relative-slot** | RCB access pattern is non-local: T-block (16-23) ↔ W/H-block (8-13) every few ops. Window shifts dominate. | +10..+30 |
| **Huffman / variable-length** | Decoder complexity (+15-20 B) ≈ bytecode savings. Break-even at best. | ~0 |
| **RLE / repeat-prefix** | Only 4 sites × 3-rep + 2 sites × 2-rep. Handler cost > savings. | +4 |
| **6-bit packed (2-bit op + 4-bit slot + escape)** | 16-slot limit again. Bit-stream decoder ~20 B. | ~0 |
| **OISC (subleq)** | 3 B/instr × ~200 instrs for RCB alone. | +400 |
| **Projective final check (skip Wz⁻¹)** | invert_mod still needed for s⁻¹ (irreducible to ECDSA). Two-case r / r+n check adds bytes. | +5 |
| **Eliminate s⁻¹** | u=e/s, v=r/s is fundamental. No algebraic rewrite avoids it. | N/A |
| **XZ-only coordinates** | Montgomery ladder needs known point-difference. Two-scalar u·G+v·Q has no fixed diff. | N/A |
| **Co-Z arithmetic** | Saves storage, not code. RCB is denser at bytecode level (confirmed: 87 B complete vs 80 B incomplete dbl+add). | +5..+15 |
| **Gy from compressed point** | To derive Gy need b; to derive b need Gy. Storing b instead of Gy = same 32 B + sqrt code (+13 B). | +13 |
| **Gx from seed** | NIST seed→G uses SHA-1. No hash primitive available. Gx is cryptographically random by design — no short field-expression. | N/A |
| **RNS (residue number system)** | Per-component mul is nice but CRT reconstruction before every compare/sub-modulus costs ≥50 B. Comparison-heavy verify is worst case for RNS. | +50..+100 |
| **Lazy carry / redundant rep** | ADD handler already defers: "subtract modulus until no-carry" runs ≤2 times, only when needed. Further laziness needs a normalize-op before every compare = more bytecode. | +5 |
| **JIT bytecode at startup** | JIT engine ≫ interpreter. No writable memory beyond stack in boot-ROM model (SMC already stretches this). | +100 |
| **Bytecode REVERSE op (BE→LE in VM)** | Still need native raw-copy of inputs to slots. Handler+copy ≈ current decode_int. | +2 |
| **Dual-base const addressing** | cmp+cmov in dispatch (+6 B) > rep movsb copy savings (−6 B). | +2 |
| **More handlers as bytecode** | Every remaining native handler touches native state (stack, registers, bt instruction, rep movsb). Boundary is at the minimum. | N/A |
| **Befunge-style 2D PC** | 2D decode + direction state ≫ 1D. Zero structural advantage for a linear algorithm. | +30 |

---

## Structural observations

**Why acc-VM is near-optimal here:** RCB's dataflow is almost purely
sequential (each output feeds the next op). An accumulator IS the
optimal register allocation for a single-chain dependency graph. The
~40 LD and ~35 ST in 190 B bytecode are the irreducible "spills" at
chain boundaries. A better VM would need to reduce chain-boundary
count, not per-op encoding — which means restructuring RCB itself
(already at the EFD-confirmed minimum) or fusing chain boundaries
(the PADD idea, #1).

**The 80 B constant wall is real:** Gx and Gy are cryptographically
random (NIST's nothing-up-my-sleeve). 57 distinct bytes in 64, zero
adjacent duplicates, all 16 nibbles present. n_low similarly. The
curve equation already extracts the only algebraic dependency (b). No
compression scheme shorter than ~75 B exists for these 80 B.

**The real 620→? gap:** handwaved Kolmogorov floor ≈ 450-500 B
(49 B irreducible consts + ~90 B native primitives + ~130 B
perfect-encoded bytecode + ~60 B entry/init — *all optimistic*).
Current 620 B is ~120-170 B above this optimistic floor. Most of that
is **encoding overhead** (handler dispatch boilerplate, stack
manipulation in CALL/RET/FOR/NEXT) and **input processing** (size
checks, decode). Neither is obviously reducible by a single structural
change — it's death-by-a-dozen-5-B-handlers.

**What WOULD get to 550 B:** probably needs 2-3 of the above
simultaneously — PADD macro-op (#1) + layout reshuffle for single rbx
(#2) + one more structural win we haven't found. Each prototype should
be built independently first (per feedback_anchor_floor: smallest thing
that exercises the unknown), then combined.
