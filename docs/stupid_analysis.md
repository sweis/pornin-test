# Why We Missed The 766 B Approach

Thomas's "stupid" implementation is 124 B smaller than our floor. The
techniques aren't exotic — they're all things we knew. We missed them
because of **search boundaries we never questioned**.

---

## 1. Techniques he used that we didn't

### Multiplication as bytecode (−80..−150 B)

The single biggest difference. Every one of our tracks (limb8, limb11,
limb5×54, limb5×56) has a native `fe_mul` routine — schoolbook product
+ Montgomery/q=t[top]/Solinas reduction, 80–150 B of carry-propagation
assembly. Thomas's multiplication is **9 bytes of bytecode**:

    _ST _F0 ; _LD _ZERO ; _FOR ; _ADD 0 ; _SKIPBITZ _F1 ; _ADD _F0 ; _NEXT ; _RET

Russian-peasant (double-and-add). Structurally identical to scalar×point.
We had the FOR/SKIPBITZ loop abstraction for point multiplication
(pt_mul's 256-iteration bit scan) but **never noticed it also
implements multiplication**.

### Accumulator-based 1-byte ISA (vs our 2-byte three-address)

Our bytecode: `Fmul dst,s1,s2` — 2 bytes (1 opcode + 1 packed nibbles).
Thomas's: `LD s1 ; MUL s2 ; ST dst` — 3 bytes, but each instruction is
1 byte (3-bit opcode + 5-bit operand). Sequential ops on the same value
skip the LD/ST pair, so RCB's long temp-chains amortize closer to 1.2
bytes/op. Our encoding paid 2 B/op regardless of data flow.

### Subroutine stack (CALL/RET/nested)

Our bytecode has fixed-entry sequences (`bc_v1`, `bc_rcb`) called via a
hardcoded offset + return-to-dispatch-loop. Thomas's has a real call
stack. `invert_mod` (14 B bytecode) called from 2 sites, `point_add_to_W`
(100 B bytecode) called from 3 sites — would be 342 B inlined, actually
costs 100 + 6 B of CALL ops. Our architecture couldn't express this.

### Modular reduction = "subtract until carry" (−30..−50 B)

No Montgomery. No Solinas. No q=t[top]. Just:

    Lop_add__loop:  rsi ← modulus;  call z256_sub;  jnc Lop_add__loop

Runs at most twice (since both operands < 2m). Our limb8's q=t[top]
reduction is the smallest we had (~30 B) — this is ~12 B.

### "Skip next instruction" conditional (SKIPCC/SKIPCS/SKIPBITZ)

Instead of conditional CALL or conditional branch-to-label, conditionals
skip exactly one instruction (or two bytes if next is CALL). This means
**no branch targets in bytecode**, just `skip;op` pairs. All our bytecode
conditionals were "branch to FAIL handler" — we encoded offsets.

### FOR/NEXT as opcodes (not native asm loop)

We implement the 256-iteration scalar-bit loop in native asm inside
pt_mul. Thomas pushes it into bytecode. Cost: ~20 B of handler code.
Saved: ~40 B of native pt_mul loop body + the ability to reuse it for
MUL + the ability to reuse it for INV (square-and-multiply).

---

## 2. Why we missed them — introspection

### Speed-floor anchoring

We never considered the 100M+ cycle region. Unstated assumption:
"signature verify in a boot ROM needs to be fast enough to not be
annoying." But 275M cyc @ 3 GHz ≈ **90 ms, once, at boot**. Entirely
acceptable. Our search space had an invisible wall at ~15M cycles.

**The tell:** our Pareto chart's y-axis maxed at 15K (thousands of
cycles). We literally couldn't plot this region. Log-y was there, but
the ylim cropped it.

### "Multiplication is a primitive" framing

We framed the problem as "minimize the cost of {field ops, point ops,
bytecode interpreter}." Multiplication was in the "field ops" bucket and
we optimized WITHIN that bucket (limb count, reduction strategy). We
never asked whether multiplication belongs in the bytecode bucket.

**The tell:** DEAD_ENDS.md has 15+ entries about alternative
multiplication/reduction strategies (WW-AMM, Solinas variants, limb
widths). Zero entries about alternative VM designs. We searched the
wrong parameter.

### We already HAD half the idea

Our bytecode interpreter already has a 256-iteration bit-scanning loop
(for pt_mul). Our INV already does square-and-multiply. We had the
pieces. The missing step was "double-and-add works for integers too" —
a fact every undergraduate knows. We just didn't connect it because we'd
categorized MUL as native.

### Incremental grind blinds to structural jumps

Our grind process: pick a track, shave bytes, measure, repeat. Each
session inherits the previous session's architecture. Moving from 933 →
890 (limb8) was 43 B over ~20 commits, each a local optimization.
Thomas's 766 B isn't reachable from 890 B by any sequence of 1–5 B
local moves — it requires throwing away fe_mul entirely.

**The tell:** feedback_local_minima.md says "stalled grind = local
minimum, swap primitive → new landscape." We swapped limb widths
(8→11→5×54→5×56). We never swapped the **multiplication primitive
itself** (hardware mul → repeated addition).

### The name itself

"stupid." Thomas named it that because double-and-add multiplication is
the **naive textbook algorithm every cryptographer learns to replace**
with something faster. We're trained to think of it as what you do
BEFORE you learn Montgomery/Karatsuba. That training is a blind spot
when the goal is size, not speed.

---

## 3. Search-practice improvements

### Explicit axis-relaxation pass

Before grinding, enumerate which constraints are hard (607/607
correctness) vs soft (cycle budget). For each soft constraint: what
becomes possible if we relax it 10×? 100×? We'd have found "100× slower
→ multiplication-as-addition" in five minutes of whiteboarding.

### "What's the smallest primitive set?" not "what's the smallest X?"

Frame as: what's the **minimal native instruction set** the bytecode VM
needs? Our answer was {fe_mul, fe_add, fe_sub, copy, bit-test, compare}.
Thomas's is {32B-add, 32B-sub, copy, bit-test}. We never tried removing
fe_mul from the list.

### Check structural isomorphisms

Scalar×point = double-and-add. Field multiplication = double-and-add.
Modular inversion = square-and-multiply = double-and-add on the exponent.
**Three operations, one loop shape.** Our pt_mul, INV, and fe_mul were
three separate pieces of code. When the same control structure appears
three times, that's a VM opcode waiting to happen.

### Plot the FULL space before grinding

Our chart cropped at 15M cyc. If the y-axis had gone to 1G cyc from the
start, the empty region at (sub-800 B, >100M cyc) would have been a
visible hole in the frontier — which is exactly the diagnostic
feedback_frontier_shape.md tells us to look for ("step near floor =
under-ground").

### Don't trust "obviously stupid" = dead

"Multiply by repeated addition" is the canonical stupid algorithm. That
categorization made it invisible. Rule: **the size-optimal solution is
allowed to be algorithmically embarrassing**. Add this to the
architecture-survey checklist.

---

## 4. Grind targets on this baseline

Listed in stupid/README.md. Summary: bytecode subroutine factoring
(×3 sequences), handler tail-sharing (op_skipcc/cs, op_ld/st), our x86
catalog (xchg/cqo/mov-cl), and a `-DFAST_MUL` variant that restores
native multiplication for the speed/size knee around 850 B / 5M cyc.
