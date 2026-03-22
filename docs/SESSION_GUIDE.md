# Session Guide — Read This First

Entry point for any future session on this project. Skim once, then
grind.

---

## Current state

**Size floor: `stupid/` at 620 B** (SMC) / 633 B (NO_SMC practical).
Previous floor: `limb8/` at 890 B. Thomas baseline was 766 B; we're
−146 B under.

| Track | Floor | Cycles | Arch | Status |
|---|---:|---:|---|---|
| `stupid/` | **620 B** | ~2.4G | 1-byte acc-VM, MUL=bytecode | **active floor**; est. arch min ~615-617 B |
| `stupid/` NO_SMC | 633 B | ~239M | same, no self-mod | practical point |
| `limb8/` SMALL_MUL8 | 890 B | ~5.2M | 8×32 q=t[top], native mul | prev floor; port b-derive? |
| `limb11x24/` | 1068 B | ~12M | 11×24 Montgomery | trick catalogue |
| `limb5x56/` | 1084 B | ~3.1M | 5×56 Montgomery | byte-aligned decode |
| `limb5x54/` | 1097 B | ~2.8M | 5×54 Montgomery | Thomas's arch |
| `speed/fast2.S` | 3265 B | ~570K | BMI2+ADX | cycles corner |

Chart: `docs/progress.png`. Data: `docs/progress.csv` + per-track
`<track>/progress.csv`.

**External competition:** Thomas v7 at 928 B / 4.48M (non-stupid);
expecting ~893 B after b-derive port. His stupid baseline was 766 B.

---

## Workflow

```
make test size            # 607/607 × all tracks, sizes side by side
make -C stupid size-all   # all build variants
make -C stupid bench20    # 20-run median (DSB jitter ±8% on 1-B shifts)
make chart                # regenerate docs/progress.png
```

**607/607 before any commit.** 33 hand-picked + 574 Wycheproof.
ASAN/UBSAN via C harness.

**Commit granularity:** one trick = one commit. Message =
`<track>: <technique>` + byte delta. Append to `<track>/progress.csv`
and `docs/progress.csv`. Regenerate PNG after each improvement.

**Chart maintenance:** track color follows ARCHITECTURE (limb8=tiny.S=
blue trail, stupid=its own color). xlim left edge tracks size floor.
Filter to self-Pareto + labeled milestones. Connector lines clip at
xlim (scatter auto-clips, line plots don't).

---

## Local-minimum avoidance — THE META-LESSONS

These are the traps we actually fell into. Check against them before
declaring a floor.

### 1. Speed-floor anchoring — plot the FULL space first

We missed the 766 B approach because our chart cropped at 15M cyc.
Thomas's point was at 141M cyc — literally off-screen. The hole in
the frontier at (sub-800 B, >100M cyc) was invisible.

**Check:** is the axis limit a constraint or a convenience? For
size-golf, only correctness is hard. Boot-ROM tolerates 100× slower.
Plot log-y to 10^9 FIRST, then crop for detail.

### 2. "X is a primitive" framing — neither MUL nor constants are irreducible

We had native `fe_mul` in every track (80–150 B). Never asked whether
MUL belongs in bytecode. DEAD_ENDS.md had 15+ entries on reduction
strategies, ZERO on VM designs. Same blind spot for constants: we
stored b as 32 B of data; it's `Gy²−Gx³+3Gx` derivable in 11 B of
bytecode.

**Check:** frame as "minimal native primitive set," not "smallest
fe_mul." Our list was {fe_mul, fe_add, fe_sub, copy, bit-test}.
Thomas's is {32B-add, 32B-sub, copy, bit-test}. For each "primitive,"
try removing it and see what bytecode substitutes. For each constant,
ask: (a) is the bit pattern redundant? (b) does it satisfy an equation
in other stored constants?

### 3. Structural isomorphisms — same loop shape = VM opcode

Scalar×point = double-and-add. Field mul = double-and-add. Modular
inversion = square-and-multiply = double-and-add on exponent. **Three
operations, one loop shape.** We had three separate code paths.

**Check:** same control structure appearing 3× in native code = VM
opcode waiting to happen. FOR/NEXT/SKIPBITZ in stupid/ serves all three.

### 4. "Obviously stupid" ≠ dead

Multiply-by-repeated-addition is the canonical naive algorithm every
cryptographer learns to REPLACE. That training is a blind spot when
size is the goal.

**Check:** the size-optimal solution is allowed to be algorithmically
embarrassing. When brainstorming, explicitly include the undergrad-
textbook version of each primitive. It's usually the smallest.

### 5. Incremental grind blinds to structural jumps

933→890 B (limb8) was 43 B over ~20 commits, each a local move.
766 B isn't reachable from 890 B by any sequence of 1–5 B moves — it
requires throwing away fe_mul entirely.

**Check:** stalled grind = local minimum → swap primitive → new
landscape. We swapped limb widths (8→11→5×54→5×56). Never swapped
the MUL primitive itself. The "primitive" you're varying might itself
be the thing to remove.

### 6. Unstated constraints — axis-relaxation pass

Three instances, all the same failure: assumed constraint wasn't
binding for the deployment target.
- Speed floor → MUL-as-bytecode (boot-ROM tolerates 100×)
- Data storage → derive b (curve equation IS the compressor)
- Code immutability → SMC (boot-ROM has no W^X; −11 B)

**Check:** before "ARCHITECTURE SETTLED," enumerate implicit
assumptions. For each: "does the ACTUAL deployment target enforce
this?" The ones that don't bind are free search space.

### 7. Dead ends encode the ATTACK, not the GOAL

Session-1 "dead end" (`call docopy` +1 B) became session-6 win (−2 B)
— not from byte shrinkage but from REFRAMING: "does op_mul need to
continue after copy?" → no, set up stack first, docopy's ret IS the
return. Same session, slot-1-modulus: "break-even" in S1 became −4 B
in S3 via different exit mechanism.

**Check:** when reading DEAD_ENDS.md, ask "what question was this
answering?" If the entry names a specific mechanism (call vs jmp,
register X), the goal may have other attacks. The tell: entry's
justification contains an assumed constraint ("because op_mul
continues," "while keeping saved_rsp").

---

## Agent-prompt patterns that work

Validated across limb8, limb5×54/56, limb11, stupid sessions.

### Concrete-tricks list as scaffold, not oracle

**Don't** translate user's aggressive target literally: "Target 850 B,
try structural ideas" → agent stalled 25 min, zero commits. Last
output was "Let me analyze..." — preamble-then-nothing.

**Do** give nearer target + concrete work queue: "Target 890 B. Five
tricks: mov-cl audit, xlatb port, shr-bitmask, stale-rel8 check,
inc-byte-vs-qword." → −7 B in 26 min.

The list doesn't need to be RIGHT, it needs to be CONCRETE. Each
"try X" = bounded investigation → win OR documented block OR adjacent
discovery. Relaunched limb8 agent's −7 B came mostly from its OWN
finds (`repe scasq`, tail-jmp), not the listed ports. Stupid-track
agent: 9 candidates prompted, 6 wins weren't in the list.

### Stall signature & recovery

- **Signature:** few output lines, long clock time, last output is
  assistant TEXT ("let me analyze X") not tool_use.
- **SendMessage nudges don't unblock** — queue for "next tool round"
  that never comes.
- **Fix:** kill and relaunch with narrower prompt.

### Target decomposition

User's aggressive target (850 B) = hard floor. Agent's target =
next checkpoint (890 B). Structural ideas go in SECOND message after
concrete wins banked, or a second agent.

---

## Detailed docs — where to look next

| File | What |
|---|---|
| `docs/TRICKS_LEDGER.md` | Every trick: applied / dead / untried, tagged & grep-able |
| `docs/DEAD_ENDS.md` | Don't-retry log, with WHY (absolute/conditional/attack-specific) |
| `docs/x86_tricks.md` | x86-64 encoding catalogue, flag-preserving ops, microcode latencies |
| `docs/GADGETS.md` | Bytecode + native x86 gadget searches (mostly negative) |
| `docs/stupid_analysis.md` | Full why-we-missed-766 writeup |
| `docs/literature_survey.md` | Research survey — RCB floor, GLV dead, wNAF dead |
| `BENCHMARK.md` | Measurement methodology, eh_frame gotcha, cycle breakdown |
| `CLAUDE.md` | Per-track invariants (limb8, stupid) — audit on reorder |
| `<track>/README.md` | Per-track biggest tricks + what didn't port |
| `<track>/progress.csv` | Commit-by-commit byte history |
