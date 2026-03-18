# Session handoff — 2026-03-18 (session 3 close)

**Read this first.** Then `PLAN.md` for the full trick catalog.

## State

**1244 B, 607/607 pass, ~11.9M cycles.** −244 B this session
(1488 baseline). Target < 928 B. **316 B to go.**

Pushing now (repo private).

## What worked this session (biggest Δ)

| Trick | Δ | Key insight |
|---|---|---|
| Decode chaining + enter/leave + .Lfail-in-middle | −76 | (session 2) Five rel32 length-check jumps → rel8. |
| NORMN drop | −14 | Mod-n chain is all-nonneg (Montgomery of nonneg = nonneg). pt_mul computes (k mod n)·G for any k≥0 since n·G=∞. |
| Slot reshuffle: constants chain 9-11, r,s @ 0,1 | −11 | rodata reorder cN,cR2N,cR2,cGX,cGY. Constants chain with ZERO lea's after cP-build. r,s via `mov rdi,r14` (3 B vs 7 B lea). |
| COPYHI Shamir backup | −9 | dst nibble means slot(dst+16). bc_v1 does the backup; 31 B native code → bytecode. |
| MULR2 was a no-op | −8 | bc_run already sets rdx=r14+s2*SLOT. With s2=15 encoded, rdx=&cR2_p. The handler's lea wrote the same value. |
| CIOS merge | −7 | Schoolbook+reduce in one loop. Same math, one outer structure. Also ~2% cycle win. |
| .Lcp_shared | −17 | (session 2) fe_mul11 ↔ NORM carry-prop byte-identical. |
| COPYHI 2-slot | −4 | u2→slot 1 (s_mont dead after INV). u1,u2 adjacent at 0,1. 4 ops instead of 8. |
| r≠0, s≠0 drop | −4 | s=0 → w=0 → u=0 → ∞ → CHKNZ(Z). r=0 → d1=X, CHKZ catches. Wycheproof confirms. |
| rcx=&cN preload, fe_mul11 preserves | −2 | Nmul inherits &cN; Fmul subtracts SLOT for &cP. fe_mul11's pop rax→pop rcx so INV's 384 calls all inherit. |

## What DIDN'T work (tried, reverted/skipped)

- **NORM before CHKNZ(Z) drop**: Wycheproof tcId=292 failed. RCB's Z is an Fadd chain output — can be kp≠0 for small k. NORM required.
- **bt [rcx+56] via fe_from_be reversal**: fe_from_be's reversal into dst+56..87 is correct DURING decode (write trails read), but fe_from_le's 88-byte stosq output then OVERWRITES those bytes with limb qwords 7-10. bt read limb 7, not n's bytes. The trick needs the reversal target to be OUTSIDE fe_from_le's write range — but reversing to the previous slot's spare bytes breaks chained decodes (Qy@6's reversal would clobber Qx@5's limbs 7-10).
- **Fadd/Fsub via copy+.Lasmod**: the fall-through-to-.Lcprop split costs more than the body sharing saves. And 3 dst==s2 Fsub's in bc can't commute.
- **Fmul fall-through to fe_mul11**: u8 jump-table reach is the binding constraint. Stubs cost what the jmp saves.
- **Nmul `add rcx,SLOT` from bc_run's &cP preload**: INV calls .Lnmul directly; fe_mul11 clobbers rcx so subsequent calls break. Fixed by preloading &cN instead.
- **dword storage (SLOT=44)**: movsxd overhead (+5 B inner loop) kills the disp8 gain (~6 B).

## Biggest untried (ordered)

### ~20-30 B: NORM body simpler
Subtract-until-neg-then-add is correct but chunky (~30 B body +
~65 B helpers). If value range after bc_v1's Fadd/Fsub chains is
tighter than the conservative [−5p, 10p] (range_proof.py should
give exact bounds per-call-site), could replace with fixed-count
adds. But tiny.S uses the same structure at 933 B — unlikely to
be a big win without a different algorithm.

### ~10-15 B: verify body under 128 for rel8 tail jmp
`jmp .Lfail` at verify end is rel32 (5 B); distance = 152 B.
Need 24 B more off verify body for rel8. No obvious single cut.
Could try moving sbb;push;pt_mul;etc into a helper. Or inline
.Lfail at the tail (+4 B vs −3 B rel8 = net +1).

### ~5 B each, speculative
- `COPYHI4`: one op for all 8 slots? Sources 0-7 contiguous if
  u1,u2 stay at 0,1 AND Gx,Gy,Z,Qx,Qy,Z chain. But they do!
  0,1,2,3,4,5,6,7 → 22,23,16,17,18,19,20,21. Source contiguous
  but dest wraps. Handler needs two rep movsq's. ~14 B handler
  + 2 B one op vs current 13 + 8. Save ~7 B.
- fe_from_be's `dec rdx` (3 B REX) → `dec edx`? rdx holds a
  pointer (>2^32). Can't truncate. But if slot base were low...
  no, stack is high on Linux.

## Slot map (current — load-bearing for bc_v1)

| Slot | bc_v1 entry | bc_v1 exit | RCB-safe? |
|---|---|---|---|
| 0 | r plain | u1 | acc X — RCB writes |
| 1 | s plain | u2 | acc Y — RCB writes |
| 2,3 | Gx,Gy mont | same | RCB writes |
| 4 | — | Z_G = 1_mont | RCB writes |
| 5,6 | Qx,Qy plain | Qx,Qy mont | ✅ addend, never written |
| 7 | e | Z_Q = 1_mont | ✅ addend |
| 8,9 | cP, cN | same | ✅ |
| 10 | cR2_n → b_mont | b_mont | ✅ |
| 11 | cR2_p | dead | RCB writes |
| 12,13 | — | scratch | RCB writes |
| 14 | — | r_mont | ✅ |
| 15 | — | n_mont | ✅ |

RCB-safe = 5,6,7,8,9,10,14,15. cR2_n @ 10 is consumed by s_mont
(first bc_v1 op after checks) before b-derive writes 10.

## Size breakdown (1250 B)

| Chunk | B |
|---|---|
| bytecode | 183 (87 RCB + 21 v3 + 75 v1) |
| constants | 160 |
| .Ljt + handlers | ~321 |
| decoders | ~55 |
| fe_mul11 (CIOS) | ~142 |
| pt_mul + bcrun_off + bc_run | ~188 |
| verify | ~201 |

Tests pass before size claims. 20-run median for cycles.
