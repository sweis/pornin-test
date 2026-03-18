# Session handoff — 2026-03-18 (session 2)

**Read this first.** Then `PLAN.md` for the trick catalog.

## Where we are

**1319 B, 607/607 pass, ~12.2M cycles.** Phase 1 complete (1488 B
baseline at commit 1260a47), Phase 2 grind in progress (−169 B over
10 commits). Target: < 928 B (Thomas's 5×54). Still **391 B to go**.

## What worked this session

| Trick | Δ | Commit |
|---|---|---|
| Decode chaining (fe_from_be exits rsi+32, rdi+88) | −48 | 376d2e3 |
| enter/leave + .Lfail-in-middle (rel8 length checks) | −28 | d247ad6 |
| .Lcp_shared (fe_mul11 ↔ NORM carry-prop identical) | −17 | 1ab794a |
| fe_from_be → reverse-into-slot + call fe_from_le | −13 | f34f5ce |
| CHKZ/CHKNZ via cmc; r12-hoist in pt_mul | −20 | 758ff4e |
| Qx,Qy,e → cP rdi chain (reorder decodes) | −10 | 7b25aa4 |
| .Laddm/.Lsubm via xor-neg (r9=0/−1) | −7 | 1ab794a |
| cP build: rep stosq×2 instead of stosq×8 | −5 | c767b2f |
| INV: pop;push stack-read trick | −7 | bcdebac |
| .Lai inline; fe_mul11 rdx direct-load; drop .Lfail2 | −12 | 89f89c2 |

## Biggest untried ideas (ordered by risk-adjusted expected Δ)

### ~20-30 B potential

- **NORMN → single conditional add-n.** u1,u2 are Nmul outputs. If
  value ∈ [-n, 4n], pt_mul computes (val mod n)·G correctly because
  n·G = ∞. Only need val ≥ 0 (bt on 2's-comp negative = wrong bits).
  One conditional add-n instead of full normalize. Would drop NORMN
  stub (~9 B) + 2 bc ops (4 B) + maybe share more with .Laddm.
  **RISK: verify the value range. fe_mul11 output can be < −n if
  inputs are extreme.** range_proof.py should answer this.

- **Table-driven decode.** verify has ~91 B of decode calls (4 lea
  rdi's × 7 B + 10 calls × 5 B + misc). A table of slot offsets +
  loop could be ~50 B. The rsi management (pops for hv/sig, lea rip
  for cN) is the hard part — need a uniform source model.

- **Fadd/Fsub share via copy-then-.Lasmod.** Commute bc_rcb's dst==s2
  Fadds to dst==s1 (copy is no-op). Then Fadd = rep movsq (s1→dst) +
  .Lasmod(s2, r9=0). Fsub same with r9=−1. ~10-15 B if the bc_rcb
  audit confirms no dst==s2 Fsub's (preliminary check says none).

### ~5-10 B potential

- **pt_mul lea rsi hoist.** The two `lea rsi,[r14+oBAK...]` are 7 B
  each. Could hoist to a register that survives .Lcadd. r12 is used
  for oU1; need another. r15 push/pop = +4 B, limits the win.

- **bc_run lodsb.** rsi as bc ptr, `lodsb;lodsb` = 2 B vs `movzwl
  [rbx];add rbx,2` = 7 B. But rsi is s1 for handlers. Register
  reassignment cascades through ~6 handlers using lodsq.

- **SET1/COPY merge.** Only 2 COPY uses (INV seed, Z_G). Can't drop
  COPY — INV seed must be distinct from s1. COPY handler is 6 B.

- **.Lfail tail `jmp` → rel8.** Currently rel32 (5 B) because .Lfail
  is 192 B back. Need body to shrink another ~70 B for rel8.

### Structural tax we're paying vs tiny.S (~55 B)

- cR2_n constant (32 B) + decode (5 B) — Montgomery-n is mandatory
  with 11×24 (n's top limb is 0xffff, not all-ones; q=t[top] fails).
- bc_v1 ops for Montgomery conversions: s_mont, 1_mont_p (6 B bc).
- NORMN ops (4 B bc) — maybe droppable per above.
- r_mont, n_mont derivation (4 B bc) — structural for Montgomery-p
  projective check.

## Size breakdown (current)

| Chunk | B | Notes |
|---|---|---|
| .rodata bytecode | 183 | 87 RCB + 21 v3 + 75 v1 |
| .rodata constants | 160 | 5 × 32 |
| .Ljt + handlers | ~334 | INV 53, NORM+helpers ~85, small ops ~130 |
| fe_from_be + fe_from_le | ~55 | merged via reverse-into-slot |
| fe_mul11 + .Lcnt | ~133 | shares .Lcp with NORM |
| .Lcadd + bcrun_off + bc_run | ~100 | |
| pt_mul | ~93 | .Lai inlined |
| verify | ~245 | |

## Files you should NOT touch

Outside `limb11/`. Per PLAN.md §5.

## Commit discipline

Granular. One trick per commit. progress.csv at working checkpoints.
**DO NOT PUSH.**
