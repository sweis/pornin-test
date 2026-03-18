# Session handoff — 2026-03-18 (session 2 close)

**Read this first.** Then `PLAN.md` for the full trick catalog.

## State

**1312 B, 607/607 pass, ~12.2M cycles.** Phase 1 complete (1488 B at
1260a47), Phase 2 grind −176 B over 11 commits. Target < 928 B
(Thomas 5×54). **384 B to go.** Repo is now private — pushing OK.

## The exact next action

```
cd limb11
make test size                # 1312 B, 607/607
# Pick an item from "biggest untried" below. NORMN-lite is the
# highest-expected-value (needs range_proof.py verification first).
python3 range_proof.py        # check: can Nmul output go below −n?
```

## What worked (Phase 2, biggest Δ first)

| Trick | Δ | Key insight |
|---|---|---|
| Decode chaining | −48 | Both decoders exit rsi+32, rdi+88. Rodata reordered: cN first (cP-build rdi flows in), cR2N,cR2→14,15, e@7 (chains after Qy). |
| enter/leave + .Lfail-in-middle | −28 | Five length-check jcc's were rel32. Epilogue BETWEEN checks and body → all rel8. enter's alignment falls out of push count. |
| .Lcp_shared | −17 | fe_mul11's carry-prop = NORM's .Lcprop byte-for-byte. One shared body; .Lcprop is an 11-B in-place wrapper. |
| fe_from_be via in-slot reversal | −13 | Slot has 56 spare bytes. Reverse BE into 56-87, call fe_from_le. Write region trails read region (5i−56 ≥ 0 for i<11). |
| CHKZ/CHKNZ cmc; r12-hoist; drop r15 | −20 | cmc flips CF sense. r12 survives .Lcadd (bc_run push/pops it). |
| xor-neg add/sub share | −7 | `xor rax,r9; sub rax,r9` = identity for r9=0, negate for r9=−1. |
| CIOS merge | −7 | Schoolbook+reduce in one loop. 2 .Lcnt calls per row; drops reduce setup + its rcx,rsi push/pop. |
| INV stack tricks | −7 | `pop;push` reads [rsp] in 2 B. Double-pop-repush gets both stack slots in 4 B. |
| .Lai inline; drop .Lfail2 | −9 | pt_mul safe on garbage (fixed 264 iters). bc_v1's fail flag survives on stack, OR'd with bc_v3's. |

## Biggest untried (risk-adjusted)

### ~20-30 B: NORMN-lite — HIGHEST VALUE, needs verification

pt_mul computes k·G for any k (double-and-add). Since G has order n,
k·G = (k mod n)·G. So u1,u2 don't need full [0,n) normalization —
any k works IF k ≥ 0 (bt on 2's-complement negative reads wrong
bits). Nmul output is in some [−C·n, C'·n]. One conditional add-n
(or unconditional add + carry-prop) suffices.

**Verify first:** range_proof.py has the Montgomery output bound.
For mod-n Nmul: output = (a·b/R + m) where inputs are bounded.
Question: can output go below −n? If not, one `.Laddm` (with r8=cN)
unconditionally makes it ≥ 0 and ≤ some C·n. Drop NORMN stub (~9 B)
+ 2 NORMN bc ops (4 B). Maybe drop .Lop12 from jump table (−1 B).

Cost: depends on how the add-n is done. If bytecode gets an ADDN
op (~10 B handler), net is small. If native verify code does it
between bc_v1 and Shamir copy: one `lea r8;call .Laddm` per scalar.

### ~15 B: Fadd/Fsub via copy-then-.Lasmod

Fadd(dst,s1,s2) = copy s1→dst, then .Lasmod(s2, r9=0). Fsub same,
r9=−1. The copy is `rep movsq` (s1→dst), then fall into .Lasmod.
**Breaks if dst==s2** (copy overwrites s2). Commute dst==s2 Fadds
to dst==s1 (copy is no-op then). Audit bc_rcb: `Fadd 0,2,0` has
dst==s2 — commute to `Fadd 0,0,2`. No dst==s2 Fsubs found.

Savings: Fadd (17 B) + Fsub (17 B) = 34 B → ~20 B shared. −14 B.

### ~15-20 B: Table-driven decode

verify has ~4 lea rdi's (28 B) + 10 calls (50 B) + pops + cP build
interspersed. A table of slot indices + a loop could be ~50 B vs
~80 B current. Hard part: unified rsi model (lea rip+cN for
constants, pops for hv/sig, direct rdx for pub). Maybe two passes
(constants then inputs) with separate tables.

### ~5-10 B: bc_run lodsb/lodsw for bytecode ptr

`lodsw` = 2 B vs `movzwl [rbx];add rbx,2` = 7 B. But rsi is s1 for
handlers. Reassignment cascades through handlers using lodsq
(Fadd, Fsub, .Lasmod, .Lorall, .Lcp_shared). Each needs `mov rsi,r?`
first. Counted ~3-5 handlers × 3 B. Net marginal to negative.

### ~5 B each, free

- `.Lsubm` fall-through (currently `jmp .Lasmod`). Reorder: .Lsubm
  before .Lasmod. But .Laddm also needs to fall through. Three-way
  layout puzzle.
- pt_mul `lea rsi,[r14+oBAK+3*SLOT]` — if Q-backup source could be
  derived from G-backup source after .Lcadd's rep movsq advances
  rsi. After G-add rsi = oBAK+3*SLOT naturally. But only if G-add
  ran (u1 bit set). Control-flow dependent; hard to exploit.

## Structural tax we're paying (~55 B, likely irreducible)

Montgomery-n: n's top limb at W=24 is 0xffff (16 bits), not
0xffffff. tiny.S's q=t[top] reduce needs top limb all-ones. Ours
isn't. So: cR2_n (32 B) + decode (~5) + bc_v1 ops for s_mont,
1_mont_p, r_mont, n_mont (~14 B). Confirmed no workaround.

## Size breakdown (1312 B)

| Chunk | B | Notes |
|---|---|---|
| bytecode | 183 | 87 RCB + 21 v3 + 75 v1 |
| constants | 160 | 5 × 32 LE |
| .Ljt + handlers | ~330 | INV 53, NORM+helpers ~80 |
| decoders | ~55 | fe_from_be calls fe_from_le |
| fe_mul11 + .Lcnt | ~126 | CIOS, shares .Lcp |
| .Lcadd + bc_run | ~100 | |
| pt_mul | ~93 | .Lai inlined |
| verify | ~245 | |

## Slot map (current — load-bearing for bc_v1 sequencing)

| Slot | bc_v1 entry | bc_v1 exit | RCB-safe? |
|---|---|---|---|
| 0-2 | — | — (acc) | written by RCB |
| 2,3 | Gx_mont, Gy_mont | same | written by RCB |
| 4 | temp | 1_mont_p (Z_G) | written by RCB |
| 5,6 | Qx, Qy plain | Qx_mont, Qy_mont | ✅ never written |
| 7 | e (hash) | 1_mont_p (Z_Q) | ✅ never written |
| 8 | cP | cP | ✅ never written |
| 9 | cN | cN | ✅ never written |
| 10 | — | b_mont | ✅ never written |
| 11 | r plain | u1 normalized | written by RCB |
| 12 | s plain | u2 normalized | written by RCB |
| 13 | — | — | written by RCB |
| 14 | cR2_n | r_mont | ✅ never written |
| 15 | cR2_p | n_mont | ✅ never written |

RCB-safe = slots 5,6,7,8,9,10,14,15. b_mont, r_mont, n_mont survive
all 264 pt_mul iterations. Addend (5-7) is written by .Lcadd's
rep movsq each iteration but never by the RCB bytecode itself.

## Commit hygiene

Granular. One trick per commit. 607/607 before any size claim.
20-run median for cycles (5-run gave a 5% false delta once). Update
progress.csv at working checkpoints. **Pushing OK now (repo private).**
