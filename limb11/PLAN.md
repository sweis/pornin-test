# 11×24 track — plan

**Target:** < 928 B (Thomas's number with 5×54).
**Current:** fe_mul alone at 158 B, full impl not yet at 607/607.
**Constraint:** work only in this directory. Don't touch tiny.S.

---

## 1. Reference baseline — get it WORKING, no golf

The first-pass number is a starting point, not a verdict. Don't golf
during the build — we don't know which tricks survive the new shape.

### What "working" means

607/607: 33 hand-picked edge cases + 574 Wycheproof. Same gate as
tiny.S. `make test` must pass before any size claim.

### Build order (each step testable in isolation)

| Step | Piece | Test | Blocks |
|---|---|---|---|
| 1.1 | fe_mul11 (done — 158 B, 103/103) | `make test-mul` | — |
| 1.2 | fe_from_be (decoder) | standalone unit | — |
| 1.3 | Fadd/Fsub limbwise | standalone unit | — |
| 1.4 | NORM (to [0,p), to [0,n)) | standalone unit | — |
| 1.5 | fe_inv_n (Fermat) | standalone unit | 1.1, 1.4 |
| 1.6 | bc_rcb wired (slot remap 9→12, 15→13) | one RCB call vs Python | 1.1-1.3 |
| 1.7 | bc_v1 (range checks, b-derive, convert, invert, u1/u2) | — | 1.1-1.6 |
| 1.8 | pt_mul nested 11×24 | one scalar-mul vs Python | 1.6, 1.7 |
| 1.9 | bc_v3 (projective check) | — | 1.8 |
| 1.10 | Full 607/607 | `make test` | all |

### Known issues to fix during phase 1

Flagged in `tv_ecdsa.S` and `gen_bytecode.py` comments:

- **bc_v1 slot collision**: u2 writes slot 3 (Gy) before Shamir
  backup needs it. Fix: u1→12, u2→11, n_mont→15.
- **fe_inv bt-on-cN**: cN stored BE, `bt` indexes LE bits. Options:
  (a) store cN twice (+32 B), (b) byteswap-on-read (+~5 B in loop),
  (c) store cN LE in rodata, convert to limbs differently. Lean (c).
- **.Lai (accumulator = ∞)**: sets Y=1 plain. Need to verify
  RCB(0:1:0, Q) = Q with plain Y in a Montgomery context. If the
  algebra cares about Y's R-factor when X=Z=0, need Y=1_mont = R.
  Test empirically: one RCB call with Y=1 vs Y=R, compare outputs.
- **R²_n constant**: needed for s → Montgomery-n. +32 B.
- **Ops SET1/COPY/NORMN**: not yet in skeleton. ~15 B each.
- **CHKZ semantics inverted for Z≠0 check**: CHKZ sets fail-bit if
  nonzero; we need fail-if-zero for the ∞ check in bc_v3. Either
  add CHKNZ op or invert in native code.

### Baseline size guess

~1050–1100 B. Heavy caveat: session estimates were ~86 B pessimistic
vs the assembler. The pieces share code in ways flat summing misses.

---

## 2. Known tricks — re-apply the full catalog

tiny.S went 2873 → 933 via ~130 commits. Every trick in that journey
was tried against the 32-bit q=t[top] shape. With 11×24 the
constraint landscape is DIFFERENT. Re-try everything, including
tricks marked FAILED in tiny.S's history.

### Structural (the big wins in tiny.S's journey)

| Trick | tiny.S Δ | 11×24 applicability |
|---|---|---|
| Bytecode interpreter | −1161 | **already in** — same framework |
| Drop Montgomery → q=t[top] | −97 | **inverted** — we ADD Montgomery. The reduce is still simple (m0inv=1 for p) but different |
| Projective final check | −21 | **already in** — d1·d2≡0 test |
| bt on cN directly (no n−2 buffer) | −19 | **applicable** — same bit trick (n vs n−2 differ only in bits 1-4). BE/LE issue to solve |
| RCB complete addition | −59 | **already in** — same formula, remapped |
| Addend slot shift (Shamir → one movsq) | −16 | **applicable** — but the contiguous-source setup needs rethinking with 88 B slots (33 qwords not 24) |
| cP built at runtime | −6 (knock-on) | **applicable** — p has 4 zeros + 4 all-ones, very sparse. Different stosq sequence |
| EFD reschedule (disp8 reach) | −2 | **different** — 88 B slots mean no two non-adjacent slots fit disp8 from each other. The trick still works (reorder bc_rcb to free a slot closer to something) but the target is different |

### Micro-grind (small but they add up)

| Trick | tiny.S Δ | 11×24 applicability |
|---|---|---|
| push;pop = 2B mov | ~−10 | **same** |
| Short jump layout | ~−15 | **different map** — handler block is smaller (Fadd/Fsub 16 B each vs 59 B total), fe_mul is bigger. Different rel8 reach. Re-survey |
| Fall-through | ~−15 | **different opportunities** — Fmul/Nmul still share via fall-through. fe_mul11's carry-prop might fall into something |
| rep movsq dataflow | — | **same** — but 33 qwords per 3-slot copy (not 12), different counts |
| loop vs dec;jnz (size vs speed) | +14 or −3 | **same choice** — inner loop runs ~K² × 256 × 12 ≈ 370K times. loop is smaller, dec;jnz faster |
| rcx=0 flow | ~−8 | **different sources/sinks** — fe_mul11's rep stosq zeroes rcx. Fadd/Fsub's loop exits with rcx=0. Re-map the flow |
| `.rodata` before `.text` for push imm8 | — | **same** — bytecode offsets still need to fit imm8. bc_v1 is bigger now (~75 B), push obc_v1 margin is different |
| u8 jump table (handlers within 255 B) | — | **more headroom** — Fadd/Fsub shrink the handler block by ~27 B. fe_inv can be FURTHER from .Ljt or something new can inline |
| movbe loop for BE decode | — | **different** — 3-byte-aligned means bswap+shr not movbe qword |

### Tricks that FAILED in tiny.S — retry

From "Things that didn't work" (§11 of tinyp256.tex):

| Failed trick | Why it failed | 11×24 reconsideration |
|---|---|---|
| Merge schoolbook+reduce into one loop | Carry overflow (~1 in 2^30 inputs) | **Montgomery's single shared inner loop IS the merge** — both phases add, same body. Already doing this. ✓ |
| Zero-skip in scalar loop | Branch mispredict (bits are random) | **still bad** — same reason. Don't retry. |
| Solinas for both moduli | n doesn't have sparse form; 2 reducers | **same** — Montgomery handles both with m0inv, which is what we do |

Others from commit history (grep for "revert" / "back out" in git log):

```
git log --all --oneline | grep -iE "revert|back.?out|doesn.t work"
```

Run this and re-evaluate each against the new shape.

---

## 3. New tricks unique to 11×24 (or that DIDN'T work for 32-bit)

### Already exploited

- **MASK = 0xFFFFFF fits imm32** — `and eax, 0xFFFFFF` is 5 B inline
  (eax short form). No movabs, no register preload. Used in fe_mul11.
- **One-operand `imul rbx`** — product fits 60 bits, rdx is
  sign-extension junk. 3 B vs 4 B for `imul rax, rbx`. Used.
- **enter/leave for the frame** — acc is 176 B (> 127), so `sub rsp`
  needs imm32 (7 B). `enter 176,0` is 4 B. Saved 11 B in fe_mul11.
- **`push rsp; pop rdi`** — after enter, rsp = rbp−176. 2 B to get
  the acc base, vs 7 B `lea rdi,[rbp-0xb0]`. Used twice.
- **.Lcnt helper** — `mov cl,K` falls through to .Lin. 2 call sites
  save 2 B each = −2 net.

### To explore

- **p/n share limbs 9-10** (both end in [0xffff00, 0xffff] — top
  32 bits identical). If cP and cN are adjacent in memory, the tail
  is shared. Or: build cP, then overwrite limbs 0-8 for cN. Could
  save ~16 B of constant/build code.

- **p has 4 zeros + 4 all-ones** (out of 11 limbs). Build sequence:
  ```
  stosq×4 (MASK); stosq×4 (0); then 1, 0xffff00, 0xffff
  ```
  The first 8 are trivial. The last 3 are small. vs tiny.S's 17 B
  stosd sequence for 8 dwords. Likely +~20 B (more limbs, bigger
  values) but the ZERO limbs are free if rax is already 0 from
  something else.

- **n's m0inv = 0xBC4F fits imm16** — `imul eax, eax, 0xBC4F` needs
  imm32 (6 B, no imm16 form). But `mov r11w, 0xBC4F` is 5 B (66 41
  BB 4F BC), then `imul eax, r11d` is 4 B. 9 B total ONCE (in Nmul),
  vs 6 B per call if inline. If fe_mul11's reduce loop has ONE imul
  by r11d (set by caller: 1 for p, 0xBC4F for n), the per-call is
  4 B and Nmul/Fmul set r11.

- **24 bits = 3 bytes — decoder is byte-aligned**. Already in the
  skeleton (`mov eax,[rsi-1]; bswap; shr 8`). But the READ-BEHIND
  (one byte before the 3 we want) means the FIRST iteration reads
  byte 28, which is valid. The LAST (top limb) reads before the
  buffer — needs special case. If we can guarantee a valid byte
  before every input (e.g., decode from a SCRATCH BUFFER we control),
  the special case goes away. Verify copies inputs to scratch first
  anyway for some constants.

- **MontMul(plain, mont) = plain** — only s needs Montgomery-n
  conversion. e, r stay plain. u1 = MontMul(e, w_mont) is plain.
  Saves 2 conversions. Already in bc_v1 draft.

- **Montgomery preserves zero** — the final d1·d2 ≡ 0 check is
  R-factor-oblivious. No conversion out of Montgomery needed for
  the result. Already relied on.

- **Carry-prop body is shared structure** — fe_mul11's carry-prop
  (`lodsq; add rax,rdx; mov rdx,rax; and; stosq; sar`) is NEARLY
  identical to NORM's carry-prop. If NORM calls into fe_mul11's
  `.Lcp` as a subroutine, the ~20 B body is written once. Needs
  the I/O to match (rsi/rdi/rdx convention).

- **Fadd and .Laddp (p += limbwise) share a body** — both do
  `lodsq; add [rdi], rax; scasq; loop`. Fadd reads from rdx,
  .Laddp reads from rcx (cP). If rcx is loaded into rsi first:
  ```
  .Laddp: push rcx; pop rsi   ; then fall through to...
  .Ladd_body: lodsq; add [rdi],rax; scasq; loop; ret
  ```
  Fadd would need to swap rsi/rdx too. Might net −10 B if the
  shared body is 12 B and there are 3 callers.

- **SET1 is nearly free** — `xor eax,eax; mov cl,K; rep stosq;
  inc qword [rdi-88]`. That's 11 B. Used twice (1_mont_p seed,
  1_mont_n seed). Could be a bytecode op with a ~13 B handler.

- **13-operand jump table** — I've added ops up to 12 (NORMN).
  16 slots in a nibble. 3 free ops. Could add: CHKNZ (for the
  ∞ check), MULR2N (Nmul with s2 = cR2_n slot), or a combined
  NORM+CHKZ (normalize then check zero — bc_v3's pattern).

- **`imul r,r,88` fits imm8** — 88 < 128. The bc_run slot-decode
  via `imul edi, edi, 88` is 3 B. No worse than tiny.S's lea×2
  for the low nibble; +2 B for the high nibble (need shr first).

### Things that got HARDER

- **disp8 slot reach** — 88 B stride means only slot 0 is in disp8
  from base. tiny.S's r8-at-slot8 → slot5-at-r8−96 trick: with
  88 B, slot8 = 704, slot5 = 440, r8−264 doesn't fit disp8. No
  equivalent trick available. Every native lea to a slot is disp32
  (7 B). Mitigation: minimize native slot touches — do more via
  bytecode, less via lea.

- **cP at slot 8 headroom trick** — tiny.S's "cP between jump table
  and handlers frees 32 B of u8-table headroom" — cP is now 88 B
  (11 qwords) if stored as limbs. If it's between .Ljt and handlers,
  handlers are 88 B further away. Might BLOW the u8 table. Store
  cP ELSEWHERE (built into a slot, not in .text/.rodata).

- **`mov cl, N` after rcx=0** — still works the same, but fewer
  natural rcx=0 points. fe_mul11's rep stosq gives one. Fadd/Fsub's
  loop exit gives one. Map them.

---

## 4. Progress tracking

`progress.csv` — one row per WORKING checkpoint (607/607 pass, or
a pre-607 unit-test milestone with cycles=0).

Format: `commit,bytes,cycles,note`

Merge into `../docs/progress.png` LATER once the track proves out.
Don't pollute the main frontier with a non-dominating point. First
entry that matters: the 607/607 baseline.

When recording cycles: 20-run median (feedback_bench_noise.md — 5
runs gave a 5% false delta once). Tests pass BEFORE bench.

---

## 5. Focus discipline

**Only this directory.** Don't touch:
- `../tv_ecdsa_tiny.S` — the 933 B reference stays frozen
- `../docs/` — chart merge happens later
- `../fast2.S`, `../speed.S` — different tracks

If a trick discovered here ALSO applies to tiny.S: note it in this
file under a "cross-pollination" heading, don't go apply it there
mid-stream.

**Don't push.** User: "the next phase we may want to keep private."
Commit locally only.

---

## Cross-pollination (tricks found here that might help tiny.S)

(Nothing yet. Add as discovered.)
