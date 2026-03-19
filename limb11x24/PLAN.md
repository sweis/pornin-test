# 11×24 track — plan

**Target:** < 928 B (Thomas's number with 5×54).
**Current:** 1312 B, 607/607 pass. Phase 2 grind. See `HANDOFF.md`.
**Constraint:** work only in this directory. Don't touch tiny.S.

---

## 1. Phase 1 — DONE (1488 B baseline at 1260a47)

607/607 from the first working build. Baseline was +438 B over the
pre-build estimate — the pieces shared less than expected, plus two
decoder bugs that needed fixing first:

- `bswap; shr 8` drops the LOW byte after bswap — want `and MASK`
  (the low 3 bytes ARE the limb). Symptom: all VALID tests fail,
  all INVALID pass. Systematic compute-path bug.
- fe_from_le left rsi at src+30, not src+32 — chained constant
  decodes drifted 2 B per call, eventually reading cGY's tail as cN.

Phase 1 decisions that stuck:
- Constants stored LE (natural quad order). `bt [cN], ebx` works
  directly in INV; fe_from_le is simpler than fe_from_be.
- NORM: subtract-until-negative-then-add-once. No top-limb-equality
  infinite loop (the earlier skeleton's while-ge-p had this trap).
- .Ljt in .text (same section as handlers for u8-offset subtraction).
- `push K; pop rcx` everywhere bc_run leaves rcx dirty (it lea's a
  stack address there). The rcx=0 memory caught this proactively.

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
