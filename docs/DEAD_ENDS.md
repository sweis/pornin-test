# Dead Ends — Do Not Retry

Consolidated index. Each entry explains WHY it's dead so future
sessions don't redo the analysis. Grouped by scope.

---

## Architectural (whole-approach)

### Shamir-free via Hamburg signed-binary ladder
**Why dead:** +277 B measured (prototype at 1168 B), structural floor
~+110-140 B. The literature survey's "−30 to +20 B" counted bytecode
ops and missed three asm cost centers:
1. **Hamburg conditional init (~50 B):** bytecode can't branch. Test
   scalar bit 0 → odd path vs even path (4× NOT qword for negate).
   RCB's init is 12 B flat (zero 3 slots + poke 1).
2. **Two-call verify tail (+117 B):** arg setup × 2; bc_norm corrupts
   slots between calls; combine = save R1 → bc_add → check Z → check
   X → restore → bc_dbl. vs limb8's 27-B tail.
3. **Coordinate mismatch (+33 B):** CMO98 Jacobian, we're homogeneous.
   Final combine needs one input affine → mod-p inversion.

**The deep finding:** RCB's 43-op COMPLETE formula costs only 7 B more
than bc_dbl(43)+bc_add(37)=80 B incomplete. Branch-free completeness
is nearly free at the bytecode level — RCB is MORE efficient than the
op-count suggests.

tcId 204 (u1·G = u2·Q, expected VALID) mandates full 3-way combine.
The Hamburg invariant DOES hold for u ∈ [1,n−1] (u=1 fine; only u=0
needs special case) — the survey's correctness concern was unfounded,
but the size estimate was catastrophically off.
→ `docs/hamburg_assessment.md`

### WW-AMM single-iteration s=256
**Why dead:** `−p⁻¹ mod 2^256 = 0xffffffff00000002…00000001`, not 1.
The survey conflated per-LIMB m0inv (=1 at W≤96, because p's low W
bits are all-ones) with FULL-WIDTH m0inv. For n, unstructured at every
width. Plus: CIOS already IS the factored form (`.Lcnt` called 2×/row);
commits 6de9a83/6ff298a are "CIOS merge" which eliminated the separate
loops WW-AMM reintroduces. **+110 B best case.**
→ `docs/ww_amm_sketch.md`, `docs/literature_survey.md`

### GLV / endomorphism scalar splitting
**Why dead:** P-256 j-invariant ∉ {0,1728} → no CM endomorphism.
Fake-GLV (ePrint 2025/933) depends on SNARK prover hints. Antipa 2005
runs EEA natively — adds code (EEA primitive, sqrt mod p, 4-point
Shamir), saves only time.
→ `docs/literature_survey.md` (3-0 vote)

### wNAF for size
**Why dead:** "−64 additions" are runtime executions, not code bytes.
Bytecode is uniform 2 B/op regardless of call count. Encoder (~30-50 B)
and on-the-fly negate are pure additive overhead. With RCB,
doubling=addition so there's no separate doubling to simplify.
(Still useful for SPEED at the fast2.S corner.)
→ `docs/literature_survey.md` (reframe of 3-0 claims)

### Post-RCB addition formulas
**Why dead:** Nothing post-2015. Triple-verified: EFD enumeration (max
year 2015), .op3 line-count (t0-t4, 43 lines), WebSearch 2016-2025.
Fay 2014 has FOUR exception cases. Susella-Montrasio 2017 refuted as
ladder-style. **Any size win must come from implementing RCB
differently, not a different formula.**
→ `docs/literature_survey.md`, `memory/reference_efd.md`

### Bytecode gadgets in constants / instruction encodings
**Why dead:** Encoding 62-68% dense — random bytes look valid by
chance but aren't useful. No ≥4-B subsequence match. Frameshift
terminators exist (3 at odd bc_rcb offsets) but the only 3-op clean
gadget (limb8 byte 71) contains spurious INV. cN zero-zone walled by
0xff invalid-ops. Stream boundaries trash slot 0.
→ `docs/gadget_hunt.md`

---

## x86 encoding (specific tricks)

### `cwde` after `lodsw` for limb11x24 fe_from_le top limb
**Why dead:** cN top16=0xFFFF, cGX=0x905F — both have bit 15 set.
cwde SIGN-extends → off by 2^256. The general rule ("if top bit
clear, 1-B movzx") is correct; these specific constants break it.
→ `docs/x86_tricks.md` line 776 (marked BROKEN)

### `salc`, `aad imm8`, `aam imm8`, BCD adjusts
**Why dead:** SIGILL in 64-bit mode. VEX reclaimed the opcode space.
Tested empirically. Use `sbb al,al` (2 B) instead of salc.
→ `docs/x86_tricks.md`

### Segment-register scratch storage
**Why dead:** `mov ds, eax` with nonzero selector segfaults —
selector still validated even though segmentation is mostly disabled.
→ `docs/x86_tricks.md`

### BMI1/BMI2/ADX for size
**Why dead:** All VEX-encoded (5-6 B). Never beat legacy equivalents.
`bextr`/`pdep`/`pext`/`mulx`/`adcx` are speed tools.
→ `docs/x86_tricks.md`

### Computed dispatch `call [rbx+rax*8]`
**Why dead:** +74 B vs current `xlatb` scheme — 8-byte vs 1-byte
table entries. Current approach is optimal.
→ `docs/x86_tricks.md`

### `lahf`/`sahf` CF transport (limb11x24)
**Why dead:** No topology fits. All CF uses are immediate set→jcc (shr→jc,
bt→jnc, neg→rcl) — zero gap. The only push/pop-across-call is NORM's
`push rdx`/`pop rdx` (2 B), which preserves a 64-bit direction {0,−1},
not a flag. .Lasmod's `lodsq` clobbers rax so AH wouldn't survive even
if the direction were flag-encoded. Register stash (r8-r11 survive
.Lasmod) is 3+3=6 B — worse than push/pop. shr-bitmask loop already
optimal (jc/pop preserve shr's ZF for free).

### `std+repe cmpsq` for limb8 `.Lop5`
**Why dead:** +1 B prototyped. The estimate missed that `loopz` with
`[reg+rcx*8-8]` SIB already gets high→low scan FOR FREE. `std+repe
cmpsq` needs 8 B pointer setup (`add r,24` × 2 — rcx is &cP on entry,
not zero). Body saves 7 B, setup costs 8 B. Net 21 B vs current 20 B.
Only applies when baseline is a branchy `jb`/`ja` loop OR when bc_run
hands pointers already at the high limb.
→ `docs/x86_tricks.md` §5.3

---

## Per-track port blockers

### xlatb → limb8
**Why blocked:** fe_inv_m uses rbx as its loop counter and calls
Nmul internally. Nmul can't find `rbx=&.Ljt` when called from there.
Montgomery tracks' INV is a bytecode op, so no conflict. Net +1 B
best case even with restructuring.
→ commit db6dad8 message

### mov cl audit → limb8
**Why blocked:** Every remaining `push N; pop rcx` site has rcx = r8
(full stack address from decoder's `mov rcx, r8`). High bytes nonzero.
→ limb8-concrete-890 agent findings

### shr-bitmask → limb8
**Why blocked:** limb8's decode is movbe-inline, not fe_from_be
call-chain. No alternating chain-vs-pop pattern to encode.
→ limb8-concrete-890 agent findings

### `.Lop6` `or ebp,eax` after `repe scasq` → limb8
**Why blocked:** .Lop6's eax is clean (scasq never writes rax) but
.Lop5's `mov rax,[...]` leaves slot data in high bits. Shared `.Lor`
constrains both paths to `or bpl,al`. Unsharing costs more than saved.
→ commit d3e0868 message

---

## Byte-level (tried, measured, lost)

### Fall-through .Lfmul→fe_mul11 in limb11x24 (PRE handler shrink)
**Why it initially failed:** Handlers+helpers were 297 B, need <256
for u8 jt. **RETRIED SUCCESSFULLY** after CHKNZ drop (−10) + INV cmp
drop (−7) brought it under threshold. → commit 5d8eb1f
**Lesson: layout-dependent wins can unlock after unrelated shrinks.
Don't permanently dismiss.**

### Sharing zero-fill between .Lset1 and cP builder (limb11x24)
**Why dead:** call overhead is 5 B rel32 × 2 sites = 10 B. Savings
is 8 B → 5 B per site = 3 B each. Break-even at 3 sites; only 2 exist.
Net +2 B.

### CHKZ/CHKNZ merge via cmc/pushf/stc (limb11x24, before dst-flip)
**Why dead:** All variants measured 27-33 B vs original 27 B. The
call rel32 overhead (5 B) exactly offset the simpler tail. Then the
dst-flip trick made this moot (−2 B, different mechanism).

### addend@slot0 / acc@slot5 swap (limb11x24)
**Why dead:** .Lcadd's lea saves 4 B, pt_mul's mov rsi,r14 → lea
costs 4 B. Net 0. The 88-B slot stride means only slot 0/1 reach
disp8; everything else is disp32 either way.

---

## Protocol for adding entries

When you find something doesn't work, add it here WITH THE WHY. The
"why" is load-bearing — it tells future sessions whether the dead end
is absolute (WW-AMM's m0inv math) or conditional (fall-through needed
handler shrink first). Cite the commit/doc that has the measurement.
