# Dead Ends — Do Not Retry

Master index. Each entry: WHY it's dead (absolute vs conditional) + cross-ref.
Detail lives elsewhere; this file stays ≤5 lines/entry.

---

## Architectural

### Shamir-free via Hamburg signed-binary ladder
+277 B measured, structural floor ~+110 B. Three missed cost centers:
conditional init (bytecode can't branch, ~50 B), two-call verify tail
(+117 B — arg setup ×2 + 3-way combine for tcId 204), Jacobian/homogeneous
mismatch (+33 B). RCB completeness costs only 7 B at bytecode level; the
infrastructure to avoid it costs 100+ B. → `docs/hamburg_assessment.md`

### WW-AMM single-iteration s=256
`−p⁻¹ mod 2^256 ≠ 1` — the "free q" conflated per-limb m0inv (=1 at
W≤96) with full-width. And CIOS already IS the factored form: `.Lcnt`
called 2×/row; commits 6de9a83/6ff298a eliminated the separate loops
WW-AMM reintroduces. +110 B best case. → `docs/ww_amm_sketch.md`

### GLV / endomorphism scalar splitting
P-256 j-invariant ∉ {0,1728} → no CM endo. Fake-GLV needs SNARK hints.
Antipa 2005 runs EEA natively — adds code, saves only time.
→ `docs/literature_survey.md`

### wNAF for size
"−64 adds" are runtime executions, not code bytes. Bytecode is 2 B/op
regardless of call count. Encoder ~30–50 B is pure overhead. (Still
useful for SPEED at fast2.S corner.) → `docs/literature_survey.md`

### Post-RCB addition formulas
Nothing post-2015 (EFD enumerated, max year 2015). Fay 2014 has FOUR
exception cases. Size wins must come from implementing RCB differently,
not a different formula. → `docs/literature_survey.md`, `memory/reference_efd.md`

### Bytecode gadgets in constants / instruction encodings
62–68% valid-op density — random bytes look valid by chance. Zero ≥4-B
matches. Only clean frameshift gadget (limb8 byte 71) contains spurious
INV. cN zero-zone walled by 8 bytes of `0xff`. → `docs/gadget_hunt.md`

### Native x86 tail-sharing / ROP
One win (`stosq;ret` tail merge, −1 B, **applied** commit 7c4ad0e).
INV/fe_mul11 4-B merge conditional on handler reorder (rel8 ripple risk,
not taken). Too few ret-blocks for birthday collisions; code too dense
with 1–2 B ops for offset-decode. → `docs/native_gadgets.md`

---

## x86 encoding tricks

### `cwde` after `lodsw` (limb11 fe_from_le top limb)
cN top16=0xFFFF, cGX=0x905F — both bit15 set → sign-extends wrong. Off
by 2^256. Rule ("bit15 clear → 1-B movzx") correct; constants break it.
→ `docs/x86_tricks.md`

### `salc`, `aad`/`aam imm8`, BCD adjusts, `pusha`/`popa`
SIGILL in 64-bit. VEX reclaimed the opcode space. Use `sbb al,al` (2 B).
→ `docs/x86_tricks.md`

### Segment-register scratch storage
`mov ds,eax` nonzero segfaults — selector still validated. Zero-only
scratch is useless. → `docs/x86_tricks.md`

### AVX/BMI1/BMI2/ADX for size — limb8 MEASURED, MOVBE-only relaxed
All VEX-encoded (4-6 B). Measured against 890 B SMALL_MUL8 baseline:
**vptest .Lop6** (SLOT=32B=1 YMM, best-fit track): 891 B, +1 B. `push 4;
pop rcx;xor eax,eax;repe scasq` = 8 B vs `vmovdqu;vptest` = 9 B. Both
need `sete al` (3 B). vzeroupper at exit would add 3 B more. **vmovdqu
3-slot copy** (.Lcadd): 32 B vs `mov cl,12;rep movsq` 5 B — +27 B.
**bextr nibble decode**: 39 B body + 18 B ctrl preload vs 34 B — current
exploits bit-position-as-scaling (`and edi,-16;lea [r14+rdi*2]` = nibble
×32 in 7 B). **mulx**: 5 B (32-bit) or 5 B (64-bit) vs `lodsd;mul` 3 B /
`lodsq;mul` 5 B; no rsi advance so +4 B lea. **blsr/blsi/blsmsk**: no
`x&(x-1)`/`x&-x` pattern exists. **vpbroadcastq cP**: cP has 4 distinct
dword values (FFFFFFFF/0/1/FFFFFFFF), not broadcastable. → `docs/x86_tricks.md`

### `call [rbx+rax*8]` dispatch
+74 B vs xlatb — 8-B vs 1-B table entries dominate. → `docs/x86_tricks.md`

### `lahf`/`sahf` CF transport (limb11)
No topology fits. All CF uses are immediate set→jcc (zero gap). NORM's
push/pop preserves a 64-bit direction, not a flag. `.Lasmod`'s `lodsq`
would clobber AH anyway. → `docs/x86_tricks.md`

### `std+repe cmpsq` for limb8 `.Lop5`
+1 B measured. `loopz` + `[reg+rcx*8-8]` SIB already gets high→low
scan free. std/cld needs +8 B pointer setup. Only beats a branchy
`jb`/`ja` baseline. → `docs/x86_tricks.md`

---

## Per-track port blockers

### xlatb → limb8
fe_inv_m uses rbx as loop counter and calls Nmul internally; Nmul can't
find `rbx=&.Ljt` from there. Montgomery tracks' INV is a bytecode op,
no conflict. Net +1 B even with restructuring. → commit db6dad8

### mov cl audit → limb8
Every remaining `push N;pop rcx` site has rcx = r8 (full stack addr
from decoder). High bytes nonzero.

### shr-bitmask → limb8
limb8 decode is movbe-inline, not fe_from_be call-chain. No alternating
chain-vs-pop pattern to encode.

### `.Lop6` `or ebp,eax` → limb8
.Lop6 eax is clean (scasq never writes rax) but .Lop5's `mov rax,[...]`
leaves slot data high. Shared `.Lor` constrains both to `or bpl,al`.
Unsharing costs more. → commit d3e0868

---

## Byte-level (tried, measured, lost)

### Fall-through .Lfmul→fe_mul11 (limb11, pre-shrink)
Initially failed (handlers 297 B > u8 jt limit). **RETRIED SUCCESSFULLY**
after CHKNZ drop + INV cmp drop brought it under 256. → commit 5d8eb1f
**Layout-dependent wins can unlock after unrelated shrinks. Don't
permanently dismiss.**

### Zero-fill share .Lset1 ↔ cP builder (limb11)
call overhead 5 B × 2 sites = 10 B; saves 3 B/site. Break-even at 3;
only 2 exist. Net +2 B.

### CHKZ/CHKNZ merge via cmc/pushf/stc (limb11, pre-dst-flip)
All variants 27–33 B vs 27 B baseline. call rel32 (5 B) exactly offset
the simpler tail. Dst-flip made moot (−2 B, different mechanism).

### addend@slot0 / acc@slot5 swap (limb11)
.Lcadd lea saves 4 B, pt_mul lea costs 4 B. Net 0. 88-B stride → only
slot 0/1 reach disp8.

---

## Protocol

Add entries WITH THE WHY. Absolute (WW-AMM's m0inv math) vs conditional
(fall-through needed handler shrink first) matters — tells future
sessions whether to retry after unrelated changes. Cite the measurement.
