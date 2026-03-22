# Dead Ends — Do Not Retry

Master index. Each entry: WHY it's dead (**absolute** = math won't
change / **conditional** = may unlock after shrinks / **attack-specific**
= goal not dead, just this attack on it). Cite measurement.

Grep-able index in `docs/TRICKS_LEDGER.md`.

---

## Architectural

### Shamir-free via Hamburg signed-binary ladder — ABSOLUTE

**+277 B measured** (prototype 1168 B vs limb8 891). Structural floor
~+110 B. The survey's −30 to +20 B band counted bytecode ops, missed
three asm cost centers:

| Component | limb8 | hamburg | Δ |
|---|--:|--:|--:|
| pt_mul / scalar_mult | 74 | 141 | **+67** — conditional init |
| verify tail | 158 | 335 | **+177** — two-call structure |
| Fadd..fe_inv_m | 99 | 114 | +15 — mod-p inv parameterization |

**Conditional init (~50 B):** test scalar bit 0; odd-path copies
u→slot3 + selects Py_pos; even-path does 4× `not qword ptr`. Bytecode
can't branch — irreducibly native. RCB's init is 12 B flat because
completeness handles ∞+Q=Q in-formula.

**Two-call verify tail (floor ~+117 B):** 2× call setup with arg
marshalling, R2 stash, inter-call cN restore, u1==0 check, 3-way
combine (tcId 204 mandates: Z=0∧X=0→double; Z=0∧X≠0→reject; Z≠0→done).
14 pieces at 8–18 B each.

**Coordinate mismatch (+33 B):** CMO98 is Jacobian, RCB homogeneous.
Combine needs mod-p inversion → fe_inv_m parameterized for both moduli.

**Deep finding:** bc_rcb (87 B complete) vs bc_dbl+bc_add (80 B
incomplete) — RCB's completeness costs only **7 B at bytecode level**.
Infrastructure to avoid it costs 100+ B. Rescue attempts (keep bc_rcb
for combine only, full-Jacobian CMO98, skip tcId 204) all net-negative
or FIPS violations. Correctness concern (Hamburg invariant for
u∈[1,n−1]) was unfounded — u=1 works fine; only u1=0 special.

### WW-AMM single-iteration s=256 — ABSOLUTE

**+110 B best case.** Two independent killers.

**Premise is false:** the "m0i=1 kills call #2" conflated per-LIMB
m0inv (=1 for W≤96, because p's low 96 bits are all-ones) with
full-width:
```
−p⁻¹ mod 2^256 = 0xffffffff00000002_..._00000001_..._00000001  ≠ 1
```
Direct test on 5 random inputs: `(T + T_lo·p) mod 2^256` nonzero every
time — low 96 bits clear, bits 96–255 don't. For n: m0inv unstructured
at every width.

**CIOS already IS the factored form:** `.Lcnt` (15 B: mov cl,K; lodsq;
imul rbx; add [rdi],rax; scasq; loop; ret) is called 2×/row. Commits
6de9a83 (limb11 −7) and 6ff298a (limb5 −18) are "CIOS merge" —
eliminated the separate loops WW-AMM reintroduces. Not applicable to
limb8 (no Montgomery — q=t[top] direct).

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

### Bytecode gadgets in constants / instruction encodings — ABSOLUTE
62–68% valid-op density — random bytes look valid by chance. Zero ≥4-B
matches. Only clean frameshift gadget (limb8 byte 71) contains spurious
INV. cN zero-zone walled by 8 bytes of `0xff`. → `docs/GADGETS.md`

### Native x86 tail-sharing / ROP — mostly ABSOLUTE
One win (`stosq;ret` tail merge, −1 B, **applied** commit 7c4ad0e).
INV/fe_mul11 4-B merge CONDITIONAL on handler reorder (rel8 ripple
risk, not taken). Too few ret-blocks for birthday collisions; code too
dense with 1–2 B ops for offset-decode. → `docs/GADGETS.md`

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

## stupid/ track dead ends

See `TRICKS_LEDGER.md` for tagged list. Key ABSOLUTE entries:
- **4-bit operand encoding** — 30 distinct slots, need 5 bits
- **RCB reschedule** — acc-VM: slot count free, only LD/ST count
  matters, already minimal
- **decode_int qword variant** — REX on lodsq/bswap/stosq = 18 B vs
  13 B byte-loop
- **Gx/Gy compression** — no zeros, no RLE; 64 raw bytes irreducible

**ATTACK-SPECIFIC** (reframed and won — instructive, keep):
- `call docopy` "+1 B, can't return" — S6 reframed: set up CALL stack
  first, tail-jump, docopy's ret IS the return (−2 B)
- slot-1-as-modulus "break-even: saved_rsp reloc + ONE disp32" — S3
  different exit mechanism (`leaq 1088(%rbp)`) + slots 30/31 (−4 B)

---

## Protocol

**Record GOAL separately from ATTACK.** "share docopy: call rel32 is
+1, tail-jump requires no-continue" — not "share docopy: dead."

**Three categories:**
- **Absolute** — math won't change (WW-AMM m0inv, 4-bit encoding).
  Don't retry.
- **Conditional** — blocked by byte-accounting (rel8 doesn't fit by N).
  Retry after N bytes accumulated elsewhere.
- **Attack-specific** — this mechanism failed, goal may have others.
  The tell: justification contains an assumed constraint ("because X
  continues after," "while keeping Y"). Check if that constraint is
  actually required.

Cite the measurement. Write the FULL blocking condition, not just the
net delta.
