# Session handoff — 2026-03-18

**Read this first.** Then `PLAN.md` for the trick catalog.

## Where we stopped

Phase 1 (reference baseline) partially complete. fe_mul11 works;
the full verifier does not build yet.

| Phase 1 step | Status |
|---|---|
| 1.1 fe_mul11 | ✅ 158 B, 103/103 (`make test-mul`) |
| 1.2 decoder | sketched in tv_ecdsa.S, not unit-tested |
| 1.3 Fadd/Fsub | sketched, not tested |
| 1.4 NORM | sketched, not tested |
| 1.5 fe_inv_n | sketched, has bt-on-BE bug |
| 1.6 bc_rcb | ✅ generator validated (87 B, slot-lifetime clean) |
| 1.7 bc_v1 | ⚠️ draft has slot collision, fix known |
| 1.8–1.10 | not started |

## The exact next action

```
cd limb11
# Fix bc_v1 slot collision in gen_bytecode.py (see below), then:
make regen         # → bytecode.inc
# Paste bytecode.inc into tv_ecdsa.S (replacing the .error),
# add missing handlers (SET1/COPY/NORMN), try to build.
make size          # first buildable number goes in progress.csv
```

## bc_v1 slot collision — the fix

`gen_bytecode.py` line ~230 writes u1→4, u2→3. Slot 3 holds Gy_mont
which the Shamir backup (step 9) needs. Fix the destination slots:

```python
# u1 = e · w. e @ 14 (plain), w_mont @ 1.
('Nmul', 12, 14,  1),  # u1 → 12 (s is dead after INV)
# u2 = r · w. r @ 11 (plain).
('Nmul', 11, 11,  1),  # u2 → 11 (r dead after THIS op — can overwrite)
('NORMN', 12, 12, 0),
('NORMN', 11, 11, 0),
```

Then verify copies 12→22, 11→23 in native code (rep movsq × 2).

Also: n_mont for bc_v3 must go in a slot RCB never writes. Available:
5,6,7,8,9,10,14,15. 15 is cR2_p — dead after the MULR2 ops. Put
n_mont @ 15:

```python
# In bc_v1, after the last MULR2 (cR2_p dead):
('MULR2', 15, 9, 15),  # n_mont = MontMul(n, R²_p) → 15
# (reads cN @ 9 — but cN is LIMB FORM there, already decoded.
#  MULR2 expects s2 = cR2 slot. This is reading slot 15 which is
#  being overwritten! Need to do this BEFORE the last MULR2, or
#  use a different slot for n_mont. Sequence carefully.)
```

**Open question:** the MULR2 op is `Fmul with s2 = slot 15`. If we
want to compute n_mont = n·R² / R, we need n as s1 and R² as s2.
n is at slot 9 (limb form). R² is at slot 15. So `MULR2 dst, 9, 15`
— but MULR2 hardcodes s2=15 in the handler (`lea rdx,[r14+sR2]`).
The bytecode's s2 nibble is IGNORED by MULR2. So we CAN do this
even after slot 15 is overwritten, as long as the HANDLER reads
from the right place.

Wait no — if MULR2's handler does `lea rdx,[r14+sR2]`, it reads
whatever is CURRENTLY in slot 15. If we've overwritten 15, it reads
the overwritten value.

**Resolution:** do `MULR2 15, 9, 15` (n_mont → 15) as the LAST
MULR2 op. It reads R² from 15, computes n·R²/R, writes to 15. The
read happens before the write (fe_mul11 copies inputs). ✓

## bt-on-cN — the three options ranked

fe_inv_n needs `bt [cN], bit` where cN is the packed integer n.
`bt` indexes bits little-endian (bit i is bit i%8 of byte i/8).
Our cN is stored as 4 BE qwords (for fe_from_be to decode).

1. **Store cN as LE bytes in .rodata** (not BE qwords). Then `bt`
   works directly. fe_from_be needs to handle LE input OR we decode
   cN with a different path. Cost: ~5 B for a LE-mode branch in
   the decoder, or 0 B if fe_from_be is LE-native and ALL constants
   are stored LE (Gx_mont, Gy_mont, R² too — just recompute the
   .quad values as LE).  **← LEAN THIS WAY.** Recompute consts.h
   with LE byte order.

2. Store cN twice (BE + LE). +32 B data. Simplest.

3. Byteswap the `bt` index at each call. `bt` reads from byte i/8;
   for a BE-stored value, the bit is at byte 31−i/8. Compute the
   swapped byte offset: `mov eax, ebx; shr eax, 3; xor al, 31;
   bt [cN + rax], bl_low3bits`. ~10 B extra in the inner loop. Loses
   to option 1.

## .Lai (∞ = (0:1:0)) — ✅ RESOLVED: plain Y=1 works

Tested in range_proof.py (end of session 2026-03-18):

```
RCB(0:1_plain:0, G) = G?  True  ✓
RCB(0:1_mont:0,  G) = G?  True  ✓
RCB(∞_plain, ∞_plain): Z out = 0  ✓ still ∞
RCB(∞_mont,  ∞_mont):  Z out = 0  ✓ still ∞
```

Both work. With X₁=Z₁=0, all X₁·? and Z₁·? products vanish; Y₁'s
R-factor is irrelevant to the output's correctness (it scales Y₃ but
projective points are defined up to scale). **`.Lai` stays simple:
`inc qword [r14+SLOT]`. No 1_mont needed.** Saves a MULR2 op in bc_v1
and removes one open question.

**Corollary:** the Z-coordinates in the Shamir backup (slots 4 and 7
set to "1") can ALSO be plain 1, not 1_mont. bc_v1's `SET1 7,0,0` +
`MULR2 7,7,15` + `COPY 4,7,0` simplifies to `SET1 7,0,0; SET1 4,0,0`.
−4 B bytecode + we don't need MULR2 for the Z's.

**Tested — Z must be 1_mont for actual points:**

```
RCB Z=1_mont both:     ✓ = 2G
RCB Z₁=mont, Z₂=plain: ✗ WRONG
RCB Z=1_plain both:    ✗ WRONG
```

The ∞ case works because X=Z=0 zeroes all the products involving
them (Y's R-factor scales the output but projective is scale-
invariant). For REAL points Z enters multiplications (t2 = Z₁·Z₂)
and the R-factors must match.

**Resolution:**
- `.Lai` (acc = ∞): Y=1 plain is fine. `inc qword [r14+SLOT]`. ✓
- Shamir backup Z's (slots 4, 7): MUST be 1_mont = R. Keep the
  `SET1 7,0,0; MULR2 7,7,15; COPY 4,7,0` sequence in bc_v1. Or:
  store 1_mont as a constant and COPY it (saves 2 bytecode ops,
  costs +32 B data). Bytecode is cheaper — keep MULR2.

## R²_n — ✅ COMPUTED, added to consts.h

R²_n = 0x2d955aba561fc164b2392b6bec5961906ab8c68a2abb372e0f80d88a9a9fedcf

BE qwords (current storage convention):
```
  .quad 0x2d955aba561fc164
  .quad 0xb2392b6bec596190
  .quad 0x6ab8c68a2abb372e
  .quad 0x0f80d88a9a9fedcf
```

LE qwords (if switching per bt-on-cN option 1):
```
  .quad 0xcfed9f9a8ad8800f
  .quad 0x2e37bb2a8ac6b86a
  .quad 0x906159ec6b2b39b2
  .quad 0x64c11f56ba5a952d
```

Slot for cR2_n: 13 (RCB scratch, but bc_v1 runs BEFORE pt_mul so
RCB hasn't touched it yet). verify decodes cR2_n → slot 13.

## Handlers missing from tv_ecdsa.S

```asm
.Lop10:  /* SET1: dst = {1, 0, ..., 0} */
    xor  eax, eax
    mov  cl, K
    push rdi
    rep  stosq
    pop  rdi
    inc  qword ptr [rdi]
    ret
    /* ~13 B */

.Lop11:  /* COPY: dst = s1 */
    mov  cl, K
    rep  movsq
    ret
    /* ~6 B — but needs rsi/rdi already set, which bc_run does */

.Lop12:  /* NORMN: like NORM but modulus = cN (slot 9) */
    lea  rcx, [r14 + sN]
    jmp  .Lop9+<offset past the rcx-already-set point>
    /* Or: .Lop9 expects rcx=&modulus. bc_run preloads rcx=&cP.
     * NORMN overwrites rcx to &cN then falls through to NORM body.
     * Same pattern as Nmul vs Fmul. ~7 B. */
```

## Files you should NOT touch

Outside this directory. Per PLAN.md §5.

## Commit messages

Granular. One commit per distinct technique or fix. Update
progress.csv at each WORKING checkpoint. **DO NOT PUSH** (competitive).
