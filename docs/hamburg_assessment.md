# Hamburg Signed-Binary Ladder — Assessment

**Verdict: architecture cannot beat 891 B. Measured +277 B (1168 B prototype);
structural floor ~+140 B even with aggressive grinding. The literature
survey's "−30 to +20 B" estimate missed three cost centers that together
dominate.**

## What was built

Working prototype at `hamburg/tv_ecdsa.S`, 1168 B SMALL_MUL8. Math verified
by Python model (`model.py`, `sim.py`) against all 5 critical Wycheproof
edges including **tcId 204 (P=Q duplication, expected VALID — must double)**.
Prototype has one slot-lifetime bug (bc_v1 curve-check clobbers e@14 before
u1 Nmul) — trivially fixable by reorder, irrelevant to the size finding.

Bytecode schedules (`gen_bytecode.py`) cross-validated at the op level:
100/100 random points for bc_dbl, bc_add; full 255-iter ladder matches
reference for u ∈ {1, 2, 3, n−1, n−2, random}.

## The critical test (survey's open question)

**u ∈ [1, n−1] is sufficient for the Hamburg invariant. u=1 works fine.**
The p256-m proof (L1098-1111) holds: for u=1, s_odd=1, every s_i=1, and
2·s_i = 2 satisfies 1 < 2 < n−1. The only scalar outside range is **u1=0**
(e ≡ 0 mod n), which p256-m special-cases at L1423 — we must too.

**tcId 204 mandates the full 3-way combine.** u1·G = u2·Q with expected=1.
Running bc_add on P=Q gives (0:0:0). Running on P=−Q gives (r²:−r³:0).
So detection is: Z=0 ∧ X=0 → restore R1 + bc_dbl; Z=0 ∧ X≠0 → bc_v3 fails
(correct); Z≠0 → done. **R1 must be saved before bc_add** (12-qw copy).

## Where the bytes went — measured, not estimated

| Component        | limb8 | hamburg | Δ    | Why |
|------------------|------:|--------:|-----:|-----|
| bytecode (total) |   161 |     178 |  +17 | bc_dbl(43)+bc_add(37)+bc_setup(13)+bc_norm(17) = 110 B vs bc_rcb(87 B). bc_v1 −8 B (no staging), bc_v3 +2 B (Jacobian Z²). |
| pt_mul / scalar_mult |    74 |     141 |  +67 | See §Hamburg-setup-tax below. |
| bcrun + jt       |    84 |      85 |   +1 | +1 table entry (INVP). |
| Fadd..fe_inv_m   |    99 |     114 |  +15 | INVP parameterization: r13=&modulus, .Lfm helper, two handler preludes. |
| verify           |   158 |     335 | +177 | See §verify-tail below. |
| **Total**        | **891** | **1168** | **+277** | |

## The three cost centers the survey missed

### 1. Hamburg setup tax (+67 B in scalar_mult, structural ~+50 B)

limb8's pt_mul init is **12 B**: `mov rdi,r14; xor eax,eax; mov cl,12;
rep stosq; inc [rdi-64]` — zero three slots, poke a 1. RCB handles
∞+Q=Q in-formula, so init is trivial.

Hamburg's init is **conditional on the scalar's low bit**:
```
  test BYTE PTR [rbx],1      ; 3 B
  jz .Leven                  ; 2 B
  ; odd: copy u→slot3 (mov,lea,mov,rep) 13 B; lea rsi Py_pos 4 B
  jmp .Linit_ry              ; 2 B
.Leven:
  ; NOT slot3 (4× not QWORD PTR [r14+96+k])     20 B
.Linit_ry:
  ; copy rsi→slot1 (lea,mov,rep)                 8 B
```
= **~52 B of pure conditional setup** that CANNOT be bytecode (bc_run
doesn't branch). Plus the pre-setup (Px,Py,u→slots, bc_setup dispatch)
is ~30 B on top. The survey's "Hamburg init (odd-conversion + conditional
point-negate)" was one bullet; it's the single biggest cost center.

**Optimization headroom**: ~20 B. The NOT sequence could be a loop (−8 B
at +cycles). The two branch arms share structure poorly. `s_odd = n−s`
could be a no-op on the odd path (always compute n−u in bc_setup, then
the odd path only does the copy-over). Best realistic: ~90-95 B scalar_mult.
Still +16-21 B vs pt_mul.

### 2. Two-call verify tail (+177 B, structural ~+100 B)

limb8's verify tail (after bc_v1) is:
```
  Shamir backup: rep movsq slots 2-7 → 16-21    (10 B)
  call pt_mul                                    (5 B)
  sbb;inc;leave;pops;ret                         (12 B)
```
**= 27 B.** One call, one shot, pt_mul tail-jumps into bc_v3.

Hamburg's verify tail MUST have:
| Piece | B (measured) | B (floor estimate) |
|---|--:|--:|
| slot4 cN restore (INV sub-2'd it) | 5 | 5 |
| 1st scalar_mult call (rsi,rbx,call) | 18 | 12 |
| bc_norm dispatch | 8 | 8 |
| R2 stash (8 qw to slot16) | 12 | 10 |
| u1==0 check (lea+xor+push+pop+repe scasq+jz) | 16 | 12 |
| slot4 cN re-copy (bc_norm made it p−2) | 14 | 10 |
| 2nd scalar_mult call (rsi=cGX in .text, rbx, call) | 18 | 12 |
| Combine R2→5,6 (rep movsq 8 qw) | 12 | 10 |
| Combine R1 save (rep movsq 12 qw) | 11 | 10 |
| bc_add dispatch | 8 | 8 |
| check Z=0 (lea+xor+push+pop+repe scasq+jnz) | 14 | 10 |
| check X=0 (same pattern, rax/rcx still set) | 10 | 8 |
| R1 restore + bc_dbl dispatch | 17 | 14 |
| bc_v3 dispatch + epilogue | 18 | 15 |
| **Total** | **181** | **144** |

Even the floor estimate is **+117 B** over limb8's 27 B. The "one final
combining add" in the survey was budgeted as ~30 B; the real cost
including R1 save/restore/detect is ~60 B. And "second scalar-mult
call + result stash" was one bullet; it's ~50 B because each call needs
its own Px,Py,u source setup and the stash requires slot4-cN restoration
*between* calls (bc_norm's INVP corrupts it).

### 3. Coordinate-system mismatch forced mod-p inversion (+15 B + 17 B bytecode)

The survey assumed bc_rcb (homogeneous) could be swapped for bc_cmo98
(Jacobian) without ripple effects. **Wrong**: the final combine must
handle general-Z inputs from BOTH scalar mults. RCB is complete but
homogeneous; CMO98 full-Jacobian is incomplete. The only way to reuse
bc_add (mixed J+affine) for the combine is to normalize R2 first → need
mod-p inversion → fe_inv_m must be parameterized for BOTH moduli.

Cost: +15 B asm (r13 modulus ptr, .Lfm helper, two preludes) + 17 B
bc_norm + 1 B jump table entry = **+33 B**. Not fatal alone, but
compounded with the above.

## Could it be rescued?

**Tried / considered:**
- **Combine via RCB (keep bc_rcb for just the final add):** bytecode
  goes to 178+87 = 265 B. Worse.
- **Combine via full-Jacobian CMO98 (23 ops, 47 B):** same P=Q detection
  problem, same R1-save cost, saves only the 33 B of mod-p-inv support.
  Net ~1135 B. Still +244 B.
- **Don't handle P=Q (let tcId 204 fail):** not a valid option — FIPS
  186-5 correctness + Wycheproof tests it. Would save ~60 B.
- **Single-dispatch bc_dbladd (chain dbl→add, one terminator):** saves
  ~8 B in the loop (one dispatch vs two) but then bc_dbl isn't
  separately callable for the combine-double → need a 43-B duplicate.
  Net +35 B.
- **Projective-equality check before bc_add (avoid R1 save):** 4 Fmuls
  in bytecode (~10 B) + 2 asm check+branch dispatches (~20 B). Saves
  the R1-save/restore (~25 B). Near-wash; slightly worse.
- **Both-outputs affine (normalize R1 too):** +8 B (2nd bc_norm dispatch)
  but combine-equality becomes trivial memcmp. Net maybe −5 B. Marginal.

**None of these touch the two structural costs.** The Hamburg setup tax
and the two-call-plus-combine verify tail are inherent to the architecture.

## The survey's error mode

Each "what we'd add" bullet was estimated as ~10-20 B by analogy to
similar-sounding constructs elsewhere in the codebase. But:
- "Hamburg init" resembles nothing in limb8 — there's no conditional
  256-bit arithmetic anywhere in the current design.
- "Second scalar-mult call" was analogized to a second `call pt_mul`
  (5 B), not the full arg-marshalling + inter-call state management.
- "Final combining add" was analogized to a single bytecode dispatch,
  not a 3-way branch with save/restore.

**The survey's anchor was limb8's per-construct costs, but Hamburg's
constructs are novel — no existing bytes in limb8 resemble them.**

## Bytecode-level findings (for the record)

- **21-op doubling, not 20**: Fadd dst≠s1 means `x+x` needs a fresh dst.
  Z3=2YZ must be computed before Y is overwritten by Y², then copied
  back to slot Z at the end (1 extra Fmul-as-copy). 43 B not 41 B.
- **obc_v1 = 127**: at the push-imm8 limit. Any bytecode growth breaks
  `push obc_v1` → 5-B encoding (+3 B × 1 site = +3 B).
- **bc_dbl + bc_add = 80 B vs bc_rcb 87 B**: only −7 B raw formula
  saving. RCB's 43-op is remarkably competitive given it's complete.
- **Neither CMO98 formula reads b**: slot 10 is freed (bc_v1's b-derive
  becomes transient, never stored). Zero saving — b-derive op count is
  the same whether stored or not. Just a free slot.

## Bottom line

|  | B |
|---|--:|
| Prototype (as-built, 1 bug, compiles) | **1168** |
| Optimistic grind floor (all pieces ~30% smaller) | ~1030 |
| Structural floor (only keep unavoidable costs) | ~1000 |
| limb8 SMALL_MUL8 (target) | **891** |
| Thomas v7 (current competition) | **928** |

**The Shamir-free architecture does NOT beat 891 B.** It doesn't beat
Thomas's 928 B either. The survey's −30 to +20 B band should be revised
to **+110 to +280 B**.

**Cycles**: not measured (tests failing), but the model runs ~2× limb8's
inner-loop op count (2 × 255 × 39 ops vs ~256 × 64 ops average) plus one
256-iter Fermat inversion. Expect ~2.5× cycles — **worse on both axes**.

## Files

- `model.py` — reference implementation, 5/5 edge vectors pass
- `sim.py` — bytecode-level simulator, 220/220 random + 6/6 edge scalars
- `gen_bytecode.py` — nibble encoder, Fadd/terminator constraint checker
- `bytecode.inc` — generated (178 B, 6 streams)
- `tv_ecdsa.S` — full assembly (1168 B SMALL_MUL8; slot14 bug on line
  of bc_v1 curve-check; fix = use slot7 for T2, re-gen)
