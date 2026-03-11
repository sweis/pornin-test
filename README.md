# Code size tracking — ECDSA/P-256 verify

Measurements of the `tv_ecdsa.c` object file (the verification core only;
the test harness is excluded).

## Build command

```
cc -std=c99 -Os -ffreestanding -fno-strict-aliasing \
   -ffunction-sections -fdata-sections \
   -fno-asynchronous-unwind-tables -fno-ident \
   -fno-stack-protector -fno-tree-loop-distribute-patterns \
   -c -o tv_ecdsa_size.o tv_ecdsa.c
```

Run `make size` to reproduce.

## Current results

| Implementation | Target | Compiler | text+rodata | Notes |
|---|---|---|---|---|
| **x86-64 asm, bytecode-interpreted** | **x86-64** | **GAS** | **1712 B** | `tv_ecdsa_bc.S` |
| C, 32-bit limbs | Cortex-M4 Thumb-2 | arm-none-eabi-gcc 13.2 `-Os` | 2082 B | realistic boot-ROM target |
| Pure x86-64 asm, 64-bit limbs | x86-64 | GAS | 2875 B | `tv_ecdsa_amd64.S` |
| C, 32-bit limbs | x86-64 | GCC 13.3 `-Os` | 3076 B | `tv_ecdsa.c` |
| C, 32-bit limbs | x86-64 | clang 18 `-Os` | ~3856 B | different inliner |

All object files have **zero undefined symbols** — no memcpy/memmove/memset/libc.

### The 1712-byte bytecode-interpreted version (`tv_ecdsa_bc.S`)

Replaces the ~60 field-op call sites with **2-byte bytecode instructions**
executed by a shared interpreter.  Each site (~15 bytes of `lea; lea; lea;
call`) becomes 2 bytes. Net savings vs conventional hand-asm: **1163 bytes**.

**Core architecture:**

- **2-byte bytecode, 16 contiguous slots.** Word = `(dst<<12)|(s1<<8)|(s2<<4)|op`.
  Op-in-low-nibble lets the decoder extract all 3 slot addresses with a
  uniform `shr eax, 4` loop — push s2/s1/dst, pop reverse → rdi/rsi/rdx
  in 23 bytes.
- **Single slot buffer.** One 512-byte buffer serves verify's bytecode
  AND pt ops. bc_v1 writes Q directly into slots 4-6 (= pt_mul's base) —
  no copy between validation and scalar mult.
- **In-place pt_mul.** Acc @ 0-2, base @ 4-6. pt_dbl = `bc_run(bc_dbl)`,
  no separate function, no copy/iter. Locals @ 8-11 preserve base.
- **`bt [mem], reg`** tests bit N of a multi-qword operand — bit index
  spans qwords automatically. 7-byte bit test vs 24-byte manual extract.

**Key size tricks:**

- `loop`/`loopz` preserve CF → tightest carry-preserving big-int add/sub.
- Fadd's temp at slot 3 of the buffer (r12+96, disp8). Slot 3 is always
  safe: bc_dbl never uses it; bc_add2's only ADD writes TO it.
- cR2N dropped: raw s → fe_inv_m gives s⁻¹·R²; 2 extra NMUL-by-one
  compensate. −32 rodata, −18 code.
- fe_inv_m uses caller's r buffer as accumulator. Both moduli have
  bit 255 set → init t=a, start at bit 254, no "started" flag.
- muladd4 base reg r9 (not rbp) → no forced disp8 byte. Drops rbp/rbx
  from fe_mul_m/fe_inv_m entirely; 4-pop shared epilogue.
- `.Lf`/`.Ld` inline after length checks → 6 branches rel8 not rel32.
- Contiguous rodata: N,P,BM one rep movsq. GXM,GYM one rep movsq.
  cN_M0I at [cN-8] = disp8.
- Dead base.z check removed (P-256 cofactor 1, so u2·Q ≠ ∞).
- `.Lfm` falls through into fe_mul_m. bcrun_r14 falls into bc_run.

**Optimization journey (2875 → 1712):**

| Size | Key technique |
|---|---|
| 2875 | baseline hand-asm |
| 2591 | 2-byte bytecode, slot pointer table |
| 2398 | 10 ops, contiguous slots, no ptr indirect |
| 2207 | block-copy consts, mid-frame ptrs |
| 2062 | in-place pt_mul (pt_dbl inlined) |
| 2018 | `loop` + cN_M0I@[cN-8] + misc — **target met** |
| 1992 | loop-based decode, new encoding |
| 1912 | `bt [mem],reg` + drop cR2N |
| 1870 | Fadd uses slot temp; bcrun fallthrough |
| 1840 | dead base.z check removed + single-branch cond-sub |
| 1816 | bit-255-always-1, drop rbx/rbp from mul/inv |
| 1793 | fe_inv_m in-place accumulator |
| 1743 | single slot buffer (Q→base direct, no copy) |
| 1712 | inline .Lf/.Ld (6 branches rel8) |

rodata 356 B: bytecode 156 B (5 streams) + constants 200 B. text 1356 B.

### ARM Cortex-M4 breakdown (the boot-ROM number)

```
.text.fe_zero                  16
.text.fe_cpy                   18
.text.fe_iszero                26
.text.fe_sub_raw               46
.text.fe_geq                   36
.text.muladd10                 60
.text.fe_mul_m                110   (vs 170 on x86-64: -35%)
.text.fe_inv_m                124
.text.Fmul                     24
.text.Fsqr                     24
.text.Fto_mont                 28
.text.pt_cpy                   34
.text.pt_set_inf               28
.text.fe_from_be               24
.text.Fsub                     52
.text.Fadd                     36
.text.pt_dbl                  254   (vs 468 on x86-64: -46%)
.text.pt_add                  332   (vs 593 on x86-64: -44%)
.text.pt_mul                   54
.text.tv_ecdsa_p256_verify    532   (vs 889 on x86-64: -40%)
.rodata  (7 × 32 B)           224
                            ──────
                             2082
```

Thumb-2's 16-bit instruction encoding is extremely dense for this kind
of pointer-passing code — the three largest functions are 40–46% smaller
than their x86-64 equivalents.

The object file has **no external symbol references** — no `memcpy`, no
`memmove`, no `memset`, no libc. The only imports are the two standard
typedefs `uint32_t` / `uint64_t` from `<stdint.h>` and `size_t` from
`<stddef.h>`. On a real firmware build you would link this object
directly; nothing else is pulled in.

## Section breakdown (x86-64, GCC 13.3)

```
.text.fe_zero                   17
.text.fe_cpy                    19
.text.fe_iszero                 24
.text.fe_sub_raw                40
.text.fe_geq                    39
.text.muladd10                  69
.text.fe_mul_m                 170   Montgomery multiplication core
.text.fe_inv_m                 181   Fermat inversion (shared p / n)
.text.Fmul                      18
.text.Fsqr                      21
.text.Fto_mont                  25
.text.pt_cpy                    37
.text.pt_set_inf                26
.text.fe_from_be                28
.text.Fsub                      51
.text.Fadd                      44
.text.pt_dbl                   451   Jacobian doubling (a = -3)
.text.pt_add                   593   Jacobian add, all special cases
.text.pt_mul                    78   double-and-add
.text.tv_ecdsa_p256_verify     889   public entry point
.rodata  (7 × 32-byte const)   224   P, N, B, GX, GY, R2P, R2N
                             ──────
                              3076
```

## Optimisation journey (x86-64, GCC 13.3 `-Os`)

| Step                                            | Size   | Δ      |
|-------------------------------------------------|--------|--------|
| Initial working implementation                  | 4271 B |        |
| Wrapper functions for mod-p ops (fewer args)    | 3835 B | -436 B |
| `fe_geq` direct compare (no temp buffer)        | 3773 B | -62 B  |
| Factor `muladd10` helper from `fe_mul_m`        | 3772 B | -1 B   |
| `Fadd` via negation + `Fsub`                    | 3737 B | -35 B  |
| Skip redundant Montgomery conversions in mod-n  | 3575 B | -162 B |
| Reuse temps in `pt_add` (12 → 6 locals)         | 3558 B | -17 B  |
| Stack-frame reuse in `verify` (Q reused for G)  | 3493 B | -65 B  |
| `-fno-stack-protector` (not applicable in ROM)  | 3162 B | -331 B |
| `NOINLINE` on `pt_cpy` / `pt_set_inf`           | 3106 B | -56 B  |
| Reuse `delta` slot in `pt_dbl`                  | 3102 B | -4 B   |
| `-ffreestanding` (eliminate `memmove` ref)      | 3076 B | -26 B  |

## Design summary

- **One generic Montgomery multiplier** parameterised by modulus — shared
  between field-p arithmetic and scalar (mod-n) arithmetic. No duplicate
  reduction code.
- **One generic Fermat inverter** — exponent `m-2` is computed from the
  modulus at runtime (saves 64 bytes of rodata versus storing both
  `p-2` and `n-2`).
- **No `memcpy`/`memset`/`memmove`** — all copies are explicit 8-word
  loops; the compiler is told via `-ffreestanding` not to substitute
  libc calls.
- **Point addition handles every special case** (`P=O`, `Q=O`, `P=Q`,
  `P=-Q`). This is essential: adversary-controlled signature components
  can force these cases during the scalar-mul loop.
- **Simple double-and-add**, called twice, instead of Shamir's trick.
  Smaller code, ~2× slower — the right trade-off for a boot ROM.

## Pure x86-64 assembly version

The hand-written assembly (`tv_ecdsa_amd64.S`) uses **64-bit limbs** (4 per
256-bit number, vs 8×32-bit in the C version). x86-64's `mulq` gives a
free 64×64→128 product and `adc/sbb` make carry chains trivial.

**Size: 2875 bytes** (text 2643 + rodata 232) — 201 bytes (6.5%) smaller
than the C version's 3076. All 33 tests pass, clean under ASAN/UBSAN.

### Per-function comparison

| Function | ASM | C | Δ | Notes |
|---|---:|---:|---:|---|
| `fe_mul_m` | 182 | 170 | +12 | 4-iteration CIOS vs 8; slight overhead from 6-limb accumulator |
| `muladd4` (inner helper) | 55 | 69 | -14 | one `mulq` per limb; tight loop |
| `fe_inv_m` | 180 | 181 | -1 | same square-and-multiply loop |
| `Fsub` | 12 | 51 | **-39** | pure tail-call |
| `Fsqr` | 5 | 21 | -16 | `mov rdx,rsi; jmp Fmul` |
| `Fto_mont` | 9 | 25 | -16 | tail-call |
| `pt_dbl` | 338 | 468 | **-130** | 4-fe stack frame, all disp8; in-place wrappers |
| `pt_add` | 480 | 593 | **-113** | dual-base-register, all disp8 |
| `verify` | 906 | 889 | +17 | large frame; split base regs keep leas short |
| `fe_sub_raw` | 50 | 40 | +10 | unrolled 4 limbs (leaf, worth the speed) |
| in-place wrappers (×5) | 28 | — | — | `Fsub_i/Fadd_i/Fmul_i/Fsqr_i/Fdbl`: 5–8 bytes each |

### Key assembly size tricks

1. **64-bit limbs**: every big-int primitive is half the iterations.
   One `mulq` + `adc` chain replaces four 32×32 partial products.

2. **Tail-call wrappers**: `Fsqr` is just `mov rdx,rsi; jmp Fmul` — 5 bytes
   total.  `Fsub` is `lea rcx,[rip+cP]; jmp fe_sub_m` — 12 bytes.
   GCC can sibling-call-optimise in some cases, but with differing
   argument counts and no inlining heuristics in its favour it emits
   a full prologue+epilogue here (the C `Fsub` is 51 bytes).

3. **In-place wrappers**: ~25 field ops in `pt_dbl`/`pt_add`/`verify`
   have `dst == src1`. Wrapper `Fmul_i: mov rsi,rdi; jmp Fmul` (5 bytes)
   saves one 4-byte `lea` at each converted call site. Net ~-100 bytes.

4. **Dual base registers into frame middle**: verify's 448-byte frame
   needs disp32 leas for half its slots if addressed from `rsp`. Setting
   `rbp = rsp+64` and `r13 = rsp+288` puts every slot within signed
   disp8 of one base or the other — all leas are 4 bytes.

5. **Formula reordering in `pt_dbl`**: computing `beta = X·gamma`
   *after* `Z3` lets `delta` and `beta` share a stack slot, shrinking
   the frame from 160 to 128 bytes (all disp8-addressable).

6. **`m0i = 1` for p**: the Montgomery reduction constant `-1/p mod 2^64`
   happens to be 1 (because `p ≡ -1 mod 2^64`).  Nothing special-cased,
   but `imul reg, 1` still costs only one instruction.

### Assembly optimisation journey

| Step | Size | Δ |
|---|---|---|
| Initial working asm (straight port of C logic) | 3367 B | |
| `rbp`+`r12` dual base in verify (disp8 not disp32) | 3200 B | -167 B |
| Loop the limb-shift in `fe_mul_m` | (incl.) | |
| 4-fe frame in `pt_dbl` (reorder formula) | 3030 B | -170 B |
| `r14`/`r15` base regs in `pt_dbl`/`pt_add` | (incl.) | |
| Mid-frame base pointers (every slot in disp8) | 2983 B | -47 B |
| In-place wrappers (`Fmul_i` etc.) | 2873 B | -110 B |
| pt_mul stack-alignment fix (ABI compliance) | 2875 B | +2 B |

## Correctness

All 33 tests pass (27 vectors + 6 length checks):

- RFC 6979 reference vectors (P-256 + SHA-256, both "sample" and "test")
- Signature malleability (`s' = n - s` must still verify)
- All-zero hash; hash numerically > n (must NOT be reduced mod n)
- 48- and 64-byte hash inputs (truncated to 32 bytes per FIPS 186-5)
- `r = 0`, `s = 0`, `r ≥ n`, `s ≥ n`, `r = n+1`, `s = 2^256-1`
- Public-key coordinates `≥ p`; point not on curve; wrong format byte
- Constructed case where `u1·G + u2·Q = O` (point at infinity) → reject
- Wrong signature / hash / public key → reject

The test harness also runs cleanly under ASAN+UBSAN.
