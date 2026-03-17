# ECDSA/P-256 verify — minimum bytes

Size-optimised ECDSA/P-256 signature verification for boot-ROM-class
targets. FIPS 186-5 compliant. Signature is raw 64 bytes (r‖s
big-endian), public key is 65 bytes uncompressed (0x04‖X‖Y), hash is
32–64 bytes (truncated to 32 per FIPS 186-5 §6.4).

All measurements are of the verification object file only. Every object
has **zero undefined symbols**: no memcpy/memmove/memset/libc.

## Build

```
make size-tiny test-tiny wp-tiny     # the current smallest
make size-fast test-fast wp-fast     # the predecessor (BMI2+MOVBE)
make size      test      wp          # portable C reference
```

## Current results

| Implementation | text+rodata | Cycles | Requires | Notes |
|---|---:|---:|---|---|
| **`tv_ecdsa_tiny.S`** `-DSMALL_MUL8` | **933 B** | ~4.7M | MOVBE | 32-bit schoolbook, `scasd` advance |
| **`tv_ecdsa_tiny.S`** `-DSMALL_MUL8 -DFAST_ADVANCE` | **939 B** | ~4.3M | MOVBE | 32-bit, `lea` advance (+6 B, −10%) |
| **`tv_ecdsa_tiny.S`** (default) | **947 B** | **~3.6M** | MOVBE | 64-bit schoolbook |
| **`tv_ecdsa_tiny.S`** `-DSOLINAS_P -DSOLINAS_LOOP` | **999 B** | ~3.1M | MOVBE | Solinas fold (looped adc) |
| **`tv_ecdsa_tiny.S`** `-DSOLINAS_P` | **1005 B** | **~3.0M** | MOVBE | Solinas fold (unrolled) |
| `tv_ecdsa_fast.S` | 1397 B | ~0.65M | BMI2+MOVBE | Montgomery+mulx, predecessor |
| `tv_ecdsa_bc.S` | 1712 B | ~1.85M | — | first bytecode version |
| `tv_ecdsa.c` (Cortex-M4) | 2082 B | — | — | realistic boot-ROM target |
| `tv_ecdsa.c` (x86-64, gcc `-Os`) | 3076 B | — | — | portable C reference |

**One source, two Pareto-optimal builds.** The default (978 B) uses
64-bit schoolbook for the 512-bit product; `-DSMALL_MUL8` swaps in a
32-bit schoolbook (−20 B) that uses `loop`+`scasd` in the hot loop —
both microcoded, ~950K iterations/verify, ~4M extra cycles. Same reduce
step either way.

**vs Thomas** (external competing implementation): v5 at 989 B / ~4.15M
cycles. Our default (978 B / ~3.45M) DOMINATES it on both axes —
Thomas is fully off the Pareto frontier. Full chart at
[`docs/progress.png`](docs/progress.png).

## Correctness

All implementations pass the same gate:

- **33 hand-picked vectors**: RFC 6979 reference, signature
  malleability (`s' = n − s`), hash numerically > n (must NOT be
  reduced mod n), 48/64-byte hashes, `r=0`/`s=0`/`r≥n`/`s≥n`, pubkey
  coords `≥p`, point-not-on-curve, wrong format byte, constructed
  `u1·G + u2·Q = O` → must reject.
- **574 Wycheproof vectors** (P-256, SHA-256 + SHA-512, P1363 raw).
- **ASAN + UBSAN** via the C harness.

## `tv_ecdsa_tiny.S` architecture

What changed from fast.S to drop ~290 bytes:

- **No Montgomery form.** Plain modular arithmetic throughout. Both
  P-256 moduli have top dword `0xFFFFFFFF` and `2^256 − m < 2^224`,
  so the reduce step is just `t[j..j+8] −= t[j+8]·m` at 32-bit
  granularity — `q = t[top_dword]` is exact to within one bit. No m0i,
  no R², no conversion ops, no Montgomery-domain constants.

- **Projective final check.** Valid iff `X ≡ r·Z² ∨ X ≡ (r+n)·Z²
  (mod p)`. Entirely in bytecode; `n·Z²` via a MULCN handler. Mod-p
  inversion is gone — the second fe_inv_m call, its arg setup, and
  the z² bytecode segment all disappear.

- **Fermat inversion reads `cN` in .text directly.** `n` and `n−2`
  differ only in bits 1–4 (four-bit borrow cascade, doesn't propagate
  past byte 0). `bt [cN],i` walks the exponent; bits 0–4 special-cased.
  No exponent buffer, no sub-2 at runtime.

- **B derived from G in bytecode.** `Gy² − Gx³ + 3Gx`. −32 B rodata.

- **Shamir's trick inherited from fast.S.** Slot 6 = z = 1 serves both
  G and Q; only X,Y swap.

### Journey (1397 → 957)

| ~Size | Key step |
|---|---|
| 1397 | fork from fast.S; roll muladd4 into a loop |
| ~1320 | **drop Montgomery** — q=t[top] reduce, no m0i/R² |
| ~1260 | fe_mul_m: countdown schoolbook, mulsub shared body |
| ~1210 | INV as bytecode op; args on stack; drop r13/r14 frame |
| ~1195 | **projective final check** — mod-p inversion deleted |
| 1177 | Fadd fallthrough; fe_inv_m into handler block |
| 1160 | merge bc_v2→bc_v1, single dispatch (−17) |
| 1124 | cGX adjacent to cN/cP, one 16-qw block copy (−12) |
| 1105 | **`bt` on cN directly** — no exponent buffer (−19) |
| 1071 | op6/7 merge → fe_sub_raw inlines; .Lop8 at 255/255 |
| 1012 | **RCB complete addition** — 3-way branch → one formula (−59) |
| 985 | **addend slot shift** — Shamir setup → one rep movsq (−16) |
| 979 | imul edi,esi,6 for slot12; drop r15; lodsb for 0x04 (−6) |
| 969 | **fe_inv_m: no seed copy** — bytecode sets dst=1, bit 255 (−10) |
| 957 | .Lfm = Nmul; layout reorders for rel8 jmps (−12) |
| 960 | push-zero unrolled: +3 B kills 220K cyc of `loop` penalty |
| 964 | **mul8: drop `loop`, keep `scasd`** — +4 B, −39% cycles |
| 935 | **cP built at runtime** (r8=&cP, rbp−40) → fe_iszero inlines; bc_run inherits r14; Fadd commutes X+=Y (−29) |
| 933 | **EFD reschedule**: hoist RCB 14,15 → 5 scratch slots → cP@slot8 → .Lcadd disp8 (−2) |

## Earlier implementations

### `tv_ecdsa_fast.S` — 1397 B, Montgomery + mulx + Shamir

The predecessor. CIOS Montgomery with advancing-pointer (no memmove),
`mulx` unrolled muladd4 (flag-preservation threads CF across limbs),
Shamir's trick for the scalar walk. BMI2+MOVBE required.

### `tv_ecdsa_bc.S` — 1712 B, first bytecode version

Where the bytecode interpreter came from. 2-byte ops, nibble-encoded
`(dst|s1, s2|op)`, 16 contiguous slots. Replaced ~60 field-op call
sites (~15 B each) with 2 B of bytecode.

### Portable C — 3076 B x86-64 / 2082 B Cortex-M4

32-bit limbs, no 128-bit intrinsics, `-ffreestanding`. One generic
Montgomery multiplier and one generic Fermat inverter, both
parameterised by modulus. Thumb-2's 16-bit encoding is very dense for
pointer-passing code: pt_dbl/pt_add/verify are 40–46% smaller on
Cortex-M4 than on x86-64.

---

## `sign_zmm.c` — constant-time signer (AVX-512 IFMA)

The opposite problem from the verifier. Not size-optimised; instead,
secrets (d, k, every ladder intermediate) never touch memory in a
data-dependent way. Zero conditional branches in the hot path.
~1.8M cycles/sign.

- **5×52 limbs**, one field element per ZMM. `vpmadd52luq`/`huq`
  give the schoolbook product directly.
- **Barrett K=512**: μ = ⌊2^512/m⌋ fits exactly 5 limbs for both p
  and n. Three schoolbooks per reduce, one `cond_sub`.
- **Montgomery ladder** + XOR-mask cswap. Same 43-op RCB complete
  addition as `tv_ecdsa_tiny.S` — doubling is self-add, no ∞ cases.
- **pt_add spills** (~200 stack writes) to fixed `%rbp` offsets —
  same cache pattern every call. Not a leak; the addresses don't
  vary with the secret.

`make test-sign` — 6 layers × 783 vectors, including RFC 6979 A.2.5.
Cross-verified against `tv_ecdsa_tiny.S`. Reference model in
`sign_zmm_model.py`; design notes in `tv_ecdsa_sign_zmm.S`.
