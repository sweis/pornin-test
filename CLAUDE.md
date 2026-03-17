Implement ECDSA signature verification with curve P-256, with a specific goal of achieving a low code footprint (i.e. optimize for size, not for speed — a plausible context would be some code that fits in a boot ROM and verifies the signature on the firmware at boot time).

Language could be C or assembly or whatever compiles to a stand-alone binary chunk (i.e. if you import stuff like memcpy() then that counts against the total size). Signature is provided as 64 bytes (r and s, in unsigned big-endian encoding, in that order). Public key is 65 bytes (uncompressed format). The hashed message is provided as input, so no need to implement a hash function (obviously a boot ROM would need a hash function but we can abstract it away for this test).

From requestor:
"I don't think these specific rules and targets have already been published anywhere so this should avoid the issue of AI just regurgitating GCC source code when tasked with writing a compiler. Also I do have some point of comparison, which I have worked a bit on recently, so I am curious to know how small this AI can get the code."

Try to make the code as small as possible while being safe and correct. Ensure commmon cryptographic mistakes are avoided. Add a suite of test vectors based on publicly availble sources to verify correctness. Look for good unit tests for common cryptographic failures, perhaps using Wycheproof as motivation.

Here is a method signature:
```
/*
 * Verify signature 'sig' (size 'sig_len' bytes) against public key
 * 'pub' (of size 'pub_len' bytes) over hash value 'hv' (of size
 * 'hv_len' bytes). The hash value MUST have been obtained from a
 * cryptographically secure hash function with an output of size at
 * least 32 bytes (usually, SHA-256 is used). The signature format is
 * "raw": the two components (r,s) of the signature are encoded as
 * unsigned integer in big-endian convention, over 32 bytes each, and
 * concatenated in that order. The public key uses the "uncompressed"
 * format, of size exactly 65 bytes (the first byte must have value 0x04).
 *
 * Returned value is 1 on success (signature is valid) or 0 on
 * error. An error is reported in any of these cases:
 *  - signature size is not correct;
 *  - public key size is not correct;
 *  - hash value size is less than 32 bytes or is greater than 64 bytes;
 *  - signature does not have a valid format (i.e. either r or s is zero
 *    or is not lower, as an integer, than the curve order).
 *  - public key does not have a valid format (one of the coordinates
 *    is out of its nominal ranges, or the point is not on the curve);
 *  - signature verification algorithm fails.
 *
 * Exact rules follow FIPS 186-5, section 6.4.2, with the hash value 'hv'
 * being 'H = Hash(M)' as computed in step 2. This implementation adds an
 * explicit check that the provided hash value length does not exceed
 * 64 bytes, because that would indicate that the caller is not provding
 * a hash value but the message itself, which is insecure (the use of a
 * cryptographic hash function is necessary for the overall security).
 * In any case, the verification algorithm starts by truncated the hash
 * value to the curve size, which is 32 bytes for curve P-256, and the
 * extra bytes are simply ignored. Hash values _shorter_ than 32 bytes
 * are also rejected because they mechanically cannot provide the "128-bit"
 * security level that is usually expected from the curve (and FIPS 186-5,
 * section 6.1.1, makes such rejection mandatory).
 */
int tv_ecdsa_p256_verify(const void *sig, size_t sig_len,
        const void *pub, size_t pub_len,
        const void *hv, size_t hv_len);
```

---

# Implementation notes

**Current:** `tv_ecdsa_tiny.S` — one source, multiple Pareto builds:
- **933 B** `-DSMALL_MUL8` (~4.7M cyc) — 32-bit schoolbook, size floor
- **947 B** default (~3.6M cyc) — 64-bit schoolbook product
- **1005 B** `-DSOLINAS_P` (~3.0M cyc) — P-256 fold, no multiplies in reduce

MOVBE only (no BMI2). Thomas's competing implementation (v6): **955 B /
~4.3M cyc** — dominated by our 947 B default on both axes.

## Workflow

```
make size-tiny test-tiny wp-tiny     # edit-build-test loop
```

33 hand-picked vectors + 574 Wycheproof = 607 tests. Must pass 607/607
before any commit. ASAN/UBSAN via the C harness.

## Architecture (what's different from fast.S)

- **No Montgomery form.** Plain modular arithmetic throughout. Reduce
  step is `t[j..j+8] −= t[j+8]·m` at 32-bit granularity — both P-256
  moduli have top dword `0xFFFFFFFF` and `2^256 − m < 2^224`, so the
  quotient estimate `q = t[top_dword]` is exact to within one bit
  (≤2 iterations per window, never negative). No m0i, no R², no
  Montgomery-domain constants.
- **Product is 64-bit (default) or 32-bit (SMALL_MUL8).** Either way
  the reduce stays 32-bit — the q=t[top] trick needs the top *dword*
  all-ones; p's top *qword* is `0xffffffff00000001`.
- **RCB complete addition** (Renes-Costello-Batina, ePrint 2015/1060).
  One 43-op formula handles P+Q, 2P, P+(−P)=∞, ∞+Q=Q with no branches.
  Homogeneous projective coordinates (x=X/Z, not Jacobian X/Z²).
  pt_add_acc's 3-way branch tree → 11-byte copy-and-dispatch. −59 B.
- **Projective final check — no mod-p inversion.** Valid iff
  `X ≡ r·Z ∨ X ≡ (r+n)·Z (mod p)`; prime p means `d1·d2 ≡ 0` is
  equivalent. Entirely in bytecode (bc_v3).
- **Fermat inversion mod-n only.** `n` and `n−2` differ only in bits
  1–4 (low byte `0x51`→`0x4F`, four-bit borrow cascade that doesn't
  propagate). So: `bt` directly on `cN` in .text, special-case bits
  0–4 with a 7-byte cmp/jb/je. No exponent buffer, no sub-2.
- **B and cP derived at runtime.** `b = Gy² − Gx³ + 3Gx` in bytecode;
  cP built with stosq/stosd (mostly 0xFF/0x00 bytes) into slot 8.
  −64 B rodata.

## Invariants that silently cost bytes if broken

- **r14 = slot base through pt_add_acc / pt_mul.** bc_run push/pops
  r14 around every dispatch; pt_add_acc and pt_mul have no frame.
- **.Lai is CALLED from pt_mul** (zeroes acc, returns eax=0).
- **RCB never writes slots 5,6,7,10.** pt_mul relies on this: the
  addend (5-7) stays put across the call (no Q-restore); b (slot 10)
  survives all 256 iterations.
- **Slots 2-7 stage Gx,Gy,1,Qx,Qy,1** before pt_mul — Shamir backup
  is one 24-qword `rep movsq` to slots 16-21.
- **cP lives at slot 8** (r8 = r14+256). bc_rcb never writes slot 8
  (verified after EFD reschedule); .Lcadd reaches slot 5 as [r8−96]
  disp8.
- **rcx=0 is a precondition** for cpy3 macro and pt_mul's `mov cl,8`.
  Every call site has rcx zeroed by a prior loop-to-zero. Audit on
  reorder.
- **`.rodata` before `.text` is load-bearing.** gas picks `push imm8`
  only for backward references. obc_v1 is at 120/127 — ~7 B of
  bytecode growth before `push obc_v1` blows to 5 bytes.
- **Jump table offsets stored as u8.** `.error`-asserted.

## x86-64 encoding facts that keep recurring

- `push rbx`=1B, `push r14`=2B. `push;pop` = 2B move for non-REX regs.
- `[rbp]`/`[r13]` force disp8=0. `[rsp]`/`[r12]` force SIB.
- `push imm8` sign-extends: 0..127 only.
- `bt [mem],reg` indexes an unbounded bit array (spans qwords).
- NEG sets CF=0 iff operand was zero. DEC preserves CF.
  `pop`/`ret`/`loop`/`stosq`/`lodsq` preserve all flags.
- gas won't relax `disp(reg)` on forward references — hardcode + assert.
- `loop` and `scasd` are microcoded (~7 cyc, ~3 cyc). `dec;jnz` / `lea`
  are 1 cyc. Matters when the inner loop runs ~1M times/verify.

## Journey summary (fast.S 1397 → tiny.S 933)

| ~Size | Key step |
|---|---|
| 1397 | fork from fast.S |
| ~1300 | **drop Montgomery** — q=t[top] reduce, no m0i/R²/cR2P |
| ~1260 | fe_mul_m squeeze: countdown schoolbook, mulsub shared body |
| ~1210 | INV as bytecode op; drop r13/r14 frame; args on stack |
| ~1195 | **projective final check** — mod-p inversion gone |
| 1160 | merge bc_v2→bc_v1 — hash→slot14, single dispatch (−17) |
| 1124 | cGX adjacent to cN — one 16-qw block copy (−12) |
| 1105 | **`bt` on cN directly** — no exponent buffer (−19) |
| 1012 | **RCB complete addition** — 3-way branch → one formula (−59) |
| 985 | **addend slot shift** — Shamir setup → one rep movsq (−16) |
| 969 | fe_inv_m: no seed copy — bytecode sets dst=1 first (−10) |
| 957 | .Lfm = Nmul; layout reorders for rel8 jmps (−12) |
| 942 | **cP built at runtime** → fe_iszero inlines (−6) |
| 935 | r8=&cP caller-saved; Fadd commutes; bc_run inherits r14 (−29) |
| 933 | **EFD reschedule** — 5 scratch slots → cP@slot8 disp8 (−2) |

See `docs/progress.png` for the full frontier vs Thomas.
