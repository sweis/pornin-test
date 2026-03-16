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

**Current:** `tv_ecdsa_tiny.S` — one source, two Pareto-optimal builds:
- **1108 B** default (~2.4M cyc) — 64-bit schoolbook product
- **1088 B** `-DSMALL_MUL8` (~6.3M cyc) — 32-bit schoolbook, size floor

MOVBE only (no BMI2). Thomas's competing implementation: **1046 B /
~4.0M cyc** — holds the size corner; default build dominates on speed.

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
- **Projective final check — no mod-p inversion.** Valid iff
  `X ≡ r·Z² ∨ X ≡ (r+n)·Z² (mod p)`; prime p means `d1·d2 ≡ 0` is
  equivalent. Entirely in bytecode (bc_v3). `n·Z²` via the MULCN
  handler (Fmul with b = &cN in .text).
- **Fermat inversion mod-n only.** `n` and `n−2` differ only in bits
  1–4 (low byte `0x51`→`0x4F`, four-bit borrow cascade that doesn't
  propagate). So: `bt` directly on `cN` in .text, special-case bits
  0–4 with a 7-byte cmp/jb/je. No exponent buffer, no sub-2.
- **B derived from G at runtime** in bytecode (`Gy² − Gx³ + 3Gx`).
  No `cBM` constant.

## Invariants that silently cost bytes if broken

- **r14 = slot base through pt_add_acc / pt_mul.** bc_run push/pops
  r14 around every dispatch; pt_add_acc and pt_mul have no frame.
- **.Lai is CALLED from pt_mul** (zeroes acc, returns eax=0).
- **cGX→cGY→cN→cP contiguous** after .Ljt — verify's 16-qword
  `rep movsq` lands G in slots 2-3, cN in 4, cP in 5. bc_v1's check
  ops read 4,5 first, then its copy ops overwrite 4,5 with Q.
- **Slot 6 = 1 is load-bearing for Shamir.** bc_dbl/add never write
  it; pt_mul's G-swap copies only slots 4-5 (X,Y). z serves both.
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

## Journey summary (fast.S 1397 → tiny.S 1108)

| ~Size | Key step |
|---|---|
| 1397 | fork from fast.S |
| ~1320 | drop Montgomery: **q=t[top] reduce**, no m0i/R²/cR2P |
| ~1260 | fe_mul_m squeeze: countdown schoolbook, mulsub reduce shared body |
| ~1210 | INV as bytecode op; drop r13/r14 frame; args on stack |
| ~1195 | **projective final check** — mod-p inversion gone entirely |
| 1177 | Fadd fallthrough; fe_inv_m into handler block; drop r13 |
| 1160 | **merge bc_v2 into bc_v1** — hash→slot14, single dispatch (−17) |
| 1136 | H-check via bc_add1 tail checkzero; push;pop reg moves |
| 1124 | cGX adjacent to cN/cP — one 16-qw block copy (−12) |
| 1105 | **`bt` on cN directly** — no exponent buffer (−19) |
| 1088 | (size floor — `loop`+`scasd` in mul8, ~6M cyc) |
| 1108 | **64-bit schoolbook default** (+20 vs floor, halves cycles) |

See `docs/progress.png` for the full frontier vs Thomas.
