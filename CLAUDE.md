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

# Implementation notes (current state)

**Best result:** `tv_ecdsa_fast.S` — 1511 bytes, ~1.20M cycles on
Skylake-class Xeon. BMI2 required (`mulx`). See README.md for technique
writeups and BENCHMARK.md for cycle attribution.

## Workflow

```
make size-fast test-fast bench    # edit-build-test loop
```

Test suite is 27 vectors + 6 length checks. Must pass 33/33 before any
commit. ASAN/UBSAN via the C harness in test_ecdsa.c.

## Invariants that silently cost bytes if broken

- **Jump table offsets must fit u8.** `.Ljt` to each handler is stored
  as one byte. Current max is Fadd at ~230/255. **~25 bytes of growth
  headroom** before the handler block before Fadd overflows. Adding code
  between `.Ljt` and `.Lop2` costs this budget.

- **Bytecode stream offsets must fit signed imm8.** All `push obc_X`
  encode as `6a XX` only if `obc_X` ≤ 127. Current max is bc_v1 at
  118. Stream order in `.rodata` is deliberately `dbl, v2, v3, add1,
  add2, v1` to keep this true. Adding bytecode ops will push bc_v1 past
  the limit.

- **`.rodata` before `.text` is load-bearing.** gas only picks the
  2-byte `push imm8` encoding for backward references. Move `.rodata`
  back down and every `push obc_X` silently becomes 5 bytes.

- **`oP_early` in the decoder is hardcoded (49).** It's asserted against
  the real `oP` with `.error`. If `.Ljt` layout changes (table size, or
  reordering cN_M0I/cN), the assert fires. Good — but it means you'll
  hit a build error, not a runtime bug.

- **cN→cP→cBM adjacency** is load-bearing for verify's bulk `rep movsq`
  that loads the constants into slots 8-11.

- **Slot layout in pt_add_acc:** bc_dbl/bc_add1/bc_add2 use slots 0-11.
  Slots 12-15 are preserved (verify stashes r,s,sinv,hash there).
  Slots 16-18 hold u2·Q across pt_mul. Changing bytecode slot usage
  can trash verify's stashed state.

## Things tried and rejected (don't re-explore)

| Idea | Why it failed |
|---|---|
| `rep stosq` in fe_mul_m zero loop | +140K cycles measured for −3 B. Startup penalty at count=9 is ~140 cyc/call, not the ~25 rule of thumb. |
| Swap rbx↔r14 in verify | 1-byte `push rbx` stockpile for `mov rdi,r14` — but the final `push rbx×4` block becomes `push r14×4` (+4). Net 0. |
| Drop r13 mid-pointer | Each `[r13+N]` → `[r14+384+N]` is disp32 (+3/site × 7). Net +14. |
| REPEAT bytecode opcode | Handler cost > the 6-8 B of repeated `0x92,0x99`/`0x43,0x11`. |
| Merge .Lop7/.Lop8 via sense bit | fe_iszero clobbers rcx; discriminator doesn't survive. |
| `enter`/`leave` for verify frame | rbp conflict with slot-2 pointer. With other callee-saves below rbp, leave needs `lea rsp,[rbp−N]` anyway — no save. |
| Length-counted bytecode (vs 0x0000 terminator) | +7 B in bc_run for −6 B of terminators. Net +1. |
| Build cP at runtime | p has nice structure (all 0x00/0xFF bytes) but limb 3 = `0xffffffff00000001` costs as much to build as store. |
| fe_cpy inlined | 3 callers × 5-byte call + 9-byte body = 24 B. Inlined: 3 × 8 B = 24 B. Wash. |
| fe_inv_m caller sets r15=m0i directly | `pop r15` in `.Lepi4` (shared with fe_mul_m) restores the pushed value, not the caller's original. ABI break. |
| cGXM in bytecode-offset scheme | 64 bytes; wherever it sits, it pushes some bc_X past 127. |

## x86-64 encoding facts that mattered

- `push rbx`=1B, `push r14`=2B. Stockpiling only wins for non-REX
  source regs.
- `[rbp]`/`[r13]` with mod=00 force disp8=0 — use `mov` not `lea` for
  the zero-displacement case. `[rsp]`/`[r12]` always need SIB.
- `push imm8` sign-extends: values 0..127 OK, 128..255 become negative.
- `bt [mem], reg` indexes an unbounded bit array regardless of operand
  size (32 vs 64-bit only affects the signed range of the reg).
- NEG sets CF=0 iff operand was zero. DEC preserves CF, sets ZF.
  `pop`/`ret`/`loopz`/`stosq`/`lodsq` preserve all flags.
- gas won't relax `disp(reg)` for forward references (unlike jumps).
  Forward-ref `lea r,[r+offset]` gets disp32 silently. Hardcode + assert.

## Possible next directions

- **ADX dual carry chains in muladd4.** `adcx`/`adox` interleave two
  carry chains. Could drop the `adc r,0` barriers. Estimate: −15% total
  cycles, +10–20 B. See BENCHMARK.md.
- **Shamir's trick** (interleave u1·G + u2·Q). Halves doublings, ~25%
  speed. Likely +30–50 B bytecode/handler. The hard part is pt_add_acc's
  special-case handling with two bases.
- **Remaining bytecode compression.** bc_dbl has `0x92,0x99`×4 (Fadd
  doubling, 8 B) and bc_v1 has `0x43,0x11`×3 (6 B). If a REPEAT-style
  encoding could ever be made cheap enough (~6 B handler), it's ~6-8 B
  saved. Previously rejected but the margin was thin.
- **Fsub's lea rcx is still present** (for the Fadd-jump-in path).
  If Fadd could preserve rcx = &P through its fe_sub_raw call, Fsub
  could drop it. fe_sub_raw's `xor ecx,ecx` is the killer — but that
  xor doubles as the CF-clear for sbb. If Fadd pushed rcx before the
  call and Fsub popped it... costs 1+1, saves 4. Net −2. Worth trying.
- **4 rel32 jumps remain** (fe_mul_m, fe_sub_raw, .Lf trampoline,
  .Lepi5). All >127 B. Function reordering hasn't helped yet, but
  with each size reduction the distances shrink.
