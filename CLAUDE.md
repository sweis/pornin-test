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

**Best result:** `tv_ecdsa_fast.S` — 1397 bytes, ~0.65M cycles on
Sapphire Rapids (fast/bc ratio ~0.35). BMI2+MOVBE required. See
README.md for technique writeups and BENCHMARK.md for cycle attribution.

## Workflow

```
make size-fast test-fast wp-fast bench    # edit-build-test loop
```

Full test gate is 33 hand-picked vectors + 574 Wycheproof = 607 tests.
Must pass 607/607 before any commit. ASAN/UBSAN via the C harness in
test_ecdsa.c.

## Invariants that silently cost bytes if broken

- **Jump table offsets must fit u8.** `.Ljt` to each handler is stored
  as one byte. Current max is Fadd at **244**/255. **~11 bytes of
  growth headroom** before overflow. cond_sub_n (9 B) + inlined fe_geq
  (+10 B) both sit in the handler block now; adding code between `.Ljt`
  and `.Lop2` costs this budget. The table itself is **8 entries** (op4
  Fto_mont was absorbed into Fmul). cGXM (64 B) now sits right before
  .Ljt — it doesn't count against this budget.

- **Bytecode stream offsets must fit signed imm8.** All `push obc_X`
  encode as `6a XX` only if `obc_X` ≤ 127. Current max is bc_v1 at
  118. Stream order in `.rodata` is deliberately `dbl, v2, v3, add1,
  add2, v1` to keep this true. Adding bytecode ops will push bc_v1 past
  the limit.

- **`.rodata` before `.text` is load-bearing.** gas only picks the
  2-byte `push imm8` encoding for backward references. Move `.rodata`
  back down and every `push obc_X` silently becomes 5 bytes.

- **`oP_early` in the decoder is hardcoded (48).** It's asserted against
  the real `oP` with `.error`. If `.Ljt` layout changes (table size, or
  reordering cN_M0I/cN), the assert fires. Good — but it means you'll
  hit a build error, not a runtime bug.

- **cN→cP→cBM→cR2P adjacency** is load-bearing for verify's 16-qword
  `rep movsq` that loads the constants into slots 8-11. cR2P in slot 11
  is how the to-Montgomery bytecode ops (plain Fmul with s2=0xb) work.

- **r14 = slot base is an invariant through pt_add_acc/pt_mul.** Both
  functions read r14 directly with no frame of their own. bc_run
  pushes/pops r14 around every dispatch, so it always comes back. If
  any future change has pt_mul/pt_add_acc called with a different r14,
  this breaks silently.

- **.Lai is called from pt_mul.** It's not just a label inside
  pt_add_acc's infinity branch — pt_mul uses it to zero the accumulator
  and relies on it returning eax=0.

- **Slot layout in pt_add_acc:** bc_dbl/bc_add1/bc_add2 use slots 0-11.
  Slots 12-15 are preserved (verify stashes r, u1, u2, `one` there —
  **slot 15 is read by bc_v3**, not dead after bc_v2). Slots 16-19
  hold G.xy + Q.xy-backup for the Shamir swap. Frame is 20 slots
  (648 B). Changing bytecode slot usage can trash verify's state.

- **Slot 6 = Mont(1) is load-bearing for Shamir.** bc_dbl/add1/add2
  never write slot 6. pt_mul's G-swap copies only slots 4-5, relying
  on slot 6 serving as z for both G and Q. Any bytecode change that
  writes slot 6 breaks this silently.

- **rcx=0 after every bcrun_r14 return** (and after fe_iszero,
  fe_sub_raw, rep movsq/stosq, fe_from_be, cond_sub_n, pt_add_acc).
  Nine `mov cl,N` sites rely on the high bytes being zero. The chain:
  every bytecode stream's final op is Fmul/Nmul/Fsub/Fadd/check, all
  of which end with fe_sub_raw's `dec ecx→0` loop or fe_iszero's
  `loop→0`; the END-word dispatch (`test;jz`) skips the decoder so
  its `lea rcx,[r14+oP]` never runs after the last handler. **Adding
  a bytecode op that leaves rcx nonzero breaks 9 sites silently.**

- **rbp is a true frame pointer from enter to leave in verify and
  fe_inv_m.** Neither function reads or writes rbp in its body, and
  every callee either ignores rbp or push/pops it (bc_run, pt_mul).
  r15 carries verify's slot-2 mid-pointer now. Any change that
  clobbers rbp between enter and leave breaks the epilogue silently.

- **pt_mul takes &u1 in rbx, not rsi.** verify's rbx already holds
  slot 13 from the stockpile; pt_mul reads it directly (never
  pushes/writes rbx). bc_run and pt_add_acc's callees all preserve
  rbx. Single caller, so no ABI drift concern, but any second caller
  must set rbx first.

- **.Lf2's `jmp .Ld2` is rel32 (141 B forward).** The body between
  `1:` and `.Ld2` is right at the edge — shrinking it by ~14 B would
  let this become rel8 (−3 B). Don't add anything between the
  inverted `jnc` and `.Ld2` without measuring.

## Things tried and rejected (don't re-explore)

| Idea | Why it failed |
|---|---|
| `rep stosq` in fe_mul_m zero loop | +140K cycles measured for −3 B. Startup penalty at count=9 is ~140 cyc/call, not the ~25 rule of thumb. |
| Swap rbx↔r14 in verify | 1-byte `push rbx` stockpile for `mov rdi,r14` — but the final `push rbx×4` block becomes `push r14×4` (+4). Net 0. |
| Drop r13 mid-pointer | Each `[r13+N]` → `[r14+384+N]` is disp32 (+3/site × 7). Net +14. |
| REPEAT bytecode opcode | Handler cost > the 6-8 B of repeated `0x92,0x99`/`0x43,0x11`. |
| Merge .Lop7/.Lop8 via sense bit | fe_iszero clobbers rcx; discriminator doesn't survive. |
| ~~`enter`/`leave` for verify frame~~ | **DONE** (−3 B) by moving slot-2 to r15 so rbp stays a genuine frame pointer. Also applied to fe_inv_m (−3 B). |
| Length-counted bytecode (vs 0x0000 terminator) | +7 B in bc_run for −6 B of terminators. Net +1. |
| Build cP at runtime | p has nice structure (all 0x00/0xFF bytes) but limb 3 = `0xffffffff00000001` costs as much to build as store. |
| fe_cpy inlined | 3 callers × 5-byte call + 9-byte body = 24 B. Inlined: 3 × 8 B = 24 B. Wash. |
| fe_inv_m caller sets r15=m0i directly | `pop r15` in `.Lepi4` (shared with fe_mul_m) restores the pushed value, not the caller's original. ABI break. |
| cGXM in bytecode-offset scheme | 64 bytes; wherever it sits, it pushes some bc_X past 127. |
| cGXM contiguous with cN..cR2P for 24-qw block copy | Landing slots conflict: slots 12-13 hold r,s. Every slot reshuffle tried hits a different conflict (G clobbered by bc_v2, or bc_v1's mont-conversion dst slots). −4 B best case, not worth the reshuffle risk. |
| Embed muladd4 inside fe_mul_m for rel8 calls | **x86-64 has no `call rel8`** — only `call rel32`. The +2 B `jmp` over muladd4 buys nothing. |
| Slot-9 as &cP for second fe_inv_m | Slot 9 has cP after the block copy but pt_mul's bc_dbl writes slot 9 as scratch — it's garbage by the time the second fe_inv_m needs it. |
| 32-bit length compares (`cmp esi` vs `cmp rsi`) | −2 B but accepts sig_len = 4GB+64 as valid. Behaviorally harmless (reads 64 bytes, verification fails) but technically violates the API contract. Skipped out of caution. |
| ~~Inline verify epilogue + drop bc_run's r13 push~~ | **DONE** (−4 B) once verify got its own leave-based epilogue — the .Lepi5 share was already gone, so the r13 push/pop was pure dead weight. |
| fe_mul_m takes r12/r13/r14 directly (drop movs) | Fmul/Nmul must set r12/r13/r14 **before** the tail-jump, which is before fe_mul_m's `push` — so bc_run's loop invariants (r12=slot_base, r14=.Ljt) are destroyed between handler calls. fe_mul_m's push/pop restores the *clobbered* values, not bc_run's. Segfault on second dispatch. −12B estimate was a mirage. |
| Drop `neg eax` from fe_sub_raw | (borrow=1,carry=1) is reachable under CIOS (carry=1 ⇒ t≥2^256 ⇒ t_low<m ⇒ borrow=1). With −1/0 instead of 1/0, `sub eax,carry` gives −2≠0 for (1,1); the old 1−1=0 correctly takes jz to skip the copy (r already holds t−m). |
| Indexed fe_sub_raw (no pointer advance) | Down-count `[rsi+rcx*8-8]` with `loop` processes high limb first — borrows propagate low-to-high, so this computes the wrong result. Up-count needs inc+cmp+jne (7 B > 4 B for lea+dec+jnz). |

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
- `xchg eax, r32` is 1 byte (`90+r`). Only `eax` gets this encoding.
  Useful when eax is dead after.
- `mulx` preserves **all flags** (CF, OF, ZF, everything). This lets
  you thread a live CF from an `add [mem]` straight through the next
  `mulx` into an `adc` — no barrier needed. This was the −16 B win
  in muladd4 (and ~13% cycles from the shorter dependency chain).
- `and dl, imm8` is 3 bytes (80 e2 XX); `and al, imm8` is 2 bytes
  (24 XX — special encoding). Matters for nibble extraction.

## Possible next directions

- **ADX dual carry chains in muladd4.** `adcx`/`adox` interleave two
  carry chains. **Partly subsumed by the mulx-preserves-flags elision**
  (which already dropped 4 of the 8 `adc r,0` barriers without ADX).
  Remaining ADX win is parallelism, not barrier elimination — but
  `adox` has no mem-dst form, so t would need to go into registers
  (big restructure). Estimate now: −5% cycles, +20–50 B.
- **~~Shamir's trick~~** — DONE at +22 B, ~30% cycles. Key insight:
  slot 6 (z=Mont(1)) is never written by bc_dbl/add, so swapping just
  X,Y (8 qw) between G and Q in slot 4-5 is enough — no second bytecode
  stream. Gotcha found during dev: **slot 15 is NOT dead after bc_v2**
  — bc_v3 reads it (as `one`) for the final from-Montgomery conversion.
  G/Q-backup must go in slots 16-19; frame grew by one slot (0 B, still
  imm32).
- **Remaining bytecode compression.** bc_dbl has `0x92,0x99`×4 (Fadd
  doubling, 8 B) and bc_v1 has `0x43,0x11`×3 (6 B). If a REPEAT-style
  encoding could ever be made cheap enough (~6 B handler), it's ~6-8 B
  saved. Previously rejected but the margin was thin. **Warning:**
  handler block headroom is down to ~11 B now.
- **.Lf trampoline (5 B rel32).** Currently jumps +260 B forward to
  .Lf2. Needs verify to shrink by ~133 B for this to become rel8 —
  unlikely without extended bytecode.
- **pt_add_acc's first path (acc.z==0 → copy Q to acc) shares
  `mov rdi,r14` with .Lai.** Both paths set rdi=r14 then do a 12-qword
  rep op (movsq vs stosq). Can't merge the rep itself but a
  `.Lrdi14: mov rdi,r14; ret` helper costs 4 B and saves 3×3 = 9 B...
  wait no, call is 5 B not 3. Net +4−9 = wash with 3 callers. With 2
  callers: loss.
- **The .Lf trampoline could move one slot earlier** (before the last
  length check instead of after it). `jbe` would then need to jump
  forward past it (+5 B) but all the jne's reach .Lf2 directly... no,
  they'd go through the trampoline anyway. Doesn't help.

## Bigger restructures under evaluation

**Note (post-1427B / post-Shamir):** the r14-invariant pass found
−70 B; Shamir ate another ~30 B of verify's middle (the stash/
restore block). The estimates below for bitwalker-merge and derive-
constants predate these — re-measure. Handler headroom is ~11 B
(Fadd at 244/255). **Extended bytecode has been re-measured below
and is now −3..−8 B, not −40..−60 B.**

These each need a dedicated session. Byte accounting below is from
actual disasm measurements, not estimates.

### Merge the bit-walkers (fe_inv_m + pt_mul)

Both are MSB-to-LSB bit-scan loops: unconditional square/double, then
conditional mul/add. Structurally identical.

| | fe_inv_m | pt_mul |
|---|---:|---:|
| total | 97 B | 55 B |
| loop body alone | 35 B | 28 B |
| prologue/setup/epilogue | 62 B | 27 B |

**Native callbacks don't fit.** A generic `bitwalk(bitvec, nbits,
cb_sqr, cb_mul)` needs 4 regs for its own state plus the callbacks need
access to the closure context. fe_inv_m's callbacks need r/a/m/m0i =
4 regs. Total 8 callee-saved regs needed; x86-64 has 6. State spills to
stack → callback stubs grow to ~15 B each → 4 stubs × 15 + ~20 B walker
= 80 B shared. Net vs current 97+55 = 152 B: only −5 B after adding per-
caller setup (~15 B × 4 = 60 B). Wash at best.

**Bytecode callbacks are the real angle.** fe_inv_m's square IS a SQR
bytecode op; its mul IS an Fmul op. A walker that takes two bytecode
stream offsets and runs one (then conditionally the other) 255× would
let fe_inv_m become: setup (46 B stays) + 2 tiny bytecode streams (4 B
each w/ terminator) + walker call. Walker itself ~25 B.

But fe_inv_m's loop needs .Lfm which loads m/m0i from r14/r15 set by
fe_inv_m's prologue. A bytecode SQR op goes through bc_run which has its
OWN r14/r15. So fe_inv_m-as-bytecode would need `Fmul` to use the right
modulus — which it does, mod-p. For mod-n, use `Nmul`. So fe_inv_m mod-p
= a loop of {SQR; conditional Fmul}, mod-n = {SQR-n?; conditional Nmul}.

Problem: there's no SQR-mod-n opcode, and fe_inv_m's square is mod-m not
mod-p. Would need either an Nmul-square variant or pass the modulus as
a handler arg. Doable but ~10 B.

**Bottom line:** this CONVERGES with extended bytecode (below). As a
standalone change, +10 to −5 B — not worth it. As part of extended
bytecode, fe_inv_m could become an INV opcode that runs a tight native
bit-loop calling Fmul/Nmul handlers directly. The loop body would be
~20 B and the 46 B setup mostly vanishes (decoder already computes
slot addresses). Defer to extended-bytecode evaluation.

### Derive structured constants at runtime

Constant-structure survey (bytes that are 0x00 or 0xFF):

| | size | structured | other | buildable? |
|---|---:|---:|---:|---|
| cP | 32 | **31** | 1 (`0x01`) | yes — 4 limbs, all 0x00/0xff except one byte |
| cR2P | 32 | 27 | 5 | maybe — 5 bytes to patch on top of all-FF |
| cN high 16 | 16 | **16** | 0 | yes — pure 0x00/0xff |
| cN low 16 | 16 | 0 | 16 | no — random |
| cBM, cN_M0I | 40 | ~0 | ~40 | no |

A fill-FF-then-patch builder for cP alone:
```
push -1; pop rax; push 4; pop rcx; rep stosq  ; 9 B: 32 × 0xFF
xor eax,eax; mov [rdi-16],rax; mov [rdi-20],eax ; 9 B: zero limb2 + limb1.hi
mov DWORD PTR [rdi-8], 1                       ; 7 B: limb3.lo = 1
```
= 25 B of code for 32 B of data. Marginal (−7 B).

**The real blocker is addressing geometry.** Handlers read cP via the
decoder's `lea rcx,[r14+oP]` (r14 = .Ljt, disp8). Built constants live
in RAM — verify's stack frame. Options:

- **[r12+disp8]** (r12 = slot base in bc_run): only slots 0–3 are disp8-
  reachable (0/32/64/96 ≤ 127). All four are working slots clobbered by
  every bytecode stream. Would need to rebuild cP before each bc_run.
- **[r12−disp8]** (below slot 0): that's bc_run's own saved-register
  area (5 pushes = 40 B below slot 0). Conflict.
- **A new base reg**: bc_run is out of callee-saved regs.

**Cleanest path found so far:** build into slot 9 (where bc_v1 expects
it anyway — replacing verify's cN/cP/cBM block copy), and have the
handlers that need cP outside bc_v1 (which is all of Fmul/Fsub/Fadd)
address it at `[r12+288]`. That's disp32: decoder's rcx preload grows
+3 B, Nmul's cN load grows +3 B, .Lop4's cR2P grows +3 B. Plus
splitting the block copy (cN and cBM no longer adjacent once cP is
gone) costs ~5 B.

Net: −32 B (cP data) + ~25 B (builder) + 9 B (disp32 × 3) + 5 B
(split copy) = **−7 B at best**. And that's only cP.

**If the builder also covers cN-high and cR2P**, potential savings
grow to ~−25 B. But cR2P's 5 patch bytes cost ~25 B of builder
(5 × `mov BYTE PTR [rdi+N], V` ≈ 4-5 B each), and cN-high (16 B)
needs its own patch sequence. Builder grows to ~50 B for 80 B of
data = −30 B raw, minus addressing costs (~15 B) = **~−15 B**.

**Verdict: worth a prototyping session.** The win is real but modest.
The addressing problem might have a cleverer solution — e.g. build
constants at verify entry into a spot that becomes disp8-reachable
from r14 after rearranging .Ljt layout. Or: fold cR2P into the
bytecode — it's only used by `.Lop4` (Fto_mont), which is called
3 times in bc_v1. If Fto_mont read R²_p from a SLOT instead of .text,
and that slot were built... this is the thread to pull.

### Extended bytecode — INV opcode (post-Shamir re-measurement)

**Revised estimate at 1427 B: −3 to −8 B.** Shamir ate most of the
replaceable middle; only the two fe_inv_m calls (41 B combined)
remain as clean bytecode candidates. Everything else has external
pointers (sig/pub/hash/cGXM/cN) that nibbles can't encode.

**Disasm-measured verify segments (1427 B build):**

| Segment | Bytes | |
|---|---:|---|
| prologue + length checks | 58 | native (branches, stack) |
| decode sig/pub, build_one, block-copy | 72 | native (external ptrs, rip-rel) |
| bc_v1 dispatch | 10 | already bytecode |
| **fe_inv_m mod-n** | **22** | **→ INV_N** |
| hash decode + cond_sub_n | 15 | native (rbx=hash ptr; pops tied to inv pushes) |
| bc_v2 dispatch | 8 | already bytecode |
| Shamir setup (G→16-17, Q→18-19) | 28 | native (cGXM is rip-rel) |
| pt_mul + fe_iszero | 19 | native (too small to amortize handler) |
| **fe_inv_m mod-p** | **19** | **→ INV_P** |
| bc_v3 dispatch | 8 | already bytecode |
| cond_sub + fe_sub_raw + epilogue | 47 | native (push rbx×4 trick, shared epi) |

**One unified INV handler (19 B) — the clever bit:**

s2 nibble = **slot index of the modulus**. Verify's block-copy
already puts cN in slot 8 and cP in slot 9 — so `s2=8` means mod-n,
`s2=9` means mod-p. The decoder computes rdx = &slot[s2] for free
(it does this for Fmul's b-pointer). Only m0i needs discrimination.

```asm
INV: ; rdi,rsi = dst,src slot addrs.  rdx = &modulus (s2 slot).
     ; rcx = &cP (decoder's preload, at .Ljt+oP).  al still holds byte 1.
  mov  rcx, [rcx-40]   ; 4B: cN_M0I at oP-40 = .Ljt+8
  test al, 0x10        ; 3B: s2 bit 0 (8=1000 vs 9=1001)
  jz   1f              ; 2B: s2=8 → mod-n, keep cN_M0I
  mov  ecx, 1          ; 5B: s2=9 → m0i_p = 1
1:jmp  fe_inv_m        ; 5B: tail call (fe_inv_m preserves r12-r15,rbx,rbp)
```

Bytecode encoding (op nibble 8 or wherever the table slot lands):
- INV_N = `0x88, 0x0d` (s2=8, dst=0, s1=13)
- INV_P = `0x98, 0x32` (s2=9, dst=3, s1=2)

Prepend to bc_v2 and bc_v3 respectively. No new dispatch calls; 2 B
each in existing streams. bc_v1 shifts 118 → 122 < 127. ✓

**Jump table overflow — rel8 trampoline (+2 B):**

Fadd at **244**/255. Handler (19 B) + table entry (1 B) before Fadd
→ 264. Overflows. Fix: 2-B `jmp rel8` trampoline right before Fadd
(offset ~243), handler body AFTER Fadd. Table entry → trampoline →
jmp +~23 → handler. Fadd shifts +2 → 246 < 255. ✓

Ripple edits (0 B cost, easy to miss):
- `oP_early` hardcode 48 → 50. The `.error` assert will catch it.
- `[r12-80]` for cGXM (verify + Shamir setup, 2 sites) → `[r12-82]`.
  grep for `r12-80` before committing.

**Stockpile unwind cost (+6 B) — can't dodge:**

Current `push rsi×2` in the inv-n block feeds `pop rdi×2` for
fe_from_be(hash) and cond_sub_n. With INV in bc_v2, pushes vanish.
Reordering hash-decode before bc_v2 (safe — no dependency on slot 0)
costs the same +6 B: pops(2) → leas(8). The stockpile was a real win
and losing it costs exactly what it was worth.

**Final accounting:**

```
  handler 19 + trampoline 2 + table 1 + bc 4 + unwind 6  =  32 B cost
  inv-n native 22 + inv-p native 19                       =  41 B save
  NET: −9 B  (optimistic; realistic −3 to −8 after slippage)
```

**Implementation order if attempting:**
1. Scaffold with 5-B rel32 trampoline (not 2-B rel8) — proves the
   fe_inv_m-from-bytecode path works end-to-end. Expect −6 B.
2. Confirm bc_run's `lea rcx,[r14+oP]` is live at handler entry
   (disasm check — it's before the table jump).
3. Reorder hash-decode before bc_v2 (isolate the unwind cost).
4. Shrink trampoline rel32→rel8 once placement is stable. −3 B more.

**Don't bother with CONDSUB/PTMUL/CPY3 as follow-ons.** Each saves
only 3-7 B against its own handler cost, and they don't share
infrastructure with INV (no modulus discrimination). PTMUL would
nest bc_run inside bc_run (fine — pt_mul already does this) but the
call is 9 B native, handler ~8 B, bytecode 2 B. Net −1 B at best.
