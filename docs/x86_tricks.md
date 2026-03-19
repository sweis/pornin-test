# x86-64 Size-Golf Instruction Catalog

MOVBE baseline, no BMI2. Encodings gas-verified. Three categories:
**USED** (in current builds), **ACTIONABLE** (not yet tried / conditional),
**DEAD** (non-obvious reasons only — obvious stuff not re-listed).

**Already exploited, not re-cataloged:** `xlatb`, `enter`/`leave`,
`lods`/`stos`/`scas`/`movs`, `loop`, `jrcxz`, `push imm8`,
`bt [mem],reg`, `repe scasq`, `movbe`, `sbb reg,reg`, `rcl`, `cmc`.

---

## 1. One-byte ops

### `cdq` / `cqo` — sign→{0,−1}, 1 B / 2 B — ACTIONABLE
`edx ← (eax < 0) ? −1 : 0`, flag-preserving. Beats `mov;sar` by 4 B.
`cqo` (2 B) does rax→rdx. **limb11 `.Lnorm` candidate** — js/jns branch
around separate ±1 loads; if sign lives in eax top bit, `cdq` gives the
mask directly. Follow with `lea edx,[rdx+rdx+1]` (4 B) for {−1,+1}.

### `cwde` / `cdqe` — sign-extend, 1 B / 2 B — USED (cdqe)
`cdqe` = `movsxd rax,eax` in 2 B not 3. Grep: neither codebase currently
does `movsxd rax,eax` — keep noting for new code. `cwde` (1 B) = free
`movzx eax,ax` **only if ax < 32768**.

`cwde` after `lodsw` for limb11 top limb: **DEAD.** cN top16=0xFFFF,
cGX=0x905F — both bit15 set → sign-extends wrong. Off by 2^256.

### `xchg eax,r32` — 1 B (`91`–`97`) — USED
limb8 `xchg ebp,eax` at pt_mul init. **Zero-extends both** rax and the
other reg (32-bit dest write × 2). Flag-preserving. 1 B vs `mov` 2 B
when rax is dead and you need a move that doesn't touch stack.

### `lahf`/`sahf` — flags↔AH, 1 B each — DEAD for limb11
No topology fits. All CF uses are immediate set→jcc (shr→jc, bt→jnc,
neg→rcl) — zero gap to bridge. NORM's `push rdx`/`pop rdx` (2 B)
preserves a 64-bit {0,−1} direction, not a flag. `.Lasmod`'s `lodsq`
clobbers rax so AH wouldn't survive anyway. → `DEAD_ENDS.md`

### `std`/`cld` — direction flag, 1 B each — DEAD for current topology
DF affects **both** rsi and rdi. The only clean win is when source and
dest both walk backward. Our byte-reversal reads forward, writes backward
via index arithmetic — no simultaneous-backward pattern exists.

---

## 2. AL short-form encodings — USED

`op al,imm8` is 2 B (dedicated opcode); `op r8,imm8` generic is 3 B.
Applies to add/or/adc/sbb/and/sub/xor/cmp/test. **We use** `cmp al,0x04`
(limb8), `test al,63` (limb11).

Caveat: `and al,N` doesn't zero-extend; if code relies on bits 8–31
being clean (e.g., before xlatb), `and eax,N` (3 B) is load-bearing.
limb11's `and eax,0xF` is this case — don't "optimize."

**`test eax,imm` has no imm8 form** — always 5 B. Use `and eax,imm8`
(3 B) when the write is tolerable, or `test al,imm8` (2 B) for low-byte.

---

## 3. Flag-preserving ops — reference

Load-bearing for carry-chain scheduling. Complete list of arithmetic-flag-clean ops:

| Op | Notes |
|---|---|
| `mov`, `lea`, `push`/`pop`, `xchg` | all forms |
| **`not`** | **2 B (r32) / 3 B (r64).** The only bitwise op that doesn't touch flags. `xor r,-1` is +1 B and clears CF. Any future `a−b = a+~b+1` should use this. |
| `bswap`, `cbw`/`cwde`/`cdqe`, `cdq`/`cqo` | clean |
| `movzx`/`movsx`/`movsxd`, `setcc`, `cmovcc` | clean |
| `lahf` | reads flags, writes AH, modifies none |
| `lods`/`stos`/`movs` (non-rep), `rep movs`/`rep stos` | clean |
| `loop` | **all flags** (we rely on this in `.Lop3` sbb chain) |
| `jcc`/`jmp`/`call`/`ret`, `enter`/`leave` | clean |
| `inc`/`dec` | **CF preserved**, others clobbered |
| `rol`/`ror` | CF set, **SF/ZF/AF/PF unchanged** |

---

## 4. Dead in 64-bit — don't revisit

| Opcode | What it would have been |
|---|---|
| `salc` (D6) | AL←CF?0xFF:0 — SIGILL. Use `sbb al,al` (2 B). |
| `aad`/`aam imm8` (D5/D4) | Free 2-byte mul-add/divmod — gone (VEX space). |
| `daa`/`das`/`aaa`/`aas`, `into`, `bound`, `pusha`/`popa` | All #UD. |
| `mov ds,eax` nonzero | Segfaults — selector still validated. 16-bit scratch only holds zero. |

---

## 5. String-op oddities

### `rep lodsq` — `rsi += rcx*8` + rcx←0 + rax←last, 3 B — ACTIONABLE (no site yet)
`lea rsi,[rsi+rcx*8]; xor ecx,ecx` = 6 B → 3 B. Clobbers rax. Cold-path only (microcoded ~N cyc).

### `repe cmpsq` for bignum geq — DEAD for limb8 `.Lop5`
+1 B measured. `loopz` with `[reg+rcx*8-8]` SIB already gets high→low
scan for free — std/cld needs 8 B pointer setup that the indexed form
doesn't. Only wins against a branchy `jb`/`ja` baseline. → `DEAD_ENDS.md`

### `push [mem]; pop [mem]` — 4 B mem→mem qword — ACTIONABLE (no site yet)
Beats `mov rax,[rsi]; mov [rdi],rax` (6 B) by 2 B when rsi/rdi aren't
set up for `movsq` (2 B). No current non-movsq mem→mem.

---

## 6. BMI1/BMI2/ADX — never smaller

All VEX (5-6 B). `mulx`/`adcx`/`adox` are speed tools (fast2.S uses them).
`bzhi` loses to `and imm8` for fixed masks. `andn` = `not;and` (4 B) vs 5 B.
Only theoretical win is `blsi` (5 B) vs `mov;neg;and` (6 B) — no ECDSA use.

---

## 7. Dispatch: xlatb is optimal

limb11: `and eax,0xF; xlatb; add rax,rbx; call rax` = 9 B + 11×1 B table.
`call [rbx+rax*8]` = 6 B dispatch, **+77 B table** (8-byte entries). Net +74 B.
`jmp [tbl]` + handler `jmp` back: worse (ret → jmp rel8/rel32 growth).
**u8 offset table is the dominant savings. Don't revisit.**

---

## 8. Misc actionables

### `shld`/`shrd` — 128-bit shift, 5 B — ACTIONABLE (limb5×54)
`shrd rax,rbx,N` beats `shr;mov;shl;or` by ~9 B per limb boundary.
Promising for 54-bit stride crossing qword boundaries. Not obviously
better for limb11 (byte-aligned 24-bit chunks already tight).
**AMD: microcoded ~6-8 cyc; Intel: 1 cyc.** Check target.

### `mul` CF/OF — free `edx≠0` test, 0 B marginal — ACTIONABLE (no site)
After `mul r`, CF=OF=(high half ≠ 0). `mul;jc` saves `test edx,edx` (2 B).
No current per-mul overflow test (reduce checks t[j+8] after accumulate).

### `ret imm16` — callee-pops, 3 B — DEAD for current ABI
Net = −4·sites + 2. Needs ≥2 sites with caller-pushed args followed by
`add rsp,N`. Our stack use is callee-saved regs, not caller-pushed args.

### `cmovcc` — 3 B (r32) — ACTIONABLE (marginal)
−1 B vs branch-around-mov (`jnc 1f; mov; 1:` = 4 B). Plausible in
`.Lnorm`/`.Lchklt` but needs a pre-loaded alternate value — setup
usually eats the saving.

### `inc byte ptr [mem]` — 2 B vs qword 3 B — USED
Saves 1 B when upper bytes known zero (no carry-out). Heavily used in
limb11 cP-build and limb8 slot-1 init.

---

## 9. Summary — remaining candidates

| Trick | Est. win | Confidence | Where |
|---|---|---|---|
| `cdq` sign→{0,−1} | −4 B | medium | limb11 `.Lnorm` |
| `not` vs `xor r,-1` | −1 B + flag clean | high | future complement |
| `shrd` for 54-bit limb decode | ~−9 B/boundary | untested | limb5×54 |
| `rep lodsq` as rsi bump | −3 B | low | no site |
| `push/pop [mem]` 1-qw copy | −2 B | low | no site |
| `cmovcc` vs branch-mov | −1 B/site | low | cold conditionals |
| `mul` CF overflow test | −2 B | low | no per-mul test |

**Confirmed dead:** `cwde` top limb, `std+repe cmpsq` geq, `lahf/sahf`
transport, `ret imm16`, all BMI/ADX, `call [tbl]` dispatch.

---

## Appendix: microcode latencies (hot-loop check)

| | uops | lat | |
|---|---|---|---|
| `loop` | ~7 | ~5 | known catastrophic |
| `scas*` | ~3 | | microcoded |
| `lahf`/`sahf` | 1/2 | 1/2 | cheap |
| `cdq`/`cqo` | 1 | 1 | cheap |
| `xchg r,r` | 2 | | fine; `xchg r,[m]` ~8 (lock) |
| `not`, `cmov`, `bsf` | 1 | 1–3 | ALU |
| `shld`/`shrd` | **1 Intel / ~6 AMD** | 3 | arch-dependent |
| `rep lodsq` | ~N | ~N | no fast-path |
| `std` | ~4 | | mildly serializing |
