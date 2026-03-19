# x86-64 Underused-Instruction Catalog for Size Golf

Target: ECDSA/P-256 verify, 64-bit mode only, **MOVBE baseline** (no
BMI2 in shipping builds). All encodings verified empirically with gas +
objdump on this box. Runtime behavior verified where documentation was
ambiguous.

**Already exploited** (not re-cataloged): `xlatb`, `enter`/`leave`,
`lods`/`stos`/`scas`/`movs`/`cmps` (all widths), `loop`, `jrcxz`,
`push imm8`, `bt [mem],reg`, `repe scasq`, `movbe`, `sbb reg,reg`,
`rcl`, `cmc`, `clc`, `stc`.

---

## 0. DEAD IN 64-BIT MODE — don't waste time

Confirmed by SIGILL on this box. Cross off permanently.

| Opcode | Mnemonic | What it would have done |
|---|---|---|
| `D6` | `salc` | AL ← CF ? 0xFF : 0x00. **SIGILL.** Use `sbb al,al` (2 B). |
| `D5 ib` | `aad imm8` | AL ← AH·imm + AL; AH ← 0. A free 2-byte mul-add — **gone.** Opcode reused for VEX space. |
| `D4 ib` | `aam imm8` | AH ← AL / imm; AL ← AL mod imm. Also **gone.** |
| `27`/`2F`/`37`/`3F` | `daa`/`das`/`aaa`/`aas` | BCD adjusts. All #UD. |
| `CE` | `into` | Trap on OF. #UD. |
| `62` | `bound` | Array-bounds check. Repurposed as EVEX prefix. |
| `9A`/`EA` | far `call`/`jmp` immediate | #UD. |
| `60`/`61` | `pusha`/`popa` | Would have been nice. #UD. |
| `C4`/`C5` | `les`/`lds` | Now VEX prefixes. |

**Segment-register scratch storage: also dead.** `mov ds, eax` with a
nonzero selector **segfaults** (the load still goes through segment
selector validation). `mov ds, eax` with `eax=0` succeeds, but a 16-bit
scratch that can only hold zero is useless.

---

## 1. One-Byte Instructions We Don't Use

### 1.1 `cdq` — sign of eax → edx, 1 byte (`99`)

**Semantics:** `edx ← (eax < 0) ? −1 : 0`. Zero-extends rdx (32-bit
dest write). **Preserves all flags.**

This is `mov edx,eax; sar edx,31` in **one byte** instead of five.

**Use case (limb11):** `.Lnorm` picks between add/sub based on sign.
Currently `js/jns` branch around separate `push 1;pop rdx` and
`push -1;pop rdx` blocks. If the sign lives in eax's top bit, `cdq`
gives you `rdx ∈ {0, −1}` directly; follow with `lea edx,[rdx+rdx+1]`
(4 B) or `or edx,1` (3 B, if −1 is what you want and you need +1 when
eax≥0) to get `{−1, +1}`. Net depends on context but the −1/0 split
alone is often usable as an arithmetic mask.

**Also:** setup for `idiv` — if eax is known nonnegative, `cdq` is a
1-byte `xor edx,edx`. We don't divide, but worth noting.

**`cqo`** (`48 99`, 2 B) is the 64-bit version: `rdx ← sar(rax,63)`.
Useful in limb11 where limbs are signed 64-bit — `cqo` after loading a
limb gives the full-width sign mask for free.

### 1.2 `cwde` / `cdqe` — sign-extend chain, 1 B / 2 B

| Encoding | Op | Semantics |
|---|---|---|
| `98` | `cwde` | eax ← sign_extend(ax). Zeroes rax[63:32]. |
| `48 98` | `cdqe` | rax ← sign_extend(eax). |
| `66 98` | `cbw` | ax ← sign_extend(al). Leaves rax[63:16] alone. |

**All preserve flags.**

`cdqe` = `movsxd rax,eax` in 2 B instead of 3 B. **Directly saves 1 B**
anywhere we sign-extend eax→rax.

`cwde` is a cheap "zero bits 16–63 of rax, conditionally set bits 16–31
if ax was negative." If ax is known ≤ 32767 (top bit clear), this is a
1-byte `movzx eax,ax`. **limb11's lodsw:** after `lodsw` (2 B, 66h
prefix keeps rax[31:16] as prior garbage), follow with `cwde` (1 B) if
the value is known < 32768 → eax clean. Currently `fe_from_le` does `xor
eax,eax; lodsw` (2+2=4 B) for the top 16-bit limb. `lodsw; cwde` is 3 B
if limb 10 < 2^15. Check the range proof — top limb is ≤ 18 bits after
`fe_mul11`, but the *decoded* constant top limb is `p >> 240 = 0xFFFF`
for cP… no, cP is built signed. cN's top dword is `0xffffffff00000000`
→ top 16 bits of the 32-byte form are 0. **Probably applies.** −1 B.

### 1.3 `xchg eax, r32` — 1 byte (`91`–`97`), with a twist

Already used once (limb8 `xchg ebp,eax` at pt_mul init). But the
**zero-extension side effect is underused**:

**Verified empirically:** `xchg eax, ebx` (1 B, `93`) zero-extends the
upper 32 bits of **both** rax and rbx. It's a 32-bit destination write
to two registers simultaneously.

Use case: if you need to swap two values AND one happens to need its
upper bits cleared AND one is (or can be arranged to be) rax. Three
jobs, one byte. Niche but real.

Also: `xchg` preserves **all** flags. So it's a flag-transparent 1-byte
move when you have a dead rax: `xchg eax, ebp` costs 1 B vs
`mov ebp,eax` at 2 B, and unlike `push;pop` doesn't touch the stack
(matters inside stack-pointer arithmetic).

Microcoded on Intel (~implicit `lock` semantics for `xchg [mem],reg`,
but reg-reg is fine — ~2 uops, no latency concern for cold code).

### 1.4 `lahf` / `sahf` — flags ↔ AH, 1 byte each (`9F` / `9E`)

**CPUID-gated** (80000001H:ECX.0 — "LAHF-SAHF"). The original AMD64
spec dropped them; re-added circa 2005. Present on everything that has
MOVBE, so **our baseline covers it.**

`lahf`: AH ← `SF:ZF:0:AF:0:PF:1:CF` (bit 7 → 0). Preserves flags.
`sahf`: the reverse; CF/PF/AF/ZF/SF set from AH, OF unchanged.

**Use case — flag save/restore across a single flag-clobbering op:**

Currently when we need to preserve CF across something like `add rsp,N`,
we arrange things so it's the last flag-setter. With lahf/sahf:

```
lahf           ; 1 B — save CF (and SF, ZF, ...)
add rsp, 72    ; clobbers flags
sahf           ; 1 B — restore
```

vs `pushfq`/`popfq` (1+1 B but each is ~20 cycles microcoded) or
rescheduling. 2 B total; main win is that it **doesn't touch the
stack**, so it can wrap stack-pointer arithmetic without the push/pop
dance.

**Gotcha:** AH can't coexist with REX. `lahf; mov r8b, ah` is
unencodable. Stay in the low-8 world between lahf and sahf.

**Second use case — transport a flag for free.** If AH is dead and you
need CF *later* (after other flag ops), `lahf` stashes it at the cost
of 1 B, and `sahf; jc` is 3 B to retrieve. Compare `setc al`
(3 B) + `test al,al; jnz` (4 B) = 7 B → `lahf`…`sahf; jc` = 4 B.
**−3 B** if the topology fits.

### 1.5 `std` / `cld` — direction flag, 1 byte each (`FD` / `FC`)

`std` sets DF=1 → string ops **decrement** rsi/rdi. `cld` clears.
Verified: `lodsb` with DF=1 loads `[rsi]` then `rsi -= 1`.

**ABI requires DF=0 at call boundaries.** Any `std` must be followed by
`cld` before `call`/`ret`. 2 B overhead per region.

**Use case — limb8 `fe_from_be`:**
```asm
fe_from_be:
    mov  cl, 4
1:  movbe rax, [rsi+rcx*8-8]   ; 7 B — complex addressing for reverse
    stosq                      ; 2 B
    loop 1b                    ; 2 B
    ret
```
The reverse-indexing `[rsi+rcx*8-8]` is necessary because we read from
the high end of the source while writing to the low end of the dest. If
we `std`, we could `lodsq` forward through source (with DF=0, rsi
advances) and `stosq` backward through dest… but DF affects both. Would
need to flip DF mid-loop — `std`/`cld` each iteration is +2 B/iter.
Dead end for this specific case.

**Where it could work — limb11 `fe_from_be`:** the byte-reversal loop:
```asm
    mov  cl, 32
1:  lodsb
    mov  [rdi+rcx+55], al      ; 4 B — reverse-indexed store
    loop 1b
```
If dest pointer started at the top and DF was set:
```asm
    std                        ; 1 B
    lea  rdi, [rdi+87]         ; 4 B — top of scratch
    mov  cl, 32
1:  lodsb                      ; reads src forward? NO — also decrements
    ...
```
Same problem — DF affects both rsi and rdi. The only clean win is when
source and dest **both** want to walk backward. Our code never has this
topology. **Low priority** but leave in catalog in case a refactor
surfaces it.

### 1.6 `stc` — set carry, 1 byte (`F9`)

Trivial but unused. `stc; sbb eax,eax` = 3 B to load −1 into eax
(matches `or eax,-1` at 3 B — a wash). But `stc; sbb al,al` = 3 B to
load AL=0xFF without touching upper bytes (no shorter alternative).

More interesting: `stc` to prime a carry chain that needs an initial +1.
`stc; adc [rdi],eax` with eax=0 = 1+2 = 3 B "increment [rdi] by 1" …
which is the same size as `inc dword ptr [rdi]` (2 B) so worse. But if
you *also* need the carry to propagate: `stc` + adc loop gives you a
256-bit increment with the +1 baked into CF. Currently limb8 does a
separate `inc` for "set slot1=1 after zeroing"; not a carry-propagation
site, so `stc` doesn't help there.

---

## 2. Short-Form AL/AX/EAX Encodings

x86 gives AL (and only AL among the 8-bit regs) dedicated short-form
opcodes for `op al, imm8` — 2 bytes instead of 3.

| Op | `al,imm8` | `r8,imm8` (general) | Δ |
|---|---|---|---|
| `add al,N` | `04 ib` (2 B) | `80 /0 ib` (3 B) | −1 |
| `or al,N`  | `0C ib` (2 B) | 3 B | −1 |
| `adc al,N` | `14 ib` (2 B) | 3 B | −1 |
| `sbb al,N` | `1C ib` (2 B) | 3 B | −1 |
| `and al,N` | `24 ib` (2 B) | 3 B | −1 |
| `sub al,N` | `2C ib` (2 B) | 3 B | −1 |
| `xor al,N` | `34 ib` (2 B) | 3 B | −1 |
| `cmp al,N` | `3C ib` (2 B) | 3 B | −1 |
| `test al,N`| `A8 ib` (2 B) | 3 B | −1 |

**We already use `cmp al,0x04`** (limb8:878) and `and al,1`/`xor al,r9b`
in the check handler. Audit for more sites: any `op r8,imm8` where
moving the data into al first is free.

**Specific candidate — limb11:426:** `test al, 63` is already 2 B (`A8
3F`). Good. But `limb11:466 and eax,0xF` is 3 B (`83 E0 0F`); `and al,
0xF` would be 2 B — but the code relies on the zero-extend to clear
bits 8–31 of eax before xlatb. `and al` only writes al, leaving
lodsw's ah garbage. **Doesn't apply here** — the zero-extend is
load-bearing.

**`eax,imm32` forms** (`05`, `0D`, etc.) exist but are 5 B — they only
win over the generic 6-B `81 /r imm32` when the immediate doesn't fit
imm8. We don't have any large-immediate arithmetic on eax. Not useful.

### 2.1 `adc al, 0` / `sbb al, 0` — 2-byte carry materialization

`adc al,0` (`14 00`, 2 B): al += CF. If al was 0, al becomes CF (0 or 1).
`sbb al,0` (`1C 00`, 2 B): al −= CF. If al was 0, al becomes 0 or 0xFF.

**`sbb al,0` is the salc replacement** *if* al is already 0. Compare:
`sbb eax,eax` (2 B) always works but zeroes full eax. When you need al
specifically and eax upper bits must survive: `sbb al,0` (2 B) if al=0
precondition holds, or `sbb al,al` (2 B) which works unconditionally
but writes 0/0xFF and sets flags.

### 2.2 `adc al, -1` — 2-byte inverted-carry trick (`14 FF`)

`al = al + 0xFF + CF`. If al=0: CF=1 → 256 → al=0 (CF_out=1); CF=0 →
255 → al=0xFF (CF_out=0). **Inverted salc** with CF passed through
inverted. If you actually want !CF materialized and al is 0: free.

---

## 3. Flag-Preserving Operations (the complete list)

We rely on flag-preservation for shr-bitmask (limb11 BE decode loop:
`shr ebx,1` sets CF+ZF, then `jc`/`pop`/`jnz` all preserve enough to
test both). Here's every op that touches **no** arithmetic flags:

| Instr | Bytes | Notes |
|---|---|---|
| `mov` | varies | All forms. Never touches flags. |
| `lea` | varies | Never touches flags. Already heavily used. |
| `push`/`pop` | 1–2 | Known. `push imm` too. |
| `xchg` | 1–3 | **Verified.** Reg-reg and reg-mem both clean. |
| **`not`** | 2 (r32) / 3 (r64) | **Verified. Preserves ALL flags.** Unlike `neg` which sets CF. |
| `bswap` | 2 (r32) / 3 (r64) | **Verified clean.** |
| `cbw`/`cwde`/`cdqe` | 2/1/2 | **Verified clean.** Sign-extend chain. |
| `cdq`/`cqo` | 1/2 | **Verified clean.** Sign→edx/rdx. |
| `movzx`/`movsx`/`movsxd` | 3 | Clean. |
| `setcc` | 3 | **Verified clean.** Reads flag, writes byte, touches no flags. |
| `cmovcc` | 3–4 | Clean. Reads flag, conditionally moves, no flag write. |
| `lahf` | 1 | Reads flags, writes AH, doesn't modify flags. |
| `lods`/`stos`/`movs` | 1–2 | Clean (non-rep). rsi/rdi move, no flags. |
| `cmps`/`scas` | 1–2 | **Set flags** from the compare. Not clean. |
| `rep` prefix | +1 | `rep movs`/`rep stos`: clean. `repe/repne`: not clean (loop on ZF). |
| `loop` | 2 | Preserves **all** flags (including CF). We rely on this for sbb chain in `.Lop3`. |
| `jcc`/`jmp`/`call`/`ret` | varies | Clean. |
| `enter`/`leave` | 4/1 | Clean. |
| `inc`/`dec` | 2–3 | **CF preserved**, others clobbered. "Mostly clean." |
| `rol`/`ror` | 2–3 | CF ← rotated-out bit, OF defined only for count=1; **SF/ZF/AF/PF unchanged**. |

**`not` is the big find.** It's `xor reg, -1` (which *would* clobber
flags) in a flag-transparent wrapper. In a carry chain where you need to
complement a limb without breaking the adc ripple: `not rax` (3 B)
instead of `xor rax,-1` (4 B) **and** no `pushf/popf` or rescheduling.
**limb8's sbb chain in `.Lop3`** doesn't need complement, but if a
future Solinas variant does: this is the tool.

**`rol`/`ror` preserve ZF/SF/PF** — so in limb11's BE-decode, you could
rotate to rearrange bits between the `shr` and the `jnz` without losing
the loop-termination flag. Probably too niche.

---

## 4. Computed-Jump Density

Current dispatch (limb8):
```asm
and  eax, 0xF              ; 3 B
mov  al, [r12+rax]         ; 4 B — u8 offset table load
add  rax, r12              ; 3 B
call rax                   ; 2 B   → 12 B dispatch, 10×1 B table
```

Current dispatch (limb11):
```asm
and  eax, 0xF              ; 3 B
xlatb                      ; 1 B — al ← [rbx+al]
add  rax, rbx              ; 3 B
call rax                   ; 2 B   → 9 B dispatch, 11×1 B table
```

**Alternative: `call [rbx+rax*8]`** (3 B, `FF 14 C3`):
```asm
and  eax, 0xF              ; 3 B
call [rbx+rax*8]           ; 3 B   → 6 B dispatch, 11×8 B table
```
Dispatch: −3 B vs limb11's xlatb path. Table: +77 B (11 entries × 7 B
each). **Net +74 B. Not close.**

**Alternative: `call [rbx+rax*2]` with 16-bit offsets?** No — x86 has
no 16-bit indirect call. `call [mem]` reads a full 64-bit target.

**Alternative: `jmp [rbx+rax*8]` + handlers end with `jmp .Lbc`:**
Converts call→ret into jmp→jmp. `jmp [rbx+rax*8]` is 3 B; each handler's
`ret` (1 B) becomes `jmp .Lbc` (2 B rel8 or 5 B rel32). With 11
handlers at ~5 rel8 / ~6 rel32: +1×5 + +4×6 = +29 B. Plus the table
growth. **Worse.**

**Alternative: push rax; ret** (1+1 = 2 B) instead of `call rax` (2 B):
same size, loses the return mechanism. Only wins if handlers were
already tail-jumping back.

**Verdict: xlatb+add+call is optimal** for our handler count and
layout. The u8 table is the dominant savings. No action.

---

## 5. String-Op Edge Cases

### 5.1 `rep lodsq` — fast-forward rsi, load last element (3 B, `F3 48 AD`)

Defined behavior: loads `[rsi]`, `[rsi+8]`, … rcx times, each into rax
(overwriting). Final state: rax = `[rsi_orig + (rcx-1)*8]`, rsi +=
rcx*8, rcx = 0.

Pointless for the loads. **Useful as `rsi += rcx*8` with a free
rcx-zero and rax load of the last element.** Compare `lea rsi,
[rsi+rcx*8]` (4 B) + `xor ecx,ecx` (2 B) = 6 B → `rep lodsq` = 3 B.
**−3 B** if you can live with rax being clobbered and rcx being the
count in qwords.

Microcoded — ~N cycles for N iterations. Cold path only.

### 5.2 `repne scasq` — find-first-match, 3 B (`F2 48 AF`)

Scans `[rdi], [rdi+8], …` until a qword equals rax (ZF=1) or rcx
exhausts. We use `repe scasq` (scan-while-equal, for iszero) but not
repne. `repne scasq` is find-first-occurrence. No current use case in
ECDSA verify, but note it for any "find the nonzero limb" needs —
it's normalization for free.

### 5.3 `repe cmpsq` — memcmp-for-equality, 3 B (`F3 48 A7`)

Compares `[rsi]` against `[rdi]`, advancing both, while equal. Exits
with ZF=0 on first mismatch or ZF=1 if rcx exhausted. **This is a
256-bit equality check in 3 bytes** (after loading rcx=4).

**Use case — limb8 final check? No:** bc_v3 checks `diff1·diff2 == 0`
via `repe scasq` against rax=0. That's the right primitive.

**Use case — `.Lop5` (fe_geq)? PROTOTYPED, +1 B.** Current: `mov;cmp;
loopz` = 12 B body, 20 B total. `std; repe cmpsq; cld` = 5 B core
(−7 on body), but **pointer setup costs 8 B** (2× `add r,24` — rcx
is &cP on entry, not zero, so no free bump). Plus `mov cl,4` (2 B)
after the push-24 trick. Net: 21 B, **+1**. 607/607 pass, semantics
correct (`setbe` captures CF|ZF for val≥mod fail). The `loopz` form's
`[reg+rcx*8-8]` SIB indexing **already** gets high→low scan for free
— that's the insight the estimate missed. Applies only when the
baseline is a branchy `jb`/`ja` loop or when bc_run hands pointers
already at the high limb.

### 5.4 `cmpsq` non-rep — 2 B (`48 A7`)

Single compare of `[rsi]` vs `[rdi]`, advances both by 8. Sets flags
like `cmp`. If you have a one-shot 64-bit compare where both operands
are already behind pointers: 2 B vs `mov rax,[rsi]; cmp rax,[rdi]`
(3+3 = 6 B). **−4 B** per site. limb8's `.Lop5` loop body could shrink
but we'd lose the countdown-indexed addressing.

### 5.5 `movsd` (non-SSE) / `movsb` — 1-byte memcpy steps

`movsb` (1 B): `[rdi++] = [rsi++]`, byte.
`movsd` (1 B): `[rdi] = [rsi]`, dword; both += 4.

We use `movsq` (2 B). A 4-byte copy via `movsd` is 1 B cheaper than
`movsq` if you only need 32 bits moved. Probably no current sites
(everything is qword-aligned qword data).

### 5.6 `ins`/`outs` — port I/O, 1 B

`insb`/`insd` (`6C`/`6D`): [rdi++] ← port[dx].
`outsb`/`outsd` (`6E`/`6F`): port[dx] ← [rsi++].

Userspace faults on these (IOPL). **Useless** except as 1-byte #GP
generators, and we don't want that. Listed for completeness.

---

## 6. Legacy BCD — **NONE SURVIVE**

Covered in §0. All SIGILL. Move on.

---

## 7. BMI1/BMI2 — Forbidden But Cataloged

All VEX-encoded, all 5+ bytes (except tzcnt/lzcnt which are `F3 0F BC/BD`
= `rep` prefix on bsf/bsr, 4 B). **Not used** for compatibility.
Documenting what we lose:

### 7.1 `bzhi r32, r32, r32` — zero high bits, 5 B

`dst ← src1 & ((1 << src2[7:0]) − 1)`. **This is our `and eax, MASK`
(3 B) but with a variable bit count.** For limb11's fixed 24-bit
mask, `and` is shorter. `bzhi` only wins if the mask width varies at
runtime, which it doesn't.

### 7.2 `mulx r, r, r/m` — multiply without flags, 5 B

`hi:lo ← rdx × src`, dest regs chosen freely, **flags unchanged**.
Compare `mul r` (2–3 B) which clobbers rdx:rax and sets CF/OF. The
flag-preservation and three-operand form are the win for fast code;
for size golf, plain `mul` is 3 B shorter. **No size case.**

### 7.3 `rorx r, r, imm8` — rotate without flags, 6 B

`ror` (3 B) is half the size. `rorx` doesn't touch CF — useful for
speed-optimized carry chains, not for size.

### 7.4 `shlx`/`shrx`/`sarx` — shift by register, no flags, 5 B

`shl eax, cl` is 2 B. The `x` versions take an arbitrary register for
the count instead of cl. 5 B. Never smaller.

### 7.5 `pdep`/`pext` — bit scatter/gather, 5 B

`pext`: gather bits selected by mask into contiguous low bits.
`pdep`: scatter contiguous low bits into positions selected by mask.
No bigint use case. Limb-decode could theoretically use `pext` to grab
24-bit chunks, but `lodsd; dec rsi; and eax,MASK` (limb11, 1+3+5 = 9 B
per chunk, in a loop body of ~11 B) is tighter than any pext setup.

### 7.6 `andn r, r, r/m` — BIC, 5 B

`dst ← ~src1 & src2`. `not eax; and eax,ebx` = 2+2 = 4 B. Shorter
without BMI.

### 7.7 `blsi`/`blsr`/`blsmsk` — lowest-set-bit ops, 5 B

`blsi`: `dst ← src & −src` (isolate lowest set bit). = `mov; neg; and`
= 2+2+2 = 6 B, so **BMI1 saves 1 B here.** But no ECDSA use.

`blsr`: `dst ← src & (src−1)` (clear lowest set bit). = `lea eax,
[rbx−1]; and eax,ebx` = 3+2 = 5 B. Wash.

`blsmsk`: `dst ← src ^ (src−1)` (mask up to lowest set). Same count.

### 7.8 `bextr r, r, r` — bitfield extract, 5 B

Start/length packed in the control reg's low 16 bits.
`shr; and` (3+3 for imm8 forms) or `shr; shl; shr` can match. No clear
size win.

### 7.9 `tzcnt` / `lzcnt` — 4 B (`F3 0F BC/BD`)

`rep`-prefixed `bsf`/`bsr`. On CPUs without BMI1, the `rep` is ignored
and you get plain `bsf`/`bsr` — which return **undefined** dest on
zero input (Intel) or leave it unchanged (AMD). `tzcnt` returns
operand-size on zero. `bsf eax,ebx` (3 B) is 1 B shorter when you know
input is nonzero.

### 7.10 `adcx` / `adox` — dual carry chains, 6 B (`66/F3 48 0F 38 F6`)

ADX extension. `adcx` uses CF only; `adox` uses OF only; both don't
touch the other's flag. Two independent add-chains interleaved without
stashing carries. **Fantastic for speed** (fast2.S uses this pattern),
**terrible for size** (6 B vs `adc` 3 B).

**Verdict: BMI/ADX never win on size.** Already-avoided; no regrets.

---

## 8. Prefix Abuse

### 8.1 `66h` on 32-bit ops → 16-bit ops

Already used: `lodsw` is `66 AD` (2 B). Any 32-bit op can get the 66h
prefix to become 16-bit. `mov ax, imm16` is `66 B8 iw` = 4 B vs
`mov eax, imm32` = 5 B. **−1 B** when a 16-bit immediate suffices AND
you're ok with bits 16–31 of the reg staying dirty.

limb11 `mov r11d, 0xBC4F` (6 B, `41 B8 4F BC 00 00`) — the value fits
16 bits. `mov r11w, 0xBC4F` = `66 41 B8 4F BC` = 5 B. **−1 B.** But
r11[31:16] stays dirty; fe_mul11 does `imul eax, r11d` which reads all
32 bits. **Needs r11d upper half clean.** Is it? bc_run runs once per
op; r11 is caller-saved so anything could be there. **Breaks.** Unless
we `xor r11d,r11d; mov r11w,0xBC4F` = 3+5 = 8 B, worse. Or re-check
whether it's actually read beyond 16 bits: `imul eax, r11d` —
`(acc[i] & MASK) * m0inv & MASK`, result masked to 24 bits. So bits
above 24 in the product are discarded. If acc[i] & MASK ≤ 2^24 and we
only care about bits 0–23 of the product: does `eax * (r11d + junk<<16)`
differ in bits 0–23 from `eax * r11d`? Yes — `eax * junk<<16` can
contribute to bit 16+ of the product. **Doesn't work.** Keep.

### 8.2 `67h` address-size override — 32-bit addressing

`67 48 AD` = `lodsq` using `[esi]` instead of `[rsi]`. Truncates the
pointer to 32 bits. Pointless unless your data lives in the low 4 GB
**and** you want to zero-extend the pointer for free. The stack is
typically in high addresses. **No use.**

`jecxz` (`67 E3 rel8`, 3 B) tests ecx instead of rcx. If you've been
doing 32-bit counter ops, ecx is what you want… but `jrcxz` (`E3 rel8`,
2 B) works anyway because 32-bit dest writes zero-extend, so rcx =
ecx. **Never smaller.**

### 8.3 Segment-override prefixes — mostly nops in 64-bit

CS/DS/ES/SS overrides (`2E`/`3E`/`26`/`36`) are **ignored** for
addressing in 64-bit mode (segment bases forced to 0). They pad
instructions by 1 B each, useful for NOP-sledding alignment but
anti-useful for size.

FS/GS (`64`/`65`) **are** respected — they apply a nonzero base
(set by the OS, typically for TLS). `gs:xlatb` = `65 D7` would read
`[gs_base + rbx + al]`. Useless for us (we don't control gs_base).

`3E` is also a "branch taken" static-prediction hint on conditional
jumps (legacy, ignored on everything post-P4). No.

### 8.4 `F3`/`F2` on non-string ops

`F3 C3` = `rep ret` (2 B): the AMD K8/K10 branch-predictor workaround.
Modern CPUs don't care; it's a 2-byte `ret`. **Pure waste.**

`F3 90` = `pause` (2 B): spin-lock hint. No use.

`F3`/`F2` on a general op: usually ignored or #UD, except where
repurposed (SSE opcodes, `tzcnt`, CET shadow-stack `F3 0F 1E FA` =
`endbr64`). **Nothing exploitable.**

---

## 9. Miscellaneous Gems

### 9.1 `not r` — flag-transparent complement, 2 B (r32) / 3 B (r64)

Covered in §3 but worth calling out: `not` is the **only** bitwise op
that doesn't touch flags. `xor reg,-1` = 3 B (r32) or 4 B (r64) *and*
clears CF. `not` is 1 B shorter in 64-bit and flag-clean. **Free win
anywhere we currently `xor r64,-1`.** Grep shows no current uses, but
any future multi-limb one's-complement (e.g., for a subtraction-by-add
via `a − b = a + ~b + 1`) should use `not`.

### 9.2 `xadd r, r` — exchange-then-add, 3 B (r32) / 4 B (r64)

`xadd dst, src`: `tmp ← dst + src; src ← dst; dst ← tmp`. Flags from
the add. Unlocked reg-reg form is non-atomic and cheap (~1–2 cycles).

It's `add` + `xchg` fused. `xadd eax, ebx` = eax←eax+ebx, ebx←old_eax.
Compare `xchg eax,ebx; add ebx,eax` = 1+2 = 3 B — same size, different
final-reg layout. `mov ecx,eax; add eax,ebx; mov ebx,ecx` = 2+2+2 = 6 B.
**Saves 3 B vs the explicit sequence** if you need sum-and-preserve and
can't spare a 1-byte xchg. Probably no current site; keep in catalog.

### 9.3 `cmpxchg r, r` — compare-and-swap, 3 B (r32)

`cmpxchg dst, src`: if eax == dst, dst ← src (ZF=1); else eax ← dst
(ZF=0). Unlocked form is not atomic.

This is a **conditional move controlled by equality with eax**, with a
side-effect load of eax on mismatch. `cmp eax,dst; jne 1f; mov dst,src;
1:` = 2+2+2 = 6 B (best case, all short forms). `cmpxchg dst, src` = 3 B.
**−3 B** if you want exactly that semantics. Highly situational; no
current ECDSA fit but distinctive enough to keep.

### 9.4 `shld` / `shrd` — double-precision shift, 4–5 B

`shld dst, src, cl/imm`: shift dst left by count, filling from the top
of src. 128-bit left-shift in one instruction per 64-bit limb.

`shrd rax, rbx, 24` = `48 0F AC D8 18` (5 B). vs `shr rax,24; mov
rcx,rbx; shl rcx,40; or rax,rcx` = 4+3+4+3 = 14 B. **−9 B per limb
boundary.**

**Use case — limb11 `fe_from_le`:** extracting 24-bit chunks from a
byte stream. Current: `lodsd; dec rsi; and eax,MASK` (1+3+5 = 9 B
body, per limb). `shrd` would need the 64-bit word in a reg and the
next 64-bit word — different topology entirely (load in 64-bit
chunks, shift across boundaries). Probably a wash after accounting for
the 64-bit load setup. **Not obviously better,** but worth a
prototype. More promising for limb5×54 where the 54-bit stride crosses
qword boundaries at awkward offsets.

Microcoded on AMD (~6-8 cycles); ~1 cycle on Intel. Careful in hot
loops.

### 9.5 `bsf` / `bsr` — bit scan, 3 B

No BMI1 requirement (core x86). `bsf eax, ebx`: eax ← position of
lowest set bit in ebx; ZF=1 if ebx was zero (eax undefined on Intel,
unchanged on AMD).

Not useful for bigint mul/reduce. **Potentially useful** for a
"skip-zero-bits" optimization in the scalar multiplication ladder
(find the next set bit of u1/u2 and fast-forward the doubling), but
that's a speed optimization, not size. The naive bit-at-a-time loop is
smaller.

### 9.6 `rol al, 4` — nibble swap, 3 B (`C0 C0 04`)

Swaps the nibbles of al. **limb8's bytecode decode** unpacks nibbles
(`movzx edi,ah; and edi,0xF` and `shr edi,4`). Already pretty tight.
But if a decode path wanted s1,s2 swapped: `rol al,4` swaps the two
nibble fields in 3 B. Current bc_rcb has explicit commutes coded in
the bytecode stream instead — that's 0 B at the dispatch site. Unlikely
to beat.

### 9.7 `ret imm16` — callee-pops, 3 B (`C2 iw`)

`ret N`: pops return address, then adds N to rsp. Callee stack cleanup.

**Use case:** if a subroutine's caller pushes args and currently does
`call sub; add rsp,8` (5+4 = 9 B per site), and there are ≥2 call
sites, switching to `ret 8` (3 B, +2 over bare ret) at the callee and
dropping the adds saves 4 B/site − 2 B one-time = net −4×(sites−1)+2
bytes. No, let's be precise: bare `ret` → `ret N` is +2 B at callee;
`add rsp,N` (4 B) drops at each caller. Net = −4·sites + 2.
Two sites: −6 B. Three: −10 B.

**limb11 `.Linv`:** calls `fe_mul11` many times with pushed args? No —
args are in registers, stack is used for saves not args. **fe_mul11's
tail** does `pop rax` (discard b), `pop rcx` (restore), `pop rax`
(discard dst). These aren't caller-pushed args in the ret-imm sense;
they're callee-pushed saves. `ret imm` can't distinguish. **No
current fit.**

### 9.8 `push [mem]` / `pop [mem]` — 2 B (+ disp)

`push qword ptr [rdi]` = `FF 37` (2 B). `pop qword ptr [rdi]` = `8F 07`
(2 B).

`push [rsi]; pop [rdi]` = 2+2 = 4 B moves one qword mem→mem via the
stack. `movsq` is 2 B and advances both pointers. `movsq` wins unless
you specifically don't want the advance or the pointers aren't rsi/rdi.

`mov rax,[rsi]; mov [rdi],rax` = 3+3 = 6 B. **push/pop [mem] saves 2 B
for a single qword mem→mem** when rsi/rdi aren't set up for `movsq`.

### 9.9 `loope` / `loopne` — conditional loop, 2 B

`loope rel8`: `rcx−−; jump if rcx≠0 AND ZF=1`. `loopne`: `…AND ZF=0`.

We use `loopz` (=`loope`) already in limb8 `.Lop5`. `loopne` is the
dual — loop while **not** equal. For a "scan until you find a match"
that's `repne scas`'s job. Rarely useful as a general loop construct,
but 2 B if the stars align.

### 9.10 `mul` CF/OF output — free "did it overflow?" (0 B marginal)

After `mul r32`, CF=OF = (edx ≠ 0). After `mul r64`, CF=OF = (rdx ≠ 0).
**Verified.**

**Free `edx==0` test.** If you're about to check whether the product
fit in 32/64 bits: `mul ebx; jc overflow` instead of `mul ebx; test
edx,edx; jnz overflow`. Saves 2 B (`test edx,edx`).

No current site — limb8's reduce always checks `t[j+8]` after
accumulation, not per-mul; limb11's imul is the 2-op form which has
different flag semantics. **Keep in catalog.**

### 9.11 `imul r, r, imm8` — scale by constant, 3 B (r32) / 4 B (r64)

Already used in limb11 bc_run for `×88` slot-stride. The 3-op form
takes an imm8 (sign-extended). `imul esi,esi,88` is 3 B vs `mov
eax,88; mul esi` = 5+2 = 7 B. **Already maximally exploited.**

Note: `imul r,r` (2-op, 3 B for r32) preserves the dest-reg upper
bits... no wait, 32-bit dest writes zero-extend. It does full r32×r32
→ r32 (truncated). Sets OF/CF if the full product doesn't fit.

### 9.12 `lea` for ×3/×5/×9 — 3 B (r32)

`lea eax,[rax+rax*2]` = eax × 3 in 3 B. +`lea eax,[rax+rax*4]` for ×5,
×9 with ×8. **Smaller than `imul eax,eax,3`** (3 B)? Same size for
r32. But lea is 1 cycle vs imul ~3. For cold code, wash. For ×88:
`lea eax,[rax+rax*4]; lea eax,[rax+rax*4]; shl eax,3` = 3+3+3 = 9 B vs
`imul eax,eax,88` = 3 B. imul wins.

### 9.13 `test` has no imm8-sign-extended form for r32 — use `and`?

`test eax, 0xF` = 5 B (`A9` + imm32, since the eax short-form is
always imm32). `and eax, 0xF` = 3 B (imm8 sign-ext form exists). If
you need the flags AND can tolerate the write: `and` is 2 B smaller.
Already exploited (limb8/limb11 use `and eax,0xF` where they could
have used test).

`test al, 0xF` = 2 B (al short-form). **Always** smaller than `test
eax, imm` if you only care about the low byte.

### 9.14 `cmovcc` — 3 B (r32) / 4 B (r64)

`cmovc eax, ebx` = 3 B. Branch-around is `jnc 1f; mov eax,ebx; 1:` =
2+2 = 4 B. **cmov saves 1 B per site vs branch-around-mov.** More for
memory sources (`cmovc eax,[rdi]` = 3 B vs `jnc;mov` = 2+2 = 4 B;
still −1).

No current use. Plausible in `.Lnorm` / `.Lchklt` where we branch to
conditionally `inc ebp` or similar. `cmovns ebp, esomething` if we had
a 1 pre-loaded... probably doesn't net save after setup.

### 9.15 `cdqe` beats `movsxd rax, eax` — 2 B vs 3 B

Obvious once stated. Grep: neither codebase does `movsxd rax,eax`.
Good. But keep it in mind — it's an easy 1 B slip when writing new
sign-extend code.

### 9.16 `xchg al, ah` — 2 B byte swap within ax (`86 E0`)

Swaps the low two bytes. `ror ax, 8` = 4 B (`66 C1 C8 08`). **−2 B.**
`bswap eax` = 2 B also, but that swaps all four bytes. For a
swap-just-ax: `xchg al,ah` is the pick.

No obvious use — our bytecode puts the op nibble in al and operands in
ah, and we unpack them separately. If we wanted them swapped: 2 B. No
current need.

### 9.17 `push rsp` pushes the OLD rsp (pre-decrement)

Already known and used (limb8:790). Listed for completeness. `push
rsp; pop rsi` = 2 B gives `rsi = &top_of_stack_at_time_of_push`. In
64-bit mode specifically — 16-bit 8086 pushed the *decremented* SP.

### 9.18 `inc`/`dec byte ptr [mem]` — 2 B (+ disp)

`inc byte ptr [rdi]` = `FE 07` (2 B). `inc dword ptr [rdi]` = `FF 07`
(2 B also). `inc qword ptr [rdi]` = `48 FF 07` (3 B).

**Byte inc is 1 B smaller than qword** when the target is known to
have its upper bytes zero (no carry-out needed). Already heavily
exploited in limb11's cP-build (`inc byte ptr [rdi-56]` etc.) and
limb8:864.

### 9.19 `loop` preserves all flags — **including CF**

Known, but worth re-emphasizing: this is why limb8's sbb chain in
`.Lop3` can use `loop` instead of `dec;jnz` (which would clear ZF and
thus… wait, `dec` preserves CF too). Both work for CF-chain. `loop`
preserves SF/ZF/OF additionally — if you're chaining on SF (limb11's
`jns`), `dec ecx; jnz` clobbers it. `loop` doesn't. **limb11's
`.Lcp_shared` ends with `add rax,rdx` and returns SF; caller does
`jns`.** If there were a counted loop between those: `loop` is the
only option.

---

## 10. Summary Table — Top Candidates

Ranked by probable net savings × likelihood of a fit.

| Trick | Size win | Confidence | Where |
|---|---|---|---|
| `std; repe cmpsq; cld` for bignum geq | ~~−4 to −7 B~~ **+1 B** | measured | limb8 `.Lop5` — `loopz`+SIB already optimal; +8 B ptr setup kills it |
| `cdq` for sign→{0,−1} mask | −4 B | medium | limb11 `.Lnorm` |
| `not` vs `xor r,-1` | −1 B + flag clean | high | any future complement |
| `lahf`/`sahf` flag transport | −3 B per use | low | future carry-save refactors |
| `cwde` after `lodsw` for top-limb | −1 B | ~~high~~ **BROKEN** | limb11 `fe_from_le` — cN top16=0xFFFF, cGX=0x905F, both bit15 set → cwde sign-extends wrong. Off by 2^256. |
| `rep lodsq` as rsi+=rcx*8 | −3 B | low | no current site |
| `push [mem]; pop [mem]` 1-qw copy | −2 B vs mov;mov | low | non-rsi/rdi mem→mem |
| `cmovcc` vs branch-around | −1 B/site | low | cold conditional moves |
| `cdqe` vs `movsxd rax,eax` | −1 B | trivial | any new sign-ext |
| `xadd` for add-and-preserve | −3 B | very low | no pattern match |
| `cmpxchg` as eax-conditional-mov | −3 B | very low | no pattern match |
| `mul` CF for overflow check | −2 B | low | no current per-mul test |

**Immediate actionables:** ~~the `cwde` one in limb11~~ (broken, bit15
set); ~~`std; repe cmpsq` geq in limb8~~ (+1 B, see §5.3).

---

## Appendix: Microcode Cost Reference

For when a trick is in a hot loop. Approximate, Skylake-class, from
Agner Fog's tables + spot-checks on this box.

| Instr | uops | Latency | Notes |
|---|---|---|---|
| `loop` | ~7 | ~5 | Catastrophic in inner loops. Known. |
| `scas*` | ~3 | — | Load + cmp + rdi-adj, microcoded. |
| `jrcxz` | ~2 | — | Fine for cold paths. |
| `enter` | ~12 | — | Once per call, don't care. |
| `lahf`/`sahf` | 1 / 2 | 1 / 2 | Cheap. Not microcoded. |
| `cdq`/`cqo` | 1 | 1 | Cheap. |
| `xchg r,r` | 2 | — | Fine. `xchg r,[m]` is ~8 (implicit lock). |
| `not r` | 1 | 1 | Same as any ALU op. |
| `shld`/`shrd` | 1 (Intel) / ~6 (AMD) | 3 / 3 | Arch-dependent! |
| `cmovcc` | 1 | 1 | No branch-mispredict cost. |
| `xadd r,r` | 2 | 2 | Fine. |
| `cmpxchg r,r` | ~5 | ~5 | Microcoded. |
| `bsf`/`bsr` | 1 | 3 | Fine. |
| `rep stosq` | — | ~N/8 + startup | Fast-string ERMSB on modern CPUs. |
| `rep lodsq` | ~N | ~N | Not fast-path. Each iter = full lodsq. |
| `std`/`cld` | ~4 / 2 | — | `std` is slightly expensive (serializing-ish on some uarches). |
