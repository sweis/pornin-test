# Tricks Ledger

One line per trick. Grep by tag: `[APPLIED]` `[DEAD:absolute]`
`[DEAD:conditional]` `[DEAD:attack]` `[UNTRIED]`. Delta format:
`(−N B, track)` or `(+N B, track)`.

---

## Architectural / VM design

[APPLIED]  MUL as bytecode double-and-add — Russian-peasant, 9 B subroutine vs 80-150 B native (−100+ B, stupid)
[APPLIED]  1-byte accumulator ISA — 3-bit op + 5-bit idx vs our 2-byte 3-address (stupid baseline)
[APPLIED]  CALL/RET nested subroutine stack in bytecode — invert_mod/point_add called, not inlined (stupid baseline)
[APPLIED]  FOR/NEXT/SKIPBITZ as opcodes — one loop serves scalar×pt, field mul, inversion (stupid baseline)
[APPLIED]  Skip-next conditional (SKIPCC/CS/BITZ) — no branch targets in bytecode (stupid baseline)
[APPLIED]  Subtract-until-carry reduction — ~12 B vs q=t[top] ~30 B (stupid baseline)
[APPLIED]  Bytecode interpreter + u8 jump table — 2 B/op, ~50 B dispatch (−hundreds B, all tracks)
[APPLIED]  RCB complete addition — one 43-op formula, zero branches (all tracks)
[APPLIED]  Projective final check — skip mod-p inversion, d1·d2≡0 test (all tracks)
[APPLIED]  q=t[top] reduce — only limb8; both moduli top-limb=0xFFFFFFFF (limb8)
[APPLIED]  R² projective cancellation — RCB homogeneous, R-level propagates (−25 B, limb11; all Montgomery)
[APPLIED]  Self-modifying z256_addsub — patch adc/sbb byte 0x11↔0x19 (−11 B, +8.5× cyc, stupid)
[APPLIED]  FAILCC opcode — subsumes SKIPCS/CC+FAIL pairs, ext table 8→5 (−6 B, stupid)
[APPLIED]  Un-specialize: slot-1=modulus VALUE — drops dispatch cmp+cmove (−4 B, stupid)
[APPLIED]  Un-specialize: eliminate op_smod — _MODN/_MODP expand to LD;ST bytecode (−3 B, stupid)
[DEAD:absolute]  Hamburg signed-binary ladder — +277 B measured; RCB completeness only 7 B → DEAD_ENDS.md §Hamburg
[DEAD:absolute]  WW-AMM s=256 — −p⁻¹ mod 2^256 ≠ 1; CIOS already factored → DEAD_ENDS.md §WW-AMM
[DEAD:absolute]  GLV/endomorphism — P-256 j-inv ∉ {0,1728}, no CM endo → literature_survey.md
[DEAD:absolute]  wNAF for size — "−64 adds" are runtime, not bytes; encoder pure overhead → literature_survey.md
[DEAD:absolute]  Post-RCB addition formulas — EFD enumerated (max 2015), nothing smaller → literature_survey.md
[DEAD:absolute]  4-bit operand encoding — 30 distinct slots referenced, need 5 bits (stupid)
[DEAD:absolute]  RCB reschedule for acc-VM — slot count free in acc-VM, only LD/ST count matters; already minimal (stupid)
[UNTRIED]  -DFAST_MUL variant — restore native schoolbook in stupid/, ~850 B / ~5M cyc knee
[UNTRIED]  Port b-derive to limb8 — Montgomery repr complicates; check if RCB bytecode can compute after conversion
[UNTRIED]  Co-Z ladder (ZADDC+ZADDU) — 39 ops/bit vs RCB 43; single-scalar only, needs 2-call tail → literature_survey.md
[UNTRIED]  Q4: RCB Fmul intermediate-product sharing — hand-analysis, no literature
[UNTRIED]  Q5: Karatsuba at K≤8 — code-size crossover unclear

## Constant derivation / data compression

[APPLIED]  b = Gy²−Gx³+3Gx bytecode — curve equation rearranged, 32 B data → 11 B bytecode (−21 B, stupid)
[APPLIED]  Build p at runtime — 3 distinct dwords [FF,0,1], stosl loop (−15 B, stupid)
[APPLIED]  Fuse n_top into p-builder — shares FF pattern, combined 12-dword builder (−8 B, stupid)
[APPLIED]  1-bit shr/sbb builder loop — final encoding of p+n_top builder (−4 B on top, stupid)
[APPLIED]  Signed cP representation — p as ±power-of-2 terms built in verify (−20 B, limb5x54)
[APPLIED]  Decode chaining — rodata ordered, rdi walks constant decodes zero leas (−48 B, limb11)
[APPLIED]  n−2 in rodata, bt direct — drops cmp/jb/je special-casing (−4 B, limb8)
[DEAD:absolute]  Gy from sqrt(Gx³−3Gx+b) — sqrt needs p≡3 exp, ~50 B bytecode, net loss
[DEAD:absolute]  Gx/Gy byte compression — no zeros, no RLE pattern, 64 raw bytes irreducible (stupid)
[DEAD:absolute]  vpbroadcastq cP — 4 distinct dword values, not broadcastable (limb8)

## x86 encoding — applied

[APPLIED]  xlatb dispatch — u8 jump table, 1 B lookup vs 3 B mov (−10..−12 B, limb5x54/56/11)
[APPLIED]  lodsw bcptr — rsi advances, frees rbx, drops add+push/pop (−1 B, limb8; enables xlatb elsewhere)
[APPLIED]  repe scasq CHKZ — compare-to-zero as string op (−4 B, limb8)
[APPLIED]  cqo+not single-loop NORM — merged two loops, or edx,eax = one insn two conditions (−3 B, limb11; −1 B limb5x54; +1 B DEAD limb5x56)
[APPLIED]  stc;jmp .Lsbb — fail reuses success epilogue, forced CF=1 (−1 B, limb8)
[APPLIED]  shr-bitmask BE chain — ebx=0b10101, one shr yields CF=chain+ZF=done (−10..−19 B, limb5x54/56/11)
[APPLIED]  enter/leave + .Lfail-in-middle — rel32→rel8 length-check jumps (−28 B, limb11)
[APPLIED]  .Lcp_shared carry-prop — byte-identical body, one subroutine (−17 B, limb11)
[APPLIED]  SF-from-.Lcprop — final add sets SF, CHKLT/NORM branch directly (limb5x54)
[APPLIED]  CIOS merge — schoolbook+reduce one loop (−18 B limb5x54; −7 B limb11)
[APPLIED]  fe_from_be falls through — reversal then fall into fe_from_le (−12 B, limb5x54; −5 B limb8 pair)
[APPLIED]  fe_from_le bit-offset loop — 5× unroll → loop, shrd+cmovb (−15 B, limb5x54)
[APPLIED]  NORMN drop — Montgomery nonneg stays nonneg; pt_mul handles k≥n free (−14 B, limb11)
[APPLIED]  r15=&cP + packed counter — fixes broken cmp bl,W idiom (−12 B, limb5x56)
[APPLIED]  xchg eax,r32 1-byte — zero-extends both, flag-preserving (limb8 pt_mul init)
[APPLIED]  cdqe 2-byte — movsxd rax,eax in 2 B not 3 (various)
[APPLIED]  AL short-form 2-byte — cmp al/test al imm8 dedicated opcodes (limb8, limb11)
[APPLIED]  inc byte ptr [mem] — 1 B vs qword when upper bytes zero (limb11 cP, limb8 slot-1)
[APPLIED]  loop instruction — 2 B vs dec+jnz 4 B; ~5 cyc microcoded (size floors only)
[APPLIED]  stosq;ret tail merge — 43 B apart, rel8, flags unchanged (−1 B, limb11, commit 7c4ad0e)
[APPLIED]  op_ok/op_fail direct unwind — cl&1 drops exit-flag machinery (−14 B, stupid)
[APPLIED]  op_ld/op_st shared pop-tail — push order inversion (−2 B, stupid)
[APPLIED]  pushq rsp;popq REG — replaces movq for low regs (−2 B, stupid)
[APPLIED]  rcx=0 inherit from entry subq — drop xorl ecx (−2 B, stupid)
[APPLIED]  sbbl r8d,r8d — replaces setc r8b, CF preserved (−1 B, stupid)
[APPLIED]  negb cl gives 255 — from FOR ext-index=1, 0−1=255 u8 (−1 B, stupid)
[APPLIED]  scale-2 index in decode_int — [rdx+rcx*2-33]+inc rdx fuses +32 advance (−1 B, stupid)
[APPLIED]  op_mul tail-jump docopy — set up stack first, docopy's ret IS return (−2 B, stupid; S1 "dead end" reframed)
[APPLIED]  decode_int via rdx — rsi=bytecode survives 5 calls sans push/pop (−2 B, stupid)
[APPLIED]  op_for/op_next xchg-swap shared — Lswap_ret + fall-through (−4 B, stupid)
[APPLIED]  merge acc alloc into push loop — 108→112 qwords, drop subq (−4 B, stupid)
[APPLIED]  Wy init = acc leftover — RCB infinity is any (0:Y:0) Y≠0 (−1 B, stupid)
[APPLIED]  _ONE→slot 27 inline pushq $1 — beats disp32 incl (−1 B, stupid)
[APPLIED]  op_failcc falls into Lop_reset — r8b≠0 makes test no-op (−1 B, stupid)

## x86 encoding — dead

[DEAD:absolute]  cwde after lodsw — cN top16=0xFFFF, cGX=0x905F bit15 set, sign-extends wrong (limb11)
[DEAD:absolute]  salc/aad/aam/BCD/pusha/popa — SIGILL in 64-bit, VEX reclaimed opcodes
[DEAD:absolute]  mov ds,eax nonzero — selector validated, segfaults; zero-only scratch useless
[DEAD:absolute]  AVX/BMI/ADX for size — all VEX 4-6 B; measured 891+ vs 890 baseline; MOVBE-only not binding (limb8)
[DEAD:absolute]  call [rbx+rax*8] dispatch — +74 B, 8-B vs 1-B table entries (limb11)
[DEAD:absolute]  bextr nibble decode — defeats-itself on bit-position-as-scaling (limb8)
[DEAD:absolute]  ret imm16 — needs ≥2 caller-pushed-arg sites; we use callee-saved regs only
[DEAD:conditional]  lahf/sahf CF transport — all CF immediate set→jcc, zero gap; .Lasmod clobbers AH (limb11)
[DEAD:conditional]  std+repe cmpsq .Lop5 — +1 B; loopz+SIB already free high→low (limb8)
[DEAD:conditional]  std/cld for byte-reversal — DF affects both rsi+rdi; no simultaneous-backward pattern
[DEAD:attack]  call docopy in op_mul — S1 "can't return"; S6 reframed: set up stack first, tail-jump (−2 B, stupid)
[DEAD:attack]  slot-1-as-modulus — S1 "break-even: saved_rsp reloc + ONE disp32"; S3 leaq-1088 exit + slots 30/31 (−4 B, stupid)
[DEAD:conditional]  INV/fe_mul11 4-B epilogue merge — 169 B apart, needs reorder, rel8 ripple risk (limb11)
[DEAD:conditional]  Fall-through .Lfmul→fe_mul11 — RETRIED SUCCESSFULLY after handler shrink <256 (limb11, commit 5d8eb1f)
[DEAD:conditional]  Tail-suffix sharing limb5 — pop;pop;pop;ret 150-152 B apart, past rel8; need −23 B from fe_mul5
[DEAD:conditional]  r13 slot-base refactor — −1 B NET after REX, invasive (stupid)

## Bytecode / gadgets

[DEAD:absolute]  Bytecode gadgets in constants — 62-68% valid-op density = noise; zero ≥4-B matches → GADGETS.md
[DEAD:absolute]  cN zero-zone as END — walled by 8 bytes 0xff (opcode nibble 15 invalid) → GADGETS.md
[DEAD:absolute]  limb8 frameshift gadget byte 71 — contains 10⁶-cyc INV, semantically useless → GADGETS.md
[DEAD:absolute]  Native x86 offset-decode/ROP — 14 ret-blocks insufficient for birthday; code too dense 1-2 B ops → GADGETS.md

## Per-track port blockers

[DEAD:conditional]  xlatb → limb8 — fe_inv_m uses rbx as counter + calls Nmul; net +1 B (commit db6dad8)
[DEAD:absolute]  mov-cl audit → limb8 — every push N;pop rcx has rcx=r8 full addr, high bytes nonzero
[DEAD:absolute]  shr-bitmask → limb8 — movbe-inline decode, no chain-vs-pop pattern
[DEAD:conditional]  .Lop6 or ebp,eax → limb8 — .Lop5 rax has slot data high; unsharing costs more (commit d3e0868)
[DEAD:absolute]  .Lcp_shared → limb5 — 128-bit shrd/adc vs 64-bit lodsq+add; different bytes
[DEAD:absolute]  cqo+not → limb5x56 — .Lcprop in-place needs +3 B mov rax,[rdi]; top limb ~36 bits needs REX (+1 B net)
[DEAD:absolute]  shrd single-cmp → limb5x56 — byte-aligned, no shrd present
[DEAD:absolute]  rbp-relative bt → limb11 — 88-B stride, only one u-slot in disp8
[DEAD:absolute]  5-temp RCB reschedule → stupid — acc-VM: slot count free, LD/ST already minimal

## Byte-level (measured, lost)

[DEAD:conditional]  Zero-fill share .Lset1↔cP — call 5 B × 2 = 10 B, saves 3 B/site, break-even at 3 (limb11, +2 B)
[DEAD:absolute]  CHKZ/CHKNZ merge cmc/pushf/stc — all 27-33 B vs 27 B baseline; call rel32 ate tail saving (limb11)
[DEAD:absolute]  addend@slot0/acc@slot5 swap — .Lcadd −4 B, pt_mul +4 B, net 0 (limb11)
[DEAD:absolute]  decode_int qword variant — REX on lodsq/bswap/stosq = 18 B vs 13 B byte-loop (stupid)
[DEAD:absolute]  POINT_COPY opcode — handler disp32 leaq 14+ B vs 5 B bytecode saved (stupid)
[DEAD:absolute]  check_lt_m subroutine — 3×3 B inline vs 4 B sub + 6 B calls, net +1 (stupid)
[DEAD:absolute]  Triple-acc subroutine — 3 sites × −1, 4 B cost, net +1 (stupid)
[DEAD:absolute]  TRIPLE/ADD2 opcode — handler 8+ B vs 6 B saved; ADD2 operand 0 gives quadruple (stupid)
[DEAD:absolute]  z256 cond-jump-in-loop — 61 B same as baseline; only SMC wins the merge (stupid)
[DEAD:absolute]  CONDCALL (SKIPBITZ+CALL) — +3 B; doskip CALL-detection still needed (stupid)
[DEAD:absolute]  Stack-based FOR/NEXT state — push/pop r9/r10 with REX = same as reg moves (stupid)
[DEAD:absolute]  incl disp8 via slot relocation — every rearrangement trades one disp32↔disp8 (stupid)

## Untried / actionable

[UNTRIED]  cdq sign→{0,−1} .Lnorm — −4 B est., medium conf (limb11) → x86_tricks.md §8
[UNTRIED]  shrd 54-bit limb decode — ~−9 B/boundary est., untested (limb5x54) → x86_tricks.md §8
[UNTRIED]  rep lodsq as rsi bump — −3 B, no site yet (cold-path only)
[UNTRIED]  push/pop [mem] 1-qw copy — −2 B, no non-movsq mem→mem site
[UNTRIED]  cmovcc vs branch-mov — −1 B/site, setup usually eats saving
[UNTRIED]  mul CF overflow test — −2 B, no per-mul test site
[UNTRIED]  not vs xor r,-1 — −1 B + flag clean, future complement use
[UNTRIED]  stupid/ lea rsp,[rbp+0x440] attack — 7 B disp32, resists register-stash so far
[UNTRIED]  stupid/ two lea rbx,[rip+...] — 14 B; decode_int↔table gap 285 B vs disp8
