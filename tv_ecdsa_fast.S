/* ======================================================================
 * ECDSA/P-256 verify — x86-64, bytecode-interpreted, speed+size optimized.
 *
 * Same architecture as tv_ecdsa_bc.S (2-byte bytecode, 16-slot buffer,
 * shared interpreter).  Requires BMI2 (mulx) and MOVBE.
 *
 * 1427 bytes, ~0.63M cycles (Skylake-class).  vs tv_ecdsa_bc.S:
 * 1712 bytes, ~1.88M cycles — so −285 bytes AND −66% cycles.
 *
 * Hot-path changes:
 *
 *   - Shamir's trick: one 256-bit walk for u1·G + u2·Q instead of two
 *     independent pt_muls — halves the doublings (256 vs 512).  Per
 *     iteration: double; if u2 bit, add Q (already in slot 4-5); if
 *     u1 bit, swap G.xy into slot 4-5, add, restore Q.xy.  Both G and
 *     Q have z = Mont(1), and slot 6 is NEVER written by bc_dbl/add,
 *     so the 8-qword X,Y swap is enough — z serves both.  ~30% cycles.
 *     Costs +22 B: larger pt_mul body, but verify's stash/restore/
 *     second-pt_mul/pt_add_acc block (61 B) is gone.
 *
 *   - Advancing-pointer CIOS in fe_mul_m: instead of shifting the
 *     6-word accumulator down one limb every outer iteration (20 memory
 *     moves per fe_mul_m), the base pointer r9 advances.  The CIOS
 *     invariant guarantees t[0]=0 after reduction, so t[1..] is the
 *     new accumulator — no data movement.  Needs a 9-word buffer.
 *     Removes the shift loop entirely: −21 bytes, huge cycle win.
 *
 *   - muladd4 fully unrolled with mulx.  mulx preserves all flags,
 *     so each mem-add's CF is threaded straight through the next mulx
 *     into the following limb's adc — one `adc r,0` barrier per limb
 *     instead of two.  The hi-reg (rcx↔rdi) never exceeds 2^64-1
 *     (hi_product ≤ 2^64-2 + one cross-carry), so it cannot wrap; the
 *     second carry lives in CF.  69 bytes, and shortens the carry
 *     dependency chain on the hottest loop — the bulk of the ~13%
 *     cycle win.  Also closes a latent edge case: the old two-adc
 *     form could wrap hi at exactly 2^64 with both carries set.
 *
 *   - fe_sub_raw/fe_add_raw use lodsq/stosq (auto-increment, 2 bytes
 *     each, flag-preserving) and `dec ecx; jnz` instead of `loop`.
 *     `dec` sets ZF but preserves CF for the carry chain.  `loop` is
 *     microcoded (~7 cyc/iter on modern Intel); dec/jnz is 1.
 *     −15 bytes AND faster.
 *
 *   - fe_cpy is 4×movsq (no `rep` startup overhead on the ~50%-taken
 *     fe_mul_m copy-back path).  Zero-init of t is `push rax`×9
 *     after xor — allocates and zeroes the 72-byte buffer in one
 *     sweep.  11 B vs 18 B for sub + stosq loop.
 *
 * Size-only changes:
 *
 *   - SQR bytecode encodes s2=s1; decoder sets rdx=rsi for free, so
 *     SQR dispatches straight to Fmul.  −5 bytes.
 *   - `push N; pop reg` replaces `mov reg,imm32` where N fits signed
 *     imm8 (−2 each, many sites).
 *   - fe_mul_m outer counter goes −32→0 so `add;jnz` drops the cmp.
 *   - verify's slot-4/slot-8 leas via rbp/r13 mid-pointers: disp8.
 *   - Constants (cP/cN/cR2P) live right after .Ljt so handlers can
 *     address them as [r14+disp8] instead of 7-byte rip-relative.
 *     5 leas × −3 bytes = −15.
 *   - Check-op handlers share the `or r13b,al; ret` tail.  −4.
 *   - Nmul shares Fmul's `jmp fe_mul_m` via short jmp.  −3.
 *   - pt_add_acc: fe_iszero preserves rdi, so compute the next
 *     address from it with disp8/sub-imm8 instead of disp32 lea.  −6.
 *   - pt_mul counter in ebp (no REX) instead of r13d.  −2.
 *   - r14=rsp in verify: r14 as base drops rsp's SIB byte.  −2.
 *   - fe_from_be advances rdi; slot16 derived as [rdi+64] after it
 *     instead of 7-byte disp32 from r14.  −3.
 *   - fe_inv_m: push rdi (1 byte) instead of mov rsi,rdi (3).  −3.
 *   - fe_sub_m + fe_add_raw inlined into Fsub (sole-caller chain);
 *     fe_sub_raw's neg leaves CF → jnc replaces test+jz.  −10.
 *   - fe_geq returns via CF; cond_sub_n branches on it directly.  −2.
 *   - fe_iszero looped: or-accumulate sets ZF on final OR.  −3.
 *   - build_one inlined (sole caller).  −6.
 *   - verify final-compare: push rbx×4, pop as needed.  −4.
 *   - Fadd: push scratch addr, pop into rdx after call.  −3.
 *   - pt_mul: dead mov removed; dec al → 255 via wrap.  −4.
 *   - Bytecode streams addressed by imm8 offset from bc_dbl; bcrun_off
 *     resolves.  7 sites × (7-byte lea → 2–3 byte load) vs +10.  −20.
 *   - fe_inv_m: sub DWORD (low limb ≫ 2, no borrow) + bt DWORD.  −2.
 *   - bc_run returns check result in CF (neg ebp): caller drops
 *     test+jnz for jc.  −2.
 *   - Decoder preloads rcx = &P; Fmul/Fadd drop their leas.  −2.
 *
 * Structural wins (r14-invariant pass):
 *
 *   - r14 = slot base is an invariant throughout the call tree (every
 *     callee that reassigns r14 also pushes/pops it).  pt_add_acc's
 *     `push r14; mov r14,rdi; ...; pop r14` frame and pt_mul's rbx
 *     copy were both reconstructing that live value.  Dropping them
 *     cascades: pt_add_acc's epilogue becomes a bare `ret`, two of its
 *     `jmp .Laa` paths become `ret`, one becomes a tail-jump; verify
 *     drops three `mov rdi,r14` preambles; pt_mul drops its whole rbx
 *     bookkeeping.  −27 combined.
 *   - cond_sub_n = .Lop3 with rcx=rdx=&N.  Conditional subtract is
 *     subtract-then-add-back-on-borrow, which is exactly the Fsub
 *     handler — just with the modulus swapped.  A 9-byte stub (three
 *     movs) placed right before .Lop3 falls through.  fe_geq then has
 *     only one caller (.Lop5) and gets inlined.  −19.
 *   - Fto_mont opcode eliminated.  verify's block copy takes cR2P
 *     along for the ride (16 qwords instead of 12), landing R² in
 *     slot 11.  A to-Montgomery conversion is then plain Fmul with
 *     s2=0xb.  Drops the handler and one jump-table entry.  −5.
 *   - pt_mul zeros its accumulator by calling .Lai (pt_add_acc's
 *     set-to-infinity path — byte-identical code).  −6.
 *   - verify: rdx (pub ptr) survives both fe_from_be calls unchanged;
 *     Fadd preserves rcx=&P around its own fe_sub_raw; build_one
 *     piggybacks on fe_from_be's advanced rdi; rbp set from that rdi
 *     instead of a prologue lea.  −11 combined.
 *   - bc_run decoder uses rax itself as the table index (consume ah
 *     first, then `and eax,0xF`); pt_mul `xchg ebp,eax`.  −2.
 *   - pt_mul scalar ptr in rbx (1-byte push/pop) not r15 (2-byte).
 *     bt [rbx],rbp is still 4 B (REX.W needed either way).  −2.
 *   - movbe in fe_from_be: load+bswap in one (7 B vs 5+3).  −1.
 *   - cGXM in .text right before .Ljt: [r12-80] (5 B, disp8 but
 *     r12 forces SIB) replaces 7-B rip-relative.  Handler offsets
 *     unaffected (cGXM is on the near side of .Ljt).  −2.
 *   - hv_len range check (32..64) merged: sub r9,32 wraps low
 *     values to huge, so cmp;jbe catches both ends.  −2.
 *   - pt_add_acc moved right before bcrun_r14: the add2 path falls
 *     through (no jmp), the dbl path's jmp is rel8.  −5.
 *   - pt_mul moved right after bc_run's epilogue: its pop rbx;pop
 *     rbp;ret (3 B) becomes a rel8 jmp into .Lepi5's tail (2 B).  −1.
 *
 * Security and validation are unchanged from tv_ecdsa_bc.S.
 * ====================================================================== */

	.intel_syntax noprefix

/* ======================================================================
 * Bytecode.  Placed before .text so stream offsets (bc_X - bc_dbl) are
 * backward references at the call sites — gas picks the imm8 encoding
 * for `push`.  Order chosen so all offsets ≤ 118 (fits signed imm8).
 *
 * Call sites load the offset as a small integer (push imm8; pop rdi,
 * or xor edi,edi for bc_dbl itself), and bcrun_off adds the base.
 * 7 sites × (7-byte rip-rel lea → 2–3 byte load) vs +10 in bcrun_off.
 * ====================================================================== */
	.section .rodata
	.p2align 3

bc_dbl:
	.byte 0x21,0xb2, 0x11,0x91, 0xb3,0x80, 0xb2,0xa0, 0xa0,0xa8
	.byte 0xa2,0x8a, 0xa2,0xa8, 0x22,0x81, 0x81,0x88, 0x93,0x88
	.byte 0xb3,0x28, 0x90,0xb0, 0xb2,0x8b, 0x82,0x88, 0x82,0xb8
	.byte 0xa1,0x0a, 0xb3,0x00, 0x03,0x88, 0x80,0x8a, 0x91,0x99
	.byte 0x92,0x99, 0x92,0x99, 0x92,0x99, 0x93,0x18, 0x00,0x00

bc_v2:
	.byte 0x04,0xdd, 0xf4,0xdd, 0x04,0xec, 0xf4,0xee, 0x00,0x00

bc_v3:
	.byte 0x31,0x33, 0x00,0x33, 0xf0,0x33, 0x00,0x00

bc_add1:
	.byte 0x21,0xa2, 0x61,0xb6, 0xb0,0x80, 0xa0,0x34, 0x60,0x91
	.byte 0xb0,0x99, 0x20,0x75, 0xa0,0x77, 0x83,0x33, 0x93,0x77
	.byte 0x00,0x00

bc_add2:
	.byte 0x60,0xa2, 0x30,0x2a, 0x31,0xa3, 0xa0,0xb3, 0xa0,0x88
	.byte 0xb0,0x99, 0x71,0x07, 0xb3,0x00, 0x82,0x38, 0x33,0x00
	.byte 0x03,0x38, 0x30,0x37, 0x93,0x13, 0x00,0x00

/* Opcode renumbering after op4 (Fto_mont) was absorbed into Fmul:
 * R² is copied to slot 11 by verify's 16-qword block copy, so a to-
 * Montgomery conversion is just Fmul with s2=0xb.  op5/6/7/8 shift
 * down to 4/5/6/7; jump table drops one entry. */
bc_v1:
	.byte 0x06,0xc0, 0x05,0xc8, 0x06,0xd0, 0x05,0xd8
	.byte 0x05,0x09, 0x05,0x19, 0xb0,0x40, 0xb0,0x51
	.byte 0xb0,0x6f, 0x51,0x05, 0x41,0x14, 0x40,0x11
	.byte 0x43,0x11, 0x43,0x11, 0x43,0x11, 0xa2,0x11
	.byte 0x13,0x00, 0x07,0x00, 0x00,0x00

.equ obc_dbl,  0
.equ obc_v2,   bc_v2   - bc_dbl
.equ obc_v3,   bc_v3   - bc_dbl
.equ obc_add1, bc_add1 - bc_dbl
.equ obc_add2, bc_add2 - bc_dbl
.equ obc_v1,   bc_v1   - bc_dbl

/* ---------------------------------------------------------------------- */
	.text

/* ----------------------------------------------------------------------
 * 256-bit primitives (4 × u64 limbs, little-endian).
 * -------------------------------------------------------------------- */

/* fe_cpy(dst=rdi, src=rsi).  movsq unrolled — `rep movsq` has a
 * ~25-cycle startup cost for small counts, and this is called from
 * fe_mul_m's ~50%-taken fallback (~4500× per verify). */
fe_cpy:
	movsq
	movsq
	movsq
	movsq
	ret

/* fe_iszero(a=rdi) -> eax=1 iff zero.  OR accumulates into rax; the
 * last OR's ZF reflects the full OR (rax is cumulative).  loop/sete/
 * movzx/ret all preserve flags: callers may branch on ZF directly.
 * Looped: 19 bytes vs 22 unrolled. ~260 calls × ~16cyc = <0.4% cost. */
fe_iszero:
	push	4
	pop	rcx
	xor	eax, eax
1:	or	rax, [rdi+rcx*8-8]
	loop	1b
	sete	al
	movzx	eax, al
	ret

/* fe_sub_raw(dst=rdi, a=rsi, b=rdx) -> borrow in eax.
 * lodsq/stosq preserve all flags; `dec` preserves CF (sets ZF only).
 * `xor ecx,ecx` doubles as the CF-clear.  Pointers advance as a side
 * effect — callers must not assume they're preserved. */
fe_sub_raw:
	xor	ecx, ecx
	mov	cl, 4
1:	lodsq
	sbb	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	dec	ecx
	jnz	1b
	sbb	eax, eax
	neg	eax
	ret

/* muladd4(t=r9, x=rdx, y=rsi).  t[0..3] += x*y, carry into t[4..5].
 * Fully unrolled.  mulx (BMI2) preserves all flags, so the mem-add
 * carry is threaded through each mulx directly into the next limb's
 * adc — one `adc r,0` barrier per limb instead of two.  The high-reg
 * (rcx↔rdi) never exceeds 2^64-1 (hi_product ≤ 2^64-2, plus at most
 * one cross-carry), so `adc hi,0` cannot itself overflow; the second
 * carry lives in CF until the next adc consumes it.
 *
 * Previously the second `adc hi,0` (after each mem-add) could wrap
 * hi at exactly 2^64 if hi_product = 2^64-2 and both carries set.
 * Cosmically rare — not hit by the test suite — but gone now. */
muladd4:
	mulx	rcx, rax, [rsi]
	add	r8, rax             /* t[0] in reg — no store-forward stall */

	mulx	rdi, rax, [rsi+8]   /* flags preserved: CF = carry from t[0] */
	adc	rax, rcx            /* lo1 + hi0 + CF_t0 */
	adc	rdi, 0
	add	[r9+8], rax

	mulx	rcx, rax, [rsi+16]  /* CF = mem-carry from t[1] */
	adc	rax, rdi
	adc	rcx, 0
	add	[r9+16], rax

	mulx	rdi, rax, [rsi+24]  /* CF = mem-carry from t[2] */
	adc	rax, rcx
	adc	rdi, 0
	add	[r9+24], rax

	adc	[r9+32], rdi        /* CF = mem-carry from t[3] */
	adc	QWORD PTR [r9+40], 0
	ret

/* .Lfm falls through into fe_mul_m. */
.Lfm:	mov	rcx, r14
	mov	r8, r15
	/* FALLTHROUGH */
/* fe_mul_m(r,a,b,m,m0i): Montgomery mul, CIOS — advancing-pointer form.
 *
 * After each reduction step, t[0] is zero by construction (that's the
 * whole point of CIOS).  Instead of memmove-ing t[1..5] down to t[0..4],
 * just advance the base pointer.  t is now a 9-word buffer; result
 * lands at t[4..7] with carry at t[8].  No shift loop.
 *
 * r10 holds b — caller-saved, untouched by muladd4/fe_sub_raw/fe_cpy. */
fe_mul_m:
	push	r12
	push	r13
	push	r14
	push	r15

	mov	r12, rdi            /* r */
	mov	r10, rdx            /* b — stays in reg */
	mov	r13, rcx            /* m */
	mov	r14, r8             /* m0i */
	mov	r15, rsi            /* a */

	/* Allocate + zero t[0..8] in one go: push rax×9 decrements rsp
	 * by 72 and writes zeros.  11 B vs 18 B for sub + dec-loop.
	 * 4 reg-pushes + 9 value-pushes = 104 B below entry rsp; entry
	 * rsp%16=8 → final %16=0, same alignment as before. */
	xor	eax, eax
	.rept 9
	push	rax
	.endr

	/* r11 counts −32→0; `add r11,8; jnz` drops the cmp.  a[i] is
	 * then [r15+r11+32], disp8 (+1 byte), but net −2. */
	mov	r9, rsp
	push	-32
	pop	r11
.Lm:	mov	r8, [r9]            /* t[0] → reg (muladd4 never touches [r9]) */
	mov	rdx, [r15+r11+32]
	mov	rsi, r10
	call	muladd4             /* r8 = updated t[0] */
	mov	rdx, r8             /* was load [r9] — reg-to-reg, no stall */
	imul	rdx, r14
	mov	rsi, r13
	call	muladd4             /* r8 = 0 by CIOS — discarded */
	add	r9, 8               /* advance: old t[1] is new t[0] */
	add	r11, 8
	jnz	.Lm
	/* r9 → t[4]; result at r9[0..3], carry at r9[4]. */

	/* Save rdi/rsi across fe_sub_raw (stosq/lodsq advance both);
	 * pop unconditionally before the branch → no stack leak on jz.
	 * Replaces the 2-mov reload with push×2+pop×2: −2. */
	mov	rdi, r12
	mov	rsi, r9
	push	rdi
	push	rsi
	mov	rdx, r13
	call	fe_sub_raw
	pop	rsi
	pop	rdi
	sub	eax, [r9+32]        /* borrow - carry: if ≠0, t < m → copy */
	jz	2f
	call	fe_cpy
2:
	add	rsp, 72
.Lepi4:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret

/* fe_inv_m.  Loop counter in rbx (callee-saved, survives fe_mul_m).
 * fe_mul_m now uses r10 internally for b, so r10 is not free here.
 * Push/pop rbx costs +2 bytes, but `mov ebx,imm` and `dec ebx` are
 * each 1 byte shorter than their r10d equivalents — net zero. */
fe_inv_m:
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbx
	sub	rsp, 32            /* 5×8 + 8(ret) + 32 = 80 aligned */

	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx

	mov	rdi, rsp
	mov	rsi, r14
	call	fe_cpy
	/* Both moduli have low limb ≫ 2 → no borrow into limb 1.
	 * 32-bit sub drops REX.W: −1. */
	sub	DWORD PTR [rsp], 2

	mov	rdi, r12
	mov	rsi, r13
	call	fe_cpy

	xor	ebx, ebx
	mov	bl, 254
.Le:	mov	rdi, r12
	/* push rdi = 1 byte; so push/push/pop/pop = 4 bytes vs two
	 * 3-byte movs.  Stack balances before the call. */
	push	rdi
	push	rdi
	pop	rdx
	pop	rsi
	call	.Lfm
	/* bt with mem operand indexes an unbounded bit array; ebx ≤ 254
	 * stays in signed 32-bit range.  Dropping REX.W: −1. */
	bt	DWORD PTR [rsp], ebx
	jnc	.Lnx
	mov	rdi, r12
	push	rdi
	pop	rsi
	mov	rdx, r13
	call	.Lfm
.Lnx:	dec	ebx
	jns	.Le

	add	rsp, 32
	pop	rbx
	jmp	.Lepi4

/* fe_from_be — cold (5 calls at setup).  _next entry bumps rsi by
 * 32 first, for chained decode (rdi already advanced by the prior
 * call's stosq×4).  Two call sites each drop their own add rsi,32. */
fe_from_be_next:
	add	rsi, 32
fe_from_be:
	push	4
	pop	rcx
1:	movbe	rax, [rsi+rcx*8-8]  /* load+bswap; 7 B vs mov(5)+bswap(3) */
	stosq
	loop	1b
	ret

/* cpy3: 12-qword copy.  Precondition rcx=0 (high bytes) — every caller
 * has rcx=0 from a prior fe_iszero/rep/fe_sub_raw.  mov cl,N = 2 B vs
 * push N;pop rcx = 3 B.  −1 B per site. */
.macro	cpy3
	mov	cl, 12
	rep	movsq
.endm

/* ----------------------------------------------------------------------
 * pt_add_acc and pt_mul take the slot base in r14 (caller-provided).
 * Every caller already has r14 = slot base: verify sets it once at
 * entry and never clobbers it; bc_run (called from inside both of
 * these) pushes/pops r14.  So the old push-r14/mov-r14/pop-r14 frame
 * in pt_add_acc was reconstructing a value that was never lost, and
 * pt_mul's rbx = rdi copy was rbx = r14 by another name.
 *
 * With the frame gone, pt_add_acc's epilogue is just `ret`.  Two of
 * the three paths that ended in `jmp .Laa` become plain `ret` (−1 B
 * each), and the third — a call then fallthrough — becomes a tail
 * jump (−1 B).  pt_mul drops its rbx push/mov/pop (−5 B) and the
 * `mov rdi,rbx` arg to pt_add_acc (−3 B).  verify drops three
 * `mov rdi,r14` preambles (−9 B).  Net −24 B.
 *
 * Placed right before bcrun_r14 so the add2 path falls straight through
 * into bcrun_r14 (no jmp at all), and the dbl-path's jmp is rel8.  −5 B.
 * The `call bcrun_r14` mid-body is still rel32 (no short call on x86-64).
 * -------------------------------------------------------------------- */
pt_add_acc:
	lea	rdi, [r14+64]
	call	fe_iszero           /* ZF ⇔ acc.z == 0 */
	jnz	1f
	/* fe_iszero preserved rdi = r14+64; compute rsi from it (disp8). */
	lea	rsi, [rdi+64]       /* r14+128 */
	mov	rdi, r14
	cpy3
	ret
1:	push	obc_add1
	pop	rdi
	call	bcrun_r14
	lea	rdi, [r14+96]
	call	fe_iszero           /* ZF ⇔ H == 0 */
	jnz	3f
	/* fe_iszero preserved rdi = r14+96.  sub imm8 −128 = +128. */
	sub	rdi, -128           /* r14+224 */
	call	fe_iszero           /* ZF ⇔ Rr == 0 */
	jnz	.Lai
	/* Tail-share: both this path and 3: end in `jmp bcrun_r14`.
	 * Short-jmp past .Lai to the shared tail-jump. */
	xor	edi, edi            /* obc_dbl = 0 */
	jmp	bcrun_r14           /* rel8 forward — pt_add_acc sits right before bcrun_r14 */
.Lai:	mov	rdi, r14
	xor	eax, eax
	/* rcx=0 on both paths here: fe_iszero's loop (pt_add_acc) and
	 * verify's rep movsq → pt_mul prologue (the `call .Lai`). */
	mov	cl, 12
	rep	stosq
	ret
3:	push	obc_add2
	pop	rdi
	/* FALLTHROUGH to bcrun_r14 */

/* ======================================================================
 * BYTECODE INTERPRETER
 * ====================================================================== */
/* Callers pass rdi = byte offset into the bytecode block.  bcrun_off
 * resolves it; bcrun_r14 also supplies rsi = r14.  Seven sites each
 * drop a 7-byte rip-rel lea for a 2–3 byte offset load; we spend +10
 * here once. */
bcrun_r14:
	mov	rsi, r14
bcrun_off:
	lea	rax, [rip+bc_dbl]
	add	rdi, rax
	/* FALLTHROUGH */
bc_run:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx, rdi
	mov	r12, rsi
	/* Check accumulator in ebp: xor is 2 bytes (no REX), and since only
	 * the low byte is ever OR'd with 0/1, `mov eax,ebp` (2 bytes) works
	 * at exit — upper bytes stay zero.  r13 is push/popped only for
	 * epilogue sharing with verify; never written inside bc_run. */
	xor	ebp, ebp
	lea	r14, [rip+.Ljt]     /* Hoist: handlers are callee-saved, r14 lives. */
.Lbc:
	movzx	eax, WORD PTR [rbx]
	add	rbx, 2
	/* END is word 0x0000 (no stream uses MUL s0,s0,s0→s0). */
	test	eax, eax
	jz	.Lbce

	/* Nibble layout: al=(s2<<4)|op, ah=(dst<<4)|s1.  Straight-line
	 * decode: no push/pop, no loop.  Slot stride is 32 bytes; a
	 * nibble in bits [7:4] is already ×16, so lea scale-2 finishes it.
	 * `and edi,-16` = 3 bytes (imm8 sign-ext → 0xFFFFFFF0); works
	 * because movzx cleared bits [31:8] already.
	 *
	 * Consume ah first (into edi/esi), then al (into edx), then
	 * `and eax,0xF` for the op — using rax itself as the table
	 * index.  No copy-to-ecx is needed. */
	movzx	edi, ah             /* edi = (dst<<4)|s1 */
	mov	esi, edi
	and	esi, 0xF
	shl	esi, 5
	add	rsi, r12            /* r12 + s1*32 */
	and	edi, -16            /* edi = dst<<4 */
	lea	rdi, [r12+rdi*2]    /* r12 + dst*32 */

	movzx	edx, al             /* edx = (s2<<4)|op; high bits cleared */
	and	dl, 0xF0            /* edx = s2<<4 */
	lea	rdx, [r12+rdx*2]    /* r12 + s2*32 */

	and	eax, 0xF            /* op — ah already dead */
	movzx	eax, BYTE PTR [r14+rax]
	add	rax, r14
	/* Most handlers want rcx = &P; those that don't overwrite it.
	 * +4 here, −4 in Fmul, −2 in Fadd.  Fadd now preserves it across
	 * its own fe_sub_raw.  oP is a forward reference here, so gas
	 * picks disp32 — hardcode and assert. */
.equ	oP_early, 48        /* .Ljt(8) + cN_M0I(8) + cN(32) */
	lea	rcx, [r14+oP_early]
	call	rax
	jmp	.Lbc

/* NEG sets CF=1 iff operand was nonzero.  pops/ret preserve flags,
 * so the bc_v1 caller branches on CF directly — other callers don't
 * care.  ebp is about to be popped anyway.  Same 2 bytes as mov. */
.Lbce:	neg	ebp
.Lepi5:
	pop	r14
	pop	r13
	pop	r12
.Lepi2:
	pop	rbx
	pop	rbp
	ret

/* pt_mul: Shamir's simultaneous double-and-add.  Computes u1·G + u2·Q
 * into the accumulator (slots 0-2) in a single 256-bit walk — halves
 * the doublings vs running two independent pt_muls (256 vs 512).
 *
 * Caller contract (verify sets this up just before the call):
 *   rsi    → &u1 (slot 13); u2 is at [rsi+32] (slot 14)
 *   slot 4-6: Q in Jacobian Montgomery form (z = Mont(1) in slot 6)
 *   slot 16-17: G.x, G.y in Montgomery form
 *   slot 18-19: backup of Q.x, Q.y (for restore after each G-add)
 *   slot 15 holds `one` throughout — bc_v3 reads it after pt_mul.
 *
 * The z-coordinate trick: bc_add1/2 read slot 6 for the addend's z, and
 * slot 6 is NEVER written by bc_dbl/add1/add2.  Both G and Q have z =
 * Mont(1), so swapping only X,Y (8 qwords) suffices — slot 6 serves both.
 *
 * Per iteration: double; if u2 bit set, add (Q is already in 4-5); if
 * u1 bit set, swap G into 4-5, add, restore Q to 4-5.  u2 checked first
 * so Q is in place for it without a preceding restore.  After the
 * G-branch restores Q, the next iteration's u2 check finds Q in place.
 *
 * Placed after bc_run so the epilogue jmp to .Lepi2 stays rel8 — the
 * extra push r12/r13 are popped inline before the jmp. */
pt_mul:
	push	rbp
	push	rbx
	push	r12
	push	r13
	lea	r12, [rbp+64]       /* &slot4 — rbp still = verify's &slot2 here (disp8) */
	mov	rbx, rsi            /* rbx = &u1; u2 at [rbx+32] */
	lea	r13, [rbx+96]       /* &slot16 (= slot13+96).  G at [r13], Q-backup at [r13+64]. */

	call	.Lai
	dec	al
	xchg	ebp, eax
.Lpm:	xor	edi, edi
	call	bcrun_r14           /* double */

	bt	[rbx+32], rbp       /* u2 bit */
	jnc	2f
	call	pt_add_acc          /* Q already in slot 4-5 */
2:
	bt	[rbx], rbp          /* u1 bit */
	jnc	3f
	mov	rdi, r12            /* &slot4 */
	push	rdi                 /* stash for restore after pt_add_acc clobbers rdi */
	mov	rsi, r13            /* &slot16 = G */
	/* rcx=0: bc_dbl (via bcrun_r14 above) ends in Fsub which leaves
	 * rcx=0 (fe_sub_raw's dec-to-0 loop); pt_add_acc (u2 branch)
	 * exits via bc_add2/dbl (same) or rep (rcx→0).  −1 B each. */
	mov	cl, 8
	rep	movsq               /* G.xy → slot 4-5.  rsi now = r13+64 = &slot18. */
	push	rsi                 /* stash &Q-backup — it's where rsi landed */
	call	pt_add_acc
	pop	rsi                 /* &slot18 = Q backup */
	pop	rdi                 /* &slot4 */
	mov	cl, 8               /* rcx=0: pt_add_acc exit paths all zero rcx */
	rep	movsq               /* Q.xy → slot 4-5 (restore) */
3:
	dec	ebp
	jns	.Lpm

	pop	r13
	pop	r12
	jmp	.Lepi2              /* shared pop rbx;pop rbp;ret */

/* G.x, G.y in Montgomery form.  Placed right before .Ljt so verify
 * can address it as [r12-80] (r12=&cN, cN=.Ljt+16, cGXM=.Ljt-64).
 * 5-byte lea (r12 forces SIB) vs 7-byte rip-relative.  Handler
 * offsets from .Ljt are unaffected since this is on the near side. */
cGXM:	.quad 0x79e730d418a9143c, 0x75ba95fc5fedb601
	.quad 0x79fb732b77622510, 0x18905f76a53755c6
cGYM:	.quad 0xddf25357ce95560a, 0x8b4ab8e4ba19e45c
	.quad 0xd2e88688dd21f325, 0x8571ff1825885d85

/* .Ljt + constants in one block so handlers can address constants via
 * [r14+disp8] instead of 7-byte rip-relative leas.  r14 = .Ljt inside
 * bc_run; handlers run before fe_mul_m's push r14 overwrites it.
 * cN→cP→cBM→cR2P adjacency is load-bearing (verify's rep movsq). */
/* 8 entries.  The old Fto_mont opcode was just Fmul with a hardcoded
 * s2 = &R²; now that verify copies R² into slot 11, Fto_mont is
 * literally Fmul with s2=0xb in the bytecode and needs no handler.
 * cR2P is never read from .text by any handler — only the block copy
 * touches it — but it stays here because the copy reads cN..cR2P as
 * one contiguous span. */
.Ljt:
	.byte	.Lop0-.Ljt, .Lop1-.Ljt, .Lop2-.Ljt, .Lop3-.Ljt
	.byte	.Lop4-.Ljt, .Lop5-.Ljt, .Lop6-.Ljt, .Lop7-.Ljt

cN_M0I:	.quad 0xccd1c8aaee00bc4f
cN:	.quad 0xf3b9cac2fc632551, 0xbce6faada7179e84
	.quad 0xffffffffffffffff, 0xffffffff00000000
cP:	.quad 0xffffffffffffffff, 0x00000000ffffffff
	.quad 0x0000000000000000, 0xffffffff00000001
cBM:	.quad 0xd89cdf6229c4bddf, 0xacf005cd78843090
	.quad 0xe5a220abf7212ed6, 0xdc30061d04874834
cR2P:	.quad 0x0000000000000003, 0xfffffffbffffffff
	.quad 0xfffffffffffffffe, 0x00000004fffffffd

.equ oN,   cN   - .Ljt
.equ oP,   cP   - .Ljt
.if oP - oP_early
.error "oP moved — update oP_early in bc_run"
.endif
.if (cN - cGXM) - 80
.error "cGXM-cN offset changed — update lea rsi,[r12-80] in verify"
.endif

/* fe_geq inlined (sole caller after cond_sub_n was rewritten as a
 * .Lop3 stub).  Compare [rdi] to [rsi] limb-by-limb from the top;
 * loopz falls out on first mismatch with cmp's CF live.  +10 B in
 * the handler block (Fadd shifts from 225 to 235, still fits u8)
 * but the 16-B standalone fe_geq is gone.  Net −6 B. */
.Lop5:	push	4
	pop	rcx
1:	mov	rax, [rdi+rcx*8-8]
	cmp	rax, [rsi+rcx*8-8]
	loopz	1b
	setae	al
	jmp	.Lor
.Lop6:	call	fe_iszero
	jmp	.Lor
.Lop7:	call	fe_iszero
	xor	al, 1
.Lor:	or	bpl, al
	ret
.Lop4:
Nmul:	lea	rcx, [r14+oN]
	mov	r8, [rcx-8]
	jmp	.Lmj               /* share Fmul's tail: short jmp, −3 bytes */
.Lop0:
Fmul:	push	1
	pop	r8
.Lmj:	jmp	fe_mul_m
/* SQR bytecode now encodes s2=s1, so the decode loop has already
 * set rdx=rsi — SQR is just Fmul.  −5 bytes (old: mov rdx,rsi;jmp). */
.equ .Lop1, .Lop0
/* fe_sub_m + fe_add_raw both inlined (sole callers in chain).
 * fe_sub_raw's `neg eax` sets CF iff borrow; pops preserve flags,
 * so jnc replaces test+jz.  The add-back loop's first adc needs
 * CF=0: `xor ecx,ecx` clears it (we're on the CF=1 branch here
 * but mov+xor reset it).  −10 vs standalone fe_sub_m+fe_add_raw. */
/* cond_sub_n — r12=&cN.  Conditional subtract IS subtract-then-add-
 * back-on-borrow, which is exactly .Lop3 with the modulus swapped
 * from P to N.  Placed here to fall through.  .Lop3 computes
 * dst = s1 - s2; on borrow adds back rcx.  With rcx=rdx=r12=&N and
 * rsi=rdi=&a: result is a-N if a≥N else (a-N)+N = a.
 * Not on the dispatch path — op3 in the jump table points at .Lop3
 * proper, past these 9 bytes.  Fadd shifts to offset 244 (fits u8). */
cond_sub_n:
	mov	rcx, r12
	mov	rsi, rdi
	mov	rdx, r12
	/* FALLTHROUGH */
/* rcx = &P is supplied by the decoder.  Fadd also preserves it
 * across its fe_sub_raw call (push/pop around it, +2 B) and jumps to
 * .Lop3 directly — the old `Fsub: lea rcx,[r14+oP]` re-load is gone. */
.Lop3:	push	rcx
	push	rdi
	call	fe_sub_raw
	pop	rdi
	pop	rdx
	jnc	1f
	mov	rsi, rdi
	xor	ecx, ecx
	mov	cl, 4
2:	lodsq
	adc	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	dec	ecx
	jnz	2b
1:	ret
.Lop2:
Fadd:	push	rdi
	push	rsi
	push	rcx                 /* save &P across fe_sub_raw */
	lea	rdi, [r12+3*32]
	/* Push scratch addr before fe_sub_raw clobbers rdi; pop into
	 * rdx after.  rcx = &P from decoder → push/pop into rsi. */
	push	rdi
	push	rcx
	pop	rsi
	call	fe_sub_raw
	pop	rdx
	pop	rcx                 /* restore &P */
	pop	rsi
	pop	rdi
	jmp	.Lop3

/* ======================================================================
 * Public entry point.
 * ====================================================================== */
	.globl	tv_ecdsa_p256_verify_asm
	.type	tv_ecdsa_p256_verify_asm, @function

tv_ecdsa_p256_verify_asm:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp, 648

	/* r14 = rsp for the whole of verify (every callee saves r14).
	 * r14 as base avoids rsp's SIB byte on the r13 lea.  rbp is
	 * set later from fe_from_be's flowed-out rdi (= r14+64 after
	 * decoding pub.x/y). */
	mov	r14, rsp
	lea	r13, [r14+12*32]

	mov	r12, rdi
	mov	rbx, r8
	/* rdx (pub ptr, arg 3) survives the two fe_from_be calls below
	 * (they touch only rsi/rdi/rcx/rax), so use it directly for the
	 * 0x04 format-byte check.  Drops `mov r8,rdx` (−3) and the REX
	 * byte on `cmp BYTE PTR [rdx],4` (−1). */

	cmp	rsi, 64
	jne	.Lf
	cmp	rcx, 65
	jne	.Lf
	/* 32 ≤ hv_len ≤ 64: fold both checks into one unsigned range test.
	 * sub wraps low values to huge; jbe covers both ends.  r9 dead after. */
	sub	r9, 32
	cmp	r9, 32
	jbe	1f
/* .Lf trampoline: top checks (5 short jumps, up to −104 rel) stay
 * short; the bottom jz+jmp now reach .Lf2/.Ld2 directly as short
 * forward.  14-byte block → 5-byte rel32 jmp; bottom adds it back
 * (+14) but saves rel32 je (−4) + rel32 jmp (−3).  Net −2. */
.Lf:	jmp	.Lf2
1:
	/* fe_from_be: stosq×4 advances rdi by 32; rsi index-read only.
	 * Chain: rdi flows call→call; rsi bumped +32 in place. */
	mov	rsi, r12
	mov	rdi, r13
	call	fe_from_be
	call	fe_from_be_next     /* rsi+=32; rdi already r13+32 */

	/* build_one: rdi flowed out of the above at r13+64 (slot 14).
	 * Zero 8 qwords = slots 14 and 15 (slot 14 is garbage until
	 * bc_v2 writes it, slot 15 becomes `one`), then set slot15's
	 * low limb.  Dropping the `lea rdi,[r13+96]`: −4 B.  rdx (pub
	 * ptr) is still live; rep stosq doesn't touch it.
	 * rcx=0 from fe_from_be's loop above.  −1 B. */
	mov	cl, 8
	xor	eax, eax
	rep	stosq
	inc	DWORD PTR [rdi-32]

	cmp	BYTE PTR [rdx], 0x04
	jne	.Lf
	lea	rsi, [rdx+1]
	mov	rdi, r14            /* slot 0 */
	call	fe_from_be
	call	fe_from_be_next     /* rsi+=32; rdi flowed to r14+64 */
	mov	rbp, rdi            /* = slot 2; cheaper than lea from r14 */
	lea	r12, [rip+cN]

	lea	rdi, [r13-128]       /* slot 8 via r13: disp8 */
	mov	rsi, r12
	/* 16-qword copy: cN→slot8, cP→slot9, cBM→slot10, cR2P→slot11.
	 * Slot 11 is never read during bc_v1 (only written later by
	 * bc_dbl), so the R² living there lets the to-Montgomery ops
	 * be plain Fmul with s2=0xb — no Fto_mont handler.
	 * rcx=0 from fe_from_be_next above (loop counts to 0).  −1 B. */
	mov	cl, 16
	rep	movsq

	push	obc_v1
	pop	rdi
	call	bcrun_r14
	jc	.Lf                 /* bc_run's neg ebp left CF = failbit */

	/* slot 13 needed five times below — three before bc_v2 (rdi for
	 * inv-n/decode/cond_sub), two after (Shamir rdi base, pt_mul rsi).
	 * rbx goes dead right after `mov rsi,rbx` (hash ptr consumed) and
	 * stays dead until the `lea rbx,[r14+96]` before inv-p.  Stockpile
	 * a third copy and pop it into rbx; then slot 16 is [rbx+96] disp8
	 * (vs [r13+128] disp32: −3 B) and pt_mul's rsi is a mov (−1 B).
	 * 3 pushes = 24 B on stack, but no callee here uses SSE — alignment
	 * is cosmetic (the push rbx×4 block later does the same 24-B skew). */
	mov	rdi, r14
	lea	rsi, [r13+32]
	push	rsi
	push	rsi
	push	rsi
	mov	rdx, r12
	mov	rcx, [r12-8]
	call	fe_inv_m

	mov	rsi, rbx
	pop	rdi
	call	fe_from_be
	pop	rdi
	call	cond_sub_n
	pop	rbx                 /* rbx = &slot13; dead window until inv-p */

	push	obc_v2
	pop	rdi
	call	bcrun_r14

	/* Shamir setup: G.xy → slot 16-17, Q.xy backup → slot 18-19.
	 * slot 6 = Mont(1) is never written by bc_dbl/add — it serves as
	 * z for BOTH G and Q, so only X,Y (8 qwords) need swapping.
	 * slot 15 must stay untouched (bc_v3 reads it as `one`).
	 * rcx=0: bc_v2 ends in Nmul → fe_mul_m → fe_sub_raw dec-to-0. */
	lea	rdi, [rbx+96]       /* slot 16 = slot 13 + 96: disp8 now */
	lea	rsi, [r12-80]       /* cGXM */
	mov	cl, 8
	rep	movsq               /* G.xy → slot 16-17; rdi now &slot18, rcx=0 */
	lea	rsi, [rbp+64]       /* slot 4 = Q.xy */
	mov	cl, 8
	rep	movsq               /* Q.xy → slot 18-19 */

	mov	rsi, rbx            /* &u1 (slot 13); u2 at +32 */
	call	pt_mul              /* acc = u1·G + u2·Q */

	mov	rdi, rbp
	call	fe_iszero           /* ZF ⇔ R1.z == 0 (R at ∞) */
	jz	.Lf2

	lea	rbx, [r14+96]

	mov	rdi, rbx
	mov	rsi, rbp
	lea	rdx, [r12+32]
	mov	cl, 1               /* rcx=0 from fe_iszero just above.  −1 B. */
	call	fe_inv_m

	push	obc_v3
	pop	rdi
	call	bcrun_r14

	/* rbx loaded into rdi three times across three calls; stockpile
	 * on stack (push rbx = 1 byte) and pop as needed.  4+4 = 8 bytes
	 * vs 4×mov (12).  Callees are all leaf — no stack align concern. */
	push	rbx
	push	rbx
	push	rbx
	push	rbx
	pop	rdi
	call	cond_sub_n
	pop	rsi
	pop	rdi
	mov	rdx, r13
	call	fe_sub_raw
	pop	rdi
	call	fe_iszero
	jmp	.Ld2                /* short: +2 past the xor */
.Lf2:	xor	eax, eax
.Ld2:	add	rsp, 648
	jmp	.Lepi5

	.section .note.GNU-stack,"",@progbits
