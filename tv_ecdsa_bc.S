/* ======================================================================
 * ECDSA/P-256 verify — x86-64 assembly, bytecode-interpreted field ops.
 *
 * Architecture
 * ------------
 * The dominant contributor to code size in a conventional asm
 * implementation is argument-setup for each field operation: every
 * `Fmul(dst, a, b)` costs ~15 bytes of lea+call.  With ~60 such ops
 * across pt_dbl, pt_add, and verify, that's ~900 bytes of pure
 * glue.
 *
 * Here we replace all straight-line field-op sequences with compact
 * 2-byte bytecode instructions dispatched by a single shared
 * interpreter.  The interpreter operates on a contiguous array of
 * 16 field-element slots (16 × 32 = 512 bytes) addressed by 4-bit
 * slot index — no pointer indirection.  Callers copy inputs into
 * slots before invoking the interpreter and copy results out after.
 *
 * Extended opcode set (4 bits):
 *   0 MUL    s[d] = s[a] * s[b] mod p  (Montgomery)
 *   1 SQR    s[d] = s[a]^2     mod p
 *   2 ADD    s[d] = s[a] + s[b] mod p
 *   3 SUB    s[d] = s[a] - s[b] mod p
 *   4 CPY    s[d] = s[a]
 *   5 NMUL   s[d] = s[a] * s[b] mod n  (Montgomery, order n)
 *   6 CGEQ   if s[d] >= s[a]: set FAIL flag
 *   7 CZ     if s[d] == 0: set FAIL flag
 *   8 CNZ    if s[d] != 0: set FAIL flag
 *   9 TOMONT s[d] = s[a] * R^2 mod p   (enter Montgomery domain, mod p)
 *   F END    return fail flag in eax
 *
 * Instruction encoding: 2 bytes (little-endian word).
 *   word = (dst << 12) | (src1 << 8) | (src2 << 4) | opcode
 * i.e. nibbles low-to-high: op, s2, s1, dst.  This order lets the
 * interpreter decode all three slot addresses with a single uniform
 * shift-right loop — after masking off the opcode, shr eax,4 three
 * times yields s2, s1, dst in sequence.  Pushed in that order and
 * popped in reverse gives rdi=dst, rsi=s1, rdx=s2 in ~20 bytes
 * instead of 41.
 *
 * Security
 * --------
 * Same algorithm, same validation, same field arithmetic as the
 * reference tv_ecdsa.c.  No secret-dependent control flow (this is
 * verification only; all inputs are public).  The bytecode is
 * static rodata — not writable, not attacker-influenced.
 * ====================================================================== */

	.intel_syntax noprefix
	.text

/* ----------------------------------------------------------------------
 * 256-bit big-integer primitives (4 × u64 limbs, little-endian).
 * -------------------------------------------------------------------- */

/* fe_cpy(dst=rdi, src=rsi).  rep movsq: 9 bytes total. */
fe_cpy:
	mov	ecx, 4
	rep	movsq
	ret

/* fe_iszero(a=rdi) -> eax (1 if zero).  Full 32-bit result since
 * verify's final call IS the function return value. */
fe_iszero:
	mov	rax, [rdi]
	or	rax, [rdi+8]
	or	rax, [rdi+16]
	or	rax, [rdi+24]
	sete	al
	movzx	eax, al
	ret

/* fe_sub_raw(dst=rdi, a=rsi, b=rdx) -> borrow in eax.
 * The `loop` instruction decrements ecx and branches WITHOUT touching
 * ANY flags — CF survives across iterations.  `lea` for pointer
 * increment also preserves flags.  This is the tightest looped
 * big-integer sub on x86-64. */
fe_sub_raw:
	mov	ecx, 4
	clc
1:	mov	rax, [rsi]
	sbb	rax, [rdx]
	mov	[rdi], rax
	lea	rsi, [rsi+8]
	lea	rdx, [rdx+8]
	lea	rdi, [rdi+8]
	loop	1b
	sbb	eax, eax
	neg	eax
	ret

/* fe_add_raw(dst=rdi, a=rsi, b=rdx).  Same loop trick. */
fe_add_raw:
	mov	ecx, 4
	clc
1:	mov	rax, [rsi]
	adc	rax, [rdx]
	mov	[rdi], rax
	lea	rsi, [rsi+8]
	lea	rdx, [rdx+8]
	lea	rdi, [rdi+8]
	loop	1b
	ret

/* fe_geq(a=rdi, b=rsi) -> al (1 if a>=b).  `loop` for -2 bytes. */
fe_geq:
	mov	ecx, 4
1:	mov	rax, [rdi+rcx*8-8]
	cmp	rax, [rsi+rcx*8-8]
	loopz	1b             /* loop while equal AND ecx > 0 */
	setae	al
	ret

/* fe_sub_m(dst,a,b,m). */
fe_sub_m:
	push	rcx
	push	rdi
	call	fe_sub_raw
	pop	rdi
	pop	rdx
	test	eax, eax
	jz	1f
	mov	rsi, rdi
	jmp	fe_add_raw
1:	ret

/* muladd4(t=r9, x=r8, y=rsi).  t[0..3] += x*y, carry into t[4],t[5].
 * Using r9 instead of rbp avoids the forced disp8 byte on [rbp+rdi]
 * (SIB with rbp base and mod=00 means disp32, so mod=01+disp8=0 is
 * forced).  [r9+rdi] encodes with no displacement.  -2 bytes. */
muladd4:
	xor	ecx, ecx
	xor	edi, edi
1:	mov	rax, r8
	mul	QWORD PTR [rsi+rdi]
	add	rax, [r9+rdi]
	adc	rdx, 0
	add	rax, rcx
	adc	rdx, 0
	mov	[r9+rdi], rax
	mov	rcx, rdx
	add	rdi, 8
	cmp	rdi, 32
	jb	1b
	add	[r9+32], rcx
	adc	QWORD PTR [r9+40], 0
	ret

/* .Lfm: fe_inv_m's "multiply with saved modulus" helper.  Placed
 * immediately before fe_mul_m so it falls through (no jmp).
 * r14 = m, r15 = m0i are fe_inv_m's saved params — valid whenever
 * .Lfm is called from fe_inv_m's loop. */
.Lfm:	mov	rcx, r14
	mov	r8, r15
	/* FALLTHROUGH */
/* fe_mul_m(r,a,b,m,m0i): Montgomery mul, CIOS. */
fe_mul_m:
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 56             /* 4 pushes + retaddr = 40; +56 = 96 aligned */

	mov	r12, rdi
	mov	[rsp+48], rdx       /* b */
	mov	r13, rcx            /* m */
	mov	r14, r8             /* m0i */
	mov	r15, rsi            /* a */

	xor	eax, eax
	mov	ecx, 6
	mov	rdi, rsp
	rep	stosq

	xor	r11d, r11d
.Lm:	mov	r9, rsp             /* t (r9 avoids forced disp; mov<lea) */
	mov	r8, [r15+r11]
	mov	rsi, [rsp+48]
	call	muladd4
	mov	r8, [rsp]
	imul	r8, r14
	mov	rsi, r13
	call	muladd4
	xor	ecx, ecx
1:	mov	rax, [rsp+rcx+8]
	mov	[rsp+rcx], rax
	add	ecx, 8
	cmp	ecx, 40
	jb	1b
	and	QWORD PTR [rsp+40], 0
	add	r11, 8
	cmp	r11, 32
	jb	.Lm

	mov	rdi, r12
	mov	rsi, rsp
	mov	rdx, r13
	call	fe_sub_raw
	sub	eax, [rsp+32]
	jz	2f
	mov	rdi, r12
	mov	rsi, rsp
	call	fe_cpy
2:
	add	rsp, 56
	/* 4-pop epilogue (rbp and rbx no longer saved — neither used). */
.Lepi4:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret

/* fe_inv_m(r,a,m,m0i): Fermat inversion in Montgomery form.
 * Low limb of both P and N is >= 3, so m[0]-2 cannot underflow. */
/* fe_inv_m(r, a, m, m0i): Fermat inversion.
 *
 * The accumulator t lives DIRECTLY IN the caller's output buffer r
 * (fe_mul_m is safe for dst==src since it copies operands into an
 * internal temp before overwriting dst).  This saves 32 bytes of
 * local stack + the final copy-out (~14 bytes).
 *
 * r10 holds the loop counter — caller-saved but untouched by
 * fe_mul_m's entire call tree (fe_mul_m uses r8,r9,r11; muladd4
 * uses r8,r9; fe_sub_raw/fe_cpy use no high regs). */
fe_inv_m:
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 40            /* e[4] only; 40+40=80 aligned */

	mov	r12, rdi           /* r = t accumulator */
	mov	r13, rsi           /* a */
	mov	r14, rdx           /* m */
	mov	r15, rcx           /* m0i */

	mov	rdi, rsp
	mov	rsi, r14
	call	fe_cpy
	sub	QWORD PTR [rsp], 2

	/* t = a; top bit of exponent is always 1 → start at bit 254. */
	mov	rdi, r12
	mov	rsi, r13
	call	fe_cpy

	mov	r10d, 254
.Le:	mov	rdi, r12
	mov	rsi, rdi
	mov	rdx, rdi
	call	.Lfm               /* t = t² (in r) */
	bt	QWORD PTR [rsp], r10
	jnc	.Lnx
	mov	rdi, r12
	mov	rsi, rdi
	mov	rdx, r13
	call	.Lfm               /* t *= a */
.Lnx:	dec	r10d
	jns	.Le
	/* t is already in r — no copy-out. */

	add	rsp, 40
	jmp	.Lepi4

/* .Lfm moved above fe_mul_m (falls through). */

/* fe_from_be(dst=rdi, src=rsi).  `loop` saves 2 bytes vs dec+jnz. */
fe_from_be:
	mov	ecx, 4
1:	mov	rax, [rsi+rcx*8-8]
	bswap	rax
	stosq
	loop	1b
	ret

/* ======================================================================
 * BYTECODE INTERPRETER — placed BEFORE the field-p wrappers so that
 * the jump-table stubs can reach them with 2-byte short jumps.
 *
 * bc_run(bytecode=rdi, slot_buf=rsi) -> eax = fail flag
 * ====================================================================== */
/* bcrun_r14 immediately before bc_run → falls through (no jmp). */
/* bcrun_r15 removed — verify now uses r14 for the slot buffer. */
bcrun_r14:
	mov	rsi, r14
	/* FALLTHROUGH */
bc_run:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx, rdi
	mov	r12, rsi
	xor	r13d, r13d
.Lbc:
	movzx	eax, WORD PTR [rbx]
	add	rbx, 2
	/* low nibble = op; next three nibbles = s2, s1, dst. */
	mov	r14d, eax
	and	r14d, 0xF
	cmp	r14b, 0xF
	je	.Lbce
	shr	eax, 4               /* drop op; now bits 0-3=s2, 4-7=s1, 8-11=dst */

	/* Uniform shift-right loop computes and pushes s2, s1, dst addrs.
	 * Pop in reverse → rdi=dst, rsi=s1, rdx=s2.  ~23 bytes vs the
	 * previous 41-byte triple-call approach. */
	mov	cl, 3
1:	mov	edx, eax
	and	edx, 0xF
	shl	edx, 5
	lea	rdx, [r12+rdx]
	push	rdx
	shr	eax, 4
	dec	cl
	jnz	1b
	pop	rdi
	pop	rsi
	pop	rdx

	lea	rbp, [rip+.Ljt]
	movzx	ecx, BYTE PTR [rbp+r14]
	add	rbp, rcx
	call	rbp
	jmp	.Lbc

.Lbce:	movzx	eax, r13b
	/* 5-pop epilogue shared with verify (jumps here after pop r15). */
.Lepi5:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp
	ret

.Ljt:
	.byte	.Lop0-.Ljt, .Lop1-.Ljt, .Lop2-.Ljt, .Lop3-.Ljt, .Lop4-.Ljt
	.byte	.Lop5-.Ljt, .Lop6-.Ljt, .Lop7-.Ljt, .Lop8-.Ljt, .Lop9-.Ljt
.Lop6:	call	fe_geq
	or	r13b, al
	ret
.Lop7:	call	fe_iszero
	or	r13b, al
	ret
.Lop8:	call	fe_iszero
	xor	al, 1
	or	r13b, al
	ret
.Lop9:	lea	rdx, [rip+cR2P]
	/* FALLTHROUGH to Fmul — op9 is TOMONT = mmul(dst, src1, R2P, P, 1) */
.Lop0:
Fmul:	lea	rcx, [rip+cP]
	mov	r8d, 1
	jmp	fe_mul_m
.Lop1:
Fsqr:	mov	rdx, rsi
	jmp	Fmul
.Lop3:
Fsub:	lea	rcx, [rip+cP]
	jmp	fe_sub_m
.Lop2:
/* Fadd is ONLY called from the bytecode interpreter (r12 = slot buf).
 * Slot 3 (= H in pt_add) is the ONE slot that's safe to clobber across
 * every ADD:
 *   - bc_dbl never uses slot 3 at all
 *   - bc_add2's ONLY ADD writes TO slot 3 (H ← 2V) intentionally, and
 *     all reads of the old-H value occur before that ADD
 *   - bc_v1 never uses slot 3
 * Using slot 3 as temp keeps Fadd at 34 bytes without corrupting ONE
 * at slot 15 or T3 at slot 11.  r12+96 is disp8 too — win on encoding. */
Fadd:	push	rdi
	push	rsi
	lea	rdi, [r12+3*32]     /* slot 3 — disp8! */
	lea	rsi, [rip+cP]
	call	fe_sub_raw
	lea	rdx, [r12+3*32]
	pop	rsi
	pop	rdi
	jmp	Fsub
.Lop5:
Nmul:	lea	rcx, [rip+cN]
	mov	r8, [rcx-8]          /* cN_M0I is at cN-8 */
	jmp	fe_mul_m
/* CPY (op 4) is dead — no bytecode stream uses it.  .Ljt[4] points
 * at .Lop5 (harmless; op 4 is never dispatched). */
.equ .Lop4, .Lop5

/* ----------------------------------------------------------------------
 * Helpers.
 * -------------------------------------------------------------------- */
/* cpy3(dst=rdi, src=rsi): copy 96 bytes. */
cpy3:
	mov	ecx, 12
	rep	movsq
	ret

/* build_one(dst=rdi): write normal-form 1.  stosq the 1 first, then
 * zero the rest — one byte shorter than zero-all + backpatch. */
build_one:
	mov	eax, 1
	stosq
	xor	eax, eax
	mov	ecx, 3
	rep	stosq
	ret

/* cond_sub_n(val=rdi): if *val >= n, subtract n in place.
 * Uses r12 as cached &cN.  fe_geq only touches rax/rcx/rdx — rdi
 * survives, so no push/pop needed. */
cond_sub_n:
	mov	rsi, r12
	call	fe_geq
	test	al, al
	jz	1f
	mov	rsi, rdi
	mov	rdx, r12
	jmp	fe_sub_raw
1:	ret

/* ----------------------------------------------------------------------
 * pt_add_acc(slot_buf=rdi) — add base (slots 4-6) into acc (slots 0-2)
 * in place, handling all special cases.  Used by both pt_mul's inner
 * loop and verify's final R1 += R2.
 *
 * Slot layout:
 *   0-2: acc.x/y/z = p = r (shared storage, reads-before-writes)
 *   3: H (driver checks — disp8 at rdi+96)
 *   4-6: base.x/y/z = q
 *   7: Rr (checked only when H==0, rare)
 *   8-11: locals
 *
 * Expects slot buffer ptr in rdi.  Preserves it in r14 internally.
 * -------------------------------------------------------------------- */
/* (bcrun_r14 / bcrun_r15 moved above bc_run for fall-through) */

/* With the dead base.z check gone, the r15 mid-pointer is used only
 * twice (rare paths) — push/pop/lea overhead (9 bytes) exceeds the
 * disp32 cost (2×3 = 6 bytes).  Dropped. */
pt_add_acc:
	push	r14
	mov	r14, rdi

	lea	rdi, [r14+64]
	call	fe_iszero
	test	al, al
	jz	1f
	mov	rdi, r14
	lea	rsi, [r14+128]     /* base; disp32, rare path */
	call	cpy3
	jmp	.Laa
	/* base.z check removed — see analysis above: base is never ∞. */
1:	lea	rdi, [rip+bc_add1]
	call	bcrun_r14
	lea	rdi, [r14+96]
	call	fe_iszero
	test	al, al
	jz	3f
	lea	rdi, [r14+7*32]    /* Rr; disp32, very rare path (H=0) */
	call	fe_iszero
	test	al, al
	jz	.Lai
	lea	rdi, [rip+bc_dbl]
	call	bcrun_r14
	jmp	.Laa
.Lai:	mov	rdi, r14
	xor	eax, eax
	mov	ecx, 12
	rep	stosq
	jmp	.Laa
3:	lea	rdi, [rip+bc_add2]
	call	bcrun_r14
.Laa:
	pop	r14
	ret

/* ----------------------------------------------------------------------
 * pt_mul(slot_buf=rdi, k=rsi) — double-and-add MSB-first.
 *
 * Input:  slot_buf[4..6] = base point (caller sets this).
 * Output: slot_buf[0..2] = k * base.
 *
 * The accumulator lives IN the slot buffer — no copy-in/copy-out per
 * iteration.  pt_dbl is inlined as a bare bc_run.
 * -------------------------------------------------------------------- */
pt_mul:
	push	rbp
	push	rbx
	push	r13
	/* No sub rsp needed: 3 pushes + retaddr = 32 bytes, already
	 * aligned.  (The previous `sub rsp,8` actually MIS-aligned.) */
	mov	rbx, rdi
	mov	rbp, rsi

	/* acc = infinity. */
	mov	rdi, rbx
	xor	eax, eax
	mov	ecx, 12
	rep	stosq

	mov	r13d, 255
.Lpm:	lea	rdi, [rip+bc_dbl]
	mov	rsi, rbx
	call	bc_run
	/* `bt [mem], reg` treats the memory operand as a bit string
	 * spanning multiple qwords — the bit index in r13 directly
	 * addresses bit r13 of the 256-bit scalar.  7 bytes total
	 * (vs 24 for the manual extract-shift-test). */
	bt	QWORD PTR [rbp], r13
	jnc	1f
	mov	rdi, rbx
	call	pt_add_acc
1:	dec	r13d
	jns	.Lpm

	pop	r13
	pop	rbx
	pop	rbp
	ret

/* ======================================================================
 * Public entry point.
 *
 * int tv_ecdsa_p256_verify_asm(sig, sig_len, pub, pub_len, hv, hv_len)
 *    rdi,  rsi,     rdx,  rcx,     r8,   r9
 *
 * Stack: the slot buffer (512 bytes) is shared across all bytecode runs;
 * the three Jacobian points (Q, R1, R2) live OUTSIDE it (since pt_mul
 * needs them as persistent structs).  Slot-resident values (r, s, t0..t2,
 * Q.x/y/z copies, constants) live inside the buffer.
 *
 * Buffer slot map:
 *   0 t0/w     1 t1/u1   2 t2/u2   3 r       4 s/e
 *   5 Q.x      6 Q.y     7 Q.z     (Montgomery-form, working copy)
 *   10 one (normal-form, for exit-Mont)
 *   11 BM      12 ONE_M  13 N      14 P     15 (scratch)
 * ====================================================================== */
	.globl	tv_ecdsa_p256_verify_asm
	.type	tv_ecdsa_p256_verify_asm, @function

/*
 * SINGLE SLOT BUFFER architecture.  One 512-byte buffer serves both
 * verify's bytecode streams AND pt_mul/pt_add_acc.  bc_v1 writes Q
 * directly into slots 4-6 (= pt_mul's base slots) — no copy needed.
 *
 * Slot map:
 *   0-2: scratch → acc/R1 during pt ops
 *   3: H (pt ops)
 *   4-6: Q (bc_v1) = base (pt ops)  ← key: same slots!
 *   7: Rr → later Z⁻¹
 *   8-10: N,P,BM consts (bc_v1) → pt locals (reused after bc_v1)
 *   11: pt locals
 *   12: r (persistent — pt ops never touch slots ≥12)
 *   13: s → e → u1 (persistent)
 *   14: u2 (persistent)
 *   15: one (for bc_v2 + Q.z; CLOBBERED by Fadd during pt ops;
 *            REBUILT before bc_v3)
 *
 * Stack layout:  slot buf (512) + R2 storage (96) = 608, round to 616.
 *
 * Register budget:
 *   r14 = slot buf base (= rsp)
 *   r13 = mid-pointer into high slots (rsp+384 = slot 12)
 *   r12 = sig → &cN (as before)
 *   rbx = hv → &R2 storage (rsp+512)
 *   rbp = mid-pointer for low slots (rsp+64)
 *   r15 DROPPED — one fewer push/pop, -2 bytes + no bcrun_r15
 */
tv_ecdsa_p256_verify_asm:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp, 616

	mov	r14, rsp             /* slot buf base */
	lea	rbp, [rsp+64]        /* slots 0-4 disp8 via rbp */
	lea	r13, [rsp+12*32]     /* slot 12+ disp8 via r13 */

	mov	r12, rdi             /* sig */
	mov	rbx, r8              /* hv */
	mov	r8, rdx              /* pub (survives fe_from_be) */

	xor	eax, eax
	cmp	rsi, 64
	jne	.Lf
	cmp	rcx, 65
	jne	.Lf
	cmp	r9, 32
	jb	.Lf
	cmp	r9, 64
	ja	.Lf

	/* r → slot 12 (via r13), s → slot 13. */
	mov	rsi, r12
	lea	rdi, [r13+0]
	call	fe_from_be
	lea	rsi, [r12+32]
	lea	rdi, [r13+32]
	call	fe_from_be

	cmp	BYTE PTR [r8], 0x04
	jne	.Lf
	lea	rsi, [r8+1]
	lea	rdi, [rbp-64]        /* qx → slot 0 */
	call	fe_from_be
	lea	rsi, [r8+33]
	lea	rdi, [rbp-32]        /* qy → slot 1 */
	call	fe_from_be
	lea	r12, [rip+cN]

	/* Constants N,P,BM → slots 8-10. */
	lea	rdi, [r14+8*32]
	mov	rsi, r12
	mov	ecx, 12
	rep	movsq
	/* rdi now at slot 11. Slot 15 (one) is at rdi+128 — disp32,
	 * but can chain from r13: r13+96 = slot 15, disp8! */
	lea	rdi, [r13+96]
	call	build_one

	/* ===== Stream 1: validation + curve check + Q.z ===== */
	lea	rdi, [rip+bc_v1]
	call	bcrun_r14
	test	eax, eax
	jnz	.Lf
	/* Q is now at slots 4-6 = pt_mul's base.  NO COPY NEEDED. */

	/* w = s⁻¹·R² mod n (cR2N-free flow). */
	lea	rdi, [rbp-64]        /* slot 0 */
	lea	rsi, [r13+32]        /* s @ slot 13 */
	mov	rdx, r12
	mov	rcx, [r12-8]
	call	fe_inv_m

	/* e = hash → slot 13 (overwrites s); cond-sub n. */
	mov	rsi, rbx
	lea	rdi, [r13+32]
	call	fe_from_be
	lea	rdi, [r13+32]
	call	cond_sub_n
	/* hv dead — reuse rbx for R2 storage ptr (rsp+512). */
	lea	rbx, [r14+512]

	/* Stream 2: u1, u2 (slots 13, 14). */
	lea	rdi, [rip+bc_v2]
	call	bcrun_r14

	/* ===== R2 = u2 * Q =====  Q already at base slots 4-6! */
	mov	rdi, r14
	lea	rsi, [r13+64]        /* u2 @ slot 14 */
	call	pt_mul
	/* Save R2 (acc @ 0-2) to external storage. */
	mov	rdi, rbx
	mov	rsi, r14
	call	cpy3

	/* ===== R1 = u1 * G =====  Load G into base (4-6); z unchanged. */
	lea	rdi, [r14+4*32]      /* disp32, 1 use */
	lea	rsi, [rip+cGXM]
	mov	ecx, 8
	rep	movsq
	mov	rdi, r14
	lea	rsi, [r13+32]        /* u1 @ slot 13 */
	call	pt_mul

	/* ===== R1 += R2 =====  Load R2 into base slots. */
	lea	rdi, [r14+4*32]
	mov	rsi, rbx
	call	cpy3
	mov	rdi, r14
	call	pt_add_acc

	/* R1 infinity? acc.z @ slot 2 = rbp+0. */
	lea	rdi, [rbp+0]
	call	fe_iszero
	test	al, al
	jnz	.Lf

	/* Affine x: Z⁻¹ → slot 3 (= H, garbage after pt ops — safe).
	 * slot 3 = r14+96, disp8 everywhere (vs slot 7 = 224 disp32). */
	lea	rdi, [r14+96]
	lea	rsi, [rbp+0]         /* R1.z @ slot 2 */
	lea	rdx, [r12+32]
	mov	ecx, 1
	call	fe_inv_m

	lea	rdi, [rip+bc_v3]
	call	bcrun_r14

	/* Result in slot 3.  Reduce mod n, compare r. */
	lea	rdi, [r14+96]
	call	cond_sub_n
	lea	rdi, [r14+96]
	mov	rsi, rdi
	lea	rdx, [r13+0]
	call	fe_sub_raw
	lea	rdi, [r14+96]
	call	fe_iszero
	jmp	.Ld

.Lf:	xor	eax, eax
.Ld:	add	rsp, 616
	jmp	.Lepi5             /* 5-pop epilogue in bc_run */

/* ======================================================================
 * Bytecode streams.  See the Python generator for annotations.
 * ====================================================================== */
	.section .rodata
	.p2align 3

/* pt_dbl: acc (= p = r) @ slots 0-2; locals @ 8-11 (HIGH — leaves
 * slots 3-7 untouched so pt_mul's base @ 4-6 survives the doubling).
 * New encoding: word = (dst<<12)|(s1<<8)|(s2<<4)|op. */
bc_dbl:
	.byte 0x01,0xb2, 0x01,0x91, 0xb3,0x80, 0xb2,0xa0, 0xa0,0xa8
	.byte 0xa2,0x8a, 0xa2,0xa8, 0x22,0x81, 0x01,0x88, 0x93,0x88
	.byte 0xb3,0x28, 0x90,0xb0, 0xb2,0x8b, 0x82,0x88, 0x82,0xb8
	.byte 0x01,0x0a, 0xb3,0x00, 0x03,0x88, 0x80,0x8a, 0x01,0x99
	.byte 0x92,0x99, 0x92,0x99, 0x92,0x99, 0x93,0x18, 0x0f,0x00

/* pt_add_acc: acc(=p=r)@0-2, H@3 (disp8 for driver!), base(=q)@4-6,
 *             Rr@7, U1/S1/T2/T3@8-11. */
bc_add1:
	.byte 0x01,0xa2, 0x01,0xb6, 0xb0,0x80, 0xa0,0x34, 0x60,0x91
	.byte 0xb0,0x99, 0x20,0x75, 0xa0,0x77, 0x83,0x33, 0x93,0x77
	.byte 0x0f,0x00

/* bc_add2: reordered so T3 (slot 11) is fully consumed BEFORE the
 * ADD — Fadd's slot-11 temp is then safe to clobber it. */
bc_add2:
	.byte 0x60,0xa2, 0x30,0x2a, 0x01,0xa3, 0xa0,0xb3, 0xa0,0x88
	.byte 0xb0,0x99, 0x01,0x07, 0xb3,0x00, 0x82,0x38, 0x33,0x00
	.byte 0x03,0x38, 0x30,0x37, 0x93,0x13, 0x0f,0x00

/* verify stream 1 (SINGLE-BUFFER layout):
 * slots: 0=qx/t0, 1=qy/t1, 4=Qx, 5=Qy, 6=Qz (= pt_mul's base!),
 *        8=N, 9=P, 10=BM, 12=r, 13=s, 15=one.
 * Q.z set BEFORE the curve check (whose ADD clobbers slot 15 via
 * Fadd's temp). */
bc_v1:
	.byte 0x07,0xc0, 0x06,0xc8, 0x07,0xd0, 0x06,0xd8
	.byte 0x06,0x09, 0x06,0x19, 0x09,0x40, 0x09,0x51
	.byte 0x09,0x6f, 0x01,0x05, 0x01,0x14, 0x40,0x11
	.byte 0x43,0x11, 0x43,0x11, 0x43,0x11, 0xa2,0x11
	.byte 0x13,0x00, 0x08,0x00, 0x0f,0x00

/* bc_v2: u1 = e*w→u1*one, u2 = r*w→u2*one. slots 13/14. */
bc_v2:
	.byte 0x05,0xdd, 0xf5,0xdd, 0x05,0xec, 0xf5,0xee, 0x0f,0x00

/* bc_v3: slot3 = Z⁻² * R1.x(slot0) * one(slot15).  Slot 3 (H, dead
 * after pt ops) = r14+96 disp8 — saves 4 disp32 leas vs slot 7. */
bc_v3:
	.byte 0x01,0x33, 0x00,0x33, 0xf0,0x33, 0x0f,0x00

/* ----------------------------------------------------------------------
 * Constants.  No alignment directive — x86-64 handles misaligned qword
 * loads correctly (slower, but this is a boot-ROM one-shot).  The
 * bytecode above is 156 bytes, so cN_M0I lands at an odd alignment;
 * saves the 4 padding bytes that .p2align 3 would insert.
 * -------------------------------------------------------------------- */

/* cN_M0I placed IMMEDIATELY BEFORE cN so that any pointer to cN
 * can reach it as [ptr-8] with disp8 addressing.  Nmul and verify's
 * fe_inv_m call both exploit this. */
cN_M0I:	.quad 0xccd1c8aaee00bc4f

/* --- contiguous 96-byte block (N, P, BM) for verify's block-load --- */
cN:	.quad 0xf3b9cac2fc632551, 0xbce6faada7179e84
	.quad 0xffffffffffffffff, 0xffffffff00000000
cP:	.quad 0xffffffffffffffff, 0x00000000ffffffff
	.quad 0x0000000000000000, 0xffffffff00000001
cBM:	.quad 0xd89cdf6229c4bddf, 0xacf005cd78843090
	.quad 0xe5a220abf7212ed6, 0xdc30061d04874834
/* --- end contiguous block --- */

cR2P:	.quad 0x0000000000000003, 0xfffffffbffffffff
	.quad 0xfffffffffffffffe, 0x00000004fffffffd
/* cR2N removed — see cR2N-free inversion flow above. */
cGXM:	.quad 0x79e730d418a9143c, 0x75ba95fc5fedb601
	.quad 0x79fb732b77622510, 0x18905f76a53755c6
cGYM:	.quad 0xddf25357ce95560a, 0x8b4ab8e4ba19e45c
	.quad 0xd2e88688dd21f325, 0x8571ff1825885d85

	.section .note.GNU-stack,"",@progbits
