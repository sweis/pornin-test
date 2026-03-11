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
 * Instruction encoding: 2 bytes.
 *   byte[0] = (opcode << 4) | dst_slot
 *   byte[1] = (src1_slot << 4) | src2_slot
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

/* fe_cpy(dst=rdi, src=rsi).  lodsq/stosq loop.  14 bytes. */
fe_cpy:
	mov	ecx, 4
1:	lodsq
	stosq
	dec	ecx
	jnz	1b
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

/* fe_geq(a=rdi, b=rsi) -> al (1 if a>=b).  Upper bits garbage. */
fe_geq:
	mov	ecx, 4
1:	mov	rax, [rdi+rcx*8-8]
	cmp	rax, [rsi+rcx*8-8]
	jne	2f
	dec	ecx
	jnz	1b
2:	setae	al
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

/* muladd4(t=rbp, x=rbx, y=rsi).  t[0..3] += x*y, carry into t[4],t[5]. */
muladd4:
	xor	ecx, ecx
	xor	edi, edi
1:	mov	rax, rbx
	mul	QWORD PTR [rsi+rdi]
	add	rax, [rbp+rdi]
	adc	rdx, 0
	add	rax, rcx
	adc	rdx, 0
	mov	[rbp+rdi], rax
	mov	rcx, rdx
	add	rdi, 8
	cmp	rdi, 32
	jb	1b
	add	[rbp+32], rcx
	adc	QWORD PTR [rbp+40], 0
	ret

/* fe_mul_m(r,a,b,m,m0i): Montgomery mul, CIOS. */
fe_mul_m:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 56

	/* r12 = r (dst ptr) — survives everything; b (rdx) stashed on
	 * stack and reloaded once per iteration. */
	mov	r12, rdi
	mov	[rsp+48], rdx       /* b */
	mov	r13, rcx            /* m */
	mov	r14, r8             /* m0i */
	mov	r15, rsi            /* a */

	xor	eax, eax
	mov	ecx, 6
	lea	rdi, [rsp]
	rep	stosq

	xor	r11d, r11d
.Lm:	lea	rbp, [rsp]
	mov	rbx, [r15+r11]
	mov	rsi, [rsp+48]       /* b */
	call	muladd4
	mov	rbx, [rsp]
	imul	rbx, r14
	mov	rsi, r13
	call	muladd4
	xor	ecx, ecx
1:	mov	rax, [rsp+rcx+8]
	mov	[rsp+rcx], rax
	add	ecx, 8
	cmp	ecx, 40
	jb	1b
	and	QWORD PTR [rsp+40], 0   /* imm8 sign-extended: 6 bytes vs 9 */
	add	r11, 8
	cmp	r11, 32
	jb	.Lm

	mov	rdi, r12
	lea	rsi, [rsp]
	mov	rdx, r13
	call	fe_sub_raw
	cmp	DWORD PTR [rsp+32], 0
	jnz	2f
	test	eax, eax
	jz	2f
	mov	rdi, r12
	lea	rsi, [rsp]
	call	fe_cpy
2:
	add	rsp, 56
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* fe_inv_m(r,a,m,m0i): Fermat inversion in Montgomery form.
 * Low limb of both P and N is >= 3, so m[0]-2 cannot underflow. */
fe_inv_m:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 72

	mov	r12, rdi
	mov	r13, rsi
	mov	r14, rdx
	mov	r15, rcx

	lea	rdi, [rsp]
	mov	rsi, r14
	call	fe_cpy
	sub	QWORD PTR [rsp], 2

	/* bl = started flag, bh = bit.  Both survive fe_mul_m (rbx is
	 * callee-saved).  The `mov rcx,r14; mov r8,r15` pair before each
	 * fe_mul_m call is factored into .Lfm (saves ~4 bytes net). */
	xor	ebx, ebx
	mov	ebp, 255
.Le:	mov	ecx, ebp
	shr	ecx, 6
	mov	rax, [rsp+rcx*8]
	mov	ecx, ebp
	and	ecx, 63
	shr	rax, cl
	mov	bh, al
	and	bh, 1
	test	bl, bl
	jz	.Lns
	lea	rdi, [rsp+32]
	mov	rsi, rdi
	mov	rdx, rdi
	call	.Lfm
	test	bh, bh
	jz	.Lnx
	lea	rdi, [rsp+32]
	mov	rsi, rdi
	mov	rdx, r13
	call	.Lfm
	jmp	.Lnx
.Lns:	test	bh, bh
	jz	.Lnx
	lea	rdi, [rsp+32]
	mov	rsi, r13
	call	fe_cpy
	mov	bl, 1
.Lnx:	dec	ebp
	jns	.Le

	mov	rdi, r12
	lea	rsi, [rsp+32]
	call	fe_cpy

	add	rsp, 72
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* Local helper: load (m, m0i) and tail-call fe_mul_m.  Placed
 * after fe_inv_m so rel8 jmp works if fe_mul_m were adjacent;
 * still saves the repeated 6-byte (mov rcx + mov r8) sequence. */
.Lfm:	mov	rcx, r14
	mov	r8, r15
	jmp	fe_mul_m

/* fe_from_be(dst=rdi, src=rsi). */
fe_from_be:
	mov	ecx, 4
1:	mov	rax, [rsi+rcx*8-8]
	bswap	rax
	stosq
	dec	ecx
	jnz	1b
	ret

/* ======================================================================
 * BYTECODE INTERPRETER — placed BEFORE the field-p wrappers so that
 * the jump-table stubs can reach them with 2-byte short jumps.
 *
 * bc_run(bytecode=rdi, slot_buf=rsi) -> eax = fail flag
 * ====================================================================== */
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
	/* al=(op<<4)|dst  ah=(s1<<4)|s2 */
	mov	r14d, eax
	shr	r14d, 4
	and	r14d, 0xF
	cmp	r14b, 0xF
	je	.Lbce

	/* Slot-to-address helper is called 3× with different nibbles.
	 * Input: cl = raw nibble byte; output: rcx = slot address. */
	mov	cl, al
	call	.Lsa
	mov	rdi, rcx           /* dst */
	mov	cl, ah
	shr	cl, 4
	call	.Lsa
	mov	rsi, rcx           /* src1 */
	mov	cl, ah
	call	.Lsa
	mov	rdx, rcx           /* src2 */

	lea	rbp, [rip+.Ljt]
	movzx	ecx, BYTE PTR [rbp+r14]
	add	rbp, rcx
	call	rbp
	jmp	.Lbc

.Lsa:	/* and-shl-lea: 4-bit nibble in cl -> address in rcx. */
	and	ecx, 0xF
	shl	ecx, 5
	lea	rcx, [r12+rcx]
	ret

.Lbce:	movzx	eax, r13b
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
Fadd:	push	rdi
	push	rsi
	sub	rsp, 40
	lea	rdi, [rsp]
	lea	rsi, [rip+cP]
	call	fe_sub_raw
	mov	rdx, rsp
	mov	rsi, [rsp+40]
	mov	rdi, [rsp+48]
	call	Fsub
	add	rsp, 40
	pop	rsi
	pop	rdi
	ret
.Lop5:
Nmul:	lea	rcx, [rip+cN]
	mov	r8, [rcx-8]          /* cN_M0I is at cN-8 */
	jmp	fe_mul_m
.Lop4:	jmp	fe_cpy

/* ----------------------------------------------------------------------
 * Helpers.
 * -------------------------------------------------------------------- */
/* cpy3(dst=rdi, src=rsi): copy 96 bytes. */
cpy3:
	mov	ecx, 12
	rep	movsq
	ret

/* build_one(dst=rdi): write normal-form 1 (qword 1 + three zeros).
 * Replaces the cONE_M rodata constant. */
build_one:
	xor	eax, eax
	mov	ecx, 4
	rep	stosq
	mov	QWORD PTR [rdi-32], 1
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
pt_add_acc:
	push	r14
	push	r15
	mov	r14, rdi
	lea	r15, [r14+128]     /* mid-pointer: base@-0..+64, Rr@+96 disp8 */

	/* If acc.z == 0: acc = base. */
	lea	rdi, [r14+64]
	call	fe_iszero
	test	al, al
	jz	1f
	mov	rdi, r14
	lea	rsi, [r15+0]       /* base; now disp8 via r15 */
	call	cpy3
	jmp	.Laa
1:	/* If base.z == 0: acc unchanged. */
	lea	rdi, [r15+64]      /* base.z */
	call	fe_iszero
	test	al, al
	jnz	.Laa
	lea	rdi, [rip+bc_add1]
	mov	rsi, r14
	call	bc_run
	/* H == 0? (slot 3 = r14+96, disp8) */
	lea	rdi, [r14+96]
	call	fe_iszero
	test	al, al
	jz	3f
	/* H=0: check Rr (slot 7 = r15+96, now disp8) */
	lea	rdi, [r15+96]
	call	fe_iszero
	test	al, al
	jz	.Lai
	lea	rdi, [rip+bc_dbl]
	mov	rsi, r14
	call	bc_run
	jmp	.Laa
.Lai:	mov	rdi, r14
	xor	eax, eax
	mov	ecx, 12
	rep	stosq
	jmp	.Laa
3:	lea	rdi, [rip+bc_add2]
	mov	rsi, r14
	call	bc_run
.Laa:
	pop	r15
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
	sub	rsp, 8             /* align */
	mov	rbx, rdi           /* slot buffer */
	mov	rbp, rsi           /* k */

	/* acc = infinity. */
	mov	rdi, rbx
	xor	eax, eax
	mov	ecx, 12
	rep	stosq

	mov	r13d, 255
.Lpm:	/* double: just run bc_dbl (acc at slots 0-2, locals at 3-6). */
	lea	rdi, [rip+bc_dbl]
	mov	rsi, rbx
	call	bc_run
	/* bit test */
	mov	ecx, r13d
	shr	ecx, 6
	mov	rax, [rbp+rcx*8]
	mov	ecx, r13d
	and	ecx, 63
	shr	rax, cl
	test	al, 1
	jz	1f
	mov	rdi, rbx
	call	pt_add_acc
1:	dec	r13d
	jns	.Lpm

	add	rsp, 8
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

tv_ecdsa_p256_verify_asm:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	/* Stack: primary slot buf (512, used for validation/u1u2/affine),
	 * secondary slot buf (512, used by pt_mul — acc@0-2, base@4-6),
	 * R2 storage (96).  Total = 1128 rounded. */
	sub	rsp, 1128

	lea	rbp, [rsp+64]        /* slots 0..4 disp8 via rbp-64..+64 */
	mov	r15, rsp             /* primary slot buf base */
	lea	r13, [rsp+512]       /* secondary slot buf (pt_mul's acc+base) */
	lea	r14, [rsp+1024]      /* R2 storage (96 bytes) */

	/* r12: sig → &cN.  pub stashed in r8 (fe_from_be touches only
	 * rax/rcx/rsi/rdi so r8 survives the four decode calls). */
	mov	r12, rdi             /* sig */
	mov	rbx, r8              /* hv */
	mov	r8, rdx              /* pub */

	/* Length checks. */
	xor	eax, eax
	cmp	rsi, 64
	jne	.Lf
	cmp	rcx, 65
	jne	.Lf
	cmp	r9, 32
	jb	.Lf
	cmp	r9, 64
	ja	.Lf

	/* Decode r -> slot 3, s -> slot 4. */
	mov	rsi, r12
	lea	rdi, [rbp+32]
	call	fe_from_be
	lea	rsi, [r12+32]
	lea	rdi, [rbp+64]
	call	fe_from_be
	/* sig dead. */

	cmp	BYTE PTR [r8], 0x04
	jne	.Lf
	lea	rsi, [r8+1]
	lea	rdi, [rbp-64]
	call	fe_from_be
	lea	rsi, [r8+33]
	lea	rdi, [rbp-32]
	call	fe_from_be
	/* pub dead; r12 -> &cN for rest of function. */
	lea	r12, [rip+cN]

	/* Block-load constants N,P,BM -> slots 11..13. */
	lea	rdi, [r15+11*32]
	mov	rsi, r12
	mov	ecx, 12
	rep	movsq
	/* After rep movsq, rdi = r15+11*32+96 = r15+448 = slot 14.
	 * Slot 10 is at rdi-128 — disp8!  Saves a full disp32 lea. */
	sub	rdi, 128
	call	build_one

	/* ===== Stream 1: validation + curve check + Q.z ===== */
	lea	rdi, [rip+bc_v1]
	mov	rsi, r15
	call	bc_run
	test	eax, eax
	jnz	.Lf

	/* Copy Q (primary slots 5-7) -> secondary buf's BASE slots. */
	lea	rdi, [r13+4*32]      /* disp32, 1 use */
	lea	rsi, [r15+5*32]
	call	cpy3

	/* ===== w = s^{-1} (Montgomery, mod n) ===== */
	lea	rdi, [rbp-64]
	lea	rsi, [rbp+64]
	lea	rdx, [rip+cR2N]
	call	Nmul
	lea	rdi, [rbp-64]
	mov	rsi, rdi
	mov	rdx, r12
	mov	rcx, [r12-8]         /* cN_M0I at cN-8 */
	call	fe_inv_m

	/* e = hash -> slot 4; cond-sub n. */
	mov	rsi, rbx
	lea	rdi, [rbp+64]
	call	fe_from_be
	lea	rdi, [rbp+64]
	call	cond_sub_n
	/* hv dead — reuse rbx to cache r13+128 (base slots), saving
	 * 3 disp32 leas below. */
	lea	rbx, [r13+128]

	/* ===== Stream 2: u1, u2 ===== */
	lea	rdi, [rip+bc_v2]
	mov	rsi, r15
	call	bc_run

	/* ===== R2 = u2 * Q ===== */
	mov	rdi, r13
	lea	rsi, [rbp+0]
	call	pt_mul
	mov	rdi, r14
	mov	rsi, r13
	call	cpy3

	/* ===== R1 = u1 * G =====  cGXM, cGYM adjacent in rodata —
	 * block-copy both (64 bytes) in one shot.  base.z unchanged. */
	mov	rdi, rbx
	lea	rsi, [rip+cGXM]
	mov	ecx, 8
	rep	movsq
	mov	rdi, r13
	lea	rsi, [rbp-32]
	call	pt_mul

	/* ===== R1 += R2 ===== */
	mov	rdi, rbx
	mov	rsi, r14
	call	cpy3
	mov	rdi, r13
	call	pt_add_acc

	/* R1 at infinity?  acc.z = r13[64]. */
	lea	rdi, [r13+64]
	call	fe_iszero
	test	al, al
	jnz	.Lf

	/* ===== Affine x =====  cP is at cN+32 = r12+32. */
	lea	rdi, [rbp-32]
	lea	rsi, [r13+64]
	lea	rdx, [r12+32]
	mov	ecx, 1
	call	fe_inv_m

	/* slot 8 = R1.x; slot 10 already = "1". */
	lea	rdi, [r15+8*32]
	mov	rsi, r13
	call	fe_cpy

	lea	rdi, [rip+bc_v3]
	mov	rsi, r15
	call	bc_run

	/* reduce mod n; compare r. */
	lea	rdi, [rbp-32]
	call	cond_sub_n
	lea	rdi, [rbp-32]
	mov	rsi, rdi
	lea	rdx, [rbp+32]
	call	fe_sub_raw
	lea	rdi, [rbp-32]
	call	fe_iszero
	jmp	.Ld

.Lf:	xor	eax, eax
.Ld:	add	rsp, 1128
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* ======================================================================
 * Bytecode streams.  See the Python generator for annotations.
 * ====================================================================== */
	.section .rodata
	.p2align 3

/* pt_dbl: acc (= p = r) @ slots 0-2; locals @ 8-11 (HIGH — leaves
 * slots 3-7 untouched so pt_mul's base @ 4-6 survives the doubling). */
bc_dbl:
	.byte 0x1b,0x20, 0x19,0x10, 0x38,0x0b, 0x2a,0x0b, 0x0a,0x8a
	.byte 0x28,0xaa, 0x2a,0x8a, 0x28,0x12, 0x18,0x80, 0x38,0x89
	.byte 0x32,0x8b, 0x0b,0x09, 0x28,0xbb, 0x28,0x88, 0x2b,0x88
	.byte 0x10,0xa0, 0x30,0x0b, 0x38,0x80, 0x08,0xa8, 0x19,0x90
	.byte 0x29,0x99, 0x29,0x99, 0x29,0x99, 0x31,0x89, 0xf0,0x00

/* pt_add_acc: acc(=p=r)@0-2, H@3 (disp8 for driver!), base(=q)@4-6,
 *             Rr@7, U1/S1/T2/T3@8-11. */
bc_add1:
	.byte 0x1a,0x20, 0x1b,0x60, 0x08,0x0b, 0x03,0x4a, 0x09,0x16
	.byte 0x09,0x9b, 0x07,0x52, 0x07,0x7a, 0x33,0x38, 0x37,0x79
	.byte 0xf0,0x00

bc_add2:
	.byte 0x0a,0x26, 0x02,0xa3, 0x1a,0x30, 0x0b,0x3a, 0x08,0x8a
	.byte 0x10,0x70, 0x30,0x0b, 0x23,0x88, 0x30,0x03, 0x33,0x80
	.byte 0x03,0x73, 0x09,0x9b, 0x31,0x39, 0xf0,0x00

/* verify stream 1: validate r,s,qx,qy; convert qx,qy to Mont; curve
 * check; Q.z = 1_mont.
 * slots: 0=qx, 1=qy, 3=r, 4=s, 5=Qx, 6=Qy, 7=Qz,
 *        11=N, 12=P, 13=BM, 14=ONE_M  (matches rodata adjacency) */
bc_v1:
	.byte 0x73,0x00, 0x63,0xb0, 0x74,0x00, 0x64,0xb0
	.byte 0x60,0xc0, 0x61,0xc0
	.byte 0x95,0x00, 0x96,0x10
	.byte 0x10,0x60, 0x11,0x50, 0x01,0x15
	.byte 0x31,0x15, 0x31,0x15, 0x31,0x15
	.byte 0x21,0x1d, 0x30,0x01, 0x80,0x00
	.byte 0x97,0xa0, 0xf0,0x00

bc_v2:
	.byte 0x51,0x40, 0x52,0x30, 0xf0,0x00

bc_v3:
	.byte 0x11,0x10, 0x01,0x18, 0x01,0x1a, 0xf0,0x00

/* ----------------------------------------------------------------------
 * Constants.  N, P, BM, ONE_M are CONTIGUOUS in this order so that
 * verify can block-copy all four into slots 11..14 with one rep movsq.
 * 8-byte alignment suffices for qword access; saves a few bytes of
 * padding versus 32-byte alignment.
 * -------------------------------------------------------------------- */
	.p2align 3

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
cR2N:	.quad 0x83244c95be79eea2, 0x4699799c49bd6fa6
	.quad 0x2845b2392b6bec59, 0x66e12d94f3d95620
cGXM:	.quad 0x79e730d418a9143c, 0x75ba95fc5fedb601
	.quad 0x79fb732b77622510, 0x18905f76a53755c6
cGYM:	.quad 0xddf25357ce95560a, 0x8b4ab8e4ba19e45c
	.quad 0xd2e88688dd21f325, 0x8571ff1825885d85

	.section .note.GNU-stack,"",@progbits
