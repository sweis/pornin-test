/* ======================================================================
 * ECDSA/P-256 verify — x86-64, bytecode-interpreted, speed+size optimized.
 *
 * Same architecture as tv_ecdsa_bc.S (2-byte bytecode, 16-slot buffer,
 * shared interpreter).  Requires BMI2 (mulx).
 *
 * 1660 bytes, ~1.28M cycles (Skylake-class).  vs tv_ecdsa_bc.S:
 * 1712 bytes, ~2.16M cycles — so −52 bytes AND −41% cycles.
 *
 * Hot-path changes:
 *
 *   - Advancing-pointer CIOS in fe_mul_m: instead of shifting the
 *     6-word accumulator down one limb every outer iteration (20 memory
 *     moves per fe_mul_m), the base pointer r9 advances.  The CIOS
 *     invariant guarantees t[0]=0 after reduction, so t[1..] is the
 *     new accumulator — no data movement.  Needs a 9-word buffer.
 *     Removes the shift loop entirely: −21 bytes, huge cycle win.
 *
 *   - muladd4 fully unrolled with mulx.  mulx writes its high word
 *     to a chosen register, so the carry chain hops rcx↔rdi with no
 *     mov.  Scalar passed in rdx (mulx's implicit source).  Low-limb
 *     writeback is a single RMW `add [mem],reg`.  85 bytes.
 *
 *   - fe_sub_raw/fe_add_raw use lodsq/stosq (auto-increment, 2 bytes
 *     each, flag-preserving) and `dec ecx; jnz` instead of `loop`.
 *     `dec` sets ZF but preserves CF for the carry chain.  `loop` is
 *     microcoded (~7 cyc/iter on modern Intel); dec/jnz is 1.
 *     −15 bytes AND faster.
 *
 *   - fe_cpy is 4×movsq (no `rep` startup overhead on the ~50%-taken
 *     fe_mul_m copy-back path).  Zero-init of t is a dec-loop for
 *     the same reason.
 *
 * Size-only changes:
 *
 *   - SQR bytecode encodes s2=s1; decoder sets rdx=rsi for free, so
 *     SQR dispatches straight to Fmul.  −5 bytes.
 *   - `push N; pop reg` replaces `mov reg,imm32` where N fits signed
 *     imm8 (−2 each, many sites).
 *   - fe_mul_m outer counter goes −32→0 so `add;jnz` drops the cmp.
 *   - verify's slot-4/slot-8 leas via rbp/r13 mid-pointers: disp8.
 *
 * Security and validation are unchanged from tv_ecdsa_bc.S.
 * ====================================================================== */

	.intel_syntax noprefix
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

fe_iszero:
	mov	rax, [rdi]
	or	rax, [rdi+8]
	or	rax, [rdi+16]
	or	rax, [rdi+24]
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

fe_add_raw:
	xor	ecx, ecx
	mov	cl, 4
1:	lodsq
	adc	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	dec	ecx
	jnz	1b
	ret

/* fe_geq — cold (validation + cond_sub_n).  Keep loopz: size wins. */
fe_geq:
	push	4
	pop	rcx
1:	mov	rax, [rdi+rcx*8-8]
	cmp	rax, [rsi+rcx*8-8]
	loopz	1b
	setae	al
	ret

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

/* muladd4(t=r9, x=rdx, y=rsi).  t[0..3] += x*y, carry into t[4..5].
 * Fully unrolled.  Uses mulx (BMI2) — high word written directly to
 * a chosen register, so the high-word carry chain hops rcx↔rdi
 * with no mov in between.  Scalar passed in rdx (mulx's implicit
 * source) — callers changed to load there directly. */
muladd4:
	mulx	rcx, rax, [rsi]
	add	[r9], rax
	adc	rcx, 0

	mulx	rdi, rax, [rsi+8]
	add	rax, rcx
	adc	rdi, 0
	add	[r9+8], rax
	adc	rdi, 0

	mulx	rcx, rax, [rsi+16]
	add	rax, rdi
	adc	rcx, 0
	add	[r9+16], rax
	adc	rcx, 0

	mulx	rdi, rax, [rsi+24]
	add	rax, rcx
	adc	rdi, 0
	add	[r9+24], rax
	adc	rdi, 0

	add	[r9+32], rdi
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
	sub	rsp, 72             /* 9 qwords for t; 40+72 = 112 aligned */

	mov	r12, rdi            /* r */
	mov	r10, rdx            /* b — stays in reg */
	mov	r13, rcx            /* m */
	mov	r14, r8             /* m0i */
	mov	r15, rsi            /* a */

	/* Zero t[0..8].  dec-loop — `rep stosq` has a ~25-cycle startup
	 * for short counts, this runs in ~18. */
	xor	eax, eax
	push	9
	pop	rcx
	mov	rdi, rsp
1:	stosq
	dec	ecx
	jnz	1b

	/* r11 counts −32→0; `add r11,8; jnz` drops the cmp.  a[i] is
	 * then [r15+r11+32], disp8 (+1 byte), but net −2. */
	mov	r9, rsp
	push	-32
	pop	r11
.Lm:	mov	rdx, [r15+r11+32]
	mov	rsi, r10
	call	muladd4
	mov	rdx, [r9]
	imul	rdx, r14
	mov	rsi, r13
	call	muladd4
	add	r9, 8
	add	r11, 8
	jnz	.Lm
	/* r9 → t[4]; result at r9[0..3], carry at r9[4]. */

	mov	rdi, r12
	mov	rsi, r9
	mov	rdx, r13
	call	fe_sub_raw
	sub	eax, [r9+32]        /* borrow - carry: if ≠0, t < m → copy */
	jz	2f
	mov	rdi, r12
	mov	rsi, r9
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
	sub	QWORD PTR [rsp], 2

	mov	rdi, r12
	mov	rsi, r13
	call	fe_cpy

	xor	ebx, ebx
	mov	bl, 254
.Le:	mov	rdi, r12
	mov	rsi, rdi
	mov	rdx, rdi
	call	.Lfm
	bt	QWORD PTR [rsp], rbx
	jnc	.Lnx
	mov	rdi, r12
	mov	rsi, rdi
	mov	rdx, r13
	call	.Lfm
.Lnx:	dec	ebx
	jns	.Le

	add	rsp, 32
	pop	rbx
	jmp	.Lepi4

/* fe_from_be — cold (5 calls at setup). */
fe_from_be:
	push	4
	pop	rcx
1:	mov	rax, [rsi+rcx*8-8]
	bswap	rax
	stosq
	loop	1b
	ret

/* ======================================================================
 * BYTECODE INTERPRETER
 * ====================================================================== */
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
	mov	r14d, eax
	and	r14d, 0xF
	cmp	r14b, 0xF
	je	.Lbce
	shr	eax, 4

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
	/* FALLTHROUGH to Fmul */
.Lop0:
Fmul:	lea	rcx, [rip+cP]
	push	1
	pop	r8
	jmp	fe_mul_m
/* SQR bytecode now encodes s2=s1, so the decode loop has already
 * set rdx=rsi — SQR is just Fmul.  −5 bytes (old: mov rdx,rsi;jmp). */
.equ .Lop1, .Lop0
.Lop3:
Fsub:	lea	rcx, [rip+cP]
	jmp	fe_sub_m
.Lop2:
Fadd:	push	rdi
	push	rsi
	lea	rdi, [r12+3*32]
	lea	rsi, [rip+cP]
	call	fe_sub_raw
	lea	rdx, [r12+3*32]
	pop	rsi
	pop	rdi
	jmp	Fsub
.Lop5:
Nmul:	lea	rcx, [rip+cN]
	mov	r8, [rcx-8]
	jmp	fe_mul_m
.equ .Lop4, .Lop5

/* ----------------------------------------------------------------------
 * Helpers.
 * -------------------------------------------------------------------- */
cpy3:
	push	12
	pop	rcx
	rep	movsq
	ret

build_one:
	push	1
	pop	rax
	stosq
	xor	eax, eax
	push	3
	pop	rcx
	rep	stosq
	ret

/* cond_sub_n — r12=&cN. fe_geq preserves rdi. */
cond_sub_n:
	mov	rsi, r12
	call	fe_geq
	test	al, al
	jz	1f
	mov	rsi, rdi
	mov	rdx, r12
	jmp	fe_sub_raw
1:	ret

/* ---------------------------------------------------------------------- */
pt_add_acc:
	push	r14
	mov	r14, rdi

	lea	rdi, [r14+64]
	call	fe_iszero
	test	al, al
	jz	1f
	mov	rdi, r14
	lea	rsi, [r14+128]
	call	cpy3
	jmp	.Laa
1:	lea	rdi, [rip+bc_add1]
	call	bcrun_r14
	lea	rdi, [r14+96]
	call	fe_iszero
	test	al, al
	jz	3f
	lea	rdi, [r14+7*32]
	call	fe_iszero
	test	al, al
	jz	.Lai
	lea	rdi, [rip+bc_dbl]
	call	bcrun_r14
	jmp	.Laa
.Lai:	mov	rdi, r14
	xor	eax, eax
	push	12
	pop	rcx
	rep	stosq
	jmp	.Laa
3:	lea	rdi, [rip+bc_add2]
	call	bcrun_r14
.Laa:
	pop	r14
	ret

pt_mul:
	push	rbp
	push	rbx
	push	r13
	mov	rbx, rdi
	mov	rbp, rsi

	mov	rdi, rbx
	xor	eax, eax
	push	12
	pop	rcx
	rep	stosq

	mov	r13d, 255
.Lpm:	lea	rdi, [rip+bc_dbl]
	mov	rsi, rbx
	call	bc_run
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
 * ====================================================================== */
	.globl	tv_ecdsa_p256_verify_asm
	.type	tv_ecdsa_p256_verify_asm, @function

tv_ecdsa_p256_verify_asm:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp, 616

	mov	r14, rsp
	lea	rbp, [rsp+64]
	lea	r13, [rsp+12*32]

	mov	r12, rdi
	mov	rbx, r8
	mov	r8, rdx

	cmp	rsi, 64
	jne	.Lf
	cmp	rcx, 65
	jne	.Lf
	cmp	r9, 32
	jb	.Lf
	cmp	r9, 64
	jbe	1f
.Lf:	xor	eax, eax
.Ld:	add	rsp, 616
	jmp	.Lepi5
1:
	mov	rsi, r12
	lea	rdi, [r13+0]
	call	fe_from_be
	lea	rsi, [r12+32]
	lea	rdi, [r13+32]
	call	fe_from_be

	cmp	BYTE PTR [r8], 0x04
	jne	.Lf
	lea	rsi, [r8+1]
	lea	rdi, [rbp-64]
	call	fe_from_be
	lea	rsi, [r8+33]
	lea	rdi, [rbp-32]
	call	fe_from_be
	lea	r12, [rip+cN]

	lea	rdi, [r13-128]       /* slot 8 via r13: disp8 */
	mov	rsi, r12
	push	12
	pop	rcx
	rep	movsq
	lea	rdi, [r13+96]
	call	build_one

	lea	rdi, [rip+bc_v1]
	call	bcrun_r14
	test	eax, eax
	jnz	.Lf

	lea	rdi, [rbp-64]
	lea	rsi, [r13+32]
	mov	rdx, r12
	mov	rcx, [r12-8]
	call	fe_inv_m

	mov	rsi, rbx
	lea	rdi, [r13+32]
	call	fe_from_be
	lea	rdi, [r13+32]
	call	cond_sub_n
	lea	rbx, [r14+512]

	lea	rdi, [rip+bc_v2]
	call	bcrun_r14

	mov	rdi, r14
	lea	rsi, [r13+64]
	call	pt_mul
	mov	rdi, rbx
	mov	rsi, r14
	call	cpy3

	lea	rdi, [rbp+64]        /* slot 4 via rbp: disp8 */
	lea	rsi, [rip+cGXM]
	push	8
	pop	rcx
	rep	movsq
	mov	rdi, r14
	lea	rsi, [r13+32]
	call	pt_mul

	lea	rdi, [rbp+64]
	mov	rsi, rbx
	call	cpy3
	mov	rdi, r14
	call	pt_add_acc

	lea	rdi, [rbp+0]
	call	fe_iszero
	test	al, al
	jnz	.Lf

	lea	rbx, [r14+96]

	mov	rdi, rbx
	lea	rsi, [rbp+0]
	lea	rdx, [r12+32]
	push	1
	pop	rcx
	call	fe_inv_m

	lea	rdi, [rip+bc_v3]
	call	bcrun_r14

	mov	rdi, rbx
	call	cond_sub_n
	mov	rdi, rbx
	mov	rsi, rdi
	lea	rdx, [r13+0]
	call	fe_sub_raw
	mov	rdi, rbx
	call	fe_iszero
	jmp	.Ld

/* ======================================================================
 * Bytecode.  SQR ops (low nibble 1) now have s2=s1 so that the
 * decoder sets rdx=rsi, letting SQR dispatch directly to Fmul.
 * ====================================================================== */
	.section .rodata
	.p2align 3

/* bc_dbl: SQR ops with s2=s1.
 * Original 0x01,0xb2 (s1=2,s2=0) → 0x21,0xb2 (s1=2,s2=2) etc. */
bc_dbl:
	.byte 0x21,0xb2, 0x11,0x91, 0xb3,0x80, 0xb2,0xa0, 0xa0,0xa8
	.byte 0xa2,0x8a, 0xa2,0xa8, 0x22,0x81, 0x81,0x88, 0x93,0x88
	.byte 0xb3,0x28, 0x90,0xb0, 0xb2,0x8b, 0x82,0x88, 0x82,0xb8
	.byte 0xa1,0x0a, 0xb3,0x00, 0x03,0x88, 0x80,0x8a, 0x91,0x99
	.byte 0x92,0x99, 0x92,0x99, 0x92,0x99, 0x93,0x18, 0x0f,0x00

bc_add1:
	.byte 0x21,0xa2, 0x61,0xb6, 0xb0,0x80, 0xa0,0x34, 0x60,0x91
	.byte 0xb0,0x99, 0x20,0x75, 0xa0,0x77, 0x83,0x33, 0x93,0x77
	.byte 0x0f,0x00

bc_add2:
	.byte 0x60,0xa2, 0x30,0x2a, 0x31,0xa3, 0xa0,0xb3, 0xa0,0x88
	.byte 0xb0,0x99, 0x71,0x07, 0xb3,0x00, 0x82,0x38, 0x33,0x00
	.byte 0x03,0x38, 0x30,0x37, 0x93,0x13, 0x0f,0x00

bc_v1:
	.byte 0x07,0xc0, 0x06,0xc8, 0x07,0xd0, 0x06,0xd8
	.byte 0x06,0x09, 0x06,0x19, 0x09,0x40, 0x09,0x51
	.byte 0x09,0x6f, 0x51,0x05, 0x41,0x14, 0x40,0x11
	.byte 0x43,0x11, 0x43,0x11, 0x43,0x11, 0xa2,0x11
	.byte 0x13,0x00, 0x08,0x00, 0x0f,0x00

bc_v2:
	.byte 0x05,0xdd, 0xf5,0xdd, 0x05,0xec, 0xf5,0xee, 0x0f,0x00

bc_v3:
	.byte 0x31,0x33, 0x00,0x33, 0xf0,0x33, 0x0f,0x00

/* ---------------------------------------------------------------------- */
cN_M0I:	.quad 0xccd1c8aaee00bc4f

cN:	.quad 0xf3b9cac2fc632551, 0xbce6faada7179e84
	.quad 0xffffffffffffffff, 0xffffffff00000000
cP:	.quad 0xffffffffffffffff, 0x00000000ffffffff
	.quad 0x0000000000000000, 0xffffffff00000001
cBM:	.quad 0xd89cdf6229c4bddf, 0xacf005cd78843090
	.quad 0xe5a220abf7212ed6, 0xdc30061d04874834

cR2P:	.quad 0x0000000000000003, 0xfffffffbffffffff
	.quad 0xfffffffffffffffe, 0x00000004fffffffd
cGXM:	.quad 0x79e730d418a9143c, 0x75ba95fc5fedb601
	.quad 0x79fb732b77622510, 0x18905f76a53755c6
cGYM:	.quad 0xddf25357ce95560a, 0x8b4ab8e4ba19e45c
	.quad 0xd2e88688dd21f325, 0x8571ff1825885d85

	.section .note.GNU-stack,"",@progbits
