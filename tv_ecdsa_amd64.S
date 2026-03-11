/* ======================================================================
 * ECDSA/P-256 signature verification — pure x86-64 assembly
 * ----------------------------------------------------------------------
 * SysV AMD64 ABI.  Public symbol:  tv_ecdsa_p256_verify_asm
 * Same contract as the C tv_ecdsa_p256_verify().
 *
 * Design:
 *   - 256-bit integers = 4 x uint64 (little-endian limbs).  Compared
 *     to the C version's 8 x uint32, every primitive is ~half the
 *     instructions, and `mulq` gives a free 128-bit product.
 *   - One generic Montgomery multiplier (CIOS, 4 iterations) used for
 *     both the field prime p and the curve order n.
 *   - m0i for p is 1, so the q = t[0]*m0i step costs nothing for
 *     field arithmetic.  (We still pass m0i as an argument so the
 *     same code handles n.)
 *   - Fermat inversion (a^(m-2)) for both p and n.
 *   - Jacobian point ops, a = -3 doubling, simple double-and-add.
 *   - All special cases in pt_add are handled (P=O, Q=O, P=Q, P=-Q).
 *
 * Rodata: 8 x 32-byte constants + two 8-byte m0i = 272 bytes.
 * ====================================================================== */

	.intel_syntax noprefix
	.text

/* ----------------------------------------------------------------------
 * Internal register / calling convention:
 *
 * All fe-operating helpers take fe pointers in rdi/rsi/rdx per the
 * SysV ABI so the wrapper functions below can fall through cheaply.
 *
 * Callee-saved used freely: rbx, rbp, r12..r15.  Every function that
 * clobbers them saves/restores via push/pop (1 byte each, the cheapest
 * prologue/epilogue on x86-64).
 * -------------------------------------------------------------------- */

/* ======================================================================
 * Field-element primitives (4 x uint64, little-endian limbs)
 * ====================================================================== */

/* fe_cpy(dst=rdi, src=rsi) : 4-limb copy.
 * Clobbers rax, rcx. */
fe_cpy:
	mov	ecx, 4
1:	mov	rax, [rsi]
	mov	[rdi], rax
	lea	rsi, [rsi+8]
	lea	rdi, [rdi+8]
	dec	ecx
	jnz	1b
	ret

/* fe_zero(dst=rdi) : zero 4 limbs.  Clobbers rax, rcx. */
fe_zero:
	xor	eax, eax
	mov	ecx, 4
1:	mov	[rdi], rax
	lea	rdi, [rdi+8]
	dec	ecx
	jnz	1b
	ret

/* fe_iszero(a=rdi) -> eax (1 if zero, else 0).  Clobbers rdx. */
fe_iszero:
	mov	rax, [rdi]
	or	rax, [rdi+8]
	or	rax, [rdi+16]
	or	rax, [rdi+24]
	sete	al
	movzx	eax, al
	ret

/* fe_sub_raw(dst=rdi, a=rsi, b=rdx) -> carry in eax (1 if borrow out).
 * Computes dst = a - b over 4 limbs.  Clobbers rcx. */
fe_sub_raw:
	mov	rax, [rsi]
	sub	rax, [rdx]
	mov	[rdi], rax
	mov	rax, [rsi+8]
	sbb	rax, [rdx+8]
	mov	[rdi+8], rax
	mov	rax, [rsi+16]
	sbb	rax, [rdx+16]
	mov	[rdi+16], rax
	mov	rax, [rsi+24]
	sbb	rax, [rdx+24]
	mov	[rdi+24], rax
	sbb	eax, eax            /* eax = 0 or -1 (borrow) */
	neg	eax                 /* 0 or 1 */
	ret

/* fe_add_raw(dst=rdi, a=rsi, b=rdx) : dst = a + b, carry-out discarded.
 * Clobbers rax. */
fe_add_raw:
	mov	rax, [rsi]
	add	rax, [rdx]
	mov	[rdi], rax
	mov	rax, [rsi+8]
	adc	rax, [rdx+8]
	mov	[rdi+8], rax
	mov	rax, [rsi+16]
	adc	rax, [rdx+16]
	mov	[rdi+16], rax
	mov	rax, [rsi+24]
	adc	rax, [rdx+24]
	mov	[rdi+24], rax
	ret

/* fe_geq(a=rdi, b=rsi) -> eax (1 if a >= b, else 0).
 * Pure compare — does not write memory.  Clobbers rdx, rcx. */
fe_geq:
	mov	rdx, [rdi+24]
	cmp	rdx, [rsi+24]
	jne	2f
	mov	rdx, [rdi+16]
	cmp	rdx, [rsi+16]
	jne	2f
	mov	rdx, [rdi+8]
	cmp	rdx, [rsi+8]
	jne	2f
	mov	rdx, [rdi]
	cmp	rdx, [rsi]
2:	setae	al                  /* CF=0 means a >= b for this limb */
	movzx	eax, al
	ret

/* fe_sub_m(dst=rdi, a=rsi, b=rdx, m=rcx) : dst = (a - b) mod m.
 * Requires a < m, b <= m.  Clobbers rax, rdx, rsi. */
fe_sub_m:
	push	rcx
	push	rdi
	call	fe_sub_raw          /* rdi = a - b, eax = borrow */
	pop	rdi
	pop	rdx
	test	eax, eax
	jz	1f
	/* Borrow: add m back.  rdi already = dst; set rsi = dst too. */
	mov	rsi, rdi
	jmp	fe_add_raw          /* tail-call */
1:	ret

/* ----------------------------------------------------------------------
 * muladd4 — one row of multiply-accumulate.
 *
 *   t[0..3] += x * y[0..3], carry propagated into t[4] and t[5].
 *
 * Args (custom internal convention):
 *   rbp = pointer to t (6-limb accumulator)
 *   rbx = scalar x
 *   rsi = pointer to y
 *   (rsi is advanced past y on return — no, keep it unmodified)
 *
 * Clobbers: rax, rdx, rcx, rdi.  Preserves rsi, rbx, rbp.
 * -------------------------------------------------------------------- */
muladd4:
	xor	ecx, ecx            /* carry-in = 0 */
	xor	edi, edi            /* limb index * 8 */
1:	mov	rax, rbx
	mul	QWORD PTR [rsi+rdi] /* rdx:rax = x * y[i] */
	add	rax, [rbp+rdi]
	adc	rdx, 0
	add	rax, rcx
	adc	rdx, 0
	mov	[rbp+rdi], rax
	mov	rcx, rdx            /* carry-out */
	add	rdi, 8
	cmp	rdi, 32
	jb	1b
	/* Propagate final carry into t[4] and (one bit) t[5]. */
	add	[rbp+32], rcx
	adc	QWORD PTR [rbp+40], 0
	ret

/* ----------------------------------------------------------------------
 * fe_mul_m — Montgomery multiplication (CIOS, 4 iterations).
 *
 *   r = a * b * R^{-1} mod m,   R = 2^256
 *
 * Args: rdi=r, rsi=a, rdx=b, rcx=m, r8=m0i
 * Returns: nothing
 * Stack: 48 bytes for the 6-limb accumulator t[0..5].
 *
 * Invariant: at end of each iteration t < m + b < 2m (so t[4] in {0,1}).
 * One conditional subtraction at the end yields the canonical result.
 * -------------------------------------------------------------------- */
fe_mul_m:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 56             /* t[6] + 8 bytes alignment */

	mov	r12, rdx            /* b */
	mov	r13, rcx            /* m */
	mov	r14, r8             /* m0i */
	mov	r15, rsi            /* a */
	/* rdi (r-dst) is caller's; stash it */
	mov	[rsp+48], rdi

	/* Zero accumulator. */
	lea	rdi, [rsp]
	xor	eax, eax
	mov	ecx, 6
1:	mov	[rdi], rax
	lea	rdi, [rdi+8]
	dec	ecx
	jnz	1b

	/* --- outer loop i = 0..3 --- */
	xor	r11d, r11d          /* i = 0 (limb offset, step 8) */
.Lmi:
	lea	rbp, [rsp]          /* t ptr for muladd4 */

	/* t += a[i] * b */
	mov	rbx, [r15 + r11]
	mov	rsi, r12
	call	muladd4

	/* q = t[0] * m0i  (mod 2^64) */
	mov	rbx, [rsp]
	imul	rbx, r14

	/* t += q * m  (clears t[0]) */
	mov	rsi, r13
	call	muladd4

	/* Shift t right by one limb (t[j] = t[j+1], j=0..4; t[5]=0). */
	xor	ecx, ecx
1:	mov	rax, [rsp + rcx + 8]
	mov	[rsp + rcx], rax
	add	ecx, 8
	cmp	ecx, 40
	jb	1b
	xor	eax, eax
	mov	[rsp+40], rax

	add	r11, 8
	cmp	r11, 32
	jb	.Lmi

	/* --- final conditional subtraction: if t >= m, t -= m --- */
	/* t is now in [rsp+0..31], t[4] in [rsp+32] is 0 or 1. */
	mov	rdi, [rsp+48]       /* r dst */
	lea	rsi, [rsp]          /* t */
	mov	rdx, r13            /* m */
	call	fe_sub_raw          /* r = t - m, eax = borrow */
	/* If t[4]==0 AND borrow, t < m: restore (copy t -> r). */
	mov	edx, [rsp+32]
	test	edx, edx
	jnz	2f                  /* t[4]==1 → t >= m → keep r = t-m */
	test	eax, eax
	jz	2f                  /* borrow==0 → t >= m → keep r */
	/* t < m: r = t */
	mov	rdi, [rsp+48]
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

/* ----------------------------------------------------------------------
 * fe_inv_m — Fermat inversion in Montgomery form.
 *
 *   r = a^(m-2) in Montgomery domain.
 *   input a: Montgomery form (a_real * R mod m)
 *   output r: Montgomery form ((a_real)^{-1} * R mod m)
 *
 * Args: rdi=r, rsi=a, rdx=m, rcx=m0i
 * Clobbers lots.
 * -------------------------------------------------------------------- */
fe_inv_m:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 72             /* e[4] @0, t[4] @32, pad */

	mov	r12, rdi            /* r (dst) */
	mov	r13, rsi            /* a */
	mov	r14, rdx            /* m */
	mov	r15, rcx            /* m0i */

	/* e = m - 2  (m is odd, m[0] > 2 so no borrow past limb 0) */
	lea	rdi, [rsp]
	mov	rsi, r14
	call	fe_cpy
	sub	QWORD PTR [rsp], 2

	/* Square-and-multiply, MSB-first.  Delay init until first 1 bit. */
	xor	ebx, ebx            /* started = 0 */
	mov	ebp, 255            /* bit index i */
.Lei:
	/* bit = (e[i>>6] >> (i & 63)) & 1 */
	mov	ecx, ebp
	shr	ecx, 6
	mov	rax, [rsp + rcx*8]  /* e[i>>6] */
	mov	ecx, ebp
	and	ecx, 63
	shr	rax, cl
	and	eax, 1              /* eax = bit */

	test	ebx, ebx
	jz	.Lnot_started

	/* t = t * t */
	push	rax                 /* save bit */
	lea	rdi, [rsp+40]       /* +8 for the push */
	mov	rsi, rdi
	mov	rdx, rdi
	mov	rcx, r14
	mov	r8, r15
	call	fe_mul_m
	pop	rax

	test	eax, eax
	jz	.Lnext
	/* t = t * a */
	lea	rdi, [rsp+32]
	mov	rsi, rdi
	mov	rdx, r13
	mov	rcx, r14
	mov	r8, r15
	call	fe_mul_m
	jmp	.Lnext

.Lnot_started:
	test	eax, eax
	jz	.Lnext
	/* First 1 bit: t = a, started = 1 */
	lea	rdi, [rsp+32]
	mov	rsi, r13
	call	fe_cpy
	mov	ebx, 1

.Lnext:
	dec	ebp
	jns	.Lei

	/* r = t */
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

/* ----------------------------------------------------------------------
 * fe_from_be(dst=rdi, src=rsi) : decode 32 BE bytes -> 4 LE limbs.
 * Clobbers rax, rcx.
 * -------------------------------------------------------------------- */
fe_from_be:
	mov	ecx, 4
1:	mov	rax, [rsi + rcx*8 - 8]   /* load from end backwards */
	bswap	rax
	mov	[rdi], rax
	lea	rdi, [rdi+8]
	dec	ecx
	jnz	1b
	ret

/* ======================================================================
 * Field-p wrappers.  Hard-code modulus to shrink every call site.
 * All take rdi=dst, rsi=a, [rdx=b] and tail-call / fall through.
 * ====================================================================== */

/* Fmul(r,a,b): fe_mul_m with m=P, m0i=1 */
Fmul:
	lea	rcx, [rip + cP]
	mov	r8d, 1              /* P_M0I = 1 */
	jmp	fe_mul_m

/* Fsqr(r,a): Fmul(r,a,a) */
Fsqr:
	mov	rdx, rsi
	jmp	Fmul

/* Fto_mont(r,a): fe_mul_m(r, a, R2P, P, 1) */
Fto_mont:
	lea	rdx, [rip + cR2P]
	jmp	Fmul

/* Fsub(r,a,b): fe_sub_m with m=P */
Fsub:
	lea	rcx, [rip + cP]
	jmp	fe_sub_m

/* Fadd(r,a,b) via negation: r = a - (P - b).  */
Fadd:
	push	rdi
	push	rsi
	sub	rsp, 40             /* tmp fe + align */
	/* tmp = P - b */
	lea	rdi, [rsp]
	lea	rsi, [rip + cP]
	/* rdx already = b */
	call	fe_sub_raw
	/* r = a - tmp  (mod P)
	 * Stack at this point: [rsp+0..31] tmp, [rsp+40] saved rsi=a,
	 * [rsp+48] saved rdi=r. */
	mov	rdx, rsp
	mov	rsi, [rsp+40]       /* a */
	mov	rdi, [rsp+48]       /* r */
	call	Fsub
	add	rsp, 40
	pop	rsi
	pop	rdi
	ret

/* In-place variants: rsi is set to rdi, saving one lea at each of
 * ~25 call sites in the point ops and verify.  Each wrapper is
 * 5 bytes (mov + jmp rel8); each converted call saves 4 bytes. */
Fsub_i:	mov	rsi, rdi
	jmp	Fsub
Fadd_i:	mov	rsi, rdi
	jmp	Fadd
Fmul_i:	mov	rsi, rdi
	jmp	Fmul
Fsqr_i:	mov	rsi, rdi
	jmp	Fsqr
/* Fdbl(r): r = 2*r.  Sets both rsi and rdx to rdi, saving two leas. */
Fdbl:	mov	rsi, rdi
	mov	rdx, rdi
	jmp	Fadd

/* ======================================================================
 * Point arithmetic (Jacobian, Montgomery form, mod p).
 * A jac point is laid out as 3 consecutive fe's: x @0, y @32, z @64.
 * Infinity is represented by z == 0.
 * ====================================================================== */

.equ JX, 0
.equ JY, 32
.equ JZ, 64
.equ JSZ, 96

/* pt_cpy(dst=rdi, src=rsi) : copy 96 bytes. */
pt_cpy:
	mov	ecx, 12
1:	mov	rax, [rsi]
	mov	[rdi], rax
	lea	rsi, [rsi+8]
	lea	rdi, [rdi+8]
	dec	ecx
	jnz	1b
	ret

/* pt_set_inf(p=rdi) : zero 96 bytes. */
pt_set_inf:
	xor	eax, eax
	mov	ecx, 12
1:	mov	[rdi], rax
	lea	rdi, [rdi+8]
	dec	ecx
	jnz	1b
	ret

/* ----------------------------------------------------------------------
 * pt_dbl(r=rdi, p=rsi) : Jacobian doubling, a = -3.
 *
 * Formula (EFD dbl-2001-b / "dbl-2007-bl" a=-3):
 *   delta = Z^2
 *   gamma = Y^2
 *   beta  = X*gamma
 *   alpha = 3*(X-delta)*(X+delta)
 *   X3 = alpha^2 - 8*beta
 *   Z3 = (Y+Z)^2 - gamma - delta
 *   Y3 = alpha*(4*beta - X3) - 8*gamma^2
 *
 * Stack layout (5 fe = 160 bytes):
 *   off  0: gamma
 *   off 32: beta
 *   off 64: alpha
 *   off 96: t1
 *  off 128: t2  (also used for delta)
 * -------------------------------------------------------------------- */
pt_dbl:
	push	rbp
	push	rbx
	push	r14
	sub	rsp, 128            /* 4 fe locals — everything in disp8 */

	mov	rbx, rdi            /* r (output) */
	mov	rbp, rsi            /* p (input)  */
	mov	r14, rsp            /* base for locals: 4-byte leas */

	/* Reordered formula — compute beta AFTER Z3 so delta and beta
	 * can share a slot, bringing the frame down to 4 fe = 128 bytes
	 * (all disp8-addressable):
	 *   delta = Z^2
	 *   gamma = Y^2
	 *   alpha = 3*(X-delta)*(X+delta)
	 *   Z3    = (Y+Z)^2 - gamma - delta     <-- delta dead
	 *   beta  = X * gamma                   <-- reuses delta slot
	 *   X3    = alpha^2 - 8*beta
	 *   Y3    = alpha*(4*beta - X3) - 8*gamma^2
	 * This is safe even when r == p: r->z is written before we read
	 * p->x again, but p->x is not yet clobbered (r->x is written later).
	 */
	.equ DL_t1,    0       /* most-referenced -> lowest offset */
	.equ DL_gamma, 32
	.equ DL_alpha, 64
	.equ DL_delta, 96
	.equ DL_beta,  96      /* shares slot with delta */
	.equ DL_t2,    96      /* and with late-use t2 */

	/* delta = Z^2;  gamma = Y^2 */
	lea	rdi, [r14 + DL_delta]
	lea	rsi, [rbp + JZ]
	call	Fsqr
	lea	rdi, [r14 + DL_gamma]
	lea	rsi, [rbp + JY]
	call	Fsqr

	/* alpha = 3*(X-delta)*(X+delta) */
	lea	rdi, [r14 + DL_t1]
	lea	rsi, [rbp + JX]
	lea	rdx, [r14 + DL_delta]
	call	Fsub
	lea	rdi, [r14 + DL_alpha]
	lea	rsi, [rbp + JX]
	lea	rdx, [r14 + DL_delta]
	call	Fadd
	lea	rdi, [r14 + DL_alpha]
	lea	rdx, [r14 + DL_t1]
	call	Fmul_i              /* alpha *= t1 */
	lea	rdi, [r14 + DL_t1]
	lea	rsi, [r14 + DL_alpha]
	lea	rdx, [r14 + DL_alpha]
	call	Fadd                /* t1 = 2*alpha */
	lea	rdi, [r14 + DL_alpha]
	lea	rdx, [r14 + DL_t1]
	call	Fadd_i              /* alpha += t1 = 3*alpha */

	/* Z3 = (Y+Z)^2 - gamma - delta */
	lea	rdi, [r14 + DL_t1]
	lea	rsi, [rbp + JY]
	lea	rdx, [rbp + JZ]
	call	Fadd
	lea	rdi, [r14 + DL_t1]
	call	Fsqr_i
	lea	rdi, [r14 + DL_t1]
	lea	rdx, [r14 + DL_gamma]
	call	Fsub_i
	lea	rdi, [rbx + JZ]
	lea	rsi, [r14 + DL_t1]
	lea	rdx, [r14 + DL_delta]
	call	Fsub                /* delta slot now free */

	/* beta = X * gamma  (into delta's slot) */
	lea	rdi, [r14 + DL_beta]
	lea	rsi, [rbp + JX]
	lea	rdx, [r14 + DL_gamma]
	call	Fmul

	/* t1 = 4*beta; t2 = 8*beta */
	lea	rdi, [r14 + DL_t1]
	lea	rsi, [r14 + DL_beta]
	lea	rdx, [r14 + DL_beta]
	call	Fadd                /* t1 = 2*beta */
	lea	rdi, [r14 + DL_t1]
	call	Fdbl                /* t1 = 4*beta */
	lea	rdi, [r14 + DL_t2]
	lea	rsi, [r14 + DL_t1]
	lea	rdx, [r14 + DL_t1]
	call	Fadd                /* t2 = 8*beta */

	/* X3 = alpha^2 - 8*beta */
	lea	rdi, [rbx + JX]
	lea	rsi, [r14 + DL_alpha]
	call	Fsqr
	lea	rdi, [rbx + JX]
	lea	rdx, [r14 + DL_t2]
	call	Fsub_i

	/* Y3 = alpha*(4*beta - X3) - 8*gamma^2 */
	lea	rdi, [r14 + DL_t1]
	lea	rdx, [rbx + JX]
	call	Fsub_i
	lea	rdi, [r14 + DL_t1]
	lea	rdx, [r14 + DL_alpha]
	call	Fmul_i              /* t1 *= alpha */
	lea	rdi, [r14 + DL_gamma]
	call	Fsqr_i
	lea	rdi, [r14 + DL_gamma]
	call	Fdbl
	lea	rdi, [r14 + DL_gamma]
	call	Fdbl
	lea	rdi, [r14 + DL_gamma]
	call	Fdbl                /* gamma = 8*gamma^2 */
	lea	rdi, [rbx + JY]
	lea	rsi, [r14 + DL_t1]
	lea	rdx, [r14 + DL_gamma]
	call	Fsub

	add	rsp, 128
	pop	r14
	pop	rbx
	pop	rbp
	ret

/* ----------------------------------------------------------------------
 * pt_add(r=rdi, p=rsi, q=rdx) : Jacobian addition.
 * Handles P=O, Q=O, P=Q (doubles), P=-Q (returns O).
 *
 * Stack: 6 fe = 192 bytes.
 *   off   0: u1   (later: v)
 *   off  32: s1
 *   off  64: t0   (= h, later scratch)
 *   off  96: t1   (= rr)
 *   off 128: t2   (= hh, later scratch)
 *   off 160: t3   (= hhh)
 * -------------------------------------------------------------------- */
pt_add:
	push	rbp
	push	rbx
	push	r13
	push	r14
	push	r15
	sub	rsp, 192

	mov	rbx, rdi           /* r */
	mov	rbp, rsi           /* p */
	mov	r13, rdx           /* q */
	mov	r14, rsp           /* low-base: offsets 0..127 in disp8 */
	lea	r15, [rsp + 128]   /* high-base: offsets 128..191 via [r15+0..63] */

	/* Slot layout (6 fe = 192 bytes).  Most-referenced at low
	 * offsets so they fit in r14 disp8. */
	.equ AD_t0,  0       /* h, later scratch */
	.equ AD_t1,  32      /* rr */
	.equ AD_u1,  64      /* U1, later V */
	.equ AD_s1,  96      /* S1 */
	/* via r15 (each at disp8): */
	.equ AD_t2,  0       /* (= rsp+128) Z1^2 / HH */
	.equ AD_t3,  32      /* (= rsp+160) Z2^2 / HHH */

	/* If p.z == 0: r = q */
	lea	rdi, [rbp + JZ]
	call	fe_iszero
	test	eax, eax
	jz	1f
	mov	rdi, rbx
	mov	rsi, r13
	call	pt_cpy
	jmp	.Ladd_done
1:	/* If q.z == 0: r = p */
	lea	rdi, [r13 + JZ]
	call	fe_iszero
	test	eax, eax
	jz	2f
	mov	rdi, rbx
	mov	rsi, rbp
	call	pt_cpy
	jmp	.Ladd_done
2:
	/* t2 = Z1^2, t3 = Z2^2 */
	lea	rdi, [r15 + AD_t2]
	lea	rsi, [rbp + JZ]
	call	Fsqr
	lea	rdi, [r15 + AD_t3]
	lea	rsi, [r13 + JZ]
	call	Fsqr
	/* U1 = X1*Z2^2 */
	lea	rdi, [r14 + AD_u1]
	lea	rsi, [rbp + JX]
	lea	rdx, [r15 + AD_t3]
	call	Fmul
	/* t0 = U2 = X2*Z1^2 */
	lea	rdi, [r14 + AD_t0]
	lea	rsi, [r13 + JX]
	lea	rdx, [r15 + AD_t2]
	call	Fmul
	/* S1 = Y1*Z2*Z2^2 */
	lea	rdi, [r14 + AD_s1]
	lea	rsi, [rbp + JY]
	lea	rdx, [r13 + JZ]
	call	Fmul
	lea	rdi, [r14 + AD_s1]
	lea	rdx, [r15 + AD_t3]
	call	Fmul_i
	/* t1 = S2 = Y2*Z1*Z1^2 */
	lea	rdi, [r14 + AD_t1]
	lea	rsi, [r13 + JY]
	lea	rdx, [rbp + JZ]
	call	Fmul
	lea	rdi, [r14 + AD_t1]
	lea	rdx, [r15 + AD_t2]
	call	Fmul_i

	/* H = t0 - U1; Rr = t1 - S1 */
	lea	rdi, [r14 + AD_t0]
	lea	rdx, [r14 + AD_u1]
	call	Fsub_i
	lea	rdi, [r14 + AD_t1]
	lea	rdx, [r14 + AD_s1]
	call	Fsub_i

	/* H == 0? */
	lea	rdi, [r14 + AD_t0]
	call	fe_iszero
	test	eax, eax
	jz	3f
	lea	rdi, [r14 + AD_t1]
	call	fe_iszero
	test	eax, eax
	jz	.Ladd_inf
	mov	rdi, rbx
	mov	rsi, rbp
	call	pt_dbl
	jmp	.Ladd_done
.Ladd_inf:
	mov	rdi, rbx
	call	pt_set_inf
	jmp	.Ladd_done
3:
	/* Z3 = Z1*Z2*H */
	lea	rdi, [r15 + AD_t2]
	lea	rsi, [rbp + JZ]
	lea	rdx, [r13 + JZ]
	call	Fmul
	lea	rdi, [rbx + JZ]
	lea	rsi, [r15 + AD_t2]
	lea	rdx, [r14 + AD_t0]
	call	Fmul

	/* HH = H^2 -> t2;  HHH = H*HH -> t3;  V = U1*HH (into u1) */
	lea	rdi, [r15 + AD_t2]
	lea	rsi, [r14 + AD_t0]
	call	Fsqr
	lea	rdi, [r15 + AD_t3]
	lea	rsi, [r14 + AD_t0]
	lea	rdx, [r15 + AD_t2]
	call	Fmul
	lea	rdi, [r14 + AD_u1]
	lea	rdx, [r15 + AD_t2]
	call	Fmul_i

	/* X3 = Rr^2 - HHH - 2V */
	lea	rdi, [rbx + JX]
	lea	rsi, [r14 + AD_t1]
	call	Fsqr
	lea	rdi, [rbx + JX]
	lea	rdx, [r15 + AD_t3]
	call	Fsub_i
	lea	rdi, [r14 + AD_t0]
	lea	rsi, [r14 + AD_u1]
	lea	rdx, [r14 + AD_u1]
	call	Fadd
	lea	rdi, [rbx + JX]
	lea	rdx, [r14 + AD_t0]
	call	Fsub_i

	/* Y3 = Rr*(V - X3) - S1*HHH */
	lea	rdi, [r14 + AD_t0]
	lea	rsi, [r14 + AD_u1]
	lea	rdx, [rbx + JX]
	call	Fsub
	lea	rdi, [r14 + AD_t0]
	lea	rdx, [r14 + AD_t1]
	call	Fmul_i
	lea	rdi, [r14 + AD_s1]
	lea	rdx, [r15 + AD_t3]
	call	Fmul_i
	lea	rdi, [rbx + JY]
	lea	rsi, [r14 + AD_t0]
	lea	rdx, [r14 + AD_s1]
	call	Fsub

.Ladd_done:
	add	rsp, 192
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	pop	rbp
	ret

/* ----------------------------------------------------------------------
 * pt_mul(r=rdi, k=rsi, p=rdx) : R = k * P, double-and-add MSB-first.
 * k is a normal-form 4-limb scalar.  P is Jacobian/Mont.
 * -------------------------------------------------------------------- */
pt_mul:
	push	rbp
	push	rbx
	push	r12
	push	r13
	mov	rbx, rdi           /* r */
	mov	rbp, rsi           /* k */
	mov	r12, rdx           /* p */

	mov	rdi, rbx
	call	pt_set_inf

	mov	r13d, 255          /* bit index */
.Lpmi:
	mov	rdi, rbx
	mov	rsi, rbx
	call	pt_dbl

	/* bit = (k[i>>6] >> (i & 63)) & 1 */
	mov	ecx, r13d
	shr	ecx, 6
	mov	rax, [rbp + rcx*8]
	mov	ecx, r13d
	and	ecx, 63
	shr	rax, cl
	test	al, 1
	jz	1f
	mov	rdi, rbx
	mov	rsi, rbx
	mov	rdx, r12
	call	pt_add
1:
	dec	r13d
	jns	.Lpmi

	pop	r13
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* ======================================================================
 * Public entry point.
 *
 * int tv_ecdsa_p256_verify_asm(
 *     const void *sig,  size_t sig_len,    // rdi, rsi
 *     const void *pub,  size_t pub_len,    // rdx, rcx
 *     const void *hv,   size_t hv_len);    // r8, r9
 *
 * Stack frame layout (offsets from rsp after prologue):
 *     0: fe r     (32)
 *    32: fe s/e   (32)  — s first, then reused for e
 *    64: fe t0/w  (32)
 *    96: fe t1/u1 (32)
 *   128: fe t2/u2 (32)
 *   160: jac Q    (96)
 *   256: jac R1   (96)
 *   352: jac R2   (96)
 *   448: fe one   (32)  — scratch "1"
 *   480: saved sig ptr, pub ptr, hv ptr
 *   total stack: ~520 bytes
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
	sub	rsp, 456            /* 5 fe + 3 jac = 160+288 = 448, +8 align */

	/* ------------------------------------------------------------------
	 * Two base registers set into the MIDDLE of their regions so that
	 * every slot is reachable with a signed 8-bit displacement.  On
	 * x86-64, [rbp+disp8] and [r13+disp8] both encode in 4 bytes
	 * (no SIB byte, mandatory disp).  This shaves 3 bytes per lea
	 * versus disp32 and 1 byte versus [rsp+disp8].
	 *
	 *   rsp+  0 : t0/w       rbp-64
	 *   rsp+ 32 : t1/u1      rbp-32
	 *   rsp+ 64 : t2/u2      rbp+0
	 *   rsp+ 96 : r          rbp+32
	 *   rsp+128 : s/e        rbp+64     <- now disp8
	 *
	 *   rsp+160 : Q          r13-128    <- exact disp8 lower bound
	 *   rsp+256 : R1         r13-32
	 *   rsp+352 : R2         r13+64
	 *
	 *   rbx stashes the hv pointer for the mid-function hash decode;
	 *   rsi and rdi come in with sig and pub which we decode early.
	 * ---------------------------------------------------------------- */
	lea	rbp, [rsp + 64]
	lea	r13, [rsp + 288]

	/* Offsets relative to rbp (temps): */
	.equ V_t0,  -64
	.equ V_w,   -64
	.equ V_t1,  -32
	.equ V_u1,  -32
	.equ V_t2,    0
	.equ V_u2,    0
	.equ V_r,    32
	.equ V_s,    64
	.equ V_e,    64
	/* Offsets relative to r13 (points): */
	.equ Q_X,   -128
	.equ Q_Y,   -96
	.equ Q_Z,   -64
	.equ R1_,   -32
	.equ R2_,    64

	/* Stash input pointers.  sig in r12, pub in r14, hv in rbx.
	 * sig and pub are dead after the decode phase; hv is needed
	 * mid-function for the hash.  r15 stays free. */
	mov	r12, rdi            /* sig */
	mov	r14, rdx            /* pub */
	mov	rbx, r8             /* hv  */

	/* --- Length checks --- */
	xor	eax, eax
	cmp	rsi, 64
	jne	.Lfail
	cmp	rcx, 65
	jne	.Lfail
	cmp	r9, 32
	jb	.Lfail
	cmp	r9, 64
	ja	.Lfail

	/* --- Decode r, s; range-check --- */
	mov	rsi, r12
	lea	rdi, [rbp + V_r]
	call	fe_from_be
	lea	rsi, [r12 + 32]
	lea	rdi, [rbp + V_s]
	call	fe_from_be

	/* r in [1, n-1] */
	lea	rdi, [rbp + V_r]
	call	fe_iszero
	test	eax, eax
	jnz	.Lfail
	lea	rdi, [rbp + V_r]
	lea	rsi, [rip + cN]
	call	fe_geq
	test	eax, eax
	jnz	.Lfail
	/* s in [1, n-1] */
	lea	rdi, [rbp + V_s]
	call	fe_iszero
	test	eax, eax
	jnz	.Lfail
	lea	rdi, [rbp + V_s]
	lea	rsi, [rip + cN]
	call	fe_geq
	test	eax, eax
	jnz	.Lfail

	/* --- Decode public key --- */
	cmp	BYTE PTR [r14], 0x04
	jne	.Lfail
	lea	rsi, [r14 + 1]
	lea	rdi, [rbp + V_t0]
	call	fe_from_be
	lea	rsi, [r14 + 33]
	lea	rdi, [rbp + V_t1]
	call	fe_from_be

	/* coords < p */
	lea	rdi, [rbp + V_t0]
	lea	rsi, [rip + cP]
	call	fe_geq
	test	eax, eax
	jnz	.Lfail
	lea	rdi, [rbp + V_t1]
	lea	rsi, [rip + cP]
	call	fe_geq
	test	eax, eax
	jnz	.Lfail

	/* Q.x, Q.y = Montgomery form of qx, qy */
	lea	rdi, [r13 + Q_X]
	lea	rsi, [rbp + V_t0]
	call	Fto_mont
	lea	rdi, [r13 + Q_Y]
	lea	rsi, [rbp + V_t1]
	call	Fto_mont
	/* t2 = b in Mont (for curve-check) */
	lea	rdi, [rbp + V_t2]
	lea	rsi, [rip + cB]
	call	Fto_mont

	/* --- On-curve: y^2 == x^3 - 3x + b --- */
	lea	rdi, [rbp + V_t0]
	lea	rsi, [r13 + Q_Y]
	call	Fsqr
	lea	rdi, [rbp + V_t1]
	lea	rsi, [r13 + Q_X]
	call	Fsqr
	lea	rdi, [rbp + V_t1]
	lea	rdx, [r13 + Q_X]
	call	Fmul_i
	/* t1 -= 3*x */
	lea	rdi, [rbp + V_t1]
	lea	rdx, [r13 + Q_X]
	call	Fsub_i
	lea	rdi, [rbp + V_t1]
	lea	rdx, [r13 + Q_X]
	call	Fsub_i
	lea	rdi, [rbp + V_t1]
	lea	rdx, [r13 + Q_X]
	call	Fsub_i
	/* t1 += b; t0 -= t1 */
	lea	rdi, [rbp + V_t1]
	lea	rdx, [rbp + V_t2]
	call	Fadd_i
	lea	rdi, [rbp + V_t0]
	lea	rdx, [rbp + V_t1]
	call	Fsub_i
	lea	rdi, [rbp + V_t0]
	call	fe_iszero
	test	eax, eax
	jz	.Lfail

	/* Q.z = 1 in Mont.  Build "1" in t0 (dead now). */
	lea	rdi, [rbp + V_t0]
	call	fe_zero
	mov	QWORD PTR [rbp + V_t0], 1
	lea	rdi, [r13 + Q_Z]
	lea	rsi, [rbp + V_t0]
	call	Fto_mont

	/* --- Compute u1, u2 mod n --- */
	lea	rdi, [rbp + V_w]
	lea	rsi, [rbp + V_s]
	lea	rdx, [rip + cR2N]
	lea	rcx, [rip + cN]
	mov	r8, [rip + cN_M0I]
	call	fe_mul_m
	lea	rdi, [rbp + V_w]
	lea	rsi, [rbp + V_w]
	lea	rdx, [rip + cN]
	mov	rcx, [rip + cN_M0I]
	call	fe_inv_m

	/* e = hash (first 32 bytes); reduce once if >= n */
	mov	rsi, rbx
	lea	rdi, [rbp + V_e]
	call	fe_from_be
	lea	rdi, [rbp + V_e]
	lea	rsi, [rip + cN]
	call	fe_geq
	test	eax, eax
	jz	1f
	lea	rdi, [rbp + V_e]
	lea	rsi, [rbp + V_e]
	lea	rdx, [rip + cN]
	call	fe_sub_raw
1:
	/* u1 = e * w mod n; u2 = r * w mod n (normal-form output) */
	lea	rdi, [rbp + V_u1]
	lea	rsi, [rbp + V_e]
	lea	rdx, [rbp + V_w]
	lea	rcx, [rip + cN]
	mov	r8, [rip + cN_M0I]
	call	fe_mul_m
	lea	rdi, [rbp + V_u2]
	lea	rsi, [rbp + V_r]
	lea	rdx, [rbp + V_w]
	lea	rcx, [rip + cN]
	mov	r8, [rip + cN_M0I]
	call	fe_mul_m

	/* --- Scalar mults --- */
	lea	rdi, [r13 + R2_]
	lea	rsi, [rbp + V_u2]
	lea	rdx, [r13 + Q_X]
	call	pt_mul
	/* Q <- G */
	lea	rdi, [r13 + Q_X]
	lea	rsi, [rip + cGX]
	call	Fto_mont
	lea	rdi, [r13 + Q_Y]
	lea	rsi, [rip + cGY]
	call	Fto_mont
	lea	rdi, [r13 + R1_]
	lea	rsi, [rbp + V_u1]
	lea	rdx, [r13 + Q_X]
	call	pt_mul

	lea	rdi, [r13 + R1_]
	lea	rsi, [r13 + R1_]
	lea	rdx, [r13 + R2_]
	call	pt_add

	lea	rdi, [r13 + R1_ + JZ]
	call	fe_iszero
	test	eax, eax
	jnz	.Lfail

	/* --- Extract affine x, compare with r --- */
	lea	rdi, [rbp + V_t1]
	lea	rsi, [r13 + R1_ + JZ]
	lea	rdx, [rip + cP]
	mov	ecx, 1
	call	fe_inv_m
	lea	rdi, [rbp + V_t1]
	call	Fsqr_i
	lea	rdi, [rbp + V_t1]
	lea	rdx, [r13 + R1_ + JX]
	call	Fmul_i
	/* Out of Mont: t1 *= 1 (build "1" in t2, dead) */
	lea	rdi, [rbp + V_t2]
	call	fe_zero
	mov	QWORD PTR [rbp + V_t2], 1
	lea	rdi, [rbp + V_t1]
	lea	rdx, [rbp + V_t2]
	call	Fmul_i              /* Fmul supplies P, P_M0I=1 */

	/* Reduce mod n: if t1 >= n, t1 -= n */
	lea	rdi, [rbp + V_t1]
	lea	rsi, [rip + cN]
	call	fe_geq
	test	eax, eax
	jz	2f
	lea	rdi, [rbp + V_t1]
	lea	rsi, [rbp + V_t1]
	lea	rdx, [rip + cN]
	call	fe_sub_raw
2:
	/* Compare t1 with r */
	lea	rdi, [rbp + V_t1]
	lea	rsi, [rbp + V_t1]
	lea	rdx, [rbp + V_r]
	call	fe_sub_raw
	lea	rdi, [rbp + V_t1]
	call	fe_iszero              /* eax = 1 if equal */
	jmp	.Ldone

.Lfail:
	xor	eax, eax
.Ldone:
	add	rsp, 456
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* ======================================================================
 * Read-only constants.
 * ====================================================================== */
	.section .rodata
	.p2align 5

cP:	.quad 0xffffffffffffffff
	.quad 0x00000000ffffffff
	.quad 0x0000000000000000
	.quad 0xffffffff00000001

cN:	.quad 0xf3b9cac2fc632551
	.quad 0xbce6faada7179e84
	.quad 0xffffffffffffffff
	.quad 0xffffffff00000000

cB:	.quad 0x3bce3c3e27d2604b
	.quad 0x651d06b0cc53b0f6
	.quad 0xb3ebbd55769886bc
	.quad 0x5ac635d8aa3a93e7

cGX:	.quad 0xf4a13945d898c296
	.quad 0x77037d812deb33a0
	.quad 0xf8bce6e563a440f2
	.quad 0x6b17d1f2e12c4247

cGY:	.quad 0xcbb6406837bf51f5
	.quad 0x2bce33576b315ece
	.quad 0x8ee7eb4a7c0f9e16
	.quad 0x4fe342e2fe1a7f9b

cR2P:	.quad 0x0000000000000003
	.quad 0xfffffffbffffffff
	.quad 0xfffffffffffffffe
	.quad 0x00000004fffffffd

cR2N:	.quad 0x83244c95be79eea2
	.quad 0x4699799c49bd6fa6
	.quad 0x2845b2392b6bec59
	.quad 0x66e12d94f3d95620

cN_M0I:	.quad 0xccd1c8aaee00bc4f

	.section .note.GNU-stack,"",@progbits
