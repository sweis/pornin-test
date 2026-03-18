/* 11×24 Montgomery mod-p — v2, squeezed.
 *
 * v1 was 190 B. Cuts:
 *   - dead push/pop before the lea rcx: −3
 *   - m in r12, dst in r15 (not stack): 3×8B disp32 mov → 0. Net −20.
 *   - schoolbook outer: a-ptr in r8 (not rsi) so inner's lodsq
 *     doesn't clobber it. Drops push/pop rsi/rdi pair: −4.
 *   - zero-init via 22×push instead of rep stosq+sub rsp: the sub
 *     was 7B (imm32); 22 pushes = 22B but NO sub and NO rep stosq
 *     setup. Net: 22 vs (4+7+2+3) = 16. LOSES 6B. Revert — keep rep.
 *     BUT: cleanup becomes 22×pop (22B) vs add rsp,imm32 (7B).
 *     So pushes lose on BOTH ends. Keep rep stosq.
 *   - actually: sub rsp via `push rcx`×22 with rcx=0 (22B alloc+zero)
 *     vs lea+sub+push+pop+rep (16B alloc+zero). rep wins.
 *
 * Target: get under 143 B (current fe_mul_m).
 */

	.intel_syntax noprefix
	.text

	.equ	W,    24
	.equ	K,    11
	.equ	MASK, (1<<W)-1
	.equ	ACC,  2*K

.globl fe_mul11
fe_mul11:
	push	rbx
	push	rbp
	push	r12
	push	r15
	push	rdi
	pop	r15              /* dst */
	push	rcx
	pop	r12              /* m */
	push	rdx
	pop	rbp              /* b */
	push	rsi
	pop	r8               /* a */

	/* Zero 22-qword acc. rep stosq is tight despite sub-imm32:
	 * lea(4) + sub(7) + mov(3) + rep stosq(3) = 17 B, and we get
	 * rcx=0 out of it for free. 22×push rcx would be 22 B. */
	xor	eax, eax
	lea	ecx, [rax + ACC]
	sub	rsp, ACC*8
	mov	rdi, rsp
	rep	stosq
	/* rdi → past acc, rcx=0 */

/* ── Schoolbook ──
 * a-ptr walks via r8 (not rsi). b stays in rbp. acc-base in rsp. */
	push	-K*8
	pop	r9
.Lso:
	mov	rbx, [r8 + r9 + K*8]   /* a[i] — r8 is &a[0], r9 is i*8-K*8 */
	lea	rdi, [rsp + r9 + K*8]  /* acc[i] */
	mov	rsi, rbp
	mov	cl, K
	call	.Lin
	add	r9, 8
	jnz	.Lso

/* ── Reduce ──
 * rbp repurposed as acc walker. m from r12. */
	push	rsp
	pop	rbp
	mov	cl, K
.Lro:
	mov	eax, [rbp]       /* low 32 of acc[i] */
	and	eax, MASK        /* q — 5 B (eax special-case encoding) */
	push	rax
	pop	rbx
	push	rcx
	mov	rdi, rbp
	mov	rsi, r12
	mov	cl, K
	call	.Lin
	pop	rcx
	/* Carry acc[i]>>24 into acc[i+1]. Pure 64-bit. */
	mov	rax, [rbp]
	sar	rax, W
	add	[rbp+8], rax
	lea	rbp, [rbp+8]
	loop	.Lro

/* ── Carry-prop acc[K..2K-1] → dst ── */
	mov	rdi, r15
	mov	cl, K
	xor	edx, edx
	mov	rsi, rbp
.Lcp:
	lodsq
	add	rax, rdx
	mov	rdx, rax
	and	eax, MASK
	stosq
	sar	rdx, W
	loop	.Lcp
	shl	rdx, W           /* absorb final carry into top limb */
	add	[rdi-8], rdx

	add	rsp, ACC*8
	pop	r15
	pop	r12
	pop	rbp
	pop	rbx
	ret

.Lin:
	lodsq
	imul	rax, rbx
	add	[rdi], rax
	scasq
	loop	.Lin
	ret

.globl fe_mul11_end
fe_mul11_end:
