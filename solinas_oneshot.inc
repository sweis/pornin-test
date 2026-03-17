	/* ================================================================
	 * ONE-SHOT SOLINAS for mod-p.  Replaces the entire sliding-window
	 * reduce (14+ iterations, data-dependent branches) with ONE pass.
	 *
	 * FIPS 186-4 9-term formula, per-position accumulator in rax (64-bit
	 * signed), carry in rbp.  Final carry ∈ [−4,+5] — biased by adding
	 * 5p (all dwords fit imm8!) → carry ∈ [0,10], then per-window fold
	 * loop until zero.  Typical: 1-3 fold iterations post-bias.
	 *
	 * Branch-free through the 139-op body.  The old `test ebx;jz` was
	 * ~30% mispredict (q∈{0,1} per iteration is essentially random) —
	 * that's ~22K mispredicts × 15-20 cyc = ~350K cyc/verify GONE.
	 * ================================================================ */
	cmp	[rsp+80], r8
	jne	.Lrgen              /* mod-n → generic */

	/* --- 139-op accumulate-and-carry chain --- */
	xor	ebp, ebp
	mov	eax, [rsp+0]
	add	rax, rbp
	mov	edx, [rsp+32]
	add	rax, rdx
	mov	edx, [rsp+36]
	add	rax, rdx
	mov	edx, [rsp+44]
	sub	rax, rdx
	mov	edx, [rsp+48]
	sub	rax, rdx
	mov	edx, [rsp+52]
	sub	rax, rdx
	mov	edx, [rsp+56]
	sub	rax, rdx
	mov	[rsp+0], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+4]
	add	rax, rbp
	mov	edx, [rsp+36]
	add	rax, rdx
	mov	edx, [rsp+40]
	add	rax, rdx
	mov	edx, [rsp+48]
	sub	rax, rdx
	mov	edx, [rsp+52]
	sub	rax, rdx
	mov	edx, [rsp+56]
	sub	rax, rdx
	mov	edx, [rsp+60]
	sub	rax, rdx
	mov	[rsp+4], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+8]
	add	rax, rbp
	mov	edx, [rsp+40]
	add	rax, rdx
	mov	edx, [rsp+44]
	add	rax, rdx
	mov	edx, [rsp+52]
	sub	rax, rdx
	mov	edx, [rsp+56]
	sub	rax, rdx
	mov	edx, [rsp+60]
	sub	rax, rdx
	mov	[rsp+8], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+12]
	add	rax, rbp
	mov	edx, [rsp+32]
	sub	rax, rdx
	mov	edx, [rsp+36]
	sub	rax, rdx
	mov	edx, [rsp+44]
	add	rax, rdx
	add	rax, rdx
	mov	edx, [rsp+48]
	add	rax, rdx
	add	rax, rdx
	mov	edx, [rsp+52]
	add	rax, rdx
	mov	edx, [rsp+60]
	sub	rax, rdx
	mov	[rsp+12], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+16]
	add	rax, rbp
	mov	edx, [rsp+36]
	sub	rax, rdx
	mov	edx, [rsp+40]
	sub	rax, rdx
	mov	edx, [rsp+48]
	add	rax, rdx
	add	rax, rdx
	mov	edx, [rsp+52]
	add	rax, rdx
	add	rax, rdx
	mov	edx, [rsp+56]
	add	rax, rdx
	mov	[rsp+16], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+20]
	add	rax, rbp
	mov	edx, [rsp+40]
	sub	rax, rdx
	mov	edx, [rsp+44]
	sub	rax, rdx
	mov	edx, [rsp+52]
	add	rax, rdx
	add	rax, rdx
	mov	edx, [rsp+56]
	add	rax, rdx
	add	rax, rdx
	mov	edx, [rsp+60]
	add	rax, rdx
	mov	[rsp+20], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+24]
	add	rax, rbp
	mov	edx, [rsp+32]
	sub	rax, rdx
	mov	edx, [rsp+36]
	sub	rax, rdx
	mov	edx, [rsp+52]
	add	rax, rdx
	mov	edx, [rsp+56]
	add	rax, rdx
	add	rax, rdx
	add	rax, rdx
	mov	edx, [rsp+60]
	add	rax, rdx
	add	rax, rdx
	mov	[rsp+24], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+28]
	add	rax, rbp
	mov	edx, [rsp+32]
	add	rax, rdx
	mov	edx, [rsp+40]
	sub	rax, rdx
	mov	edx, [rsp+44]
	sub	rax, rdx
	mov	edx, [rsp+48]
	sub	rax, rdx
	mov	edx, [rsp+52]
	sub	rax, rdx
	mov	edx, [rsp+60]
	add	rax, rdx
	add	rax, rdx
	add	rax, rdx
	mov	[rsp+28], eax
	sar	rax, 32

	/* --- bias: add 5p, carry → eax+4+overflow ∈ [0,10] --- */
	/* 5p dwords: -5,-1,-1,4,0,0,5,-5,4 — all signed imm8 */
	add	DWORD PTR [rsp+0], -5
	adc	DWORD PTR [rsp+4], -1
	adc	DWORD PTR [rsp+8], -1
	adc	DWORD PTR [rsp+12], 4
	adc	DWORD PTR [rsp+16], 0
	adc	DWORD PTR [rsp+20], 0
	adc	DWORD PTR [rsp+24], 5
	adc	DWORD PTR [rsp+28], -5
	adc	eax, 4          /* eax = biased carry ≥ 0 */

	/* --- drain: per-window fold until eax = 0.  ≤10 iters. --- */
	mov	[rsp+32], eax
	lea	rdi, [rsp]          /* fold expects rdi = &t[0] */
.Lfix:	mov	ebx, [rsp+32]
	test	ebx, ebx
	jz	.Lrdone
	xor	eax, eax
	mov	[rsp+32], eax
	add	[rsp], ebx
	adc	[rsp+4], eax
	adc	[rsp+8], eax
	adc	[rsp+12], eax
	adc	[rsp+16], eax
	adc	[rsp+20], eax
	adc	[rsp+24], eax
	adc	[rsp+28], ebx
	adc	[rsp+32], eax
	sub	[rsp+12], ebx
	sbb	[rsp+16], eax
	sbb	[rsp+20], eax
	sbb	[rsp+24], ebx
	sbb	[rsp+28], eax
	sbb	[rsp+32], eax
	jmp	.Lfix
.Lrdone:
	jmp	.Lrskip             /* skip generic reduce */
.Lrgen:
