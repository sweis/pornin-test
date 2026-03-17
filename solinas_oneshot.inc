	/* ================================================================
	 * ONE-SHOT SOLINAS — register-hoisted.  A[13,14,15,11] appear in
	 * 6-7 positions each; load once into r9-r11,rcx (zero-extended).
	 * Saves ~21 loads.  rax=acc, rbp=carry, rdx=temp for A[8,9,10,12].
	 * ================================================================ */
	cmp	[rsp+80], r8
	jne	.Lrgen

	/* hoist hot dwords (32-bit load zero-extends to 64) */
	mov	ecx, [rsp+44]
	mov	r9d, [rsp+52]
	mov	r10d, [rsp+56]
	mov	r11d, [rsp+60]

	xor	ebp, ebp
	mov	eax, [rsp+0]
	add	rax, rbp
	mov	edx, [rsp+32]
	add	rax, rdx
	mov	edx, [rsp+36]
	add	rax, rdx
	sub	rax, rcx
	mov	edx, [rsp+48]
	sub	rax, rdx
	sub	rax, r9
	sub	rax, r10
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
	sub	rax, r9
	sub	rax, r10
	sub	rax, r11
	mov	[rsp+4], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+8]
	add	rax, rbp
	mov	edx, [rsp+40]
	add	rax, rdx
	add	rax, rcx
	sub	rax, r9
	sub	rax, r10
	sub	rax, r11
	mov	[rsp+8], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+12]
	add	rax, rbp
	mov	edx, [rsp+32]
	sub	rax, rdx
	mov	edx, [rsp+36]
	sub	rax, rdx
	add	rax, rcx
	add	rax, rcx
	mov	edx, [rsp+48]
	add	rax, rdx
	add	rax, rdx
	add	rax, r9
	sub	rax, r11
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
	add	rax, r9
	add	rax, r9
	add	rax, r10
	mov	[rsp+16], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+20]
	add	rax, rbp
	mov	edx, [rsp+40]
	sub	rax, rdx
	sub	rax, rcx
	add	rax, r9
	add	rax, r9
	add	rax, r10
	add	rax, r10
	add	rax, r11
	mov	[rsp+20], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+24]
	add	rax, rbp
	mov	edx, [rsp+32]
	sub	rax, rdx
	mov	edx, [rsp+36]
	sub	rax, rdx
	add	rax, r9
	add	rax, r10
	add	rax, r10
	add	rax, r10
	add	rax, r11
	add	rax, r11
	mov	[rsp+24], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+28]
	add	rax, rbp
	mov	edx, [rsp+32]
	add	rax, rdx
	mov	edx, [rsp+40]
	sub	rax, rdx
	sub	rax, rcx
	mov	edx, [rsp+48]
	sub	rax, rdx
	sub	rax, r9
	add	rax, r11
	add	rax, r11
	add	rax, r11
	mov	[rsp+28], eax
	sar	rax, 32

	/* bias: add 5p → carry nonneg */
	add	DWORD PTR [rsp+0], -5
	adc	DWORD PTR [rsp+4], -1
	adc	DWORD PTR [rsp+8], -1
	adc	DWORD PTR [rsp+12], 4
	adc	DWORD PTR [rsp+16], 0
	adc	DWORD PTR [rsp+20], 0
	adc	DWORD PTR [rsp+24], 5
	adc	DWORD PTR [rsp+28], -5
	adc	eax, 4

	/* drain */
	mov	[rsp+32], eax
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
	jmp	.Lrskip
.Lrgen:
