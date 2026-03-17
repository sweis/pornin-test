	/* ONE-SHOT SOLINAS — FULL HOIST (all 8 high dwords in regs).
	 * Zero loads inside position bodies.  rax=acc, rbp=carry.
	 * A[8..15] in rbx,rsi,rdi,rcx,rdx,r9,r10,r11. */
	cmp	[rsp+80], r8
	jne	.Lrgen
	mov	ebx, [rsp+32]
	mov	esi, [rsp+36]
	mov	edi, [rsp+40]
	mov	ecx, [rsp+44]
	mov	edx, [rsp+48]
	mov	r9d, [rsp+52]
	mov	r10d, [rsp+56]
	mov	r11d, [rsp+60]
	xor	ebp, ebp
	mov	eax, [rsp+0]
	add	rax, rbp
	add	rax, rbx
	add	rax, rsi
	sub	rax, rcx
	sub	rax, rdx
	sub	rax, r9
	sub	rax, r10
	mov	[rsp+0], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+4]
	add	rax, rbp
	add	rax, rsi
	add	rax, rdi
	sub	rax, rdx
	sub	rax, r9
	sub	rax, r10
	sub	rax, r11
	mov	[rsp+4], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+8]
	add	rax, rbp
	add	rax, rdi
	add	rax, rcx
	sub	rax, r9
	sub	rax, r10
	sub	rax, r11
	mov	[rsp+8], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+12]
	add	rax, rbp
	sub	rax, rbx
	sub	rax, rsi
	add	rax, rcx
	add	rax, rcx
	add	rax, rdx
	add	rax, rdx
	add	rax, r9
	sub	rax, r11
	mov	[rsp+12], eax
	sar	rax, 32
	mov	rbp, rax
	mov	eax, [rsp+16]
	add	rax, rbp
	sub	rax, rsi
	sub	rax, rdi
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
	sub	rax, rdi
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
	sub	rax, rbx
	sub	rax, rsi
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
	add	rax, rbx
	sub	rax, rdi
	sub	rax, rcx
	sub	rax, rdx
	sub	rax, r9
	add	rax, r11
	add	rax, r11
	add	rax, r11
	mov	[rsp+28], eax
	sar	rax, 32

	/* Table-lookup correction. */
	add	eax, 4
	shl	eax, 5
	lea	rsi, [rip+carry_adjust_table]
	add	rsi, rax
	mov	rax, [rsi];    add [rsp], rax
	mov	rax, [rsi+8];  adc [rsp+8], rax
	mov	rax, [rsi+16]; adc [rsp+16], rax
	mov	rax, [rsi+24]; adc [rsp+24], rax
	sbb	rbp, rbp
	mov	r9,  [rsp];    sub r9,  [r8]
	mov	r10, [rsp+8];  sbb r10, [r8+8]
	mov	r11, [rsp+16]; sbb r11, [r8+16]
	mov	rax, [rsp+24]; sbb rax, [r8+24]
	sbb	rdx, rdx
	not	rbp
	and	rdx, rbp
	neg	rdx
	cmovc	r9,  [rsp]
	cmovc	r10, [rsp+8]
	cmovc	r11, [rsp+16]
	cmovc	rax, [rsp+24]
	mov	rdi, [rsp+72]
	mov	[rdi], r9
	mov	[rdi+8], r10
	mov	[rdi+16], r11
	mov	[rdi+24], rax
	xor	ecx, ecx
	add	rsp, 88
	pop	rbp
	pop	rbx
	ret
.Lrgen:
