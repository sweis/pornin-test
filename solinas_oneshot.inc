	/* ================================================================
	 * LAZY-CARRY SOLINAS.  Phase 1: compute all 8 position accumulators
	 * INDEPENDENTLY (each = A[pos] + Σ coeff·A[8+i], 64-bit signed).
	 * Phase 2: single 8-step carry propagation.  Phase 1 parallelizes
	 * at IPC~4 (~14 cyc for 56 ops); only Phase 2 serializes (~16 cyc).
	 * vs current ~50 cyc (serial 8× sar+mov carry chain interleaved).
	 * ================================================================ */
	cmp	[rsp+80], r8
	jne	.Lrgen
	push	r12
	push	r13
	push	r15
	/* Stack shifted +24; t[] now at rsp+24, m at rsp+104, dst at rsp+96. */
	mov	edx, [rsp+72]
	mov	r9d, [rsp+76]
	mov	r10d, [rsp+80]
	mov	r11d, [rsp+84]

	/* Phase 1: 8 independent accumulators. */
	mov	ebp, [rsp+24]          /* A[0] zero-ext */
	mov	eax, [rsp+56]
	add	rbp, rax
	mov	eax, [rsp+60]
	add	rbp, rax
	mov	eax, [rsp+68]
	sub	rbp, rax
	sub	rbp, rdx
	sub	rbp, r9
	sub	rbp, r10
	mov	ebx, [rsp+28]          /* A[1] zero-ext */
	mov	eax, [rsp+60]
	add	rbx, rax
	mov	eax, [rsp+64]
	add	rbx, rax
	sub	rbx, rdx
	sub	rbx, r9
	sub	rbx, r10
	sub	rbx, r11
	mov	r12d, [rsp+32]          /* A[2] zero-ext */
	mov	eax, [rsp+64]
	add	r12, rax
	mov	eax, [rsp+68]
	add	r12, rax
	sub	r12, r9
	sub	r12, r10
	sub	r12, r11
	mov	r13d, [rsp+36]          /* A[3] zero-ext */
	mov	eax, [rsp+56]
	sub	r13, rax
	mov	eax, [rsp+60]
	sub	r13, rax
	mov	eax, [rsp+68]
	add	r13, rax
	add	r13, rax
	add	r13, rdx
	add	r13, rdx
	add	r13, r9
	sub	r13, r11
	mov	r15d, [rsp+40]          /* A[4] zero-ext */
	mov	eax, [rsp+60]
	sub	r15, rax
	mov	eax, [rsp+64]
	sub	r15, rax
	add	r15, rdx
	add	r15, rdx
	add	r15, r9
	add	r15, r9
	add	r15, r10
	mov	esi, [rsp+44]          /* A[5] zero-ext */
	mov	eax, [rsp+64]
	sub	rsi, rax
	mov	eax, [rsp+68]
	sub	rsi, rax
	add	rsi, r9
	add	rsi, r9
	add	rsi, r10
	add	rsi, r10
	add	rsi, r11
	mov	edi, [rsp+48]          /* A[6] zero-ext */
	mov	eax, [rsp+56]
	sub	rdi, rax
	mov	eax, [rsp+60]
	sub	rdi, rax
	add	rdi, r9
	add	rdi, r10
	add	rdi, r10
	add	rdi, r10
	add	rdi, r11
	add	rdi, r11
	mov	ecx, [rsp+52]          /* A[7] zero-ext */
	mov	eax, [rsp+56]
	add	rcx, rax
	mov	eax, [rsp+64]
	sub	rcx, rax
	mov	eax, [rsp+68]
	sub	rcx, rax
	sub	rcx, rdx
	sub	rcx, r9
	add	rcx, r11
	add	rcx, r11
	add	rcx, r11

	/* Phase 2: propagate carries.  acc[i] += carry; store low32; carry = hi32. */
	mov	[rsp+24], ebp
	sar	rbp, 32
	mov	rax, rbp
	add	rbx, rax
	mov	[rsp+28], ebx
	sar	rbx, 32
	mov	rax, rbx
	add	r12, rax
	mov	[rsp+32], r12d
	sar	r12, 32
	mov	rax, r12
	add	r13, rax
	mov	[rsp+36], r13d
	sar	r13, 32
	mov	rax, r13
	add	r15, rax
	mov	[rsp+40], r15d
	sar	r15, 32
	mov	rax, r15
	add	rsi, rax
	mov	[rsp+44], esi
	sar	rsi, 32
	mov	rax, rsi
	add	rdi, rax
	mov	[rsp+48], edi
	sar	rdi, 32
	mov	rax, rdi
	add	rcx, rax
	mov	[rsp+52], ecx
	sar	rcx, 32
	mov	rax, rcx

	/* Table correction + cond-sub (same as before). */
	add	eax, 4
	shl	eax, 5
	lea	rsi, [rip+carry_adjust_table]
	add	rsi, rax
	mov	rax, [rsi];    add [rsp+24], rax
	mov	rax, [rsi+8];  adc [rsp+32], rax
	mov	rax, [rsi+16]; adc [rsp+40], rax
	mov	rax, [rsi+24]; adc [rsp+48], rax
	sbb	rbp, rbp
	mov	r9,  [rsp+24]; sub r9,  [r8]
	mov	r10, [rsp+32]; sbb r10, [r8+8]
	mov	r11, [rsp+40]; sbb r11, [r8+16]
	mov	rax, [rsp+48]; sbb rax, [r8+24]
	sbb	rdx, rdx
	not	rbp
	and	rdx, rbp
	neg	rdx
	cmovc	r9,  [rsp+24]
	cmovc	r10, [rsp+32]
	cmovc	r11, [rsp+40]
	cmovc	rax, [rsp+48]
	mov	rdi, [rsp+96]       /* dst (shifted +24 from +72) */
	mov	[rdi], r9
	mov	[rdi+8], r10
	mov	[rdi+16], r11
	mov	[rdi+24], rax
	xor	ecx, ecx
	pop	r15
	pop	r13
	pop	r12
	add	rsp, 88
	pop	rbp
	pop	rbx
	ret
.Lrgen:
