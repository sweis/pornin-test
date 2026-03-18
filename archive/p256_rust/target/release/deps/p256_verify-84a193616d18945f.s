	.file	"p256_verify.5a544926527648a2-cgu.0"
	.section	.text._RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe13from_be_bytes,"ax",@progbits
	.globl	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe13from_be_bytes
	.p2align	4
	.type	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe13from_be_bytes,@function
_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe13from_be_bytes:
	.cfi_startproc
	movq	24(%rsi), %rcx
	bswapq	%rcx
	movq	16(%rsi), %rdx
	bswapq	%rdx
	movq	%rdi, %rax
	movq	8(%rsi), %rdi
	bswapq	%rdi
	movq	(%rsi), %rsi
	bswapq	%rsi
	movq	%rcx, (%rax)
	movq	%rdx, 8(%rax)
	movq	%rdi, 16(%rax)
	movq	%rsi, 24(%rax)
	retq
.Lfunc_end0:
	.size	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe13from_be_bytes, .Lfunc_end0-_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe13from_be_bytes
	.cfi_endproc

	.section	.text._RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe2lt,"ax",@progbits
	.globl	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe2lt
	.p2align	4
	.type	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe2lt,@function
_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe2lt:
	.cfi_startproc
	movq	24(%rdi), %rax
	movq	24(%rsi), %rcx
	cmpq	%rcx, %rax
	jne	.LBB1_5
	movq	16(%rdi), %rax
	movq	16(%rsi), %rcx
	cmpq	%rcx, %rax
	jne	.LBB1_5
	movq	8(%rdi), %rax
	movq	8(%rsi), %rcx
	cmpq	%rcx, %rax
	jne	.LBB1_5
	movq	(%rdi), %rax
	movq	(%rsi), %rcx
	cmpq	%rcx, %rax
	jne	.LBB1_5
	xorl	%eax, %eax
	retq
.LBB1_5:
	cmpq	%rcx, %rax
	setb	%al
	retq
.Lfunc_end1:
	.size	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe2lt, .Lfunc_end1-_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe2lt
	.cfi_endproc

	.section	.text._RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe3sqr,"ax",@progbits
	.globl	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe3sqr
	.p2align	4
	.type	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe3sqr,@function
_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe3sqr:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	(%rsi), %r8
	movq	8(%rsi), %r14
	movq	%r8, %rax
	mulq	%r8
	movq	%rdx, -48(%rsp)
	movq	%rax, -8(%rsp)
	movq	%r14, %rax
	mulq	%r8
	movq	%rax, %rcx
	movq	%rdx, %r15
	movq	16(%rsi), %r11
	movq	%r11, %rax
	mulq	%r8
	movq	%rdx, %rbp
	movq	%rax, %r13
	movq	%rax, -40(%rsp)
	movq	%r14, %rax
	mulq	%r14
	movq	%rax, -24(%rsp)
	movq	%rdx, %r9
	movq	24(%rsi), %r10
	movq	%r10, %rax
	mulq	%r8
	movq	%rdx, %rbx
	movq	%rdx, -16(%rsp)
	movq	%rax, %r8
	movq	%rax, -32(%rsp)
	movq	%r10, %rax
	mulq	%r14
	movq	%rax, %rsi
	movq	%rdx, %r12
	movq	-48(%rsp), %rax
	addq	%rcx, %rax
	movq	%r13, %rdx
	movq	%r15, %r13
	adcq	%r15, %rdx
	movq	%r8, %r15
	adcq	%rbp, %r15
	movq	%rsi, %r8
	adcq	%rbx, %r8
	movq	%r12, %rbx
	adcq	$0, %rbx
	addq	-24(%rsp), %rdx
	adcq	$0, %r9
	addq	%rcx, %rax
	movq	%rax, -48(%rsp)
	adcq	%r13, %rdx
	movq	%rdx, %r13
	adcq	$0, %r9
	movq	%r11, %rax
	mulq	%r14
	movq	%rdx, %rcx
	addq	%rax, %r15
	movq	%rdx, %r14
	adcq	$0, %r14
	addq	%r9, %r15
	adcq	$0, %r14
	addq	-40(%rsp), %r13
	adcq	%rbp, %rax
	adcq	$0, %rcx
	addq	%r15, %rax
	movq	%rax, %r15
	adcq	$0, %rcx
	addq	%r8, %r14
	adcq	$0, %rbx
	movq	%r11, %rax
	mulq	%r11
	movq	%rdx, %r9
	addq	%r14, %rax
	adcq	$0, %r9
	addq	%rcx, %rax
	adcq	$0, %r9
	addq	-32(%rsp), %r15
	movq	%r15, -40(%rsp)
	adcq	-16(%rsp), %rsi
	adcq	$0, %r12
	addq	%rax, %rsi
	adcq	$0, %r12
	movq	%r10, %rax
	mulq	%r11
	movq	%rdx, %rcx
	addq	%rax, %rbx
	movq	%rdx, %r8
	adcq	$0, %r8
	addq	%r9, %rbx
	adcq	$0, %r8
	addq	%rax, %rbx
	adcq	$0, %rcx
	addq	%r12, %rbx
	adcq	$0, %rcx
	movq	%r10, %rax
	mulq	%r10
	addq	%r8, %rax
	adcq	$0, %rdx
	addq	%rcx, %rax
	adcq	$0, %rdx
	movl	%esi, %r8d
	movq	%r8, -32(%rsp)
	movl	%ebx, %ecx
	shrq	$32, %rbx
	movl	%r15d, %r11d
	shrq	$32, %rsi
	addq	%rsi, %r8
	subq	%r8, %r11
	movq	-48(%rsp), %r9
	shrq	$32, %r9
	subq	%r8, %r9
	movq	-8(%rsp), %r12
	movl	%r12d, %r10d
	addq	%r8, %r10
	movl	%eax, %r15d
	shrq	$32, %rax
	leaq	(%r9,%rbx,2), %r9
	leaq	(%rcx,%rbx), %r14
	addq	%r15, %rbx
	addq	%rax, %rbx
	movl	%edx, %ebp
	addq	%rbp, %rbx
	subq	%rbx, %r10
	addq	%rcx, %rsi
	movq	%rdx, %rbx
	shrq	$32, %rbx
	movq	%r12, %rcx
	shrq	$32, %rcx
	addq	%rsi, %rcx
	leaq	(%rax,%rbx), %rdx
	addq	%rbp, %rdx
	subq	%rdx, %rcx
	subq	%r15, %rcx
	movq	%r10, %r8
	sarq	$32, %r8
	addq	%r8, %rcx
	movl	-48(%rsp), %r12d
	addq	%r14, %r12
	subq	%rdx, %r12
	movq	%rcx, %rdx
	sarq	$32, %rdx
	addq	%rdx, %r12
	movq	%r12, %r8
	sarq	$32, %r8
	addq	%rax, %r9
	subq	%rbx, %r9
	leaq	(%r9,%r15,2), %rdx
	addq	%r8, %rdx
	movl	%r13d, %r8d
	subq	%rsi, %r8
	movq	%rdx, %rsi
	sarq	$32, %rsi
	leaq	(%r8,%r15,2), %r8
	leaq	(%r8,%rax,2), %r9
	addq	%rbp, %r9
	addq	%rsi, %r9
	shrq	$32, %r13
	subq	%r14, %r13
	movq	%r9, %rsi
	sarq	$32, %rsi
	addq	%rbx, %r13
	leaq	(,%rax,2), %r8
	addq	%r13, %r8
	leaq	(%r8,%rbp,2), %r8
	addq	%rsi, %r8
	leaq	(,%rbp,2), %rsi
	addq	%rbp, %rsi
	addq	%rax, %r11
	leaq	(%r11,%rbx,2), %r11
	addq	%rsi, %r11
	movq	%r8, %rsi
	sarq	$32, %rsi
	addq	%rsi, %r11
	movq	-40(%rsp), %rsi
	shrq	$32, %rsi
	addq	-32(%rsp), %rsi
	addq	%r15, %r14
	addq	%rax, %r14
	subq	%r14, %rsi
	movl	%r10d, %eax
	movl	%r12d, %r10d
	movl	%r9d, %r9d
	leaq	(%rbx,%rbx,2), %rbx
	addq	%rbx, %rsi
	movl	%r11d, %ebx
	sarq	$32, %r11
	addq	%r11, %rsi
	movq	%rsi, %r11
	shrq	$32, %r11
	addl	$4, %r11d
	shlq	$32, %rcx
	orq	%rax, %rcx
	shlq	$32, %rdx
	orq	%r10, %rdx
	shlq	$32, %r8
	orq	%r9, %r8
	shlq	$32, %rsi
	orq	%rbx, %rsi
	shlq	$5, %r11
	leaq	.Lanon.d570490c5cf842a63bbf96cc5ce2db76.0(%rip), %rax
	addq	(%r11,%rax), %rcx
	adcq	8(%r11,%rax), %rdx
	adcq	16(%r11,%rax), %r8
	adcq	24(%r11,%rax), %rsi
	setb	%r10b
	xorl	%eax, %eax
	cmpq	$-1, %rcx
	setne	%al
	movabsq	$-4294967296, %r11
	leaq	(%rdx,%r11), %r9
	incq	%r9
	movl	$4294967295, %ebx
	cmpq	%rbx, %rdx
	setb	%bpl
	subq	%rax, %r9
	setb	%al
	orb	%bpl, %al
	movzbl	%al, %r14d
	cmpq	%r11, %rsi
	seta	%r11b
	cmpq	%r14, %r8
	leaq	(%rsi,%rbx), %rbx
	sbbq	$0, %rbx
	movq	%rdi, %rax
	setae	%dil
	andb	%r11b, %dil
	orb	%r10b, %dil
	movzbl	%dil, %edi
	addq	%rdi, %rcx
	xorl	%r10d, %r10d
	testb	%dil, %dil
	cmoveq	%rdx, %r9
	cmovneq	%r14, %r10
	cmoveq	%rsi, %rbx
	subq	%r10, %r8
	movq	%rcx, (%rax)
	movq	%r9, 8(%rax)
	movq	%r8, 16(%rax)
	movq	%rbx, 24(%rax)
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end2:
	.size	_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe3sqr, .Lfunc_end2-_RNvMNtCs7KORJJ6Te6I_11p256_verify2feNtB2_2Fe3sqr
	.cfi_endproc

	.type	.Lanon.d570490c5cf842a63bbf96cc5ce2db76.0,@object
	.section	.rodata..Lanon.d570490c5cf842a63bbf96cc5ce2db76.0,"a",@progbits
	.p2align	3, 0x0
.Lanon.d570490c5cf842a63bbf96cc5ce2db76.0:
	.asciz	"\373\377\377\377\377\377\377\377\377\377\377\377\004\000\000\000\000\000\000\000\000\000\000\000\005\000\000\000\373\377\377\377\374\377\377\377\377\377\377\377\377\377\377\377\003\000\000\000\000\000\000\000\000\000\000\000\004\000\000\000\374\377\377\377\375\377\377\377\377\377\377\377\377\377\377\377\002\000\000\000\000\000\000\000\000\000\000\000\003\000\000\000\375\377\377\377\376\377\377\377\377\377\377\377\377\377\377\377\001\000\000\000\000\000\000\000\000\000\000\000\002\000\000\000\376\377\377\377\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001\000\000\000\000\000\000\000\000\000\000\000\377\377\377\377\377\377\377\377\377\377\377\377\376\377\377\377\000\000\000\000\002\000\000\000\000\000\000\000\000\000\000\000\376\377\377\377\377\377\377\377\377\377\377\377\375\377\377\377\001\000\000\000\003\000\000\000\000\000\000\000\000\000\000\000\375\377\377\377\377\377\377\377\377\377\377\377\374\377\377\377\002\000\000\000\004\000\000\000\000\000\000\000\000\000\000\000\374\377\377\377\377\377\377\377\377\377\377\377\373\377\377\377\003\000\000\000\005\000\000\000\000\000\000\000\000\000\000\000\373\377\377\377\377\377\377\377\377\377\377\377\372\377\377\377\004\000\000"
	.size	.Lanon.d570490c5cf842a63bbf96cc5ce2db76.0, 320

	.ident	"rustc version 1.94.0-nightly (1aa9bab4e 2025-12-05)"
	.section	".note.GNU-stack","",@progbits
