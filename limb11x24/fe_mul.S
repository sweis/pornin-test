/* 11×24 Montgomery mod-p — v5. 163 → ?
 *
 * v4 cuts:
 *   - .Lcnt helper: mov cl,K falls through to .Lin. −2 at call sites.
 *   - push rsi;pop rdi BEFORE lodsq in reduce (no lea back-up). −2.
 *   - last carry-prop iter unmasked outside loop. −1.
 *
 * rcx=0-on-entry: DEFERRED. Current tiny.S passes m in rcx; pushing
 * it leaves high bytes dirty. lea ecx,[rax+22] costs +1 over mov cl
 * but is self-contained. Revisit at integration when the dispatch
 * can zero rcx and pass m via r8.
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
	push	r12
	push	rdi              /* dst → [rbp+24] */
	push	rcx              /* m   → [rbp+16] */
	push	rdx              /* b   → [rbp+8]  */
	enter	ACC*8, 0

	/* Zero acc. rcx holds m-ptr on entry (pushed above); high bytes
	 * are junk, so lea not mov cl. rax=0 from xor is free. */
	xor	eax, eax
	lea	ecx, [rax + ACC]
	push	rsp
	pop	rdi
	rep	stosq            /* rcx=0 out */

	lea	r8, [rsi + K*8]
	mov	r12, [rbp + 8]   /* b */

/* ── Schoolbook ── */
	push	-K*8
	pop	r9
.Lso:
	mov	rbx, [r8 + r9]
	lea	rdi, [rbp + r9 - ACC*8 + K*8]
	mov	rsi, r12
	call	.Lcnt
	add	r9, 8
	jnz	.Lso

/* ── Reduce ── */
	push	rsp
	pop	rsi
	mov	r8, [rbp + 16]   /* m */
	mov	cl, K
.Lro:
	push	rsi
	pop	rdi              /* rdi = acc[i] BEFORE lodsq — no lea */
	lodsq                    /* rax = acc[i], rsi → acc[i+1] */
	and	eax, MASK
	push	rax
	pop	rbx
	push	rcx
	push	rsi
	mov	rsi, r8
	call	.Lcnt
	pop	rsi
	pop	rcx
	mov	rax, [rsi - 8]
	sar	rax, W
	add	[rsi], rax
	loop	.Lro
	/* rsi → acc[K]. */

/* ── Carry-prop. Last limb unmasked outside loop (value ≤ 2^258 means
 * top limb ≤ 2^18, so the final carry is already 0 — no shl+add). */
	mov	rdi, [rbp + 24]
	mov	cl, K-1
	xor	edx, edx
.Lcp:
	lodsq
	add	rax, rdx
	mov	rdx, rax
	and	eax, MASK
	stosq
	sar	rdx, W
	loop	.Lcp
	lodsq                    /* acc[2K-1] */
	add	rax, rdx         /* + final carry. No mask — full value. */
	stosq

	leave
	pop	rax
	pop	rax
	pop	rax
	pop	r12
	pop	rbx
	ret

/* ── .Lcnt: mov cl,K and fall through. Both call sites used to do
 * mov cl,K (2 B) + call .Lin (5 B) = 7 B each. Now just call .Lcnt
 * (5 B). Net −4 B over 2 sites, +2 B here = −2 B. ── */
.Lcnt:	mov	cl, K
.Lin:
	lodsq
	imul	rbx
	add	[rdi], rax
	scasq
	loop	.Lin
	ret

.globl fe_mul11_end
fe_mul11_end:
