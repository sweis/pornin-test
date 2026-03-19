/* 5×54 signed-limb Montgomery multiply. R = 2^270.
 * Output ≡ a·b·R⁻¹ (mod m). SOS: full schoolbook → reduce.
 *
 * Ranges (range_proof.py, K=5 W=54):
 *   input limbs: |limb| ≤ 2^59 (canonical 54 + RCB ×12 growth)
 *   products:    |prod| ≤ 2^118 (signed)
 *   accumulator: 128-bit, peak ~2^119 (signed — fits with 8 bits spare)
 *   output val:  ~4m (top limb signed, limbs 0..3 in [0, 2^54))
 *
 * p m0inv = 1 (low 54 bits of p are all-ones → −p⁻¹ ≡ 1 mod 2^54).
 * n m0inv = 0x11c8aaee00bc4f (doesn't fit imm32 — movabs or r11 preload).
 *
 * API: fe_mul5(rdi=dst, rsi=a, rdx=b, rcx=m)
 *   r11 = m0inv (preloaded by caller: 1 for p, 0x11c8aaee00bc4f for n)
 *   r13 = MASK  (preloaded, preserved — 0x3fffffffffffff)
 * Preserves: rbx, rbp, r12, r13, r14, r15 (SysV + r13 invariant).
 * Restores rcx on exit (INV's 384 calls rely on stable &m).
 */

	.intel_syntax noprefix
	.text

	.equ	W,   54
	.equ	K,   5
	.equ	ACC_QW, 2*K*2      /* 10 slots × 2 qwords = 20 */

.globl fe_mul5
fe_mul5:
	push	rbx
	push	r12
	mov	r12, rdx           /* b — before rdx clobbered */
	push	rdi                /* dst */
	push	rcx                /* m */
	enter	ACC_QW*8, 0        /* 160 B — 128-bit × 10 accumulator */

	/* Zero accumulator. */
	xor	eax, eax
	push	rsp
	pop	rdi
	lea	ecx, [rax + ACC_QW]
	rep	stosq              /* leaves rcx = 0 */

	/* rsi = a (entry value, untouched). Walk a[i] via negative offset
	 * from end, same trick as limb11 for a tight i-loop. */
	lea	r8, [rsi + K*8]    /* a + K*8 */

	/* ── Schoolbook: acc[i+j] += a[i] * b[j] ── */
	push	-K*8
	pop	r9                 /* r9 = i*8 − K*8, counts to 0 */
.Lsb:
	mov	rbx, [r8 + r9]     /* a[i] */
	lea	rdi, [rbp + r9*2 - K*16]   /* &acc[i] (16 B stride) */
	mov	rsi, r12           /* b */
	mov	cl, K              /* rcx = 0 from rep stosq / loop exit */
	call	.Lin
	add	r9, 8
	jnz	.Lsb
	/* rcx = 0 again. */

	/* ── Reduce: q = (acc[i].lo * m0inv) & MASK; acc += q*m ── */
	mov	r8, [rbp + 8]      /* m (saved above frame: rbp+8) */
	lea	r9, [rbp - ACC_QW*8]   /* &acc[0] */
	mov	cl, K
.Lrd:
	push	rcx
	mov	rbx, [r9]          /* acc[i].lo */
	imul	rbx, r11           /* * m0inv (low 64 → low 54 OK) */
	and	rbx, r13           /* q */
	mov	rdi, r9
	mov	rsi, r8
	mov	cl, K              /* rcx.hi was set from push/pop — zero it */
	xor	ecx, ecx
	mov	cl, K
	call	.Lin

	/* acc[i] low 54 bits now 0. Carry acc[i]>>54 into acc[i+1]. */
	mov	rax, [r9]
	mov	rdx, [r9 + 8]
	shrd	rax, rdx, W        /* bits 54..117 of 128-bit acc */
	sar	rdx, W             /* bits 118+ (signed) */
	add	[r9 + 16], rax
	adc	[r9 + 24], rdx

	lea	r9, [r9 + 16]
	pop	rcx
	loop	.Lrd
	/* r9 now at &acc[K]. rcx = 0. */

	/* ── Final carry-prop: acc[K..2K-1] → dst[0..K-1] ──
	 * 128-bit carry through the chain. Last limb absorbs residual
	 * (no mask, signed). Running 128-bit carry in r10:rax. */
	mov	rdi, [rbp + 16]    /* dst */
	xor	eax, eax           /* carry.lo */
	xor	r10d, r10d         /* carry.hi */
	mov	cl, K-1
.Lcp:
	add	rax, [r9]
	adc	r10, [r9 + 8]      /* r10:rax = acc[K+k] + carry */
	mov	rdx, rax
	and	rdx, r13           /* low 54 → output limb */
	mov	[rdi], rdx
	shrd	rax, r10, W        /* new carry.lo */
	sar	r10, W             /* new carry.hi */
	lea	r9, [r9 + 16]
	scasq
	loop	.Lcp
	/* Last limb: value + carry.lo, no mask. carry.hi provably fits
	 * (max output value ~4m < 2^258; after 4 carry shifts, carry ≪ 2^64). */
	add	rax, [r9]
	stosq

	leave
	pop	rcx                /* restore m — INV relies on this */
	pop	rax                /* discard dst */
	pop	r12
	pop	rbx
	ret

/* ── Inner loop: K iterations of acc += rbx * operand. ──
 * rdi → acc (128-bit slots, +16 stride). rsi → operand (+8).
 * rbx = scalar. rcx = count. Clobbers rax, rdx, rsi, rdi, rcx. */
.Lin:
	lodsq
	imul	rbx                /* rdx:rax = signed 128-bit product */
	add	[rdi], rax
	adc	[rdi+8], rdx
	lea	rdi, [rdi+16]
	loop	.Lin
	ret

.globl fe_mul5_end
fe_mul5_end:

/* ── Test shim: preloads r13 = MASK, r11 = m0inv. ──
 * C signature: fe_mul5_shim(dst, a, b, m, m0inv) */
.globl fe_mul5_shim
fe_mul5_shim:
	push	r13
	movabs	r13, (1<<W)-1
	mov	r11, r8            /* m0inv (5th arg) */
	call	fe_mul5
	pop	r13
	ret
