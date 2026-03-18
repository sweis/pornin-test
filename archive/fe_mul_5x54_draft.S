/* Standalone 5×54-bit signed-limb Montgomery multiply mod P-256.
 * For SIZE measurement vs current fe_mul_m (143 B).
 *
 * Representation: 5 qwords per field element. Limb k holds a signed
 * value nominally in [0, 2^54) but can grow via lazy add/sub. The
 * represented integer is Σ limb[k] · 2^(54k).
 *
 * Montgomery: R = 2^270. Output ≡ a·b/R (mod p). For p's low 54 bits
 * all-ones, -p^(-1) ≡ 1 (mod 2^54), so the Montgomery quotient is
 * just q = acc[i] & MASK54 — no multiply.
 *
 * SOS structure: full 5×5 schoolbook into a 10-slot × 128-bit
 * accumulator, then 5 reduce iterations.
 *
 * Ranges (from range_limbs.py):
 *   input limbs: |limb| ≤ 2^59 (canonical 2^54 + ×12 RCB growth)
 *   products:    |prod| ≤ 2^118
 *   accumulator: ≤ 2^119 (5 products + reduce contributions)
 *   output val:  ≤ 2^258 ≈ 4p  (NOT reduced to [0,p) — caller lives with it)
 *
 * API: fe_mul5(rdi=dst, rsi=a, rdx=b, rcx=m). r13=MASK54 preloaded.
 */

	.intel_syntax noprefix
	.text

	.equ	W,   54
	.equ	K,   5
	.equ	ACC_QW, 2*K*2      /* 10 slots × 2 qwords = 20 qwords */

.globl fe_mul5
fe_mul5:
	push	rbx
	push	rbp
	push	r12
	push	rdi                /* dst — pop at epilogue */
	push	rcx                /* m — peek via [rsp] */
	mov	r12, rdx           /* b */

	/* Zero the 128-bit × 10 accumulator: 20 qwords. rcx=0 assumed on
	 * entry (same invariant as current fe_mul_m). */
	xor	ecx, ecx
.rept ACC_QW
	push	rcx
.endr
	mov	rbp, rsp           /* acc base */

/* ── Schoolbook: for i in 0..5, for j in 0..5: acc[i+j] += a[i]*b[j] ──
 * a[i] loaded into rbx. Inner loop advances rsi (b) and rdi (acc). */
	push	-K*8               /* i*8, as a negative offset from a+40 */
	pop	r10
	add	rsi, K*8           /* rsi → a+40, so [rsi+r10] = a[i] */
.Lso:
	mov	rbx, [rsi + r10]   /* a[i], signed */
	lea	rdi, [rbp + r10*2] /* acc + i*16 */
	push	r12
	mov	cl, K
	call	.Lin
	pop	r12
	add	r10, 8
	jnz	.Lso
	/* rcx=0 via loop exit. */

/* ── Reduce: for i in 0..5: q = acc[i]&MASK; acc[i..i+4] += q*m;
 *           carry acc[i]>>54 into acc[i+1]. ──
 * Same inner loop (ADD), different multiplier source. */
	mov	cl, K
.Lro:
	mov	rbx, [rbp]         /* acc[i] low64 — low 54 bits are what we need */
	and	rbx, r13           /* q = acc[i] & MASK54. m0inv=1 for p. */
	push	rcx
	push	rbp
	pop	rdi                /* rdi = acc[i] */
	mov	rsi, [rsp + ACC_QW*8 + 16]  /* m, past acc+dst+savedrcx on stack */
	mov	cl, K
	call	.Lin
	pop	rcx
	/* Carry acc[i] >> 54 into acc[i+1]. acc[i] is 128-bit;
	 * after adding q*m, low 54 bits are 0. High bits carry. */
	mov	rax, [rbp]
	mov	rdx, [rbp+8]
	shrd	rax, rdx, W        /* bits 54-117 of acc[i] */
	sar	rdx, W             /* bits 118+ (signed) */
	add	[rbp+16], rax
	adc	[rbp+24], rdx
	lea	rbp, [rbp+16]      /* advance to acc[i+1] */
	loop	.Lro
	/* rbp now points at acc[K] = acc[5]. */

/* ── Final carry-propagate: acc[5..9] → 5 output limbs ──
 * Each 128-bit acc slot is bounded ≤ 2^119. After carry-prop, limbs
 * 0..3 are in [0, 2^54), limb 4 absorbs the rest (signed, ≤ 2^42). */
	mov	rdi, [rsp + ACC_QW*8 + 8]  /* dst */
	xor	edx, edx           /* carry_lo */
	xor	ebx, ebx           /* carry_hi */
	mov	cl, K
.Lcp:
	mov	rax, [rbp]
	add	rax, rdx           /* + carry_lo */
	mov	rdx, [rbp+8]
	adc	rdx, rbx           /* + carry_hi (128-bit add) */
	/* rdx:rax = acc[K+k] + carry. Extract low 54, carry rest. */
	mov	rbx, rax
	and	rbx, r13           /* low 54 → output limb */
	mov	[rdi], rbx
	shrd	rax, rdx, W        /* new carry_lo = bits 54-117 */
	sar	rdx, W             /* new carry_hi = bits 118+ */
	mov	rbx, rdx           /* save hi for next iter's adc */
	mov	rdx, rax           /*       lo for next iter's add */
	lea	rbp, [rbp+16]
	scasq                      /* rdi += 8 */
	loop	.Lcp
	/* Final carry (rbx:rdx) absorbed into top limb. */
	add	[rdi-8], rdx       /* limb 4 += final carry_lo << 0... */
	/* Actually: limb 4 already got (acc[9]+carry)&MASK. The residual
	 * carry >> 54 is what we add. But we want limb 4 to be the FULL
	 * (acc[9]+carry)>>0 not just low 54 bits. Redo last iteration
	 * differently: don't mask the last one.
	 *
	 * Simpler: after the loop, undo the mask on limb 4 and add the
	 * carry that was shifted out. limb[4]_stored = (v & MASK54);
	 * we want limb[4] = v = (v & MASK) | (carry << 54). So: */
	shl	rdx, W
	add	[rdi-8], rdx
	/* (carry_hi in rbx is 0 here — acc[9] is small enough that
	 * after >>54 there's nothing in bits 64+. Range analysis gives
	 * acc[9] ≤ ~2^65; >>54 = ~2^11. rbx=0 holds.) */

	add	rsp, ACC_QW*8 + 16  /* discard acc + m + dst */
	pop	r12
	pop	rbp
	pop	rbx
	ret

/* ── Inner loop: acc[k] += rbx * [rsi++], K times. 128-bit acc. ──
 * rdi → acc slot (advances by 16). rsi → operand (advances by 8).
 * rbx = multiplier. rcx = count. Clobbers rax, rdx, rsi, rdi, rcx. */
.Lin:
	lodsq                      /* rax = next limb */
	imul	rbx                /* rdx:rax = rax * rbx, signed 128-bit */
	add	[rdi], rax
	adc	[rdi+8], rdx
	lea	rdi, [rdi+16]
	loop	.Lin
	ret

.globl fe_mul5_end
fe_mul5_end:
