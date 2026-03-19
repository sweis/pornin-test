/* ======================================================================
 * tv_ecdsa.S — ECDSA/P-256 verify, 5×54-bit signed limbs.
 *
 * Architecture: Montgomery form (R = 2^270). Field elements are 5 limbs
 * × 54 bits nominal, signed, lazy-carry. Fadd/Fsub are pure limbwise
 * (no carry, no reduce). fe_mul5 normalizes its output.
 *
 *   Range proof (range_proof.py, K=5 W=54):
 *     KW = 270 > 263.2 (RCB ×12 Y3-chain convergence bound)
 *     accumulator ≤ 119 bits (fits signed-128, 8 bits spare)
 *     mul-input limbs ≤ 59 bits (canonical 54 + ×12 growth ≈ +4)
 *
 *   Montgomery: p's low 54 bits all-ones → −p⁻¹ ≡ 1 (mod 2^54).
 *   n's m0inv = 0x11c8aaee00bc4f (movabs, doesn't fit imm32).
 *   MASK = 2^54−1 = 0x3fffffffffffff: movabs → r13, preserved everywhere.
 *
 * Slots: 40 B each (5 qwords). 24 slots. Frame 968 B (960 + 8 align).
 * Slots 0,1,2,3 reach disp8 from r14 (40*3 = 120 < 128).
 *
 * Constants stored as 32 LE bytes — `bt [cN], ebx` works directly in
 * fe_inv. cP stored too (not runtime-built) for baseline simplicity.
 *
 * Projective R-cancellation: Q stays plain (level 0), G Montgomery
 * (level 1). RCB preserves triple-consistency regardless of absolute
 * level. Final check aligns X·1 vs r·Z. No cR2_p needed.
 *
 * PHASE 1 BASELINE — not golfed. 607/607, then grind.
 * ====================================================================== */

	.intel_syntax noprefix

	.equ	W,      54
	.equ	K,      5
	.equ	SLOT,   K*8        /* 40 B */
	.equ	NSLOTS, 24
	.equ	FRAME,  NSLOTS*SLOT + 8   /* 968 — +8 for 16-align with 5 pushes */

/* Slot map (same indices as limb11 — bytecode is slot-indexed):
 *   0-2   acc (X:Y:Z)
 *   3,4   RCB scratch
 *   5-7   addend (X₂:Y₂:Z₂) — RCB never writes
 *   8     cP — RCB never writes
 *   9     cN — RCB never writes
 *   10    b — RCB never writes
 *   11-13 RCB scratch
 *   14    (r+n) — RCB never writes
 *   15    one — RCB never writes
 *   16-21 Shamir backups
 *   22,23 u1, u2 */
	.equ	oADD,   5*SLOT
	.equ	oCP,    8*SLOT
	.equ	oCN,    9*SLOT
	.equ	oBAK,   16*SLOT
	.equ	oU1,    22*SLOT

/* ======================================================================
 * RODATA — before .text so bytecode offsets fit push-imm8
 * ====================================================================== */
	.section .rodata, "a"

.include "bytecode.inc"

/* Constants — 32 LE bytes each. cP stored (not runtime-built): p's
 * 5×54 limbs are less sparse than 11×24 (only 1 all-ones, 1 zero).
 * R = 2^270. Chain decode: cP→8, cN→9, cR2N→10, Gx→11, Gy→12. */
cP:	.quad	0xffffffffffffffff, 0x00000000ffffffff
	.quad	0x0000000000000000, 0xffffffff00000001
cN:	.quad	0xf3b9cac2fc632551, 0xbce6faada7179e84
	.quad	0xffffffffffffffff, 0xffffffff00000000
cR2N:	.quad	0x017644694887ac57, 0x9ea8ca2ae130785e
	.quad	0x92b6bec59619076a, 0x55aba83afc16484a
cGX:	.quad	0xcc35062a450f0624, 0xa57f11d76d805e79
	.quad	0xdccaddd889441d6e, 0x17ddaf71d571985a
cGY:	.quad	0x94d5f3a55582a15c, 0xae390d2a7917377c
	.quad	0x21a237487cc962d2, 0x7fc62abe1761535e

/* ======================================================================
 * TEXT
 * ====================================================================== */
	.text

/* ── Jump table — same-section for .Lop−.Ljt constant. u8-fit assert
 * at end of file. ── */
.Ljt:
	.byte	.Lfmul-.Ljt, .Lfadd-.Ljt, .Lfsub-.Ljt, .Lnmul-.Ljt
	.byte	.Lchklt-.Ljt, .Lchkz-.Ljt, .Linv_s-.Ljt, .Lnorm-.Ljt
	.byte	.Lset1-.Ljt, .Lcopy-.Ljt, .Lchknz-.Ljt, .Lcopyhi-.Ljt
	/* ZERO dropped — Fsub(x,x)=0 does the same job. */

/* ── Handlers ──
 * bc_run preloads rdi=dst, rsi=s1, rdx=s2 (slot pointers), rcx=&cN.
 * All handlers may clobber rax, rcx, rdx, rsi, rdi, r8-r11.
 * Must preserve rbx (bc ptr), r12 (jt), rbp (fail bits), r13 (MASK),
 * r14 (slot base), r15 (unused here — pt_mul's counter).
 *
 * Layout: .Lfmul/.Lnmul moved to immediately precede fe_mul5 so .Lnmul
 * falls through (−5 B) and .Lfmul's jmp is rel8 over the movabs (−3 B).
 * .Linv's body moves after fe_mul5 (stub keeps .Ljt entry in u8). */

.Lcopyhi: /* 8 slots from s1 → slot(dst+16). Single call in bc_v1. */
	add	rdi, 16*SLOT
	push	8*K
	jmp	.Lcopy_n
.Lcopy:
	push	K
.Lcopy_n:
	pop	rcx
	rep	movsq
	ret

.Lset1:
	xor	eax, eax
	push	K
	pop	rcx
	rep	stosq
	inc	qword ptr [rdi - K*8]
	ret

.Lfadd:
	push	K
	pop	rcx
1:	lodsq
	add	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	loop	1b
	ret

.Lfsub:
	push	K
	pop	rcx
1:	lodsq
	sub	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	loop	1b
	ret

.Lchknz: /* bit 0 ← (s1 == 0).  CHKZ sets bit 0 = (s1≠0); xor flips. */
	call	.Lchkz
	xor	ebp, 1
	ret
.Lchkz:
	xor	edx, edx
	push	K
	pop	rcx
1:	lodsq
	or	rdx, rax
	loop	1b
	neg	rdx                 /* CF = (rdx != 0) */
	rcl	ebp, 1
	ret

.Lchklt:
	push	K-1
	pop	rcx
1:	mov	rax, [rsi + rcx*8]
	cmp	rax, [rdx + rcx*8]
	jb	2f
	ja	3f
	dec	ecx
	jns	1b
3:	inc	ebp
2:	ret

/* ── NORM — bring value to [0, p). In-place on s1. ── */
.Lnorm:
	lea	r8, [rcx - SLOT]    /* &cN − SLOT = &cP */
	push	rsi
	pop	rdi
	call	.Lcprop
1:	test	byte ptr [rdi + K*8 - 1], 0x80
	jz	2f
	call	.Laddm
	jmp	1b
2:	call	.Lsubm
	test	byte ptr [rdi + K*8 - 1], 0x80
	jz	2b
	/* fall into .Laddm for final add */

.Laddm:                             /* rdx free: NORM ignores bc_run's s2 arg */
	xor	edx, edx
.Lasmod:
	push	rdi
	mov	rsi, r8
	mov	cl, K               /* rcx = 0 — all paths here came through .Lcprop's loop */
1:	lodsq
	xor	rax, rdx
	sub	rax, rdx
	add	[rdi], rax
	scasq
	loop	1b
	pop	rdi
	/* fall into .Lcprop */
.Lcprop:
	push	rdi
	xor	edx, edx
	push	K-1
	pop	rcx
1:	mov	rax, [rdi]
	add	rax, rdx
	mov	rdx, rax
	and	rax, r13            /* MASK in register — not imm32 */
	stosq
	sar	rdx, W
	loop	1b
	add	[rdi], rdx
	pop	rdi
	ret

.Lsubm:
	push	-1
	pop	rdx
	jmp	.Lasmod

.Linv_s: /* Stub — .Linv body lives after fe_mul5 to make room in u8. */
	jmp	.Linv

.Lfmul: /* MontMul mod p. Jump rel8 over .Lnmul's movabs into fe_mul5. */
	sub	rcx, SLOT
	push	1
	pop	r11
	jmp	fe_mul5             /* rel8 — 10 B away */

.Lnmul: /* MontMul mod n. Falls through to fe_mul5.
 * fe_mul5 preserves rcx so INV's 384 calls all inherit &cN. */
	movabs	r11, 0x11c8aaee00bc4f
	/* FALL THROUGH */

/* ======================================================================
 * fe_mul5 — Montgomery multiply, 5×54, 128-bit accumulator.
 *   rdi=dst, rsi=a, rdx=b, rcx=m, r11=m0inv, r13=MASK (preserved).
 *   Restores rcx on exit (INV relies on stable &m).
 * ====================================================================== */
	.equ	ACC_QW, 4*K         /* 10 × 128-bit = 20 qwords */

fe_mul5:
	push	rbx
	push	rdx                 /* b → [rbp+24]. r12 (=.Ljt) stays untouched. */
	push	rdi
	push	rcx
	enter	ACC_QW*8, 0

	xor	eax, eax
	push	rsp
	pop	rdi
	lea	ecx, [rax + ACC_QW]
	rep	stosq               /* rcx = 0 after */

	lea	r8, [rsi + K*8]

	/* CIOS: schoolbook row + reduce row per iteration. r10 = &acc[i]
	 * (survives .Lin). rbx indexes a[] (stride 8) — non-REX counter.
	 * r9 is the .Lin multiplicand (a[i] then q). */
	push	-K*8
	pop	rbx
.Lcios:	mov	r9, [r8 + rbx]              /* a[i] */
	lea	r10, [rbp + rbx*2 - K*16]   /* &acc[i] — disp8 (-80) */
	mov	rsi, [rbp + 24]             /* b — stack-stored, r12 stays = .Ljt */
	call	.Lcnt                       /* .Lcnt sets rdi = r10 itself */
	mov	r9, [r10]                   /* acc[i].lo */
	imul	r9, r11
	and	r9, r13                     /* q */
	mov	rsi, [rbp + 8]              /* m */
	call	.Lcnt
	mov	rax, [r10]                  /* acc[i] ≡ 0 mod 2^W now */
	mov	rdx, [r10 + 8]
	shrd	rax, rdx, W
	sar	rdx, W
	add	[r10 + 16], rax
	adc	[r10 + 24], rdx
	add	rbx, 8              /* 64-bit — ebx would zero-extend, wreck negative index */
	jnz	.Lcios

	/* Carry-prop: acc[K..2K-1] (128-bit) → dst[0..K-1]. r10 ended at
	 * &acc[K-1]; source = r10+16. Running carry in rdx:rbx; lodsq ×2
	 * advances rsi by 16 (rax scratch). rbx = 0 from loop exit above —
	 * no xor needed. Top limb ≤ 2^42 so dropping hi in tail is correct. */
	lea	rsi, [r10 + 16]
	mov	rdi, [rbp + 16]
	xor	edx, edx
	mov	cl, K-1
.Lcp5:	lodsq
	add	rdx, rax
	lodsq
	adc	rbx, rax
	push	rdx
	pop	rax                 /* 2 B vs mov=3 B */
	and	rax, r13
	stosq
	shrd	rdx, rbx, W
	sar	rbx, W
	loop	.Lcp5
	lodsq
	add	rax, rdx
	stosq

	leave
	pop	rcx
	pop	rax                 /* discard rdi */
	pop	rax                 /* discard rdx */
	pop	rbx
	ret

.Lcnt:	mov	rdi, r10    /* both CIOS call sites need rdi = &acc[i] */
	mov	cl, K       /* rcx high bytes zero — from rep stosq / prior .Lin */
.Lin:	lodsq
	imul	r9
	add	[rdi], rax
	adc	[rdi+8], rdx
	lea	rdi, [rdi+16]
	loop	.Lin
	ret

/* ── INV — s^(n−2) mod n via Fermat. n−2 differs from n only in bits
 * 1..4 (low byte 0x51 → 0x4F). bt on cN directly, special-case 0..4.
 * Moved here (post-fe_mul5) so .Lnmul can fall through; .Linv_s is the
 * u8-reachable stub. ── */
.Linv:
	push	rbx
	push	rsi                 /* s_mont */
	push	rdi                 /* accumulator — seeded with s_mont */
	xor	ebx, ebx
	mov	bl, 254             /* bit 255 implicit (seed = s_mont) */
.Le:	pop	rsi
	push	rsi
	push	rsi
	push	rsi
	pop	rdi
	pop	rdx
	call	.Lnmul              /* dst = dst² */
	cmp	ebx, 4
	jb	.Lmul               /* bits 0-3: n-2 has 1111 */
	je	.Lnx                /* bit 4: n-2 has 0 */
	bt	dword ptr [rip + cN], ebx
	jnc	.Lnx
.Lmul:	pop	rdi
	pop	rdx
	push	rdx
	push	rdi
	push	rdi
	pop	rsi
	call	.Lnmul
.Lnx:	dec	ebx
	jns	.Le
	pop	rax
	pop	rax
	pop	rbx
	ret

/* ── Decoders ──
 * Limb i starts at bit 54i → byte 54i/8, shift 54i&7. Loop i=0..3 with
 * a running bit-offset (ebx); unroll i=4 as (24,24) — the natural (27,0)
 * would read bytes 27..34 (3 past a 32-B input).
 *
 * fe_from_le takes its SOURCE in rdx (not rsi). This lets fe_from_be
 * fall through: its reversal loop leaves rsi=src+32 (for BE chaining)
 * and rdx=rdi+8 (in-slot buffer start) — exactly what fe_from_le wants.
 * fe_from_le clobbers rbx (only called from verify, never as a handler).
 * LE chain: exit rdx=src+32, rdi=dst+40.
 * BE chain: exit rsi=src+32, rdi=dst+40 (rdx garbage). */

fe_from_be:
	lea	rdx, [rdi + 40]
	push	32
	pop	rcx
1:	lodsb
	dec	rdx
	mov	[rdx], al
	loop	1b                  /* rsi=src+32, rdx=rdi+8, rcx=0 */
	/* FALL THROUGH — rsi preserved through fe_from_le (uses ebx,ecx,rdx). */

/* 54 = 48 + 6, so byte-offset 6i and shift 6i extract bits 48i+6i = 54i.
 * Need 64 bits after shift for full 54-bit limb, but shr by 6i leaves only
 * 64−6i bits — insufficient for i≥2. shrd with [rdx+6i+8] supplies the
 * high bits (iter-3 reads bytes 26..33: 2 B past, valid but value masked
 * off). Iter 4 WOULD read [rdx+32] = past input; skip that load, shrd
 * with rbx=0 ≡ shr (limb 4 is 40 bits, doesn't need high qword). */
fe_from_le:
	xor	ecx, ecx
1:	mov	rax, [rdx + rcx]
	xor	ebx, ebx
	cmp	cl, 24
	jae	2f                  /* iter 4: leave rbx=0 (shrd ≡ shr) */
	mov	rbx, [rdx + rcx + 8]
2:	shrd	rax, rbx, cl
	and	rax, r13
	stosq
	add	ecx, 6
	cmp	cl, 30
	jne	1b
	add	rdx, 32
	ret

/* ======================================================================
 * bc_run — bytecode interpreter
 * ====================================================================== */

/* .Lcadd: copy 3 slots → addend, dispatch bc_rcb. */
.Lcadd:
	lea	rdi, [r14 + oADD]
	push	3*K
	pop	rcx
	rep	movsq
	xor	edi, edi            /* obc_rcb = 0 */
	jmp	bcrun_off

pt_mul:
	/* rbp = verify's frame pointer = r14 + FRAME (bc_run push/pops rbp
	 * so it's restored across .Lcadd). u1 at slot 22 = rbp−88, u2 at
	 * slot 23 = rbp−48 — both disp8 from rbp. Saves 6 B vs [r14+disp32]. */
	push	K-1
	pop	r15
.Lpo:	push	W-1
	pop	rbx
.Lpi:	mov	rsi, r14
	call	.Lcadd
	bt	[rbp + r15*8 - (FRAME - oU1)], ebx
	jnc	1f
	lea	rsi, [r14 + oBAK]
	call	.Lcadd
1:	bt	[rbp + r15*8 - (FRAME - oU1 - SLOT)], ebx
	jnc	2f
	lea	rsi, [r14 + oBAK + 3*SLOT]
	call	.Lcadd
2:	dec	ebx
	jns	.Lpi
	dec	r15
	jns	.Lpo
	/* falls through to final check */
	push	obc_v3
	pop	rdi

bcrun_off:
	lea	rax, [rip + bc_rcb]
	add	rdi, rax

bc_run:
	push	rbp
	push	rbx
	push	rdi
	pop	rbx
	xor	ebp, ebp
	/* r12 = &.Ljt inherited from verify; fe_mul5 preserves it. */
.Lbc:
	mov	eax, [rbx]          /* over-read 2 B — and eax,0xF later clears */
	add	rbx, 2
	test	al, al
	jz	.Lbce

	movzx	edi, ah
	mov	esi, edi
	and	esi, 0xF
	imul	esi, esi, SLOT
	add	rsi, r14
	shr	edi, 4
	imul	edi, edi, SLOT
	add	rdi, r14

	movzx	edx, al
	shr	edx, 4
	imul	edx, edx, SLOT
	add	rdx, r14

	and	eax, 0xF
	mov	al, [r12 + rax]     /* high bytes zero from the `and` above */
	add	rax, r12
	lea	rcx, [r14 + oCN]
	call	rax
	jmp	.Lbc

.Lbce:	neg	ebp
	sbb	eax, eax
	pop	rbx
	pop	rbp
	ret

/* ======================================================================
 * verify — entry point
 * ====================================================================== */
.globl tv_ecdsa_p256_verify_asm
tv_ecdsa_p256_verify_asm:
	/* rdi=sig, rsi=sig_len, rdx=pub, rcx=pub_len, r8=hv, r9=hv_len */
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15

	/* Alignment: caller's rsp ≡ 0 (mod 16) at call → −8 (ret) − 40
	 * (5 pushes) − 8 (enter's rbp) − 968 = −1024 ≡ 0 (mod 16). */
	enter	FRAME, 0

	xor	eax, eax
	cmp	rsi, 64
	jne	.Lfail
	cmp	rcx, 65
	jne	.Lfail
	sub	r9, 32
	cmp	r9, 32
	ja	.Lfail
	cmp	byte ptr [rdx], 0x04
	je	.Lok
.Lfail:
	leave
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.Lok:
	mov	r14, rsp
	push	-1
	pop	r13
	shr	r13, 64-W           /* MASK = 2^54−1; movabs is 10 B, this is 8 */
	lea	r12, [rip + .Ljt]   /* jump table — preserved by handlers + fe_mul5 */

	push	rdi                 /* sig — r8 (hv) is untouched by fe_from_be */

	/* BE chain at slot 3 (3*SLOT = 120: disp8). Qx,Qy,r,s,e → 3..7.
	 * rdi ends at slot 8, ready for LE constants. The bc_v1 layout
	 * stages all 8 Shamir values at slots 0..7 → one rep movsq. */
	lea	rsi, [rdx + 1]
	lea	rdi, [r14 + 3*SLOT]
	call	fe_from_be          /* Qx → 3 */
	call	fe_from_be          /* Qy → 4 */
	pop	rsi                 /* sig */
	call	fe_from_be          /* r  → 5 */
	call	fe_from_be          /* s  → 6 */
	mov	rsi, r8             /* hv */
	call	fe_from_be          /* e  → 7 */

	/* Constants (LE). cP,cN,cR2N,cGX,cGY → 8,9,10,11,12. */
	lea	rdx, [rip + cP]
	push	5
	pop	r15
1:	call	fe_from_le
	dec	r15
	jnz	1b

	push	obc_v1
	pop	rdi
	call	bcrun_off
	push	rax
	call	pt_mul
	pop	rdx
	or	eax, edx
	inc	eax
	jmp	.Lfail

	.section .note.GNU-stack,"",@progbits
