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
	.byte	.Lchklt-.Ljt, .Lchkz-.Ljt, .Linv-.Ljt, .Lnorm-.Ljt
	.byte	.Lset1-.Ljt, .Lcopy-.Ljt, .Lchknz-.Ljt, .Lcopyhi-.Ljt
	.byte	.Lzero-.Ljt

/* ── Handlers ──
 * bc_run preloads rdi=dst, rsi=s1, rdx=s2 (slot pointers), rcx=&cN.
 * All handlers may clobber rax, rcx, rdx, rsi, rdi, r8-r11.
 * Must preserve rbx (bc ptr), r12 (jt), rbp (fail bits), r13 (MASK),
 * r14 (slot base), r15 (unused here — pt_mul's counter). */

.Lfmul: /* Fmul — MontMul mod p. m0inv = 1. rcx = &cN → sub SLOT = &cP. */
	sub	rcx, SLOT
	push	1
	pop	r11
	jmp	fe_mul5

.Lnmul: /* Nmul — MontMul mod n. m0inv doesn't fit imm32 — movabs.
 * fe_mul5 preserves rcx so INV's 384 calls all inherit &cN. */
	movabs	r11, 0x11c8aaee00bc4f
	jmp	fe_mul5

.Lcopyhi: /* 2 slots from s1 → slot(dst+16). */
	add	rdi, 16*SLOT
	push	2*K
	jmp	.Lcopy_n
.Lcopy:
	push	K
.Lcopy_n:
	pop	rcx
	rep	movsq
	ret

.Lzero:
	xor	eax, eax
	jmp	.Lset_l0
.Lset1:
	push	1
	pop	rax
.Lset_l0:
	stosq
	xor	eax, eax
	push	K-1
	pop	rcx
	rep	stosq
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

/* ── INV — s^(n−2) mod n via Fermat. n−2 differs from n only in bits
 * 1..4 (low byte 0x51 → 0x4F). bt on cN directly, special-case 0..4. ── */
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

.Laddm:
	xor	r9d, r9d
.Lasmod:
	push	rdi
	mov	rsi, r8
	push	K
	pop	rcx
1:	lodsq
	xor	rax, r9
	sub	rax, r9
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
	pop	r9
	jmp	.Lasmod

/* ── Decoders ──
 * 54-bit limbs are not byte-aligned: limb i starts at bit 54i.
 *   limb 0: byte  0, shift  0
 *   limb 1: byte  6, shift  6
 *   limb 2: byte 13, shift  4
 *   limb 3: byte 20, shift  2
 *   limb 4: byte 24, shift 24  ← (27,0) would overread; (24,24) fits 32-byte input
 * Both decoders chain: exit rsi=src+32, rdi=dst+40. */

fe_from_le:
	mov	rax, [rsi]
	and	rax, r13
	stosq
	mov	rax, [rsi+6]
	shr	rax, 6
	and	rax, r13
	stosq
	mov	rax, [rsi+13]
	shr	rax, 4
	and	rax, r13
	stosq
	mov	rax, [rsi+20]
	shr	rax, 2
	and	rax, r13
	stosq
	mov	rax, [rsi+24]
	shr	rax, 24
	stosq
	add	rsi, 32
	ret

/* fe_from_be — reverse 32 input bytes into stack buffer, then decode.
 * Buffer is exactly 32 B; limb 4 uses (24,24) so no overread. */
fe_from_be:
	sub	rsp, 40             /* 32 B buffer + 8 B to keep 16-align */
	lea	rdx, [rsp + 31]
	push	32
	pop	rcx
1:	lodsb
	mov	[rdx], al
	dec	rdx
	loop	1b                  /* rsi = src+32, rcx = 0 */
	push	rsi
	lea	rsi, [rsp + 8]      /* buffer, past the pushed rsi */
	call	fe_from_le
	pop	rsi
	add	rsp, 40
	ret

/* ======================================================================
 * fe_mul5 — Montgomery multiply, 5×54, 128-bit accumulator.
 *   rdi=dst, rsi=a, rdx=b, rcx=m, r11=m0inv, r13=MASK (preserved).
 *   Restores rcx on exit (INV relies on stable &m).
 * ====================================================================== */
	.equ	ACC_QW, 4*K         /* 10 × 128-bit = 20 qwords */

fe_mul5:
	push	rbx
	push	r12
	mov	r12, rdx
	push	rdi
	push	rcx
	enter	ACC_QW*8, 0

	xor	eax, eax
	push	rsp
	pop	rdi
	lea	ecx, [rax + ACC_QW]
	rep	stosq               /* rcx = 0 after */

	lea	r8, [rsi + K*8]

	/* Schoolbook: acc[i+j] += a[i]·b[j] (128-bit). */
	push	-K*8
	pop	r9
.Lsb:	mov	rbx, [r8 + r9]
	lea	rdi, [rbp + r9*2 - K*16]
	mov	rsi, r12
	mov	cl, K
	call	.Lin
	add	r9, 8
	jnz	.Lsb

	/* Reduce: q = (acc[i].lo · m0inv) & MASK; acc += q·m; carry >>54. */
	mov	r8, [rbp + 8]       /* m */
	lea	r9, [rbp - ACC_QW*8]
	mov	cl, K
.Lrd:	push	rcx
	mov	rbx, [r9]
	imul	rbx, r11
	and	rbx, r13
	mov	rdi, r9
	mov	rsi, r8
	xor	ecx, ecx
	mov	cl, K
	call	.Lin
	mov	rax, [r9]
	mov	rdx, [r9 + 8]
	shrd	rax, rdx, W
	sar	rdx, W
	add	[r9 + 16], rax
	adc	[r9 + 24], rdx
	lea	r9, [r9 + 16]
	pop	rcx
	loop	.Lrd

	/* Carry-prop: acc[K..2K-1] (128-bit) → dst[0..K-1] (54-bit + top). */
	mov	rdi, [rbp + 16]
	xor	eax, eax
	xor	r10d, r10d
	mov	cl, K-1
.Lcp5:	add	rax, [r9]
	adc	r10, [r9 + 8]
	mov	rdx, rax
	and	rdx, r13
	mov	[rdi], rdx
	shrd	rax, r10, W
	sar	r10, W
	lea	r9, [r9 + 16]
	scasq
	loop	.Lcp5
	add	rax, [r9]
	stosq

	leave
	pop	rcx
	pop	rax
	pop	r12
	pop	rbx
	ret

.Lin:	lodsq
	imul	rbx
	add	[rdi], rax
	adc	[rdi+8], rdx
	lea	rdi, [rdi+16]
	loop	.Lin
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
	/* r12 holds &.Ljt (set in verify) — use direct disp32 bt's here.
	 * The two bt encodings are 9 B each; prior lea+bt+bt was 7+5+6=18.
	 * Wash on pt_mul, but frees r12 for bc_run to inherit. */
	push	K-1
	pop	r15
.Lpo:	push	W-1
	pop	rbx
.Lpi:	mov	rsi, r14
	call	.Lcadd
	bt	[r14 + r15*8 + oU1], ebx
	jnc	1f
	lea	rsi, [r14 + oBAK]
	call	.Lcadd
1:	bt	[r14 + r15*8 + oU1 + SLOT], ebx
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
	movabs	r13, (1<<W)-1       /* MASK — preserved by everything below */
	lea	r12, [rip + .Ljt]   /* jump table — preserved by handlers + fe_mul5 */

	push	rdi                 /* sig */
	push	r8                  /* hv */

	/* User inputs (BE). Qx,Qy,e chain 5,6,7. rdi ends at slot 8. */
	lea	rsi, [rdx + 1]
	lea	rdi, [r14 + 5*SLOT]
	call	fe_from_be          /* Qx → 5 */
	call	fe_from_be          /* Qy → 6 */
	pop	rsi
	call	fe_from_be          /* e  → 7 */

	/* Constants (LE). cP,cN,cR2N,cGX,cGY → 8,9,10,11,12. All chain. */
	lea	rsi, [rip + cP]
	call	fe_from_le
	call	fe_from_le
	call	fe_from_le
	call	fe_from_le
	call	fe_from_le

	pop	rsi                 /* sig */
	call	fe_from_be          /* r → 13 */
	call	fe_from_be          /* s → 14 */

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
