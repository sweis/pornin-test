/* ======================================================================
 * tv_ecdsa_limb11.S — ECDSA/P-256 verify, 11×24-bit signed limbs.
 *
 * Architecture: Montgomery form throughout (R = 2^264). Field elements
 * are 11 limbs × 24 bits nominal, signed, lazy-carry. Fadd/Fsub are
 * pure limbwise (no carry, no reduce). fe_mul11 normalizes its output.
 *
 *   Range proof (range_proof.py, commit a5fc446):
 *     KW = 264 > 263.2 (RCB ×12 Y3-chain convergence bound)
 *     accumulator ≤ 60 bits (fits signed-64, 3 bits spare)
 *     mul-input limbs ≤ 29 bits (canonical 24 + ×12 growth ≈ +4)
 *     mul-output value ≤ 2^258 (≈ 4p, top limb ≤ 18 bits)
 *
 *   Montgomery: p's low 24 bits = 0xFFFFFF → −p⁻¹ ≡ 1 (mod 2^24),
 *   so q = acc[i] & MASK (no multiply). n's m0inv = 0xBC4F.
 *
 * Slots: 88 B each (11 qwords). 24 slots. Stack frame ~2200 B.
 * bc_run decodes slot indices via imul-by-88 (fits imm8).
 *
 * Constants stored as LE bytes (4 quads, low→high) — this makes
 * `bt [cN], ebx` work directly in fe_inv (bit i of n is at byte i/8).
 * fe_from_be for user inputs (sig, pub, hash); fe_from_le for constants.
 *
 * PHASE 1 BUILD — not golfed. Get 607/607, then grind.
 * ====================================================================== */

	.intel_syntax noprefix

	.equ	W,      24
	.equ	K,      11
	.equ	MASK,   (1<<W)-1
	.equ	SLOT,   K*8        /* 88 B per slot */
	.equ	NSLOTS, 24

/* Slot map (RCB never writes 5,6,7,8,9,10,14,15 — load-bearing):
 *   0-2   acc (X:Y:Z)
 *   3,4   RCB scratch
 *   5-7   addend (X₂:Y₂:Z₂)
 *   8     cP (built at runtime)
 *   9     cN (decoded)
 *   10    b (derived in bc_v1)
 *   11-13 RCB scratch
 *   14    r_mont (bc_v1 writes, bc_v3 reads — survives 256 RCBs)
 *   15    cR2_p → n_mont (bc_v1 converts in place as LAST MULR2)
 *   16-21 Shamir backups (G @ 16-18, Q @ 19-21)
 *   22,23 u1, u2 scalars (normalized [0,n) for bit-read)
 *
 * (Names can't be sP/sN — Intel-syntax regs are case-insensitive.) */
	.equ	oADD,   5*SLOT
	.equ	oCP,    8*SLOT
	.equ	oCN,    9*SLOT
	.equ	oR2,    15*SLOT
	.equ	oBAK,   16*SLOT
	.equ	oU1,    22*SLOT
	.equ	oU2,    23*SLOT

/* ======================================================================
 * RODATA — before .text so bytecode stream offsets fit push-imm8
 * ====================================================================== */
	.section .rodata, "a"

.include "bytecode.inc"

/* Constants — 32 LE bytes each (4 quads, low-qword-first = natural LE).
 * Order chosen for rdi chaining: cP-build ends at slot 9 → cN decodes
 * there; cGX/cGY → 2,3 chain; cR2N/cR2 → 14,15 chain (cR2_n @ 14 is
 * consumed before r_mont writes 14). */
cN:	.quad	0xf3b9cac2fc632551, 0xbce6faada7179e84
	.quad	0xffffffffffffffff, 0xffffffff00000000
cGX:	.quad	0xe730d418a9143c18, 0xba95fc47edb60179
	.quad	0xfb732b7762251075, 0x905f76bd3755c661
cGY:	.quad	0xf25357ce95560a85, 0x4ab8e43519e45cdd
	.quad	0xe88688dd21f3258b, 0x71ff18aa885d854d
cR2N:	.quad	0x0f80d88a9a9fedcf, 0x6ab8c68a2abb372e
	.quad	0xb2392b6bec596190, 0x2d955aba561fc164
cR2:	.quad	0x0000000000030000, 0xfffbffffffff0000
	.quad	0xfffffffffffeffff, 0x0004fffffffdffff

/* ======================================================================
 * TEXT
 * ====================================================================== */
	.text

/* ── Jump table — must be in .text so .Lop−.Ljt is a same-section
 * constant. gas .if can't forward-ref, so the u8-fit assert lives
 * at the end of the file (after all .Lop labels are defined). ── */
.Ljt:
	.byte	.Lop0-.Ljt, .Lop1-.Ljt, .Lop2-.Ljt, .Lop3-.Ljt
	.byte	.Lop4-.Ljt, .Lop5-.Ljt, .Lop6-.Ljt, .Lop7-.Ljt
	.byte	.Lop8-.Ljt, .Lop9-.Ljt, .Lop10-.Ljt, .Lop11-.Ljt
	.byte	.Lop12-.Ljt, .Lop13-.Ljt

/* ── Handlers ──
 * bc_run preloads rdi=dst, rsi=s1, rdx=s2 (slot pointers), rcx=&cP.
 * All handlers may clobber rax, rcx, rdx, rsi, rdi, r8-r11.
 * Must preserve rbx (bytecode ptr), r12 (jt), rbp (fail bits), r14.
 *
 * rcx high bytes are DIRTY (bc_run lea's a stack address) — every
 * `mov cl,N` would leave a huge rcx. Use push;pop for loop counters. */

.Lop8:  /* MULR2 — Fmul with s2 = slot 15 (cR2_p). */
	lea	rdx, [r14 + oR2]
	/* falls through */
.Lop0:  /* Fmul — MontMul mod p. m0inv = 1. */
.Lop1:
	push	1
	pop	r11
	jmp	fe_mul11

.Lop4:  /* Nmul — MontMul mod n. */
	lea	rcx, [r14 + oCN]
	mov	r11d, 0xBC4F
	jmp	fe_mul11

.Lop11: /* COPY — dst = s1. */
	push	K
	pop	rcx
	rep	movsq
	ret

.Lop10: /* SET1 — dst = {1, 0, ..., 0}. */
	xor	eax, eax
	push	K
	pop	rcx
	push	rdi
	rep	stosq
	pop	rdi
	inc	qword ptr [rdi]
	ret

.Lop2:  /* Fadd — limbwise, no carry. */
	push	K
	pop	rcx
1:	lodsq
	add	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	loop	1b
	ret

.Lop3:  /* Fsub — limbwise. */
	push	K
	pop	rcx
1:	lodsq
	sub	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	loop	1b
	ret

.Lop13: /* CHKNZ — bpl |= (s1 == 0). */
	call	.Lorall
	cmc                         /* CF ← zero */
	jmp	.Ladc
.Lop6:  /* CHKZ — bpl |= (s1 != 0). */
	call	.Lorall             /* CF ← nonzero */
.Ladc:	adc	bpl, 0
	ret
.Lorall:
	xor	eax, eax
	push	K
	pop	rcx
1:	or	rax, [rsi]
	lea	rsi, [rsi+8]
	loop	1b
	neg	rax                 /* CF = (rax != 0) */
	ret

.Lop5:  /* CHKLT — bpl |= (s1 >= s2). Both canonical limb form. */
	push	K-1
	pop	rcx
1:	mov	rax, [rsi + rcx*8]
	cmp	rax, [rdx + rcx*8]
	jb	2f                  /* s1 < s2: pass */
	ja	3f                  /* s1 > s2: fail */
	dec	ecx
	jns	1b
	/* all equal: s1 >= s2, fail */
3:	or	bpl, 1
2:	ret

/* ── INV — s^(n-2) mod n via Fermat. ──
 * dst pre-seeded with 1_mont_n. s1 = s_mont. n vs n-2 differ only in
 * bits 1-4 (0x51 → 0x4F); bits 0-3 of n-2 are all 1, bit 4 is 0,
 * bits 5+ match n. cN is stored LE so bt indexes bits directly.
 * Placed BEFORE NORM helpers so .Lop7 stays in u8 reach of .Ljt. */

.Lop7:
	push	rbx
	push	rsi                 /* s_mont */
	push	rdi                 /* accumulator — pre-seeded with s_mont */
	xor	ebx, ebx
	mov	bl, 254             /* bit 255 is implicit (seed = s_mont) */
.Le:	pop	rsi
	push	rsi                 /* rsi = dst, stack unchanged */
	push	rsi
	push	rsi
	pop	rdi
	pop	rdx
	call	.Lop4               /* dst = dst² (Nmul) */
	cmp	ebx, 4
	jb	.Lmul               /* bits 0-3: n-2 has 1111 */
	je	.Lnx                /* bit 4: n-2 has 0 */
	bt	dword ptr [rip + cN], ebx
	jnc	.Lnx
.Lmul:	pop	rdi
	pop	rdx                 /* rdx = src */
	push	rdx
	push	rdi                 /* stack restored */
	push	rdi
	pop	rsi
	call	.Lop4
.Lnx:	dec	ebx
	jns	.Le
	pop	rax
	pop	rax
	pop	rbx
	ret

/* ── NORM / NORMN ──
 * Bring value to [0, m). In-place on s1. Subtract-until-negative
 * then add-once is correct for any value in a bounded range (no
 * top-limb-equality trap). r8 holds the modulus (not rcx, which
 * gets clobbered by loop counters). */

.Lop12: /* NORMN */
	lea	r8, [r14 + oCN]
	jmp	.Lnorm
.Lop9:  /* NORM — rcx = &cP preloaded by bc_run. */
	mov	r8, rcx
.Lnorm:
	push	rsi
	pop	rdi                 /* in-place on s1 */
	call	.Lcprop
	/* While top < 0: add m, re-carry. */
1:	cmp	qword ptr [rdi + (K-1)*8], 0
	jge	2f
	call	.Laddm
	jmp	1b
	/* Subtract m until negative, then add m once. */
2:	call	.Lsubm
	cmp	qword ptr [rdi + (K-1)*8], 0
	jge	2b
	/* fall into .Laddm for the final add; its tail ret returns. */

.Laddm:	/* [rdi] += [r8], carry-prop.  xor/sub r9 is a no-op when r9=0,
	 * two's-complement negate when r9=−1 — shared body for add/sub. */
	xor	r9d, r9d
	/* falls through */
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
	/* falls through */
.Lcprop:	/* in-place wrapper — fe_mul11 calls .Lcp_shared directly. */
	push	rdi
	mov	rsi, rdi
	call	.Lcp_shared
	pop	rdi
	ret
.Lcp_shared:	/* out-of-place carry-prop rsi → rdi. */
	xor	edx, edx
	push	K-1
	pop	rcx
1:	lodsq
	add	rax, rdx
	mov	rdx, rax
	and	eax, MASK
	stosq
	sar	rdx, W
	loop	1b
	lodsq
	add	rax, rdx
	stosq
	ret

.Lsubm:
	push	-1
	pop	r9
	jmp	.Lasmod

/* ── Decoders ── */

/* fe_from_be — byte-reverse into the unused top of the dst slot
 * (bytes 56-87), then decode from there with fe_from_le. Write
 * region [8i,8i+8) trails read region [56+3i,56+3i+4) by 5i−56 ≥ 0
 * for i < 11, so in-place is safe. Exits rsi = src+32, rdi = dst+88. */
fe_from_be:
	lea	rdx, [rdi + 87]
	push	32
	pop	rcx
1:	lodsb
	mov	[rdx], al
	dec	rdx
	loop	1b
	push	rsi                 /* = src+32 */
	lea	rsi, [rdx + 1]      /* = dst+56 */
	call	fe_from_le
	pop	rsi
	ret

fe_from_le:
	push	K-1
	pop	rcx
1:	mov	eax, [rsi]
	and	eax, MASK
	stosq
	add	rsi, 3
	loop	1b
	movzx	eax, word ptr [rsi]
	stosq
	add	rsi, 2              /* leave rsi = src+32 for chaining */
	ret

/* ======================================================================
 * fe_mul11 — r11d = m0inv (set by Fmul=1 / Nmul=0xBC4F), rcx = m.
 * ====================================================================== */
fe_mul11:
	push	rbx
	push	r12
	mov	r12, rdx            /* b — load before rdx clobbered by imul */
	push	rdi
	push	rcx                 /* m → [rbp+8] */
	enter	2*K*8, 0

	xor	eax, eax
	lea	ecx, [rax + 2*K]
	push	rsp
	pop	rdi
	rep	stosq               /* rcx = 0 out */

	lea	r8, [rsi + K*8]

	push	-K*8
	pop	r9
.Lso:	mov	rbx, [r8 + r9]
	lea	rdi, [rbp + r9 - 2*K*8 + K*8]
	mov	rsi, r12
	call	.Lcnt
	add	r9, 8
	jnz	.Lso

	push	rsp
	pop	rsi
	mov	r8, [rbp + 8]
	mov	cl, K               /* rcx was 0 from rep stosq */
.Lro:	push	rsi
	pop	rdi
	lodsq
	imul	eax, r11d
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

	mov	rdi, [rbp + 16]
	call	.Lcp_shared

	leave
	pop	rax
	pop	rax
	pop	r12
	pop	rbx
	ret

.Lcnt:	mov	cl, K               /* callers have rcx=0 */
.Lin:	lodsq
	imul	rbx
	add	[rdi], rax
	scasq
	loop	.Lin
	ret

/* ======================================================================
 * bc_run — bytecode interpreter
 * ====================================================================== */

/* .Lcadd: copy 3 slots from [rsi] → addend (slots 5-7), dispatch bc_rcb. */
.Lcadd:
	lea	rdi, [r14 + oADD]
	push	3*K
	pop	rcx
	rep	movsq
	xor	edi, edi            /* obc_rcb = 0 */
	/* falls through */

bcrun_off:
	lea	rax, [rip + bc_rcb]
	add	rdi, rax
	/* falls through */

bc_run:
	push	rbp
	push	rbx
	push	r12
	push	rdi
	pop	rbx                 /* bytecode ptr */
	xor	ebp, ebp            /* fail-bit accumulator */
	lea	r12, [rip + .Ljt]
.Lbc:
	movzx	eax, word ptr [rbx]
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
	movzx	eax, byte ptr [r12 + rax]
	add	rax, r12
	lea	rcx, [r14 + oCP]
	call	rax
	jmp	.Lbc

.Lbce:	neg	ebp                 /* CF = (ebp != 0) */
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* ======================================================================
 * pt_mul — u1·G + u2·Q via Shamir. 264 iterations (11 limbs × 24 bits);
 * top 8 bits are zero so the extra doublings hit ∞ → harmless.
 * ====================================================================== */
pt_mul:
	/* acc = ∞ = (0:1:0). Plain Y=1 works for ∞ per HANDOFF. */
	mov	rdi, r14
	xor	eax, eax
	push	3*K
	pop	rcx
	rep	stosq
	inc	qword ptr [r14 + SLOT]
	/* r12 hoists &u1; bc_run push/pops r12 so it survives .Lcadd. */
	lea	r12, [r14 + oU1]
	push	K-1
	pop	r13
.Lpo:	push	W-1
	pop	rbx
.Lpi:	/* Double: acc → addend, RCB(acc, acc). */
	mov	rsi, r14
	call	.Lcadd
	/* u1 bit */
	bt	[r12 + r13*8], ebx
	jnc	1f
	lea	rsi, [r14 + oBAK]
	call	.Lcadd
1:	/* u2 bit — u2 at oU1+SLOT; 88 fits disp8. */
	bt	[r12 + r13*8 + SLOT], ebx
	jnc	2f
	lea	rsi, [r14 + oBAK + 3*SLOT]
	call	.Lcadd
2:	dec	ebx
	jns	.Lpi
	dec	r13
	jns	.Lpo
	/* Dispatch final check. */
	push	obc_v3
	pop	rdi
	jmp	bcrun_off

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

	/* enter before checks → all paths go through leave. Stack is
	 * 16-aligned: SysV caller rsp was aligned at call, −8 (ret addr)
	 * −32 (4 pushes) −8 (enter's rbp) = −48, then sub 2112 (÷16). */
	enter	NSLOTS * SLOT, 0

	xor	eax, eax
	cmp	rsi, 64
	jne	.Lfail
	cmp	rcx, 65
	jne	.Lfail
	cmp	r9, 32
	jb	.Lfail
	cmp	r9, 64
	ja	.Lfail
	cmp	byte ptr [rdx], 0x04
	je	.Lok
	/* .Lfail falls in the middle — all jcc's above reach it rel8. */
.Lfail:
	leave
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.Lok:
	mov	r14, rsp

	push	rdi                 /* sig */
	push	r8                  /* hv  */

	/* User inputs (BE). Qx,Qy,e chain 5,6,7 → rdi ends at slot 8. */
	lea	rsi, [rdx + 1]      /* pub+1 (skip 0x04) */
	lea	rdi, [r14 + 5*SLOT]
	call	fe_from_be          /* Qx → 5 */
	call	fe_from_be          /* Qy → 6 */
	pop	rsi                 /* hv */
	call	fe_from_be          /* e  → 7   rdi now at slot 8 */

	/* cP → slot 8 — rdi inherited. Leaves rdi at slot 9. */
	mov	eax, MASK
	push	4
	pop	rcx
	rep	stosq               /* limbs 0-3 = 0xffffff */
	xor	eax, eax
	mov	cl, 4               /* rcx = 0 from rep */
	rep	stosq               /* limbs 4-7 = 0 */
	inc	eax
	stosq
	mov	eax, 0xffff00
	stosq
	shr	eax, 8              /* 0xffff */
	stosq

	/* Constants (LE). rodata order chains rdi: 9 → 2,3 → 14,15. */
	lea	rsi, [rip + cN]
	call	fe_from_le          /* cN → 9 */
	lea	rdi, [r14 + 2*SLOT]
	call	fe_from_le          /* cGX → 2 */
	call	fe_from_le          /* cGY → 3 */
	lea	rdi, [r14 + 14*SLOT]
	call	fe_from_le          /* cR2_n → 14 */
	call	fe_from_le          /* cR2_p → 15 */

	pop	rsi                 /* sig */
	lea	rdi, [r14 + 11*SLOT]
	call	fe_from_be          /* r → 11 */
	call	fe_from_be          /* s → 12 */

	/* ── bc_v1 ── */
	push	obc_v1
	pop	rdi
	call	bcrun_off
	jc	.Lfail2

	/* Shamir backup: 2-7 → 16-21 (6 slots = 66 qw). */
	lea	rsi, [r14 + 2*SLOT]
	lea	rdi, [r14 + oBAK]
	push	6*K
	pop	rcx
	rep	movsq
	/* u1,u2: 11,12 → 22,23 (2 slots = 22 qw). rdi already at oBAK+6*SLOT=22*SLOT. */
	lea	rsi, [r14 + 11*SLOT]
	push	2*K
	pop	rcx
	rep	movsq

	/* ── pt_mul (dispatches bc_v3 at the end) ── */
	call	pt_mul
	sbb	eax, eax
	inc	eax                 /* eax = !CF = (fail bits were 0) */
	jmp	.Lfail

.Lfail2:
	xor	eax, eax
	jmp	.Lfail

	.section .note.GNU-stack,"",@progbits
