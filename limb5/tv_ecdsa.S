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
 *   8     cP (signed-limb, built in verify) — RCB never writes
 *   9     cN — RCB never writes
 *   10    b — RCB never writes
 *   11-13 RCB scratch
 *   14    (r+n) — RCB never writes
 *   15    one — RCB never writes
 *   16-21 Shamir backups
 *   22,23 u1, u2
 *
 * cP at 8 (not 9): verify builds it right after the BE chain (rdi
 * already points there), then the 4-iter LE loop chains straight
 * through without an unrolled fe_from_le call. */
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

/* Constants — 32 LE bytes each. Chain: cN→9, cR2N→10, Gx→11, Gy→12.
 * cP built signed-form in verify (−32 B rodata). cN stored as n−2
 * (low byte 0x4F not 0x51) so .Linv can `bt` directly without
 * special-casing bits 0..4. bc_v1 adds 2 back in slot 9 (two limbwise
 * Fadd with 1@15) before the range checks. */
cN:	.quad	0xf3b9cac2fc63254f, 0xbce6faada7179e84     /* n − 2 */
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
	.byte	.Lset1-.Ljt, .Lcopy-.Ljt, .Lcopyhi-.Ljt
	/* ZERO dropped (Fsub(x,x)=0). CHKNZ dropped (CHKZ dst=1 = flip). */

/* ── Handlers ──
 * bc_run preloads rdi=dst, rsi=s1, rdx=s2 (slot pointers), rcx=&cN.
 * All handlers may clobber rax, rcx, rdx, rsi, rdi, r8-r11.
 * Must preserve rbx (bc ptr), r12 (jt), rbp (fail bits), r13 (MASK),
 * r14 (slot base), r15 (unused here — pt_mul's counter).
 *
 * Layout: .Lfmul → .Lnmul → .Linv → fe_mul5. .Linv body fits between
 * .Lnmul and fe_mul5 (46 B) — .Lfmul's jmp is rel8 over 58 B, .Linv's
 * jt entry lands at ~223. No stub needed (−5 B). .Lnmul pays +2 B for
 * its jmp but that's still net −3 B. */

.Lcopyhi: /* 8 slots from s1 → slots 16..23. Single call: dst=15 encoded
 * in bc_v1 so bc_run gives rdi = r14+600; +SLOT → 640 (disp8 imm). */
	add	rdi, SLOT
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
	inc	byte ptr [rdi - K*8]   /* slot is all-zero → byte inc ≡ qword inc */
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

/* CHKZ with dst-as-flag: dst=0 → shift (s1≠0) into ebp; dst=1 → shift
 * (s1==0). rdi = r14 + dst·SLOT from bc_run; dst·SLOT is 0 or 40.
 * 40>>5 = 1. xor ebp with that bit AFTER the rcl → flips bit 0 iff dst=1. */
.Lchkz:
	xor	edx, edx
	push	K
	pop	rcx
1:	lodsq
	or	rdx, rax
	loop	1b
	neg	rdx                 /* CF = (rdx != 0) */
	rcl	ebp, 1
	sub	rdi, r14
	shr	edi, 5              /* 0 or 1 */
	xor	ebp, edi
	ret

/* CHKLT — bpl |= (s1 ≥ s2). Subtract-and-check-sign: Fsub then
 * cprop → SF = sign of value(s1)−value(s2). Works for s2 in any
 * limb form (signed cP, unsigned cN) since cprop delivers the true
 * sign of the integer difference. dst (slot 0 in bc_v1) is scratch.
 * .Lcprop's last `add [rdi],rdx` sets SF; pop/ret preserve flags. */
.Lchklt:
	push	rdi
	call	.Lfsub
	pop	rdi
	call	.Lcprop
	js	2f
	inc	ebp
2:	ret

/* ── NORM — bring value to [0, p). In-place on s1. .Lcprop's last
 * `add [rdi],rdx` sets SF from the top limb; .Laddm/.Lsubm both fall
 * into .Lcprop so SF is live at every loop head. ── */
.Lnorm:
	lea	r8, [rcx - SLOT]    /* &cN − SLOT = &cP (slot 8) */
	push	rsi
	pop	rdi
	call	.Lcprop
1:	jns	2f
	call	.Laddm
	jmp	1b
2:	call	.Lsubm
	jns	2b
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
1:	add	rdx, [rdi]          /* rdx = running carry + limb */
	push	rdx
	pop	rax                 /* 2 B copy; rdx kept for sar */
	and	rax, r13
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

.Lfmul: /* MontMul mod p. rel8 over .Lnmul + .Linv (58 B). */
	sub	rcx, SLOT           /* cP = cN − 1 slot (slot 8) */
	push	1
	pop	r11
	jmp	fe_mul5

.Lnmul: /* MontMul mod n. fe_mul5 preserves rcx so INV's 384 calls
 * all inherit &cN. */
	movabs	r11, 0x11c8aaee00bc4f
	jmp	fe_mul5             /* rel8 — over .Linv body (46 B) */

/* ── INV — s^(n−2) mod n via Fermat. n−2 stored directly in rodata
 * so `bt` works on all bits without special-casing. Lives here (between
 * .Lnmul and fe_mul5) so it fits the u8 jt slot directly — no stub. ── */
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
	bt	dword ptr [rip + cN], ebx   /* cN stored as n−2 */
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

/* Dispatch tail — lives here so both `jmp .Lfail` (up, −32) and the
 * final `jmp .Ltail` (up, from .Lok end) fit rel8. Inlined at the end
 * of .Lok it blows the .Lfail jmp past −128. */
.Ltail:
	push	obc_v1
	pop	rdi
	call	bcrun_off
	push	rax
	call	pt_mul
	pop	rdx
	or	eax, edx
	inc	eax
	jmp	.Lfail

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
	call	fe_from_be          /* e  → 7; rdi = slot 8 */

	/* cP → slot 8, SIGNED limb form: (−1, 2^42, 0, 2^30, 2^40−256).
	 * p = 2^256 − 2^224 + 2^192 + 2^96 − 1 — five ±power-of-2 terms.
	 * Zero-fill then 4 patches. fe_mul5/NORM arithmetic is already
	 * signed (imul, 128-bit acc); CHKLT changed to Fsub-based.
	 * rep stosd: 2 B (no REX.W), 10 dwords = 5 qwords. */
	xor	eax, eax
	push	K*2
	pop	rcx
	rep	stosd                       /* all zero; rdi → slot 9 */
	dec	qword ptr [rdi - 40]        /* limb 0 = −1 */
	mov	byte ptr [rdi - 27], 0x04   /* limb 1 byte 5: 2^42 */
	mov	byte ptr [rdi - 13], 0x40   /* limb 3 byte 3: 2^30 */
	dec	dword ptr [rdi - 7]         /* limb 4 bytes 1-4: 2^40−256 = 0x00FFFFFFFF00 */

	/* Constants (LE). cN,cR2N,cGX,cGY → 9,10,11,12. Stack-slot counter:
	 * fe_from_le doesn't push (no call, no frame), so [rsp] stays put. */
	lea	rdx, [rip + cN]
	push	4
1:	call	fe_from_le
	dec	byte ptr [rsp]
	jnz	1b
	pop	rcx                         /* discard */

	jmp	.Ltail

	.section .note.GNU-stack,"",@progbits
