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
 *   16,17 u1, u2 scalars (normalized [0,n) for bit-read)
 *   18-23 Shamir backups (G @ 18-20, Q @ 21-23)
 *
 * (Names can't be sP/sN — Intel-syntax regs are case-insensitive.) */
	.equ	oADD,   5*SLOT
	.equ	oCP,    8*SLOT
	.equ	oCN,    9*SLOT
	.equ	oR2,    15*SLOT
	.equ	oU1,    16*SLOT     /* 8-slot COPYHI: 0-7 → 16-23 */
	.equ	oBAK,   18*SLOT     /*   [u1,u2,Gbak(3),Qbak(3)] */

/* ======================================================================
 * RODATA — before .text so bytecode stream offsets fit push-imm8
 * ====================================================================== */
	.section .rodata, "a"

.include "bytecode.inc"

/* Constants — 32 LE bytes each. cR2_p DROPPED — projective scale-
 * invariance lets Q stay plain (level 0) and G scale by Gx_mont.
 * rodata: cN,cR2N,cGX,cGY → 4 constants (128 B). Chain 9,10 → 2,3. */
/* cN stores n−2 (not n) — INV's bt reads the Fermat exponent directly,
 * no cmp/jb/je special-case. verify +2's slot 9 after decode (only low
 * byte differs: 0x4f vs 0x51). */
cN:	.quad	0xf3b9cac2fc63254f, 0xbce6faada7179e84
	.quad	0xffffffffffffffff, 0xffffffff00000000
cR2N:	.quad	0x0f80d88a9a9fedcf, 0x6ab8c68a2abb372e
	.quad	0xb2392b6bec596190, 0x2d955aba561fc164
cGX:	.quad	0xe730d418a9143c18, 0xba95fc47edb60179
	.quad	0xfb732b7762251075, 0x905f76bd3755c661
cGY:	.quad	0xf25357ce95560a85, 0x4ab8e43519e45cdd
	.quad	0xe88688dd21f3258b, 0x71ff18aa885d854d

/* ======================================================================
 * TEXT
 * ====================================================================== */
	.text

/* ── Jump table — must be in .text so .Lop−.Ljt is a same-section
 * constant. gas .if can't forward-ref, so the u8-fit assert lives
 * at the end of the file (after all .Lop labels are defined). ── */
.Ljt:
	.byte	.Lfmul-.Ljt, .Lfadd-.Ljt, .Lfsub-.Ljt, .Lnmul-.Ljt
	.byte	.Lchklt-.Ljt, .Lchkz-.Ljt, .Linv-.Ljt, .Lnorm-.Ljt
	.byte	.Lset1-.Ljt, .Lcopy-.Ljt, .Lcopyhi-.Ljt

/* ── Handlers ──
 * bc_run preloads rdi=dst, rsi=s1, rdx=s2 (slot pointers), rcx=&cP.
 * All handlers may clobber rax, rcx, rdx, rsi, rdi, r8-r11.
 * Must preserve rbx (bytecode ptr), r12 (jt), rbp (fail bits), r14.
 *
 * rcx high bytes are DIRTY (bc_run lea's a stack address) — every
 * `mov cl,N` would leave a huge rcx. Use push;pop for loop counters. */

.Lcopyhi: /* 8 slots from s1 → slot(dst+16). bc_v1 stages 0-7 then
 * single COPYHI(0,0,0) → 16-23. 8*K = 88 fits push imm8. */
	add	rdi, 16*SLOT
	push	8*K
	jmp	.Lcopy_n
.Lcopy:
	push	K
.Lcopy_n:
	pop	rcx
	rep	movsq
	ret

.Lset1: /* dst = {1, 0, ..., 0}.  (ZERO dropped — Fsub(x,x)=0 in bytecode.) */
	xor	eax, eax
	push	K
	pop	rcx
	rep	stosq
	inc	byte ptr [rdi - SLOT]    /* 3 B (vs inc qword 4 B); slot is all-zero */
	ret

.Lfadd: /* limbwise, no carry */
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

.Lchkz:  /* ebp bit 0 ← (s1 != 0) XOR (dst == 1). CHKNZ = CHKZ with dst=1.
  * bc_run sets rdi = r14 + dst·SLOT.  dst·SLOT ∈ {0, 88}; 88>>6 = 1. */
	xor	edx, edx
	push	K
	pop	rcx
1:	lodsq
	or	rdx, rax
	loop	1b
	neg	rdx                 /* CF = (rdx != 0) */
	rcl	ebp, 1              /* CF → bit 0; prior bits shifted up */
	sub	rdi, r14
	shr	edi, 6              /* 0 or 88 → 0 or 1 */
	xor	ebp, edi
	ret

.Lchklt: /* bpl |= (s1 >= s2). Subtract-and-check-sign — works for
 * s2 in ANY limb form (signed cP, unsigned cN) since carry-prop
 * gives the true sign of value(s1)−value(s2). Writes to dst slot
 * (bc_v1 uses slot 0, overwritten by Fadd 0,5,5 before next read). */
	push	rdi
	call	.Lfsub
	pop	rdi                 /* back to dst; push/pop beats sub rdi,SLOT */
	call	.Lcprop             /* tail sets sign flags */
	jnz	2f                  /* negative → s1 < s2 → pass */
	inc	ebp                 /* ≥ 0 → fail */
2:	ret

/* ── INV — s^(n-2) mod n via Fermat. ── */

.Linv:
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
	call	.Lnmul              /* dst = dst² */
	bt	dword ptr [rip + cN], ebx   /* rodata IS n-2 now */
	jnc	.Lnx
.Lmul:	pop	rdi
	pop	rdx                 /* rdx = src */
	push	rdx
	push	rdi                 /* stack restored */
	push	rdi
	pop	rsi
	call	.Lnmul
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

.Lnorm:
	lea	r8, [rcx - SLOT]    /* &cN − SLOT = &cP */
	push	rsi
	pop	rdi                 /* in-place on s1 */
	call	.Lcprop             /* tail-tests sign; jz = non-negative */
	/* While top < 0: add m, re-carry. */
1:	jz	2f
	call	.Laddm              /* → .Lasmod → .Lcprop; flags at return */
	jmp	1b
	/* Subtract m until negative, then add m once. */
2:	push	-1
	pop	rdx                 /* non-REX pop (−1 B vs pop r9) */
	call	.Lasmod             /* → .Lcprop; flags at return */
	jz	2b
	/* fall into .Laddm for the final add; its tail ret returns. */

.Laddm:	/* [rdi] += [r8], carry-prop.  rdx ∈ {0,−1} flag: xor/sub is a no-op
	 * when 0, two's-complement negate when −1. NORM's bc_run s2 arg is
	 * always 0 (unused) so rdx is free — saves REX on xor and pop. */
	xor	edx, edx
	/* falls through */
.Lasmod:
	push	rdi
	mov	rsi, r8
	push	K
	pop	rcx
1:	lodsq
	xor	rax, rdx
	sub	rax, rdx
	add	[rdi], rax
	scasq
	loop	1b
	pop	rdi
	/* falls through */
.Lcprop:	/* in-place wrapper — fe_mul11 calls .Lcp_shared directly.
	 * TAIL TESTS SIGN: all 3 callers (NORM×2 + CHKLT) branched on this
	 * immediately after. Hoist here; pop/ret preserve flags. −8 B net. */
	push	rdi
	push	rdi
	pop	rsi                 /* push;pop beats mov rsi,rdi by 1 B */
	call	.Lcp_shared
	pop	rdi
	test	byte ptr [rdi + K*8 - 1], 0x80
	ret

/* ── Fmul/Nmul — moved here (end of handlers) so .Lfmul falls through
 * into fe_mul11. Both offsets < 256 (jt u8). .Lnmul jmp rel8 over
 * .Lfmul's 8-B body. .Lcp_shared + decoders moved AFTER fe_mul11 to
 * keep handler region under 256. ── */
.Lnmul: /* Nmul — MontMul mod n.  bc_run preloads rcx=&cN; fe_mul11
 * preserves rcx (pop rcx not pop rax) so INV's 384 calls inherit it. */
	mov	r11d, 0xBC4F
	jmp	fe_mul11            /* rel8 — skips .Lfmul's 8 B */

.Lfmul: /* Fmul — MontMul mod p. m0inv = 1.  MULR2 = Fmul with s2=15. */
	sub	rcx, SLOT           /* &cN − SLOT = &cP */
	push	1
	pop	r11
	/* FALLS THROUGH into fe_mul11 — no jmp needed. */

/* ======================================================================
 * fe_mul11 — r11d = m0inv (set by Fmul=1 / Nmul=0xBC4F), rcx = m.
 * ====================================================================== */
fe_mul11:
	push	rbx
	push	rdi
	push	rcx                 /* m → [rbp+16] */
	push	rdx                 /* b → [rbp+8]  — no r12 needed */
	enter	2*K*8, 0

	xor	eax, eax
	lea	ecx, [rax + 2*K]
	push	rsp
	pop	rdi
	rep	stosq               /* rcx = 0 out */

	/* CIOS: for each row i, do schoolbook row + Montgomery reduce
	 * row in one pass.  a[i] indexed via [rsi+r9+K*8] — disp8=88 fits,
	 * no lea r8 needed. rsi bracketed across the two .Lcnt calls. */
	push	-K*8
	pop	r9
.Lcios:	mov	rbx, [rsi + r9 + K*8]       /* a[i] */
	lea	rdi, [rbp + r9 - K*8]       /* &acc[i] */
	push	rsi                         /* preserve &a[0] */
	push	rdi
	mov	rsi, [rbp + 8]              /* b */
	call	.Lcnt

	pop	rdi
	mov	eax, [rdi]
	imul	eax, r11d
	and	eax, MASK
	push	rax
	pop	rbx                         /* q */
	push	rdi
	mov	rsi, [rbp + 16]             /* m */
	call	.Lcnt

	pop	rdi
	mov	rax, [rdi]
	sar	rax, W
	add	[rdi + 8], rax

	pop	rsi
	add	r9, 8
	jnz	.Lcios

	lea	rsi, [rdi + 8]              /* &acc[K] — rdi ended at &acc[K-1] */
	mov	rdi, [rbp + 24]
	call	.Lcp_shared

	leave
	pop	rax                 /* discard b */
	pop	rcx                 /* restore — INV's 384 calls rely on this */
	pop	rax                 /* discard dst */
	pop	rbx
	ret

.Lcnt:	mov	cl, K               /* callers have rcx=0 */
.Lin:	lodsq
	imul	rbx
	add	[rdi], rax
	scasq
	loop	.Lin
	ret

/* ── .Lcp_shared + decoders — moved here (after fe_mul11) to keep
 * the handler region under 256 B for the jt u8 constraint. ── */

.Lcp_shared:	/* out-of-place carry-prop rsi → rdi. */
	xor	edx, edx
	push	K-1
	pop	rcx
1:	lodsq
	add	rax, rdx
	push	rax
	pop	rdx                 /* −1 B vs mov rdx,rax (3→2) */
	and	eax, MASK
	stosq
	sar	rdx, W
	loop	1b
	lodsq
	add	rax, rdx
	stosq
	ret

/* fe_from_be — byte-reverse into the unused top of the dst slot
 * (bytes 56-87), then decode from there with fe_from_le. Write
 * region [8i,8i+8) trails read region [56+3i,56+3i+4) by 5i−56 ≥ 0
 * for i < 11, so in-place is safe. Exits rsi = src+32, rdi = dst+88. */
fe_from_be:
	push	32
	pop	rcx
1:	lodsb
	mov	[rdi + rcx + 55], al  /* rcx 32→1 → rdi+87→rdi+56. SIB+disp8. */
	loop	1b
	push	rsi                 /* = src+32 (lodsb advanced it) */
	lea	rsi, [rdi + 56]     /* rdi untouched by this loop */
	call	fe_from_le
	pop	rsi
	ret

fe_from_le:
	push	K-1
	pop	rcx
1:	lodsd                       /* 1 B; rsi += 4 */
	dec	rsi                 /* net +3. Beats mov eax,[rsi]+add rsi,3 by 2 B */
	and	eax, MASK
	stosq
	loop	1b
	xor	eax, eax
	lodsw                       /* ax ← top 16 bits; rsi += 2 (chain) */
	stosq
	ret

/* ======================================================================
 * bc_run — bytecode interpreter
 * ====================================================================== */

/* .Lcadd: copy 3 slots from [rsi] → addend (slots 5-7), dispatch bc_rcb.
 * pt_mul sits between here and bcrun_off so its tail can fall through. */
.Lcadd:
	lea	rdi, [r14 + oADD]
	push	3*K
	pop	rcx
	rep	movsq
	xor	edi, edi            /* obc_rcb = 0 */
	jmp	bcrun_off           /* rel8 over pt_mul (~90 B) */

pt_mul:
	/* acc = ∞ = (0:1:0) done by bc_v1's tail (ZERO/SET1/ZERO ops).
	 * r15 hoists &u1; r12 stays = &.Ljt for bc_run. */
	lea	r15, [r14 + oU1]
	push	K-1
	pop	r13
.Lpo:	push	W-1
	pop	rbx
.Lpi:	/* Double: acc → addend, RCB(acc, acc). */
	mov	rsi, r14
	call	.Lcadd
	/* u1 bit */
	bt	[r15 + r13*8], ebx
	jnc	1f
	lea	rsi, [r14 + oBAK]
	call	.Lcadd
1:	/* u2 bit — u2 at oU1+SLOT; 88 fits disp8. */
	bt	[r15 + r13*8 + SLOT], ebx
	jnc	2f
	lea	rsi, [r14 + oBAK + 3*SLOT]
	call	.Lcadd
2:	dec	ebx
	jns	.Lpi
	dec	r13
	jns	.Lpo
	/* Dispatch final check — falls through. */
	push	obc_v3
	pop	rdi

bcrun_off:
	push	rbp
	push	rbx                 /* save first; lea goes straight to rbx */
	lea	rbx, [rip + bc_rcb]
	add	rbx, rdi
	xor	ebp, ebp            /* fail-bit accumulator */
	/* r12 = &.Ljt inherited from verify (set once, fe_mul11 preserves). */
.Lbc:
	mov	eax, [rbx]          /* over-reads 2 B — and eax,0xF later clears */
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
	mov	al, [r12 + rax]     /* high bytes already 0 from the and */
	add	rax, r12
	lea	rcx, [r14 + oCN]    /* cN; Fmul/NORM subtract SLOT for cP */
	call	rax
	jmp	.Lbc

.Lbce:	neg	ebp
	sbb	eax, eax            /* 0 pass, −1 fail */
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

	/* enter before checks → all paths go through leave. 5 pushes +
	 * ret addr + enter's rbp = −56, then 2112 (÷8). 16-align: pad
	 * frame to 2120 (+8 B stack, 0 B code — enter imm16). */
	enter	NSLOTS * SLOT + 8, 0

	/* Speculative setup BEFORE checks (leave unwinds on fail path;
	 * register sets just wasted work). Reorder checks so sig_len (rsi)
	 * is tested FIRST, then lea rsi can clobber it. This pushes .Lfail
	 * 17 B closer to the tail jmp → reaches rel8. */
	xor	eax, eax
	mov	r14, rsp
	lea	r12, [rip + .Ljt]   /* set once — survives all bc_run calls */
	push	rdi                 /* sig */
	push	r8                  /* hv  */

	cmp	rsi, 64             /* sig_len FIRST — before rsi clobber */
	jne	.Lfail
	lea	rsi, [rdx + 1]      /* pub+1 — rsi free now */
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
	/* User inputs (BE). Qx,Qy,e chain 5,6,7 → rdi ends at slot 8. */
	lea	rdi, [r14 + 5*SLOT]
	call	fe_from_be          /* Qx → 5 */
	call	fe_from_be          /* Qy → 6 */
	pop	rsi                 /* hv */
	call	fe_from_be          /* e  → 7   rdi now at slot 8 */

	/* cP → slot 8, SIGNED limb form: (−1,0,0,0,1,0,0,0,1,−256,65536).
	 * p = 2^256 − 2^224 + 2^192 + 2^96 − 1 — five ±power-of-2 terms.
	 * Zero-fill then inc/dec patches. rdi inherited at slot 8, exits
	 * at slot 9.  fe_mul11/NORM arithmetic is already signed; CHKLT
	 * changed to Fsub-based to handle this. */
	xor	eax, eax
	push	K
	pop	rcx
	rep	stosq               /* all zero; rdi → slot 9 */
	dec	qword ptr [rdi - 88]   /* limb 0 = −1 */
	inc	byte ptr [rdi - 56]    /* limb 4 = 1 (byte inc — slot is zeroed) */
	inc	byte ptr [rdi - 24]    /* limb 8 = 1 */
	dec	qword ptr [rdi - 16]   /* limb 9 = −1 ... */
	inc	byte ptr [rdi - 16]    /*   low byte → 0: = −256 */
	inc	byte ptr [rdi - 6]     /* limb 10 byte 2: = 65536 */

	/* Constants (LE). cN,cR2_n,cGX,cGY → 9,10,11,12 — all chain.
	 * Then r,s → 13,14 chain too. ZERO lea's after the Qx start. */
	lea	rsi, [rip + cN]
	call	fe_from_le          /* cN (= n−2) → 9; rdi now at slot 10 */
	add	byte ptr [rdi - SLOT], 2   /* slot 9 limb 0: 0x63254f → 0x632551 */
	call	fe_from_le          /* cR2_n → 10 */
	call	fe_from_le          /* cGX → 11 */
	call	fe_from_le          /* cGY → 12 */

	pop	rsi                 /* sig */
	call	fe_from_be          /* r → 13 */
	call	fe_from_be          /* s → 14 */

	/* ── bc_v1 ── */
	push	obc_v1
	pop	rdi
	call	bcrun_off           /* returns eax = 0/−1 */
	push	rax                 /* bc_v1 fail flag — pt_mul safe on garbage */
	call	pt_mul              /* returns eax = 0/−1 via bc_v3 */
	pop	rdx
	or	eax, edx            /* −1 if either failed */
	inc	eax
	jmp	.Lfail

	.section .note.GNU-stack,"",@progbits
