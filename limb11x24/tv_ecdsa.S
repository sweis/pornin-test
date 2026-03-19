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
	.byte	.Lfmul-.Ljt, .Lfadd-.Ljt, .Lfsub-.Ljt, fe_mul11-.Ljt
	.byte	.Lchklt-.Ljt, .Lchkz-.Ljt, .Linv-.Ljt, .Lnorm-.Ljt
	.byte	.Lset1-.Ljt, .Lcopy-.Ljt, .Lcopyhi-.Ljt

/* ── Handlers ──
 * bc_run preloads rdi=dst, rsi=s1, rdx=s2 (slot pointers), rcx=&cP.
 * All handlers may clobber rax, rcx, rdx, rsi, rdi, r8-r11.
 * Must preserve rbx (=&.Ljt), rbp (fail bits), r14, r15.
 * (r12 wholly unused — jt ptr lives in rbx per-bcrun.)
 *
 * rcx high bytes are DIRTY (bc_run lea's a stack address) — every
 * `mov cl,N` would leave a huge rcx. Use push;pop for loop counters. */

.Lcopyhi: /* 8 slots from s1 → slot 16-23. bc_v1 uses COPYHI(15,0,0):
 * bc_run preloads rdi = r14 + 15·SLOT; handler adds just SLOT (disp8). */
	add	rdi, SLOT
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

/* Fadd/Fsub merged: r8 ∈ {+1,−1}; imul r9,r8 conditionally negates.
 * 34→32 B (ported from limb5x56 fc89ce3). imul ~3 cyc/iter but the
 * `loop` it shares a body with is ~7 — FAST swaps just the loop. */
.Lfsub:
	push	-1
	jmp	1f
.Lfadd:
	push	1
1:	pop	r8
	push	K
	pop	rcx
2:	lodsq
	mov	r9, [rdx]
	imul	r9, r8
	add	rax, r9
	stosq
	lea	rdx, [rdx+8]
#ifdef FAST
	dec	ecx
	jnz	2b
#else
	loop	2b
#endif
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
	xor	ebp, r9d            /* bc_run saved dst nibble — 0 or 1 direct */
	ret

.Lchklt: /* bpl |= (s1 >= s2). Subtract-and-check-sign — works for
 * s2 in ANY limb form (signed cP, unsigned cN) since carry-prop
 * gives the true sign of value(s1)−value(s2). Writes to dst slot
 * (bc_v1 uses slot 0, overwritten by Fadd 0,5,5 before next read). */
	push	rdi
	call	.Lfsub
	pop	rdi                 /* back to dst; push/pop beats sub rdi,SLOT */
	call	.Lcprop             /* SF = sign of top limb */
	js	2f                  /* negative → s1 < s2 → pass */
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
	call	fe_mul11            /* dst = dst². r11d set by bc_run dispatch. */
	bt	dword ptr [rip + cN], ebx   /* rodata IS n-2 now */
	jnc	.Lnx
.Lmul:	pop	rdi
	pop	rdx                 /* rdx = src */
	push	rdx
	push	rdi                 /* stack restored */
	push	rdi
	pop	rsi
	call	fe_mul11
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
	/* All NORM bytecode has dst==s1 → bc_run gives rdi==rsi already.
	 * Modulus = r15 (&cP — set in verify, preserved everywhere). */
	call	.Lcprop             /* SF = sign of top limb (from final add) */
	/* While top < 0: add m, re-carry. */
1:	jns	2f
	call	.Laddm              /* → .Lasmod → .Lcprop; SF at return */
	jmp	1b
	/* Subtract m until negative, then add m once. */
2:	push	-1
	pop	rdx                 /* non-REX pop (−1 B vs pop r9) */
	call	.Lasmod             /* → .Lcprop; SF at return */
	jns	2b
	/* fall into .Laddm for the final add; its tail ret returns. */

.Laddm:	/* [rdi] ±= [r8], carry-prop.  rdx ∈ {+1,−1}; imul rax,rdx (2-op
	 * form, rdx untouched) conditionally negates. 4 B vs xor+sub 6 B;
	 * push 1;pop rdx is +1 B vs xor edx. Net −1 B. */
	push	1
	pop	rdx
	/* falls through */
.Lasmod:
	push	rdi
	mov	rsi, r15            /* &cP — set once in verify */
	mov	cl, K               /* rcx=0 — all entry paths came through .Lcprop's loop */
1:	lodsq
	imul	rax, rdx
	add	[rdi], rax
	scasq
	loop	1b
	pop	rdi
	/* falls through */
.Lcprop:	/* in-place wrapper — fe_mul11 calls .Lcp_shared directly.
	 * SIGN FLAG AT RETURN: .Lcp_shared's final `add rax,rdx` sets SF
	 * from the top limb. stosq/pop/ret all preserve flags. All callers
	 * (NORM×2 + CHKLT) use js/jns directly. −12 B vs inline tests. */
	push	rdi
	push	rdi
	pop	rsi                 /* push;pop beats mov rsi,rdi by 1 B */
	call	.Lcp_shared
	pop	rdi
	ret

/* ── .Lfmul — end of handlers so it falls through into fe_mul11.
 * Nmul's jt entry points DIRECTLY at fe_mul11 (offset < 256); bc_run
 * pre-sets r11d=0xBC4F before every dispatch. .Lfmul overrides to 1.
 * INV's 510 fe_mul11 calls inherit the bc_run-set r11d. ── */
.Lfmul: /* Fmul — MontMul mod p. m0inv = 1.  MULR2 = Fmul with s2=15. */
	mov	rcx, r15            /* &cP (set in verify). 3 B vs sub rcx,SLOT 4 B. */
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

/* .Lin is THE hotspot: 2 calls/CIOS row × 11 rows × ~7K fe_mul11 ≈ 1.7M
 * iterations. `loop` (~7 cyc microcoded) + `scasq` (~3 cyc + store-fwd
 * stall from the add [rdi] right above) dominate. FAST costs +4 B.
 * (lodsq→mov;add tested: +5 B, ~30K cyc — OoO hides it behind imul.) */
.Lcnt:	mov	cl, K               /* callers have rcx=0 */
.Lin:	lodsq
	imul	rbx
	add	[rdi], rax
#ifdef FAST
	add	rdi, 8
	dec	ecx
	jnz	.Lin
#else
	scasq
	loop	.Lin
#endif
	ret

/* ── .Lcp_shared + decoders — moved here (after fe_mul11) to keep
 * the handler region under 256 B for the jt u8 constraint. ── */

.Lcp_shared:	/* out-of-place carry-prop rsi → rdi. ~77K iters —
 * FAST doesn't touch: +3 B bought <10K cyc (store-fwd handles push;pop). */
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
	mov	cl, 32              /* rcx ∈ {65,0} at entry (pub_len or fe_from_le exit) — high bytes clean */
1:	lodsb
	mov	[rdi + rcx + 55], al  /* rcx 32→1 → rdi+87→rdi+56. SIB+disp8. */
	loop	1b
	push	rsi                 /* = src+32 (lodsb advanced it) */
	lea	rsi, [rdi + 56]     /* rdi untouched by this loop */
	call	fe_from_le
	pop	rsi
	ret

fe_from_le:
	mov	cl, K-1             /* rcx ∈ {0,1,2,3} — fe_from_be loop, rep stosq, or LE-loop counter */
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
	rep	movsq               /* rcx = 0 out — bcrun_off takes offset in rcx */
	jmp	bcrun_off           /* rel8 over pt_mul (~90 B) */

pt_mul:
	/* acc = ∞ = (0:1:0) done by bc_v1's tail (ZERO/SET1/ZERO ops).
	 * r15 = &cP (set in verify, untouched). rbx = packed bit counter;
	 * bcrun_off push/pops it around every dispatch.
	 *
	 * Packed bit counter: ebx = limb·64 + bit. bt [r10],ebx uses ebx as
	 * an absolute bit offset into the qword array — bit b of limb L is at
	 * bit offset L·64+b. Starts at (K-1)·64+(W-1) = 663, ends at 0, then
	 * dec→−1, sub→−41, jns falls out. Crossing: after dec from L·64+0,
	 * ebx = (L−1)·64+63 → (ebx+1)&63 == 0 → sub (64−W) to skip dead bits.
	 * (NOT cmp bl,W — bl is ebx mod 256, not mod 64. Ported from fc89ce3.)
	 * Frees r13 entirely (−4 B prolog). r10 survives bc_run (no handler). */
	lea	r10, [r14 + oU1]
	mov	ebx, (K-1)*64 + (W-1)
.Lpi:	/* Double: acc → addend, RCB(acc, acc). */
	mov	rsi, r14
	call	.Lcadd
	/* u1 bit */
	bt	[r10], ebx
	jnc	1f
	lea	rsi, [r14 + oBAK]
	call	.Lcadd
1:	/* u2 bit — u2 at oU1+SLOT; 88 fits disp8. */
	bt	[r10 + SLOT], ebx
	jnc	2f
	lea	rsi, [r14 + oBAK + 3*SLOT]
	call	.Lcadd
2:	dec	ebx
	lea	eax, [rbx+1]
	test	al, 63
	jnz	.Lpi
	sub	ebx, 64-W
	jns	.Lpi
	/* Dispatch final check — falls through. */
	push	obc_v3
	pop	rcx

bcrun_off:
	push	rbp
	push	rbx                 /* pt_mul's packed counter — survives all dispatches */
	/* .Ljt ptr in rbx — set HERE, not verify. xlatb (1 B) beats
	 * `mov al,[r12+rax]` (4 B, REX.B). r12 wholly unused → push/pop r12
	 * + lea r12 drop from verify (−11). Here: +1+7+1−3 = +6. Net −5.
	 * Handlers preserve rbx (fe_mul11 and .Linv push/pop; rest don't touch). */
	lea	rbx, [rip + .Ljt]
	lea	rsi, [rip + bc_rcb]
	add	rsi, rcx            /* offset — .Lcadd's rep movsq leaves rcx=0 */
	xor	ebp, ebp            /* fail-bit accumulator */
.Lbc:
	lodsw                       /* ax ← op; rsi += 2. High eax garbage — */
	test	al, al              /*   and eax,0xF below clears it. */
	jz	.Lbce
	push	rsi                 /* save bc_ptr before esi clobber */

	movzx	edi, ah
	mov	esi, edi
	and	esi, 0xF
	imul	esi, esi, SLOT
	add	rsi, r14
	shr	edi, 4
	mov	r9d, edi            /* raw dst nibble → CHKZ reads directly */
	imul	edi, edi, SLOT
	add	rdi, r14

	movzx	edx, al
	shr	edx, 4
	imul	edx, edx, SLOT
	add	rdx, r14

	and	eax, 0xF
	xlatb                       /* AL ← [RBX+AL]. 1 B. rax high bytes stay 0 from and. */
	add	rax, rbx
	lea	rcx, [r15 + SLOT]   /* &cN = &cP + SLOT (r15 disp8, was 7 B r14+disp32) */
	mov	r11d, 0xBC4F        /* n m0inv — Nmul jt entry = fe_mul11 direct */
	call	rax
	pop	rsi
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
	push	r14
	push	r15

	/* enter before checks → all paths go through leave. 3 pushes +
	 * ret addr + enter's rbp = −40. Frame pads 8 B for 16-align
	 * (40+2120=2160 ÷16). r12,r13 unused. */
	enter	NSLOTS * SLOT + 8, 0

	/* Speculative setup BEFORE checks (leave unwinds on fail path;
	 * register sets just wasted work). Reorder checks so sig_len (rsi)
	 * is tested FIRST, then lea rsi can clobber it. This pushes .Lfail
	 * 17 B closer to the tail jmp → reaches rel8. */
	xor	eax, eax
	mov	r14, rsp
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
	pop	rbx
	ret
.Lok:
	/* User inputs (BE). Qx,Qy,e chain 5,6,7 → rdi ends at slot 8. */
	lea	rdi, [r14 + 5*SLOT]
	call	fe_from_be          /* Qx → 5 */
	call	fe_from_be          /* Qy → 6 */
	pop	rsi                 /* hv */
	call	fe_from_be          /* e  → 7   rdi now at slot 8 */
	mov	r15, rdi            /* r15 = &cP — used by Fmul, NORM/Lasmod, bc_run */

	/* cP → slot 8, SIGNED limb form: (−1,0,0,0,1,0,0,0,1,−256,65536).
	 * p = 2^256 − 2^224 + 2^192 + 2^96 − 1 — five ±power-of-2 terms.
	 * Zero-fill then inc/dec patches. rdi inherited at slot 8, exits
	 * at slot 9.  fe_mul11/NORM arithmetic is already signed; CHKLT
	 * changed to Fsub-based to handle this. */
	xor	eax, eax
	mov	cl, K               /* rcx=0 — fe_from_le's loop exit */
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
	mov	cl, 3               /* rcx=0 — fe_from_le exit. Loop cR2_n, cGX, cGY. */
1:	push	rcx
	call	fe_from_le
	pop	rcx
	loop	1b

	pop	rsi                 /* sig */
	call	fe_from_be          /* r → 13 */
	call	fe_from_be          /* s → 14 */

	/* ── bc_v1 ── */
	push	obc_v1
	pop	rcx
	call	bcrun_off           /* returns eax = 0/−1 */
	push	rax                 /* bc_v1 fail flag — pt_mul safe on garbage */
	call	pt_mul              /* returns eax = 0/−1 via bc_v3 */
	pop	rdx
	or	eax, edx            /* −1 if either failed */
	inc	eax
	jmp	.Lfail

	.section .note.GNU-stack,"",@progbits
