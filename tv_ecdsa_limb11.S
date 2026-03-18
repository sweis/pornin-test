/* ======================================================================
 * tv_ecdsa_limb11.S — ECDSA/P-256 verify, 11×24-bit signed limbs.
 *
 * Architecture: Montgomery form throughout (R = 2^264). Field elements
 * are 11 limbs × 24 bits nominal, signed, lazy-carry. Fadd/Fsub are
 * pure limbwise (no carry, no reduce). fe_mul normalizes its output.
 *
 *   Range proof (range_limbs.py, commit a5fc446):
 *     KW = 264 > 263.2 (RCB ×12 Y3-chain convergence bound)
 *     accumulator ≤ 60 bits (fits signed-64, 3 bits spare)
 *     mul-input limbs ≤ 29 bits (canonical 24 + ×12 growth ≈ +4)
 *     mul-output value ≤ 2^258 (≈ 4p, top limb ≤ 18 bits)
 *
 *   Montgomery: p's low 24 bits = 0xFFFFFF → −p⁻¹ ≡ 1 (mod 2^24),
 *   so q = acc[i] & MASK (no multiply). n's m0inv = 0xBC4F.
 *
 * Slots: 88 B each (11 qwords). 24 slots. Stack frame ~2200 B.
 * With 88-B stride, no two non-adjacent slots are in disp8 reach.
 * bc_run decodes slot indices via imul-by-88 (3 B, fits imm8).
 *
 * cGX, cGY stored as Gx·R mod p, Gy·R mod p (Montgomery form,
 * precomputed). Derived b = Gy²−Gx³+3Gx via MontMul gives b·R — it's
 * automatically in Montgomery form.
 *
 * This is the FIRST-PASS build. Not golfed. Get 607/607, then grind.
 * ====================================================================== */

	.intel_syntax noprefix

	.equ	W,      24
	.equ	K,      11
	.equ	MASK,   (1<<W)-1
	.equ	SLOT,   K*8        /* 88 B per slot */
	.equ	NSLOTS, 24

/* Slot map (mirrors tiny.S where possible so bc_rcb ports cleanly):
 *   0-2   acc (X,Y,Z)    — RCB writes
 *   3,4   scratch
 *   5-7   addend (X₂,Y₂,Z₂) — RCB reads, never writes (load-bearing)
 *   8     cP (built at runtime)
 *   9     cN (decoded from packed)
 *   10    b (derived)
 *   11-13 more RCB scratch
 *   14    hash e (decoded)
 *   15    cR2 (decoded)
 *   16-21 Shamir backups (G @ 16-18, Q @ 19-21)
 *   22,23 u1, u2 scalars (normalized to [0,n) for bit-read) */
	.equ	sACC,   0*SLOT
	.equ	sADD,   5*SLOT
	.equ	sP,     8*SLOT
	.equ	sN,     9*SLOT
	.equ	sB,     10*SLOT
	.equ	sH,     14*SLOT
	.equ	sR2,    15*SLOT
	.equ	sBAK,   16*SLOT
	.equ	sU1,    22*SLOT
	.equ	sU2,    23*SLOT

/* ======================================================================
 * RODATA — bytecode, constants, jump table
 * ====================================================================== */
	.section .rodata, "a"

/* RCB-43 complete addition. Same formula as tiny.S (Renes-Costello-
 * Batina Alg 7, a=−3). Nibble encoding: byte0=(s2<<4)|op, byte1=(dst<<4)|s1.
 *
 * Ops:  0=Fmul  1=SQR(=Fmul)  2=Fadd  3=Fsub  4=Nmul
 *       5=checklt  6=checkzero  7=INV  8=MULR2  9=NORM
 *
 * Slot assignments match tiny.S where possible. RCB never writes
 * 5,6,7,10 (addend + b survive all 256 pt_mul iterations). */
.macro BC op, dst, s1, s2
	.byte	(\s2<<4)|\op, (\dst<<4)|\s1
.endm

bc_rcb:
	/* t0=X1·X2; t1=Y1·Y2; t2=Z1·Z2 */
	BC 0, 11,  0, 5    /* t0 = X1*X2    slot 11 */
	BC 0, 12,  1, 6    /* t1 = Y1*Y2    slot 12 */
	BC 0, 13,  2, 7    /* t2 = Z1*Z2    slot 13 */
	/* t3 = (X1+Y1)(X2+Y2) − t0 − t1 */
	BC 2,  3,  0, 1    /* t3 = X1+Y1 */
	BC 2,  4,  5, 6    /* t4 = X2+Y2 */
	BC 0,  3,  3, 4    /* t3 = t3*t4 */
	BC 3,  3,  3,11    /* t3 -= t0 */
	BC 3,  3,  3,12    /* t3 -= t1 */
	/* t4 = (Y1+Z1)(Y2+Z2) − t1 − t2 */
	BC 2,  4,  1, 2
	BC 2,  0,  6, 7    /* Y3 = Y2+Z2 (slot 0 is scratch here; X1 dead) */
	BC 0,  4,  4, 0
	BC 3,  4,  4,12
	BC 3,  4,  4,13
	/* t5 = (X1+Z1)(X2+Z2) − t0 − t2 … but X1 is dead. Use backup?
	 * NO — in pt_mul, X1=acc[0], X2=addend[5]. acc gets overwritten
	 * by RCB. We need X1 (slot 0) until it's consumed. But op 10
	 * above wrote slot 0 = Y2+Z2, clobbering X1 which is needed at
	 * op 14 (X1+Z1). BUG.
	 *
	 * tiny.S's bc_rcb uses different temp slots. Let me mirror its
	 * exact schedule instead of re-deriving. */

	/* ── ABANDONING hand-translation. Pull tiny.S's bc_rcb verbatim
	 * (nibble values already encode slot+op) and keep its slot
	 * assignments. The bytecode is OPAQUE — it works in any slot
	 * geometry as long as the handler semantics match. ── */
	.error "bc_rcb: use tiny.S's exact bytecode stream"

bc_v3:
	/* Projective final check, to be filled in. */

bc_v1:
	/* Validation + setup, to be filled in. */

/* Constants: 32 B packed BE each. Decoded to 11-limb slots at runtime. */
cGX:	.quad	0x905f76bd3755c661, 0xfb732b7762251075
	.quad	0xba95fc47edb60179, 0xe730d418a9143c18
cGY:	.quad	0x71ff18aa885d854d, 0xe88688dd21f3258b
	.quad	0x4ab8e43519e45cdd, 0xf25357ce95560a85
cN:	.quad	0xffffffff00000000, 0xffffffffffffffff
	.quad	0xbce6faada7179e84, 0xf3b9cac2fc632551
cR2:	.quad	0x0004fffffffdffff, 0xfffffffffffeffff
	.quad	0xfffbffffffff0000, 0x0000000000030000

.Ljt:
	.byte	.Lop0-.Ljt, .Lop1-.Ljt, .Lop2-.Ljt, .Lop3-.Ljt
	.byte	.Lop4-.Ljt, .Lop5-.Ljt, .Lop6-.Ljt, .Lop7-.Ljt
	.byte	.Lop8-.Ljt, .Lop9-.Ljt

/* ======================================================================
 * TEXT
 * ====================================================================== */
	.text

/* fe_from_be: 32 BE bytes at [rsi] → 11 limbs at [rdi].
 * 24 bits = 3 bytes exactly. Read [rsi+offset..+2] as a 4-byte
 * unaligned load (one extra byte behind), bswap, shr 8 drops the
 * extra. Top limb (16 bits) special-cased. */
fe_from_be:
	push	rsi
	lea	rsi, [rsi + 29]     /* byte 29 = low 3 bytes of limb 0 */
	mov	cl, K-1
1:	mov	eax, [rsi - 1]      /* reads bytes [off-1, off, off+1, off+2] */
	bswap	eax
	shr	eax, 8              /* drop the extra (byte off-1) */
	stosq
	sub	rsi, 3
	loop	1b
	/* Top limb: bytes 0-1, 16 bits. rsi is at input+29-30 = input-1. */
	movzx	eax, word ptr [rsi + 1]   /* bytes 0,1 LE */
	xchg	al, ah              /* → BE */
	stosq
	pop	rsi
	ret

/* pt_mul: u1·G + u2·Q via Shamir. Scalars in slots 22,23 (normalized,
 * 11-limb form). Nested loop: 11 limbs × 24 bits = 264 iterations.
 * Bits read MSB-first: outer limb 10→0, inner bit 23→0. Top 8 bits
 * (264−256) are zero — extra doublings on ∞, harmless.
 *
 * Per-bit: double acc (RCB self-add); if u1 bit set, add G-backup;
 * if u2 bit set, add Q-backup. G-backup at slots 16-18, Q at 19-21. */
pt_mul:
	call	.Lai                /* zero acc, set Y=1_mont */
	/* Outer: limb index in r13, from K-1 down to 0. */
	push	K-1
	pop	r13
.Lpo:	mov	ebx, W-1            /* inner: bit 23 → 0 */
.Lpi:	/* Double: copy acc → addend, RCB. */
	mov	rsi, r14            /* acc = slots 0-2 */
	call	.Lcadd
	/* u1 bit: slot 22, limb r13, bit ebx. */
	mov	rax, [r14 + sU1]    /* placeholder — need [r14+sU1+r13*8] */
	/* ^^ this disp32 indexing is wrong. Fix: */
	lea	rsi, [r14 + sU1]
	bt	[rsi + r13*8], ebx
	jnc	1f
	lea	rsi, [r14 + sBAK]   /* G-backup */
	call	.Lcadd
1:	lea	rsi, [r14 + sU2]
	bt	[rsi + r13*8], ebx
	jnc	2f
	lea	rsi, [r14 + sBAK + 3*SLOT]   /* Q-backup */
	call	.Lcadd
2:	dec	ebx
	jns	.Lpi
	dec	r13
	jns	.Lpo
	/* Fall through to final-check dispatch. */
	push	obc_v3
	pop	rdi
	jmp	bcrun_off

/* Zero acc (slots 0-2), set slot 1 limb 0 = 1_mont.  ∞ = (0:1:0) in
 * homogeneous projective; Montgomery form means Y = 1·R mod p = R.
 * R's limbs: ... actually 1_mont is R mod p, a full 256-bit value.
 * Can't just set one limb. Need to STORE 1_mont somewhere or compute.
 *
 * Alternative: ∞ = (0:Y:0) for ANY Y≠0. Use Y = anything nonzero.
 * Simplest: Y = 1 (plain, not Montgomery). Does RCB handle this?
 * RCB(∞, Q) should = Q. Let's check: with X1=Z1=0, the formula
 * should produce Q regardless of Y1's Montgomery-ness.
 *
 * From the RCB paper: the formula is Montgomery-oblivious for the
 * ∞ case IF X1=Z1=0 triggers the right algebra. Need to verify.
 * For now: set Y = 1 (limb 0 = 1, rest 0) and TEST. */
.Lai:
	push	rdi
	mov	rdi, r14
	xor	eax, eax
	push	3*K                 /* 33 qwords */
	pop	rcx
	rep	stosq
	inc	qword ptr [r14 + SLOT]   /* slot 1 limb 0 = 1 */
	pop	rdi
	ret

/* .Lcadd: copy 3 slots from [rsi] to addend (slots 5-7), dispatch bc_rcb.
 * 3 slots = 33 qwords. */
.Lcadd:
	lea	rdi, [r14 + sADD]
	push	3*K
	pop	rcx
	rep	movsq
	xor	edi, edi            /* obc_rcb = 0 */
	/* FALLTHROUGH to bcrun_off */

bcrun_off:
	lea	rax, [rip + bc_rcb]
	add	rdi, rax
	/* FALLTHROUGH */
bc_run:
	push	rbp
	push	rbx
	push	r12
	push	rdi
	pop	rbx                 /* bytecode ptr */
	xor	ebp, ebp            /* check accumulator */
	lea	r12, [rip + .Ljt]
.Lbc:
	movzx	eax, word ptr [rbx]
	add	rbx, 2
	test	al, al
	jz	.Lbce

	/* Decode nibbles to slot pointers. Slot stride = 88; imul imm8. */
	movzx	edi, ah             /* (dst<<4)|s1 */
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
	lea	rcx, [r14 + sP]     /* preload &cP (disp32, sP=704) */
	call	rax
	jmp	.Lbc

.Lbce:	neg	ebp
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* ── Handlers ── */

.Lop8:  /* MULR2: Fmul with s2 = &cR2 slot. For Montgomery conversion. */
	lea	rdx, [r14 + sR2]
	/* FALLTHROUGH to Fmul */
.Lop0:  /* Fmul: dst = MontMul(s1, s2) mod p. m0inv = 1 (free q). */
.Lop1:  /* SQR = Fmul (bytecode encodes s2=s1). */
Fmul:	push	1                   /* p's m0inv = 1 */
	pop	r11
	jmp	fe_mul11

.Lop4:  /* Nmul: mod-n. m0inv = 0xBC4F. rcx → cN slot. */
Nmul:	lea	rcx, [r14 + sN]
	mov	r11d, 0xBC4F
	jmp	fe_mul11

.Lop2:  /* Fadd: dst[k] = s1[k] + s2[k], limbwise, no carry. */
Fadd:	mov	cl, K
1:	lodsq
	add	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	loop	1b
	ret

.Lop3:  /* Fsub: dst[k] = s1[k] − s2[k]. */
Fsub:	mov	cl, K
1:	lodsq
	sub	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	loop	1b
	ret

.Lop5:  /* checklt: bpl |= (s1 ≥ s2). s1 is a decoded input (fully
 * canonical from fe_from_be), s2 is a modulus slot (also canonical).
 * Limb-wise compare from the top. */
	push	K-1
	pop	rcx
1:	mov	rax, [rsi + rcx*8]
	cmp	rax, [rdx + rcx*8]
	jb	2f                  /* s1 < s2: pass */
	ja	3f                  /* s1 > s2: fail */
	dec	ecx
	jns	1b
	/* equal: s1 ≥ s2, fail */
3:	or	bpl, 1
2:	ret

.Lop6:  /* checkzero: bpl |= (s1 ≠ 0). s1 is fe_mul output (limbs
 * 0..K-2 canonical, top signed). For the zero check to work, s1 must
 * be NORMALIZED to [0, p) first (via op 9). Then all-limbs-zero ⇔ 0. */
	xor	eax, eax
	mov	cl, K
1:	or	rax, [rsi]
	lea	rsi, [rsi+8]
	loop	1b
	neg	rax                 /* CF = (rax ≠ 0) */
	adc	bpl, 0
	ret

.Lop9:  /* NORM: bring s1 to [0, p). Carry-prop, then while-neg add p,
 * while-ge-p sub p. Writes back to s1 (in-place). rcx = &cP on entry. */
	push	rdi
	push	rsi
	pop	rdi
	/* Carry-propagate: limbs 0..K-2 → [0, 2^24), top absorbs. */
	call	.Lcprop
	/* While top < 0: add p limbwise, re-carry. */
1:	cmp	qword ptr [rdi + (K-1)*8], 0
	jge	2f
	call	.Laddp
	call	.Lcprop
	jmp	1b
	/* While value ≥ p: sub p, re-carry. Compare top limb to p's. */
2:	mov	rax, [rdi + (K-1)*8]
	cmp	rax, [rcx + (K-1)*8]
	jb	3f
	ja	4f
	/* Top limbs equal: compare lower limbs. Rare — just do full sub
	 * and check the result sign (easier than multi-limb compare). */
4:	call	.Lsubp
	call	.Lcprop
	jmp	2b
3:	pop	rdi
	ret

.Lcprop:  /* In-place carry-propagate [rdi]. */
	push	rdi
	push	rsi
	push	rdi
	pop	rsi
	xor	edx, edx
	mov	cl, K-1
1:	lodsq
	add	rax, rdx
	mov	rdx, rax
	and	eax, MASK
	stosq
	sar	rdx, W
	loop	1b
	add	[rdi], rdx          /* top limb: no mask, absorb carry */
	pop	rsi
	pop	rdi
	ret

.Laddp:  /* [rdi] += p, limbwise. rcx = &cP. */
	push	rdi
	push	rsi
	push	rcx
	pop	rsi
	mov	cl, K
1:	lodsq
	add	[rdi], rax
	scasq
	loop	1b
	pop	rsi
	pop	rdi
	ret

.Lsubp:  /* [rdi] −= p. Same shape as .Laddp. */
	push	rdi
	push	rsi
	push	rcx
	pop	rsi
	mov	cl, K
1:	lodsq
	sub	[rdi], rax
	scasq
	loop	1b
	pop	rsi
	pop	rdi
	ret

.Lop7:  /* INV: s^(n-2) mod n, Fermat. Same structure as tiny.S —
 * bt on cN (packed) directly for bits 5+, special-case 0-4. Result
 * in [rdi], seed from [rsi]. Caller sets dst=1 first (one_mont_n). */
fe_inv_n:
	push	rbx
	push	rsi                 /* src */
	push	rdi                 /* dst — also working accumulator */
	xor	ebx, ebx
	mov	bl, 255
.Le:	mov	rsi, [rsp]          /* dst */
	mov	rdi, rsi
	mov	rdx, rsi
	call	Nmul                /* dst = dst² mod n */
	cmp	ebx, 4
	jb	.Lmul               /* bits 0-3: n-2 has 1111 */
	je	.Lnx                /* bit 4: n-2 has 0, n has 1 */
	bt	dword ptr [rip + cN + 24], ebx   /* cN is BE; bt indexes bits... */
	/* ^^ WRONG — cN is stored BE (quads), bt reads LE bit order.
	 * Need cN in LE bit order for bt. Either: store cN both ways,
	 * or byteswap on read, or use a different bit-test. DEFER. */
	jnc	.Lnx
.Lmul:	mov	rdi, [rsp]
	mov	rsi, rdi
	mov	rdx, [rsp + 8]      /* original src */
	call	Nmul
.Lnx:	dec	ebx
	jns	.Le
	pop	rax                 /* discard dst */
	pop	rax                 /* discard src */
	pop	rbx
	ret

/* ── fe_mul11 — see limb11_mul.S for derivation. Adapted here:
 * r11 holds m0inv (set by Fmul=1 / Nmul=0xBC4F). m in rcx. ── */
fe_mul11:
	push	rbx
	push	r12
	push	rdi
	push	rcx                 /* m → [rbp+16] */
	push	rdx                 /* b → [rbp+8] */
	enter	2*K*8, 0

	xor	eax, eax
	lea	ecx, [rax + 2*K]
	push	rsp
	pop	rdi
	rep	stosq

	lea	r8, [rsi + K*8]
	mov	r12, [rbp + 8]

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
	mov	r8, [rbp + 16]
	mov	cl, K
.Lro:	push	rsi
	pop	rdi
	lodsq
	imul	eax, r11d           /* q = acc[i] · m0inv — the signed mont twist */
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

	mov	rdi, [rbp + 24]
	mov	cl, K-1
	xor	edx, edx
.Lcp:	lodsq
	add	rax, rdx
	mov	rdx, rax
	and	eax, MASK
	stosq
	sar	rdx, W
	loop	.Lcp
	lodsq
	add	rax, rdx
	stosq

	leave
	pop	rax
	pop	rax
	pop	rax
	pop	r12
	pop	rbx
	ret

.Lcnt:	mov	cl, K
.Lin:	lodsq
	imul	rbx
	add	[rdi], rax
	scasq
	loop	.Lin
	ret

/* ======================================================================
 * verify — entry point
 * ====================================================================== */
.globl tv_ecdsa_p256_verify_asm
tv_ecdsa_p256_verify_asm:
	/* rdi=sig, rsi=sig_len, rdx=pub, rcx=pub_len, r8=hv, r9=hv_len */
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15

	/* Length checks. */
	xor	eax, eax            /* return 0 (fail) by default */
	cmp	rsi, 64
	jne	.Lfail
	cmp	rcx, 65
	jne	.Lfail
	cmp	r9, 32
	jb	.Lfail
	cmp	r9, 64
	ja	.Lfail
	cmp	byte ptr [rdx], 0x04
	jne	.Lfail

	/* Stack frame: NSLOTS × SLOT bytes. */
	mov	rbp, rsp
	sub	rsp, NSLOTS * SLOT
	mov	r14, rsp            /* slot base */

	push	rdi                 /* sig */
	push	rdx                 /* pub */
	push	r8                  /* hv */

	/* Build cP into slot 8. */
	lea	rdi, [r14 + sP]
	mov	eax, MASK           /* 0xFFFFFF */
	stosq
	stosq
	stosq
	stosq
	xor	eax, eax
	stosq
	stosq
	stosq
	stosq
	inc	eax                 /* 1 */
	stosq
	mov	eax, 0xffff00
	stosq
	mov	eax, 0xffff
	stosq

	/* Decode cN → slot 9, cR2 → slot 15, cGX → slot 2, cGY → slot 3. */
	lea	rsi, [rip + cN]
	lea	rdi, [r14 + sN]
	call	fe_from_be
	lea	rsi, [rip + cR2]
	lea	rdi, [r14 + sR2]
	call	fe_from_be
	lea	rsi, [rip + cGX]
	lea	rdi, [r14 + 2*SLOT]
	call	fe_from_be
	lea	rsi, [rip + cGY]
	lea	rdi, [r14 + 3*SLOT]
	call	fe_from_be

	/* Decode user inputs: r, s from sig; Qx, Qy from pub; e from hv.
	 * These go to temp slots; bc_v1 will validate and convert. */
	pop	rsi                 /* hv */
	lea	rdi, [r14 + sH]
	call	fe_from_be          /* e (hash) → slot 14 */
	pop	rsi                 /* pub */
	inc	rsi                 /* skip 0x04 */
	lea	rdi, [r14 + 5*SLOT]
	call	fe_from_be          /* Qx → slot 5 */
	lea	rsi, [rsi + 32]
	lea	rdi, [r14 + 6*SLOT]
	call	fe_from_be          /* Qy → slot 6 */
	pop	rsi                 /* sig */
	lea	rdi, [r14 + 11*SLOT]   /* r → slot 11 (temp) */
	call	fe_from_be
	lea	rsi, [rsi + 32]
	lea	rdi, [r14 + 12*SLOT]   /* s → slot 12 */
	call	fe_from_be

	/* Run bc_v1: validation, derive b, compute u1/u2, setup backups. */
	push	obc_v1
	pop	rdi
	call	bcrun_off
	jc	.Lfail2             /* validation failed */

	/* Scalar mul: pt_mul reads u1 from slot 22, u2 from slot 23.
	 * bc_v1 must have normalized them and put them there.
	 * pt_mul falls through to bc_v3 (final check). */
	call	pt_mul
	/* CF from bc_v3's checkzero. CF=1 means nonzero → invalid. */
	sbb	eax, eax
	inc	eax                 /* eax = 1 if valid, 0 if not */
	jmp	.Lout

.Lfail2:
	xor	eax, eax
.Lout:
	mov	rsp, rbp
.Lfail:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

/* ── Placeholder bytecode offsets ── */
	.equ	obc_rcb, 0
	.equ	obc_v3,  bc_v3 - bc_rcb
	.equ	obc_v1,  bc_v1 - bc_rcb
