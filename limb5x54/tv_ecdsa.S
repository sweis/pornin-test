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
 * Layout: .Lnmul → .Linv → .Lfmul → fe_mul5. .Lfmul falls through
 * (−2 B, no jmp). Handler shrinks from prior commits made room:
 * .Lfmul lands at 247 (< 256 u8 limit). .Lnmul's jmp stays rel8
 * over .Linv+.Lfmul (54 B). */

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
	/* Clears 3 slots (dst, dst+1, dst+2); sets (dst+1)[0]=1. Both
	 * call sites want (0:1:0) triples: SET1(14)→slot15=1 at bc_v1
	 * start (14,16 garbage anyway), SET1(0)→acc=(0:1:0) at end. */
	xor	eax, eax
	push	3*K
	pop	rcx
	rep	stosq
	inc	byte ptr [rdi - 2*K*8] /* middle slot byte 0: all-zero → byte inc ≡ qword inc */
	ret

/* Fadd/Fsub merged: r8 = ±1 sign, imul the s2 limb. −2 B vs two separate
 * loops (34→32). r8,r9 clobbered — handler spec allows r8-r11. */
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
	loop	2b
	ret

/* CHKZ with dst-as-flag: dst=0 → shift (s1≠0) into ebp; dst=1 → shift
 * (s1==0). bc_run preloads r9d = dst nibble (0 or 1). xor ebp with
 * that bit AFTER the rcl → flips bit 0 iff dst=1. */
.Lchkz:
	xor	edx, edx
	push	K
	pop	rcx
1:	lodsq
	or	rdx, rax
	loop	1b
	neg	rdx                 /* CF = (rdx != 0) */
	rcl	ebp, 1
	xor	ebp, r9d            /* dst nibble: 0 = keep, 1 = flip */
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

/* ── NORM — bring value to [0, p). In-place on s1. All 3 bytecode
 * calls encode dst==s1 → bc_run gives rdi==rsi already. .Lcprop's
 * last `add [rdi],rdx` sets SF from the top limb; .Laddm/.Lsubm
 * both fall into .Lcprop so SF is live at every loop head.
 *
 * .Lasmod's cP source = r15 (set in verify to &slot8). Drops the
 * `mov r8,rdx` preload (−3 B). rdx∈{+1,−1} via push/pop; imul
 * replaces xor+sub conditional-negate (4 B vs 6 B, −2; .Laddm +1). ── */
.Lnorm:
	call	.Lcprop
1:	jns	2f
	call	.Laddm
	jmp	1b
2:	push	-1
	pop	rdx
	call	.Lasmod             /* .Lsubm inlined — single caller */
	jns	2b
	/* fall into .Laddm for final add */

.Laddm:
	push	1
	pop	rdx
.Lasmod:
	push	rdi
	mov	rsi, r15            /* &cP — set once in verify, preserved everywhere */
	mov	cl, K               /* rcx = 0 — all paths here came through .Lcprop's loop */
1:	lodsq
	imul	rax, rdx            /* rdx ∈ {+1, −1}: 4 B vs xor+sub 6 B */
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

.Lnsp:	/* 2 B stub: rdi ← rsi. Both .Linv call sites want dst=s1;
	 * factoring it here saves 3 B of stack-dance there. */
	push	rsi
	pop	rdi
.Lnmul: /* MontMul mod n. fe_mul5 preserves rcx so INV's 384 calls
 * all inherit &cN. rel8 over .Linv + .Lfmul (53 B). */
	movabs	r11, 0x11c8aaee00bc4f
	jmp	fe_mul5

/* ── INV — s^(n−2) mod n via Fermat. n−2 stored directly in rodata
 * so `bt` works on all bits without special-casing. Lives between
 * .Lnmul and .Lfmul so it fits the u8 jt slot directly — no stub. ── */
.Linv:
	push	rbx
	push	rsi                 /* s_mont */
	push	rdi                 /* accumulator — seeded with s_mont */
	xor	ebx, ebx
	mov	bl, 254             /* bit 255 implicit (seed = s_mont) */
.Le:	pop	rsi
	push	rsi
	push	rsi                 /* 2 B vs mov rdx,rsi 3 B */
	pop	rdx
	call	.Lnsp               /* rdi←rsi; dst = dst² */
	bt	dword ptr [rip + cN], ebx   /* cN stored as n−2 */
	jnc	.Lnx
.Lmul:	pop	rsi
	pop	rdx
	push	rdx
	push	rsi
	call	.Lnsp               /* rdi←rsi; dst = dst·s_mont */
.Lnx:	dec	ebx
	jns	.Le
	pop	rax
	pop	rax
	pop	rbx
	ret

.Lfmul: /* MontMul mod p. FALLS THROUGH to fe_mul5. */
	mov	rcx, r15            /* &cP (r15 set in verify). 3 B vs sub 4 B. */
	push	1
	pop	r11

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
	lea	rdx, [rdi + 8]      /* in-slot buffer start (what fe_from_le wants) */
	push	32
	pop	rcx
1:	lodsb
	mov	[rdx+rcx-1], al     /* rcx counts 32→1: writes bytes 31→0 (reversed). 4 B vs dec+mov 5 B. */
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
	cmovb	rbx, [rdx + rcx + 8]   /* iter 4: cl=24, CF=0, rbx stays 0.
	                                * cmov LOADS regardless — [rdx+32]
	                                * always valid (rodata chain or
	                                * in-frame slot buffer). −1 B. */
	shrd	rax, rbx, cl
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

/* .Lcadd: copy 3 slots → addend, dispatch bc_rcb. rcx = 0 after rep
 * movsq → bcrun_off takes offset in rcx (obc_rcb = 0 for free).
 * r15 = r14+oCP = r14+320; oADD=200 → r15−120 (disp8, −3 B). */
.Lcadd:
	lea	rdi, [r15 - (oCP - oADD)]
	push	3*K
	pop	rcx
	rep	movsq
	jmp	bcrun_off

pt_mul:
	/* Packed counter: ebx = limb*64 + bit. bt [rbp-88], ebx indexes bit
	 * ebx of the u1 array (unbounded — bt spans qwords, dword addressing:
	 * addr = base + 4*(ebx/32), bit = ebx%32).  ebx = limb*64+bit → same
	 * physical bit as the old [rbp+r15*8-88],ebx with r15=limb.
	 *
	 * Wrap: dec from limb*64+0 → (limb-1)*64+63. Valid ebx has ebx&63
	 * ∈ [0,53]; only 63 ever appears in [54,63] (exactly after wrap).
	 * (ebx+1)&63 == 0 ⟺ just wrapped. For limb<4, (limb*64)&0xFF is
	 * 0/64/128/192 — all have bits 0-5 clear, so test al,63 works.
	 *
	 * Setup 5 B vs 7 B. bt 4 B each vs 6 B (drops REX.X SIB). Loop
	 * control 14 B vs 9 B. Net −1 B. r15 freed for &cP base. */
	mov	ebx, (K-1)*64 + (W-1)    /* 4*64+53 = 309 */
.Lpi:	mov	rsi, r14
	call	.Lcadd
	bt	[rbp - (FRAME - oU1)], ebx
	jnc	1f
	lea	rsi, [r14 + oBAK]
	call	.Lcadd
1:	bt	[rbp - (FRAME - oU1 - SLOT)], ebx
	jnc	2f
	lea	rsi, [r14 + oBAK + 3*SLOT]
	call	.Lcadd
2:	dec	ebx
	lea	eax, [rbx+1]        /* eax = pre-dec value */
	test	al, 63              /* 0 ⟺ pre-dec ebx was limb*64 */
	jnz	.Lpi
	sub	ebx, 64-W           /* rebiase: (limb-1)*64+63 → (limb-1)*64+53 */
	jns	.Lpi
	/* falls through to final check */
	push	obc_v3
	pop	rcx

bcrun_off:
	/* bc pointer in rsi (not rbx): lodsw loads+advances in 2 B (was
	 * mov+add = 6 B). Caller's rsi not preserved — pt_mul/.Ltail set
	 * rsi before each bcrun_off anyway. rbx preserved passively
	 * (handlers preserve it, we don't touch) — pt_mul's packed counter
	 * in ebx survives .Lcadd calls. push/pop rsi in-loop around
	 * handler (which sets rsi = s1). Net: −4 B.
	 * lodsw's upper-eax stale bits are harmless: movzx from ah/al
	 * ignores them; `and eax,0xF` zero-extends to full rax. */
	push	rbp
	lea	rsi, [rip + bc_rcb]
	add	rsi, rcx            /* offset in rcx — .Lcadd has rcx=0 from rep movsq */
	xor	ebp, ebp
	/* r12 = &.Ljt inherited from verify; fe_mul5 preserves it. */
.Lbc:
	lodsw                       /* ax = [rsi]; rsi += 2 */
	test	al, al
	jz	.Lbce
	push	rsi                 /* save bc ptr — handler sets rsi to s1 */

	movzx	edi, ah
	mov	esi, edi
	and	esi, 0xF
	imul	esi, esi, SLOT
	add	rsi, r14
	shr	edi, 4
	mov	r9d, edi            /* save dst nibble for CHKZ's flip-bit */
	imul	edi, edi, SLOT
	add	rdi, r14

	movzx	edx, al
	shr	edx, 4
	imul	edx, edx, SLOT
	add	rdx, r14

	and	eax, 0xF
	mov	al, [r12 + rax]     /* high bytes zero from the `and` above */
	add	rax, r12
	lea	rcx, [r15 + SLOT]   /* &cN = &cP + SLOT (r15 disp8, −3 B vs r14+disp32) */
	call	rax
	pop	rsi                 /* restore bc ptr */
	jmp	.Lbc

.Lbce:	neg	ebp
	sbb	eax, eax
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
	pop	rcx
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

	/* BE chain at slot 3 (3*SLOT = 120: disp8). Qx,Qy,r,s,e → 3..7.
	 * 2-pair loop for pub (Qx,Qy) then sig (r,s): push both sources,
	 * pop per iteration. fe_from_be chains rsi +32. −2 B vs unrolled. */
	push	rdi                 /* sig — popped in iteration 2 */
	lea	rsi, [rdx + 1]
	push	rsi                 /* pub+1 — popped in iteration 1 */
	lea	rdi, [r14 + 3*SLOT]
	push	2
	pop	rcx
1:	pop	rsi
	push	rcx
	call	fe_from_be          /* iter1: Qx,Qy → 3,4. iter2: r,s → 5,6. */
	call	fe_from_be
	pop	rcx
	loop	1b
	mov	rsi, r8             /* hv */
	call	fe_from_be          /* e  → 7; rdi = slot 8 */

	/* r15 = &cP. Preserved by all handlers + fe_mul5 (never touched).
	 * Reaches oADD (−120), oCN (+40), oCP (+0) all disp8. Used by
	 * bc_run, .Lfmul, .Lcadd, .Lasmod. Frees pt_mul's r15 counter. */
	mov	r15, rdi

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

	/* Constants (LE). cN,cR2N,cGX,cGY → 9,10,11,12. rcx=0 from rep
	 * stosd above (cP patches don't touch it) → mov cl,4 is 2 B and
	 * safe. push/pop around call since fe_from_le clobbers rcx. */
	lea	rdx, [rip + cN]
	mov	cl, 4
1:	push	rcx
	call	fe_from_le
	pop	rcx
	loop	1b

	jmp	.Ltail

	.section .note.GNU-stack,"",@progbits
