/* ======================================================================
 * tv_ecdsa.S — ECDSA/P-256 verify, 5×56-bit signed limbs.
 *
 * Architecture: Montgomery form (R = 2^280). Field elements are 5 limbs
 * × 56 bits nominal, signed, lazy-carry. Fadd/Fsub are pure limbwise
 * (no carry, no reduce). fe_mul5 normalizes its output.
 *
 *   Range proof (range_proof.py, K=5 W=56):
 *     KW = 280 > 263.2 (RCB ×12 Y3-chain convergence bound)
 *     accumulator ≤ 123 bits (fits signed-128, 4 bits spare)
 *     mul-input limbs ≤ 61 bits (canonical 56 + ×12 growth ≈ +4)
 *
 *   Montgomery: p's low 56 bits all-ones → −p⁻¹ ≡ 1 (mod 2^56).
 *   n's m0inv = 0xd1c8aaee00bc4f (movabs, doesn't fit imm32).
 *   MASK = 2^56−1 = 0xffffffffffffff: movabs → r13, preserved everywhere.
 *
 * Slots: 40 B each (5 qwords). 24 slots. Frame 960 B (24·40 exactly;
 * 4 callee-save pushes → no alignment pad needed).
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

	.equ	W,      56
	.equ	K,      5
	.equ	SLOT,   K*8        /* 40 B */
	.equ	NSLOTS, 24
	.equ	FRAME,  NSLOTS*SLOT       /* 960 — 4 pushes, no align pad */

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
cR2N:	.quad	0xea7fbc24cfb36926, 0x4956a0a7b8636a7a
	.quad	0xec59619076ab51d1, 0x83b51c1e84a3d0b1
cGX:	.quad	0xd418a9143c18905f, 0xfc475d570179e730
	.quad	0x2b7762251075ba95, 0x76bdc7b4c6616b14
cGY:	.quad	0x57ce95560a8571ff, 0xe434a7e55cddf253
	.quad	0x88dd21f3258b4ab8, 0x18aafa5c854d7687

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
 * Must preserve rbx (&.Ljt — for xlatb), rbp (fail bits), r13 (MASK),
 * r14 (slot base), r15 (&cP). r12 wholly unused.
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
	imul	rax, rdx            /* rdx ∈ {+1, −1} */
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
	movabs	r11, 0xd1c8aaee00bc4f
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
	mov	rdx, rsi
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
	push	rdx                 /* b → [rbp+24]. Stack-stored; no extra callee-saved reg. */
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
	mov	rsi, [rbp + 24]             /* b */
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
	 * no xor needed. Top limb ≤ 2^34 so dropping hi in tail is correct. */
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
 * W=56 → 7 bytes per limb exactly. lodsq (+8) / dec rsi (−1) = +7.
 * Top limb is 32 bits (256 − 4·56): lodsd zero-extends AND advances +4
 * → drops the whole `mov eax,[rdx]; stosq; add rdx,4` tail to `lodsd; stosq`.
 *
 * fe_from_le takes its source in rsi. fe_from_be's reversal leaves
 * rsi=src+32 (BE-chain ptr) and rdx=rdi+8 (in-slot buffer); one xchg
 * swaps them for fall-through. BE caller reads the advanced src from
 * rdx on return.
 * LE chain: exit rsi=src+32 (4·7+4), rdi=dst+40.
 * BE chain: exit rdx=src+32, rdi=dst+40 (rsi garbage). */

fe_from_be:
	lea	rdx, [rdi + 40]
	mov	cl, 32              /* rcx ∈ {65, 0} at entry — pub_len arg or fe_from_le exit; high bytes clean */
1:	lodsb
	dec	rdx
	mov	[rdx], al
	loop	1b                  /* rsi=src+32, rdx=rdi+8, rcx=0 */
	xchg	rsi, rdx            /* rsi=rdi+8 (decode src), rdx=src+32 (chain) */
	/* FALL THROUGH */

/* Write trails read: reversal buffer at rdi+8..rdi+39 (old rdi). Stosq
 * writes old_rdi+0,+8,+16,+24,+32; lodsq reads at rsi=old_rdi+8,+15,+22,+29
 * then lodsd at +36. Same-iter read precedes write; cross-iter gap grows
 * (write@+8k ends at +8k+7, next read@+8+7k starts there for k≥1). */
fe_from_le:
	mov	cl, 4               /* rcx = 0 from fe_from_be's loop / rep stosd */
1:	lodsq
	dec	rsi                 /* net +7 per iteration */
	and	rax, r13
	stosq
	loop	1b
	lodsd                       /* top 32 bits, zero-extends, rsi += 4 */
	stosq
	ret

/* ======================================================================
 * bc_run — bytecode interpreter
 * ====================================================================== */

/* .Lcadd: copy 3 slots → addend, dispatch bc_rcb. rcx = 0 after rep
 * movsq → bcrun_off takes offset in rcx (obc_rcb = 0 for free).
 * r15 = r14+oCP = r14+320; oADD=200 → r15−120 (disp8, −3 B).
 *
 * Caller passes the SOURCE OFFSET (not pointer) in esi — `mov esi,imm32`
 * is 5 B vs 7 B for `lea rsi,[r14+disp32]`; xor esi,esi is 2 B vs 3 B
 * for `mov rsi,r14`. `add rsi,r14` here costs +3 B; three call sites
 * save 1+2+2 = 5 B. Net −2 B. (esi write zero-extends → full addr.) */
.Lcadd:
	lea	rdi, [r15 - (oCP - oADD)]
	add	rsi, r14
	push	3*K
	pop	rcx
	rep	movsq
	jmp	bcrun_off

pt_mul:
	/* Packed counter: ebx = limb·64 + bit. bt [rbp-88], ebx indexes bit
	 * ebx of the u1 array (bt spans qwords — unbounded bit addressing).
	 * Each limb is a qword; useful bits [0,W−1]. Crossing detection:
	 * (ebx+1) & 63 == 0 iff dec took us from limb·64+0 to (limb−1)·64+63.
	 * NOT `cmp bl, W` — bl = ebx mod 256, tracks bit-within-limb only
	 * for limbs {0, K−1} where limb·64 ≡ 0 mod 256.
	 *
	 * vs 2-loop: control +3 B; bt −4 B (drops SIB index r15·8 + REX.X).
	 * Net −1 B. r15 freed for &cP pointer (−7 B net across .Lfmul,
	 * NORM, .Lcadd, bc_run). rbp = r14+FRAME; u1 at −88. */
	mov	ebx, (K-1)*64 + (W-1)    /* 4·64+55 = 311 */
.Lpi:	xor	esi, esi            /* offset 0 — .Lcadd adds r14 */
	call	.Lcadd
	bt	[rbp - (FRAME - oU1)], ebx
	jnc	1f
	mov	esi, oBAK
	call	.Lcadd
1:	bt	[rbp - (FRAME - oU1 - SLOT)], ebx
	jnc	2f
	mov	esi, oBAK + 3*SLOT
	call	.Lcadd
2:	dec	ebx
	lea	eax, [rbx+1]        /* crossed iff (ebx+1) ≡ 0 (mod 64) */
	test	al, 63
	jnz	.Lpi
	sub	ebx, 64-W           /* rebiase: (limb−1)·64+63 → (limb−1)·64+W−1 */
	jns	.Lpi                /* ebx ≥ 0: more limbs */
	/* falls through to final check */
	push	obc_v3
	pop	rcx

bcrun_off:
	push	rbp
	push	rbx                 /* pt_mul's packed counter — survives every dispatch */
	/* bcptr in rsi (lodsw), jt in rbx (xlatb). r12 wholly unused → verify
	 * drops push/pop/lea r12 (−11). Here: +7 (lea rbx) +2 (push/pop rsi)
	 * −4 (lodsw vs mov+add) −3 (xlatb vs REX mov) = +2. Net −9.
	 * Handlers already preserve rbx (fe_mul5, .Linv push/pop; rest don't
	 * touch). bcptr save/restore around call — handlers clobber rsi via
	 * lodsq for fe-limb reads. */
	lea	rbx, [rip + .Ljt]
	lea	rsi, [rip + bc_rcb]
	add	rsi, rcx            /* offset in rcx — .Lcadd has rcx=0 from rep movsq */
	xor	ebp, ebp
.Lbc:
	lodsw                       /* ax ← op; rsi += 2. High eax garbage — */
	test	al, al              /*   and eax,0xF below clears. */
	jz	.Lbce
	push	rsi                 /* bcptr — clobbered by slot-ptr compute + lodsq */

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
	xlatb                       /* AL ← [RBX+AL]. 1 B. rax high bytes stay 0 from and. */
	add	rax, rbx
	lea	rcx, [r15 + SLOT]   /* &cN = &cP + SLOT (r15 disp8, −3 B vs r14+disp32) */
	call	rax
	pop	rsi
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
	push	r13
	push	r14
	push	r15

	/* Alignment: caller's rsp ≡ 0 (mod 16) at call → −8 (ret) − 32
	 * (4 pushes) − 8 (enter's rbp) − 960 = −1008 ≡ 0 (mod 16). */
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
	shr	r13, 64-W           /* MASK = 2^56−1; movabs is 10 B, this is 8 */

	/* BE chain at slot 3 (3*SLOT = 120: disp8). Qx,Qy,r,s,e → 3..7.
	 * rdi ends at slot 8, ready for LE constants. The bc_v1 layout
	 * stages all 8 Shamir values at slots 0..7 → one rep movsq.
	 *
	 * 5 decodes, 3 source groups: pub+1(×2), sig(×2), hv(×1). fe_from_be
	 * returns the advanced src in rdx (xchg before fall-through). The
	 * bitmask ebx=0b10101 drives the chain: `shr ebx,1` yields CF=bit0
	 * and ZF=(ebx==0) in one 2-B instruction. CF=1 (iters 1,3,5) →
	 * push rdx so pop gets the chain ptr; CF=0 (iters 2,4) → pop reads
	 * the next src from the prologue pushes. ZF=1 after iter 5 exits.
	 * Stack is balanced: 2 prologue pushes − 2 CF=0 pops = 0. rbx=0 at
	 * exit (for `mov bl,4` below). 27 B vs 38 B straight-line. */
	push	r8                  /* hv — popped on iter 4 */
	push	rdi                 /* sig — popped on iter 2 */
	lea	rsi, [rdx + 1]
	lea	rdi, [r14 + 3*SLOT]
	push	0b10101
	pop	rbx
1:	call	fe_from_be
	shr	ebx, 1              /* CF = chain-bit, ZF = done */
	jnc	2f                  /* CF=0: next src is on stack already */
	push	rdx                 /* CF=1: chain — push advanced ptr */
2:	pop	rsi
	jnz	1b                  /* ZF from shr; push/pop preserve flags */

	/* r15 = &cP. Preserved by all handlers + fe_mul5 (never touched);
	 * pt_mul's packed counter uses ebx only. Reaches oADD (−120),
	 * oCN (+40), oCP (+0) all disp8. bc_run, .Lfmul, .Lcadd, .Lasmod. */
	mov	r15, rdi

	/* cP → slot 8, SIGNED limb form: (−1, 2^40, 0, 2^24, 2^32−1).
	 * p = 2^256 − 2^224 + 2^192 + 2^96 − 1. At W=56: 96=56+40,
	 * 192=3·56+24, 224=4·56+0, 256=4·56+32 → limb 4 = 2^32 − 2^0.
	 * Zero-fill then 4 patches. fe_mul5/NORM arithmetic is already
	 * signed (imul, 128-bit acc); CHKLT changed to Fsub-based.
	 * rep stosd: 2 B (no REX.W), 10 dwords = 5 qwords. rcx = 0 from
	 * fe_from_le's `loop` → `mov cl` suffices. */
	xor	eax, eax
	mov	cl, K*2
	rep	stosd                       /* all zero; rdi → slot 9 */
	dec	qword ptr [rdi - 40]        /* limb 0 = −1 */
	inc	byte ptr [rdi - 27]         /* limb 1 byte 5: 0→1 → 2^40 */
	inc	byte ptr [rdi - 13]         /* limb 3 byte 3: 0→1 → 2^24 */
	dec	dword ptr [rdi - 8]         /* limb 4 low dword: 0→0xFFFFFFFF, no REX */

	/* Constants (LE). cN,cR2N,cGX,cGY → 9,10,11,12. fe_from_le reads
	 * from rsi now (lodsq). rbx = 0 from the BE loop's final shr →
	 * `mov bl` is safe (high bytes clean). */
	lea	rsi, [rip + cN]
	mov	bl, 4
1:	call	fe_from_le
	dec	ebx
	jnz	1b

	jmp	.Ltail

	.section .note.GNU-stack,"",@progbits
