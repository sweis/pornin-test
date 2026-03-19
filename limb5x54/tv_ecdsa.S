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
 * Slots: 40 B each (5 qwords). 24 slots. Frame 960 B (4 pushes; r12 unused).
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
	.equ	FRAME,  NSLOTS*SLOT       /* 960 — 16-aligned with 4 pushes (r12 dropped) */

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
 * Must preserve rbx (bcrun_off's .Ljt), rbp (fail bits), r13 (MASK),
 * r14 (slot base), r15 (&cP). r12 unused.
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

/* ── NORM — bring value to [0, p). In-place on s1. Single merged loop
 * (port of limb11 135a928): .Lcprop returns rax = top limb (see
 * restructure below). cqo sign-extends rax → rdx; `not rdx` (flag-
 * clean) flips: neg→0 (add), nonneg→−1 (sub). Stash across .Lasmod,
 * pop, then `or rdx, rax` — SF=0 iff (added ∧ result≥0). Sub always
 * loops (rdx=−1 forces SF=1).
 *
 * Differs from limb11: (1) .Lcprop restructure costs +1 B (limb11's
 * .Lcp_shared tail naturally leaves rax=top via stosq; limb5's `add
 * [rdi],rdx` doesn't). (2) |top| < 2^44 here (vs ≤2^18 in limb11, K=11
 * smears more) — bit 31 is data not sign → `or rdx,rax` (3 B) not
 * `or edx,eax` (2 B). Net: −4 (loop merge) +2 (.Lasmod) +1 (.Lcprop)
 * = −1 B. .Laddm deleted. ── */
.Lnorm:
	call	.Lcprop             /* rax = top limb; SF = sign(top) */
1:	cqo                         /* rdx ← sar(rax,63). 2 B. */
	not	rdx                 /* {−1,0}→{0,−1}. Flag-preserving. 3 B. */
	push	rdx
	call	.Lasmod             /* → .Lcprop → rax = new top */
	pop	rdx
	or	rdx, rax            /* 64-bit (|top|<2^44): SF=1 ⇔ subbed ∨ still-neg */
	js	1b
	ret

.Lasmod:
	/* rdx ∈ {0,−1}: xor+sub conditional-negate (0→nop, −1→two's-comp).
	 * +2 B vs imul's {+1,−1} convention — paid back by cqo+not above. */
	push	rdi
	mov	rsi, r15            /* &cP — set once in verify, preserved everywhere */
	mov	cl, K               /* rcx = 0 — all paths here came through .Lcprop's loop */
1:	lodsq
	xor	rax, rdx
	sub	rax, rdx
	add	[rdi], rax
	scasq
	loop	1b
	pop	rdi
	/* fall into .Lcprop */

/* .Lcprop — restructured to return rax = top limb (for cqo) AND
 * SF = sign(top) (for .Lchklt's `js`). `loop 2f` mid-body: iters
 * 1..K-1 jump to mask+store+shift; iter K (rcx 1→0) falls through
 * with rax still unmasked from the push/pop copy. `add rdx,[rdi]`
 * on iter K sets SF; push/pop/loop/stosq/pop/ret all preserve flags.
 * +1 B vs old (extra stosq + jmp 1b vs add-mem-rdx tail). */
.Lcprop:
	push	rdi
	xor	edx, edx
	push	K
	pop	rcx
1:	add	rdx, [rdi]          /* iter K: SF = sign(top) — survives to ret */
	push	rdx
	pop	rax                 /* rax = unmasked; on iter K = top limb */
	loop	2f                  /* rcx→0: fall through (iter K) */
	stosq                       /* store unmasked top */
	pop	rdi
	ret
2:	and	rax, r13
	stosq
	sar	rdx, W
	jmp	1b

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
	push	rdx                 /* b → [rbp+24] */
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
 * a running bit-offset (ecx); unroll i=4 as (24,24) — the natural (27,0)
 * would read bytes 27..34 (3 past a 32-B input).
 *
 * fe_from_le takes its SOURCE in rdx (not rsi). This lets fe_from_be
 * fall through: its reversal loop leaves rsi=src+32 (for BE chaining)
 * and rdx=rdi+8 (in-slot buffer start) — exactly what fe_from_le wants.
 * fe_from_le clobbers r9 (only called from verify, never as a handler;
 * r9 is hv_len−32 junk after spec checks). rbx preserved — the BE
 * loop's shr-bitmask lives there across calls.
 * LE chain: exit rdx=src+32, rdi=dst+40.
 * BE chain: exit rsi=src+32, rdi=dst+40 (rdx garbage). */

fe_from_be:
	lea	rdx, [rdi + 8]      /* in-slot buffer start (what fe_from_le wants) */
	mov	cl, 32              /* entry rcx ∈ {65,30} (pub_len / fe_from_le exit) — both <256 */
1:	lodsb
	mov	[rdx+rcx-1], al     /* rcx counts 32→1: writes bytes 31→0 (reversed). 4 B vs dec+mov 5 B. */
	loop	1b                  /* rsi=src+32, rdx=rdi+8, rcx=0 */
	/* FALL THROUGH — rsi preserved through fe_from_le (uses r9,ecx,rdx). */

/* 54 = 48 + 6, so byte-offset 6i and shift 6i extract bits 48i+6i = 54i.
 * Need 64 bits after shift for full 54-bit limb, but shr by 6i leaves only
 * 64−6i bits — insufficient for i≥2. shrd with [rdx+6i+8] supplies the
 * high bits. Limb 4 is 40 bits; shrd with r9=0 ≡ shr suffices.
 *
 * Single-cmp: cmovb PRELOADS r9 for the NEXT iter (after `add ecx,6`
 * so rcx already holds next-iter offset). cmp cl,24: CF=1 for cl∈{6,12,18}
 * (next iter ≠ last → load); CF=0 ZF=1 for cl=24 (next is iter 4 → keep
 * zeroed); CF=0 ZF=0 for cl=30 (exit). jbe loops on CF|ZF = 5 iters.
 * Iter 0 shrd count = 0 → no-op (Intel SDM: count=0 leaves dest+flags
 * unchanged) so entry-r9 is irrelevant. cmov reads regardless; max
 * [rdx+38] — 14 B past LE source, in-frame for BE, page slack for rodata.
 * rbx→r9: +1 B (`xor r9d,r9d` is 3B vs 2B) — buys BE shr-bitmask (−9). */
fe_from_le:
	xor	ecx, ecx
1:	mov	rax, [rdx + rcx]
	shrd	rax, r9, cl         /* iter 0: cl=0 → no-op */
	and	rax, r13
	stosq
	xor	r9d, r9d            /* pre-zero for next iter's cmovb-skip case */
	add	ecx, 6
	cmp	cl, 24
	cmovb	r9, [rdx + rcx + 8]    /* preload for NEXT iter; skipped when cl≥24 */
	jbe	1b                  /* cl ≤ 24: loop (5 iters total) */
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
	/* bc pointer in rsi (lodsw loads+advances, 2 B vs mov+add 6 B).
	 * .Ljt pointer in rbx — set HERE, not verify: push/pop around body
	 * saves pt_mul's packed counter; `mov al,[rbx+rax]` is 3 B (no
	 * REX.B) vs [r12+rax] 4 B. r12 wholly unused → push/pop r12 and
	 * `lea r12` dropped from verify (−11 B). Here: +1+7+1 = +9 but
	 * mov al −1 → net +8. Overall −3. Handlers preserve rbx (fe_mul5,
	 * .Linv push/pop it; others don't touch). push/pop rsi in-loop
	 * around handler (which sets rsi = s1). lodsw's upper-eax stale
	 * bits harmless: movzx ignores; `and eax,0xF` zero-extends. */
	push	rbp
	push	rbx                 /* pt_mul's packed counter */
	lea	rbx, [rip + .Ljt]
	lea	rsi, [rip + bc_rcb]
	add	rsi, rcx            /* offset in rcx — .Lcadd has rcx=0 from rep movsq */
	xor	ebp, ebp
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
	xlatb                       /* AL ← [RBX + AL]. 1 B. rax high bytes stay 0 from `and`. */
	add	rax, rbx
	lea	rcx, [r15 + SLOT]   /* &cN = &cP + SLOT (r15 disp8, −3 B vs r14+disp32) */
	call	rax
	pop	rsi                 /* restore bc ptr */
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
	 * (4 pushes) − 8 (enter's rbp) − 960 = −1008 ≡ 0 (mod 16).
	 * r12 not pushed — wholly unused (jt ptr lives in rbx per-bcrun). */
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

.Lok:
	mov	r14, rsp
	push	-1
	pop	r13
	shr	r13, 64-W           /* MASK = 2^54−1; movabs is 10 B, this is 8 */

	/* BE chain at slot 3 (3*SLOT = 120: disp8). Qx,Qy,r,s,e → 3..7.
	 * rdi ends at slot 8, ready for cP build.
	 *
	 * 5 decodes, 3 source groups: pub+1(×2), sig(×2), hv(×1). fe_from_be
	 * leaves rsi=src+32 naturally (fe_from_le preserves rsi). Bitmask
	 * ebx=0b10101 drives chain-vs-pop: `shr ebx,1` yields CF=bit0 and
	 * ZF=(ebx==0) in one 2-B instruction. CF=1 (iters 1,3,5) → rsi
	 * already advanced; CF=0 (iters 2,4) → pop next src. jc/pop
	 * preserve the shr's ZF for the loop test. Stack balanced: 2 pushes
	 * (hv,sig), 2 pops (iters 2,4). ebx=0 at exit. 26 B vs 35 B. */
	push	r8                  /* hv — popped on iter 4 */
	push	rdi                 /* sig — popped on iter 2 */
	lea	rsi, [rdx + 1]      /* initial rsi = pub+1 */
	lea	rdi, [r14 + 3*SLOT]
	push	0b10101
	pop	rbx
1:	call	fe_from_be
	shr	ebx, 1              /* CF = chain-bit, ZF = done */
	jc	2f                  /* CF=1: rsi already = src+32 (chain) */
	pop	rsi                 /* CF=0: next source group */
2:	jnz	1b

	/* r15 = &cP. Preserved by all handlers + fe_mul5 (never touched).
	 * Reaches oADD (−120), oCN (+40), oCP (+0) all disp8. Used by
	 * bc_run, .Lfmul, .Lcadd, .Lasmod. Frees pt_mul's r15 counter. */
	mov	r15, rdi

	/* cP → slot 8, SIGNED limb form: (−1, 2^42, 0, 2^30, 2^40−256).
	 * p = 2^256 − 2^224 + 2^192 + 2^96 − 1 — five ±power-of-2 terms.
	 * Zero-fill then 4 patches. fe_mul5/NORM arithmetic is already
	 * signed (imul, 128-bit acc); CHKLT changed to Fsub-based.
	 * rep stosd: 2 B (no REX.W), 10 dwords = 5 qwords. ecx=30 from
	 * fe_from_le (high bytes 0) → mov cl is 2 B vs push/pop 3 B. */
	xor	eax, eax
	mov	cl, K*2
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

	/* Dispatch tail — inlined now that .Lok shrank (BE loop −9 B).
	 * `jmp .Lfail` below reaches back −108 B (9 B .Lfail + 99 B .Lok),
	 * fits rel8 with 20 B margin. `je .Lok` now jumps forward only
	 * over .Lfail (9 B) — also still rel8. rcx=0 (LE loop exit). */
	mov	cl, obc_v1
	call	bcrun_off
	push	rax
	call	pt_mul
	pop	rdx
	or	eax, edx
	inc	eax
	jmp	.Lfail

	.section .note.GNU-stack,"",@progbits
