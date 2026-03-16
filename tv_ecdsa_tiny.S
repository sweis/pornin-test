/* ======================================================================
 * ECDSA/P-256 verify — x86-64, bytecode-interpreted, SIZE-OPTIMIZED.
 *
 * ~1108 B default build; 1088 B with -DSMALL_MUL8 (~2× cycles).
 * Requires MOVBE only (no BMI2 — plain `mul`, not `mulx`).
 *
 * ARCHITECTURE
 *
 *   Plain modular arithmetic — NO MONTGOMERY FORM anywhere.  All
 *   field elements are stored and operated on in normal form.
 *
 *   fe_mul_m reduction: q = t[top_dword].  Both P-256 moduli have
 *   top dword 0xFFFFFFFF and 2^256 − m < 2^224, so at 32-bit
 *   granularity the reduce step is just  t[j..j+8] −= t[j+8]·m.
 *   Since q < 2^32 and product < 2^256, each step leaves
 *   t[j+8] ∈ {0,1} — ≤2 iterations per window position, never
 *   negative.  Slide j from 8 to 0.  No quotient estimation, no
 *   inverse constants, no R².
 *
 *   fe_mul_m product: 64-bit schoolbook (default, 4×4 qword muls)
 *   or 32-bit (SMALL_MUL8, 8×8 dword).  Either way the 512-bit
 *   product is identical; reduce stays 32-bit regardless — the
 *   q=t[top] trick needs top-limb = all-ones, and only the top
 *   DWORD satisfies that (p's top qword is 0xffffffff00000001).
 *
 *   Bytecode: 2-byte ops, nibble-encoded (s2|op, dst|s1), over 16
 *   stack slots × 32 B.  Interpreter hoists &cP into rcx and &.Ljt
 *   into r14; handlers address constants at [r14+disp8] instead of
 *   7-B rip-relative.  Jump-table offsets stored as single bytes
 *   — every handler must be within 255 B of .Ljt (.Lop8 is last).
 *
 *   Shamir's trick: one 256-bit walk computes u1·G + u2·Q.  Per
 *   iteration: double; if u2 bit, add Q (resident in slot 4-5);
 *   if u1 bit, swap G into 4-5, add, restore Q.  Both G and Q
 *   have z = 1 and slot 6 is NEVER written by bc_dbl/add — so
 *   the 8-qword X,Y swap is sufficient, z serves both.
 *
 *   Projective final check — NO mod-p inversion.  Valid iff
 *   x mod n == r, which in Jacobian coords is X ≡ r·Z² (mod p)
 *   OR X ≡ (r+n)·Z² (mod p).  p prime ⇒ diff1·diff2 ≡ 0 is
 *   equivalent.  Computed entirely in bc_v3 bytecode; the
 *   n·Z² term comes from MULCN (op 9: Fmul with b = &cN in
 *   .text), so no runtime constant derivation.
 *
 *   Fermat inversion — mod n ONLY (mod-p gone via the projective
 *   check).  n and n−2 differ only in bits 1-4 (low byte 0x51 vs
 *   0x4F is a four-bit borrow cascade, no borrow into byte 1).
 *   So: bt directly on cN in .text (read-only); bits 0-4 are
 *   special-cased with a 7-byte cmp/jb/je.  No exponent buffer,
 *   no stack copy, no sub-2.
 *
 * KEY INVARIANTS
 *
 *   r14 = slot base through pt_add_acc / pt_mul.  Every callee
 *   that reassigns r14 push/pops it (bc_run).  pt_add_acc and
 *   pt_mul have no frame; they read r14 directly.
 *
 *   .Lai is CALLED from pt_mul (not just a label).  Zeroes the
 *   accumulator and returns eax=0 (pt_mul dec/xchgs that into
 *   ebp=255 for the loop counter).
 *
 *   cGX→cGY→cN→cP contiguous after .Ljt: verify's single
 *   16-qword rep movsq lands G in slots 2-3, cN in 4, cP in 5.
 *   bc_v1's check ops read cN/cP from 4,5 (ops run first), then
 *   its copy ops overwrite 4,5 with Q (safe — checks done).
 *
 *   Slot 6 = 1 is load-bearing for Shamir: bc_dbl/add1/add2
 *   never write it.  Any bytecode change that writes slot 6
 *   breaks the G/Q swap silently.
 *
 *   rcx=0 is a frequent precondition (cpy3 macro, pt_mul's
 *   mov cl,8): every caller has rcx=0 from a prior loop-to-zero.
 *   Audit these if reordering.
 *
 * -DSMALL_MUL8: `loop`+`scasd` in the mul8 inner loop.  Both
 * are microcoded (~7 cyc and ~3 cyc vs 1 cyc); that loop runs
 * ~950K iterations per verify, so the penalty is ~3M cycles.
 * Default build uses dec+jnz + lea (+20 B, −51% cycles).
 *
 * Security and validation are unchanged from tv_ecdsa_bc.S.
 * ====================================================================== */

	.intel_syntax noprefix

/* ======================================================================
 * Bytecode.  Placed before .text so stream offsets (bc_X - bc_dbl) are
 * backward references at the call sites — gas picks the imm8 encoding
 * for `push`.  Order chosen so all offsets ≤ 120 (fits signed imm8;
 * bc_v1 is last).
 *
 * Call sites load the offset as a small integer (push imm8; pop rdi,
 * or xor edi,edi for bc_dbl itself), and bcrun_off adds the base.
 * ====================================================================== */
	.section .rodata
	.p2align 3

bc_dbl:
	.byte 0x21,0xb2, 0x11,0x91, 0xb3,0x80, 0xb2,0xa0, 0xa0,0xa8
	.byte 0xa2,0x8a, 0xa2,0xa8, 0x22,0x81, 0x81,0x88, 0x93,0x88
	.byte 0xb3,0x28, 0x90,0xb0, 0xb2,0x8b, 0x82,0x88, 0x82,0xb8
	.byte 0xa1,0x0a, 0xb3,0x00, 0x03,0x88, 0x80,0x8a, 0x91,0x99
	.byte 0x92,0x99, 0x92,0x99, 0x92,0x99, 0x93,0x18, 0x00,0x00

/* bc_v2 merged into bc_v1: hash decode writes e to slot 14, so s
 * in slot 13 survives to INV; the two Nmuls append to bc_v1's tail.
 * One dispatch, one terminator. */

/* bc_v3: PROJECTIVE CHECK — no mod-p inversion.  Valid iff
 * x mod n == r ⇔ X ≡ r·Z² (mod p) OR X ≡ (r+n)·Z² (mod p).
 * p is prime → (diff1·diff2 ≡ 0) ⇔ (either ≡ 0).  diff2 =
 * diff1 − n·Z² via MULCN (b=cN in .text) + Fsub; equivalent to
 * diff1 + (p−n)·Z² via Fadd but needs no p−n constant.
 * First op: R.z==0 (∞) → fail. */
bc_v3:
	.byte 0x06,0x20            /* checkzero slot2 (R.z): ∞ → fail */
	.byte 0x21,0x72            /* slot7  = z²                     */
	.byte 0x70,0xac            /* slot10 = r·z²  (r=slot12)       */
	.byte 0xa3,0xa0            /* slot10 = X − r·z²       = diff1 */
	.byte 0x08,0x37            /* slot3  = n·z²  (MULCN=op8 now)  */
	.byte 0x33,0x3a            /* slot3  = diff1 − n·z² = diff2 (Fsub)*/
	.byte 0x30,0x3a            /* slot3  = diff1·diff2            */
	.byte 0x16,0x30            /* check slot3 nonzero (op6 s2=1)  */
	.byte 0x00,0x00

/* Tail checkzero on slot3 (= H): bc_run returns CF=1 iff H==0.
 * pt_add_acc branches on CF directly (jnc).  bc_add1 has no Fadd
 * (ops 0,1,3 only), so slot3 survives as the penultimate Fsub
 * wrote it — Fadd would clobber slot 3 as scratch. */
bc_add1:
	.byte 0x21,0xa2, 0x61,0xb6, 0xb0,0x80, 0xa0,0x34, 0x60,0x91
	.byte 0xb0,0x99, 0x20,0x75, 0xa0,0x77, 0x83,0x33, 0x93,0x77
	.byte 0x06,0x30            /* checkzero slot3 (H) → CF on return */
	.byte 0x00,0x00

bc_add2:
	.byte 0x60,0xa2, 0x30,0x2a, 0x31,0xa3, 0xa0,0xb3, 0xa0,0x88
	.byte 0xb0,0x99, 0x71,0x07, 0xb3,0x00, 0x82,0x38, 0x33,0x00
	.byte 0x03,0x38, 0x30,0x37, 0x93,0x13, 0x00,0x00

/* bc_v1: range checks + curve check + s⁻¹ + u1,u2.
 *
 * Q in slots 0,1; G in slots 2,3; cN,cP temporarily in 4,5
 * (block-copied, read by the checks, then overwritten by Q-copy).
 *
 * Slots 4,5 get Qx,Qy via Fmul(x, slot15=1) = x — a 2-B copy.
 * Slot 6 = 1 via 1·1 (pt_add_acc reads it as addend's z).
 *
 * Curve constant B is derived from G (B = Gy² − Gx³ + 3·Gx).
 * Curve check uses slots 7,11 as scratch so 0,1,4,5 survive for
 * the Shamir copy.  No Fadd anywhere — Fadd clobbers slot 3 (Gy). */
bc_v1:
	/* Range/zero checks.  cN/cP in slots 4,5 (block-copied). */
	.byte 0x06,0xc0, 0x05,0xc4, 0x06,0xd0, 0x05,0xd4
	.byte 0x05,0x05, 0x05,0x15
	.byte 0xf0,0x40            /* slot4 = Qx·1 = Qx  (copy)    */
	.byte 0xf0,0x51            /* slot5 = Qy·1 = Qy  (copy)    */
	.byte 0xf0,0x6f            /* slot6 = 1·1 = 1    (z-coord) */
	/* B-derive: G in 2,3 (normal form).  slot10 = B. */
	.byte 0x21,0xa2            /* slot10 = Gx²           (SQR) */
	.byte 0x20,0xaa            /* slot10 = Gx³           (Fmul)*/
	.byte 0x23,0xaa            /* slot10 -= Gx           (Fsub)*/
	.byte 0x23,0xaa            /* slot10 -= Gx           (Fsub)*/
	.byte 0x23,0xaa            /* slot10 -= Gx (=Gx³−3Gx)      */
	.byte 0x31,0x73            /* slot7  = Gy²           (SQR) */
	.byte 0xa3,0xa7            /* slot10 = Gy²−slot10 = B(Fsub)*/
	/* Curve check: scratch in 7,11 so Q(0,1,4,5) and G(2,3)
	 * survive.  slot7 = Qy²−B−(Qx³−3Qx); nonzero ⇔ off-curve. */
	.byte 0x01,0xb0            /* slot11 = Qx²           (SQR) */
	.byte 0x00,0xbb            /* slot11 = Qx³           (Fmul)*/
	.byte 0x03,0xbb            /* slot11 -= Qx           (Fsub)*/
	.byte 0x03,0xbb            /* slot11 -= Qx           (Fsub)*/
	.byte 0x03,0xbb            /* slot11 -= Qx (=Qx³−3Qx)      */
	.byte 0x11,0x71            /* slot7  = Qy²           (SQR) */
	.byte 0xa3,0x77            /* slot7 -= B             (Fsub)*/
	.byte 0xb3,0x77            /* slot7 -= slot11        (Fsub)*/
	.byte 0x16,0x70            /* check slot7 nonzero (op6 s2=1)  */
	.byte 0x07,0x0d            /* INV (op7 now): slot0 = s⁻¹ mod n*/
	/* bc_v2 appended: hash is in slot14, s⁻¹ in slot0, r in slot12.
	 * Checks may have failed — harmless, ebp already tainted. */
	.byte 0x04,0xde            /* slot13 = slot14·slot0 = e·s⁻¹ = u1 */
	.byte 0x04,0xec            /* slot14 = slot12·slot0 = r·s⁻¹ = u2 */
	.byte 0x00,0x00

.equ obc_dbl,  0
.equ obc_v3,   bc_v3   - bc_dbl
.equ obc_add1, bc_add1 - bc_dbl
.equ obc_add2, bc_add2 - bc_dbl
.equ obc_v1,   bc_v1   - bc_dbl

/* ---------------------------------------------------------------------- */
	.text

/* ----------------------------------------------------------------------
 * 256-bit primitives (4 × u64 limbs, little-endian).
 * -------------------------------------------------------------------- */

/* fe_iszero(a=rdi) -> al=1 iff zero, ZF set iff zero.  OR
 * accumulates into rax; the last OR's ZF reflects the full value.
 * loop/sete/ret preserve flags: pt_add_acc branches on ZF
 * directly.  High bytes of rax are garbage from the OR loop —
 * .Lop6/7 only read al.  Preserves rdi. */
fe_iszero:
	push	4
	pop	rcx
	xor	eax, eax
1:	or	rax, [rdi+rcx*8-8]
	loop	1b
	sete	al
	ret

/* fe_sub_raw INLINED in .Lop3 — see handler block. */

/* mul8 OP: dst[0..8] OP= ebx·src[0..7], 32-bit limbs.  One
 * expansion in the default build (reduce=sub only — schoolbook
 * is 64-bit inlined); two under SMALL_MUL8 (add + sub).
 *
 * `loop` and `scasd` are microcoded on every modern x86
 * (~7 cyc and ~3 cyc).  This is the hottest loop — using
 * `dec+jnz` + `lea` instead roughly halves total cycles per
 * verify.  -DSMALL_MUL8 picks the microcoded forms for the
 * absolute size floor.
 *
 * Clobbers: ebp (prev_hi), rcx→0, eax/edx, rsi/rdi advance +32. */
.macro	mul8 op
	mov	cl, 8               /* rcx=0 on entry (prior mul8 or push-loop) */
	xor	ebp, ebp
7:	lodsd
	mul	ebx
	add	eax, ebp
	adc	edx, 0
	\op	[rdi], eax
	adc	edx, 0
	mov	ebp, edx
#ifdef SMALL_MUL8
	scasd                       /* 1 B, ~3 cyc microcoded */
	loop	7b                  /* 2 B, ~7 cyc microcoded */
#else
	lea	rdi, [rdi+4]        /* 4 B, 1 cyc — +3 B */
	dec	ecx
	jnz	7b                  /* 4 B, 1 cyc — +2 B */
#endif
	\op	[rdi], ebp
.endm

/* .Lfm: load rcx=&cN, fall through.  Called only from fe_inv_m,
 * which only runs mod-n (mod-p gone — projective check).  r14 at
 * the call site is bc_run's .Ljt hoist.  gas won't pick disp8 for
 * forward-ref oN — hardcode + assert. */
.equ	oN_early, 73
.Lfm:	lea	rcx, [r14+oN_early]
	/* FALLTHROUGH */
/* fe_mul_m(r=rdi, a=rsi, b=rdx, m=rcx).  r = a·b mod m.  32-bit limbs.
 *
 * THE TRICK: both P-256 moduli have top dword 0xFFFFFFFF AND
 * 2^256 − m < 2^224.  At 32-bit granularity (and only there), the
 * reduce step is trivial:  q = t[j+8];  t[j..j+8] += q·(2^256−m).
 * Since q < 2^32 and neg_m < 2^224, q·neg_m < 2^256 — adding to a
 * <2^256 window gives <2^257, so new t[j+8] ∈ {0,1}.  ≤2 inner
 * iters per position, never negative.  Slide j from 8 to 0.
 *
 * One mul-accumulate serves both schoolbook AND reduce (add vs sub). */
fe_mul_m:
	push	rbx                 /* mul8 reads ebx */
	push	rbp                 /* mul8 clobbers ebp */
	/* b,a in r9,r10 (caller-saved, mul8 doesn't touch).  r12-r15
	 * not touched — no push/pop.  fe_inv_m's r8,r14 survive. */

	mov	r9, rdx             /* b */
	mov	r10, rsi            /* a */
	/* m on stack under dest: push is 1 B, tail pops it straight
	 * into rcx for the cond-sub.  Reduce loop reads at [rsp+88]. */
	push	rcx                 /* m → [rsp+80] after zero-loop */
	push	rdi                 /* dest → [rsp+72] */

	/* Frame: just t[0..17] = 72 B.  Push-zero 9 qwords. */
	xor	eax, eax
	push	9
	pop	rcx
2:	push	rax
#ifdef SMALL_MUL8
	loop	2b
#else
	dec	ecx                 /* +2 B; 9 iter × ~6K calls = ~0.3M cyc */
	jnz	2b
#endif
	/* rsp → t[0].  rcx=0. */

	/* 64-BIT SCHOOLBOOK (default): 4×4 qword muls.  Same 512-bit
	 * product as 32-bit; reduce stays 32-bit regardless (q=t[top]
	 * trick needs top DWORD = -1, top qword isn't).  REX on every
	 * op grows the body but 16 iterations vs 64 wins net. */
	push	-32
	pop	r11
#ifdef SMALL_MUL8
.Lm:	mov	ebx, [r10+r11+32]   /* a[i], dword */
	lea	rdi, [rsp+r11+32]   /* &t[i] */
	mov	rsi, r9             /* b */
	mul8	add                 /* t[i..i+8] += a[i]·b */
	add	r11, 4
	jnz	.Lm
#else
.Lm:	mov	rbx, [r10+r11+32]   /* a[i], qword (same 5 B — REX.W|XB) */
	lea	rdi, [rsp+r11+32]   /* &t[i] */
	mov	rsi, r9             /* b */
	mov	cl, 4
	xor	ebp, ebp            /* 32-bit op zero-extends rbp */
7:	lodsq
	mul	rbx
	add	rax, rbp
	adc	rdx, 0
	add	[rdi], rax
	adc	rdx, 0
	mov	rbp, rdx
	lea	rdi, [rdi+8]
	dec	ecx
	jnz	7b
	add	[rdi], rbp
	add	r11, 8
	jnz	.Lm
#endif

	/* REDUCE.  rdi = window pointer (no REX on [rdi+32]).  mul8
	 * advances rdi — push/pop around it. */
	lea	rdi, [rsp+32]       /* &t[8] */
.Lr:	mov	ebx, [rdi+32]       /* q = t[j+8] — NOT cleared */
	test	ebx, ebx
	jz	4f
	push	rdi
	mov	rsi, [rsp+88]       /* m (72 t + 8 dest + 8 pushrdi) */
	mul8	sub                 /* t[j..j+8] -= q·m; rdi += 32 */
	pop	rdi
	jmp	.Lr
4:	sub	rdi, 4
	cmp	rdi, rsp
	jae	.Lr
	/* t[0..7] < 2^256, possibly ≥ m.  t[8] = 0. */

	/* Final cond-sub via .Lop3.  rsi = &t BEFORE releasing the
	 * frame (reads are safe: .Lop3's pushes land at t[14..17],
	 * past the result in t[0..7]).  dest/m pop from under t.
	 * `push rsp` captures pre-decrement value; pop balances. */
	push	rsp
	pop	rsi
	add	rsp, 72
	pop	rdi                 /* dest */
	pop	rcx                 /* m */
	push	rcx
	pop	rdx
	call	.Lop3

	pop	rbp
	pop	rbx
	ret


/* fe_from_be — cold (5 calls at setup).  _next entry bumps rsi by
 * 32 first, for chained decode (rdi already advanced by the prior
 * call's stosq×4).  Two call sites each drop their own add rsi,32. */
fe_from_be_next:
	add	rsi, 32
fe_from_be:
	push	4
	pop	rcx
1:	movbe	rax, [rsi+rcx*8-8]  /* load+bswap; 7 B vs mov(5)+bswap(3) */
	stosq
	loop	1b
	ret

/* cpy3: 12-qword copy.  PRECONDITION rcx=0 (high bytes) — every
 * caller has rcx=0 from a prior fe_iszero/rep loop exit.  mov cl
 * is 2 B vs push;pop 3 B. */
.macro	cpy3
	mov	cl, 12
	rep	movsq
.endm

/* ----------------------------------------------------------------------
 * pt_add_acc / pt_mul read the slot base from r14 directly — no frame.
 * verify sets r14=rsp once; bc_run (called from inside these) push/
 * pops r14 around its own reassignment, so it always comes back.
 *
 * Placed right before bcrun_r14: add2 path FALLS THROUGH (no jmp),
 * dbl path's jmp is rel8.  x86-64 has no short call — the mid-body
 * `call bcrun_r14` is still rel32.
 * -------------------------------------------------------------------- */
pt_add_acc:
	lea	rdi, [r14+64]
	call	fe_iszero           /* ZF ⇔ acc.z == 0 */
	jnz	1f
	/* fe_iszero preserved rdi = r14+64; compute rsi from it (disp8). */
	lea	rsi, [rdi+64]       /* r14+128 */
	mov	rdi, r14
	cpy3
	ret
1:	push	obc_add1
	pop	rdi
	call	bcrun_r14
	/* bc_add1's tail checkzero(slot3=H) → CF=1 iff H==0.
	 * r12 = &slot4 (pt_mul's, survives bc_run) → slot7 at
	 * r12+96, disp8.  r12 needs SIB but still beats disp32. */
	jnc	3f                  /* H ≠ 0 → bc_add2 */
	lea	rdi, [r12+96]       /* slot 7 = Rr (slot4+96) */
	call	fe_iszero           /* ZF ⇔ Rr == 0 */
	jnz	.Lai
	xor	edi, edi            /* obc_dbl = 0 */
	jmp	bcrun_r14           /* rel8 — bcrun_r14 is just below */
.Lai:	mov	rdi, r14
	xor	eax, eax
	/* rcx=0 on both paths here: fe_iszero's loop (pt_add_acc) and
	 * verify's rep movsq → pt_mul prologue (the `call .Lai`). */
	mov	cl, 12
	rep	stosq
	ret
3:	push	obc_add2
	pop	rdi
	/* FALLTHROUGH to bcrun_r14 */

/* ======================================================================
 * BYTECODE INTERPRETER
 * ====================================================================== */
/* rdi = byte offset from bc_dbl.  bcrun_off resolves; bcrun_r14 also
 * supplies rsi = r14 (slot base).  Call sites use push imm8; pop rdi
 * (2-3 B) instead of 7-B rip-rel lea. */
bcrun_r14:
	mov	rsi, r14
bcrun_off:
	lea	rax, [rip+bc_dbl]
	add	rdi, rax
	/* FALLTHROUGH */
bc_run:
	push	rbp
	push	rbx
	push	r12
	push	r14
	push	rdi                 /* 2B push;pop vs 3B REX.W mov */
	pop	rbx
	mov	r12, rsi
	/* Check accumulator in ebp (no REX).  Only bpl is ever OR'd
	 * (with 0/1); upper bytes stay zero from this xor.  r13 not
	 * push/popped: nothing in the dispatch tree touches it. */
	xor	ebp, ebp
	lea	r14, [rip+.Ljt]     /* Hoist: handlers are callee-saved, r14 lives. */
.Lbc:
	movzx	eax, WORD PTR [rbx]
	add	rbx, 2
	/* END is word 0x0000 (no stream uses MUL s0,s0,s0→s0). */
	test	eax, eax
	jz	.Lbce

	/* Nibble layout: al=(s2<<4)|op, ah=(dst<<4)|s1.  Straight-line
	 * decode: no push/pop, no loop.  Slot stride is 32 bytes; a
	 * nibble in bits [7:4] is already ×16, so lea scale-2 finishes it.
	 * `and edi,-16` = 3 bytes (imm8 sign-ext → 0xFFFFFFF0); works
	 * because movzx cleared bits [31:8] already.
	 *
	 * Consume ah first (into edi/esi), then al (into edx), then
	 * `and eax,0xF` for the op — using rax itself as the table
	 * index.  No copy-to-ecx is needed. */
	movzx	edi, ah             /* edi = (dst<<4)|s1 */
	mov	esi, edi
	and	esi, 0xF
	shl	esi, 5
	add	rsi, r12            /* r12 + s1*32 */
	and	edi, -16            /* edi = dst<<4 */
	lea	rdi, [r12+rdi*2]    /* r12 + dst*32 */

	movzx	edx, al             /* edx = (s2<<4)|op; high bits cleared */
	and	dl, 0xF0            /* edx = s2<<4 */
	lea	rdx, [r12+rdx*2]    /* r12 + s2*32 */

	and	eax, 0xF            /* op — ah already dead */
	movzx	eax, BYTE PTR [r14+rax]
	add	rax, r14
	/* Preload rcx = &P: most handlers want it (Fmul/Fsub/Fadd),
	 * the rest overwrite it.  oP is a forward ref — gas picks
	 * disp32 for those; hardcode + assert below. */
.equ	oP_early, 105       /* .Ljt(9) + cGX/Y(64) + cN(32) */
	lea	rcx, [r14+oP_early]
	call	rax
	jmp	.Lbc

/* NEG sets CF=1 iff operand was nonzero.  pops/ret preserve flags —
 * callers branch on CF directly (jc=fail for bc_v1/v3, jnc for
 * bc_add1's H-check).  ebp is about to be popped anyway. */
.Lbce:	neg	ebp
	pop	r14
	pop	r12
.Lepi2:
	pop	rbx
	pop	rbp
	ret

/* pt_mul: Shamir's simultaneous double-and-add.  One 256-bit walk
 * computes u1·G + u2·Q into the accumulator (slots 0-2).
 *
 * Caller contract (verify):
 *   rbx      → &u1 (slot 13); u2 at [rbx+32] (slot 14)
 *   r14      → slot base (slot 0)
 *   r15      → slot 2 (for &slot4 derivation below)
 *   slot 4-5 : Q.x, Q.y   (z in slot 6 — see below)
 *   slot 6   : 1          (shared z for G AND Q)
 *   slot 16-17: G.x, G.y  (at rbx+96)
 *   slot 18-19: Q.x, Q.y backup (for restore after each G-add)
 *
 * z-coordinate trick: bc_add1/2 read slot 6 for the addend's z but
 * NEVER write it.  Both G and Q are affine (z=1), so the same slot
 * 6 serves both — only X,Y (8 qwords) need swapping per G-branch.
 *
 * Per iteration: double; if u2 bit, add (Q already in 4-5); if u1
 * bit, swap G into 4-5, add, restore Q.  u2 checked first so Q is
 * in place without a preceding restore.
 *
 * rbx is callee-saved everywhere pt_mul reaches (bc_run pushes it;
 * pt_add_acc's callees do too), so pt_mul neither pushes nor writes
 * it — verify's &slot13 survives end-to-end. */
pt_mul:
	push	rbp
	push	r12
	lea	r12, [r15+64]       /* &slot4 — r15 = &slot2 (disp8) */

	call	.Lai
	dec	al
	xchg	ebp, eax
.Lpm:	xor	edi, edi
	call	bcrun_r14           /* double */

	/* bt [mem],reg indexes an unbounded bit array regardless of
	 * operand size — 32 vs 64-bit only affects the signed range
	 * of the reg.  ebp ∈ [0,255] fits comfortably.  Dropping
	 * REX.W: −1 B × 2. */
	bt	DWORD PTR [rbx+32], ebp   /* u2 bit */
	jnc	2f
	call	pt_add_acc          /* Q already in slot 4-5 */
2:
	bt	DWORD PTR [rbx], ebp      /* u1 bit */
	jnc	3f
	mov	rdi, r12            /* &slot4 */
	push	rdi                 /* stash for restore after pt_add_acc clobbers rdi */
	lea	rsi, [rbx+96]       /* &slot16 = G (rbx = &slot13) */
	/* rcx=0: bc_dbl ends in Fsub → fe_sub_raw dec-to-0; pt_add_acc
	 * (u2 branch) exits via bc_add2/dbl (same) or rep (rcx→0). */
	mov	cl, 8
	rep	movsq               /* G.xy → slot 4-5.  rsi landed at &slot18. */
	push	rsi                 /* stash &Q-backup — it's where rsi landed */
	call	pt_add_acc
	pop	rsi                 /* &slot18 = Q backup */
	pop	rdi                 /* &slot4 */
	mov	cl, 8               /* rcx=0: pt_add_acc exit paths all zero rcx */
	rep	movsq               /* Q.xy → slot 4-5 (restore) */
3:
	dec	ebp
	jns	.Lpm

	pop	r12
	pop	rbp
	ret

/* .Ljt + constants.  cGX→cGY→cN→cP contiguous in that order:
 * verify copies all four to slots 2-5 in one 16-qword rep movsq
 * (G → 2,3; cN → 4; cP → 5).  bc_v1's range/zero checks read
 * cN/cP from 4,5 first, then its Q-copy ops overwrite 4,5 —
 * safe because checks always run before the copy.
 *
 * cGX/cGY between .Ljt and handlers push handler offsets up by
 * 64 B — .Lop8 (fe_inv_m) is the furthest. */
.Ljt:
	.byte	.Lop0-.Ljt, .Lop1-.Ljt, .Lop2-.Ljt, .Lop3-.Ljt
	.byte	.Lop4-.Ljt, .Lop5-.Ljt, .Lop6-.Ljt
	.byte	.Lop8-.Ljt  /* INV = fe_inv_m, mod-n only (op 7) */
	.byte	.Lop9-.Ljt  /* MULCN (op 8) */
/* op6 = check (s2 bit0: 0=checkzero, 1=checknonzero).  op7
 * (checknonzero) absorbed — s2 encodes sense.  −1 table, −1
 * handler vs separate ops; frees 2B headroom so fe_sub_raw
 * can inline in .Lop3 (puts .Lop8 at exactly 255). */

cGX:	.quad 0xf4a13945d898c296, 0x77037d812deb33a0
	.quad 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247
cGY:	.quad 0xcbb6406837bf51f5, 0x2bce33576b315ece
	.quad 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b
cN:	.quad 0xf3b9cac2fc632551, 0xbce6faada7179e84
	.quad 0xffffffffffffffff, 0xffffffff00000000
cP:	.quad 0xffffffffffffffff, 0x00000000ffffffff
	.quad 0x0000000000000000, 0xffffffff00000001

.equ oN,   cN   - .Ljt
.equ oP,   cP   - .Ljt
.if oN - oN_early
.error "oN moved — update oN_early in .Lfm"
.endif
.if oP - oP_early
.error "oP moved — update oP_early in bc_run"
.endif
.if (cN - cGX) - 64
.error "cGX..cN spacing changed — verify's 16-qword block copy depends on cGX,cGY,cN,cP contiguous"
.endif
/* Jump-table offsets fit in u8: .Lop8 is furthest; no assert
 * (gas .if can't forward-ref) — `.byte` truncation at .Ljt will
 * produce wrong bytes, not a build error, if it ever overflows. */

/* fe_geq inlined.  Compare [rdi] ≥ [rsi] limb-by-limb from the
 * top; loopz falls out on first mismatch with cmp's CF live. */
.Lop5:	push	4
	pop	rcx
1:	mov	rax, [rdi+rcx*8-8]
	cmp	rax, [rsi+rcx*8-8]
	loopz	1b
	setae	al
	jmp	.Lor
/* s2 bit0 (= bit4 of byte1 at [rbx-2]) selects sense.  s2=0
 * checkzero (fail if zero), s2=1 checknonzero (fail if nonzero).
 * 13 B vs 14 B for two handlers.  Reads byte1 back from the
 * stream — decoder's `and eax,0xF` consumed s2 already. */
.Lop6:	call	fe_iszero
	test	BYTE PTR [rbx-2], 0x10
	jz	.Lor
	xor	al, 1
.Lor:	or	bpl, al
	ret
/* MULCN: Fmul with b = &cN (.text) instead of a slot.  bc_v3
 * uses this for n·z²; diff2 = diff1 − n·z² (mod p) via Fsub
 * is equivalent to diff1 + (p−n)·z² via Fadd but needs no p−n.
 * rcx = &cP untouched (mod-p).  rel8 to Fmul. */
.Lop9:
MULCN:	lea	rdx, [r14+oN]
	jmp	Fmul
/* Nmul/Fmul differ only in modulus.  Decoder preloaded rcx = &cP;
 * Nmul overwrites to &cN and falls through. */
.Lop4:
Nmul:	lea	rcx, [r14+oN]
	/* FALLTHROUGH */
.Lop0:
Fmul:	jmp	fe_mul_m
/* SQR = Fmul: bytecode encodes s2=s1, decoder already set rdx=rsi. */
.equ .Lop1, .Lop0
/* Fadd (dst = s1+s2 mod p): compute p−s2 into slot 3 (scratch),
 * fall through to Fsub with rdx=&scratch so .Lop3 does s1−(p−s2).
 * Fadd preserves rcx=&cP across fe_sub_raw (push/pop) so Fsub's
 * add-back path gets the right modulus. */
/* Fsub (.Lop3): dst = a−b; if borrow, add m back.  fe_sub_raw
 * returns borrow in CF; pops preserve flags → jnc direct.  The
 * add-back's first adc needs CF=0: clc (rcx=0 from fe_sub_raw's
 * dec-to-0, but we're on the CF=1 path).  ALSO used by fe_mul_m
 * for its final conditional subtract. */
.Lop2:
Fadd:	push	rdi
	push	rsi
	push	rcx                 /* save &P across fe_sub_raw */
	lea	rdi, [r12+3*32]
	push	rdi
	push	rcx
	pop	rsi
	/* Fadd calls .Lop3 for p−s2 → scratch.  s2 < p so .Lop3's
	 * jnc (no borrow) always taken — same result as fe_sub_raw
	 * but reusing the inlined body.  0 B change (rel32 either way). */
	call	.Lop3
	pop	rdx
	pop	rcx
	pop	rsi
	pop	rdi
	/* FALLTHROUGH */
/* fe_sub_raw inlined here — sole remaining caller.  The op6/7
 * merge freed exactly 14 B of handler-block headroom (.Lop8
 * 241+14 = 255, fits u8).  −20 B (standalone gone) +19 (body)
 * −5 (call) = −6 B.  Plus −2 B from the merge = −8 B chain. */
.Lop3:	push	rcx
	push	rdi
	xor	ecx, ecx
	mov	cl, 4
3:	lodsq
	sbb	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	dec	ecx
	jnz	3b
	pop	rdi
	pop	rdx
	jnc	1f
	push	rdi                 /* 2B vs 3B REX.W mov */
	pop	rsi
	clc                         /* rcx=0 from fe_sub_raw; CF=1 on this path */
	mov	cl, 4
2:	lodsq
	adc	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	dec	ecx
	jnz	2b
1:	ret

/* .Lop8 = fe_inv_m.  Placed here so its offset from .Ljt fits u8.
 * Called only from bc_v1 (op 8), mod-n only — mod-p inversion was
 * eliminated by the projective final check. */
.Lop8:
/* fe_inv_m: r = a^(n-2) mod n (Fermat).  NO EXPONENT BUFFER.
 *
 * n and n−2 differ only in bits 1-4 (low byte 0x51 vs 0x4F — a
 * four-bit borrow cascade, no borrow into byte 1).  So: bt
 * directly on cN in .text and special-case ebx<5.
 *   ebx ∈ {0,1,2,3}: force mul (n−2 bits 0-3 = 1111; n bit 0 is
 *                    also 1 so the ebx=0 force is redundant-correct)
 *   ebx == 4:        force skip (n bit4=1 but n−2 bit4=0)
 *   ebx ≥ 5:         n and n−2 agree — bt on cN is exact.
 *
 * Loop counter in rbx (callee-saved, survives .Lfm).  dst in r8
 * (fe_mul_m doesn't touch it).  src pushed to [rsp].  r14 = .Ljt
 * (bc_run's hoist — fe_mul_m doesn't touch that either). */
fe_inv_m:
	push	rbx
	push	rsi                 /* src → [rsp] for the loop */
	mov	r8, rdi             /* dst — survives fe_mul_m */

	/* rdi,rsi still hold dst,src.  rcx = &cP (decoder preload),
	 * not 0, so push/pop not mov cl. */
	push	4
	pop	rcx
	rep	movsq               /* dst ← src.  rcx=0 after. */

	xor	ebx, ebx
	mov	bl, 254
.Le:	mov	rdi, r8
	push	rdi                 /* stash across .Lfm (balances stack too) */
	push	rdi
	push	rdi
	pop	rdx
	pop	rsi
	call	.Lfm
	pop	rdi
	/* Bits 0-4 special: n=…10001, n-2=…01111 in the low nibble+1.
	 * jb catches 0-3 (force mul), je catches 4 (force skip). */
	cmp	ebx, 4
	jb	.Lmul
	je	.Lnx
	bt	DWORD PTR [r14+oN_early], ebx   /* cN in .text, disp8 */
	jnc	.Lnx
.Lmul:	push	rdi
	pop	rsi
	mov	rdx, [rsp]          /* src; rsp stable between iterations */
	call	.Lfm
.Lnx:	dec	ebx
	jns	.Le

	pop	rcx                 /* discard src */
	pop	rbx
	ret

/* ======================================================================
 * Public entry point.
 * ====================================================================== */
	.globl	tv_ecdsa_p256_verify_asm
	.type	tv_ecdsa_p256_verify_asm, @function

tv_ecdsa_p256_verify_asm:
	/* enter 648,0 = push rbp; mov rbp,rsp; sub rsp,648 in 4 B.
	 * rbp stays a true frame pointer end-to-end → leave works at
	 * exit.  Every callee either leaves rbp alone or push/pops it
	 * (bc_run, pt_mul, fe_mul_m).  r15 is the slot-2 mid-pointer;
	 * no callee writes it (pt_mul reads it once for &slot4).
	 * enter is microcoded (~12 cyc) but runs once. */
	push	rbx
	push	r14
	push	r15
	enter	648, 0
	/* r12 not pushed: after MULCN dropped the p−n compute, verify's
	 * only use of &cN was the block-copy source.  Direct rip-rel to
	 * cGX (7B) replaces lea r12(7B) + lea rsi,[r12-64](5B).  pt_mul
	 * push/pops its own r12 (slot4) — independent.  −9 B. */

	/* r14 = slot base for the whole of verify.  r13 not used
	 * anywhere. */
	mov	r14, rsp

	/* ABI args rdi (sig), rdx (pub), r8 (hash) all survive the
	 * length checks (cmp-only on rsi/rcx/r9) and fe_from_be calls
	 * (touch rsi/rdi/rcx/rax only). */
	cmp	rsi, 64
	jne	.Lf2
	cmp	rcx, 65
	jne	.Lf2
	/* 32 ≤ hv_len ≤ 64: fold both checks into one unsigned range test.
	 * sub wraps low values to huge; ja covers both ends.  r9 dead after. */
	sub	r9, 32
	cmp	r9, 32
	ja	.Lf2
	/* fe_from_be: stosq×4 advances rdi by 32; rsi index-read only.
	 * Chain: rdi flows call→call; rsi bumped +32 in place by the
	 * _next entry.  rdi (sig, ABI arg1) still live here. */
	push	rdi                 /* 2B vs 3B REX.W mov */
	pop	rsi
	lea	rdi, [r14+12*32]    /* slot 12 (disp32) */
	call	fe_from_be
	call	fe_from_be_next     /* rsi+=32; rdi flowed to slot 13 */

	/* HASH DECODE here — rdi = slot 14 from sig-decode flowthrough.
	 * Slot 13 (s) untouched so bc_v1 can check it AND invert it;
	 * e goes to 14 where the appended Nmul reads it.  fe_from_be
	 * touches only rsi/rdi/rcx/rax — r8 (hash, ABI arg5) and rdx
	 * (pub) both survive the sig-decode calls above.  rcx=0 on
	 * entry (fe_from_be loop exit).  rdi → slot 15 for build_one. */
	mov	rsi, r8
	call	fe_from_be

	/* build_one: rdi = slot 15.  Only 4 qwords (slot 14 already
	 * holds hash).  rcx=0 from fe_from_be. */
	mov	cl, 4
	xor	eax, eax
	rep	stosq
	inc	DWORD PTR [rdi-32]
	/* rdi = slot 16 now.  Stockpile rbx = &slot13 — survives to
	 * pt_mul (bc_run push/pops rbx, nothing else writes it).
	 * Shamir's slot16 lea uses it for disp8. */
	lea	rbx, [rdi-96]       /* slot 13 */

	cmp	BYTE PTR [rdx], 0x04
	jne	.Lf2
	lea	rsi, [rdx+1]
	mov	rdi, r14            /* slot 0 */
	call	fe_from_be
	call	fe_from_be_next     /* rsi+=32; rdi flowed to r14+64 */
	mov	r15, rdi            /* = slot 2; cheaper than lea from r14 */

	/* ONE 16-qword copy: cGX,cGY,cN,cP → slots 2,3,4,5.  G → 2,3
	 * (survives to Shamir — bc_v1 never writes them).  cN,cP → 4,5
	 * (bc_v1's check ops read them first, then Q-copy overwrites).
	 * rdi already at slot 2 from pub decode.  rcx=0. */
	lea	rsi, [rip+cGX]
	mov	cl, 16
	rep	movsq               /* rdi → slot 6, rcx → 0 */

	push	obc_v1
	pop	rdi
	call	bcrun_r14
	/* bc_v1 fail: fall through into .Lf2.  Every other fail
	 * (length checks, 0x04 check) reaches .Lf2 as rel8 from
	 * here.  .Lf2's own jmp to .Ld2 is near the rel8 edge —
	 * a byte or two of growth between here and .Ld2 blows it. */
	jnc	1f
.Lf2:	xor	eax, eax
	jmp	.Ld2
1:
	/* bc_v1 also ran INV + the two Nmuls (u1,u2 now in 13,14).
	 * NO cond_sub of the hash: e might be ≥ n but Nmul computes
	 * e·s⁻¹ mod n correctly for any a < 2^256. */

	/* Shamir setup: slots 2-5 → slots 16-19 (G.xy + Q.xy backup).
	 * Slots 2,3 hold G (block-copied pre-bc_v1, never written by
	 * bc_v1); slots 4,5 hold Q (bc_v1's Fmul(x,1) copy ops).  One
	 * 16-qword rep movsq.  rbx = &slot13 from the stockpile.
	 * rcx=0: bc_v1's last op is Nmul → fe_mul_m → .Lop3 exit. */
	lea	rdi, [rbx+96]       /* slot 16 = slot 13 + 96: disp8 */
	mov	rsi, r15            /* slot 2 */
	mov	cl, 16
	rep	movsq               /* slots 2-5 → 16-19 in one go */

	/* rbx = &slot13 (stockpile) — pt_mul reads u1/u2 from it. */
	call	pt_mul              /* acc (slots 0-2) = u1·G + u2·Q */

	/* bc_v3: projective check.  See bc_v3 header. */
	push	obc_v3
	pop	rdi
	call	bcrun_r14
	sbb	eax, eax            /* CF=1 → eax=−1; CF=0 → eax=0 */
	inc	eax                 /* −1→0 (fail), 0→1 (valid) */
.Ld2:	leave               /* mov rsp,rbp; pop rbp — rbp untouched since enter */
	pop	r15
	pop	r14
	pop	rbx
	ret

	.section .note.GNU-stack,"",@progbits
