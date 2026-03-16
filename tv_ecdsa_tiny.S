/* ======================================================================
 * ECDSA/P-256 verify — x86-64, bytecode-interpreted, SIZE-OPTIMIZED.
 *
 * 1032 B default build; 1012 B with -DSMALL_MUL8 (~2× cycles).
 * Requires MOVBE only (no BMI2 — plain `mul`, not `mulx`).
 *
 * THE FOUR BIG IDEAS
 *
 *   1. NO MONTGOMERY.  Both P-256 moduli have top dword 0xFFFFFFFF
 *   and 2^256 − m < 2^224.  At 32-bit granularity, the reduction
 *   is just  q = t[top_dword]; t −= q·m  repeated.  Each step
 *   leaves t[top] ∈ {0,1}.  No quotient estimation, no m⁻¹, no R².
 *   Field elements stay in normal form throughout.
 *
 *   2. RCB COMPLETE ADDITION.  One 43-op formula (Renes-Costello-
 *   Batina, ePrint 2015/1060) handles P+Q, P+P, P−P=∞, ∞+Q=Q
 *   without branching.  The 62-byte pt_add_acc 3-way branch tree
 *   (acc.z / H / Rr checks) becomes an 11-byte "copy addend then
 *   dispatch".  Doubling is the same operation with addend = acc.
 *   Coordinates are homogeneous projective (x=X/Z), not Jacobian.
 *
 *   3. NO MOD-p INVERSION.  The final check x ≡ r (mod n) becomes
 *   X ≡ r·Z (mod p) OR X ≡ (r+n)·Z (mod p) — stay in projective
 *   coords, check the product of the two differences for zero
 *   (p prime → product zero iff a factor is zero).  All in bc_v3.
 *
 *   4. bt ON cN DIRECTLY.  Fermat inversion (mod-n only — mod-p
 *   gone via #3) needs the bits of n−2.  n and n−2 differ only in
 *   bits 1-4 (0x51 vs 0x4F: a four-bit borrow cascade, nothing
 *   higher).  So bt on cN in .text (read-only) is correct for
 *   bits 5+, and a 7-byte cmp/jb/je handles bits 0-4.  No exponent
 *   buffer, no copy-and-decrement.
 *
 * BYTECODE INTERPRETER
 *
 *   2-byte ops over 22 stack slots (16 work + 6 backup).  Nibble
 *   encoding: byte1 = (s2<<4)|op, byte2 = (dst<<4)|s1.  9 handlers
 *   in a u8 jump table right before the constants — &cP and &cN
 *   are disp8-reachable from r14 (= &.Ljt).  .Lop8 (fe_inv_m, the
 *   biggest handler) lands at offset 255/255 — zero headroom, but
 *   it fits.  Three streams: bc_rcb (88B), bc_v3 (16B), bc_v1 (58B).
 *
 * KEY INVARIANTS
 *
 *   RCB NEVER WRITES slots 4,5,6,10.  pt_mul relies on this: the
 *   addend (4-6) stays put across the call (no Q-restore needed),
 *   and b (slot 10, derived by bc_v1) survives all 256 iterations.
 *
 *   ∞ = (0:1:0), NOT (0:0:0).  RCB on (0:0:0)+Q gives (0:0:0),
 *   which is wrong.  pt_mul's init explicitly sets slot1 = 1 after
 *   zeroing slots 0-2.  Self-adding (0:1:0) keeps it canonical.
 *
 *   cGX→cGY→cN→cP contiguous after .Ljt — verify's single 16-qword
 *   rep movsq lands G in slots 2-3, cN in 4, cP in 5.  bc_v1's
 *   check ops read cN/cP first, THEN the copy ops overwrite 4,5
 *   with Q.  Order matters.
 *
 *   rcx=0 is a precondition for most `mov cl,N` sites.  Every
 *   caller gets rcx=0 from a prior loop-to-zero (rep, .Lop3's
 *   dec-to-0, fe_iszero).  Audit these if reordering.
 *
 * -DSMALL_MUL8: uses `loop`+`scasd` in mul8's inner loop (both
 * microcoded, ~7+3 cyc vs 1+1).  ~950K iterations → ~3M cycle
 * penalty.  Default uses dec+jnz + lea.  See mul8 macro header.
 *
 * Security and validation unchanged from tv_ecdsa_bc.S.
 * ====================================================================== */

	.intel_syntax noprefix

/* ======================================================================
 * Bytecode.  Placed before .text so stream offsets (bc_X - bc_rcb) are
 * backward references at the call sites — gas picks the imm8 encoding
 * for `push`.  Order chosen so all offsets ≤ 120 (fits signed imm8;
 * bc_v1 is last).
 *
 * Call sites load the offset as a small integer (push imm8; pop rdi,
 * or xor edi,edi for bc_rcb), and bcrun_off adds the base.
 * ====================================================================== */
	.section .rodata
	.p2align 3

/* bc_rcb: Renes-Costello-Batina COMPLETE addition (ePrint 2015/1060,
 * Algorithm 7 for a=−3).  "Complete" means one formula gives the
 * right answer for EVERY input pair — P+Q (distinct), P+P (doubling),
 * P+(−P) = ∞, and ∞+Q = Q — with no branching.  This is what lets
 * pt_add_acc be 11 bytes instead of 62: no acc.z check, no H check,
 * no Rr check.  The old Jacobian add1/add2 formulas would divide by
 * zero on these edge cases.
 *
 * COORDINATES: homogeneous projective — (X:Y:Z) represents the
 * affine point (X/Z, Y/Z).  This is DIFFERENT from Jacobian
 * (X/Z², Y/Z³).  ∞ is any (0:Y:0) with Y≠0.  Y≠0 matters: RCB
 * on (0:0:0)+Q gives (0:0:0) ≠ Q, but (0:1:0)+Q gives Q correctly.
 * The self-add (0:1:0)+(0:1:0) = (0:1:0) — ∞ stays canonical.
 *
 * THE SIZE WIN:  This one 43-op stream replaces bc_dbl (50 B) +
 * bc_add1 (24 B) + bc_add2 (28 B) = 102 B with 88 B.  More
 * importantly, pt_add_acc's entire 3-way branch tree dissolves
 * into "copy addend; dispatch bc_rcb".  Doubling is the SAME
 * operation — just copy acc into the addend slots first.
 *
 * SLOT LAYOUT:
 *   Inputs:   P=(X1,Y1,Z1) in 0,1,2.  Q=(X2,Y2,Z2) in 4,5,6.
 *             b (curve constant) in slot 10.
 *   Output:   P+Q in slots 0,1,2.
 *   READ-ONLY: slots 4,5,6,10.  Load-bearing — pt_mul relies on
 *             Q/G being preserved across the call, and b must
 *             survive 256 iterations.
 *   Scratch:  7,8,9,11,15 (permanent) + 3 (transient).
 *
 * The slot-3 trick: the formula needs 6 live temporaries at once
 * (step 10), but we only have 5 permanent scratch slots.  Slot 3
 * is Fadd's internal scratch (clobbered by every Fadd), BUT the
 * sixth temp (t5) is always written BY an Fadd and consumed BY the
 * very next Fmul/Fsub — never spanning another Fadd.  So slot 3
 * serves both roles: Fadd writes p−s2 there, then dst=3 means the
 * final result overlays it, and the next op reads it before any
 * clobber.  Tight but verified by exhaustive Python simulation
 * against the affine reference for all edge cases. */
bc_rcb:
	.byte 0x40,0x70, 0x50,0x81, 0x60,0x92, 0x12,0xb0, 0x52,0xf4
	.byte 0xf0,0xbb, 0x82,0xf7, 0xf3,0xbb, 0x22,0xf1, 0x62,0x35
	.byte 0x30,0xff, 0x92,0x38, 0x33,0xff, 0x62,0x14, 0x22,0x30
	.byte 0x10,0x03, 0x92,0x17, 0x13,0x10, 0xa0,0x29, 0x23,0x01
	.byte 0x02,0x20, 0x22,0x00, 0x03,0x28, 0x02,0x08, 0xa0,0x11
	.byte 0x92,0x89, 0x92,0x98, 0x93,0x11, 0x73,0x11, 0x12,0x81
	.byte 0x12,0x18, 0x72,0x87, 0x72,0x78, 0x93,0x77, 0x10,0x8f
	.byte 0x10,0x97, 0x20,0x10, 0x92,0x11, 0x00,0x0b, 0x83,0x00
	.byte 0x20,0x2f, 0x70,0x8b, 0x82,0x22
	.byte 0x00,0x00

/* bc_v3: PROJECTIVE CHECK — homogeneous coords (x=X/Z, not X/Z²).
 * Valid iff X/Z mod n == r ⇔ X ≡ r·Z (mod p) OR X ≡ (r+n)·Z.
 * diff2 = diff1 − n·Z via MULCN+Fsub.  slot7 scratch (RCB's t0,
 * dead after pt_mul).  7 ops — one less than Jacobian (no Z²). */
bc_v3:
	.byte 0x06,0x20            /* checkzero slot2 (Z): ∞ → fail   */
	.byte 0x20,0x7c            /* slot7  = r·Z  (r=12, Z=2)       */
	.byte 0x73,0x70            /* slot7  = X − r·Z        = diff1 */
	.byte 0x08,0x32            /* slot3  = n·Z  (MULCN, s1=Z)     */
	.byte 0x33,0x37            /* slot3  = diff1 − n·Z    = diff2 */
	.byte 0x70,0x33            /* slot3  = diff1·diff2            */
	.byte 0x16,0x30            /* check slot3 nonzero (op6 s2=1)  */
	.byte 0x00,0x00

/* bc_v1: range checks + curve check + s⁻¹ + u1,u2.
 *
 * Q in slots 0,1; G in slots 2,3; cN,cP temporarily in 4,5
 * (block-copied, read by the checks, then overwritten by Q-copy).
 *
 * Slots 4,5 get Qx,Qy via Fmul(x, slot15=1) = x — a 2-B copy.
 * Slot 6 = 1 via 1·1 (addend's Z for RCB).
 *
 * Curve constant b is derived from G (b = Gy² − Gx³ + 3·Gx).
 * slot 10 holds b THROUGHOUT pt_mul — RCB reads it, never writes.
 * Curve check uses slots 7,11 as scratch so 0,1,4,5 survive for
 * the Shamir copy.  No Fadd anywhere — Fadd clobbers slot 3 (Gy). */
bc_v1:
	/* Range/zero checks.  cN/cP in slots 4,5 (block-copied). */
	.byte 0x06,0xc0, 0x05,0xc4, 0x06,0xd0, 0x05,0xd4
	.byte 0x05,0x05, 0x05,0x15
	.byte 0xf0,0x40            /* slot4 = Qx·1 = Qx  (copy)    */
	.byte 0xf0,0x51            /* slot5 = Qy·1 = Qy  (copy)    */
	.byte 0xf0,0x6f            /* slot6 = 1·1 = 1    (addend Z)*/
	/* b-derive: G in 2,3.  slot10 = b (survives pt_mul — RCB
	 * reads slot 10 for the b multiplications, never writes). */
	.byte 0x21,0xa2            /* slot10 = Gx²           (SQR) */
	.byte 0x20,0xaa            /* slot10 = Gx³           (Fmul)*/
	.byte 0x23,0xaa            /* slot10 -= Gx           (Fsub)*/
	.byte 0x23,0xaa            /* slot10 -= Gx           (Fsub)*/
	.byte 0x23,0xaa            /* slot10 -= Gx (=Gx³−3Gx)      */
	.byte 0x31,0x73            /* slot7  = Gy²           (SQR) */
	.byte 0xa3,0xa7            /* slot10 = Gy²−slot10 = b(Fsub)*/
	/* Curve check: scratch in 7,11 so Q(0,1,4,5) and G(2,3)
	 * survive.  slot7 = Qy²−b−(Qx³−3Qx); nonzero ⇔ off-curve. */
	.byte 0x01,0xb0            /* slot11 = Qx²           (SQR) */
	.byte 0x00,0xbb            /* slot11 = Qx³           (Fmul)*/
	.byte 0x03,0xbb            /* slot11 -= Qx           (Fsub)*/
	.byte 0x03,0xbb            /* slot11 -= Qx           (Fsub)*/
	.byte 0x03,0xbb            /* slot11 -= Qx (=Qx³−3Qx)      */
	.byte 0x11,0x71            /* slot7  = Qy²           (SQR) */
	.byte 0xa3,0x77            /* slot7 -= b             (Fsub)*/
	.byte 0xb3,0x77            /* slot7 -= slot11        (Fsub)*/
	.byte 0x16,0x70            /* check slot7 nonzero (op6 s2=1)  */
	.byte 0x07,0x0d            /* INV (op7): slot0 = s⁻¹ mod n    */
	.byte 0x04,0xde            /* slot13 = slot14·slot0 = e·s⁻¹ = u1 */
	.byte 0x04,0xec            /* slot14 = slot12·slot0 = r·s⁻¹ = u2 */
	.byte 0x00,0x00

.equ obc_rcb,  0
.equ obc_v3,   bc_v3  - bc_rcb
.equ obc_v1,   bc_v1  - bc_rcb

/* ---------------------------------------------------------------------- */
	.text

/* ----------------------------------------------------------------------
 * 256-bit primitives (4 × u64 limbs, little-endian).
 * -------------------------------------------------------------------- */

/* fe_iszero(a=rdi) -> al=1 iff zero.  OR-accumulates into rax;
 * last OR's ZF reflects the full 256-bit value.  Sole caller is
 * .Lop6 (the bytecode check handler) — reads only al.  High bytes
 * of rax are garbage from the OR loop.  Preserves rdi. */
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

/* ----------------------------------------------------------------------
 * .Lcadd / pt_mul read the slot base from r14 (verify's r14=rsp) and
 * r15 (= slot 2, for deriving &slot4 as r15+64).  bc_run push/pops
 * r14/r15 around its own use so they always come back.
 *
 * Placed right before bcrun_r14: add2 path FALLS THROUGH (no jmp),
 * dbl path's jmp is rel8.  x86-64 has no short call — the mid-body
 * `call bcrun_r14` is still rel32.
 * -------------------------------------------------------------------- */
/* RCB complete addition handles P+Q, 2P, P−P=∞, ∞+Q uniformly.
 * pt_mul's helper copies src → addend slots (4-6), then dispatches
 * bc_rcb.  Doubling = self-add (src=r14=acc); Q/G adds use 3-slot
 * backups (X,Y,Z=1).  rsi set by caller; rcx=0 on entry (every
 * path: rep movsq above or bc_run epilogue's neg+pops).  rel8 to
 * bcrun_r14 just below. */
.Lcadd:
	lea	rdi, [r15+64]       /* addend = slot4 */
	mov	cl, 12
	rep	movsq
	xor	edi, edi            /* obc_rcb = 0 */
	/* FALLTHROUGH to bcrun_r14 */

/* ======================================================================
 * BYTECODE INTERPRETER
 * ====================================================================== */
/* rdi = byte offset from bc_rcb.  bcrun_off resolves; bcrun_r14 also
 * supplies rsi = r14 (slot base).  Call sites use push imm8; pop rdi
 * (2-3 B) instead of 7-B rip-rel lea. */
bcrun_r14:
	mov	rsi, r14
bcrun_off:
	lea	rax, [rip+bc_rcb]
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
 * callers branch on CF directly (jc = a check failed for bc_v1/v3;
 * bc_rcb has no checks so CF=0 always). */
.Lbce:	neg	ebp
	pop	r14
	pop	r12
.Lepi2:
	pop	rbx
	pop	rbp
	ret

/* pt_mul: Shamir via RCB-ONLY.  Doubling = self-add (acc→addend,
 * RCB).  Q/G adds use 3-slot backups (X,Y,Z=1) — RCB reads addend
 * Z from slot6 and NEVER writes slots 4-6.  r12 not needed.
 *
 * Caller (verify): rbx=&slot16.  u1 at [rbx−96], u2 at [rbx−64].
 * G-backup at [rbx], Q-backup at [rbx+96] — both disp8.  r14=slot base.
 * r15=slot2.  G-backup at slots 16-18, Q-backup at 19-21.
 * slot10 = b (RCB reads, never writes).  rcx=0 on entry. */
pt_mul:
	push	rbp
	/* Init acc = ∞ = (0:1:0).  RCB needs Y≠0 for ∞+Q=Q. */
	mov	rdi, r14
	xor	eax, eax
	mov	cl, 12
	rep	stosq               /* slots 0-2 = 0 */
	inc	DWORD PTR [r14+32]  /* slot1 = 1 */
	dec	al                  /* al was 0, now 255 */
	xchg	ebp, eax            /* ebp = 255 */
.Lpm:
	/* Doubling: copy acc (0-2) → addend (4-6), self-add. */
	mov	rsi, r14
	call	.Lcadd
	/* u2 bit: copy Q-backup (slots 19-21) → addend, add. */
	bt	DWORD PTR [rbx-64], ebp   /* u2 = slot14 = slot16−64 */
	jnc	2f
	lea	rsi, [rbx+96]       /* slot19 = slot16+96.  disp8. */
	call	.Lcadd
2:	/* u1 bit: copy G-backup (slots 16-18) → addend, add. */
	bt	DWORD PTR [rbx-96], ebp   /* u1 = slot13 */
	jnc	3f
	push	rbx
	pop	rsi                 /* slot16 — G is here; 2B vs 3B mov */
	call	.Lcadd
3:	dec	ebp
	jns	.Lpm
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
	enter	712, 0              /* 22 slots: 3-slot backups for RCB */
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
	/* rdi = slot 16.  Stockpile rbx = slot16 (not 13) — makes
	 * G-backup a mov, Q-backup disp8 instead of disp32.  u1/u2
	 * at [rbx−96]/[rbx−64], both disp8.  push;pop = 2B vs 4B lea. */
	push	rdi
	pop	rbx                 /* slot 16 */

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

	/* Shamir setup: 3-slot backups for RCB (X,Y,Z=1 each).
	 * G at slots 16-18, Q at 19-21.  G.xy in slots 2,3 (block
	 * copy), Q.xyz in slots 4,5,6 (bc_v1 copies + slot6=1).
	 * G's Z borrowed from slot6.  rcx=0 from bc_v1's last Nmul. */
	push	rbx
	pop	rdi                 /* slot 16 — 2B vs 3B mov */
	mov	rsi, r15            /* slot 2 */
	mov	cl, 8
	rep	movsq               /* G.xy → 16,17.  rdi=slot18, rsi=slot4. */
	lea	rsi, [rsi+64]       /* slot6 (slot4+64) */
	mov	cl, 4
	rep	movsq               /* slot6 → slot18 (G.z=1).  rdi=slot19. */
	lea	rsi, [r15+64]       /* slot4 */
	mov	cl, 12
	rep	movsq               /* Q.xyz (4,5,6) → 19,20,21. */

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
