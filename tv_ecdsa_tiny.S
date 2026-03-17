/* ======================================================================
 * ECDSA/P-256 verify — x86-64, bytecode-interpreted, SIZE-OPTIMIZED.
 *
 * 978 B default build; 964 B with -DSMALL_MUL8.  The SMALL_MUL8 knob
 * now trades −14 B for +39% cycles — `scasd` stays (the real size
 * win), `loop` is gone (was ~80% of the cycle penalty on its own).
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
 *   are disp8-reachable from r12 (= &.Ljt).  .Lop8 (fe_inv_m, the
 *   biggest handler) lands at offset 252/255 — 3 B headroom since
 *   Fmul's jmp went rel8.  Streams: bc_rcb (88B), bc_v3 (16B), bc_v1 (60B).
 *
 * KEY INVARIANTS
 *
 *   RCB NEVER WRITES slots 5,6,7,10.  pt_mul relies on this: the
 *   addend (5-7) stays put across the call (no Q-restore needed),
 *   and b (slot 10, derived by bc_v1) survives all 256 iterations.
 *
 *   ∞ = (0:1:0), NOT (0:0:0).  RCB on (0:0:0)+Q gives (0:0:0),
 *   which is wrong.  pt_mul's init explicitly sets slot1 = 1 after
 *   zeroing slots 0-2.  Self-adding (0:1:0) keeps it canonical.
 *
 *   cGX→cGY→cN→cP contiguous after .Ljt — verify's single 16-qword
 *   rep movsq lands G in slots 2-3, cN in 4, cP in 5.  bc_v1's
 *   check ops read cN/cP first, THEN the staging ops overwrite 4-7
 *   with 1,Qx,Qy,1 for the Shamir backup.  Order matters.
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
 *   Inputs:   P=(X1,Y1,Z1) in 0,1,2.  Q=(X2,Y2,Z2) in 5,6,7.
 *             b (curve constant) in slot 10.
 *   Output:   P+Q in slots 0,1,2.
 *   READ-ONLY: slots 5,6,7,10.  Load-bearing — pt_mul relies on
 *             Q/G being preserved across the call, and b must
 *             survive 256 iterations.
 *   Scratch:  4,8,9,11,15 (permanent) + 3 (transient).
 *
 * WHY 5,6,7 NOT 4,5,6:  bc_v1 lays out slots 2..7 as Gx,Gy,1,Qx,
 * Qy,1 — so verify's Shamir backup is ONE 24-qword rep movsq
 * (slots 2-7 → 16-21) instead of three separate copies.  The
 * addend slot shift is a pure nibble relabeling (4→5,5→6,6→7,7→4
 * cycle); t0 moves from slot 7 to slot 4.  Zero byte cost here;
 * Shamir setup drops 18 B.
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
	.byte 0x50,0x40, 0x60,0x81, 0x70,0x92, 0x12,0xb0, 0x62,0xf5
	.byte 0xf0,0xbb, 0x82,0xf4, 0xf3,0xbb, 0x22,0xf1, 0x72,0x36
	.byte 0x30,0xff, 0x92,0x38, 0x33,0xff, 0x72,0x15, 0x22,0x30
	.byte 0x10,0x03, 0x92,0x14, 0x13,0x10, 0xa0,0x29, 0x23,0x01
	.byte 0x02,0x20, 0x02,0x02, 0x03,0x28, 0x02,0x08, 0xa0,0x11
	.byte 0x92,0x89, 0x92,0x98, 0x93,0x11, 0x43,0x11, 0x12,0x81
	.byte 0x12,0x18, 0x42,0x84, 0x42,0x48, 0x93,0x44, 0x10,0x8f
	.byte 0x10,0x94, 0x20,0x10, 0x12,0x19, 0xb0,0x00, 0x83,0x00
	.byte 0x20,0x2f, 0x40,0x8b, 0x22,0x28
	.byte 0x00                 /* 1-B terminator (test al,al) */

/* bc_v3: PROJECTIVE CHECK — homogeneous coords (x=X/Z, not X/Z²).
 * Valid iff X/Z mod n == r ⇔ X ≡ r·Z (mod p) OR X ≡ (r+n)·Z.
 * diff2 = diff1 − n·Z via MULCN+Fsub.  slot7 scratch (was RCB's
 * addend Z, dead after pt_mul).  7 ops — one less than Jacobian. */
bc_v3:
	.byte 0x06,0x20            /* checkzero slot2 (Z): ∞ → fail   */
	.byte 0x20,0x7c            /* slot7  = r·Z  (r=12, Z=2)       */
	.byte 0x73,0x70            /* slot7  = X − r·Z        = diff1 */
	.byte 0x08,0x32            /* slot3  = n·Z  (MULCN, s1=Z)     */
	.byte 0x33,0x37            /* slot3  = diff1 − n·Z    = diff2 */
	.byte 0x70,0x33            /* slot3  = diff1·diff2            */
	.byte 0x16,0x30            /* check slot3 nonzero (op6 s2=1)  */
	.byte 0x00

/* bc_v1: range checks + curve check + Shamir staging + s⁻¹ + u1,u2.
 *
 * Q in slots 0,1; G in slots 2,3; cN,cP temporarily in 4,5
 * (block-copied, read by the checks, overwritten later).
 *
 * Curve constant b is derived from G (b = Gy² − Gx³ + 3·Gx).
 * slot 10 holds b THROUGHOUT pt_mul — RCB reads it, never writes.
 * No Fadd anywhere — Fadd clobbers slot 3 (Gy).
 *
 * SHAMIR STAGING (runs after curve check, before INV): four copy
 * ops lay slots 4-7 out as  1, Qx, Qy, 1.  Combined with G at
 * slots 2,3, verify sees slots 2-7 = Gx,Gy,1,Qx,Qy,1 — exactly
 * the backup layout pt_mul wants.  One 24-qword rep movsq.
 * Must run AFTER curve check (which clobbers slot 7) and BEFORE
 * INV (which clobbers slot 0 = Qx). */
bc_v1:
	/* Range/zero checks.  cN/cP in slots 4,5 (block-copied). */
	/* checkzero-s DROPPED: s=0 → INV gives 0 → u1=u2=0 → ladder
	 * never adds → R=∞ → bc_v3's checkzero(Z) catches it.  −2 B. */
	.byte 0x06,0xc0, 0x05,0xc4,            0x05,0xd4
	.byte 0x09,0x00, 0x09,0x10   /* geq_p (op9): r13 = &cP, s1 unused */
	/* b-derive: G in 2,3.  slot10 = b (survives pt_mul — RCB
	 * reads slot 10 for the b multiplications, never writes). */
	.byte 0x21,0xa2            /* slot10 = Gx²           (SQR) */
	.byte 0x20,0xaa            /* slot10 = Gx³           (Fmul)*/
	.byte 0x23,0xaa            /* slot10 -= Gx           (Fsub)*/
	.byte 0x23,0xaa            /* slot10 -= Gx           (Fsub)*/
	.byte 0x23,0xaa            /* slot10 -= Gx (=Gx³−3Gx)      */
	.byte 0x31,0x73            /* slot7  = Gy²           (SQR) */
	.byte 0xa3,0xa7            /* slot10 = Gy²−slot10 = b(Fsub)*/
	/* Curve check: scratch in 7,11 so Q(0,1) and G(2,3) survive.
	 * slot7 = Qy²−b−(Qx³−3Qx); nonzero ⇔ off-curve. */
	.byte 0x01,0xb0            /* slot11 = Qx²           (SQR) */
	.byte 0xb0,0xb0            /* slot11 = Qx³  (commuted — s2≠0)*/
	.byte 0x03,0xbb            /* slot11 -= Qx           (Fsub)*/
	.byte 0x03,0xbb            /* slot11 -= Qx           (Fsub)*/
	.byte 0x03,0xbb            /* slot11 -= Qx (=Qx³−3Qx)      */
	.byte 0x11,0x71            /* slot7  = Qy²           (SQR) */
	.byte 0xa3,0x77            /* slot7 -= b             (Fsub)*/
	.byte 0xb3,0x77            /* slot7 -= slot11        (Fsub)*/
	.byte 0x16,0x70            /* check slot7 nonzero (op6 s2=1)  */
	/* Shamir staging: slots 4-7 ← 1,Qx,Qy,1 via Fmul(·, slot15=1).
	 * Runs after curve check (slot7 now free), before INV (slot0
	 * still Qx).  This +2 B here saves 18 B in verify.  −16 net. */
	.byte 0xf0,0x4f            /* slot4 = 1·1 = 1  (G-backup Z) */
	.byte 0xf0,0x50            /* slot5 = Qx·1 = Qx             */
	.byte 0xf0,0x61            /* slot6 = Qy·1 = Qy             */
	.byte 0xf0,0x7f            /* slot7 = 1·1 = 1  (Q-backup Z) */
	/* slot0 = 1 for fe_inv_m: loop starts r=1 at bit 255 instead
	 * of r=a at bit 254 (bit 255 of n−2 is 1, so first iter gives
	 * r=1²·a=a — same state, one iter later).  +2 B here; drops
	 * rep movsq + r8 save/restore in fe_inv_m = −12 B.  Qx already
	 * safe in slot5. */
	.byte 0xf0,0x0f            /* slot0 = 1·1 = 1  (fe_inv_m seed) */
	.byte 0x07,0x0d            /* INV (op7): slot0 = s⁻¹ mod n    */
	.byte 0x04,0xde            /* slot13 = slot14·slot0 = e·s⁻¹ = u1 */
	.byte 0x04,0xec            /* slot14 = slot12·slot0 = r·s⁻¹ = u2 */
	.byte 0x00

.equ obc_rcb,  0
.equ obc_v3,   bc_v3  - bc_rcb
.equ obc_v1,   bc_v1  - bc_rcb

/* ---------------------------------------------------------------------- */
	.text

/* ----------------------------------------------------------------------
 * 256-bit primitives (4 × u64 limbs, little-endian).
 * -------------------------------------------------------------------- */

/* fe_iszero INLINED in .Lop6 — cP removal freed 36 B handler
 * headroom, enough for the 10 B body growth.  −16 B standalone
 * + (15 body − 5 call) = −6 B net. */
/* fe_sub_raw INLINED in .Lop3 — see handler block. */

/* mul8 OP: dst[0..8] OP= ebx·src[0..7], 32-bit limbs.  One
 * expansion in the default build (reduce=sub only — schoolbook
 * is 64-bit inlined); two under SMALL_MUL8 (add + sub).
 *
 * Hottest loop — ~1.3M iterations/verify.  `scasd` (1 B) is
 * microcoded (~3 cyc); `loop` was catastrophically so (~5 cyc
 * EFFECTIVE penalty/iter, ~6.5M cyc total in SMALL_MUL8).  The
 * SMALL_MUL8 knob now keeps `scasd` for the size edge (−3 B/exp
 * vs `lea`) but drops `loop` for dec+jnz (+2 B/exp, −39% cycles).
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
	scasd                       /* 1 B, ~3 cyc microcoded — keeps the size edge */
	dec	ecx
	jnz	7b                  /* was `loop`: +2 B, recovers ~5 cyc/iter */
#else
	lea	rdi, [rdi+4]        /* 4 B, 1 cyc — +3 B over scasd */
	dec	ecx
	jnz	7b
#endif
	\op	[rdi], ebp
.endm

/* oN hardcode: gas won't pick disp8 for forward-ref oN at the bt
 * in fe_inv_m.  Assert below.  fe_mul_m moved to AFTER the handler
 * block — Fmul's jmp is rel8 (forward 115 B; 12 B headroom).
 * fe_inv_m reaches it via Nmul → Fmul fallthrough → rel8 jmp. */
.equ	oN_early, 74        /* +1 for the geq_p table entry */

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
 * pt_mul / .Lcadd read the slot base from r14 (verify's r14=rsp).
 * bc_run push/pops r14 around its own use so it always comes back.
 *
 * pt_mul is BEFORE .Lcadd (which is before bcrun_r14) so pt_mul's
 * tail `jmp bcrun_r14` only jumps over .Lcadd (14 B) — rel8, not
 * rel32.  .Lcadd still falls through to bcrun_r14.  pt_mul's three
 * calls to .Lcadd go forward but are rel32 either way (no short
 * call on x86-64).
 * -------------------------------------------------------------------- */
/* pt_mul: Shamir via RCB-ONLY.  Doubling = self-add (acc→addend,
 * RCB).  Q/G adds use 3-slot backups (X,Y,Z=1) — RCB reads addend
 * Z from slot7 and NEVER writes slots 5-7.
 *
 * Caller (verify): rbx=&slot16.  u1 at [rbx−96], u2 at [rbx−64].
 * G-backup at [rbx], Q-backup at [rbx+96] — both disp8.  r14=slot
 * base.  G-backup at slots 16-18, Q-backup at 19-21.
 * slot10 = b (RCB reads, never writes).  rcx=0 on entry. */
pt_mul:
	push	rbp
	/* Init acc = ∞ = (0:1:0).  RCB needs Y≠0 for ∞+Q=Q. */
	mov	rdi, r14
	xor	eax, eax
	mov	cl, 12
	rep	stosq               /* slots 0-2 = 0.  rdi → r14+96. */
	inc	DWORD PTR [rdi-64]  /* slot1 = 1.  [r14+32] costs REX; −1B. */
	dec	al                  /* al was 0, now 255 */
	xchg	ebp, eax            /* ebp = 255 */
.Lpm:
	/* Doubling: copy acc (0-2) → addend (5-7), self-add. */
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
	/* TAIL into bc_v3 dispatch.  pop rbp BEFORE the jmp (bcrun
	 * doesn't know about our push); bcrun's ret goes to OUR
	 * caller (verify) directly — call pt_mul's ret addr is
	 * still on the stack, the jmp preserves it.  CF (check
	 * result) survives all the way to verify's sbb.  The jmp
	 * is rel8 now — only .Lcadd (14 B) between here and bcrun. */
	pop	rbp
	push	obc_v3
	pop	rdi
	jmp	bcrun_r14

/* RCB complete addition handles P+Q, 2P, P−P=∞, ∞+Q uniformly.
 * pt_mul's helper copies src → addend slots (5-7), then dispatches
 * bc_rcb.  Doubling = self-add (src=r14=acc); Q/G adds use 3-slot
 * backups (X,Y,Z=1).  rsi set by caller; rcx=0 on entry (every
 * path: bc_run epilogue's neg+pops, or pt_mul init's rep stosq). */
.Lcadd:
	lea	rdi, [r14+160]      /* addend = slot5.  disp32; r15 is gone. */
	mov	cl, 12
	rep	movsq
	xor	edi, edi            /* obc_rcb = 0 */
	/* FALLTHROUGH to bcrun_r14 */

/* ======================================================================
 * BYTECODE INTERPRETER
 * ====================================================================== */
/* rdi = byte offset from bc_rcb.  r14 = slot base is INHERITED from
 * the caller (verify sets it once; pt_mul/.Lcadd don't touch it) —
 * bc_run pushes r12 and uses IT for &.Ljt instead.  The old tunnel
 * (bcrun_r14 set rsi=r14, bc_run did mov r12,rsi, later used r12 as
 * slot base while r14 got .Ljt) was 10 B of detour that vanishes
 * when r14 stays slot-base end to end.  bcrun_r14 is now just an
 * alias of bcrun_off — callers still jmp/call here for clarity. */
bcrun_r14:
bcrun_off:
	lea	rax, [rip+bc_rcb]
	add	rdi, rax
	/* FALLTHROUGH */
bc_run:
	push	rbp
	push	rbx
	push	r12
	push	rdi                 /* 2B push;pop vs 3B REX.W mov */
	pop	rbx
	/* r14 = slot base (inherited).  r12 → .Ljt.  Check accumulator
	 * in ebp (no REX).  Only bpl is ever OR'd; upper bytes stay
	 * zero from the xor.  r13,r14 not push/popped — not clobbered. */
	xor	ebp, ebp
	lea	r12, [rip+.Ljt]
.Lbc:
	movzx	eax, WORD PTR [rbx]
	add	rbx, 2
	/* END is byte1=0x00.  The two ops that naturally encode as
	 * s2=0/op=0 (bc_rcb 0x00,0x0b; bc_v1 0x00,0xbb) are commuted
	 * (Fmul commutes) so byte1≠0.  Terminator drops to 1 B × 3
	 * streams = −3 B.  The word read past the terminator is the
	 * next stream's first op (or garbage past bc_v1) — ah is dead
	 * on the jz-taken path, doesn't matter. */
	test	al, al
	jz	.Lbce

	/* Nibble layout: al=(s2<<4)|op, ah=(dst<<4)|s1.  Straight-line
	 * decode: no push/pop, no loop.  Slot stride is 32 bytes; a
	 * nibble in bits [7:4] is already ×16, so lea scale-2 finishes it.
	 * `and edi,-16` = 3 bytes (imm8 sign-ext → 0xFFFFFFF0); works
	 * because movzx cleared bits [31:8] already. */
	movzx	edi, ah             /* edi = (dst<<4)|s1 */
	mov	esi, edi
	and	esi, 0xF
	shl	esi, 5
	add	rsi, r14            /* r14 + s1*32 */
	and	edi, -16            /* edi = dst<<4 */
	lea	rdi, [r14+rdi*2]    /* r14 + dst*32 */

	movzx	edx, al             /* edx = (s2<<4)|op; high bits cleared */
	and	dl, 0xF0            /* edx = s2<<4 */
	lea	rdx, [r14+rdx*2]    /* r14 + s2*32 */

	and	eax, 0xF            /* op — ah already dead */
	movzx	eax, BYTE PTR [r12+rax]
	add	rax, r12
	/* Preload rcx = &P: most handlers want it (Fmul/Fsub/Fadd),
	 * the rest overwrite it.  r8 = &cP (slot22), set by verify.
	 * r8 caller-saved but never clobbered in the call tree. */
	mov	rcx, r8
	call	rax
	jmp	.Lbc

/* NEG sets CF=1 iff operand was nonzero.  pops/ret preserve flags —
 * callers branch on CF directly. */
.Lbce:	neg	ebp
	pop	r12
	pop	rbx
	pop	rbp
	ret

/* .Ljt + constants.  cGX→cGY→cN→cP contiguous in that order:
 * verify copies all four to slots 2-5 in one 16-qword rep movsq
 * (G → 2,3; cN → 4; cP → 5).  bc_v1's range/zero checks read
 * cN/cP from 4,5 first, then its staging ops overwrite 4-7 with
 * 1,Qx,Qy,1 — safe because checks run before staging.
 *
 * cGX/cGY between .Ljt and handlers push handler offsets up by
 * 64 B — .Lop8 (fe_inv_m) is the furthest. */
.Ljt:
	.byte	.Lop0-.Ljt, .Lop1-.Ljt, .Lop2-.Ljt, .Lop3-.Ljt
	.byte	.Lop4-.Ljt, .Lop5-.Ljt, .Lop6-.Ljt
	.byte	.Lop8-.Ljt  /* INV = fe_inv_m, mod-n only (op 7) */
	.byte	.Lop9-.Ljt  /* MULCN (op 8) */
	.byte	.Lop5p-.Ljt /* geq_p (op 9): rsi=r13=&cP, for Qx<p/Qy<p */
/* op6 = check (s2 bit0: 0=checkzero, 1=checknonzero).  The old
 * separate checknonzero op was absorbed — s2 encodes sense.  The
 * table entry and handler it freed let fe_sub_raw inline in .Lop3. */

cGX:	.quad 0xf4a13945d898c296, 0x77037d812deb33a0
	.quad 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247
cGY:	.quad 0xcbb6406837bf51f5, 0x2bce33576b315ece
	.quad 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b
cN:	.quad 0xf3b9cac2fc632551, 0xbce6faada7179e84
	.quad 0xffffffffffffffff, 0xffffffff00000000
/* cP DELETED — built at runtime in slot22 (rbp−40, disp8).  19 B of
 * code vs 32 B of data, and r13 holds &cP for the decoder preload
 * (mov rcx,r13 = 3 B vs lea = 4 B).  The 32 B of handler-block
 * headroom this frees lets fe_iszero inline into .Lop6. */

.equ oN,   cN   - .Ljt
.if oN - oN_early
.error "oN moved — update oN_early (fe_inv_m bt uses hardcoded disp8)"
.endif
.if (cN - cGX) - 64
.error "cGX..cN spacing changed — verify's 16-qword block copy depends on cGX,cGY,cN,cP contiguous"
.endif
/* Jump-table offsets fit in u8: .Lop8 is furthest; no assert
 * (gas .if can't forward-ref) — `.byte` truncation at .Ljt will
 * produce wrong bytes, not a build error, if it ever overflows. */

/* .Lop5p: geq with rsi = r13 = &cP.  op1 (was SQR alias, now this);
 * bc_v1's SQR ops are re-encoded as explicit Fmul (s2=s1, op=0).
 * Falls through to .Lop5.  bc_v1's Qx<p,Qy<p checks use this —
 * slot5 no longer gets cP block-copied (cP is built at slot22). */
.Lop5p:	mov	rsi, r8
	/* FALLTHROUGH */
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
 * fe_iszero inlined (cP removal freed the headroom — .Lop8 at
 * 219 + this 10 B = 229, still fits u8). */
.Lop6:	push	4
	pop	rcx
	xor	eax, eax
2:	or	rax, [rdi+rcx*8-8]
	loop	2b
	sete	al
	test	BYTE PTR [rbx-2], 0x10
	jz	.Lor
	xor	al, 1
.Lor:	or	bpl, al
	ret
/* MULCN: Fmul with b = &cN (.text) instead of a slot.  bc_v3
 * uses this for n·Z; diff2 = diff1 − n·Z (mod p).  rcx = &cP
 * untouched (mod-p).  rel8 to Fmul. */
.Lop9:
MULCN:	lea	rdx, [r12+oN]
	jmp	Fmul
/* Nmul/Fmul differ only in modulus.  Decoder preloaded rcx = &cP;
 * Nmul overwrites to &cN and falls through. */
.Lop4:
Nmul:	lea	rcx, [r12+oN]
	/* FALLTHROUGH */
.Lop0:
Fmul:	jmp	fe_mul_m
/* SQR = Fmul: bytecode encodes s2=s1, decoder already set rdx=rsi. */
.equ .Lop1, .Lop0
/* Fadd (dst = s1+s2 mod p): compute p−s2 into DST, then fall
 * through to Fsub with rdx=&dst so .Lop3 does s1−(p−s2) in place.
 *
 * dst-as-scratch is safe iff dst≠s1 (else p−s2 clobbers s1 before
 * the second .Lop3 reads it).  bc_rcb had three dst==s1 ops (X+=Y
 * pattern); they're COMMUTED to dst==s2 in the bytecode (addition
 * is commutative; 0B).  dst==s2 is fine: first .Lop3 reads s2[i]
 * before writing dst[i]=s2[i] per-limb, second reads s1 unaliased.
 * None of the 20 Fadds target slots 5-7 (RCB never writes those).
 *
 * First .Lop3 never borrows (s2<p) so .Lop3's internal pop rdi
 * restores it — no push/pop rdi here.  Slot 3 no longer clobbered
 * as a side effect; bc_rcb's explicit dst=3 ops still work. */
/* Fsub (.Lop3): dst = a−b; if borrow, add m back.  ALSO used by
 * fe_mul_m for its final conditional subtract. */
.Lop2:
Fadd:	push	rsi
	push	rcx                 /* save &P */
	push	rdi                 /* &dst → pops into rdx */
	push	rcx
	pop	rsi                 /* rsi = &P */
	call	.Lop3               /* dst = P − s2.  rdi preserved (no borrow). */
	pop	rdx                 /* rdx = &dst */
	pop	rcx
	pop	rsi
	/* FALLTHROUGH — rdi=rdx=&dst, rsi=s1 */
/* fe_sub_raw inlined here — sole remaining caller.  The old op6/7
 * merge freed the handler-block headroom for this. */
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

/* .Lop8 = fe_inv_m.  Placed here so its offset from .Ljt fits u8
 * (currently 252/255).  Called only from bc_v1 (op 7; the label
 * name is historical).  Mod-n only — mod-p inversion was
 * eliminated by the projective final check. */
.Lop8:
/* fe_inv_m: r = a^(n-2) mod n (Fermat).  NO EXPONENT BUFFER, NO
 * SEED COPY.  Caller (bc_v1) puts 1 in dst first; loop starts at
 * bit 255 instead of 254 — bit 255 of n−2 is 1 (top byte 0xFF),
 * so first iter gives r = 1² · a = a, identical to the old start
 * state one iteration later.  Drops rep movsq (9 B) + the r8
 * save/restore pair (6 B): fe_mul_m does NOT preserve rdi (.Lop3's
 * add-back path advances it), so each call is bracketed by push
 * rdi/pop rdi instead — 2 B per bracket, already present at .Le,
 * +2 B at .Lmul.  Net −12 B.
 *
 * n and n−2 differ only in bits 1-4 (low byte 0x51 vs 0x4F — a
 * four-bit borrow cascade, no borrow into byte 1).  bt directly
 * on cN in .text and special-case ebx<5:
 *   ebx ∈ {0,1,2,3}: force mul (n−2 bits 0-3 = 1111)
 *   ebx == 4:        force skip (n bit4=1 but n−2 bit4=0)
 *   ebx ≥ 5:         n and n−2 agree — bt on cN is exact.
 *
 * Loop counter in rbx (callee-saved, survives Nmul).  src at
 * [rsp].  r12 = .Ljt (bc_run's hoist — fe_mul_m doesn't touch). */
fe_inv_m:
	push	rbx
	push	rsi                 /* src → [rsp] */
	xor	ebx, ebx
	mov	bl, 255
.Le:	push	rdi
	push	rdi
	push	rdi                 /* 3rd push = rdi-preserve across call */
	pop	rdx
	pop	rsi
	call	Nmul                /* = lea rcx,&cN; jmp fe_mul_m. */
	pop	rdi                 /* fe_mul_m may leave rdi at dst+32 */
	cmp	ebx, 4
	jb	.Lmul
	je	.Lnx
	bt	DWORD PTR [r12+oN_early], ebx   /* cN in .text, disp8 */
	jnc	.Lnx
.Lmul:	push	rdi
	pop	rsi
	pop	rdx                 /* src from prologue push; 2B vs 4B mov[rsp] */
	push	rdx                 /* keep it there for next iter */
	push	rdi                 /* preserve rdi across this call too */
	call	Nmul
	pop	rdi
.Lnx:	dec	ebx
	jns	.Le
	pop	rcx                 /* discard src */
	pop	rbx
	ret

/* fe_mul_m(r=rdi, a=rsi, b=rdx, m=rcx).  r = a·b mod m.  32-bit limbs.
 *
 * PLACED AFTER THE HANDLER BLOCK so Fmul's jmp is rel8 (forward
 * 115 B; 12 B before rel8 overflows — watch if Fadd/.Lop3/fe_inv_m
 * grow).  fe_inv_m → Nmul → Fmul fallthrough → rel8 jmp → here.
 * call .Lop3 at the tail is backward rel32 (unchanged).
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
	 * not touched — no push/pop.  fe_inv_m's rbx,r12 survive. */

	mov	r9, rdx             /* b */
	mov	r10, rsi            /* a */
	/* m on stack under dest: push is 1 B, tail pops it straight
	 * into rcx for the cond-sub.  Reduce loop reads at [rsp+88]. */
	push	rcx                 /* m → [rsp+80] after zero-loop */
	push	rdi                 /* dest → [rsp+72] */

	/* Frame: t[0..17] = 72 B zeroed.  Unrolled push — the old
	 * loop (`loop` in SMALL_MUL8, dec+jnz in default) cost ~65/~12
	 * cyc per call × ~7.5K calls ≈ 490K / 90K cycles just in
	 * overhead.  9 bare pushes ≈ 9 cycles.  +3 B SMALL_MUL8 / +1 B
	 * default; kills an #ifdef.  push rcx (not rax) — the xor
	 * zeroes rcx for mul8's `mov cl,N` (which reads full rcx via
	 * loop/dec), AND pushes zeros, AND eax=0 was never needed past
	 * the pushes (lodsd overwrites).  Three jobs, one xor. */
	xor	ecx, ecx
	.rept 9
	push	rcx
	.endr
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

	/* REDUCE.  rdi flowed out of the schoolbook loop at rsp+60
	 * (SMALL_MUL8: last iter lea=rsp+28, mul8 +32) or rsp+56
	 * (default: lea=rsp+24, 4×lea+8=+32).  Want rsp+32 = &t[8].
	 * sub is 4 B vs 5 B for a fresh lea [rsp+32]. */
#ifdef SMALL_MUL8
	sub	rdi, 28
#else
	sub	rdi, 24
#endif
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

/* ======================================================================
 * Public entry point.
 * ====================================================================== */
	.globl	tv_ecdsa_p256_verify_asm
	.type	tv_ecdsa_p256_verify_asm, @function

tv_ecdsa_p256_verify_asm:
	/* enter N,0 = push rbp; mov rbp,rsp; sub rsp,N in 4 B.
	 * rbp stays a true frame pointer end-to-end → leave works at
	 * exit.  Every callee either leaves rbp alone or push/pops it
	 * (bc_run, pt_mul, fe_mul_m).  enter is microcoded (~12 cyc)
	 * but runs once.  r15 dropped — .Lcadd goes via r14 disp32. */
	push	rbx
	push	r14
	enter	744, 0              /* 22 slots + cP at slot22 (32 B) */
	/* r12 not pushed: bc_run push/pops it as .Ljt.  r8 = &cP below
	 * (caller-saved, but nothing in the call tree touches it:
	 * fe_mul_m uses r9-r11, bc_run/pt_mul/fe_inv_m use low regs).
	 * r8 on entry is hv (ABI arg5) — consumed at hash decode,
	 * dead by the time we set it. */
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
	 * Chain: rdi flows call→call; rsi bumped +32 by _next entry.
	 * rsi still = 64 here (cmp doesn't modify) → 64·6 = 384 =
	 * slot12 offset.  imul(3)+add(3) = 6 B vs 7 B lea disp32. */
	push	rdi                 /* sig → stack */
	imul	edi, esi, 6         /* edi = 64·6 = 384.  zero-extends rdi. */
	add	rdi, r14            /* slot 12 */
	pop	rsi                 /* rsi = sig */
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

	/* BUILD cP at slot22.  p = 2^256 − 2^224 + 2^192 + 2^96 − 1.
	 * LE dwords: FFFFFFFF ×3, 0 ×3, 1, FFFFFFFF.  Placed HERE
	 * because eax=0 survives from build_one's xor (rep stosq,
	 * inc[mem], push/pop don't touch it) — so `dec eax` (2B)
	 * gives FFFFFFFF instead of `or eax,-1` (3B).  r8 (hv) was
	 * consumed at hash decode above; caller-saved but nothing
	 * below clobbers it.  rbp−40 = slot22 (enter 744). */
	lea	rdi, [rbp-40]
	push	rdi
	pop	r8                  /* r8 = &cP */
	dec	eax                 /* eax was 0; now FFFFFFFF */
	stosd
	stosd
	stosd                       /* dw0-2 = FFFFFFFF */
	xor	eax, eax
	stosd
	stosd
	stosd                       /* dw3-5 = 0 */
	inc	eax
	stosd                       /* dw6 = 1 */
	neg	eax
	stosd                       /* dw7 = FFFFFFFF */

	/* Format byte: lodsb advances rsi past the 0x04 to the X
	 * coord for free.  push;pop+lodsb+cmp(al) = 5 B vs cmp[rdx]
	 * +lea = 7 B.  rdx,rsi both non-REX → push;pop beats mov.
	 * rdx dead after (hash pointer in r8 already used). */
	push	rdx
	pop	rsi
	lodsb
	cmp	al, 0x04
	jne	.Lf2
	mov	rdi, r14            /* slot 0 */
	call	fe_from_be
	call	fe_from_be_next     /* rsi+=32; Qy → slot1.  rdi exits at slot2. */

	/* ONE 16-qword copy: cGX,cGY,cN,cP → slots 2,3,4,5.  G → 2,3
	 * (survives to Shamir — bc_v1 never writes them).  cN,cP → 4,5
	 * (bc_v1's check ops read them first, then staging overwrites
	 * 4-7 with 1,Qx,Qy,1).  rdi already at slot 2.  rcx=0. */
	lea	rsi, [rip+cGX]
	mov	cl, 12              /* cP is gone — only G + cN (12 qw) */
	rep	movsq               /* rdi → slot 5, rcx → 0 */

	push	obc_v1
	pop	rdi
	call	bcrun_r14
	/* bc_v1 fail: fall through into .Lf2.  Every other fail
	 * (length checks, 0x04 check) reaches .Lf2 as rel8. */
	jnc	1f
.Lf2:	xor	eax, eax
	jmp	.Ld2
1:
	/* bc_v1 also ran INV + the two Nmuls (u1,u2 now in 13,14).
	 * NO cond_sub of the hash: e might be ≥ n but Nmul computes
	 * e·s⁻¹ mod n correctly for any a < 2^256. */

	/* Shamir backups: bc_v1 staged slots 2-7 as Gx,Gy,1,Qx,Qy,1
	 * — exactly the layout pt_mul wants at 16-21.  ONE rep movsq.
	 * The 3-copy chain (G.xy, borrow G.z, Q.xyz) is gone: the RCB
	 * addend slot shift (4,5,6 → 5,6,7, free) plus one extra bc_v1
	 * copy op (+2 B) buys this 18 B drop.  rcx=0 from last Nmul. */
	push	rbx
	pop	rdi                 /* slot 16 — 2B vs 3B mov */
	lea	rsi, [r14+64]       /* slot 2.  4B disp8; r15 (3B mov) gone. */
	mov	cl, 24
	rep	movsq               /* slots 2-7 → 16-21.  rcx → 0. */

	/* rbx = &slot16 (stockpile) — pt_mul reads u1/u2 at [rbx−96/−64].
	 * pt_mul tail-jumps into bc_v3 dispatch — returns HERE with
	 * CF set by bc_run's neg ebp.  See pt_mul epilogue. */
	call	pt_mul              /* acc = u1·G + u2·Q, then bc_v3 check */
	sbb	eax, eax            /* CF=1 → eax=−1; CF=0 → eax=0 */
	inc	eax                 /* −1→0 (fail), 0→1 (valid) */
.Ld2:	leave               /* mov rsp,rbp; pop rbp — rbp untouched since enter */
	pop	r14
	pop	rbx
	ret

	.section .note.GNU-stack,"",@progbits
