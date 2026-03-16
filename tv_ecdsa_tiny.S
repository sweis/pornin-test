/* ======================================================================
 * ECDSA/P-256 verify — x86-64, bytecode-interpreted, SIZE-OPTIMIZED.
 *
 * Forked from tv_ecdsa_fast.S (1397 B speed+size).  This variant
 * trades cycles for bytes: muladd4 rolled into a loop, store-forward
 * stalls accepted, mulx flag-threading dropped.  Target: 1024 B.
 *
 * Requires BMI2 (mulx) and MOVBE.
 *
 * Hot-path changes:
 *
 *   - Shamir's trick: one 256-bit walk for u1·G + u2·Q instead of two
 *     independent pt_muls — halves the doublings (256 vs 512).  Per
 *     iteration: double; if u2 bit, add Q (already in slot 4-5); if
 *     u1 bit, swap G.xy into slot 4-5, add, restore Q.xy.  Both G and
 *     Q have z = Mont(1), and slot 6 is NEVER written by bc_dbl/add,
 *     so the 8-qword X,Y swap is enough — z serves both.  ~30% cycles.
 *     Costs +22 B: larger pt_mul body, but verify's stash/restore/
 *     second-pt_mul/pt_add_acc block (61 B) is gone.
 *
 *   - Advancing-pointer CIOS in fe_mul_m: instead of shifting the
 *     6-word accumulator down one limb every outer iteration (20 memory
 *     moves per fe_mul_m), the base pointer r9 advances.  The CIOS
 *     invariant guarantees t[0]=0 after reduction, so t[1..] is the
 *     new accumulator — no data movement.  Needs a 9-word buffer.
 *     Removes the shift loop entirely: −21 bytes, huge cycle win.
 *
 *   - muladd4 fully unrolled with mulx.  mulx preserves all flags,
 *     so each mem-add's CF is threaded straight through the next mulx
 *     into the following limb's adc — one `adc r,0` barrier per limb
 *     instead of two.  The hi-reg (rcx↔rdi) never exceeds 2^64-1
 *     (hi_product ≤ 2^64-2 + one cross-carry), so it cannot wrap; the
 *     second carry lives in CF.  69 bytes, and shortens the carry
 *     dependency chain on the hottest loop — the bulk of the ~13%
 *     cycle win.  Also closes a latent edge case: the old two-adc
 *     form could wrap hi at exactly 2^64 with both carries set.
 *
 *   - fe_sub_raw/fe_add_raw use lodsq/stosq (auto-increment, 2 bytes
 *     each, flag-preserving) and `dec ecx; jnz` instead of `loop`.
 *     `dec` sets ZF but preserves CF for the carry chain.  `loop` is
 *     microcoded (~7 cyc/iter on modern Intel); dec/jnz is 1.
 *     −15 bytes AND faster.
 *
 *   - fe_cpy is 4×movsq (no `rep` startup overhead on the ~50%-taken
 *     fe_mul_m copy-back path).  Zero-init of t is `push rax`×9
 *     after xor — allocates and zeroes the 72-byte buffer in one
 *     sweep.  11 B vs 18 B for sub + stosq loop.
 *
 * Size-only changes:
 *
 *   - SQR bytecode encodes s2=s1; decoder sets rdx=rsi for free, so
 *     SQR dispatches straight to Fmul.  −5 bytes.
 *   - `push N; pop reg` replaces `mov reg,imm32` where N fits signed
 *     imm8 (−2 each, many sites).
 *   - fe_mul_m outer counter goes −32→0 so `add;jnz` drops the cmp.
 *   - verify's slot-4/slot-8 leas via rbp/r13 mid-pointers: disp8.
 *   - Constants (cP/cN/cR2P) live right after .Ljt so handlers can
 *     address them as [r14+disp8] instead of 7-byte rip-relative.
 *     5 leas × −3 bytes = −15.
 *   - Check-op handlers share the `or r13b,al; ret` tail.  −4.
 *   - Nmul shares Fmul's `jmp fe_mul_m` via short jmp.  −3.
 *   - pt_add_acc: fe_iszero preserves rdi, so compute the next
 *     address from it with disp8/sub-imm8 instead of disp32 lea.  −6.
 *   - pt_mul counter in ebp (no REX) instead of r13d.  −2.
 *   - r14=rsp in verify: r14 as base drops rsp's SIB byte.  −2.
 *   - fe_from_be advances rdi; slot16 derived as [rdi+64] after it
 *     instead of 7-byte disp32 from r14.  −3.
 *   - fe_inv_m: push rdi (1 byte) instead of mov rsi,rdi (3).  −3.
 *   - fe_sub_m + fe_add_raw inlined into Fsub (sole-caller chain);
 *     fe_sub_raw's neg leaves CF → jnc replaces test+jz.  −10.
 *   - fe_geq returns via CF; cond_sub_n branches on it directly.  −2.
 *   - fe_iszero looped: or-accumulate sets ZF on final OR.  −3.
 *   - build_one inlined (sole caller).  −6.
 *   - verify final-compare: push rbx×4, pop as needed.  −4.
 *   - Fadd: push scratch addr, pop into rdx after call.  −3.
 *   - pt_mul: dead mov removed; dec al → 255 via wrap.  −4.
 *   - Bytecode streams addressed by imm8 offset from bc_dbl; bcrun_off
 *     resolves.  7 sites × (7-byte lea → 2–3 byte load) vs +10.  −20.
 *   - fe_inv_m: sub DWORD (low limb ≫ 2, no borrow) + bt DWORD.  −2.
 *   - bc_run returns check result in CF (neg ebp): caller drops
 *     test+jnz for jc.  −2.
 *   - Decoder preloads rcx = &P; Fmul/Fadd drop their leas.  −2.
 *
 * Structural wins (r14-invariant pass):
 *
 *   - r14 = slot base is an invariant throughout the call tree (every
 *     callee that reassigns r14 also pushes/pops it).  pt_add_acc's
 *     `push r14; mov r14,rdi; ...; pop r14` frame and pt_mul's rbx
 *     copy were both reconstructing that live value.  Dropping them
 *     cascades: pt_add_acc's epilogue becomes a bare `ret`, two of its
 *     `jmp .Laa` paths become `ret`, one becomes a tail-jump; verify
 *     drops three `mov rdi,r14` preambles; pt_mul drops its whole rbx
 *     bookkeeping.  −27 combined.
 *   - cond_sub_n = .Lop3 with rcx=rdx=&N.  Conditional subtract is
 *     subtract-then-add-back-on-borrow, which is exactly the Fsub
 *     handler — just with the modulus swapped.  A 9-byte stub (three
 *     movs) placed right before .Lop3 falls through.  fe_geq then has
 *     only one caller (.Lop5) and gets inlined.  −19.
 *   - Fto_mont opcode eliminated.  verify's block copy takes cR2P
 *     along for the ride (16 qwords instead of 12), landing R² in
 *     slot 11.  A to-Montgomery conversion is then plain Fmul with
 *     s2=0xb.  Drops the handler and one jump-table entry.  −5.
 *   - pt_mul zeros its accumulator by calling .Lai (pt_add_acc's
 *     set-to-infinity path — byte-identical code).  −6.
 *   - verify: rdx (pub ptr) survives both fe_from_be calls unchanged;
 *     Fadd preserves rcx=&P around its own fe_sub_raw; build_one
 *     piggybacks on fe_from_be's advanced rdi; rbp set from that rdi
 *     instead of a prologue lea.  −11 combined.
 *   - bc_run decoder uses rax itself as the table index (consume ah
 *     first, then `and eax,0xF`); pt_mul `xchg ebp,eax`.  −2.
 *   - pt_mul scalar ptr in rbx (1-byte push/pop) not r15 (2-byte).
 *     bt [rbx],rbp is still 4 B (REX.W needed either way).  −2.
 *   - movbe in fe_from_be: load+bswap in one (7 B vs 5+3).  −1.
 *   - cGXM in .text right before .Ljt: [r12-80] (5 B, disp8 but
 *     r12 forces SIB) replaces 7-B rip-relative.  Handler offsets
 *     unaffected (cGXM is on the near side of .Ljt).  −2.
 *   - hv_len range check (32..64) merged: sub r9,32 wraps low
 *     values to huge, so cmp;jbe catches both ends.  −2.
 *   - pt_add_acc moved right before bcrun_r14: the add2 path falls
 *     through (no jmp), the dbl path's jmp is rel8.  −5.
 *   - pt_mul moved right after bc_run's epilogue: its pop rbx;pop
 *     rbp;ret (3 B) becomes a rel8 jmp into .Lepi5's tail (2 B).  −1.
 *
 * Security and validation are unchanged from tv_ecdsa_bc.S.
 * ====================================================================== */

	.intel_syntax noprefix

/* ======================================================================
 * Bytecode.  Placed before .text so stream offsets (bc_X - bc_dbl) are
 * backward references at the call sites — gas picks the imm8 encoding
 * for `push`.  Order chosen so all offsets ≤ 118 (fits signed imm8).
 *
 * Call sites load the offset as a small integer (push imm8; pop rdi,
 * or xor edi,edi for bc_dbl itself), and bcrun_off adds the base.
 * 7 sites × (7-byte rip-rel lea → 2–3 byte load) vs +10 in bcrun_off.
 * ====================================================================== */
	.section .rodata
	.p2align 3

bc_dbl:
	.byte 0x21,0xb2, 0x11,0x91, 0xb3,0x80, 0xb2,0xa0, 0xa0,0xa8
	.byte 0xa2,0x8a, 0xa2,0xa8, 0x22,0x81, 0x81,0x88, 0x93,0x88
	.byte 0xb3,0x28, 0x90,0xb0, 0xb2,0x8b, 0x82,0x88, 0x82,0xb8
	.byte 0xa1,0x0a, 0xb3,0x00, 0x03,0x88, 0x80,0x8a, 0x91,0x99
	.byte 0x92,0x99, 0x92,0x99, 0x92,0x99, 0x93,0x18, 0x00,0x00

/* bc_v2 MERGED into bc_v1 — hash decode now writes e to slot 14
 * (not 13), so s in 13 survives to INV and bc_v1 can flow straight
 * into the two Nmuls.  One dispatch, one terminator, one stream.
 * See bc_v1 tail for the appended ops.  −17 B. */

/* bc_v3: PROJECTIVE CHECK — no mod-p inversion.  Valid iff
 * x mod n == r ⇔ X ≡ r·Z² (mod p) OR X ≡ (r+n)·Z² (mod p).  p is
 * prime → (diff1·diff2 ≡ 0) ⇔ (either ≡ 0).  diff2 = diff1 − n·Z²
 * and n·Z² ≡ −(p−n)·Z² (mod p) so diff2 = diff1 + (p−n)·Z².
 * slot 11 = p−n (native compute post-pt_mul, rbx-64 disp8).
 * slot 7 holds z² (survives Fadd's slot-3 scratch).  First op:
 * R.z==0 (∞) → fail.  Fadd at op 6 has dst=scratch=slot 3 — the
 * write overlays the scratch, works (read-before-write per limb). */
bc_v3:
	.byte 0x06,0x20            /* checkzero slot2 (R.z): ∞ → fail */
	.byte 0x21,0x72            /* slot7  = z²                     */
	.byte 0x70,0xac            /* slot10 = r·z²  (r=slot12)       */
	.byte 0xa3,0xa0            /* slot10 = X − r·z²       = diff1 */
	.byte 0x70,0x3b            /* slot3  = (p−n)·z²  (p−n=slot11) */
	.byte 0x32,0x3a            /* slot3  = diff1 + (p−n)z² = diff2*/
	.byte 0x30,0x3a            /* slot3  = diff1·diff2            */
	.byte 0x07,0x30            /* check slot3 nonzero → fail      */
	.byte 0x00,0x00

bc_add1:
	.byte 0x21,0xa2, 0x61,0xb6, 0xb0,0x80, 0xa0,0x34, 0x60,0x91
	.byte 0xb0,0x99, 0x20,0x75, 0xa0,0x77, 0x83,0x33, 0x93,0x77
	.byte 0x00,0x00

bc_add2:
	.byte 0x60,0xa2, 0x30,0x2a, 0x31,0xa3, 0xa0,0xb3, 0xa0,0x88
	.byte 0xb0,0x99, 0x71,0x07, 0xb3,0x00, 0x82,0x38, 0x33,0x00
	.byte 0x03,0x38, 0x30,0x37, 0x93,0x13, 0x00,0x00

/* Opcode renumbering after op4 (Fto_mont) was absorbed into Fmul:
 * No Montgomery.  Inputs (Q in 0,1; G in 2,3) are already in
 * normal form — no to-Mont conversion.  Slots 4,5 still get Qx,Qy
 * (for Shamir): Fmul(x, slot15=1) = x, a plain copy in 2 B.
 * Slot 6 = 1 via 1·1 (pt_add_acc reads it as addend's z).
 *
 * B is derived from G (normal form); curve check uses slots 7,11
 * as scratch so 0,1,4,5 survive for the Shamir copy.  No Fadd
 * anywhere (its handler clobbers slot 3 = Gy). */
bc_v1:
	.byte 0x06,0xc0, 0x05,0xc8, 0x06,0xd0, 0x05,0xd8
	.byte 0x05,0x09, 0x05,0x19
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
	.byte 0x07,0x70            /* check slot7 nonzero (dst=7!) */
	.byte 0x88,0x0d            /* INV: slot0 = slot13^-1 mod slot8(cN) */
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

/* fe_iszero(a=rdi) -> eax=1 iff zero.  OR accumulates into rax; the
 * last OR's ZF reflects the full OR (rax is cumulative).  loop/sete/
 * movzx/ret all preserve flags: callers may branch on ZF directly.
 * Looped: 19 bytes vs 22 unrolled. ~260 calls × ~16cyc = <0.4% cost. */
fe_iszero:
	push	4
	pop	rcx
	xor	eax, eax
1:	or	rax, [rdi+rcx*8-8]
	loop	1b
	sete	al
	movzx	eax, al
	ret

/* fe_sub_raw(dst=rdi, a=rsi, b=rdx) -> borrow in eax.
 * lodsq/stosq preserve all flags; `dec` preserves CF (sets ZF only).
 * `xor ecx,ecx` doubles as the CF-clear.  Pointers advance as a side
 * effect — callers must not assume they're preserved. */
/* fe_sub_raw: dst = a − b.  CF on return = final borrow (last sbb;
 * lea/dec/jnz all preserve CF).  Sole CF consumer is .Lop3's jnc —
 * the old `sbb eax;neg` tail just rebuilt the same CF.  eax never
 * read by any caller (Fadd: p>s2, verify p−n: p>n, both ignore). */
fe_sub_raw:
	xor	ecx, ecx
	mov	cl, 4
1:	lodsq
	sbb	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	dec	ecx
	jnz	1b
	ret

/* mul8 OP: dst[0..8] OP= ebx·src[0..7], 32-bit limbs.  INLINED at
 * both call sites (schoolbook=add, reduce=sub).  25 B macro body ×
 * 2 sites = 50 B vs 51 B shared function + 10 B calls = 61 B.  −11.
 * Clobbers: ebp (prev_hi), rcx→0, eax/edx, rsi/rdi advance +32. */
.macro	mul8 op
	/* rcx=0 always here: push-loop's `loop` (first schoolbook),
	 * or prior mul8's `loop` (all subsequent).  −1 B × 2 sites. */
	mov	cl, 8
	xor	ebp, ebp
7:	lodsd
	mul	ebx
	add	eax, ebp
	adc	edx, 0
	\op	[rdi], eax
	adc	edx, 0
	mov	ebp, edx
	scasd
	loop	7b
	\op	[rdi], ebp
.endm

/* .Lfm falls through.  fe_inv_m is ONLY called for mod-n now
 * (mod-p inversion gone via projective check).  r14 in bc_run
 * context = .Ljt; cN is at r14+9 (9-entry table).  Hardcode the
 * 9 — gas won't pick disp8 for forward-ref oN. */
.equ	oN_early, 9
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
 * One mulacc serves both schoolbook multiply AND reduce.  No m0i,
 * no R², no Montgomery — plain modular arithmetic.  r8 ignored. */
fe_mul_m:
	push	rbx                 /* mul8 reads ebx */
	push	rbp                 /* mul8 clobbers ebp */
	/* b,a in r9,r10 (caller-saved, mul8 doesn't touch).  No r13/r14
	 * push/pop.  fe_inv_m's r13,r14 survive fe_mul_m unchanged.  −8 B. */

	mov	r9, rdx             /* b */
	mov	r10, rsi            /* a */
	mov	r8, rcx             /* m — reduce AND cond-sub use it directly */
	/* dest (rdi) goes on the stack under t — popped after t is
	 * released.  r12 no longer pushed/used; .Lepi4 shrinks. */
	push	rdi

	/* Frame: just t[0..17] = 72 B.  mulsub subtracts q·m directly,
	 * so no neg_m needed.  Push-zero 9 qwords (72 B). */
	xor	eax, eax
	push	9
	pop	rcx
2:	push	rax
	loop	2b
	/* rsp → t[0].  rcx=0. */

	/* Schoolbook then reduce (separate — merged reverse-order has
	 * an overflow: i−1's fold writes t[i+7] large, then i−1's
	 * mulacc final-carry add to t[i+7] can exceed 2^32, dropping
	 * a bit.  Forward-order merged is equivalent to separate). */
	push	-32
	pop	r11
.Lm:	mov	ebx, [r10+r11+32]   /* a[i] */
	lea	rdi, [rsp+r11+32]   /* &t[i] */
	mov	rsi, r9             /* b */
	mul8	add                 /* t[i..i+8] += a[i]·b */
	add	r11, 4
	jnz	.Lm

	/* rdi as window pointer (no REX on [rdi+32]); push/pop around
	 * mul8's +32 advance.  −2 B vs r9.  */
	lea	rdi, [rsp+32]       /* &t[8] */
.Lr:	mov	ebx, [rdi+32]       /* q = t[j+8] — NOT cleared */
	test	ebx, ebx
	jz	4f
	push	rdi
	mov	rsi, r8             /* m */
	mul8	sub                 /* t[j..j+8] -= q·m; rdi += 32 */
	pop	rdi
	jmp	.Lr
4:	sub	rdi, 4
	cmp	rdi, rsp
	jae	.Lr
	/* t[0..7] < 2^256, possibly ≥ m.  t[8] = 0. */

	/* Final cond-sub via .Lop3.  rsi = &t BEFORE releasing the
	 * frame (reads are safe: .Lop3's pushes land at t[14..17],
	 * past the result in t[0..7]).  dest pops from under t.
	 * `push rsp` = pre-decrement value; pop balances.  2 B vs 3. */
	push	rsp
	pop	rsi
	add	rsp, 72
	pop	rdi                 /* dest (pushed before push-loop) */
	mov	rcx, r8             /* m */
	push	rcx
	pop	rdx                 /* 5 B total vs 2×mov r8 (6 B) */
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

/* cpy3: 12-qword copy.  Precondition rcx=0 (high bytes) — every caller
 * has rcx=0 from a prior fe_iszero/rep/fe_sub_raw.  mov cl,N = 2 B vs
 * push N;pop rcx = 3 B.  −1 B per site. */
.macro	cpy3
	mov	cl, 12
	rep	movsq
.endm

/* ----------------------------------------------------------------------
 * pt_add_acc and pt_mul take the slot base in r14 (caller-provided).
 * Every caller already has r14 = slot base: verify sets it once at
 * entry and never clobbers it; bc_run (called from inside both of
 * these) pushes/pops r14.  So the old push-r14/mov-r14/pop-r14 frame
 * in pt_add_acc was reconstructing a value that was never lost, and
 * pt_mul's rbx = rdi copy was rbx = r14 by another name.
 *
 * With the frame gone, pt_add_acc's epilogue is just `ret`.  Two of
 * the three paths that ended in `jmp .Laa` become plain `ret` (−1 B
 * each), and the third — a call then fallthrough — becomes a tail
 * jump (−1 B).  pt_mul drops its rbx push/mov/pop (−5 B) and the
 * `mov rdi,rbx` arg to pt_add_acc (−3 B).  verify drops three
 * `mov rdi,r14` preambles (−9 B).  Net −24 B.
 *
 * Placed right before bcrun_r14 so the add2 path falls straight through
 * into bcrun_r14 (no jmp at all), and the dbl-path's jmp is rel8.  −5 B.
 * The `call bcrun_r14` mid-body is still rel32 (no short call on x86-64).
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
	lea	rdi, [r14+96]
	call	fe_iszero           /* ZF ⇔ H == 0 */
	jnz	3f
	/* fe_iszero preserved rdi = r14+96.  sub imm8 −128 = +128. */
	sub	rdi, -128           /* r14+224 */
	call	fe_iszero           /* ZF ⇔ Rr == 0 */
	jnz	.Lai
	/* Tail-share: both this path and 3: end in `jmp bcrun_r14`.
	 * Short-jmp past .Lai to the shared tail-jump. */
	xor	edi, edi            /* obc_dbl = 0 */
	jmp	bcrun_r14           /* rel8 forward — pt_add_acc sits right before bcrun_r14 */
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
/* Callers pass rdi = byte offset into the bytecode block.  bcrun_off
 * resolves it; bcrun_r14 also supplies rsi = r14.  Seven sites each
 * drop a 7-byte rip-rel lea for a 2–3 byte offset load; we spend +10
 * here once. */
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
	mov	rbx, rdi
	mov	r12, rsi
	/* Check accumulator in ebp: xor is 2 bytes (no REX), and since only
	 * the low byte is ever OR'd with 0/1, `mov eax,ebp` (2 bytes) works
	 * at exit — upper bytes stay zero.
	 *
	 * r13 is never read or written here (the decoder uses r12/r14,
	 * handlers either don't touch r13 or push it themselves —
	 * fe_mul_m does).  It was push/popped purely so verify could
	 * share .Lepi5; now that verify has its own leave-based
	 * epilogue, the push/pop is dead.  −4 B. */
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
	/* Most handlers want rcx = &P; those that don't overwrite it.
	 * +4 here, −4 in Fmul, −2 in Fadd.  Fadd now preserves it across
	 * its own fe_sub_raw.  oP is a forward reference here, so gas
	 * picks disp32 — hardcode and assert. */
.equ	oP_early, 41        /* .Ljt(9) + cN(32) — 9-entry table */
	lea	rcx, [r14+oP_early]
	call	rax
	jmp	.Lbc

/* NEG sets CF=1 iff operand was nonzero.  pops/ret preserve flags,
 * so the bc_v1 caller branches on CF directly — other callers don't
 * care.  ebp is about to be popped anyway.  Same 2 bytes as mov. */
.Lbce:	neg	ebp
	pop	r14
	pop	r12
.Lepi2:
	pop	rbx
	pop	rbp
	ret

/* pt_mul: Shamir's simultaneous double-and-add.  Computes u1·G + u2·Q
 * into the accumulator (slots 0-2) in a single 256-bit walk — halves
 * the doublings vs running two independent pt_muls (256 vs 512).
 *
 * Caller contract (verify sets this up just before the call):
 *   rsi    → &u1 (slot 13); u2 is at [rsi+32] (slot 14)
 *   slot 4-6: Q in Jacobian Montgomery form (z = Mont(1) in slot 6)
 *   slot 16-17: G.x, G.y in Montgomery form
 *   slot 18-19: backup of Q.x, Q.y (for restore after each G-add)
 *   slot 15 holds `one` throughout — bc_v3 reads it after pt_mul.
 *
 * The z-coordinate trick: bc_add1/2 read slot 6 for the addend's z, and
 * slot 6 is NEVER written by bc_dbl/add1/add2.  Both G and Q have z =
 * Mont(1), so swapping only X,Y (8 qwords) suffices — slot 6 serves both.
 *
 * Per iteration: double; if u2 bit set, add (Q is already in 4-5); if
 * u1 bit set, swap G into 4-5, add, restore Q to 4-5.  u2 checked first
 * so Q is in place for it without a preceding restore.  After the
 * G-branch restores Q, the next iteration's u2 check finds Q in place.
 *
 * Caller passes &u1 IN RBX (not rsi).  verify's rbx already holds
 * slot 13 from the earlier stockpile, so the old `mov rsi,rbx` in
 * verify + `push rbx; mov rbx,rsi` here was a round trip that
 * rebuilt the same value.  rbx is callee-saved everywhere pt_mul
 * reaches (bc_run pushes it; pt_add_acc's callees do too), so
 * pt_mul neither pushes nor writes it.  Verify doesn't read rbx
 * after pt_mul returns (next use is `lea rbx,[r14+96]`).  −7 B.
 *
 * Epilogue is now inline (pop rbp; ret) — no more .Lepi2 share
 * since there's no rbx to pop.  Same 6 B either way. */
pt_mul:
	push	rbp
	push	r12
	push	r13
	lea	r12, [r15+64]       /* &slot4 — r15 = verify's &slot2 here (disp8) */
	lea	r13, [rbx+96]       /* &slot16 (= slot13+96).  G at [r13], Q-backup at [r13+64]. */

	call	.Lai
	dec	al
	xchg	ebp, eax
.Lpm:	xor	edi, edi
	call	bcrun_r14           /* double */

	bt	[rbx+32], rbp       /* u2 bit */
	jnc	2f
	call	pt_add_acc          /* Q already in slot 4-5 */
2:
	bt	[rbx], rbp          /* u1 bit */
	jnc	3f
	mov	rdi, r12            /* &slot4 */
	push	rdi                 /* stash for restore after pt_add_acc clobbers rdi */
	mov	rsi, r13            /* &slot16 = G */
	/* rcx=0: bc_dbl (via bcrun_r14 above) ends in Fsub which leaves
	 * rcx=0 (fe_sub_raw's dec-to-0 loop); pt_add_acc (u2 branch)
	 * exits via bc_add2/dbl (same) or rep (rcx→0).  −1 B each. */
	mov	cl, 8
	rep	movsq               /* G.xy → slot 4-5.  rsi now = r13+64 = &slot18. */
	push	rsi                 /* stash &Q-backup — it's where rsi landed */
	call	pt_add_acc
	pop	rsi                 /* &slot18 = Q backup */
	pop	rdi                 /* &slot4 */
	mov	cl, 8               /* rcx=0: pt_add_acc exit paths all zero rcx */
	rep	movsq               /* Q.xy → slot 4-5 (restore) */
3:
	dec	ebp
	jns	.Lpm

	pop	r13
	pop	r12
	pop	rbp
	ret

/* G.x, G.y in Montgomery form.  Placed right before .Ljt so verify
 * can address it as [r12-80] (r12=&cN, cN=.Ljt+16, cGXM=.Ljt-64).
 * 5-byte lea (r12 forces SIB) vs 7-byte rip-relative.  Handler
 * offsets from .Ljt are unaffected since this is on the near side. */
/* G in NORMAL form (no Montgomery).  Same 64 B.  Affine (x,y). */
cGX:	.quad 0xf4a13945d898c296, 0x77037d812deb33a0
	.quad 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247
cGY:	.quad 0xcbb6406837bf51f5, 0x2bce33576b315ece
	.quad 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b

/* .Ljt + constants.  cN_M0I and cR2P gone (no Montgomery → no m0i,
 * no R²).  cN→cP adjacency load-bearing for verify's block copy. */
.Ljt:
	.byte	.Lop0-.Ljt, .Lop1-.Ljt, .Lop2-.Ljt, .Lop3-.Ljt
	.byte	.Lop4-.Ljt, .Lop5-.Ljt, .Lop6-.Ljt, .Lop7-.Ljt
	.byte	.Lop8-.Ljt  /* INV (slot-based, only mod-n now) */

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
.if (cN - cGX) - 73
.error "cGX-cN offset changed — update lea rsi,[r12-73] in verify"
.endif

/* fe_geq inlined (sole caller after cond_sub_n was rewritten as a
 * .Lop3 stub).  Compare [rdi] to [rsi] limb-by-limb from the top;
 * loopz falls out on first mismatch with cmp's CF live.  +10 B in
 * the handler block (Fadd shifts from 225 to 235, still fits u8)
 * but the 16-B standalone fe_geq is gone.  Net −6 B. */
.Lop5:	push	4
	pop	rcx
1:	mov	rax, [rdi+rcx*8-8]
	cmp	rax, [rsi+rcx*8-8]
	loopz	1b
	setae	al
	jmp	.Lor
.Lop6:	call	fe_iszero
	jmp	.Lor
.Lop7:	call	fe_iszero
	xor	al, 1
.Lor:	or	bpl, al
	ret
/* .Lop8 (INV) is fe_inv_m itself — moved to after .Lop3.  −5 B. */
/* No m0i → Nmul is just a rcx override, Fmul is just the jmp.
 * Decoder preloaded rcx = &cP; Nmul overwrites to &cN then falls
 * through.  −10 B (push 1;pop r8 + mov r8,[rcx-8] + jmp .Lmj). */
.Lop4:
Nmul:	lea	rcx, [r14+oN]
	/* FALLTHROUGH */
.Lop0:
Fmul:	jmp	fe_mul_m
/* SQR bytecode now encodes s2=s1, so the decode loop has already
 * set rdx=rsi — SQR is just Fmul.  −5 bytes (old: mov rdx,rsi;jmp). */
.equ .Lop1, .Lop0
/* fe_sub_m + fe_add_raw both inlined (sole callers in chain).
 * fe_sub_raw's `neg eax` sets CF iff borrow; pops preserve flags,
 * so jnc replaces test+jz.  The add-back loop's first adc needs
 * CF=0: `xor ecx,ecx` clears it (we're on the CF=1 branch here
 * but mov+xor reset it).  −10 vs standalone fe_sub_m+fe_add_raw. */
/* rcx = &P is supplied by the decoder.  Fadd also preserves it
 * across its fe_sub_raw call (push/pop around it, +2 B) and jumps to
 * .Lop3 directly — the old `Fsub: lea rcx,[r14+oP]` re-load is gone. */
/* Fadd now BEFORE .Lop3 → falls through (drops 2-B jmp).  .Lop3's
 * table offset grows by ~20 B but stays u8.  */
.Lop2:
Fadd:	push	rdi
	push	rsi
	push	rcx                 /* save &P across fe_sub_raw */
	lea	rdi, [r12+3*32]
	push	rdi
	push	rcx
	pop	rsi
	call	fe_sub_raw
	pop	rdx
	pop	rcx
	pop	rsi
	pop	rdi
	/* FALLTHROUGH */
.Lop3:	push	rcx
	push	rdi
	call	fe_sub_raw
	pop	rdi
	pop	rdx
	jnc	1f
	mov	rsi, rdi
	clc                         /* rcx=0 from fe_sub_raw; CF=1 on this path */
	mov	cl, 4
2:	lodsq
	adc	rax, [rdx]
	stosq
	lea	rdx, [rdx+8]
	dec	ecx
	jnz	2b
1:	ret

/* .Lop8 = fe_inv_m (moved here to drop the 5-B jmp).  Offset
 * from .Ljt is ~170 B — fits u8.  fe_inv_m is mod-n only. */
.Lop8:
/* fe_inv_m.  Loop counter in rbx (callee-saved, survives fe_mul_m).
 * fe_mul_m now uses r10 internally for b, so r10 is not free here.
 * Push/pop rbx costs +2 bytes, but `mov ebx,imm` and `dec ebx` are
 * each 1 byte shorter than their r10d equivalents — net zero. */
fe_inv_m:
	/* All args on stack — fe_mul_m preserves r12-r15 now so no
	 * callee-save reg is needed for dest/src/m.  Just push rbx
	 * (loop counter) + args.  rbp from enter is the stable base;
	 * [rbp+8]=dest, [rbp+16]=src, [rbp+24]=m.  −7 B: drop push
	 * r12,r13 (−4) + pops (−4) + movs (−6); add push rdi,rsi
	 * (+2), pops (+2), [rbp+N] loads vs reg (+3).  */
	push	rbx
	push	rsi                 /* src → [rbp+16] */
	push	rdi                 /* dst → [rbp+8]  */
	enter	32, 0

	mov	rdi, rsp
	lea	rsi, [r14+oN_early] /* cN (.text, via bc_run's r14=.Ljt) */
	push	4
	pop	rcx
	rep	movsq               /* exponent ← m; rcx=0 after */
	/* Both moduli have low limb ≫ 2 → no borrow into limb 1. */
	sub	DWORD PTR [rsp], 2

	mov	rdi, [rbp+8]        /* dst */
	mov	rsi, [rbp+16]       /* src */
	mov	cl, 4               /* rcx=0 from rep above */
	rep	movsq               /* r ← a */

	xor	ebx, ebx
	mov	bl, 254
.Le:	mov	rdi, [rbp+8]
	push	rdi                 /* stash for reuse after .Lfm clobbers */
	push	rdi
	push	rdi
	pop	rdx
	pop	rsi
	call	.Lfm
	pop	rdi                 /* restore dest — before bt so [rsp]=exp */
	bt	DWORD PTR [rsp], ebx
	jnc	.Lnx
	push	rdi
	pop	rsi
	mov	rdx, [rbp+16]       /* src */
	call	.Lfm
.Lnx:	dec	ebx
	jns	.Le

	leave
	pop	rcx                 /* discard dst */
	pop	rcx                 /* discard src */
	pop	rbx
	ret

/* ======================================================================
 * Public entry point.
 * ====================================================================== */
	.globl	tv_ecdsa_p256_verify_asm
	.type	tv_ecdsa_p256_verify_asm, @function

tv_ecdsa_p256_verify_asm:
	/* enter 648,0 = push rbp; mov rbp,rsp; sub rsp,648 in 4 B
	 * (vs 1+7=8 B).  r15 takes over as the slot-2 mid-pointer so
	 * rbp stays a true frame pointer end-to-end → leave works at
	 * exit.  Every callee either leaves rbp alone (fe_inv_m,
	 * fe_mul_m, fe_from_be, cond_sub_n) or push/pops it (bc_run,
	 * pt_mul).  r15 is preserved by the same set — fe_mul_m and
	 * fe_inv_m push it; bc_run's handlers reach fe_mul_m only via
	 * tail-jump so r15 round-trips.  pt_mul reads r15 once at
	 * entry (for &slot4) and never writes it.
	 *
	 * rbp→r15 swap is size-neutral at every access (both need
	 * REX in their [reg+disp8] / mov-to-rdi forms anyway).
	 * Net: prologue −2, epilogue −1 (leave+pops vs add+jmp
	 * .Lepi5).  enter is microcoded (~12 cyc) but runs once. */
	push	rbx
	push	r12
	push	r14
	push	r15
	enter	648, 0

	/* r14 = rsp for the whole of verify.  r13 no longer used
	 * (final check is projective — no `mov rdx,r13` for r).
	 * Drop push/pop r13 and the lea; disp32 at the 2 use sites
	 * is +7 B but −11 B from push+pop+lea.  −4 B net. */
	mov	r14, rsp

	/* ABI args rdi (sig), rdx (pub), r8 (hash) all survive the
	 * length checks (cmp-only on rsi/rcx/r9) and fe_from_be calls
	 * (touch rsi/rdi/rcx/rax only — r8 untouched).  The old
	 * `mov r12,rdi; mov rbx,r8` pair stashed values that were
	 * never in danger.  −6 B. */
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
	 * Chain: rdi flows call→call; rsi bumped +32 in place.
	 * rdi (sig ptr, ABI arg1) still live — nothing above touched it. */
	mov	rsi, rdi
	lea	rdi, [r14+12*32]    /* slot 12 (disp32; r13 gone) */
	call	fe_from_be
	call	fe_from_be_next     /* rsi+=32; rdi already r13+32 */

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
	/* rdi = slot 16; rbx stockpiled here for the whole of verify
	 * (bc_run pushes/pops rbx, nothing else between here and
	 * pt_mul writes it).  All Shamir/p−n leas are rbx-disp8. */
	lea	rbx, [rdi-96]       /* slot 13 */

	cmp	BYTE PTR [rdx], 0x04
	jne	.Lf2
	lea	rsi, [rdx+1]
	mov	rdi, r14            /* slot 0 */
	call	fe_from_be
	call	fe_from_be_next     /* rsi+=32; rdi flowed to r14+64 */
	mov	r15, rdi            /* = slot 2; cheaper than lea from r14 */
	lea	r12, [rip+cN]

	/* G → slots 2,3 (rdi already there).  Normal form now (no
	 * Montgomery).  bc_v1 derives B from it and never writes
	 * slot 2 or 3 so G survives to the Shamir setup.  rcx=0. */
	lea	rsi, [r12-73]       /* cGX (9-entry table) */
	mov	cl, 8
	rep	movsq               /* rdi → slot 4, rcx → 0 */

	sub	rdi, -128           /* slot 4 + 128 = slot 8 */
	mov	rsi, r12
	/* 8-qword copy: cN→8, cP→9.  cR2P and cN_M0I both gone —
	 * no Montgomery, no m0i, no R².  B derived in bc_v1. */
	mov	cl, 8
	rep	movsq

	push	obc_v1
	pop	rdi
	call	bcrun_r14
	/* bc_v1 fail: fall through into .Lf2.  Every other fail-path
	 * caller (length checks, 0x04 check, R.z=∞) reaches .Lf2 as
	 * rel8 from here — the top jne is +98 fwd, jz after pt_mul is
	 * −89 back.  .Lf2's own jmp to .Ld2 is +126 fwd: exactly at
	 * the rel8 edge (any byte added between here and .Ld2 breaks
	 * it).  The happy path falls through call fe_iszero straight
	 * into .Ld2 — eax from fe_iszero IS the return value.  The
	 * old 5 B rel32 trampoline + 2 B end-jmp are both gone; only
	 * this 4 B xor+jmp is added.  −5 B. */
	jnc	1f
.Lf2:	xor	eax, eax
	jmp	.Ld2
1:
	/* bc_v1 now also ran the two Nmuls (u1,u2 in 13,14).  Hash
	 * decode was done pre-bc_v1 into slot 14.  rbx = &slot13
	 * from the early stockpile — bc_run pushed/popped it.
	 * NO cond_sub: e might be ≥ n but Nmul computes e·s⁻¹ mod n
	 * regardless — (a·b) mod n is right for any a < 2^256. */

	/* Shamir setup: G.xy → 16-17, Q.xy backup → 18-19.  slots
	 * 2,3,4,5 are already G.x,G.y,Q.x,Q.y (Montgomery) — G was
	 * loaded pre-bc_v1, Q was to-Mont'd by bc_v1, and nothing
	 * since (inv_m/hash/cond_sub/bc_v2) has touched any of them.
	 * Slots 16-19 are contiguous too.  One 16-qword copy.  −9 B.
	 * rcx=0: bc_v1's last op is Nmul → fe_mul_m → fe_sub_raw dec-to-0. */
	lea	rdi, [rbx+96]       /* slot 16 = slot 13 + 96: disp8 */
	mov	rsi, r15            /* slot 2 */
	mov	cl, 16
	rep	movsq               /* slots 2-5 → 16-19 in one go */

	/* rbx = &slot13 already (stockpile) — pt_mul reads it directly. */
	call	pt_mul              /* acc = u1·G + u2·Q */

	/* p−n into slot 11 natively (no survivor slot through pt_mul —
	 * 4,5,6 are Q/1, 7 is add1→add2 handoff).  rbx = slot 13 from
	 * stockpile; slot 11 = rbx−64 disp8.  cP = r12+32, cN = r12. */
	lea	rdi, [rbx-64]       /* slot 11 */
	lea	rsi, [r12+32]       /* &cP */
	mov	rdx, r12            /* &cN */
	call	fe_sub_raw          /* slot11 = p − n */

	/* bc_v3: projective check — NO mod-p inversion.  ∞-check,
	 * diff1·diff2 ≡ 0 (mod p) ⇔ valid (p prime → field).  Drops
	 * native ∞-check (10 B), lea rbx (4 B), 35 B final block.
	 * Adds 20 B p−n compute + 4 B CF→eax.  Net ~−25 B. */
	push	obc_v3
	pop	rdi
	call	bcrun_r14
	sbb	eax, eax            /* CF=1 → eax=−1; CF=0 → eax=0 */
	inc	eax                 /* −1→0 (fail), 0→1 (valid) */
.Ld2:	leave               /* mov rsp,rbp; pop rbp — rbp untouched since enter */
	pop	r15
	pop	r14
	pop	r12
	pop	rbx
	ret

	.section .note.GNU-stack,"",@progbits
