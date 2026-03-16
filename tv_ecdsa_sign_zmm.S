/* ======================================================================
 * ECDSA/P-256 sign — AVX-512 IFMA, ALL-REGISTER, constant-time.
 *
 * DESIGN GOAL: secrets never touch memory.  The private key d, the
 * nonce k, and every intermediate of the Montgomery ladder live
 * exclusively in ZMM registers from entry to exit.  No spill, no
 * stack frame for working state, no secret-dependent branch or
 * load.  An attacker watching L1D traffic or branch history sees a
 * fixed pattern regardless of k.
 *
 * Requires: AVX-512F + AVX-512IFMA (vpmadd52luq/huq).
 *
 * REPRESENTATION: 5×52-bit redundant limbs.  One field element =
 * one ZMM register, lanes 0-4 (lanes 5-7 zero).  The 4 bits of
 * headroom per lane (52 < 64) allow a few additions before carry
 * propagation is needed — critical for the RCB add sequence.
 *
 *   a = a₀ + a₁·2^52 + a₂·2^104 + a₃·2^156 + a₄·2^208
 *
 * IFMA SCHOOLBOOK: vpmadd52luq computes low52(a×b) per-lane;
 * vpmadd52huq the high 52.  The product of two 52-bit values is
 * 104 bits — exactly two 52-bit halves with no slack bits lost.
 * Five broadcast-and-accumulate passes (one per limb of a) build
 * the full 10-limb product, shifted into place with valignq.
 *
 * MONTGOMERY LADDER:  R0,R1 = ∞,G.  For each bit of k from the
 * top: cswap(R0,R1,bit); R1=R0+R1; R0=2·R0; cswap(R0,R1,bit).
 * Both operations ALWAYS execute — no branch on the bit.  The
 * cswap is XOR-with-mask (vpternlogq).  Point ops use the same
 * RCB complete addition as tv_ecdsa_tiny.S — doubling is self-add,
 * ∞ is (0:1:0), no special cases.
 *
 * ZMM ALLOCATION (persistent through the ladder):
 *   zmm0-2  R0 = (X:Y:Z)                SECRET
 *   zmm3-5  R1 = (X:Y:Z)                SECRET
 *   zmm6    k (bits being consumed)     SECRET — THE nonce
 *   zmm7    d (private key)             SECRET — used post-ladder
 *   zmm8    p (modulus, 5×52)           public constant
 *   zmm9    MASK52 = 2^52 − 1           public constant
 *   zmm10   b (curve param, 5×52)       public constant
 *   zmm11   FOLD260 = 2^260 mod p       reduction constant
 *   zmm12-27  pt_add + fe_mul scratch   transient
 *   zmm28-31  cswap + misc scratch      transient
 *
 * WHAT STILL TOUCHES MEMORY (and why it's safe):
 *   - Loading constants (p, b, G, FOLD260) — all public.
 *   - Loading d, k, e at entry — ONE read each, same address every
 *     call, no secret-dependent addressing.
 *   - Storing r, s at exit — they're the public output.
 *   - The code itself (instruction fetch) — public.
 *   - call/ret for fe_mul (stack) — fixed sequence, no secret data.
 *
 * CAVEAT: this is a foundation, not a production signer.  No RFC
 * 6979 (k must be supplied — do the HMAC derivation in C, it's all
 * public-hash operations on the message).  No fault-injection
 * countermeasures.  Assumes the process has exclusive ZMM use
 * (no context switch saves secrets to the kernel's XSAVE area —
 * that's an OS-level guarantee, not something this code controls).
 * ====================================================================== */

	.intel_syntax noprefix
	.text

/* ----------------------------------------------------------------------
 * fe_mul: zmm_c = zmm_a · zmm_b  (mod p)
 *
 * ZMM16 = a, ZMM17 = b on entry.  ZMM16 = result on exit.
 * Clobbers ZMM18-27.  Reads ZMM8 (p), ZMM9 (MASK52), ZMM11 (FOLD260).
 *
 * The product is built in two ZMM accumulators holding the 10-limb
 * result (limbs 0-7 in zmm19, limbs 8-9 spill into zmm20).  valignq
 * shifts the accumulator window as each broadcast row accumulates.
 * -------------------------------------------------------------------- */
	.globl	fe_mul_ifma
	.type	fe_mul_ifma, @function

/* ======================================================================
 * STATUS: DESIGN DOCUMENT.  See sign_zmm_femul.c for the intrinsics
 * implementation of fe_mul (the one primitive everything else composes).
 * The Python model (sign_zmm_model.py) passes RFC 6979 A.2.5.
 *
 * Hand-tuned assembly comes AFTER the intrinsics version passes the
 * full test suite and a careful read of the compiler output shows
 * a spill.  Writing valignq lane-shifts freehand is a bug farm.
 * ====================================================================== */
