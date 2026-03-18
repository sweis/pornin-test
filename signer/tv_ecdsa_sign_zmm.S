/* ======================================================================
 * ECDSA/P-256 sign — AVX-512 IFMA, constant-time.  DESIGN NOTES.
 *
 * The working implementation is sign_zmm.c (intrinsics).  This file
 * documents the design decisions and what "constant-time" means here.
 *
 * ──────────────────────────────────────────────────────────────────
 *  THREAT MODEL
 * ──────────────────────────────────────────────────────────────────
 *
 * An attacker observes: branch history, cache-line access pattern,
 * instruction timing.  They do NOT see register contents or the
 * values stored to memory (only which addresses are touched, when).
 *
 * LEAKS we defend against:
 *   - Secret-dependent BRANCH: iteration counts, if/else on key bits.
 *   - Secret-dependent MEMORY INDEX: table[secret] leaks secret via
 *     cache line.  Even fixed-size tables.
 *
 * NOT a leak (and we rely on this):
 *   - Storing a secret VALUE to a FIXED address.  The address doesn't
 *     vary, so the access pattern doesn't either.  pt_add's ~200
 *     register spills are this category — fixed %rbp offsets, 0
 *     branches, same trace every call.  Store-to-load forwarding
 *     latency is value-independent on every x86 we care about.
 *
 * ──────────────────────────────────────────────────────────────────
 *  REPRESENTATION: 5×52-bit limbs
 * ──────────────────────────────────────────────────────────────────
 *
 *   a = a₀ + a₁·2^52 + a₂·2^104 + a₃·2^156 + a₄·2^208
 *
 * One field element = lanes 0-4 of a ZMM.  Lanes 5-7 MUST be zero
 * (IFMA madd is lane-wise — garbage in 5-7 pollutes the accumulator).
 * 12 bits of headroom per lane (52 < 64) let additions accumulate
 * before carry propagation is needed.
 *
 * Carry propagation has no cross-lane flag.  Synthesize it:
 *   c  = t >> 52                        (vpsrlq — or srai if signed)
 *   t &= MASK52                          (vpandq)
 *   t += c shifted left 1 lane           (valignq + vpaddq)
 * Five passes fully tighten (lane 0's overflow reaches lane 5).
 *
 * ──────────────────────────────────────────────────────────────────
 *  REDUCTION: Barrett K=512
 * ──────────────────────────────────────────────────────────────────
 *
 *   μ = ⌊2^512 / m⌋   — 257 bits, fits EXACTLY in 5 limbs (both p, n)
 *   q = ⌊t · μ / 2^512⌋
 *   r = t − q·m       ∈ [0, 2m)   — one cond_sub finishes
 *
 * Why K=512: it's the largest K where μ fits 5 limbs.  K=520 gives a
 * 265-bit μ (limb 5 = 16) — small but nonzero, needs special handling.
 * K=512 keeps everything in the 5×5 schoolbook.
 *
 * The one fiddly bit: 512 = 9·52 + 44 (not limb-aligned).  Extract
 * output limbs 9-14, then cross-lane shift right 44:
 *   q[i] = (L[9+i] >> 44) | (L[10+i] << 8)
 * That's vpsrlq + valignr + vpsllq + vporq.
 *
 * Three schoolbooks per reduce (t_lo·μ, t_hi·μ, q·m).  ~60 IFMA ops.
 *
 * ──────────────────────────────────────────────────────────────────
 *  LADDER: Montgomery, constant-time
 * ──────────────────────────────────────────────────────────────────
 *
 *   R0, R1 = ∞, G
 *   for i = 255 downto 0:
 *     b = bit i of k                    (extract to GPR — value secret,
 *     cswap(R0, R1, b)                   sequence fixed)
 *     R1 = R0 + R1                      (ALWAYS — no skip-on-zero-bit)
 *     R0 = 2·R0
 *     cswap(R0, R1, b)
 *
 * cswap: XOR-with-mask.  mask = (0−b) broadcast.
 *   delta = (a XOR b) AND mask;  a ^= delta;  b ^= delta.
 *
 * Point addition uses RCB complete formulas (same 43-op sequence as
 * tv_ecdsa_tiny.S's bc_rcb).  ∞ = (0:1:0) — the Y≠0 matters; (0:0:0)
 * doesn't work as ∞ under RCB.
 *
 * ──────────────────────────────────────────────────────────────────
 *  WHAT TOUCHES MEMORY (and why it's OK)
 * ──────────────────────────────────────────────────────────────────
 *
 *   Loading d, k, e at entry        one read each, fixed address
 *   Loading constants (p, n, μ, G)  public
 *   Storing r, s at exit            the public output
 *   pt_add's spills                 fixed offsets, fixed order
 *   call/ret for fe_mul (stack)     fixed sequence, public
 *
 * NOT handled (out of scope):
 *   - Context switches saving ZMM to XSAVE area.  That's an OS-level
 *     guarantee (mlock the key, or don't context-switch mid-sign).
 *   - Fault injection / glitching.  Physical-access attacks.
 *   - RFC 6979 k derivation.  Do it in C — it's all public-hash ops.
 *
 * ──────────────────────────────────────────────────────────────────
 *  STATUS
 * ──────────────────────────────────────────────────────────────────
 *
 * sign_zmm.c passes: 200 schoolbook vectors, 500 fe_mul, 27 pt_add
 * (including completeness edge cases), 20 ladder, 32 sign (including
 * RFC 6979 A.2.5).  Cross-verified against tv_ecdsa_tiny.S (607/607
 * Wycheproof).  ~1.8M cycles/sign on Sapphire Rapids.
 *
 * Hand-tuned asm would save some cycles (GCC's spills cost ~20%), but
 * the compiler already produces branch-free code.  Diminishing returns.
 * ====================================================================== */
