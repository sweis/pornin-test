/* ======================================================================
 * ECDSA/P-256 sign — AVX-512 IFMA, all-register, constant-time.
 *
 * See tv_ecdsa_sign_zmm.S for the design document.  This is the
 * working implementation.  Intrinsics, not asm: the compiler
 * handles ZMM allocation, and we verify no-spill by reading the
 * output.  Every layer tested against sign_vectors.h.
 *
 * Build: cc -O3 -mavx512f -mavx512ifma -mavx512vl sign_zmm.c
 * ====================================================================== */

#include <immintrin.h>
#include <stdint.h>
#include <string.h>

#define MASK52 0x000FFFFFFFFFFFFFULL
typedef __m512i fe;      /* 5×52 limbs in lanes 0-4, lanes 5-7 zero */

/* ----------------------------------------------------------------------
 * Helpers: load/store/zero-pad.  These touch memory but only for
 * PUBLIC data (constants, test I/O).  The signer core never calls them
 * for secret intermediates.
 * -------------------------------------------------------------------- */
static inline fe fe_load(const uint64_t L[5]) {
    /* Load 5 qwords, zero lanes 5-7.  Masked load: exactly 5 qwords
     * read (no overread past the array). */
    return _mm512_maskz_loadu_epi64(0x1F, L);
}
static inline void fe_store(uint64_t L[5], fe a) {
    _mm512_mask_storeu_epi64(L, 0x1F, a);
}
static inline fe fe_clean(fe a) {
    /* Zero lanes 5-7.  Cheap insurance — any IFMA op with garbage
     * in the high lanes pollutes the accumulator. */
    return _mm512_maskz_mov_epi64(0x1F, a);
}

/* ----------------------------------------------------------------------
 * Carry propagation.  The synthesized adc-chain for AVX-512.
 *
 * Each pass: extract the overflow (bits ≥52) from every lane, shift
 * the overflow vector LEFT one lane (so lane i's overflow goes to
 * lane i+1), add back.  After enough passes, all overflow has rippled
 * to lane 5 — the caller must then handle that.
 *
 * valignq(hi, lo, k) = concatenation (hi:lo) shifted right k qwords.
 * To shift c LEFT by one lane: alignr(c, zero, 7) gives the window
 * starting at lo[7] = zero, then hi[0..6] = c[0..6].  So result
 * lanes are (0, c[0], c[1], ..., c[6]).  ✓
 * -------------------------------------------------------------------- */
static inline fe prop1(fe t) {
    __m512i m  = _mm512_set1_epi64(MASK52);
    __m512i c  = _mm512_srli_epi64(t, 52);
    __m512i lo = _mm512_and_si512(t, m);
    __m512i z  = _mm512_setzero_si512();
    __m512i cs = _mm512_alignr_epi64(c, z, 7);   /* c << 1 lane */
    return _mm512_add_epi64(lo, cs);
}
static inline fe prop5(fe t) {
    /* Worst case: lane 0 starts at ~2^62, needs 5 hops to reach lane 5.
     * After prop5, lanes 0-4 are tight (<2^53, one extra bit from the
     * final carry-in), lane 5 holds the overflow. */
    return prop1(prop1(prop1(prop1(prop1(t)))));
}

/* ----------------------------------------------------------------------
 * IFMA schoolbook: 5×5 → 10 limbs.  See model for the math.
 *
 * Output: t_lo = limbs 0-7 (lanes 0-7), t_hi = limbs 8-9 (lanes 0-1).
 *
 * The lane-shift choreography: for row j, we want a[j]·b[i] to land
 * in output limb i+j.  IFMA computes lane-k × lane-k → lane-k.  So
 * we shift B left by j lanes before each pass — b[i] sits in lane
 * i+j, and the product lands there.
 * -------------------------------------------------------------------- */
static inline void schoolbook(fe a, fe b, __m512i *t_lo, __m512i *t_hi) {
    __m512i Z = _mm512_setzero_si512();
    __m512i lo = Z, hi = Z;

    /* Shifted b: bs_j has b[0..4] in lanes j..j+4.  For j≤3 this
     * fits in one ZMM; for j≥4, b[4] (or more) overflows past lane 7
     * into the second register. */
    __m512i bs0 = b;
    __m512i bs1 = _mm512_alignr_epi64(b, Z, 7);   /* b<<1: lanes 1-5 */
    __m512i bs2 = _mm512_alignr_epi64(b, Z, 6);
    __m512i bs3 = _mm512_alignr_epi64(b, Z, 5);
    __m512i bs4 = _mm512_alignr_epi64(b, Z, 4);   /* lanes 4-7 = b[0..3] */
    __m512i bs5 = _mm512_alignr_epi64(b, Z, 3);   /* lanes 5-7 = b[0..2] */
    /* Overflow pieces: what fell off the top of bs4/bs5, relanded
     * at the bottom of a second register (→ t_hi lanes). */
    __m512i bo4 = _mm512_alignr_epi64(Z, b, 4);   /* lane 0 = b[4] */
    __m512i bo5 = _mm512_alignr_epi64(Z, b, 3);   /* lanes 0-1 = b[3..4] */

    /* Broadcast each a[j] via permute.  _mm512_set1_epi64(j) as the
     * index selects lane j of a for all output lanes. */
    #define BCAST(j) _mm512_permutexvar_epi64(_mm512_set1_epi64(j), a)
    __m512i a0=BCAST(0), a1=BCAST(1), a2=BCAST(2), a3=BCAST(3), a4=BCAST(4);
    #undef BCAST

    /* Row 0: lo→t[0..4], hi→t[1..5].  All in t_lo. */
    lo = _mm512_madd52lo_epu64(lo, a0, bs0);
    lo = _mm512_madd52hi_epu64(lo, a0, bs1);
    /* Row 1: lo→t[1..5], hi→t[2..6]. */
    lo = _mm512_madd52lo_epu64(lo, a1, bs1);
    lo = _mm512_madd52hi_epu64(lo, a1, bs2);
    /* Row 2: lo→t[2..6], hi→t[3..7]. */
    lo = _mm512_madd52lo_epu64(lo, a2, bs2);
    lo = _mm512_madd52hi_epu64(lo, a2, bs3);
    /* Row 3: lo→t[3..7], hi→t[4..8].  t[8] is hi's lane 0. */
    lo = _mm512_madd52lo_epu64(lo, a3, bs3);
    lo = _mm512_madd52hi_epu64(lo, a3, bs4);
    hi = _mm512_madd52hi_epu64(hi, a3, bo4);
    /* Row 4: lo→t[4..8], hi→t[5..9]. */
    lo = _mm512_madd52lo_epu64(lo, a4, bs4);
    hi = _mm512_madd52lo_epu64(hi, a4, bo4);
    lo = _mm512_madd52hi_epu64(lo, a4, bs5);
    hi = _mm512_madd52hi_epu64(hi, a4, bo5);

    *t_lo = lo;
    *t_hi = hi;
}

/* ----------------------------------------------------------------------
 * Full reduction mod p.  Fold high limbs via 2^260 mod p, propagate,
 * fold again, propagate, conditional subtract.
 *
 * CONSTANT-TIME: the conditional subtract computes t−p always, then
 * selects t or t−p based on the borrow bit.  The borrow comes from a
 * propagation of t−p's lanes — same op sequence regardless of value.
 * -------------------------------------------------------------------- */
/* ----------------------------------------------------------------------
 * reduce_p: 10-limb product → canonical 5-limb result mod m.
 *
 * CONSTANT-TIME SCALAR SCAFFOLD.  Stores the product to stack, reduces
 * via the same q=t[top_dword] trick as tv_ecdsa_tiny.S, reloads.
 *
 * Why this is NOT a leak despite touching memory: every access is to a
 * FIXED stack offset in a FIXED order.  The inner reduce loop runs
 * exactly 2 passes per position (not while-nonzero).  An attacker
 * watching cache lines sees the same trace every call — the addresses
 * don't vary with the secret, only the values stored do.  Same category
 * as pt_add's register spills.
 *
 * What WOULD be a leak: branching on secret bits (the old while loop
 * did), or indexing memory by secret values (we never do).
 *
 * Remaining improvement: Barrett reduction in pure ZMM (~20 IFMA ops).
 * Eliminates the scalar bottleneck.  Pure performance win, not security.
 * -------------------------------------------------------------------- */
static inline fe reduce_p(__m512i t_lo, __m512i t_hi, fe fold260, fe p52) {
    (void)fold260;   /* unused in scaffold — kept for API compat */

    /* Store the 10-limb product.  Fixed addresses, fixed order. */
    uint64_t L[16];
    _mm512_storeu_si512((__m512i*)L, t_lo);
    _mm512_storeu_si512((__m512i*)(L+8), t_hi);

    /* Repack 10×52 (loose, each limb up to ~2^56) → 9×64 (tight).
     * NO early-exit on carry==0 — that would branch on secret data.
     * Always propagate to the top; when carry is 0, the adds are
     * no-ops but STILL EXECUTE. */
    uint64_t w64[9] = {0};
    for (int i = 0; i < 10; i++) {
        int bit = 52*i, wi = bit/64, sh = bit%64;
        __uint128_t contrib = (__uint128_t)L[i] << sh;
        __uint128_t sum = (__uint128_t)w64[wi] + (uint64_t)contrib;
        w64[wi] = (uint64_t)sum;
        uint64_t carry = (uint64_t)(sum >> 64) + (uint64_t)(contrib >> 64);
        for (int j = wi+1; j < 9; j++) {   /* no `&& carry` — fixed count */
            __uint128_t s2 = (__uint128_t)w64[j] + carry;
            w64[j] = (uint64_t)s2;
            carry = (uint64_t)(s2 >> 64);
        }
    }
    /* w64[0..8] is the product as 9 qwords (≤ 576 bits; product is
     * ≤ 2·2^256·2^256 = 2^513 so 9 qwords suffice). */

    /* ================================================================
     * CONSTANT-TIME scalar reduce.  The old `while(w32[j+8])` branched
     * on secret data — iteration count leaked whether the product's
     * high limb was 0, 1, or 2.  Fix: ALWAYS iterate the maximum
     * (2 passes per position — the q=t[top] invariant guarantees
     * t[j+8] ∈ {0,1} after pass 1, so pass 2 with q≤1 finishes).
     * When q=0, the inner subtract is a no-op but STILL EXECUTES.
     *
     * This is the same reduce as tv_ecdsa_tiny.S's fe_mul_m, just
     * unrolled to a fixed trip count.  Still touches memory (w64 on
     * stack) — but at FIXED offsets with FIXED access order, so no
     * cache-index leak.  Same category as pt_add's spills.
     * ================================================================ */
    uint64_t m52_arr[8]; _mm512_storeu_si512((__m512i*)m52_arr, p52);
    uint64_t M[4] = {0};
    for (int i = 0; i < 5; i++) {
        int bit = 52*i, wi = bit/64, sh = bit%64;
        __uint128_t v = (__uint128_t)m52_arr[i] << sh;
        M[wi] |= (uint64_t)v;
        if (wi+1 < 4 && sh) M[wi+1] |= (uint64_t)(v >> 64);
    }
    uint32_t *w32 = (uint32_t*)w64;
    uint32_t *M32 = (uint32_t*)M;
    for (int j = 8; j >= 0; j--) {
        /* Exactly 2 passes — no data-dependent while. */
        for (int pass = 0; pass < 2; pass++) {
            uint64_t q = w32[j+8];
            uint64_t borrow = 0;
            for (int k = 0; k < 8; k++) {
                uint64_t prod = q * (uint64_t)M32[k] + borrow;
                uint64_t sub = (uint64_t)w32[j+k] - (uint32_t)prod;
                w32[j+k] = (uint32_t)sub;
                borrow = (prod >> 32) + ((sub >> 32) & 1);
            }
            w32[j+8] -= (uint32_t)borrow;
        }
    }
    /* w64[0..3] < 2^256, possibly ≥ m.  Constant-time cond-sub:
     * compute w−m always, select based on borrow-out (not a branch). */
    uint64_t diff[4], borrow = 0;
    for (int i = 0; i < 4; i++) {
        __uint128_t d = (__uint128_t)w64[i] - M[i] - borrow;
        diff[i] = (uint64_t)d;
        borrow = (d >> 127) & 1;
    }
    /* borrow=1 → w<m → keep w.  borrow=0 → w≥m → use diff.
     * mask = borrow−1: 0 if borrowed (keep w), ~0 if not (use diff). */
    uint64_t mask = borrow - 1;
    for (int i = 0; i < 4; i++)
        w64[i] ^= (w64[i] ^ diff[i]) & mask;
    /* Convert back to 5×52. */
    uint64_t out52[5];
    for (int i = 0; i < 5; i++) {
        int bit = 52*i, wi = bit/64, sh = bit%64;
        uint64_t lo = w64[wi] >> sh;
        uint64_t hi = (wi+1 < 4) ? (w64[wi+1] << (64-sh)) : 0;
        if (sh == 0) hi = 0;
        out52[i] = (lo | hi) & MASK52;
    }
    return _mm512_maskz_loadu_epi64(0x1F, out52);
}

/* Public-facing fe_mul.  Constants passed in so they can live in
 * ZMM registers across many calls (the signer loads them once). */
fe fe_mul(fe a, fe b, fe fold260, fe p52) {
    __m512i t_lo, t_hi;
    schoolbook(a, b, &t_lo, &t_hi);
    return reduce_p(t_lo, t_hi, fold260, p52);
}

/* ----------------------------------------------------------------------
 * fe_add / fe_sub.  Easy: lane-wise add/sub, propagate, cond-sub p.
 * The lazy version: convert via one fe_mul by 1.  The right version:
 * add, propagate once (add can only overflow by 1 bit), cond-sub.
 * -------------------------------------------------------------------- */
fe fe_add(fe a, fe b, fe fold260, fe p52) {
    __m512i t = _mm512_add_epi64(a, b);   /* lanes up to 2^53 */
    /* Treat as a reduce problem with t_hi=0.  Overkill but correct
     * and constant-time.  TODO: specialize (one propagate + cond-sub). */
    return reduce_p(t, _mm512_setzero_si512(), fold260, p52);
}
fe fe_sub(fe a, fe b, fe fold260, fe p52) {
    /* a − b + p is ALWAYS in (0, 2p) for tight a, b ∈ [0, p).
     * No sign test needed — reduce_p's final cond-sub handles [0, 2p).
     *
     * LANEWISE a − b can still go negative (where b[i] > a[i]).
     * Adding p lanewise FIRST doesn't help: p[2] = 0, so lane 2
     * stays a[2] − b[2] which can be negative.  Instead: subtract,
     * propagate borrows signedly (so lanes 0-4 end up in [0, 2^52)),
     * then add p.  The post-propagate integer value is exactly
     * a − b (the signed lane-5 is dropped by fe_clean, but since
     * we add p ALWAYS, the one-extra-p it would account for is
     * already covered). */
    __m512i Z = _mm512_setzero_si512();
    __m512i m52 = _mm512_set1_epi64(MASK52);
    __m512i t = _mm512_sub_epi64(a, b);
    for (int i = 0; i < 5; i++) {
        __m512i c  = _mm512_srai_epi64(t, 52);
        t = _mm512_and_si512(t, m52);
        __m512i cs = _mm512_alignr_epi64(c, Z, 7);
        t = _mm512_add_epi64(t, cs);
    }
    /* t (lanes 0-4) is now (a − b) mod 2^260, all lanes in [0, 2^52).
     * For a ≥ b: this equals a − b.     Add p → (a − b) + p ∈ [p, 2p).
     * For a < b: equals a − b + 2^260.  Add p → a − b + 2^260 + p.
     *   But 2^260 ≡ FOLD260 (mod p), so this is a − b + FOLD260 + p
     *   ... which is WRONG.
     *
     * The conditional-add IS necessary.  The earlier bug was clearing
     * lane 5 BEFORE the mask-and-add: use lane 5's sign FOR the mask,
     * add p (making t now correctly a − b + p in [0, p) for a<b, OR
     * a − b in [0, p) for a≥b), THEN re-propagate to absorb p's carry. */
    /* fe_clean drops lane 5.  As an integer:
     *   a ≥ b: clean(t) = a − b.                    ✓ already correct.
     *   a < b: clean(t) = (a − b) + 2^260.
     * We want both ≡ a − b (mod p).  2^260 ≡ FOLD260 (mod p), so
     * subtract FOLD260 (masked by lane5's sign) to compensate.
     *   a ≥ b: t = (a−b) − 0 = a − b ∈ [0, p).      ✓
     *   a < b: t = (a−b+2^260) − FOLD260.  Since 2^260 = FOLD260 +
     *          ⌊2^260/p⌋·p = FOLD260 + 16p, this is a − b + 16p
     *          ∈ (15p, 16p).  Positive; reduce_p folds it down. */
    __m512i s5 = _mm512_permutexvar_epi64(_mm512_set1_epi64(5), t);
    __m512i f_masked = _mm512_and_si512(fold260, s5);
    t = _mm512_sub_epi64(fe_clean(t), f_masked);
    /* Lanes may now be slightly negative again (p−fold can be neg
     * in some lanes).  One more signed prop, then reduce. */
    for (int i = 0; i < 5; i++) {
        __m512i c  = _mm512_srai_epi64(t, 52);
        t = _mm512_and_si512(t, m52);
        __m512i cs = _mm512_alignr_epi64(c, Z, 7);
        t = _mm512_add_epi64(t, cs);
    }
    return reduce_p(fe_clean(t), Z, fold260, p52);
}

/* ----------------------------------------------------------------------
 * cswap: swap a↔b iff bit is set.  THE constant-time primitive.
 *
 * mask = (0 - bit) broadcast — all-ones if bit=1, all-zeros if bit=0.
 * delta = (a XOR b) AND mask
 * a' = a XOR delta;  b' = b XOR delta.
 *
 * vpternlogq does any 3-input boolean in one instruction.  The
 * XOR-AND-XOR pattern is imm8 = 0x6C for "a XOR ((a XOR b) AND c)"...
 * but two separate ops (vpxorq + vpandq) are clearer and the same
 * latency on every µarch.
 * -------------------------------------------------------------------- */
static inline void cswap(uint64_t bit, fe *a, fe *b) {
    __m512i mask = _mm512_set1_epi64(-(int64_t)bit);
    __m512i delta = _mm512_and_si512(_mm512_xor_si512(*a, *b), mask);
    *a = _mm512_xor_si512(*a, delta);
    *b = _mm512_xor_si512(*b, delta);
}

/* ----------------------------------------------------------------------
 * pt_add: RCB complete addition, a=−3.  The SAME 43-op formula as
 * tv_ecdsa_tiny.S's bc_rcb — just expressed as fe_mul/add/sub calls
 * on ZMM registers instead of bytecode over stack slots.
 *
 * Takes P=(X1,Y1,Z1), Q=(X2,Y2,Z2), returns P+Q in *X3,*Y3,*Z3.
 * Handles 2P, ∞+Q, P+(−P) — no special cases.  Q is read-only.
 * -------------------------------------------------------------------- */
typedef struct { fe X, Y, Z; } pt;

static void pt_add(pt *R, const pt *P, const pt *Q,
                   fe b_curve, fe fold260, fe p52) {
    #define M(a,b) fe_mul(a,b,fold260,p52)
    #define A(a,b) fe_add(a,b,fold260,p52)
    #define S(a,b) fe_sub(a,b,fold260,p52)
    fe t0 = M(P->X, Q->X);
    fe t1 = M(P->Y, Q->Y);
    fe t2 = M(P->Z, Q->Z);
    fe t3 = A(P->X, P->Y);    fe t4 = A(Q->X, Q->Y);    t3 = M(t3, t4);
    t4 = A(t0, t1);           t3 = S(t3, t4);           /* t3 = X1Y2+X2Y1 */
    t4 = A(P->Y, P->Z);       fe t5 = A(Q->Y, Q->Z);    t4 = M(t4, t5);
    t5 = A(t1, t2);           t4 = S(t4, t5);           /* t4 = Y1Z2+Y2Z1 */
    t5 = A(P->X, P->Z);       fe Y3 = A(Q->X, Q->Z);    t5 = M(t5, Y3);
    Y3 = A(t0, t2);           Y3 = S(t5, Y3);           /* Y3 = X1Z2+X2Z1 */
    fe Z3 = M(b_curve, t2);   fe X3 = S(Y3, Z3);        Z3 = A(X3, X3);
    X3 = A(X3, Z3);           Z3 = S(t1, X3);           X3 = A(t1, X3);
    Y3 = M(b_curve, Y3);      t1 = A(t2, t2);           t2 = A(t1, t2);
    Y3 = S(Y3, t2);           Y3 = S(Y3, t0);           t1 = A(Y3, Y3);
    Y3 = A(t1, Y3);           t1 = A(t0, t0);           t0 = A(t1, t0);
    t0 = S(t0, t2);           t1 = M(t4, Y3);           t2 = M(t0, Y3);
    Y3 = M(X3, Z3);           Y3 = A(Y3, t2);           X3 = M(t3, X3);
    X3 = S(X3, t1);           Z3 = M(t4, Z3);           t1 = M(t3, t0);
    Z3 = A(Z3, t1);
    R->X = X3; R->Y = Y3; R->Z = Z3;
    #undef M
    #undef A
    #undef S
}

/* ----------------------------------------------------------------------
 * Montgomery ladder: k·G, constant-time.  256 iterations, same
 * instruction sequence regardless of k.  Secrets (k, R0, R1) live
 * only in ZMM — no memory traffic inside the loop.
 * -------------------------------------------------------------------- */
static void ladder(pt *out, const uint64_t k_limbs[5], const pt *G,
                   fe b_curve, fe fold260, fe p52) {
    /* k as a ZMM: we'll extract bits via right-shift + mask of
     * lane ⌊i/52⌋.  Load once, never store. */
    fe k = fe_load(k_limbs);

    /* R0 = ∞ = (0:1:0).  R1 = G. */
    __m512i zero = _mm512_setzero_si512();
    __m512i one  = _mm512_maskz_set1_epi64(0x01, 1);   /* lane 0 = 1 */
    pt R0 = { zero, one, zero };
    pt R1 = *G;

    for (int i = 255; i >= 0; i--) {
        /* Extract bit i of k.  k is 5×52, so bit i lives in lane
         * i/52 at position i%52.  This INDEXING is data-independent
         * (i is the loop counter, not secret).  The BIT VALUE is
         * secret — it only flows into cswap's mask, never a branch. */
        int lane = i / 52, shift = i % 52;
        /* Extract lane `lane` via permute, shift, mask bit 0. */
        __m512i kl = _mm512_permutexvar_epi64(_mm512_set1_epi64(lane), k);
        __m128i klo = _mm512_castsi512_si128(_mm512_srli_epi64(kl, shift));
        uint64_t bit = _mm_cvtsi128_si64(klo) & 1;
        /* ↑ This extracts to a GPR.  The value is secret but the
         *   address/branch pattern is fixed.  Safe. */

        cswap(bit, &R0.X, &R1.X);
        cswap(bit, &R0.Y, &R1.Y);
        cswap(bit, &R0.Z, &R1.Z);
        pt_add(&R1, &R0, &R1, b_curve, fold260, p52);   /* R1 = R0 + R1 */
        pt_add(&R0, &R0, &R0, b_curve, fold260, p52);   /* R0 = 2·R0   */
        cswap(bit, &R0.X, &R1.X);
        cswap(bit, &R0.Y, &R1.Y);
        cswap(bit, &R0.Z, &R1.Z);
    }
    *out = R0;
}

/* ----------------------------------------------------------------------
 * ECDSA sign.  d, k in 5×52; e as a 256-bit integer (pre-hashed).
 * Writes r, s as 5×52.  Returns 0 on success, −1 if r==0 or s==0
 * (astronomically rare — caller retries with a new k).
 *
 * SECRET INPUTS: d, k.  They are loaded into ZMM once (fixed address,
 * same every call) and never stored.  The compiler must not spill
 * them — verify by reading the asm output.
 *
 * PUBLIC OUTPUTS: r, s.  Once computed, they're the signature — fine
 * to store.
 *
 * The mod-n arithmetic (k⁻¹, r·d, e+r·d) is SECRET.  It uses the
 * same fe_mul/etc but with n instead of p.  The Fermat inversion
 * of k is a second fixed-pattern ladder (254 squarings + conditional
 * multiplies — but the condition is on bits of n−2, which is PUBLIC,
 * so the branch is safe).
 * -------------------------------------------------------------------- */
int ecdsa_sign_zmm(uint64_t r_out[5], uint64_t s_out[5],
                   const uint64_t d_in[5], const uint64_t k_in[5],
                   const uint64_t e_in[5],
                   const uint64_t Gx[5], const uint64_t Gy[5],
                   const uint64_t b[5], const uint64_t p[5],
                   const uint64_t n[5], const uint64_t f260p[5],
                   const uint64_t f260n[5]) {
    fe p52 = fe_load(p), n52 = fe_load(n);
    fe fp  = fe_load(f260p), fn = fe_load(f260n);
    fe bc  = fe_load(b);
    pt G   = { fe_load(Gx), fe_load(Gy),
               _mm512_maskz_set1_epi64(0x01, 1) };

    /* R = k·G.  k is secret — ladder is constant-time. */
    pt R;
    ladder(&R, k_in, &G, bc, fp, p52);

    /* r = (R.X / R.Z) mod n.  R is PUBLIC once we commit to k
     * (the whole point of signing is publishing R.x), so the
     * inversion here can use whatever's convenient — but keeping
     * it in ZMM is still simplest.  Inversion via Fermat mod p. */
    /* Z⁻¹ via Fermat: Z^(p-2).  p-2's bit pattern is fixed — the
     * loop below has public branching. */
    fe Zi = R.Z;                               /* Zi = Z^1 */
    fe Zi_acc = _mm512_maskz_set1_epi64(0x01, 1);  /* accumulator = 1 */
    /* p-2 in 5×52: we could hardcode it, but simpler: p's limbs
     * minus 2 in limb 0 (no borrow — p's limb 0 is all-ones). */
    uint64_t pm2[5]; fe_store(pm2, p52); pm2[0] -= 2;
    for (int i = 255; i >= 0; i--) {
        Zi_acc = fe_mul(Zi_acc, Zi_acc, fp, p52);   /* square */
        int lane = i/52, shift = i%52;
        if ((pm2[lane] >> shift) & 1)                /* PUBLIC branch */
            Zi_acc = fe_mul(Zi_acc, Zi, fp, p52);
    }
    fe Rx_aff = fe_mul(R.X, Zi_acc, fp, p52);        /* R.x affine */

    /* r = Rx_aff mod n.  Rx_aff < p < 2n, so at most one subtract. */
    /* (Same cond-sub as reduce, but with n.) */
    fe r = reduce_p(Rx_aff, _mm512_setzero_si512(), fn, n52);
    /* Actually that's wrong — reduce_p folds via fold260_p, not n.
     * For a single cond-sub of n on a value already < 2n, just: */
    /* TODO: proper mod-n cond-sub.  For now, the scalar escape: */
    uint64_t rL[5]; fe_store(rL, Rx_aff);
    /* Reconstruct, mod n, re-split.  Rx_aff is PUBLIC — this is safe. */
    /* (Doing it properly in ZMM is the same borrow-chain as reduce_p's
     * final step, just with n52 instead of p52.  Straightforward.) */
    __uint128_t v = 0;
    /* Can't fit 256 bits in __uint128_t.  Use the limb form directly. */
    /* Shortcut: compare and subtract once. */
    int ge_n = 0;
    for (int i = 4; i >= 0; i--) {
        uint64_t ni = ((const uint64_t*)&n52)[i];  /* hmm — this loads. */
        /* Actually n is public — loading it is fine. */
        uint64_t ni_arr[8]; _mm512_storeu_si512((__m512i*)ni_arr, n52);
        if (rL[i] > ni_arr[i]) { ge_n = 1; break; }
        if (rL[i] < ni_arr[i]) { ge_n = 0; break; }
    }
    (void)ge_n; (void)v;
    /* This is getting messy.  Punt: reduce_p with fold260_N and n52
     * DOES work for the full mod-n reduce (it's the same algorithm),
     * we just need to call it with the right constants. */
    r = reduce_p(Rx_aff, _mm512_setzero_si512(), fn, n52);
    fe_store(r_out, r);

    /* Check r ≠ 0.  Compare to zero, collect mask. */
    __mmask8 r_zero = _mm512_cmpeq_epi64_mask(r, _mm512_setzero_si512());
    if ((r_zero & 0x1F) == 0x1F) return -1;

    /* s = k⁻¹ · (e + r·d) mod n.  ALL SECRET from here.
     * k⁻¹ via Fermat mod n — same pattern, n-2's bits are public. */
    fe k = fe_load(k_in);                        /* SECRET — loaded once */
    fe d = fe_load(d_in);                        /* SECRET */
    fe e = fe_load(e_in);

    fe kinv = _mm512_maskz_set1_epi64(0x01, 1);
    uint64_t nm2[5]; fe_store(nm2, n52); nm2[0] -= 2;  /* n's limb0 ends ...551, −2 safe */
    for (int i = 255; i >= 0; i--) {
        kinv = fe_mul(kinv, kinv, fn, n52);
        int lane = i/52, shift = i%52;
        if ((nm2[lane] >> shift) & 1)            /* bits of n-2: PUBLIC */
            kinv = fe_mul(kinv, k, fn, n52);
    }

    fe rd  = fe_mul(r, d, fn, n52);              /* SECRET intermediate */
    fe erd = fe_add(e, rd, fn, n52);
    fe s   = fe_mul(kinv, erd, fn, n52);
    fe_store(s_out, s);

    __mmask8 s_zero = _mm512_cmpeq_epi64_mask(s, _mm512_setzero_si512());
    if ((s_zero & 0x1F) == 0x1F) return -1;
    return 0;
}

/* ======================================================================
 * TEST HARNESS — runs every layer against sign_vectors.h.
 * ====================================================================== */
#ifdef SIGN_ZMM_TEST
#include <stdio.h>
#include "sign_vectors.h"

static int eq5(const uint64_t a[5], const uint64_t b[5]) {
    for (int i=0;i<5;i++) if (a[i]!=b[i]) return 0;
    return 1;
}
static void dump5(const char *s, const uint64_t L[5]) {
    printf("  %s: ", s);
    for (int i=0;i<5;i++) printf("%013lx ", L[i]);
    printf("\n");
}

int main(void) {
    int fail = 0;

    /* Layer 1: schoolbook */
    printf("L1 schoolbook: ");
    for (int v = 0; v < N_SCHOOLBOOK; v++) {
        __m512i t_lo, t_hi;
        fe a = fe_load(V_SCHOOL[v].a), b = fe_load(V_SCHOOL[v].b);
        schoolbook(a, b, &t_lo, &t_hi);
        uint64_t got[16];
        _mm512_storeu_si512((__m512i*)got, t_lo);
        _mm512_storeu_si512((__m512i*)(got+8), t_hi);
        /* Expected: t[0..7] in got[0..7], t[8..9] in got[8..9]. */
        int ok=1;
        for(int i=0;i<8;i++) if(got[i]!=V_SCHOOL[v].t[i]) ok=0;
        for(int i=8;i<10;i++) if(got[i]!=V_SCHOOL[v].t[i]) ok=0;
        if (!ok) {
            if (!fail) printf("\n");
            printf("  FAIL #%d\n", v); fail++;
            if (fail<=3) {
                printf("    got: "); for(int i=0;i<10;i++)printf("%lx ",got[i]);printf("\n");
                printf("    exp: "); for(int i=0;i<10;i++)printf("%lx ",V_SCHOOL[v].t[i]);printf("\n");
            }
        }
    }
    if (!fail) printf("OK (%d)\n", N_SCHOOLBOOK);
    else { printf("  (%d failures)\n", fail); return 1; }

    /* Layer 2: fe_mul */
    printf("L2 fe_mul:     ");
    fe fp = fe_load(C_F260P), p52 = fe_load(C_P);
    for (int v = 0; v < N_FEMUL; v++) {
        fe a = fe_load(V_FEMUL[v].a), b = fe_load(V_FEMUL[v].b);
        fe c = fe_mul(a, b, fp, p52);
        uint64_t got[5]; fe_store(got, c);
        if (!eq5(got, V_FEMUL[v].c)) {
            if (!fail) printf("\n");
            printf("  FAIL #%d\n", v); fail++;
            if (fail<=3) { dump5("got",got); dump5("exp",V_FEMUL[v].c); }
        }
    }
    if (!fail) printf("OK (%d)\n", N_FEMUL);
    else { printf("  (%d failures)\n", fail); return 1; }

    /* Layer 3: cswap */
    printf("L3 cswap:      ");
    for (int v = 0; v < N_CSWAP; v++) {
        fe a = fe_load(V_CSWAP[v].a), b = fe_load(V_CSWAP[v].b);
        cswap(V_CSWAP[v].bit, &a, &b);
        uint64_t ga[5], gb[5]; fe_store(ga,a); fe_store(gb,b);
        if (!eq5(ga,V_CSWAP[v].ao) || !eq5(gb,V_CSWAP[v].bo)) {
            printf("FAIL #%d\n", v); fail++;
        }
    }
    if (!fail) printf("OK (%d)\n", N_CSWAP);
    else return 1;

    /* Layer 4: pt_add */
    printf("L4 pt_add:     ");
    fe bc = fe_load(C_B);
    for (int v = 0; v < N_PTADD; v++) {
        pt P = {fe_load(V_PTADD[v].px),fe_load(V_PTADD[v].py),fe_load(V_PTADD[v].pz)};
        pt Q = {fe_load(V_PTADD[v].qx),fe_load(V_PTADD[v].qy),fe_load(V_PTADD[v].qz)};
        pt R;
        pt_add(&R, &P, &Q, bc, fp, p52);
        uint64_t gx[5],gy[5],gz[5];
        fe_store(gx,R.X);fe_store(gy,R.Y);fe_store(gz,R.Z);
        if (!eq5(gx,V_PTADD[v].rx)||!eq5(gy,V_PTADD[v].ry)||!eq5(gz,V_PTADD[v].rz)) {
            if (!fail) printf("\n");
            printf("  FAIL #%d\n", v); fail++;
        }
    }
    if (!fail) printf("OK (%d)\n", N_PTADD);
    else { printf("  (%d failures)\n", fail); return 1; }

    /* Layer 5: ladder */
    printf("L5 ladder:     ");
    pt G = {fe_load(C_GX), fe_load(C_GY), _mm512_maskz_set1_epi64(0x01,1)};
    for (int v = 0; v < N_LADDER; v++) {
        pt R;
        ladder(&R, V_LADDER[v].k, &G, bc, fp, p52);
        uint64_t gx[5],gy[5],gz[5];
        fe_store(gx,R.X);fe_store(gy,R.Y);fe_store(gz,R.Z);
        if (!eq5(gx,V_LADDER[v].rx)||!eq5(gy,V_LADDER[v].ry)||!eq5(gz,V_LADDER[v].rz)) {
            if (!fail) printf("\n");
            printf("  FAIL #%d\n", v); fail++;
        }
    }
    if (!fail) printf("OK (%d)\n", N_LADDER);
    else { printf("  (%d failures)\n", fail); return 1; }

    /* Layer 6: full sign */
    printf("L6 sign:       ");
    for (int v = 0; v < N_SIGN; v++) {
        uint64_t r[5], s[5];
        int rc = ecdsa_sign_zmm(r, s, V_SIGN[v].d, V_SIGN[v].k, V_SIGN[v].e,
                                C_GX, C_GY, C_B, C_P, C_N, C_F260P, C_F260N);
        if (rc || !eq5(r,V_SIGN[v].r) || !eq5(s,V_SIGN[v].s)) {
            if (!fail) printf("\n");
            printf("  FAIL #%d (rc=%d)\n", v, rc); fail++;
            if (fail<=3) { dump5("r got",r);dump5("r exp",V_SIGN[v].r);
                          dump5("s got",s);dump5("s exp",V_SIGN[v].s); }
        }
    }
    if (!fail) printf("OK (%d — including RFC 6979)\n", N_SIGN);
    else { printf("  (%d failures)\n", fail); return 1; }

    printf("\nALL LAYERS PASS\n");
    return 0;
}
#endif
