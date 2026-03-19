/* Correctness harness for fe_mul5 (5×56 Montgomery multiply).
 * Checks against Python-generated reference vectors.
 * Vectors: MontMul(a, b) = a*b/R mod m, with R = 2^280. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* fe_mul5(dst, a, b, m, m0inv)
 * r13 must be preloaded with MASK = 2^56-1 (handled by a shim here). */
extern void fe_mul5_shim(int64_t *dst, const int64_t *a, const int64_t *b,
                         const int64_t *m, int64_t m0inv);

#define K 5
#define W 56
#define MASK ((1L << W) - 1)

static const int64_t P_LIMBS[K] = {
    0xffffffffffffffL, 0xffffffffffL, 0L, 0x1000000L, 0xffffffffL
};
static const int64_t N_LIMBS[K] = {
    0xb9cac2fc632551L, 0xfaada7179e84f3L, 0xffffffffffbce6L, 0xffffffL, 0xffffffffL
};
static const int64_t N_M0INV = 0xd1c8aaee00bc4fL;

#include "vectors_mul.h"

/* Compare a (possibly non-canonical) output against a canonical expected
 * value. Fully reduce a to [0, m) then compare. */
static int limbs_eq_mod(const int64_t *a, const int64_t *exp, const int64_t *m) {
    int64_t t[K];
    memcpy(t, a, sizeof t);

    for (int iter = 0; iter < 20; iter++) {
        /* Carry-propagate. */
        int64_t carry = 0;
        for (int k = 0; k < K; k++) {
            int64_t v = t[k] + carry;
            t[k] = v & MASK;
            carry = v >> W;
        }
        t[K-1] += carry << W;

        if (t[K-1] < 0) {
            for (int k = 0; k < K; k++) t[k] += m[k];
            continue;
        }
        /* Compare to m from top. */
        int ge = 0;
        for (int k = K-1; k >= 0; k--) {
            if (t[k] > m[k]) { ge = 1; break; }
            if (t[k] < m[k]) { break; }
            if (k == 0) ge = 1;
        }
        if (ge) {
            for (int k = 0; k < K; k++) t[k] -= m[k];
            continue;
        }
        break;
    }
    for (int k = 0; k < K; k++)
        if (t[k] != exp[k]) return 0;
    return 1;
}

static void dump(const char *lbl, const int64_t *v) {
    printf("  %s = {", lbl);
    for (int k = 0; k < K; k++) printf("0x%lx%s", v[k], k<K-1?",":"");
    printf("}\n");
}

int main(void) {
    int pass = 0, fail = 0;

    /* Mod-p vectors (m0inv = 1). */
    for (int i = 0; i < NUM_VECTORS; i++) {
        const int64_t *a = VECTORS[i];
        const int64_t *b = VECTORS[i] + K;
        const int64_t *exp = VECTORS[i] + 2*K;
        int64_t got[K];
        fe_mul5_shim(got, a, b, P_LIMBS, 1);
        if (limbs_eq_mod(got, exp, P_LIMBS)) {
            pass++;
        } else {
            fail++;
            if (fail <= 3) {
                printf("FAIL p-vector %d:\n", i);
                dump("a  ", a); dump("b  ", b);
                dump("exp", exp); dump("got", got);
            }
        }
    }

    /* Mod-n vectors (m0inv = 0xd1c8aaee00bc4f). */
    for (int i = 0; i < NUM_NVECTORS; i++) {
        const int64_t *a = NVECTORS[i];
        const int64_t *b = NVECTORS[i] + K;
        const int64_t *exp = NVECTORS[i] + 2*K;
        int64_t got[K];
        fe_mul5_shim(got, a, b, N_LIMBS, N_M0INV);
        if (limbs_eq_mod(got, exp, N_LIMBS)) {
            pass++;
        } else {
            fail++;
            if (fail <= 3) {
                printf("FAIL n-vector %d:\n", i);
                dump("a  ", a); dump("b  ", b);
                dump("exp", exp); dump("got", got);
            }
        }
    }

    printf("%d/%d passed\n", pass, pass+fail);
    return fail != 0;
}
