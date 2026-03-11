/*
 * ECDSA/P-256 signature verification — size-optimised implementation.
 *
 * Design notes
 * ------------
 *  - 256-bit integers are held in little-endian arrays of eight 32-bit limbs.
 *  - All field arithmetic uses Montgomery multiplication with a single
 *    generic routine that works for both the field prime p and the group
 *    order n (the modulus is passed as a parameter). This avoids having
 *    two copies of the reduction code.
 *  - Modular inversion is done by Fermat's little theorem (exponentiation
 *    to m-2), reusing the multiplication routine.
 *  - Point arithmetic uses Jacobian coordinates; the doubling formula
 *    exploits a = -3. The addition routine handles all special cases
 *    (P = O, Q = O, P = Q, P = -Q).
 *  - Scalar multiplication is a straightforward double-and-add; it is
 *    called twice (for u1*G and u2*Q) rather than interleaved, because
 *    the code-size saving from having a single simple loop outweighs
 *    the speed benefit of Shamir's trick.
 *
 * The public inputs (signature, public key, hash) are untrusted and are
 * fully validated before any arithmetic is performed:
 *   - signature length == 64, public key length == 65, 32 <= hash <= 64
 *   - public key starts with 0x04
 *   - public key coordinates x,y are each < p
 *   - public key point satisfies y^2 = x^3 - 3x + b  (mod p)
 *   - r, s are each in [1, n-1]
 *
 * Since P-256 has cofactor 1, every point on the curve (other than the
 * point at infinity, which the uncompressed format cannot encode) is in
 * the prime-order subgroup, so no additional subgroup check is needed.
 *
 * This is verification only: there is no secret-dependent branching or
 * memory access, so constant-time execution is not a requirement. Code
 * size is the primary optimisation target.
 */

#include "tv_ecdsa.h"
#include <stdint.h>

/*
 * Ask the compiler not to inline helpers that are called from multiple
 * sites. With -Os the compiler usually does the right thing, but these
 * small leaf functions are just on the borderline where inlining costs
 * more than it saves.
 */
#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

/* ---------------------------------------------------------------------- */
/* 256-bit integer primitives                                             */
/* ---------------------------------------------------------------------- */

typedef uint32_t u32;
typedef uint64_t u64;

/* A 256-bit unsigned integer, eight 32-bit little-endian limbs. */
typedef u32 fe[8];

/* P-256 field prime. */
static const fe P = {
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
	0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
};

/* Curve order. */
static const fe N = {
	0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
	0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
};

/* Curve coefficient b. */
static const fe B = {
	0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
	0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
};

/* Conventional generator (affine). */
static const fe GX = {
	0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
	0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2
};
static const fe GY = {
	0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
	0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2
};

/* 2^512 mod p and 2^512 mod n (for conversion into Montgomery form). */
static const fe R2P = {
	0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFB,
	0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000004
};
static const fe R2N = {
	0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C,
	0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94
};

/* -1/p mod 2^32 and -1/n mod 2^32 (Montgomery reduction constant). */
#define P_M0I  0x00000001u
#define N_M0I  0xEE00BC4Fu

/* Set to zero. */
static void fe_zero(u32 *d)
{
	int i;
	for (i = 0; i < 8; i++) d[i] = 0;
}

/* Copy. */
static void fe_cpy(u32 *d, const u32 *s)
{
	int i;
	for (i = 0; i < 8; i++) d[i] = s[i];
}

/* Return 1 if a == 0. */
static int fe_iszero(const u32 *a)
{
	u32 x = 0;
	int i;
	for (i = 0; i < 8; i++) x |= a[i];
	return x == 0;
}

/* Raw subtraction r = a - b, returns borrow out (0 or 1). */
static u32 fe_sub_raw(u32 *r, const u32 *a, const u32 *b)
{
	u64 c = 0;
	int i;
	for (i = 0; i < 8; i++) {
		u64 v = (u64)a[i] - b[i] - c;
		r[i] = (u32)v;
		c = (v >> 63) & 1;
	}
	return (u32)c;
}

/* Return 1 if a >= b (as 256-bit unsigned integers). */
static int fe_geq(const u32 *a, const u32 *b)
{
	int i;
	for (i = 7; i >= 0; i--) {
		if (a[i] != b[i]) return a[i] > b[i];
	}
	return 1;
}

/* Raw addition r = a + b (carry out is discarded — only used for
 * fixed-width modular add-back). */
static void fe_add_raw(u32 *r, const u32 *a, const u32 *b)
{
	u64 c = 0;
	int i;
	for (i = 0; i < 8; i++) {
		u64 v = (u64)a[i] + b[i] + c;
		r[i] = (u32)v;
		c = v >> 32;
	}
}

/*
 * Modular subtraction: r = (a - b) mod m. Requires a < m and b <= m.
 * Result is in [0, m-1].
 */
static void fe_sub_m(u32 *r, const u32 *a, const u32 *b, const u32 *m)
{
	if (fe_sub_raw(r, a, b)) {
		/* Borrow: add m back. */
		fe_add_raw(r, r, m);
	}
}

/*
 * Internal helper: t[0..9] += x * y[0..7], with carry propagation
 * into the two high limbs. Used twice per iteration in Montgomery
 * multiplication; factoring it saves ~100 bytes.
 */
static void muladd10(u32 *t, u32 x, const u32 *y)
{
	u64 c = 0;
	int j;
	for (j = 0; j < 8; j++) {
		u64 v = (u64)t[j] + (u64)x * y[j] + c;
		t[j] = (u32)v;
		c = v >> 32;
	}
	for (; c; j++) {
		u64 v = (u64)t[j] + c;
		t[j] = (u32)v;
		c = v >> 32;
	}
}

/*
 * Montgomery multiplication: r = a * b * R^{-1} mod m, where R = 2^256.
 * Requires a, b < m. Modulus m must be odd. m0i = -m^{-1} mod 2^32.
 *
 * Standard CIOS (coarsely integrated operand scanning) algorithm.
 * Invariant: partial result t < m + b < 2m, so a single conditional
 * subtraction at the end suffices.
 */
static void fe_mul_m(u32 *r, const u32 *a, const u32 *b,
	const u32 *m, u32 m0i)
{
	u32 t[10];
	int i, j;

	for (i = 0; i < 10; i++) t[i] = 0;

	for (i = 0; i < 8; i++) {
		muladd10(t, a[i], b);         /* t += a[i] * b */
		muladd10(t, t[0] * m0i, m);   /* t += q * m (clears low limb) */
		for (j = 0; j < 9; j++) t[j] = t[j + 1];
		t[9] = 0;
	}

	/*
	 * Now 0 <= t < 2m (t[8] is 0 or 1). One conditional subtraction
	 * of m brings it into [0, m-1].
	 */
	{
		u32 bb = fe_sub_raw(r, t, m);
		if (!t[8] && bb) fe_cpy(r, t);
	}
}

/*
 * Modular inversion by Fermat's little theorem, in Montgomery form:
 *   input 'a' is a_real * R mod m, output is (a_real)^{-1} * R mod m.
 * The exponent is m-2 (computed here from m), which is correct because
 * both p and n are prime.
 */
static void fe_inv_m(u32 *r, const u32 *a, const u32 *m, u32 m0i)
{
	fe t, e;
	int i, started = 0;

	/* e = m - 2. m is odd and > 2 so no borrow past limb 0. */
	fe_cpy(e, m);
	e[0] -= 2;

	/* Square-and-multiply, MSB-first. Delay init until first set bit
	 * (saves storing "1 in Montgomery form"). e > 0 for our moduli. */
	for (i = 255; i >= 0; i--) {
		u32 bit = (e[i >> 5] >> (i & 31)) & 1;
		if (started) {
			fe_mul_m(t, t, t, m, m0i);
			if (bit) fe_mul_m(t, t, a, m, m0i);
		} else if (bit) {
			fe_cpy(t, a);
			started = 1;
		}
	}
	fe_cpy(r, t);
}

/*
 * One Montgomery reduction step: r = a * R^{-1} mod m. This is just
 * a Montgomery product with 1 as the other operand; used to convert
 * out of Montgomery form.
 */
static void fe_redc(u32 *r, const u32 *a, const u32 *m, u32 m0i)
{
	fe one;
	fe_zero(one);
	one[0] = 1;
	fe_mul_m(r, a, one, m, m0i);
}

/* ---------------------------------------------------------------------- */
/* Curve arithmetic (Jacobian coordinates, Montgomery form mod p)         */
/* ---------------------------------------------------------------------- */

/*
 * All field elements inside points are kept in Montgomery form.
 * The point at infinity is represented by z = 0 (x and y are then
 * irrelevant).
 */
typedef struct {
	fe x, y, z;
} jac;

/*
 * Thin wrappers for arithmetic mod p. These are real functions, not
 * macros: hard-coding the modulus here means every call site passes
 * only 2–3 pointers instead of 4–5 arguments, which noticeably
 * reduces code size in the point-arithmetic routines.
 */
static void Fsub(u32 *r, const u32 *a, const u32 *b) { fe_sub_m(r, a, b, P); }
static void Fmul(u32 *r, const u32 *a, const u32 *b) { fe_mul_m(r, a, b, P, P_M0I); }
static void Fsqr(u32 *r, const u32 *a)               { fe_mul_m(r, a, a, P, P_M0I); }

static void Fto_mont(u32 *r, const u32 *a)           { fe_mul_m(r, a, R2P, P, P_M0I); }

/*
 * Modular addition via negation: a + b = a - (p - b). This shares the
 * conditional-add-back logic of Fsub instead of needing a separate
 * conditional-subtract-on-carry-out path. If b == 0 the temp is p,
 * which Fsub handles correctly (a - p borrows, add p back, yields a).
 */
static void Fadd(u32 *r, const u32 *a, const u32 *b)
{
	fe t;
	fe_sub_raw(t, P, b);
	Fsub(r, a, t);
}

/* Copy a Jacobian point. */
static NOINLINE void pt_cpy(jac *d, const jac *s)
{
	fe_cpy(d->x, s->x);
	fe_cpy(d->y, s->y);
	fe_cpy(d->z, s->z);
}

/* Set a Jacobian point to the point at infinity. */
static NOINLINE void pt_set_inf(jac *r)
{
	fe_zero(r->x); fe_zero(r->y); fe_zero(r->z);
}

/*
 * Point doubling: R = 2*P. Formula exploits a = -3.
 * Input and output in Jacobian/Montgomery form.
 * Works for all inputs including the point at infinity (if P.z = 0
 * then R.z will also be 0).
 *
 * Ref: EFD "dbl-2007-bl" with a = -3 optimisation.
 *   delta = Z^2
 *   gamma = Y^2
 *   beta  = X * gamma
 *   alpha = 3*(X - delta)*(X + delta)
 *   X3 = alpha^2 - 8*beta
 *   Z3 = (Y + Z)^2 - gamma - delta
 *   Y3 = alpha*(4*beta - X3) - 8*gamma^2
 */
static void pt_dbl(jac *r, const jac *p)
{
	/* delta dies after Z3 is written; its slot is reused as t2. */
	fe gamma, beta, alpha, t1, t2;
#define delta t2

	Fsqr(delta, p->z);                    /* delta = Z^2 */
	Fsqr(gamma, p->y);                    /* gamma = Y^2 */
	Fmul(beta, p->x, gamma);              /* beta  = X*gamma */

	Fsub(t1, p->x, delta);                /* t1 = X - delta */
	Fadd(alpha, p->x, delta);             /* alpha holds X + delta temporarily */
	Fmul(alpha, t1, alpha);               /* alpha = (X-delta)(X+delta) */
	Fadd(t1, alpha, alpha);
	Fadd(alpha, t1, alpha);               /* alpha *= 3 */

	/* Z3 = (Y+Z)^2 - gamma - delta  — compute early, before
	 * gamma/delta are overwritten. */
	Fadd(t1, p->y, p->z);
	Fsqr(t1, t1);
	Fsub(t1, t1, gamma);
	Fsub(r->z, t1, delta);                /* delta dead */

	/* X3 = alpha^2 - 8*beta */
	Fadd(t1, beta, beta);                 /* t1 = 2*beta */
	Fadd(t1, t1, t1);                     /* t1 = 4*beta */
	Fadd(t2, t1, t1);                     /* t2 = 8*beta */
	Fsqr(r->x, alpha);
	Fsub(r->x, r->x, t2);

	/* Y3 = alpha*(4*beta - X3) - 8*gamma^2 */
	Fsub(t1, t1, r->x);                   /* t1 = 4*beta - X3 */
	Fmul(t1, alpha, t1);
	Fsqr(gamma, gamma);                   /* gamma^2 */
	Fadd(gamma, gamma, gamma);
	Fadd(gamma, gamma, gamma);
	Fadd(gamma, gamma, gamma);            /* 8*gamma^2 */
	Fsub(r->y, t1, gamma);

#undef delta
}

/*
 * Point addition: R = P + Q. Full Jacobian + Jacobian.
 * Handles all special cases: P or Q is infinity, P = Q, P = -Q.
 *
 * Ref: EFD "add-2007-bl".
 *   Z1Z1 = Z1^2
 *   Z2Z2 = Z2^2
 *   U1 = X1 * Z2Z2
 *   U2 = X2 * Z1Z1
 *   S1 = Y1 * Z2 * Z2Z2
 *   S2 = Y2 * Z1 * Z1Z1
 *   H  = U2 - U1
 *   Rr = S2 - S1
 *   if H == 0:
 *     if Rr == 0: double
 *     else: infinity
 *   I  = (2H)^2
 *   J  = H * I
 *   V  = U1 * I
 *   X3 = Rr^2 - J - 2V            (using Rr = 2*(S2-S1) variant? no,
 *                                   we use the simpler non-doubled R)
 *
 * We use the simpler variant without the internal *2 scaling:
 *   HH = H^2
 *   HHH = H * HH
 *   V  = U1 * HH
 *   X3 = Rr^2 - HHH - 2V
 *   Y3 = Rr*(V - X3) - S1*HHH
 *   Z3 = Z1*Z2*H
 */
static void pt_add(jac *r, const jac *p, const jac *q)
{
	/*
	 * Temporaries are aggressively reused to keep the stack frame
	 * small. The defines below give readable names without adding
	 * storage.
	 */
	fe u1, s1, t0, t1, t2, t3;
#define h    t0    /* = U2 - U1, later dead */
#define rr   t1    /* = S2 - S1 */
#define hh   t2    /* = H^2, later dead */
#define hhh  t3    /* = H^3 */
#define v    u1    /* = U1*HH (overwrites U1) */

	/* Handle infinity inputs. */
	if (fe_iszero(p->z)) { pt_cpy(r, q); return; }
	if (fe_iszero(q->z)) { pt_cpy(r, p); return; }

	Fsqr(t2, p->z);               /* t2 = Z1^2 */
	Fsqr(t3, q->z);               /* t3 = Z2^2 */
	Fmul(u1, p->x, t3);           /* U1 = X1*Z2^2 */
	Fmul(t0, q->x, t2);           /* t0 = U2 = X2*Z1^2 */
	Fmul(s1, p->y, q->z);
	Fmul(s1, s1, t3);             /* S1 = Y1*Z2^3 */
	Fmul(t1, q->y, p->z);
	Fmul(t1, t1, t2);             /* t1 = S2 = Y2*Z1^3 */

	Fsub(h,  t0, u1);             /* H  = U2 - U1 */
	Fsub(rr, t1, s1);             /* Rr = S2 - S1 */

	if (fe_iszero(h)) {
		if (fe_iszero(rr)) pt_dbl(r, p);
		else               pt_set_inf(r);
		return;
	}

	/* Z3 = Z1*Z2*H — compute before H is overwritten. */
	Fmul(t2, p->z, q->z);
	Fmul(r->z, t2, h);

	Fsqr(hh, h);
	Fmul(hhh, h, hh);             /* H dead after this */
	Fmul(v, u1, hh);              /* V = U1*HH; U1, HH dead */

	/* X3 = Rr^2 - HHH - 2V */
	Fsqr(r->x, rr);
	Fsub(r->x, r->x, hhh);
	Fadd(t0, v, v);
	Fsub(r->x, r->x, t0);

	/* Y3 = Rr*(V - X3) - S1*HHH */
	Fsub(t0, v, r->x);
	Fmul(t0, rr, t0);
	Fmul(s1, s1, hhh);
	Fsub(r->y, t0, s1);

#undef h
#undef rr
#undef hh
#undef hhh
#undef v
}

/*
 * Scalar multiplication: R = k * P.
 * Straightforward double-and-add, MSB-first. k is a normal 256-bit
 * integer (not Montgomery). P is in Jacobian/Montgomery form.
 *
 * If k == 0 or P is infinity, result is infinity.
 */
static void pt_mul(jac *r, const u32 *k, const jac *p)
{
	int i;
	pt_set_inf(r);
	for (i = 255; i >= 0; i--) {
		pt_dbl(r, r);
		if ((k[i >> 5] >> (i & 31)) & 1) {
			pt_add(r, r, p);
		}
	}
}

/* ---------------------------------------------------------------------- */
/* ECDSA verification                                                     */
/* ---------------------------------------------------------------------- */

/*
 * Decode 32 big-endian bytes into a little-endian 8-limb fe.
 */
static void fe_from_be(u32 *r, const unsigned char *src)
{
	int i;
	for (i = 0; i < 8; i++) {
		const unsigned char *p = src + 4 * (7 - i);
		r[i] = ((u32)p[0] << 24) | ((u32)p[1] << 16)
		     | ((u32)p[2] <<  8) | ((u32)p[3]      );
	}
}

int tv_ecdsa_p256_verify(const void *sig, size_t sig_len,
	const void *pub, size_t pub_len,
	const void *hv, size_t hv_len)
{
	const unsigned char *sp = (const unsigned char *)sig;
	const unsigned char *pp = (const unsigned char *)pub;
	const unsigned char *hp = (const unsigned char *)hv;
	/*
	 * Stack budget: many of these slots are reused across phases.
	 * The defines below give phase-specific names to shared storage.
	 */
	fe r, s, t0, t1, t2;
	jac Q, R1, R2;
#define qx  t0           /* decode: raw pubkey x, then dead */
#define qy  R2.x         /* decode: raw pubkey y, then dead */
#define e   s            /* hash scalar; overwrites s once s is in Mont */
#define w   t0           /* s^{-1} * R mod n; overwrites qx slot */
#define u1  t1           /* scalar for G */
#define u2  t2           /* scalar for Q */

	/* --- Length checks --- */
	if (sig_len != 64) return 0;
	if (pub_len != 65) return 0;
	if (hv_len < 32 || hv_len > 64) return 0;

	/* --- Decode and range-check r, s --- */
	fe_from_be(r, sp);
	fe_from_be(s, sp + 32);
	/* r, s must be in [1, n-1]. */
	if (fe_iszero(r) || fe_geq(r, N)) return 0;
	if (fe_iszero(s) || fe_geq(s, N)) return 0;

	/* --- Decode and validate public key --- */
	if (pp[0] != 0x04) return 0;
	fe_from_be(qx, pp + 1);
	fe_from_be(qy, pp + 33);
	/* Coordinates must be in [0, p-1]. */
	if (fe_geq(qx, P)) return 0;
	if (fe_geq(qy, P)) return 0;

	/*
	 * On-curve check: qy^2 == qx^3 - 3*qx + b  (mod p).
	 * We do this in Montgomery form. Q.x / Q.y get the Montgomery
	 * representation of the coordinates, which we keep for later.
	 */
	Fto_mont(Q.x, qx);
	Fto_mont(Q.y, qy);                    /* qx, qy dead after this */
	Fto_mont(t2, B);

	Fsqr(t0, Q.y);                        /* t0 = y^2 */
	Fsqr(t1, Q.x);
	Fmul(t1, t1, Q.x);                    /* t1 = x^3 */
	Fsub(t1, t1, Q.x);
	Fsub(t1, t1, Q.x);
	Fsub(t1, t1, Q.x);                    /* t1 = x^3 - 3x */
	Fadd(t1, t1, t2);                     /* t1 = x^3 - 3x + b */
	Fsub(t0, t0, t1);
	if (!fe_iszero(t0)) return 0;         /* not on curve */

	/* Q.z = 1 in Montgomery form (= R mod p). */
	fe_zero(t0); t0[0] = 1;
	Fto_mont(Q.z, t0);

	/*
	 * --- Compute u1, u2 mod n ---
	 * We compute w = s^{-1} in Montgomery form (w * R mod n), then
	 * exploit the Montgomery product identity: for normal-domain x,
	 *   mmul(x, w*R) = x * (w*R) * R^{-1} = x * w mod n
	 * giving u1, u2 directly in normal form.
	 *
	 * FIPS 186-5: e = leftmost 256 bits of H; NOT reduced mod n.
	 * However, our CIOS multiplier needs inputs < n, so we do one
	 * conditional subtraction (n > 2^255 ⇒ 2^256 < 2n ⇒ one sub is
	 * enough). This reduction preserves the mathematical result
	 * since u1 = e * w mod n anyway.
	 */
	fe_mul_m(w, s, R2N, N, N_M0I);        /* w = s * R mod n
	                                       * (s is dead; slot reused for e) */
	fe_inv_m(w, w, N, N_M0I);             /* w = s^{-1} * R mod n */

	fe_from_be(e, hp);                    /* e = leftmost 32 bytes of H */
	if (fe_geq(e, N)) fe_sub_raw(e, e, N);

	fe_mul_m(u1, e, w, N, N_M0I);         /* u1 = e * s^{-1} mod n */
	fe_mul_m(u2, r, w, N, N_M0I);         /* u2 = r * s^{-1} mod n */

	/*
	 * --- Compute R = u1*G + u2*Q ---
	 * We do u2*Q first, then overwrite Q with the generator (saving
	 * a whole Jacobian point of stack) for u1*G.
	 */
	pt_mul(&R2, u2, &Q);                  /* R2 = u2*Q; Q now dead */
	Fto_mont(Q.x, GX);
	Fto_mont(Q.y, GY);                    /* Q.z still holds 1-in-Mont */
	pt_mul(&R1, u1, &Q);                  /* R1 = u1*G */

	pt_add(&R1, &R1, &R2);

	/* If R is the point at infinity, reject. */
	if (fe_iszero(R1.z)) return 0;

	/*
	 * --- Extract affine x-coordinate and compare with r ---
	 * Affine X = Jacobian X / Z^2.
	 */
	fe_inv_m(t1, R1.z, P, P_M0I);         /* Z^{-1} (Mont) */
	Fsqr(t1, t1);                         /* Z^{-2} (Mont) */
	Fmul(t1, t1, R1.x);                   /* X * Z^{-2} (Mont) */
	fe_redc(t1, t1, P, P_M0I);            /* out of Montgomery */

#undef qx
#undef qy
#undef e
#undef w
#undef u1
#undef u2

	/*
	 * t1 is now the affine x-coordinate, in [0, p-1].
	 * FIPS 186-5: accept if (x mod n) == r.
	 * Since p - n is tiny (~2^128), t1 >= n is astronomically rare
	 * with honest signers, but we handle it correctly. A single
	 * conditional subtraction suffices (p < 2n).
	 */
	if (fe_geq(t1, N)) fe_sub_raw(t1, t1, N);

	/* Compare with r. */
	fe_sub_raw(t1, t1, r);
	return fe_iszero(t1);
}
