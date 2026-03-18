/* 11×24 Montgomery constants — generated. */
/* R = 2^264 mod p. Store Gx·R, Gy·R so they're already */
/* in Montgomery form; b derives as b_mont automatically. */

#define CGX_MONT_Q0 0x905f76bd3755c661ULL
#define CGX_MONT_Q1 0xfb732b7762251075ULL
#define CGX_MONT_Q2 0xba95fc47edb60179ULL
#define CGX_MONT_Q3 0xe730d418a9143c18ULL

#define CGY_MONT_Q0 0x71ff18aa885d854dULL
#define CGY_MONT_Q1 0xe88688dd21f3258bULL
#define CGY_MONT_Q2 0x4ab8e43519e45cddULL
#define CGY_MONT_Q3 0xf25357ce95560a85ULL

#define CN_Q0 0xffffffff00000000ULL
#define CN_Q1 0xffffffffffffffffULL
#define CN_Q2 0xbce6faada7179e84ULL
#define CN_Q3 0xf3b9cac2fc632551ULL

#define CR2_Q0 0x0004fffffffdffffULL
#define CR2_Q1 0xfffffffffffeffffULL
#define CR2_Q2 0xfffbffffffff0000ULL
#define CR2_Q3 0x0000000000030000ULL

/* R² mod n — for s → Montgomery-n (the ONLY mod-n conversion needed;
 * e and r stay plain because MontMul(plain, mont) = plain). */
#define CR2N_Q0 0x2d955aba561fc164ULL
#define CR2N_Q1 0xb2392b6bec596190ULL
#define CR2N_Q2 0x6ab8c68a2abb372eULL
#define CR2N_Q3 0x0f80d88a9a9fedcfULL

#define N_M0INV 0xbc4f  /* fits imm16 but imul needs imm32 encoding */

/* ── If switching to LE-stored constants (bt-on-cN fix option 1): ──
 * recompute ALL of the above with LE byte order. The values are the
 * same integers; only the .quad byte layout changes. fe_from_be
 * becomes fe_from_le (reads from low byte up, no bswap needed).
 * See HANDOFF.md "bt-on-cN — three options ranked". */
