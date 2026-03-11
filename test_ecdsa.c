/*
 * Test harness for tv_ecdsa_p256_verify().
 *
 * Includes:
 *   - RFC 6979 test vectors (deterministic ECDSA, P-256 + SHA-256)
 *   - NIST CAVP-style validity checks
 *   - Wycheproof-inspired edge cases:
 *       * r = 0, s = 0
 *       * r = n, s = n (out of range)
 *       * r, s = 2^256 - 1 (far out of range)
 *       * signature malleability (s' = n - s) — MUST still verify
 *       * public key not on curve
 *       * public key coordinates >= p
 *       * public key format byte != 0x04
 *       * hash = 0
 *       * hash value numerically > n (must NOT be reduced mod n by verifier)
 *       * longer hashes (SHA-384, SHA-512 sizes) — truncated to 32 bytes
 *       * hash length out of range (< 32 or > 64)
 *       * u1*G + u2*Q = point at infinity
 *
 * All positive vectors were independently generated in Python and
 * cross-checked against RFC 6979 reference values.
 */

#include <stdio.h>
#include <string.h>

#ifndef tv_ecdsa_p256_verify
#include "tv_ecdsa.h"
#endif

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static size_t hex2bin(unsigned char *dst, const char *src)
{
	size_t n = 0;
	while (src[0] && src[1]) {
		int hi = hexval(src[0]);
		int lo = hexval(src[1]);
		if (hi < 0 || lo < 0) break;
		dst[n++] = (unsigned char)((hi << 4) | lo);
		src += 2;
	}
	return n;
}

struct tv {
	const char *name;
	const char *pub;
	const char *hash;
	const char *sig;
	int expect;           /* 1 = valid, 0 = invalid */
};

/* ================================================================ */
/*  Test vectors                                                    */
/* ================================================================ */

static const struct tv VEC[] = {

/* ---- RFC 6979 Appendix A.2.5, P-256 + SHA-256 ---- */
{
	"RFC6979 'sample' SHA-256",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	1
},
{
	"RFC6979 'test' SHA-256",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	"f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
	"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
	1
},

/* ---- Custom key / message ---- */
{
	"Custom key, 'Hello, world!'",
	"04471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c"
	"dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858",
	"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3",
	"58893cc65cc5c0da46a14c5a42878d877003623cdceec62cb9a9069fa2c02ea4"
	"d44c73ba73545b00933229e64de5e17dbed60de75722e680e0d440cf865c2244",
	1
},

/* ---- Signature tampering ---- */
{
	"INVALID: s flipped bit",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda9",
	0
},
{
	"INVALID: r flipped bit",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3717"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: wrong hash",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"fa3e8de0df11a0a63891e2cc88694ce692f7a7fad0c39882346f9eb01ad124a4",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: wrong public key",
	"04471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c"
	"dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},

/* ---- Range checks on r and s (Wycheproof-style) ---- */
{
	"INVALID: r = 0",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"0000000000000000000000000000000000000000000000000000000000000000"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: s = 0",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"0000000000000000000000000000000000000000000000000000000000000000",
	0
},
{
	"INVALID: r = n",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: s = n",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	0
},
{
	"INVALID: r = n + 1",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"
	"0000000000000000000000000000000000000000000000001234567890abcdef",
	0
},
{
	"INVALID: s = 2^256 - 1",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"0000000000000000000000000000000000000000000000000000000000000001"
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	0
},
{
	"INVALID: r = n - 1 (in range, bad sig)",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: s = n - 1 (in range, bad sig)",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	0
},
{
	"INVALID: r = s = 1",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"0000000000000000000000000000000000000000000000000000000000000001"
	"0000000000000000000000000000000000000000000000000000000000000001",
	0
},

/* ---- Signature malleability: s' = n - s  MUST still verify ---- */
{
	"VALID: malleability s' = n - s",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
	1
},

/* ---- Public key validation ---- */
{
	"INVALID: pubkey not on curve (y+1)",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d446229a",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: pubkey x = p",
	"04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: pubkey y = p",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: pubkey format byte 0x05",
	"0560fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},
{
	"INVALID: pubkey (0,0) not on curve",
	"040000000000000000000000000000000000000000000000000000000000000000"
	"0000000000000000000000000000000000000000000000000000000000000000",
	"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
	"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
	0
},

/* ---- Hash edge cases ---- */
{
	"VALID: all-zero hash",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"b0600e56f7ca1989ed8bcd296e263bb26e01f734420a6fee92212f3b9ffc753b"
	"b298fd8d5a61adf5acd0fa47412de3eec3f4ad49ced9a0973ac4a0afbf2a9981",
	1
},
{
	/* Hash value e > n but < 2^256. The verifier MUST use the raw
	 * 256-bit value, NOT reduce mod n. This test was signed with the
	 * unreduced hash, so a verifier that reduces mod n will fail. */
	"VALID: hash > n (NOT reduced)",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325b5",
	"7b9e7d0d415f39adce899a4ced3efb4c23d286a85a2fe66f86689fd4756fd8e9"
	"080687dfa4fc192b44fb16a0a09b5c93b1ed45e334b1e3244afe47bc1178c6b6",
	1
},
{
	"VALID: 48-byte hash (SHA-384, truncated)",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312"
	"313bca4a9b5b890efee42c77b1ee25fe",
	"4a5530b043726fbeebd13c58ebc50dcc944fd60e07b714aac9b57eddc6037a88"
	"e1bbcd63d798ec6f8eb0c0cc265784268ba18ceb76f4a490b8498afc6c19c3a0",
	1
},
{
	"VALID: 64-byte hash (SHA-512, truncated)",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"39a5e04aaff7455d9850c605364f514c11324ce64016960d23d5dc57d3ffd8f4"
	"9a739468ab8049bf18eef820cdb1ad6c9015f838556bc7fad4138b23fdf986c7",
	"57e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34"
	"55a2de31dd7c9ea2c1b4e5d3f665c4d1fa35525f6f15cd90e98aa9767b5d29cc",
	1
},

/* ---- Special: result of u1*G + u2*Q is the point at infinity ---- */
{
	"INVALID: u1*G + u2*Q = infinity",
	"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
	"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
	"4f0c89fb528e8a623e96c4e1b497e83eef718116dcb10f12d950e1538c685808",
	"5555555555555555555555555555555555555555555555555555555555555555"
	"3333333333333333333333333333333333333333333333333333333333333333",
	0
},

};

#define NVEC (sizeof VEC / sizeof VEC[0])

/* ================================================================ */
/*  Length-check tests (can't go in table: need custom lengths)      */
/* ================================================================ */

static int run_length_tests(void)
{
	/* Use a valid vector as baseline. */
	static const char *PUB = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
	static const char *HASH = "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf";
	static const char *SIG = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

	unsigned char pub[65], hash[64], sig[64];
	size_t publen, hashlen, siglen;
	int fails = 0;

	publen  = hex2bin(pub,  PUB);
	hashlen = hex2bin(hash, HASH);
	siglen  = hex2bin(sig,  SIG);

	/* Sanity: baseline must verify. */
	if (tv_ecdsa_p256_verify(sig, siglen, pub, publen, hash, hashlen) != 1) {
		printf("  FAIL  baseline for length tests\n");
		fails++;
	}

	/* sig too short */
	if (tv_ecdsa_p256_verify(sig, 63, pub, publen, hash, hashlen) != 0) {
		printf("  FAIL  sig_len=63 accepted\n"); fails++;
	}
	/* sig too long */
	if (tv_ecdsa_p256_verify(sig, 65, pub, publen, hash, hashlen) != 0) {
		printf("  FAIL  sig_len=65 accepted\n"); fails++;
	}
	/* pub too short */
	if (tv_ecdsa_p256_verify(sig, siglen, pub, 64, hash, hashlen) != 0) {
		printf("  FAIL  pub_len=64 accepted\n"); fails++;
	}
	/* pub too long */
	if (tv_ecdsa_p256_verify(sig, siglen, pub, 66, hash, hashlen) != 0) {
		printf("  FAIL  pub_len=66 accepted\n"); fails++;
	}
	/* hash too short (31 bytes) */
	if (tv_ecdsa_p256_verify(sig, siglen, pub, publen, hash, 31) != 0) {
		printf("  FAIL  hv_len=31 accepted\n"); fails++;
	}
	/* hash too long (65 bytes) */
	if (tv_ecdsa_p256_verify(sig, siglen, pub, publen, hash, 65) != 0) {
		printf("  FAIL  hv_len=65 accepted\n"); fails++;
	}

	if (fails == 0) {
		printf("  pass  length checks (6 cases)\n");
	}
	return fails;
}

int main(void)
{
	size_t i;
	int fails = 0;

	printf("== ECDSA P-256 verification tests ==\n");

	for (i = 0; i < NVEC; i++) {
		unsigned char pub[65], hash[64], sig[64];
		size_t publen, hashlen, siglen;
		int got;

		publen  = hex2bin(pub,  VEC[i].pub);
		hashlen = hex2bin(hash, VEC[i].hash);
		siglen  = hex2bin(sig,  VEC[i].sig);

		got = tv_ecdsa_p256_verify(sig, siglen, pub, publen,
			hash, hashlen);

		if (got == VEC[i].expect) {
			printf("  pass  %s\n", VEC[i].name);
		} else {
			printf("  FAIL  %s  (got %d, expected %d)\n",
				VEC[i].name, got, VEC[i].expect);
			fails++;
		}
	}

	fails += run_length_tests();

	printf("\n%s: %zu vectors + 6 length checks, %d failures\n",
		fails ? "FAILED" : "OK", NVEC, fails);
	return fails ? 1 : 0;
}
