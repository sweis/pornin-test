/*
 * Test harness for the pure-assembly tv_ecdsa_p256_verify_asm().
 * Reuses the same test vectors as test_ecdsa.c by redefining the
 * function-under-test via a preprocessor macro.
 */

#include <stddef.h>

/* Implemented in tv_ecdsa_amd64.S */
extern int tv_ecdsa_p256_verify_asm(const void *sig, size_t sig_len,
        const void *pub, size_t pub_len,
        const void *hv, size_t hv_len);

/* Make the test file call the assembly function instead. */
#define tv_ecdsa_p256_verify tv_ecdsa_p256_verify_asm
#include "test_ecdsa.c"
