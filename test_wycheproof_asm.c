/*
 * Wycheproof test driver for the assembly verifiers.
 * Same shim as test_ecdsa_asm.c: redefine the function-under-test
 * and #include the real test source.
 */

#include <stddef.h>

extern int tv_ecdsa_p256_verify_asm(const void *sig, size_t sig_len,
        const void *pub, size_t pub_len,
        const void *hv, size_t hv_len);

#define tv_ecdsa_p256_verify tv_ecdsa_p256_verify_asm
#include "test_wycheproof.c"
