Implement ECDSA signature verification with curve P-256, with a specific goal of achieving a low code footprint (i.e. optimize for size, not for speed — a plausible context would be some code that fits in a boot ROM and verifies the signature on the firmware at boot time).

Language could be C or assembly or whatever compiles to a stand-alone binary chunk (i.e. if you import stuff like memcpy() then that counts against the total size). Signature is provided as 64 bytes (r and s, in unsigned big-endian encoding, in that order). Public key is 65 bytes (uncompressed format). The hashed message is provided as input, so no need to implement a hash function (obviously a boot ROM would need a hash function but we can abstract it away for this test).

From requestor:
"I don't think these specific rules and targets have already been published anywhere so this should avoid the issue of AI just regurgitating GCC source code when tasked with writing a compiler. Also I do have some point of comparison, which I have worked a bit on recently, so I am curious to know how small this AI can get the code."

Try to make the code as small as possible while being safe and correct. Ensure commmon cryptographic mistakes are avoided. Add a suite of test vectors based on publicly availble sources to verify correctness. Look for good unit tests for common cryptographic failures, perhaps using Wycheproof as motivation.

/*
 * Verify signature 'sig' (size 'sig_len' bytes) against public key
 * 'pub' (of size 'pub_len' bytes) over hash value 'hv' (of size
 * 'hv_len' bytes). The hash value MUST have been obtained from a
 * cryptographically secure hash function with an output of size at
 * least 32 bytes (usually, SHA-256 is used). The signature format is
 * "raw": the two components (r,s) of the signature are encoded as
 * unsigned integer in big-endian convention, over 32 bytes each, and
 * concatenated in that order. The public key uses the "uncompressed"
 * format, of size exactly 65 bytes (the first byte must have value 0x04).
 *
 * Returned value is 1 on success (signature is valid) or 0 on
 * error. An error is reported in any of these cases:
 *  - signature size is not correct;
 *  - public key size is not correct;
 *  - hash value size is less than 32 bytes or is greater than 64 bytes;
 *  - signature does not have a valid format (i.e. either r or s is zero
 *    or is not lower, as an integer, than the curve order).
 *  - public key does not have a valid format (one of the coordinates
 *    is out of its nominal ranges, or the point is not on the curve);
 *  - signature verification algorithm fails.
 *
 * Exact rules follow FIPS 186-5, section 6.4.2, with the hash value 'hv'
 * being 'H = Hash(M)' as computed in step 2. This implementation adds an
 * explicit check that the provided hash value length does not exceed
 * 64 bytes, because that would indicate that the caller is not provding
 * a hash value but the message itself, which is insecure (the use of a
 * cryptographic hash function is necessary for the overall security).
 * In any case, the verification algorithm starts by truncated the hash
 * value to the curve size, which is 32 bytes for curve P-256, and the
 * extra bytes are simply ignored. Hash values _shorter_ than 32 bytes
 * are also rejected because they mechanically cannot provide the "128-bit"
 * security level that is usually expected from the curve (and FIPS 186-5,
 * section 6.1.1, makes such rejection mandatory).
 */
int tv_ecdsa_p256_verify(const void *sig, size_t sig_len,
        const void *pub, size_t pub_len,
        const void *hv, size_t hv_len);
