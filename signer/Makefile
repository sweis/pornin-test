# signer/ — AVX-512 all-ZMM ECDSA signer (separate from verify tracks).
# See tv_ecdsa_sign_zmm.S header for design doc.
CC     = gcc
CFLAGS = -O2 -g -Wall -mavx512f -mavx512dq

.PHONY: test clean

test: sign_zmm
	./sign_zmm

sign_zmm: sign_zmm.c tv_ecdsa_sign_zmm.S sign_vectors.h
	$(CC) $(CFLAGS) -o $@ sign_zmm.c tv_ecdsa_sign_zmm.S

clean:
	rm -f sign_zmm *.o
