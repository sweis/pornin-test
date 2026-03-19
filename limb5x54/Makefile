# limb5/ — 5×54 signed-limb Montgomery track.
COMMON = ../common
include $(COMMON)/track.mk

tv_ecdsa.o: bytecode.inc

.PHONY: test-mul regen check all

all: test size

test-mul: test_mul.c fe_mul.S vectors_mul.h
	$(CC) $(CFLAGS) $(SANFLAGS) test_mul.c fe_mul.S -o $(TMP)_test_mul
	$(TMP)_test_mul

test: test-mul

regen: bytecode.inc

bytecode.inc: gen_bytecode.py
	python3 gen_bytecode.py > $@ 2>$(TMP)_bc_check.txt
	@cat $(TMP)_bc_check.txt

check:
	python3 -c "import sys; sys.path.insert(0,'$(COMMON)'); \
		from range_proof import Cfg, rcb_fixpoint; \
		cfg = Cfg(K=5, W=54, acc_bits=128); \
		wl, wa, out, trace, ok = rcb_fixpoint(cfg); \
		print(f'5×54: converges={ok}, max_acc={wa}b, max_limb_in={wl}b')"
