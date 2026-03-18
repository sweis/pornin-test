# limb5/ — 5×54 signed-limb Montgomery track.
# Thomas at 928 B with this architecture. Target: match or beat.
#
# Workflow: make test → make size → commit → update progress.csv

CC      = gcc
CFLAGS  = -O2 -g -Wall
SANFLAGS = -fsanitize=address,undefined
PARENT  = ..

.PHONY: all test test-mul size bench bench20 clean regen check

all: test size

# ── Unit tests (work before 607/607) ──
test-mul: test_mul.c fe_mul.S vectors_mul.h
	$(CC) $(CFLAGS) $(SANFLAGS) test_mul.c fe_mul.S -o /tmp/limb5_test_mul
	/tmp/limb5_test_mul

# ── Full test suite (the 607/607 gate) ──
test: test-mul test-full

test-full: tv_ecdsa.o
	$(CC) $(CFLAGS) $(SANFLAGS) -o /tmp/limb5_test_ecdsa \
		tv_ecdsa.o $(PARENT)/test_ecdsa_asm.c
	/tmp/limb5_test_ecdsa
	$(CC) $(CFLAGS) $(SANFLAGS) -o /tmp/limb5_test_wp \
		tv_ecdsa.o $(PARENT)/test_wycheproof_asm.c
	/tmp/limb5_test_wp

tv_ecdsa.o: tv_ecdsa.S bytecode.inc
	$(CC) -c tv_ecdsa.S -o $@

# ── Size (the number that matters) ──
size: tv_ecdsa.o
	@size tv_ecdsa.o | tail -1

size-mul:
	@$(CC) -c fe_mul.S -o /tmp/limb5_fe_mul.o
	@echo "fe_mul5:" && size /tmp/limb5_fe_mul.o | tail -1

# ── Bench ──
bench: tv_ecdsa.o
	$(CC) -O2 -o /tmp/limb5_bench tv_ecdsa.o $(PARENT)/bench.c
	/tmp/limb5_bench

bench20: tv_ecdsa.o
	$(CC) -O2 -o /tmp/limb5_bench tv_ecdsa.o $(PARENT)/bench.c
	@for i in $$(seq 1 20); do /tmp/limb5_bench; done | sort -n | sed -n '10,11p'

# ── Regenerate derived files ──
regen: bytecode.inc

bytecode.inc: ../common/gen_bytecode.py
	python3 ../common/gen_bytecode.py > $@ 2>/tmp/limb5_bc_check.txt
	@cat /tmp/limb5_bc_check.txt

# ── Range proof ──
check:
	python3 -c "import sys; sys.path.insert(0,'../common'); \
		from range_proof import Cfg, rcb_fixpoint; \
		cfg = Cfg(K=5, W=54, acc_bits=128); \
		wl, wa, out, trace, ok = rcb_fixpoint(cfg); \
		print(f'5×54: converges={ok}, max_acc={wa}b, max_limb_in={wl}b')"

clean:
	rm -f *.o /tmp/limb5_*
