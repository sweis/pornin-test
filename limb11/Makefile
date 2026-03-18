# limb11/ — 11×24 signed-limb Montgomery track.
# Thomas at 928/4.48M with 5×54. Target: < 928.
#
# Workflow: make test → make size → commit → update progress.csv

CC      = gcc
CFLAGS  = -O2 -g -Wall
SANFLAGS = -fsanitize=address,undefined
PARENT  = ..

.PHONY: all test test-mul size bench clean regen check

all: test size

# ── Unit tests (work before 607/607) ──
test-mul: test_mul.c fe_mul.S vectors_mul.h
	$(CC) $(CFLAGS) $(SANFLAGS) test_mul.c fe_mul.S -o /tmp/limb11_test_mul
	/tmp/limb11_test_mul

# ── Full test suite (the 607/607 gate) ──
# Reuses the parent project's test harnesses. Once tv_ecdsa.S is
# working, these targets wire it into the existing test_ecdsa_asm.c
# and test_wycheproof_asm.c.
test: test-mul test-full

test-full: tv_ecdsa.o
	$(CC) $(CFLAGS) $(SANFLAGS) -o /tmp/limb11_test_ecdsa \
		tv_ecdsa.o $(PARENT)/test_ecdsa_asm.c
	/tmp/limb11_test_ecdsa
	$(CC) $(CFLAGS) $(SANFLAGS) -o /tmp/limb11_test_wp \
		tv_ecdsa.o $(PARENT)/test_wycheproof_asm.c
	/tmp/limb11_test_wp

tv_ecdsa.o: tv_ecdsa.S bytecode.inc
	$(CC) -c tv_ecdsa.S -o $@

# ── Size (the number that matters) ──
size: tv_ecdsa.o
	@size tv_ecdsa.o | tail -1

size-mul:
	@$(CC) -c fe_mul.S -o /tmp/limb11_fe_mul.o
	@echo "fe_mul11:" && size /tmp/limb11_fe_mul.o | tail -1
	@echo "vs current tiny.S fe_mul_m: 143 B"

# ── Bench (only after 607/607) ──
bench: tv_ecdsa.o
	$(CC) -O2 -o /tmp/limb11_bench tv_ecdsa.o $(PARENT)/bench.c
	/tmp/limb11_bench

bench20: tv_ecdsa.o
	$(CC) -O2 -o /tmp/limb11_bench tv_ecdsa.o $(PARENT)/bench.c
	@for i in $$(seq 1 20); do /tmp/limb11_bench; done | sort -n | sed -n '10,11p'

# ── Regenerate derived files ──
regen: bytecode.inc vectors_mul.h

bytecode.inc: gen_bytecode.py
	python3 gen_bytecode.py > $@ 2>/tmp/limb11_bc_check.txt
	@cat /tmp/limb11_bc_check.txt

vectors_mul.h: range_proof.py
	@echo "Run the vector-gen snippet in range_proof.py context if vectors need regenerating."

# ── Range proof (re-verify the convergence + correctness) ──
check:
	python3 range_proof.py

clean:
	rm -f *.o /tmp/limb11_*
