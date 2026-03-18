# speed/ — cycles, not bytes. BMI2+ADX (fast, fast2) and MOVBE-only (speed).
COMMON = ../common
CC     = gcc
CFLAGS = -O2 -g -Wall
TMP    = /tmp/speed

.PHONY: all test size bench clean

IMPLS = fast fast2 speed

all: test size

test: $(IMPLS:%=test-%)
size: $(IMPLS:%=size-%)
bench: $(IMPLS:%=bench-%)

test-%: tv_ecdsa_%.o
	$(CC) $(CFLAGS) -I$(COMMON) -o $(TMP)_$*_test $< $(COMMON)/test_ecdsa_asm.c
	$(TMP)_$*_test
	$(CC) $(CFLAGS) -I$(COMMON) -o $(TMP)_$*_wp $< $(COMMON)/test_wycheproof_asm.c
	$(TMP)_$*_wp

size-%: tv_ecdsa_%.o
	@printf "%-8s " $*; size $< | tail -1

bench-%: tv_ecdsa_%.o
	$(CC) -O2 -o $(TMP)_$*_bench $< $(COMMON)/bench.c
	@printf "%-8s " $*; $(TMP)_$*_bench

tv_ecdsa_%.o: tv_ecdsa_%.S
	$(CC) -c $< -o $@

clean:
	rm -f *.o $(TMP)_*
