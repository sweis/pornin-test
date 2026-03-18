# common/track.mk — shared targets for limbN/ tracks.
#
# Each track's Makefile sets COMMON (usually ../common) and includes this.
# Assumes tv_ecdsa.S → tv_ecdsa.o → link with common test harnesses.
# Per-track extras (test-mul, regen, check) stay in the track's own Makefile.

CC       ?= gcc
CFLAGS   ?= -O2 -g -Wall
SANFLAGS ?= -fsanitize=address,undefined
TRACK    ?= $(notdir $(CURDIR))
TMP      := /tmp/$(TRACK)

.PHONY: test test-full size bench bench20 clean

test: test-full

test-full: tv_ecdsa.o
	$(CC) $(CFLAGS) $(SANFLAGS) -I$(COMMON) -o $(TMP)_test_ecdsa \
		tv_ecdsa.o $(COMMON)/test_ecdsa_asm.c
	$(TMP)_test_ecdsa
	$(CC) $(CFLAGS) $(SANFLAGS) -I$(COMMON) -o $(TMP)_test_wp \
		tv_ecdsa.o $(COMMON)/test_wycheproof_asm.c
	$(TMP)_test_wp

tv_ecdsa.o: tv_ecdsa.S
	$(CC) -c tv_ecdsa.S -o $@

size: tv_ecdsa.o
	@size tv_ecdsa.o | tail -1

bench: tv_ecdsa.o
	$(CC) -O2 -o $(TMP)_bench tv_ecdsa.o $(COMMON)/bench.c
	$(TMP)_bench

bench20: tv_ecdsa.o
	$(CC) -O2 -o $(TMP)_bench tv_ecdsa.o $(COMMON)/bench.c
	@for i in $$(seq 1 20); do $(TMP)_bench; done | sort -n | sed -n '10,11p'

clean::
	rm -f *.o $(TMP)_*
