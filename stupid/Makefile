# stupid/ — Thomas's bytecode-VM track. MUL is itself a bytecode subroutine
# (double-and-add, 256 iterations per multiply). Native primitives reduce to
# 32-byte add/sub/copy + bit-test.
#
# Two builds:
#   default:     size floor (~672 B / ~240M cyc) — `loop` in z256_add/sub
#   -DFAST_Z256: +4 B, −40% cycles  (~676 B / ~148M cyc) — dec;jnz
COMMON = ../common
include $(COMMON)/track.mk

.PHONY: all size-all
all: test size-all

size-all: tv_ecdsa.S
	@echo "=== default (size floor, loop) ==="
	@$(CC) -c tv_ecdsa.S -o $(TMP)_def.o && size $(TMP)_def.o | tail -1
	@echo "=== -DFAST_Z256 (dec;jnz, −40% cyc) ==="
	@$(CC) -c -DFAST_Z256 tv_ecdsa.S -o $(TMP)_fz.o && size $(TMP)_fz.o | tail -1
