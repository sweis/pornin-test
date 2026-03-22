# stupid/ — Thomas's bytecode-VM track. MUL is itself a bytecode subroutine
# (double-and-add, 256 iterations per multiply). Native primitives reduce to
# 32-byte add/sub/copy + bit-test.
#
# Two builds:
#   default:     size floor (640 B / ~2G cyc) — `loop` + SMC patch in z256
#   -DFAST_Z256: +2 B — dec;jnz (minor; SMC stalls dominate either way)
#
# SELF-MODIFYING CODE: z256_addsub patches its own adc/sbb byte per call.
# Code lives in .selfmod (awx) section. Boot-ROM target has no W^X, but
# modern CPUs pipeline-flush on SMC → ~8.5× slower than pre-SMC 660 B build
# (commit 2b83a10, ~237M cyc). The 660 B point stays on the Pareto frontier.
COMMON = ../common
include $(COMMON)/track.mk

.PHONY: all size-all
all: test size-all

size-all: tv_ecdsa.S
	@echo "=== default (size floor, SMC) ==="
	@$(CC) -c tv_ecdsa.S -o $(TMP)_def.o && size $(TMP)_def.o | tail -1
	@echo "=== -DFAST_Z256 (dec;jnz in z256) ==="
	@$(CC) -c -DFAST_Z256 tv_ecdsa.S -o $(TMP)_fz.o && size $(TMP)_fz.o | tail -1
	@echo "=== -DNO_SMC (two z256 funcs, ~8× faster) ==="
	@$(CC) -c -DNO_SMC tv_ecdsa.S -o $(TMP)_ns.o && size $(TMP)_ns.o | tail -1
	@echo "=== -DNO_SMC -DFAST_Z256 ==="
	@$(CC) -c -DNO_SMC -DFAST_Z256 tv_ecdsa.S -o $(TMP)_nsf.o && size $(TMP)_nsf.o | tail -1
