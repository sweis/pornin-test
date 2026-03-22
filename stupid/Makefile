# stupid/ — Thomas's bytecode-VM track. MUL is itself a bytecode subroutine
# (double-and-add, 256 iterations per multiply). Native primitives reduce to
# 32-byte add/sub/copy + bit-test. ~50× slower than limb8 but ~124 B smaller.
#
# Baseline: 766 B / ~275M cyc (Thomas Stupid, as received).
COMMON = ../common
include $(COMMON)/track.mk

.PHONY: all
all: test size
