# limb8/ — 8×32 q=t[top] track (tiny.S). Only W where both p AND n
# have all-ones top limb → no Montgomery needed. Three builds:
#   default:      947 B / ~3.6M cyc  — 64-bit schoolbook
#   -DSMALL_MUL8: 933 B / ~4.7M cyc  — 32-bit loop+scasd (size floor)
#   -DSOLINAS_P: 1005 B / ~3.0M cyc  — P-256 fold, no multiplies
COMMON = ../common
include $(COMMON)/track.mk

.PHONY: all size-all

all: test size-all

# All three variants, side by side.
size-all: tv_ecdsa.S
	@echo "=== default (64-bit schoolbook) ==="
	@$(CC) -c tv_ecdsa.S -o $(TMP)_def.o && size $(TMP)_def.o | tail -1
	@echo "=== -DSMALL_MUL8 (size floor, ~2× cycles) ==="
	@$(CC) -c -DSMALL_MUL8 tv_ecdsa.S -o $(TMP)_sm.o && size $(TMP)_sm.o | tail -1
	@echo "=== -DSOLINAS_P (Solinas fold) ==="
	@$(CC) -c -DSOLINAS_P tv_ecdsa.S -o $(TMP)_sol.o && size $(TMP)_sol.o | tail -1
