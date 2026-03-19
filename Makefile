# Top-level: dispatch to per-track Makefiles. Each track is self-contained.
#
#   limb8/   — 8×32 q=t[top] (tiny.S). 933 B size floor. Only non-Montgomery.
#   limb11/  — 11×24 Montgomery. 1194 B. Trick catalogue.
#   limb5x54/— 5×54 Montgomery. 1141 B current. Thomas's arch.
#   limb5x56/— 5×56 Montgomery. Byte-aligned decode, cleaner signed cP.
#   speed/   — fast/fast2/speed.S. Cycles, not bytes. BMI2+ADX, MOVBE.
#   signer/  — AVX-512 ZMM signer. Separate concern.
#   common/  — shared: test harnesses, bench, range_proof, gen_bytecode.
#   archive/ — superseded (C refs, old asm, Rust port).

TRACKS = limb8 limb11 limb5x54 limb5x56

.PHONY: all test size bench clean chart $(TRACKS) speed signer

all: test size

test: $(TRACKS:%=test-%)
size: $(TRACKS:%=size-%)
bench: $(TRACKS:%=bench-%)

test-%:
	@echo "=== $* ==="
	@$(MAKE) -C $* test

size-%:
	@printf "%-8s " $*; $(MAKE) --no-print-directory -C $* size

bench-%:
	@$(MAKE) --no-print-directory -C $* bench20

$(TRACKS) speed signer:
	@$(MAKE) -C $@

chart:
	python3 docs/plot_history.py

clean:
	@for d in $(TRACKS) speed signer; do $(MAKE) -C $$d clean; done
