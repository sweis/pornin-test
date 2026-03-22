# Top-level: dispatch to per-track Makefiles. Each track is self-contained.
#
#   limb8/     — 8×32 q=t[top]. 890 B floor. Only non-Montgomery track.
#   limb11x24/ — 11×24 Montgomery. 1068 B. Trick-catalogue source.
#   limb5x54/  — 5×54 Montgomery. 1097 B. Thomas's architecture.
#   limb5x56/  — 5×56 Montgomery. 1084 B. Byte-aligned decode.
#   speed/   — fast/fast2/speed.S. Cycles, not bytes. BMI2+ADX, MOVBE.
#   signer/  — AVX-512 ZMM signer. Separate concern.
#   common/  — shared: test harnesses, bench, range_proof, gen_bytecode.
#   archive/ — superseded (C refs, old asm, Rust port).

TRACKS = limb8 limb11x24 limb5x54 limb5x56 stupid

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

docs/progress.csv: $(TRACKS:%=%/progress.csv)
	@python3 -c "import csv; \
rows = [(t,)+tuple(r[:4]) for t in '$(TRACKS)'.split() \
        for r in csv.reader(open(f'{t}/progress.csv')) \
        if r and not r[0].startswith('#') and r[0]!='commit']; \
w = csv.writer(open('$@','w')); \
w.writerow(['track','commit','bytes','cycles','note']); \
[w.writerow(r) for r in rows]; \
print(f'docs/progress.csv: {len(rows)} rows')"

chart: docs/progress.csv
	python3 tools/plot_history.py

clean:
	@for d in $(TRACKS) speed signer; do $(MAKE) -C $$d clean; done
