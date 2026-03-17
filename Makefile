# Build for ECDSA/P-256 verification (size-optimised).
#
# Per-implementation targets (each has size-X / test-X / wp-X where
# applicable):
#   -tiny   tv_ecdsa_tiny.S   ????B   BMI2+MOVBE  (size-only, speed traded)
#   -fast   tv_ecdsa_fast.S   1397 B  BMI2+MOVBE  (best speed+size)
#   -bc     tv_ecdsa_bc.S     1712 B  portable x86-64
#   -asm    tv_ecdsa_amd64.S  2875 B  conventional hand-asm
#   (none)  tv_ecdsa.c        3076 B  portable C, 32-bit limbs
#   -small  tv_ecdsa_small.c  ~3027 B ARM-tuned C (4-arg calls)
#   -thumb  tv_ecdsa.c        2082 B  Cortex-M4 (needs arm-none-eabi-gcc)
#
# Other:
#   make bench   - cycle-count fast.S vs bc.S
#   make wp-all  - run Wycheproof suite on all four x86-64 impls
#   make clean   - remove build artifacts

CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -Wshadow -Wconversion -O2

# Size-optimised flags for the crypto core only.
# -ffunction-sections + -fdata-sections lets a linker discard unused
# symbols from a real firmware build; we report only the .text+.rodata
# of tv_ecdsa.o as the relevant footprint.
# -ffreestanding: this is bare-metal code with no libc; prevents the
# compiler from emitting calls to memset/memmove/memcpy for struct or
# array assignments. -fno-tree-loop-distribute-patterns: extra insurance
# against the limb-shift loop in fe_mul_m being turned into memmove().
SIZE_CFLAGS = -std=c99 -Os -ffreestanding -fno-strict-aliasing \
              -ffunction-sections -fdata-sections \
              -fno-asynchronous-unwind-tables -fno-ident \
              -fno-stack-protector -fno-tree-loop-distribute-patterns

.PHONY: all test test-asm test-small size size-asm size-small clean \
        wp wp-fast wp-bc wp-asm wp-all

all: test_ecdsa test_ecdsa_asm

test_ecdsa: tv_ecdsa.c test_ecdsa.c tv_ecdsa.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa.c test_ecdsa.c

# Pure-assembly variant (x86-64 only).
test_ecdsa_asm: tv_ecdsa_amd64.S test_ecdsa_asm.c test_ecdsa.c
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_amd64.S test_ecdsa_asm.c

test: test_ecdsa
	./test_ecdsa

test-asm: test_ecdsa_asm
	./test_ecdsa_asm

# Build just the crypto core with size flags and show section sizes.
# This is the number that matters for ROM budgeting.
tv_ecdsa_size.o: tv_ecdsa.c tv_ecdsa.h
	$(CC) $(SIZE_CFLAGS) -c -o $@ tv_ecdsa.c

size: tv_ecdsa_size.o
	@echo "=== size (-Os) of tv_ecdsa.c ==="
	@size $<
	@echo ""
	@echo "=== detailed section sizes ==="
	@size -A $< | grep -E '^\.(text|rodata|data|bss)' || true

# ARM-tuned C variant: modulus+m0i bundled into a struct so every hot
# call fits in 4 args (AAPCS r0-r3 -> sibling-call optimisation works).
tv_ecdsa_small.o: tv_ecdsa_small.c tv_ecdsa.h
	$(CC) $(SIZE_CFLAGS) -c -o $@ tv_ecdsa_small.c

test_ecdsa_small: tv_ecdsa_small.c test_ecdsa.c tv_ecdsa.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_small.c test_ecdsa.c

test-small: test_ecdsa_small
	./test_ecdsa_small

size-small: tv_ecdsa_small.o
	@echo "=== size (-Os) of tv_ecdsa_small.c ==="
	@size $<

# Assemble the pure-asm version and report its size.
tv_ecdsa_amd64.o: tv_ecdsa_amd64.S
	$(CC) -c -o $@ $<

size-asm: tv_ecdsa_amd64.o
	@echo "=== size of tv_ecdsa_amd64.S (pure assembly, 64-bit limbs) ==="
	@size $<
	@echo ""
	@size -A $< | grep -E '^\.(text|rodata|data|bss)' || true
	@echo ""
	@echo "=== undefined symbols ==="
	@nm $< | grep ' U ' || echo "NONE — fully self-contained"

# Bytecode-interpreted asm (the smallest x86-64 variant).
tv_ecdsa_bc.o: tv_ecdsa_bc.S
	$(CC) -c -o $@ $<

test_ecdsa_bc: tv_ecdsa_bc.S test_ecdsa_asm.c test_ecdsa.c
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_bc.S test_ecdsa_asm.c

test-bc: test_ecdsa_bc
	./test_ecdsa_bc

size-bc: tv_ecdsa_bc.o
	@echo "=== size of tv_ecdsa_bc.S (bytecode-interpreted, 64-bit limbs) ==="
	@size $<
	@echo ""
	@size -A $< | grep -E '^\.(text|rodata|data|bss)' || true
	@echo ""
	@echo "=== undefined symbols ==="
	@nm $< | grep ' U ' || echo "NONE — fully self-contained"

# Size-only variant (forked from fast.S, speed traded for bytes).
tv_ecdsa_tiny.o: tv_ecdsa_tiny.S
	$(CC) -c -o $@ $<

test_ecdsa_tiny: tv_ecdsa_tiny.S test_ecdsa_asm.c test_ecdsa.c
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_tiny.S test_ecdsa_asm.c

test-tiny: test_ecdsa_tiny
	./test_ecdsa_tiny

size-tiny: tv_ecdsa_tiny.o
	@echo "=== tv_ecdsa_tiny.S default (dominates Thomas on both axes) ==="
	@size $<
	@echo ""
	@size -A $< | grep -E '^\.(text|rodata|data|bss)' || true
	@echo ""
	@echo "=== with -DSMALL_MUL8 (absolute size floor, ~2x cycles) ==="
	@$(CC) -c -DSMALL_MUL8 -o /tmp/_tiny_small.o tv_ecdsa_tiny.S && size /tmp/_tiny_small.o | tail -1 && rm -f /tmp/_tiny_small.o

test_wycheproof_tiny: tv_ecdsa_tiny.S test_wycheproof_asm.c test_wycheproof.c wycheproof_vectors.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_tiny.S test_wycheproof_asm.c

wp-tiny: test_wycheproof_tiny
	./test_wycheproof_tiny

bench_tiny: tv_ecdsa_tiny.S bench.c
	$(CC) -O2 -o $@ $^

# Speed+size optimized bytecode variant (BMI2 mulx).
tv_ecdsa_fast.o: tv_ecdsa_fast.S
	$(CC) -c -o $@ $<

test_ecdsa_fast: tv_ecdsa_fast.S test_ecdsa_asm.c test_ecdsa.c
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_fast.S test_ecdsa_asm.c

test-fast: test_ecdsa_fast
	./test_ecdsa_fast

size-fast: tv_ecdsa_fast.o
	@echo "=== size of tv_ecdsa_fast.S (bytecode + mulx unrolled) ==="
	@size $<
	@echo ""
	@size -A $< | grep -E '^\.(text|rodata|data|bss)' || true
	@echo ""
	@echo "=== undefined symbols ==="
	@nm $< | grep ' U ' || echo "NONE — fully self-contained"

# ---- Wycheproof test suite ----------------------------------------
# Vectors in wycheproof_vectors.h are checked in; regenerate with:
#   make wycheproof_vectors.h

WP_BASE = https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1
WP_FILES = ecdsa_secp256r1_sha256_p1363_test.json \
           ecdsa_secp256r1_sha512_p1363_test.json

wycheproof_vectors.h: gen_wycheproof.py
	@for f in $(WP_FILES); do curl -sL $(WP_BASE)/$$f -o /tmp/$$f; done
	python3 gen_wycheproof.py $(addprefix /tmp/,$(WP_FILES)) > $@

test_wycheproof: tv_ecdsa.c test_wycheproof.c tv_ecdsa.h wycheproof_vectors.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa.c test_wycheproof.c

test_wycheproof_fast: tv_ecdsa_fast.S test_wycheproof_asm.c test_wycheproof.c wycheproof_vectors.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_fast.S test_wycheproof_asm.c

test_wycheproof_bc: tv_ecdsa_bc.S test_wycheproof_asm.c test_wycheproof.c wycheproof_vectors.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_bc.S test_wycheproof_asm.c

test_wycheproof_asm: tv_ecdsa_amd64.S test_wycheproof_asm.c test_wycheproof.c wycheproof_vectors.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_amd64.S test_wycheproof_asm.c

wp: test_wycheproof
	./test_wycheproof

wp-fast: test_wycheproof_fast
	./test_wycheproof_fast

wp-bc: test_wycheproof_bc
	./test_wycheproof_bc

wp-asm: test_wycheproof_asm
	./test_wycheproof_asm

wp-all: wp wp-asm wp-bc wp-fast

# Cycle-count benchmark.  Links against any .S exporting the _asm symbol.
bench_bc: tv_ecdsa_bc.S bench.c
	$(CC) -O2 -o $@ $^

bench_fast: tv_ecdsa_fast.S bench.c
	$(CC) -O2 -o $@ $^

bench: bench_bc bench_fast
	@echo "=== tv_ecdsa_bc.S (baseline) ==="
	@for i in 1 2 3 4 5; do ./bench_bc; done | sort -t: -k2 -n | head -1
	@echo "=== tv_ecdsa_fast.S ==="
	@for i in 1 2 3 4 5; do ./bench_fast; done | sort -t: -k2 -n | head -1

# Optional: Thumb-2 build for a realistic embedded target (requires
# arm-none-eabi-gcc). Not built by default.
tv_ecdsa_thumb.o: tv_ecdsa.c tv_ecdsa.h
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb $(SIZE_CFLAGS) -c -o $@ tv_ecdsa.c

size-thumb: tv_ecdsa_thumb.o
	@echo "=== size (-Os, Cortex-M4 Thumb) of tv_ecdsa.c ==="
	@arm-none-eabi-size $<

clean:
	rm -f test_ecdsa test_ecdsa_asm test_ecdsa_bc test_ecdsa_fast \
	      test_wycheproof test_wycheproof_asm test_wycheproof_bc test_wycheproof_fast \
	      bench_bc bench_fast \
	      test_ecdsa_small \
	      tv_ecdsa_size.o tv_ecdsa_small.o tv_ecdsa_thumb.o tv_ecdsa_amd64.o \
	      tv_ecdsa_bc.o tv_ecdsa_fast.o

# ---------------------------------------------------------------------
# All-ZMM signer (AVX-512 IFMA, constant-time Montgomery ladder)
# ---------------------------------------------------------------------
sign_vectors.h: gen_sign_vectors.py sign_zmm_model.py
	python3 gen_sign_vectors.py

sign_zmm_test: sign_zmm.c sign_vectors.h
	$(CC) -O3 -mavx512f -mavx512ifma -mavx512vl -DSIGN_ZMM_TEST -o $@ sign_zmm.c

test-sign: sign_zmm_test
	./sign_zmm_test

sign-crossverify: sign_zmm.c tv_ecdsa_tiny.S sign_vectors.h
	# Sign with ZMM, verify with tiny — catches everything except
	# bugs shared between the two RCB implementations.
	@echo "(cross-verify harness in /tmp/crossverify.c — manual for now)"

# Speed-optimized variant (one-shot FIPS Solinas, MOVBE-only)
tv_ecdsa_speed.o: tv_ecdsa_speed.S solinas_oneshot.inc
	$(CC) -c -o $@ $<

test_ecdsa_speed: tv_ecdsa_speed.S solinas_oneshot.inc test_ecdsa_asm.c
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_speed.S test_ecdsa_asm.c

test-speed: test_ecdsa_speed
	./test_ecdsa_speed

size-speed: tv_ecdsa_speed.o
	@size $<

test_wycheproof_speed: tv_ecdsa_speed.S solinas_oneshot.inc test_wycheproof_asm.c wycheproof_vectors.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa_speed.S test_wycheproof_asm.c

wp-speed: test_wycheproof_speed
	./test_wycheproof_speed

bench_speed: tv_ecdsa_speed.S solinas_oneshot.inc bench.c
	$(CC) -O2 -o $@ $^
