# Build for ECDSA/P-256 verification (size-optimised).
#
# Targets:
#   make           - build test binary (default)
#   make test      - build and run tests
#   make size      - build size-optimised object and report code size
#   make clean     - remove build artifacts

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

.PHONY: all test size clean

all: test_ecdsa

test_ecdsa: tv_ecdsa.c test_ecdsa.c tv_ecdsa.h
	$(CC) $(CFLAGS) -o $@ tv_ecdsa.c test_ecdsa.c

test: test_ecdsa
	./test_ecdsa

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

# Optional: Thumb-2 build for a realistic embedded target (requires
# arm-none-eabi-gcc). Not built by default.
tv_ecdsa_thumb.o: tv_ecdsa.c tv_ecdsa.h
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb $(SIZE_CFLAGS) -c -o $@ tv_ecdsa.c

size-thumb: tv_ecdsa_thumb.o
	@echo "=== size (-Os, Cortex-M4 Thumb) of tv_ecdsa.c ==="
	@arm-none-eabi-size $<

clean:
	rm -f test_ecdsa tv_ecdsa_size.o tv_ecdsa_thumb.o
