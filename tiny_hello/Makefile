BINS = tiny_hello tiny_hello64 hello58 hello57 hello45_argv

all: $(BINS) test

tiny_hello: gen_hello.py
	python3 gen_hello.py $@

tiny_hello64: gen_hello64.py
	python3 gen_hello64.py $@

hello58 hello57 hello45_argv: gen_v2.py
	python3 gen_v2.py $@

test: $(BINS)
	@echo "=== sizes ==="
	@wc -c $(BINS) | grep -v total
	@echo "=== tiny_hello (76B reference) ==="
	@./tiny_hello; echo "(exit $$?)"
	@echo "=== hello58 ==="
	@./hello58; echo "(exit $$?)"
	@test "$$(./hello58)" = "$$(printf 'Hello World')" && echo "  output OK"
	@echo "=== hello57 (no newline) ==="
	@./hello57; rc=$$?; echo; echo "(exit $$rc)"
	@test "$$(./hello57)" = "Hello World" && echo "  output OK"
	@echo "=== hello45_argv (argv[0] trick) ==="
	@out=$$(bash -c "exec -a $$'Hello World\n' ./hello45_argv" 2>/dev/null); \
	  echo "$$out"; test "$$out" = "Hello World" && echo "  output OK"
	@echo "=== tiny_hello64 (117B reference) ==="
	@./tiny_hello64; echo "(exit $$?)"

verify: hello58
	@echo "=== readelf ==="
	@readelf -hl hello58 2>&1 || true
	@echo "=== disassembly (entry @ 0x14) ==="
	@objdump -D -b binary -m i386 -M intel --start-address=0x14 --stop-address=0x2A hello58
	@echo "=== run ==="
	@./hello58 | xxd

clean:
	rm -f $(BINS)

.PHONY: all test verify clean
