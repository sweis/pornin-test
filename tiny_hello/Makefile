all: tiny_hello tiny_hello64
	@echo "=== 32-bit ELF ==="
	@wc -c tiny_hello
	@./tiny_hello; echo "(exit $$?)"
	@echo "=== 64-bit ELF ==="
	@wc -c tiny_hello64
	@./tiny_hello64; echo "(exit $$?)"

tiny_hello: gen_hello.py
	python3 gen_hello.py $@

tiny_hello64: gen_hello64.py
	python3 gen_hello64.py $@

verify: tiny_hello tiny_hello64
	@echo "=== 32-bit: readelf ==="
	@readelf -hl tiny_hello 2>&1
	@echo "=== 32-bit: disassembly ==="
	@objdump -D -b binary -m i386 -M intel --start-address=8 --stop-address=40 tiny_hello
	@echo "=== 32-bit: run ==="
	@./tiny_hello; echo "(exit $$?)"
	@echo "=== 64-bit: readelf ==="
	@readelf -hl tiny_hello64 2>&1
	@echo "=== 64-bit: run ==="
	@./tiny_hello64; echo "(exit $$?)"

clean:
	rm -f tiny_hello tiny_hello64

.PHONY: all verify clean
