#!/usr/bin/env python3
r"""Minimal ELF32 'Hello World' generators using e_phoff=4 (full ehdr/phdr overlap).

Variants:
  hello58       58B  self-contained "Hello World\n", clean exit(12)
  hello57       57B  self-contained "Hello World" (no newline), clean exit(11)
  hello45_argv  45B  writes argv[0] (caller supplies "Hello World\n"), crash exit

Shared layout (e_phoff=4, phdr @ bytes 4-35):
  00-03  7F 45 4C 46    magic
  04-07  01 00 00 00    EI_CLASS=1 / p_type=PT_LOAD
  08-0B  p_offset       (=0)
  0C-0F  p_vaddr        (chosen so e_entry bytes are safe code)
  10-13  02 00 03 00    e_type/e_machine (= p_paddr, ignored)
  14-17  p_filesz       (CODE; must <= p_memsz)
  18-1B  e_entry/p_memsz
  1C-1F  04 00 00 00    e_phoff / p_flags=PF_R (READ_IMPLIES_EXEC for ia32)
  20-29  CODE           (e_shoff/p_align/e_flags/e_ehsize — all unchecked)
  2A-2B  20 00          e_phentsize=32 (kernel-enforced)
  2C-2D  01 00          e_phnum=1
  2E+    string

Self-contained execution flow (entry @ 0x14):
  D = p_vaddr = 0x05430000  (chosen so bytes 18-1B = 14 00 43 05)
  14: B2 LL       mov dl, len
  16: B0 00       mov al, 0   (byte 17=00 keeps p_filesz <= p_memsz)
  18: 14 00       adc al, 0   (e_entry[0:2]; harmless)
  1A: 43          inc ebx     (e_entry[2]; ebx=1=stdout)
  1B: 05 04 00 00 00  add eax, 4  (e_entry[3] + e_phoff as imm32; eax=4=sys_write)
  20: B9 .. .. 43 05  mov ecx, D+str_off
  25: CD 80       int 0x80    (write)
  27: 93          xchg eax, ebx  (eax=1)
  28: CD 80       int 0x80    (exit)
"""
import struct, sys, os

def hexdump(e):
    for i in range(0, len(e), 16):
        h = ' '.join(f'{b:02X}' for b in e[i:i+16])
        a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in e[i:i+16])
        print(f"  {i:04X}  {h:<48s}  {a}")

def build_selfcontained(string):
    D = 0x05430000
    STR_OFF = 0x2E
    size = STR_OFF + len(string)
    e = bytearray(size)
    e[0:4] = b'\x7fELF'
    e[4] = 1
    struct.pack_into('<I', e, 0x0C, D)
    struct.pack_into('<H', e, 0x10, 2)
    struct.pack_into('<H', e, 0x12, 3)
    e[0x14:0x18] = bytes([0xB2, len(string), 0xB0, 0x00])
    struct.pack_into('<I', e, 0x18, D + 0x14)
    assert e[0x18:0x1C] == bytes([0x14, 0x00, 0x43, 0x05])
    struct.pack_into('<I', e, 0x1C, 4)
    e[0x20:0x25] = bytes([0xB9, STR_OFF, 0x00, 0x43, 0x05])
    e[0x25:0x2A] = bytes([0xCD, 0x80, 0x93, 0xCD, 0x80])
    struct.pack_into('<H', e, 0x2A, 32)
    e[0x2C] = 1
    e[0x2D] = 0
    e[STR_OFF:] = string
    p_filesz = struct.unpack_from('<I', e, 0x14)[0]
    p_memsz = struct.unpack_from('<I', e, 0x18)[0]
    assert p_filesz <= p_memsz
    return bytes(e)

def build_argv():
    """45B: writes 12 bytes of argv[0] to stdout, then crashes.
    Invoke with argv[0] = "Hello World\n"."""
    D = 0x00010000
    e = bytearray(45)
    e[0:4] = b'\x7fELF'
    e[4] = 1
    struct.pack_into('<I', e, 0x0C, D)
    struct.pack_into('<H', e, 0x10, 2)
    struct.pack_into('<H', e, 0x12, 3)
    struct.pack_into('<I', e, 0x14, 45)          # p_filesz
    struct.pack_into('<I', e, 0x18, D + 0x20)    # e_entry/p_memsz
    struct.pack_into('<I', e, 0x1C, 4)           # e_phoff
    # 0x20: pop eax; pop ecx; inc ebx; mov dl,12; mov al,4; int 80; xchg; int 80
    e[0x20:0x2A] = bytes([0x58, 0x59, 0x43, 0xB2, 0x0C, 0xB0, 0x04, 0xCD, 0x80, 0x93])
    # 0x2A: 20 00 → and [eax],al; eax=1 after xchg → [1] unmapped → SEGV
    struct.pack_into('<H', e, 0x2A, 32)
    e[0x2C] = 1
    return bytes(e)

VARIANTS = {
    'hello60': lambda: build_selfcontained(b"Hello, world!\n"),
    'hello58': lambda: build_selfcontained(b"Hello World\n"),
    'hello57': lambda: build_selfcontained(b"Hello World"),
    'hello45_argv': build_argv,
}

if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) > 1 else 'hello58'
    base = os.path.basename(name)
    fn = VARIANTS.get(base)
    if not fn:
        print(f"Unknown variant {base}. Choose from: {list(VARIANTS)}")
        sys.exit(1)
    e = fn()
    with open(name, 'wb') as f:
        f.write(e)
    os.chmod(name, 0o755)
    print(f"{name}: {len(e)} bytes")
    hexdump(e)
