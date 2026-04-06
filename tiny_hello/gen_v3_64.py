#!/usr/bin/env python3
r"""86-byte ELF64 'Hello, world!\n' using e_phoff=0x18 (phdr overlays ehdr).

The phdr starts at 0x18, overlapping e_entry/e_phoff/e_shoff/e_flags/e_ehsize/
e_phentsize/e_phnum/e_sh* — every ehdr field after e_version. Since
e_entry[0:4] = p_type = 1, the entry point's low 32 bits are forced to 1,
so execution begins at file byte 1: the "ELF" magic bytes, which decode as
three REX prefixes (45 4C 46 — only the last counts on x86-64).

  Off  Hex                        ELF / phdr             As code (entry @ 1)
  00   7F 45 4C 46                magic                  [01-03: REX×3]
  04   B0 01                      e_ident[4:6]           mov al, 1
  06   89 C7                      e_ident[6:8]           mov edi, eax
  08   48 8D 35 39 00 00 00       e_ident[8:15]          lea rsi, [rip+0x39]
  0F   3D                         e_ident[15]            cmp eax, imm32 (eats 10-13)
  10   02 00 3E 00                e_type / e_machine     (imm32)
  14   B2 0E                      e_version[0:2]         mov dl, 14
  16   EB 18                      e_version[2:4]         jmp 0x30
  18   01 00 00 00                e_entry[0:4]=p_type
  1C   05 00 00 00                e_entry[4:8]=p_flags   PF_R|PF_X
  20   18 00 00 00 00 00 00 00    e_phoff = p_offset = 0x18
  28   18 00 00 00 05 00 00 00    e_shoff = p_vaddr = 0x500000018
  30   0F 05                      e_flags[0:2]=p_paddr   syscall (write)
  32   B0 3C                      e_flags[2:4]           mov al, 60
  34   0F 05                      e_ehsize               syscall (exit)
  36   38 00                      e_phentsize=56=p_paddr[6:8]
  38   01 00                      e_phnum=1 = p_filesz[0:2]
  3A   00 00 00 00 00 00          e_sh* = p_filesz[2:8]  (p_filesz=1)
  40   01 00 00 00 00 00 00 00    p_memsz = 1            (=filesz: no BSS)
  48   "Hello, world!\n"          p_align + 6 tail bytes

p_filesz = p_memsz = 1: maps page 0 only, no BSS zeroing. The string at 0x48
is inside page 0 of the file mapping. p_vaddr = (p_flags<<32)+0x18 because
e_entry = (p_flags<<32)|1 = D+1 forces D = p_flags<<32.

Why 86 is the floor: p_memsz[6:8] @ bytes 0x46-0x47 must be 0 (vaddr+memsz <
TASK_SIZE ≈ 2^47), and e_phentsize/e_phnum @ 0x36-0x39 are forced. The only
14-byte gap that avoids both is 0x48-0x55. e_phoff < 0x18 makes p_offset
include e_phoff bytes → p_offset ≥ 2^32, unmappable. e_phoff > 0x18 grows
the file (phdr-read bound = e_phoff+56).

Prior best in this repo: 117 bytes. Otterness 2021: 120 bytes.
"""
import struct, sys, os

STRING = b"Hello, world!\n"
P_FLAGS = 5  # PF_R|PF_X — PF_R needed so write() can read the buffer
D = P_FLAGS << 32
STR_OFF = 0x48
SIZE = STR_OFF + len(STRING)
assert SIZE == 86

e = bytearray(SIZE)
e[0:4] = b'\x7fELF'

# Code in e_ident[4:16] + e_version (entry @ byte 1; magic = REX prefixes)
e[0x04:0x06] = bytes([0xB0, 0x01])               # mov al, 1
e[0x06:0x08] = bytes([0x89, 0xC7])               # mov edi, eax
disp = STR_OFF - 0x0F
e[0x08:0x0F] = bytes([0x48, 0x8D, 0x35]) + struct.pack('<i', disp)  # lea rsi
e[0x0F] = 0x3D                                   # cmp eax, imm32 (absorbs e_type/mach)
struct.pack_into('<HH', e, 0x10, 2, 0x3E)        # e_type, e_machine
e[0x14:0x16] = bytes([0xB2, len(STRING)])        # mov dl, 14
e[0x16:0x18] = bytes([0xEB, 0x30 - 0x18])        # jmp 0x30

struct.pack_into('<Q', e, 0x18, D + 1)           # e_entry = p_type|p_flags<<32
struct.pack_into('<Q', e, 0x20, 0x18)            # e_phoff = p_offset
struct.pack_into('<Q', e, 0x28, D + 0x18)        # e_shoff = p_vaddr

# Code in e_flags + e_ehsize (= p_paddr[0:6], don't-care)
e[0x30:0x32] = bytes([0x0F, 0x05])               # syscall (write)
e[0x32:0x34] = bytes([0xB0, 0x3C])               # mov al, 60
e[0x34:0x36] = bytes([0x0F, 0x05])               # syscall (exit)

struct.pack_into('<H', e, 0x36, 56)              # e_phentsize (= p_paddr[6:8])
e[0x38] = 1                                      # e_phnum (= p_filesz[0:2] = 1)
struct.pack_into('<Q', e, 0x40, 1)               # p_memsz = 1 (= p_filesz, no BSS)
e[STR_OFF:] = STRING                             # p_align + tail

assert e[0x18:0x1C] == bytes([1,0,0,0])          # p_type = PT_LOAD
assert e[0x1C] & 1                               # p_flags has PF_X
assert struct.unpack_from('<Q', e, 0x38)[0] == struct.unpack_from('<Q', e, 0x40)[0]

out = sys.argv[1] if len(sys.argv) > 1 else "hello64_86"
with open(out, 'wb') as f:
    f.write(e)
os.chmod(out, 0o755)
print(f"{out}: {len(e)} bytes")
for i in range(0, len(e), 16):
    h = ' '.join(f'{b:02X}' for b in e[i:i+16])
    a = ''.join(chr(b) if 32<=b<127 else '.' for b in e[i:i+16])
    print(f"  {i:04X}  {h:<48s}  {a}")
