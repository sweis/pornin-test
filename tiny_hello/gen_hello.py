#!/usr/bin/env python3
"""Generate a minimal 76-byte ELF32 that prints "Hello World\n".

Layout:
  Bytes  0-15:  ELF ident (code embedded in padding bytes 8-15)
  Bytes 16-19:  e_type=ET_EXEC, e_machine=EM_386
  Bytes 19-23:  (code falls through e_machine high byte into e_version)
  Bytes 24-27:  e_entry = 0x00010008
  Bytes 28-31:  e_phoff = 44
  Bytes 32-39:  e_shoff + e_flags = code (mov al,4; int 0x80; mov al,1; int 0x80)
  Bytes 40-43:  e_ehsize=52, e_phentsize=32
  Bytes 44-51:  e_phnum=1 / p_type=1, e_sh*=0 / p_offset=0  (8-byte overlap)
  Bytes 52-55:  p_vaddr = 0x00010000
  Bytes 56-59:  p_paddr = 0 (unused)
  Bytes 60-63:  p_filesz = 76
  Bytes 64-75:  "Hello World\\n" stored as p_memsz + p_flags + p_align

Code flow (entry at VA 0x10008, file offset 8):
  08: mov ecx, 0x10040   ; string VA (offset 64)
  0D: mov dl, 12         ; string length
  0F: jmp short +2       ; skip e_type/e_machine (lands at byte 19)
  13: add al, al         ; harmless NOP (byte 19=0x00 + byte 20=0xC0)
  15: inc ebx            ; fd = 1 (ebx was 0 from kernel)
  16: jmp short +8       ; jump to byte 32
  20: mov al, 4          ; sys_write
  22: int 0x80
  24: mov al, 1          ; sys_exit
  26: int 0x80           ; exit(1)
"""
import struct, sys, stat, os

LOAD_ADDR = 0x00010000
STRING = b"Hello World\n"
STRING_OFF = 64
STRING_VA = LOAD_ADDR + STRING_OFF
ENTRY_OFF = 8
ENTRY_VA = LOAD_ADDR + ENTRY_OFF
FILE_SIZE = 76

elf = bytearray(FILE_SIZE)

# ---- ELF ident (bytes 0-15) ----
elf[0:4] = b'\x7fELF'
elf[4] = 1          # ELFCLASS32
elf[5] = 1          # ELFDATA2LSB
elf[6] = 1          # EV_CURRENT
elf[7] = 0          # ELFOSABI_NONE

# Code chunk 1 embedded in e_ident[8..15]:
#   mov ecx, STRING_VA  (5 bytes: B9 xx xx xx xx)
#   mov dl, 12          (2 bytes: B2 0C)
#   jmp short +2        (2 bytes: EB 02) -- offset=e_type low byte=0x02
elf[8]    = 0xB9
struct.pack_into('<I', elf, 9, STRING_VA)   # imm32 = 0x00010040
elf[13]   = 0xB2
elf[14]   = len(STRING)
elf[15]   = 0xEB     # jmp short, offset is next byte (= e_type low = 0x02)

# ---- e_type, e_machine (bytes 16-19) ----
struct.pack_into('<H', elf, 16, 2)     # ET_EXEC
struct.pack_into('<H', elf, 18, 3)     # EM_386
# Execution lands at byte 19 (e_machine high = 0x00)
# Byte 19 = 0x00 = opcode for ADD r/m8, r8
# Byte 20 = ModRM: we set it to 0xC0 = mod=11,reg=AL,rm=AL → add al,al

# ---- e_version (bytes 20-23) = code ----
elf[20] = 0xC0       # ModRM for "add al, al" (register-only, harmless)
elf[21] = 0x43       # inc ebx (32-bit 1-byte encoding)
elf[22] = 0xEB       # jmp short
elf[23] = 0x08       # offset +8 → byte 32  (PC at 24, 24+8=32)

# ---- e_entry (bytes 24-27) ----
struct.pack_into('<I', elf, 24, ENTRY_VA)   # 0x00010008

# ---- e_phoff (bytes 28-31) ----
struct.pack_into('<I', elf, 28, 44)         # phdr at offset 44

# ---- e_shoff (bytes 32-35) = code chunk 3a ----
#   mov al, 4   (B0 04)
#   int 0x80    (CD 80)
elf[32] = 0xB0; elf[33] = 0x04  # mov al, 4 = sys_write
elf[34] = 0xCD; elf[35] = 0x80  # int 0x80

# ---- e_flags (bytes 36-39) = code chunk 3b ----
#   mov al, 1   (B0 01)
#   int 0x80    (CD 80)
elf[36] = 0xB0; elf[37] = 0x01  # mov al, 1 = sys_exit
elf[38] = 0xCD; elf[39] = 0x80  # int 0x80

# ---- e_ehsize, e_phentsize (bytes 40-43) ----
struct.pack_into('<H', elf, 40, 52)    # e_ehsize
struct.pack_into('<H', elf, 42, 32)    # e_phentsize

# ---- Overlapping region: ehdr tail / phdr start (bytes 44-51) ----
# e_phnum=1  (bytes 44-45) = p_type low = 0x0001
# e_shentsize=0 (46-47)    = p_type high = 0x0000  → p_type = PT_LOAD = 1
# e_shnum=0 (48-49)        = p_offset low
# e_shstrndx=0 (50-51)     = p_offset high           → p_offset = 0
struct.pack_into('<H', elf, 44, 1)     # e_phnum
struct.pack_into('<H', elf, 46, 0)     # e_shentsize
struct.pack_into('<H', elf, 48, 0)     # e_shnum
struct.pack_into('<H', elf, 50, 0)     # e_shstrndx

# ---- Phdr (bytes 52-75, non-overlapping part) ----
struct.pack_into('<I', elf, 52, LOAD_ADDR)  # p_vaddr
struct.pack_into('<I', elf, 56, 0)          # p_paddr (unused)
struct.pack_into('<I', elf, 60, FILE_SIZE)  # p_filesz

# String "Hello World\n" AS p_memsz + p_flags + p_align
assert len(STRING) == 12
elf[64:76] = STRING

# Verify p_flags has PF_R|PF_X set
p_flags = struct.unpack_from('<I', elf, 68)[0]
assert p_flags & 0x5 == 0x5, f"p_flags={p_flags:#x} missing PF_R|PF_X"

# Verify p_memsz >= p_filesz
p_memsz = struct.unpack_from('<I', elf, 64)[0]
assert p_memsz >= FILE_SIZE, f"p_memsz={p_memsz:#x} < filesz={FILE_SIZE:#x}"

# Write output
outname = sys.argv[1] if len(sys.argv) > 1 else "tiny_hello"
with open(outname, 'wb') as f:
    f.write(elf)
os.chmod(outname, 0o755)

print(f"Generated {outname}: {len(elf)} bytes")

# Hex dump
for i in range(0, len(elf), 16):
    hexpart = ' '.join(f'{b:02X}' for b in elf[i:i+16])
    ascpart = ''.join(chr(b) if 32 <= b < 127 else '.' for b in elf[i:i+16])
    print(f"  {i:04X}  {hexpart:<48s}  {ascpart}")
