#!/usr/bin/env python3
"""Generate a minimal ELF64 that prints "Hello World\n".

64-bit ELF: ehdr=64 bytes, phdr=56 bytes.
Best overlap: e_phoff=56 → 8-byte overlap → 112 bytes of header space.
String "Hello World\\n" (12 bytes) embedded in e_shoff + e_flags (bytes 40-51).
Code embedded in: e_ident[8..15], e_version[20..23], p_paddr[80..87].
Remaining code after headers.

Code flow:
  Entry at byte 8 (VA 0x400008).
  Chunk A (8-15):  inc edi; mov eax,edi; mov dl,12; jmp short +24 → byte 40...
  Wait, can't reach string setup. Instead:

  Approach: entry at byte 8, code in ident, jmp to e_shoff=40? No, string is there.

  Instead: entry at byte 80 (p_paddr), code there + after headers. String at 40-51.
"""
import struct, sys, os

LOAD_ADDR = 0x400000
FILE_SIZE = 116  # Will be determined by code layout

# Helper: build the 64-bit binary
def build():
    # String embedded at bytes 40-51 (e_shoff + e_flags)
    STRING = b"Hello World\n"
    STRING_OFF = 40
    STRING_VA = LOAD_ADDR + STRING_OFF

    # Code at bytes 8-15 (e_ident padding), then jmp to code at bytes 112+
    # Actually, simpler: entry at byte 8, code scattered, rest after headers.

    # Let me use: entry at byte 8.
    # Chunk A (8-15, 8 bytes): basic setup + jmp to chunk B
    # Chunk B (20-23, 4 bytes): jmp to chunk C
    # Chunk C (80-87, 8 bytes): mov esi + jmp to post-header code
    # Post-header (112+): syscall + exit

    # But to skip bytes 16-19 (e_type=2, e_machine=0x3E) we need a jump.
    # Use CMP trick: byte 15 = 0x3D → cmp eax, imm32, consuming bytes 16-19.
    # Then we fall through to byte 20.

    # Chunk A (8-14, 7 bytes of real code, byte 15=CMP opcode):
    #   inc edi        (2: FF C7)
    #   mov eax, edi   (2: 89 F8)
    #   mov dl, 12     (2: B2 0C)
    #   push rdi       (1: 57) — save 1 for later exit
    # Byte 15: 0x3D = cmp eax, imm32 → consumes 16-19

    # Chunk B (20-23, 4 bytes, e_version):
    #   jmp short → byte 80 (2: EB XX)
    #   2 bytes unused

    # Chunk C (80-87, 8 bytes, p_paddr):
    #   mov esi, STRING_VA (5: BE XX XX XX XX)
    #   jmp short → 112 (2: EB XX)
    #   1 byte unused

    # Post (112+):
    #   syscall         (2: 0F 05) — write(1, str, 12)
    #   pop rax         (1: 58) — rax = 1 (pushed rdi earlier)
    #   int 0x80        (2: CD 80) — 32-bit exit(ebx=0)
    # Total post: 5 bytes. File = 112 + 5 = 117.

    # Actually, let me try to keep it simpler and just put code after headers:
    # Entry at byte 8.
    # Chunk A (8-14): inc edi; mov eax,edi; mov dl,12
    # Byte 15 = 0x3D (cmp opcode, consumes 16-19)
    # Chunk B (20-21): jmp short → 80
    # Chunk C (80-84): mov esi, STRING_VA
    # Bytes 85-86: jmp short → 112
    # Post (112-116): syscall; pop rax; int 0x80

    FILE_SIZE = 117
    ENTRY_OFF = 8
    ENTRY_VA = LOAD_ADDR + ENTRY_OFF

    elf = bytearray(FILE_SIZE)

    # ---- ELF64 Header ----
    elf[0:4] = b'\x7fELF'
    elf[4] = 2          # ELFCLASS64
    elf[5] = 1          # ELFDATA2LSB
    elf[6] = 1          # EV_CURRENT
    elf[7] = 0          # ELFOSABI_NONE

    # Chunk A: code in e_ident[8..14]
    elf[8]  = 0xFF; elf[9]  = 0xC7  # inc edi (2 bytes)
    elf[10] = 0x89; elf[11] = 0xF8  # mov eax, edi (2 bytes)
    elf[12] = 0xB2; elf[13] = 12    # mov dl, 12 (2 bytes)
    elf[14] = 0x57                   # push rdi (save 1 for exit later)

    # Byte 15: CMP opcode that consumes e_type + e_machine (bytes 16-19)
    elf[15] = 0x3D  # cmp eax, imm32 → instruction spans 15-19

    # e_type, e_machine (consumed by CMP as imm32)
    struct.pack_into('<H', elf, 16, 2)      # ET_EXEC
    struct.pack_into('<H', elf, 18, 0x3E)   # EM_X86_64

    # Chunk B: e_version = jmp to chunk C
    elf[20] = 0xEB                           # jmp short
    elf[21] = 80 - 22                        # offset: 80 - (20+2) = 58 = 0x3A
    elf[22] = 0x00; elf[23] = 0x00           # padding

    # e_entry
    struct.pack_into('<Q', elf, 24, ENTRY_VA)

    # e_phoff
    struct.pack_into('<Q', elf, 32, 56)      # phdr at offset 56

    # e_shoff = "Hello Wo" (first 8 bytes of string)
    elf[40:48] = STRING[:8]

    # e_flags = "rld\n" + padding (last 4 bytes of string)
    elf[48:52] = STRING[8:12]

    # e_ehsize (can be any value, kernel doesn't check for main binary)
    struct.pack_into('<H', elf, 52, 5)       # 5 (has PF_R|PF_X bits for p_flags trick)
    # Actually e_ehsize is at bytes 52-53, separate from phdr.
    # Let me just set it properly.
    struct.pack_into('<H', elf, 52, 64)      # standard e_ehsize

    # e_phentsize
    struct.pack_into('<H', elf, 54, 56)      # must be exactly 56

    # --- Phdr overlaps last 8 bytes of ehdr ---
    # Bytes 56-57: e_phnum = 1 / p_type low
    struct.pack_into('<H', elf, 56, 1)
    # Bytes 58-59: e_shentsize = 0 / p_type bytes 2-3
    struct.pack_into('<H', elf, 58, 0)
    # → p_type = 0x00000001 = PT_LOAD

    # Bytes 60-61: e_shnum / p_flags low
    # Bytes 62-63: e_shstrndx / p_flags high
    # p_flags needs PF_R|PF_X = 5
    struct.pack_into('<H', elf, 60, 5)       # e_shnum = 5 (ignored)
    struct.pack_into('<H', elf, 62, 0)       # e_shstrndx = 0
    # → p_flags = 0x00000005 = PF_R|PF_X

    # --- Phdr continued (bytes 64-111) ---
    # p_offset
    struct.pack_into('<Q', elf, 64, 0)

    # p_vaddr
    struct.pack_into('<Q', elf, 72, LOAD_ADDR)

    # p_paddr (bytes 80-87) = Chunk C: code
    elf[80] = 0xBE                           # mov esi, imm32
    struct.pack_into('<I', elf, 81, STRING_VA)  # 0x400028
    elf[85] = 0xEB                           # jmp short
    elf[86] = 112 - 87                       # offset: 112 - 87 = 25 = 0x19
    elf[87] = 0x00                           # padding

    # p_filesz
    struct.pack_into('<Q', elf, 88, FILE_SIZE)

    # p_memsz (must be >= p_filesz)
    struct.pack_into('<Q', elf, 96, FILE_SIZE)

    # p_align
    struct.pack_into('<Q', elf, 104, 0x200000)

    # --- Post-header code (bytes 112+) ---
    elf[112] = 0x0F; elf[113] = 0x05   # syscall (write)
    elf[114] = 0x58                      # pop rax (rax = 1 from push rdi)
    elf[115] = 0xCD; elf[116] = 0x80    # int 0x80 (32-bit sys_exit, ebx=0)

    return elf

elf = build()
outname = sys.argv[1] if len(sys.argv) > 1 else "tiny_hello64"
with open(outname, 'wb') as f:
    f.write(elf)
os.chmod(outname, 0o755)

print(f"Generated {outname}: {len(elf)} bytes")
for i in range(0, len(elf), 16):
    hexpart = ' '.join(f'{b:02X}' for b in elf[i:i+16])
    ascpart = ''.join(chr(b) if 32 <= b < 127 else '.' for b in elf[i:i+16])
    print(f"  {i:04X}  {hexpart:<48s}  {ascpart}")
