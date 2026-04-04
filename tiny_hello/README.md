# Tiny ELF Hello World

Minimal ELF binaries that print "Hello World\n".

| Binary | Arch | Size | Exit |
|--------|------|------|------|
| `tiny_hello` | i386 (ELF32) | **76 bytes** | 1 |
| `tiny_hello64` | x86-64 (ELF64) | **117 bytes** | 0 |

For comparison, Nathan Otterness's [Tiny ELF Files: Revisited in 2021](https://nathanotterness.com/2021/10/tiny_elf_modernized.html) achieved ~120 bytes for x86-64.

## Build & Test

```
make          # generates both, runs them
make verify   # detailed header dumps + disassembly
```

Requires Python 3. Runs on x86-64 Linux (32-bit ELF needs IA-32 compat support, which most distros have).

## Techniques (76-byte ELF32)

### 1. 32-bit ELF instead of 64-bit
ELF32 headers are much smaller: ehdr=52 bytes, phdr=32 bytes (vs 64+56=120 for ELF64).

### 2. Ehdr/Phdr overlap (8 bytes)
Program header starts at `e_phoff=44`, overlapping the last 8 bytes of the ELF header:
- `e_phnum=1` doubles as `p_type=PT_LOAD` (both are 0x00000001)
- `e_shnum=e_shstrndx=0` doubles as `p_offset=0`

### 3. Code embedded in header fields
16 bytes of x86 code live inside unused/abused ELF header fields:

| Offset | ELF Field | Code |
|--------|-----------|------|
| 8-14 | `e_ident[8..14]` | `mov ecx, str_va; mov dl, 12; jmp` |
| 19-23 | `e_machine[1]` + `e_version` | `add al,al; inc ebx; jmp` |
| 32-39 | `e_shoff` + `e_flags` | `mov al,4; int 0x80; mov al,1; int 0x80` |

The jump at byte 15 (`EB 02`) exploits `e_type=2` as its offset, landing at byte 19.
Bytes 19-20 (`00 C0`) decode as `add al, al` — a harmless register-only operation.

### 4. String as program header fields
"Hello World\n" (12 bytes) is stored directly as `p_memsz` + `p_flags` + `p_align`:
- `p_memsz` = "Hell" = 0x6C6C6548 (~1.8 GB, lazily allocated)
- `p_flags` = "o Wo" = 0x6F57206F (PF_R|PF_W|PF_X all set: 0x6F & 7 = 7)
- `p_align` = "rld\n" = 0x0A646C72 (ignored for ET_EXEC with MAP_FIXED)

### 5. Linux zeroes registers on exec
All GPRs are zero at ELF entry, so no explicit clearing needed. This saves
`xor eax,eax` / `xor edx,edx` etc.

## Why 76 is the floor

The kernel reads `e_phentsize × e_phnum` bytes from file offset `e_phoff`:
- `e_phentsize` must be exactly 32 (kernel enforces `== sizeof(Elf32_Phdr)`)
- With `e_phoff=44`: kernel reads bytes 44-75, requiring file ≥ **76 bytes**

Every other `e_phoff < 44` that could give `p_type=PT_LOAD` fails on other
constraints (p_offset, p_vaddr alignment, p_flags, or p_memsz < p_filesz).
Full analysis in `gen_hello.py`.

## Byte map

```
Off  Hex                              Meaning
00   7F 45 4C 46 01 01 01 00          ELF magic + ident
08   B9 40 00 01 00 B2 0C EB          CODE: mov ecx,0x10040; mov dl,12; jmp +2
10   02 00 03 00                       e_type=EXEC, e_machine=386
14   C0 43 EB 08                       CODE: add al,al; inc ebx; jmp +8
18   08 00 01 00                       e_entry = 0x10008
1C   2C 00 00 00                       e_phoff = 44
20   B0 04 CD 80                       CODE: mov al,4; int 0x80 (write)
24   B0 01 CD 80                       CODE: mov al,1; int 0x80 (exit)
28   34 00 20 00                       e_ehsize=52, e_phentsize=32
2C   01 00 00 00                       e_phnum=1 / p_type=LOAD
30   00 00 00 00                       p_offset=0
34   00 00 01 00                       p_vaddr=0x10000
38   00 00 00 00                       p_paddr=0
3C   4C 00 00 00                       p_filesz=76
40   48 65 6C 6C 6F 20 57 6F 72 6C 64 0A   "Hello World\n"
```
