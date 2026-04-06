# Tiny ELF Hello World

Minimal ELF binaries that print "Hello World".

| Binary | Arch | Size | Output | Exit | Self-contained |
|--------|------|------|--------|------|----------------|
| `hello45_argv` | i386 | **45 bytes** | argv[0] | SEGV | no¹ |
| `hello57` | i386 | **57 bytes** | `Hello World` | 11 | yes |
| `hello58` | i386 | **58 bytes** | `Hello World\n` | 12 | yes |
| `tiny_hello` | i386 | 76 bytes | `Hello World\n` | 1 | yes (old floor) |
| `tiny_hello64` | x86-64 | 117 bytes | `Hello World\n` | 0 | yes |

¹ prints first 12 bytes of argv[0]; invoke with `exec -a $'Hello World\n' ./hello45_argv`

For comparison: Nathan Otterness's [Tiny ELF Files: Revisited in 2021](https://nathanotterness.com/2021/10/tiny_elf_modernized.html)
hit ~120 bytes for x86-64; tmp.0ut #3 reports 77 bytes for x86-64.

## Build & Test

```
make          # builds all variants, runs them
make verify   # readelf + disassembly for hello58
```

Requires Python 3 and an x86-64 Linux kernel with IA-32 compat (most distros).

## How 58 bytes works (down from 76)

The 76-byte version overlapped the program header with the *last 8 bytes*
of the ELF header (`e_phoff=44`). The 58-byte version sets **`e_phoff=4`**,
overlapping the program header with *almost the entire* ELF header — the
phdr's `p_type` field reads `EI_CLASS=1` as `PT_LOAD`, and `p_flags` reads
`e_phoff=4` as `PF_R`. This is Brian Raiter's classic 45-byte trick,
extended to carry a payload.

Key kernel-loader facts (probed on 6.12; see `NOTES.md`):

- `EI_CLASS`/`EI_DATA`/`EI_VERSION` are **not checked** — only the 4-byte magic, `e_type`, `e_machine`, and `e_phentsize` are validated.
- `e_ehsize`, `e_shoff`, `e_flags`, `p_align`, `p_paddr` are **not checked**.
- For ia32 binaries with no `PT_GNU_STACK`, `READ_IMPLIES_EXEC` makes `PF_R` sufficient.
- `p_filesz` may exceed the file size (mmap pads with zeros within page 0).

### Byte map (hello58)

```
Off  Hex                          ELF field              As code (entry @ 0x14)
00   7F 45 4C 46 01 00 00 00      magic + p_type=LOAD
08   00 00 00 00                  p_offset=0
0C   00 00 43 05                  p_vaddr=0x05430000
10   02 00 03 00                  e_type/e_mach (=p_paddr)
14   B2 0C                        p_filesz[0:2]          mov dl, 12
16   B0 00                        p_filesz[2:4]          mov al, 0
18   14 00                        e_entry[0:2]           adc al, 0
1A   43                           e_entry[2]             inc ebx        ← free
1B   05 04 00 00 00               e_entry[3] + e_phoff   add eax, 4     ← free
20   B9 2E 00 43 05               e_shoff/p_align+       mov ecx, 0x0543002E
25   CD 80                        e_flags[1:3]           int 0x80  (write)
27   93                           e_flags[3]             xchg eax, ebx
28   CD 80                        e_ehsize               int 0x80  (exit)
2A   20 00                        e_phentsize=32
2C   01 00                        e_phnum=1
2E   48 65 6C 6C 6F 20 57 6F 72 6C 64 0A   "Hello World\n"
```

`p_vaddr=0x05430000` is chosen so that `e_entry = p_vaddr+0x14` encodes
in little-endian as `14 00 43 05` — when *executed*, byte `43` is `inc ebx`
(stdout fd) and byte `05` begins `add eax, imm32`, which then consumes
the mandatory `e_phoff = 04 00 00 00` as its immediate, yielding `eax=4`
(`SYS_write`). Two register setups for free.

### Why 58 is the self-contained floor

With `e_phoff=4` (the only viable value ≤18), bytes `0x2A-0x2D` are forced
to `20 00 01 00` and the longest contiguous free span before them is 10
bytes (`0x20-0x29`). The 12-byte string can't fit there, and no 12-byte
window of "Hello World\n" matches the fixed bytes at `0x10-0x13`,
`0x1C-0x1F`, or `0x2A-0x2D`. So the string must start at `0x2E`. Full
analysis (including why push-to-stack and writev don't help) in `NOTES.md`.

## The 45-byte argv variant

For the ≤50-byte target: drop the string from the binary and print
`argv[0]` instead. Code is 9 bytes at `0x20-0x29`:
`pop eax; pop ecx; inc ebx; mov dl,12; mov al,4; int 0x80; xchg eax,ebx`.
The kernel zero-fills byte `0x2D` (file is 45 bytes), giving `e_phnum=1`.

```
bash -c "exec -a $'Hello World\n' ./hello45_argv"
```
