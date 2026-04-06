# Tiny ELF Hello World

Minimal ELF binaries that print "Hello World".

| Binary | Arch | Size | Output | Exit | Self-contained |
|--------|------|------|--------|------|----------------|
| `hello45_argv` | i386 | **45 bytes** | argv[0] | SEGV | no¹ |
| `hello57` | i386 | **57 bytes** | `Hello World` | 11 | yes |
| `hello58` | i386 | **58 bytes** | `Hello World\n` | 12 | yes |
| `hello60` | i386 | **60 bytes** | `Hello, world!\n` | 14 | yes |
| `tiny_hello` | i386 | 76 bytes | `Hello World\n` | 1 | yes (old floor) |
| `hello64_86` | x86-64 | **86 bytes** | `Hello, world!\n` | 1 | yes |
| `tiny_hello64` | x86-64 | 117 bytes | `Hello World\n` | 0 | yes (old floor) |

¹ prints first 12 bytes of argv[0]; invoke with `exec -a $'Hello World\n' ./hello45_argv`

For comparison: Nathan Otterness's [Tiny ELF Files: Revisited in 2021](https://nathanotterness.com/2021/10/tiny_elf_modernized.html)
hit ~120 bytes for x86-64; Brian Raiter's [hello.asm](https://www.muppetlabs.com/~breadbox/software/tiny/hello.asm.txt)
is 62 bytes for i386 (13-char string).

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

## How 86 bytes works for ELF64 (down from 117)

ELF64 headers are bigger (ehdr=64, phdr=56) but the same overlap idea
applies. **`e_phoff=0x18`** is the unique minimum: it makes `p_type` read
`e_entry[0:4]=1`, `p_offset` read `e_phoff` itself (=0x18, small), and
`p_paddr` (don't-care) absorb the mandatory `e_phentsize=56`.

Since `e_entry` low 32 bits = `p_type` = 1, entry is forced to file byte 1.
Bytes 1-3 are "ELF" = `45 4C 46` = three REX prefixes; the CPU keeps the
last one and byte 4 becomes the first real opcode. A `cmp eax, imm32` at
byte 0x0F absorbs `e_type`/`e_machine` as its immediate; a short jmp at
0x16 lands in `p_paddr` (bytes 0x30-0x35) for the two `syscall`s.

```
00  7F 45 4C 46                magic; bytes 1-3 = REX×3, entry@1
04  B0 01 89 C7                mov al,1; mov edi,eax
08  48 8D 35 39 00 00 00       lea rsi,[rip+0x39]  → string@0x48
0F  3D 02 00 3E 00             cmp eax,imm32 (eats e_type/e_mach)
14  B2 0E EB 18                mov dl,14; jmp 0x30
18  01 00 00 00 05 00 00 00    e_entry = p_type|p_flags<<32
20  18 00 00 00 00 00 00 00    e_phoff = p_offset = 0x18
28  18 00 00 00 05 00 00 00    e_shoff = p_vaddr = 0x500000018
30  0F 05 B0 3C 0F 05          p_paddr: syscall; mov al,60; syscall
36  38 00 01 00 …              e_phentsize/e_phnum = p_paddr[6:]/p_filesz
40  01 00 00 00 00 00 00 00    p_memsz=1 (=filesz; no BSS clear)
48  "Hello, world!\n"          p_align[0:8] + 6 trailing
```

The string lives in `p_align` (unchecked) plus 6 bytes past the phdr.
`p_memsz[6:8]` @ 0x46-0x47 must be 0 (else `vaddr+memsz` exceeds the
47-bit user VA limit), so the earliest the string can start is 0x48 →
file = 0x48 + 14 = 86. Probe results in `NOTES.md`.
