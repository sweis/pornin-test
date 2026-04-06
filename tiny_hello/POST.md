# Shrinking "Hello, world!" ELF binaries: 76→58 (i386) and 120→86 (x86-64)

How small can a Linux executable that prints `Hello, world!` actually be?
Starting from the prior community benchmarks — Brian Raiter's
[62-byte i386 hello](https://www.muppetlabs.com/~breadbox/software/tiny/hello.asm.txt)
and Nathan Otterness's
[120-byte x86-64 hello](https://nathanotterness.com/2021/10/tiny_elf_modernized.html) —
here's how to take a few more bytes off each.

## Background: what the kernel actually checks

An ELF file has two headers: the ELF header (`ehdr`, 52/64 bytes) tells
the kernel where to find the program header (`phdr`, 32/56 bytes), which
tells it what to map into memory. Almost everything else is optional.

Probing kernel 6.12 turned up the actual hard rules:

| Field | i386 | x86-64 |
|---|---|---|
| Magic `7F 45 4C 46` | required | required |
| `e_type` | 2 or 3 | 2 or 3 |
| `e_machine` | 3 or 6 | 0x3E |
| `e_phentsize` | exactly 32 | exactly 56 |
| `e_phnum` | ≥ 1 | ≥ 1 |
| `p_type` | 1 (PT_LOAD) | 1 (PT_LOAD) |
| `p_flags` | any with PF_R | must include PF_X |
| **everything else** | **ignored** | **ignored** |

`EI_CLASS`, `EI_DATA`, `e_ehsize`, `e_shoff`, `e_flags`, `p_align`,
`p_paddr` — all unchecked. That's a lot of bytes to repurpose.

## i386: 58 bytes

**Step 1 — Set `e_phoff = 4`.** This makes the 32-byte program header
overlay bytes 4–35 of the ELF header. `p_type` now reads byte 4
(`EI_CLASS=1`) as `PT_LOAD=1`, and `p_flags` reads `e_phoff` itself
(value 4) as `PF_R`. This is Raiter's
[45-byte trick](https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html);
on 32-bit, missing `PT_GNU_STACK` triggers `READ_IMPLIES_EXEC`, so PF_R
alone is enough.

**Step 2 — Pick a load address whose bytes are also instructions.** With
entry at file offset `0x14`, `e_entry` (which doubles as `p_memsz`) is
`load_addr + 0x14`. Choose `load_addr = 0x05430000` so `e_entry`
encodes as `14 00 43 05`:

```
14 00   adc al, 0      ; harmless
43      inc ebx        ; ebx=1 (stdout)
05 ..   add eax, imm32 ; imm32 = next 4 bytes = e_phoff = 4 → eax=4 (SYS_write)
```

Two register setups recovered from mandatory header bytes.

**Step 3 — Pack the rest into the gaps.** `mov dl,len` goes into
`p_filesz`; `mov ecx,str; int 80h; xchg; int 80h` fits in `e_shoff`
through `e_ehsize` (all unchecked). The string starts at `0x2E`, right
after `e_phnum`.

```
00  7F 45 4C 46 01 00 00 00  00 00 00 00 00 00 43 05
10  02 00 03 00 B2 0C B0 00  14 00 43 05 04 00 00 00
20  B9 2E 00 43 05 CD 80 93  CD 80 20 00 01 00 .string.
```

58 bytes for `Hello World\n`, 60 for `Hello, world!\n`. Raiter's version
enters at `0x1A` and uses an `and eax,imm32` to step *over* the
`e_phentsize` bytes; entering at `0x14` and exiting *before* them saves 3.

## x86-64: 86 bytes

ELF64 headers are bigger and the layout is different — `p_flags` sits
right after `p_type`, and x86-64 doesn't get `READ_IMPLIES_EXEC`, so
the 32-bit trick doesn't transfer directly.

**Step 1 — Set `e_phoff = 0x18`.** This is the smallest value that
works: `p_type` reads `e_entry[0:4]`, `p_offset` reads `e_phoff` itself
(=0x18, small enough), and `p_paddr` (don't-care) lands on the mandatory
`e_phentsize`. Anything smaller pushes `e_type`/`e_machine` into
`p_offset`'s high bytes, making it ≥ 4 GB.

**Step 2 — Live with entry at byte 1.** Since `e_entry[0:4] = p_type = 1`,
the entry address ends in `...0001` — file byte 1, mid-magic. Bytes 1–3
are `"ELF"` = `45 4C 46`, which decode as three REX prefixes. The CPU
keeps the last one and treats byte 4 as the opcode, so put real code there.

**Step 3 — Absorb the fixed bytes as immediates.** A `cmp eax, imm32`
at byte `0x0F` swallows `e_type`/`e_machine` (`02 00 3E 00`) as its
operand. A short `jmp` at `0x16` hops over `e_entry`/`e_phoff`/`p_vaddr`
into `p_paddr` for the two `syscall` instructions.

**Step 4 — String in `p_align`.** Bytes `0x48–0x4F` are `p_align`
(unchecked), giving 8 free bytes; the remaining 6 trail off the end.

```
00  7F 45 4C 46 B0 01 89 C7  48 8D 35 39 00 00 00 3D   mov al,1; mov edi,eax; lea rsi,[rip+str]; cmp eax,
10  02 00 3E 00 B2 0E EB 18  01 00 00 00 05 00 00 00   <e_type/mach>; mov dl,14; jmp 0x30 | e_entry=p_type/p_flags
20  18 00 00 00 00 00 00 00  18 00 00 00 05 00 00 00   e_phoff=p_offset | p_vaddr
30  0F 05 B0 3C 0F 05 38 00  01 00 00 00 00 00 00 00   syscall; mov al,60; syscall | phentsize/phnum/filesz
40  01 00 00 00 00 00 00 00  "Hello, world!\n"         p_memsz | p_align+tail = string
```

86 bytes. Otterness overlapped 8 bytes of header; this overlaps 40.

## Why not smaller?

Both floors come down to one thing: a handful of small integers
(`p_type=1`, `e_phoff=4`, `e_phentsize=32`, `e_phnum=1`) sit at fixed
offsets, and their high bytes are zero. Those zeros aren't padding —
they're the upper bits of the numbers. The longest run of bytes you can
freely choose is 10 (i386) or 14 (x86-64), and the string is longer than
either, so it has to go after the last forced byte. Add the string
length to that offset and you get the floor.

## References

- Brian Raiter, [*A Whirlwind Tutorial on Creating Really Teensy ELF Executables*](https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html) — the original 45-byte analysis
- Brian Raiter, [hello.asm](https://www.muppetlabs.com/~breadbox/software/tiny/hello.asm.txt) — the `0x05430000` trick
- Nathan Otterness, [*Tiny ELF Files: Revisited in 2021*](https://nathanotterness.com/2021/10/tiny_elf_modernized.html) — modern x86-64 baseline
- tmp.0ut #3, [*Cramming a Tiny Program into a Tiny ELF File*](https://tmpout.sh/3/22.html) — x86-64 syscall-return tricks
