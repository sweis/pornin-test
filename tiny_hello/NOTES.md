# Tiny Hello — getting below 76 bytes

Goal: ELF binary that prints "Hello World", ≤50 bytes.

## Results

| File | Size | Output | Exit | Self-contained? |
|------|------|--------|------|-----------------|
| `tiny_hello` (old) | 76 | `Hello World\n` | 1 | yes |
| `hello58` | **58** | `Hello World\n` | 12 | yes |
| `hello57` | **57** | `Hello World` | 11 | yes |
| `hello45_argv` | **45** | argv[0] | SEGV | no — caller sets argv[0] |

**76 → 58 = −18 bytes (−24%)** for the honest self-contained version.
The 45-byte variant meets the ≤50 goal but requires `exec -a $'Hello World\n' ./hello45_argv`.

## Kernel 6.12 probe results

These were the load-bearing discoveries (probe.py / probe2.py):

- **EI_CLASS, EI_DATA, EI_VERSION: NOT checked.** Kernel only validates magic + e_machine + e_type + e_phentsize.
- **e_ehsize, e_shoff, e_flags, p_align, p_paddr: NOT checked.**
- **e_phentsize MUST be exactly 32** (kernel-enforced).
- **e_machine ∈ {3, 6}** (EM_386 or EM_486).
- **e_type ∈ {2, 3}** (ET_EXEC or ET_DYN).
- **PF_R-only works** for ia32: missing PT_GNU_STACK → READ_IMPLIES_EXEC.
- **p_filesz past EOF: OK.** mmap succeeds; access past page 0 → SIGBUS (we never go there).
- **vaddr+memsz < ~0xFFFFE000** (ia32 TASK_SIZE). vaddr ≤ 0x7FFFE000 safe.
- **e_phnum is u16 at 0x2C-0x2D** — byte 0x2D must be 0 if file > 45 bytes.

The old README's "76-byte floor" assumed e_phoff < 44 was infeasible. It isn't.

## The e_phoff=4 structure (Brian Raiter's trick)

With `e_phoff=4`, the 32-byte phdr overlaps bytes 4-35 of the 52-byte ehdr:

```
00-03  7F 45 4C 46    magic
04-07  01 00 00 00    EI_CLASS=1 → p_type=PT_LOAD
08-0B  p_offset       (must be < 4096; ≡ p_vaddr mod 4096)
0C-0F  p_vaddr        (≥ 0x10000)
10-13  02 00 03 00    e_type/e_machine → p_paddr (ignored)
14-17  p_filesz       (≤ p_memsz)
18-1B  e_entry        = p_memsz
1C-1F  04 00 00 00    e_phoff → p_flags=PF_R
20-23  e_shoff        → p_align (ignored)
24-29  e_flags+e_ehsize (ignored)
2A-2B  20 00          e_phentsize=32 (enforced)
2C-2D  01 00          e_phnum=1 (2D may come from bprm zero-fill if file=45)
```

**e_phoff=4 is unique** for e_phoff ≤ 18: it's the only value where
p_type lands on a 01 00 00 00 (from EI_CLASS) AND p_flags lands on a
byte with PF_R set (e_phoff itself) AND p_memsz ≥ p_filesz is satisfiable
AND p_offset can be < 4096. Exhaustive check of e_phoff ∈ [0,18] is in
the session log.

## Why 58 is the self-contained floor

**Hard-fixed bytes** (19 total): 0x00-0x07, 0x10-0x13, 0x1C-0x1F, 0x2A-0x2C.
Plus byte 0x2D=0 if file > 45.

**Max contiguous free span before 0x2E: 10 bytes** (0x20-0x29). The
12-byte string "Hello World\n" cannot fit there, and every 12-byte
window touching 0x10-0x13 / 0x1C-0x1F / 0x2A-0x2D fails (none of those
fixed sequences appear in the string). Checked all alignments.

So the string must start at 0x2E → file ≥ 58.

A brute-force search (`search50.py`) confirmed this and also found a
second 58-byte solution: push-based, flowing *through* `20 00 01 00` as
`and [eax],al; add [eax],eax` with eax=esp (stack is writable). That
approach also bottoms out at 58 — restoring eax=4 after the corruption
costs exactly the bytes saved. Two independent constructions converging
on 58 is strong evidence of optimality.

**Can the string overlap p_filesz/e_entry (0x14-0x1B)?** "Hello Wo" there
gives e_entry=0x6F57206F → entry_off = 0x6F (file offset 111). Every
8-byte substring of "Hello World\n" gives entry_off ≥ 0x6F. Dead.

**Can we push the string to stack (3×push imm32 = 15B)?** Total code
becomes 22B (with eax=4 from the e_phoff trick). Available code budget
across 0x14-0x17 + 0x1A + 0x20-0x29 is ~15B (after accounting for
e_entry-byte constraints and the 0x2A-0x2D wall). Short by 7B; spilling
to 0x2E+ gives file ≥ 53, but the push-at-0x14 collides with byte
0x18=entry_off (no string dword has a usable last byte). Dead.

## The 58-byte execution flow

`D = p_vaddr = 0x05430000` chosen so `e_entry = D+0x14 = 05 43 00 14`
in LE = `14 00 43 05` — those four bytes are *executed*:

```
14: B2 0C       mov dl, 12
16: B0 00       mov al, 0        ; byte 17=00 keeps p_filesz ≤ p_memsz
18: 14 00       adc al, 0        ; e_entry[0:2], harmless
1A: 43          inc ebx          ; e_entry[2], ebx=1=stdout
1B: 05 04 00 00 00  add eax, 4   ; e_entry[3] + e_phoff as imm32 → eax=4=SYS_write
20: B9 2E 00 43 05  mov ecx, D+0x2E
25: CD 80       int 0x80         ; write(1, str, 12)
27: 93          xchg eax, ebx    ; eax=1
28: CD 80       int 0x80         ; exit(12)
2A: 20 00       (e_phentsize, unreached)
2C: 01 00       (e_phnum)
2E: "Hello World\n"
```

The `inc ebx` and `add eax,4` come *for free* from e_entry/e_phoff bytes
— that's why no `mov al,4` is needed and bytes 0x16-0x17 can be the
no-op `mov al,0` (only there to keep p_filesz's top byte ≤ 0x05).

## The 45-byte argv variant

Prints the first 12 bytes of argv[0]. 9 bytes of code at 0x20-0x29:
`pop eax; pop ecx; inc ebx; mov dl,12; mov al,4; int 0x80; xchg eax,ebx`.
Then falls into `and [eax],al` at 0x2A → SEGV (after the write).

Invocation: `bash -c 'exec -a $'"'"'Hello World\n'"'"' ./hello45_argv'`
or via Python `subprocess.run(['Hello World\n'], executable='./hello45_argv')`.

## Cross-check: Raiter's hello.asm

Brian Raiter's [hello.asm](https://www.muppetlabs.com/~breadbox/software/tiny/hello.asm.txt)
uses the *same* `D=0x05430000` trick (independently rediscovered here)
but enters at `0x1A` instead of `0x14`, and uses `and eax, 0x10020` at
byte `0x29` to absorb `e_phentsize`+`e_phnum` as an imm32, then exits
at `0x2E-0x30`. String at `0x31`. For a 12-char string that's **61 bytes**.

This version saves 3 bytes by:
- Entry at `0x14`: bytes `0x14-0x17` become code (`mov dl,12; mov al,0`),
  with `p_filesz = 0x00B00CB2` still ≤ `p_memsz`.
- Exit (`xchg; int 80`) fits at `0x27-0x29`, *before* the `0x2A` wall —
  no absorber needed, string starts at `0x2E` instead of `0x31`.

Raiter's [teensy.html](https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html)
confirms 45 bytes is the absolute floor for any i386 ELF (byte `0x2C` =
`e_phnum` must exist). His page predates the kernel's `e_phentsize==32`
check; that check IS enforced on 6.12.

## ELF64 (86 bytes)

Kernel 6.12 ELF64 probe results (probe64.py):
- EI_CLASS/EI_DATA/EI_VERSION/e_ehsize/e_shnum/p_align: NOT checked.
- e_phentsize MUST be 56.
- p_flags MUST include PF_X (no READ_IMPLIES_EXEC for x86-64). PF_R also
  needed in practice — `write()` reads the buffer; PF_X-only maps it
  exec-only and the syscall returns -EFAULT.

`e_phoff=0x18` is the unique minimum for ELF64. Smaller values put
e_type/e_machine (`02 00 3E 00` @ 0x10-0x13) into `p_offset` or `p_vaddr`
high bytes, making them ≥ 2^32. At 0x18:
- p_type @ 0x18 = e_entry[0:4] = 1
- p_flags @ 0x1C = e_entry[4:8] (set to 5 = PF_R|PF_X)
- p_offset @ 0x20 = e_phoff = 0x18 (small ✓)
- p_paddr @ 0x30-0x37 absorbs e_phentsize/e_phnum-low (don't-care)
- p_filesz @ 0x38: low byte forced to 01 by e_phnum

`e_entry & 0xFFFFFFFF = 1` forces entry at file byte 1. Bytes 1-3 = "ELF"
= `45 4C 46` = three REX prefixes; CPU keeps the last (REX.RX), making
byte 4 the first opcode. Tested on this CPU: works (no #UD). Byte 4 =
`B0` (`mov al,1`) overrides REX anyway since it's a 1-byte-opcode form.

String must start ≥ 0x48: p_memsz @ 0x40-0x47 has bytes 0x46-0x47 forced
≤ small (vaddr+memsz < 2^47 task-size limit). 0x48 + 14 = 86.

## Dead ends (don't retry)

- e_phoff ∈ {0-3, 5-18}: all fail p_type/p_flags/p_offset/p_memsz constraints.
- ET_DYN: e_entry = p_memsz forces entry at end-of-mapping (zeros). PIC overhead +4B doesn't help.
- writev with header-as-iovec: iovec[0].base inevitably = e_entry → entry at "Hell" → insb fault.
- String-as-code: 'l'=0x6C=insb, 'o'=0x6F=outsw — both fault in ring 3.
- Two writes ("Hell"@0x14 + "o World\n"@0x20): code cost (21B+) exceeds savings.
- p_vaddr < 0x10000: mmap_min_addr blocks (we're not root).
- vaddr ≥ 0x80000000: vaddr+memsz overflow → SEGV.
