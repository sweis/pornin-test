; tiny_hello.asm — 76-byte ELF32 "Hello World\n"
;
; Build: nasm -f bin -o tiny_hello tiny_hello.asm && chmod +x tiny_hello
;   (or: python3 gen_hello.py)
;
; Tricks used:
;   1. 32-bit ELF (ehdr=52, phdr=32) instead of 64-bit (ehdr=64, phdr=56)
;   2. 8-byte ehdr/phdr overlap: phdr starts at e_phoff=44 (inside ehdr)
;   3. Code embedded in e_ident[8..15], e_version, e_shoff, e_flags
;   4. String "Hello World\n" stored AS p_memsz + p_flags + p_align
;   5. Fall-through from e_ident into e_machine→e_version using the
;      "add al, al" decoded from bytes 0x00 0xC0 (e_machine_hi, e_version_lo)
;   6. Linux zeroes all GPRs on exec → no explicit register clearing needed
;   7. p_flags = "o Wo" = 0x6F57206F has PF_R|PF_W|PF_X all set
;   8. p_memsz = "Hell" = 0x6C6C6548 (~1.8 GB, lazily allocated)
;
; Register state on entry (Linux guarantees all zero for 32-bit ELF exec):
;   eax=0, ebx=0, ecx=0, edx=0, esi=0, edi=0
;
; Execution flow:
;   0x08: mov ecx, 0x10040    ; string VA = load_addr + 64
;   0x0D: mov dl, 12          ; strlen("Hello World\n")
;   0x0F: jmp short +2        ; offset = e_type = 2 → skip to byte 19
;   0x13: add al, al          ; bytes 19-20 (0x00 0xC0): harmless NOP
;   0x15: inc ebx             ; ebx: 0 → 1 = stdout
;   0x16: jmp short +8        ; → byte 32
;   0x20: mov al, 4           ; sys_write
;   0x22: int 0x80            ; write(1, "Hello World\n", 12)
;   0x24: mov al, 1           ; sys_exit
;   0x26: int 0x80            ; _exit(1)

BITS 32
org 0x00010000

; === ELF Header (52 bytes) ===
ehdr:
    db  0x7F, "ELF"            ; 00: e_ident[0..3] magic
    db  1, 1, 1, 0             ; 04: class=32, data=LE, ver=1, osabi=0

_start:                         ; 08: entry point (in e_ident[8..15])
    mov ecx, str               ; 08: B9 40 00 01 00
    mov dl, str.len             ; 0D: B2 0C
    jmp short .past_hdr         ; 0F: EB 02

    ; bytes 10-11 = e_type
    dw  2                       ; 10: ET_EXEC

    ; bytes 12-13 = e_machine
    dw  3                       ; 12: EM_386

    ; Execution lands at byte 13 (0x00 from e_machine high byte)
    ; 0x00 0xC0 = "add al, al" (register-only, harmless)
.past_hdr:                      ; byte 19 really, but the label here is for the
                                ; reader — NASM org math handles the rest

    ; bytes 14-17 = e_version (we embed code here)
    db  0xC0                    ; 14: ModRM for add al,al
    inc ebx                     ; 15: 43 — ebx = 1 (stdout fd)
    jmp short .write            ; 16: EB 08 → byte 32

    ; 18-1B: e_entry
    dd  _start                  ; 18: 0x00010008

    ; 1C-1F: e_phoff
    dd  phdr                    ; 1C: 44 = 0x2C

.write:                         ; 20: in e_shoff
    ; 20-23: e_shoff (abused for code)
    mov al, 4                   ; 20: B0 04 — sys_write
    int 0x80                    ; 22: CD 80

    ; 24-27: e_flags (abused for code)
    mov al, 1                   ; 24: B0 01 — sys_exit
    int 0x80                    ; 26: CD 80

    ; 28-29: e_ehsize
    dw  52                      ; 28: 0x34

    ; 2A-2B: e_phentsize
    dw  32                      ; 2A: 0x20

; === Phdr overlaps last 8 bytes of ehdr ===
phdr:
    ; 2C-2D: e_phnum = 1 / p_type low
    dw  1
    ; 2E-2F: e_shentsize = 0 / p_type high
    dw  0
    ; → p_type = 0x00000001 = PT_LOAD

    ; 30-31: e_shnum = 0 / p_offset low
    dw  0
    ; 32-33: e_shstrndx = 0 / p_offset high
    dw  0
    ; → p_offset = 0

; === Phdr continued (non-overlapping, bytes 52-75) ===
    dd  0x00010000              ; 34: p_vaddr
    dd  0                       ; 38: p_paddr (unused)
    dd  fileend - ehdr          ; 3C: p_filesz = 76

str:                            ; 40: p_memsz + p_flags + p_align = string
    db  "Hello World", 10       ; "Hello World\n" = 12 bytes
.len equ $ - str
fileend:
