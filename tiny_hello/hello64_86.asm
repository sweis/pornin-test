; hello64_86.asm — 86-byte x86-64 ELF that prints "Hello, world!\n"
; Build: nasm -f bin -o hello64_86 hello64_86.asm && chmod +x hello64_86

BITS 64
        org   0x500000000

        db    0x7F                   ; 00: magic[0]
_start:                              ; entry @ byte 1: "ELF" = 3 REX prefixes
        db    "ELF"                  ; 01: magic[1:4] = 45 4C 46 = REX.B,.WR,.RX
        mov   al, 1                  ; 04: e_ident pad — first real opcode
        mov   edi, eax               ; 06:   rdi=1 (stdout)
        lea   rsi, [rel msg]         ; 08:   rsi=&msg (rip-relative)
        db    0x3D                   ; 0F: cmp eax, imm32 — eats next 4 bytes:
        dw    2                      ; 10: e_type=ET_EXEC
        dw    0x3E                   ; 12: e_machine=EM_X86_64
        mov   dl, msg.len            ; 14: e_version
        jmp   tail                   ; 16:   → 0x30 (p_paddr)
        dd    1                      ; 18: e_entry[0:4]  / p_type=PT_LOAD
        dd    5                      ; 1C: e_entry[4:8]  / p_flags=PF_R|PF_X
        dq    0x18                   ; 20: e_phoff       / p_offset = 0x18
        dq    $$ + 0x18              ; 28: e_shoff       / p_vaddr
tail:   syscall                      ; 30: e_flags…      / p_paddr — write()
        mov   al, 60                 ; 32:
        syscall                      ; 34:                 — exit()
        dw    56                     ; 36: e_phentsize=56
        dw    1                      ; 38: e_phnum=1     / p_filesz[0:2]
        dw    0, 0, 0                ; 3A: e_sh*         / p_filesz[2:8]
        dq    1                      ; 40:               / p_memsz=1
msg:    db    'Hello, world!', 10    ; 48:               / p_align + tail
.len    equ   $ - msg
