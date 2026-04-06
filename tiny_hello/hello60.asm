; hello60.asm — 60-byte i386 ELF that prints "Hello, world!\n"
; Build: nasm -f bin -o hello60 hello60.asm && chmod +x hello60

BITS 32
        org   0x05430000

        db    0x7F, "ELF"       ; 00: magic
        dd    1                 ; 04: EI_CLASS=1       / p_type=PT_LOAD
        dd    0                 ; 08: e_ident pad      / p_offset=0
        dd    $$                ; 0C: e_ident pad      / p_vaddr=0x05430000
        dw    2                 ; 10: e_type=ET_EXEC   / p_paddr lo
        dw    3                 ; 12: e_machine=EM_386 / p_paddr hi
_start:                         ; ----- e_entry points here (0x05430014) -----
        mov   dl, msg.len       ; 14: e_version        / p_filesz  (B2 0E)
        mov   al, 0             ; 16:   "              /   "       (B0 00)
        ; bytes 18-1B = e_entry/p_memsz = 14 00 43 05, executed as:
        db    0x14, 0x00        ; 18:   adc al, 0        (e_entry[0:2])
        db    0x43              ; 1A:   inc ebx          (e_entry[2]) → ebx=1
        db    0x05              ; 1B:   add eax, imm32   (e_entry[3])
        dd    4                 ; 1C: e_phoff=4/p_flags=PF_R; imm32 → eax=4
        mov   ecx, msg          ; 20: e_shoff/p_align/e_flags
        int   0x80              ; 25:   write(1, msg, len)
        xchg  eax, ebx          ; 27:   eax=1
        int   0x80              ; 28:   exit(len)
        dw    32                ; 2A: e_phentsize=32
        dw    1                 ; 2C: e_phnum=1
msg:    db    'Hello, world!', 10
.len    equ   $ - msg
