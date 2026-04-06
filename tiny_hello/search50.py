#!/usr/bin/env python3
"""Brute-force search for ≤50-byte i386 ELF that prints 'Hello World\\n'.

Strategy:
  1. Exhaustively check every string placement in a ≤50-byte file against
     the hard-fixed header bytes (allowing matches).
  2. For push-based: enumerate code layouts that fit pushes + setup in the
     choosable regions, build candidates, exec them.
  3. For each candidate that passes static checks: actually exec and verify.
"""
import struct, os, subprocess, itertools, sys

STRING = b"Hello World\n"
TARGET = STRING

# Hard-fixed bytes for e_phoff=4 (offset → required value).
# e_type ∈ {2,3}, e_machine ∈ {3,6} — try all 4 combos.
def fixed_bytes(e_type, e_mach, file_len):
    f = {
        0x00: 0x7F, 0x01: 0x45, 0x02: 0x4C, 0x03: 0x46,
        0x04: 0x01, 0x05: 0x00, 0x06: 0x00, 0x07: 0x00,
        0x10: e_type, 0x11: 0x00, 0x12: e_mach, 0x13: 0x00,
        0x1C: 0x04, 0x1D: 0x00, 0x1E: 0x00, 0x1F: 0x00,
        0x2A: 0x20, 0x2B: 0x00, 0x2C: 0x01,
    }
    if file_len > 45:
        f[0x2D] = 0x00
    return f

def try_exec(e, label=""):
    fn = "/tmp/s50_cand"
    with open(fn, 'wb') as fh: fh.write(bytes(e))
    os.chmod(fn, 0o755)
    try:
        r = subprocess.run([fn], capture_output=True, timeout=2)
        ok = r.stdout == TARGET
        if ok:
            print(f"  *** SUCCESS *** {label} size={len(e)} rc={r.returncode}")
            for i in range(0, len(e), 16):
                h = ' '.join(f'{b:02X}' for b in e[i:i+16])
                print(f"    {i:04X}  {h}")
        return ok, r.stdout, r.returncode
    except subprocess.TimeoutExpired:
        return False, b"", "TIMEOUT"
    except OSError as ex:
        return False, b"", f"ENOEXEC"

# ============================================================================
# Phase 1: Contiguous string placement — does ANY offset let the string
# coexist with fixed bytes in a ≤50-byte file?
# ============================================================================
print("=== Phase 1: contiguous string placement scan ===")
found_placement = False
for et, em in itertools.product([2, 3], [3, 6]):
    for N in range(45, 51):
        fb = fixed_bytes(et, em, N)
        for S in range(0, N - len(STRING) + 1):
            ok = True
            for i, ch in enumerate(STRING):
                off = S + i
                if off in fb and fb[off] != ch:
                    ok = False
                    break
            if ok:
                # Also: bytes 0x08-0x0B (p_offset) must encode value < 4096
                # bytes 0x0C-0x0F (p_vaddr) must be ≥ 0x10000
                # If string covers those, check.
                # (We'll just report the placement; constraints checked in build.)
                print(f"  placement: e_type={et} e_mach={em} N={N} S={S:#x} "
                      f"(string fits without fixed-byte conflict)")
                found_placement = True
if not found_placement:
    print("  NONE — no contiguous placement of 'Hello World\\n' avoids fixed bytes in ≤50B")

# ============================================================================
# Phase 2: Push-based — try to fit 3×push + setup in ≤50 bytes.
#
# Code pieces (i386):
#   P1 = 68 72 6C 64 0A   push "rld\n"   (must be 1st push)
#   P2 = 68 6F 20 57 6F   push "o Wo"    (must be 2nd)
#   P3 = 68 48 65 6C 6C   push "Hell"    (must be 3rd)
#   MC = 89 E1            mov ecx, esp   (after P3)
#   MD = B2 0C            mov dl, 12
#   IB = 43               inc ebx
#   MA = B0 04            mov al, 4      (or eax=4 via header)
#   SY = CD 80            int 0x80       (last)
#
# Regions (entry at 0x14, D chosen for header-flow):
#   R1 = 0x14-0x17 (4B; byte 0x17 ≤ D>>24)
#   [0x18-0x19 = adc al, b19; b19 low-nibble 0]
#   R2 = 0x1A (1B = D>>16)
#   [0x1B = D>>24; 0x1C-0x1F absorbed if 0x1B ∈ {05,0D,15,25,2D,35,3D,68,A9,B8-BF}]
#   R3 = 0x20-0x28 (9B)
#   [0x29 = absorber ∈ {3D,A9,BD,BE,BF}; 0x2A-0x2D absorbed]
#   R4 = 0x2E-(N-1)
#
# Constraints:
#   - Pushes P1,P2,P3 in that order (each 5B contiguous)
#   - MC after P3
#   - SY last
#   - eax=4 at SY: either MA somewhere, OR header sets it (0x1B=05 with al=0 before)
#
# The tightest packing: P1 in R3 (0x20-0x24), absorber at 0x29, P2+P3+MC+SY in R4.
# R4 needs 5+5+2+2=14B. R3 has 4B left (0x25-0x28) for MD+IB+?. R1 for MA-ish.
# N = 0x2E + 14 = 60. Unless setup compresses.
#
# Try alternative: flow THROUGH 0x2A-0x2D (not absorb) with eax=stack.
# ============================================================================
print("\n=== Phase 2: push-based layouts ===")

P1 = bytes([0x68, 0x72, 0x6C, 0x64, 0x0A])
P2 = bytes([0x68, 0x6F, 0x20, 0x57, 0x6F])
P3 = bytes([0x68, 0x48, 0x65, 0x6C, 0x6C])

results = []

# Layout A: entry@0x14, eax=esp early, flow through 0x2A-0x2D, eax reset late.
# 0x14: 89 E0 B2 0C   mov eax,esp; mov dl,12   (p_filesz=0x0C_B2_E0_89)
# 0x18: 14 00         adc al,0
# 0x1A: 43            inc ebx
# 0x1B: 3D 04 00 00 00  cmp eax,4  (eax≈esp unchanged)
# 0x20-0x29: P1 + P2
# 0x2A: 20 00  and [eax],al  (eax≈esp, [stack] OK)
# 0x2C: 01 00  add [eax],eax (OK)
# 0x2E: P3
# 0x33: 89 E1  mov ecx,esp
# 0x35: 6A 04 58  push 4; pop eax
# 0x38: CD 80  int 80
# N=0x3A=58
for N in [58]:
    D = 0x3D430000  # b1B=3D, b1A=43, b19=00
    e = bytearray(N)
    e[0:8] = b'\x7fELF\x01\x00\x00\x00'
    struct.pack_into('<I', e, 0x0C, D)
    struct.pack_into('<HH', e, 0x10, 2, 3)
    e[0x14:0x18] = bytes([0x89, 0xE0, 0xB2, 0x0C])
    struct.pack_into('<I', e, 0x18, D + 0x14)
    struct.pack_into('<I', e, 0x1C, 4)
    e[0x20:0x25] = P1
    e[0x25:0x2A] = P2
    struct.pack_into('<H', e, 0x2A, 32)
    e[0x2C] = 1; e[0x2D] = 0
    e[0x2E:0x33] = P3
    e[0x33:0x3A] = bytes([0x89, 0xE1, 0x6A, 0x04, 0x58, 0xCD, 0x80])
    pf = struct.unpack_from('<I', e, 0x14)[0]
    pm = struct.unpack_from('<I', e, 0x18)[0]
    if pf <= pm and D + pm < 0xFFFFE000:
        ok, out, rc = try_exec(e, f"LayoutA N={N}")
        results.append(('A', N, ok, out, rc))

# Layout B: same but try to shave — put `push 4;pop eax` BEFORE P3?
# After P2, eax≈esp. 0x2E: 6A 04 58 → push 4, pop eax. eax=4. But push 4 went on
# stack between P2 and P3! Stack: [4, oWo, rld\n]. Then P3: [Hell, 4, oWo, rld\n].
# write(esp,12) = "Hell" + 04 00 00 00 + "o Wo". ✗
# So push 4;pop eax must be AFTER P3. Can't shave.

# Layout C: absorber at 0x29, only 1 push before, 2 after.
# 0x14-0x17: B2 0C B0 04  mov dl,12; mov al,4  (byte 0x17=04)
# 0x18: 14 00  adc al,0 (al=4)
# 0x1A: 43  inc ebx
# 0x1B: 3D 04 00 00 00  cmp eax,4  (eax=4)
# 0x20-0x24: P1
# 0x25-0x28: 4B — useless (89 E1 here is wrong, pushes not done)
# 0x29: BD  mov ebp, imm32 (absorbs 0x2A-0x2D)
# 0x2E-0x32: P2
# 0x33-0x37: P3
# 0x38: 89 E1 CD 80
# N=0x3C=60 ✗

# Layout D: 2 pushes at 0x20-0x29, absorber would need to start at 0x2A — can't.
# Only way to survive 0x2A with 2 pushes done is eax=writable (Layout A).

# Layout E: entry@0x20, setup AFTER pushes via jmp-back.
# Doesn't fit; jmps cost too much.

# ============================================================================
# Phase 3: Exhaustive — try every entry_off, every D (sampled), build & exec.
# This catches anything the manual analysis missed.
# ============================================================================
print("\n=== Phase 3: targeted exec sweep (≤56B) ===")

# The only way to ≤56 is if SOME instruction sequence through the forced
# bytes 0x18-0x1F and 0x2A-0x2D happens to work. Let me try a grid:
#   - entry_off ∈ {0x0C, 0x14, 0x20}
#   - b19 ∈ {0x00, 0x10, ..., 0xF0}
#   - b1A ∈ useful 1-byte ops {43, 90, 40-47, 50-57, 91-97}
#   - b1B ∈ absorbers {05, 0D, 15, 2D, 35, 3D, 68, A9, B8-BF}
#   - layout: setup in 0x14-0x17, P1 at 0x20-0x24, ??? at 0x25-0x29,
#     then 0x2A-0x2D, then 0x2E+
# and see if ANY combination yields a ≤56-byte success.

count = 0
for N in range(46, 57):
    for b1B in [0x05, 0x0D, 0x15, 0x2D, 0x35, 0x3D, 0x68, 0xA9,
                0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF]:
        if b1B > 0x7F:  # vaddr+memsz overflow
            # Actually b1B=D>>24. D+D < 0xFFFFE000 → D < 0x7FFFF000.
            # b1B ≤ 0x7F. Skip A9,B8-BF.
            continue
        for b1A in [0x43, 0x90, 0x40, 0x41, 0x42, 0x91, 0x92, 0x93, 0x99]:
            for b19 in [0x00]:
                D = (b1B << 24) | (b1A << 16) | (b19 << 8)
                if D < 0x10000:
                    continue
                # Several code templates for 0x14-0x17 + tail at 0x2E+
                templates = []
                # T1: header sets eax (via 05/35), tail does pushes
                if b1B in (0x05, 0x35) and b1A == 0x43:
                    # 0x14: B2 0C ?? ??  with byte 0x17 ≤ b1B and al=0 after
                    # 0x18: 14 00 adc al,0
                    # 0x1A: 43 inc ebx
                    # 0x1B: 05/35 → eax=4
                    # 0x20-0x24: P1
                    # 0x25-0x28: 4B
                    # 0x29: absorber
                    # 0x2E+: P2 P3 mov ecx,esp int80
                    tail = P2 + P3 + bytes([0x89, 0xE1, 0xCD, 0x80])
                    if 0x2E + len(tail) <= N:
                        for pre in [bytes([0xB2,0x0C,0xB0,0x00]),
                                    bytes([0xB2,0x0C,0x24,0x00])]:
                            if pre[3] > b1B: continue
                            e = bytearray(N)
                            e[0:8] = b'\x7fELF\x01\x00\x00\x00'
                            struct.pack_into('<I', e, 0x0C, D)
                            struct.pack_into('<HH', e, 0x10, 2, 3)
                            e[0x14:0x18] = pre
                            struct.pack_into('<I', e, 0x18, D + 0x14)
                            struct.pack_into('<I', e, 0x1C, 4)
                            e[0x20:0x25] = P1
                            e[0x25:0x29] = bytes([0x90,0x90,0x90,0x90])
                            e[0x29] = 0x3D  # cmp eax,imm32 absorber
                            struct.pack_into('<H', e, 0x2A, 32)
                            e[0x2C]=1; e[0x2D]=0
                            e[0x2E:0x2E+len(tail)] = tail
                            pf = struct.unpack_from('<I', e, 0x14)[0]
                            pm = struct.unpack_from('<I', e, 0x18)[0]
                            if pf > pm: continue
                            count += 1
                            ok, out, rc = try_exec(e, f"T1 N={N} D={D:#x}")
                            if ok: results.append(('T1', N, ok, out, rc))
                # T2: eax=esp early, flow through 0x2A-0x2D, reset eax late
                if b1B == 0x3D and b1A == 0x43:
                    tail = P3 + bytes([0x89,0xE1, 0x6A,0x04,0x58, 0xCD,0x80])
                    if 0x2E + len(tail) <= N:
                        e = bytearray(N)
                        e[0:8] = b'\x7fELF\x01\x00\x00\x00'
                        struct.pack_into('<I', e, 0x0C, D)
                        struct.pack_into('<HH', e, 0x10, 2, 3)
                        e[0x14:0x18] = bytes([0x89,0xE0,0xB2,0x0C])
                        struct.pack_into('<I', e, 0x18, D + 0x14)
                        struct.pack_into('<I', e, 0x1C, 4)
                        e[0x20:0x25] = P1
                        e[0x25:0x2A] = P2
                        struct.pack_into('<H', e, 0x2A, 32)
                        e[0x2C]=1; e[0x2D]=0
                        e[0x2E:0x2E+len(tail)] = tail
                        pf = struct.unpack_from('<I', e, 0x14)[0]
                        pm = struct.unpack_from('<I', e, 0x18)[0]
                        if pf > pm: continue
                        count += 1
                        ok, out, rc = try_exec(e, f"T2 N={N} D={D:#x}")
                        if ok: results.append(('T2', N, ok, out, rc))

print(f"  tried {count} candidates")

# ============================================================================
# Summary
# ============================================================================
print("\n=== SUMMARY ===")
successes = [r for r in results if r[2]]
if successes:
    best = min(successes, key=lambda r: r[1])
    print(f"Best: {best[0]} at {best[1]} bytes")
else:
    print("No ≤56-byte self-contained success found.")
    print("Tightest constraint: 12-byte string needs contiguous space; max gap")
    print("before 0x2E is 10B (0x20-0x29). Push-based needs 3×5B contiguous")
    print("chunks; only ONE fits before the 0x2A wall, forcing 2 pushes + 4B")
    print("setup into 0x2E+ = 14B → file ≥ 60. Flow-through-0x2A needs eax=stack")
    print("then eax-reset (3B) → file ≥ 58.")
    print("→ 58 bytes is the self-contained floor.")
