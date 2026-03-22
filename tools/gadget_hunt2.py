#!/usr/bin/env python3
"""
Gadget-hunt pass 2: deeper analysis.
Focus on:
  - TRUE frameshift (odd byte offsets only)
  - Clean-terminated runs (those ending at 0x00 — jumpable tail)
  - cN's 00 00 00 00 region as terminator zone
  - Cross-stream matches (bc_v1 ops appearing in bc_rcb, etc.)
  - 2-byte single-op matches (which specific ops already exist elsewhere)
  - Remap feasibility
"""

import sys
from collections import defaultdict, Counter

limb8_text    = open('/tmp/limb8_text.bin',   'rb').read()
limb11_text   = open('/tmp/limb11_text.bin',  'rb').read()
limb11_rodata = open('/tmp/limb11_rodata.bin','rb').read()

# Stream extraction (ops only, no END byte)
L8_BC  = {'bc_rcb': limb8_text[0x000:0x056],
          'bc_v3':  limb8_text[0x057:0x065],
          'bc_v1':  limb8_text[0x066:0x0a0]}
L11_BC = {'bc_rcb': limb11_rodata[0x000:0x056],
          'bc_v3':  limb11_rodata[0x057:0x06d],
          'bc_v1':  limb11_rodata[0x06e:0x0be]}

# Constants as raw bytes
L8_CONST = {'cGX': limb8_text[0x156:0x176],
            'cGY': limb8_text[0x176:0x196],
            'cN':  limb8_text[0x196:0x1b6]}
L11_CONST = {'cN':   limb11_rodata[0x0bf:0x0df],
             'cR2N': limb11_rodata[0x0df:0x0ff],
             'cGX':  limb11_rodata[0x0ff:0x11f],
             'cGY':  limb11_rodata[0x11f:0x13f]}

# Jump tables
L8_JT  = limb8_text[0x14c:0x156]
L11_JT = limb11_text[0x000:0x00b]

# Native code (non-bytecode, non-constant)
L8_NATIVE  = limb8_text[0x0a1:0x14c] + limb8_text[0x1b6:]
L11_NATIVE = limb11_text[0x00b:]

L11_OPS = {0:'Fmul', 1:'Fadd', 2:'Fsub', 3:'Nmul', 4:'CHKLT',
           5:'CHKZ', 6:'INV', 7:'NORM', 8:'SET1', 9:'COPY', 10:'COPYHI'}
L8_OPS  = {0:'Fmul', 1:'SQR', 2:'Fadd', 3:'Fsub', 4:'Nmul',
           5:'CHKLT', 6:'CHKZ', 7:'CHKNZ', 8:'MULCN', 9:'INV'}

def decode(b0, b1, ops):
    if b0 == 0: return None
    oc = b0 & 0xF
    if oc not in ops: return None
    return (ops[oc], b1>>4, b1&0xF, b0>>4)

# ─────────────────────────────────────────────────────────────────────
# A) TRUE frameshift: odd-offset reads ONLY
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("A) TRUE FRAMESHIFT: bc_rcb read at ODD byte offsets")
print("="*72)
print("  Reads the BYTE STREAM at offset 1, 3, 5, ... — each 'op' is")
print("  the b1 of op[k] + b0 of op[k+1]. If valid → parallel op stream.")
print()

for label, bc, ops in [('limb8', L8_BC['bc_rcb'], L8_OPS),
                       ('limb11', L11_BC['bc_rcb'], L11_OPS)]:
    # Read from byte 1, stride 2
    shifted_ops = []
    for i in range(1, len(bc)-1, 2):
        d = decode(bc[i], bc[i+1], ops)
        shifted_ops.append((i, bc[i], bc[i+1], d))
    valid = [x for x in shifted_ops if x[3] is not None]
    print(f"  {label}/bc_rcb: {len(shifted_ops)} frameshifted positions, {len(valid)} valid")
    # Find longest run of consecutive valid
    runs = []
    cur = []
    for x in shifted_ops:
        if x[3] is not None:
            cur.append(x)
        else:
            if len(cur) >= 2:
                runs.append(cur)
            cur = []
    if len(cur) >= 2:
        runs.append(cur)
    runs.sort(key=lambda r: -len(r))
    for r in runs[:5]:
        ops_str = '; '.join(f"{d[0]}({d[1]},{d[2]},{d[3]})" for _,_,_,d in r)
        print(f"    run @ bytes {r[0][0]}..{r[-1][0]+1}  ({len(r)} ops):  {ops_str}")
    print()

# ─────────────────────────────────────────────────────────────────────
# B) Clean-terminated runs in constants (end at 0x00)
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("B) CLEAN-TERMINATED runs — runs followed by 0x00 byte")
print("="*72)
print("  A run ending at 0x00 is DIRECTLY dispatchable (no patching).")
print("  cN has a 4-byte 0x00 zone at offset 24-27 — prime real estate.")
print()

for label, consts, ops in [('limb8', L8_CONST, L8_OPS),
                           ('limb11', L11_CONST, L11_OPS)]:
    for cname, cdata in consts.items():
        # For each starting offset, walk forward until invalid OR 0x00
        for start in range(len(cdata)-1):
            j = start
            run = []
            while j+1 < len(cdata):
                d = decode(cdata[j], cdata[j+1], ops)
                if d is None:
                    term = (cdata[j] == 0x00)
                    break
                run.append((cdata[j], cdata[j+1], d))
                j += 2
            else:
                term = False
            if term and len(run) >= 1:
                # CLEAN: run of N ops, followed by 0x00.
                ops_str = '; '.join(f"{d[0]}({d[1]},{d[2]},{d[3]})" for _,_,d in run)
                print(f"  ★ {label}/{cname}[{start:2}]: {len(run)} ops + END → [{ops_str}]")

# ─────────────────────────────────────────────────────────────────────
# C) Single-op matches: which bytecode ops already exist as 2-byte
#    sequences elsewhere?
# ─────────────────────────────────────────────────────────────────────
print()
print("="*72)
print("C) SINGLE-OP EXACT MATCHES: 2-byte ops in bytecode that appear elsewhere")
print("="*72)
print("  (Informational — single-op reuse isn't a win by itself, but")
print("   density tells us how 'dense' the encoding space is.)")
print()

for label, bc_streams, consts, native, ops in [
    ('limb8',  L8_BC,  L8_CONST,  L8_NATIVE,  L8_OPS),
    ('limb11', L11_BC, L11_CONST, L11_NATIVE, L11_OPS),
]:
    # Collect all unique 2-byte ops across all streams
    all_ops = set()
    for sname, sbytes in bc_streams.items():
        for i in range(0, len(sbytes), 2):
            all_ops.add(sbytes[i:i+2])
    print(f"  {label}: {len(all_ops)} unique 2-byte op patterns used")

    # Search each in constants
    for cname, cdata in consts.items():
        hits = []
        for op in all_ops:
            pos = cdata.find(op)
            if pos >= 0:
                d = decode(op[0], op[1], ops)
                hits.append((pos, op, d))
        if hits:
            for pos, op, d in sorted(hits):
                print(f"    → {cname}[{pos:2}]: {op.hex()} = {d[0]}({d[1]},{d[2]},{d[3]})")

    # Search in native
    native_hits = 0
    for op in all_ops:
        if native.find(op) >= 0:
            native_hits += 1
    print(f"    → native code: {native_hits}/{len(all_ops)} ops appear somewhere")
    print()

# ─────────────────────────────────────────────────────────────────────
# D) Cross-stream gadgets: does any bc_v1/bc_v3 subsequence match a
#    bc_rcb position (aligned OR frameshifted)?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("D) CROSS-STREAM: bc_v1/bc_v3 sequences hiding inside bc_rcb")
print("="*72)
print("  bc_rcb is 86 B. If a tail of bc_v1 appears at ANY offset in")
print("  bc_rcb, we could dispatch there.")
print()

for label, bc_streams in [('limb8', L8_BC), ('limb11', L11_BC)]:
    rcb = bc_streams['bc_rcb'] + b'\x00'  # include terminator
    for sname in ['bc_v1', 'bc_v3']:
        sb = bc_streams[sname]
        # Find any ≥4 B substring of sb in rcb
        found = False
        for L in range(len(sb), 3, -1):
            for start in range(len(sb) - L + 1):
                sub = sb[start:start+L]
                pos = rcb.find(sub)
                if pos >= 0:
                    if not found:
                        print(f"  {label}/{sname} → {label}/bc_rcb:")
                        found = True
                    alignment = "aligned" if pos % 2 == 0 else "FRAMESHIFTED"
                    print(f"    {L} B @ {sname}[{start}..{start+L}] found at bc_rcb[{pos}] ({alignment})")
                    print(f"      bytes: {sub.hex()}")
            if found: break  # only report longest

# ─────────────────────────────────────────────────────────────────────
# E) The cN terminator zone — what ops END at offset 24?
# ─────────────────────────────────────────────────────────────────────
print()
print("="*72)
print("E) cN TERMINATOR ZONE — bytes 24-27 are 0x00 (both builds)")
print("="*72)
print("  cN low bytes: n mod 2^64 (or n-2 for limb8, which changes byte 0).")
print("  The high 16 bytes are ff*8 + 00*4 + ff*4 (P-256 n structure).")
print("  So: any 2-op run at offset 20 or 22 gets a free terminator at 24.")
print()

for label, cN, ops in [('limb8', L8_CONST['cN'], L8_OPS),
                       ('limb11', L11_CONST['cN'], L11_OPS)]:
    print(f"  {label}/cN bytes 16-28: {cN[16:28].hex()}")
    # The 8 0xff bytes at 16-23 have opcode nibble = 0xf → invalid in both.
    # So no ops can START in the ff zone. But bytes 14-15 might.
    for start in [12, 14, 20, 22]:
        if start+2 <= len(cN):
            b0, b1 = cN[start], cN[start+1]
            d = decode(b0, b1, ops)
            next_byte = cN[start+2] if start+2 < len(cN) else None
            print(f"    @ {start}: {b0:02x} {b1:02x}  decode={d}  next={next_byte:02x}" if next_byte else "")

# ─────────────────────────────────────────────────────────────────────
# F) What remaps would make a constant sequence match something useful?
# ─────────────────────────────────────────────────────────────────────
print()
print("="*72)
print("F) REMAP SEARCH: constant ops that match bc structure under slot permutation")
print("="*72)
print("  Q: can a permutation σ of slots make cGX[j:j+2k] == bc_rcb[i:i+2k]?")
print("  Requires: ∀ ops, (σ(s2)<<4)|oc_c == (σ'(s2)<<4)|oc_b  which means")
print("  opcodes MUST match verbatim; only slot nibbles can permute.")
print()

def opcode_only(bs):
    """Extract just the opcode sequence (low nibbles of even bytes)."""
    return bytes(bs[i] & 0xF for i in range(0, len(bs), 2))

for label, bc_streams, consts, ops in [('limb8', L8_BC, L8_CONST, L8_OPS),
                                        ('limb11', L11_BC, L11_CONST, L11_OPS)]:
    # For each bytecode stream, get opcode-only pattern
    for sname, sbytes in bc_streams.items():
        bc_opc = opcode_only(sbytes)
        # For each constant, at each offset, get opcode pattern
        for cname, cdata in consts.items():
            for start in range(len(cdata)-3):
                # Max match length: how many ops from here
                max_ops = (len(cdata) - start) // 2
                for L in range(min(max_ops, len(bc_opc)), 2, -1):
                    # Extract L ops from constant at this offset
                    cwin = cdata[start:start+2*L]
                    copc = bytes(cwin[i] & 0xF for i in range(0, len(cwin), 2))
                    # Valid opcodes?
                    if any(c not in ops for c in copc): continue
                    if any(cwin[i] == 0 for i in range(0, len(cwin), 2)): continue
                    # Match against bc opcode sequence
                    pos = bc_opc.find(copc)
                    if pos >= 0:
                        # Check if slot permutation is consistent
                        # Extract slot nibbles from both
                        bc_slots = []
                        c_slots  = []
                        for k in range(L):
                            bc_b0, bc_b1 = sbytes[2*(pos+k)], sbytes[2*(pos+k)+1]
                            c_b0,  c_b1  = cwin[2*k], cwin[2*k+1]
                            bc_slots.extend([bc_b0>>4, bc_b1>>4, bc_b1&0xF])  # s2, dst, s1
                            c_slots.extend( [c_b0>>4,  c_b1>>4,  c_b1&0xF])
                        # Check bijection: every time bc has slot X, c must have same Y
                        mapping = {}
                        inv_map = {}
                        consistent = True
                        for bs, cs in zip(bc_slots, c_slots):
                            if bs in mapping:
                                if mapping[bs] != cs:
                                    consistent = False; break
                            else:
                                if cs in inv_map:
                                    consistent = False; break
                                mapping[bs] = cs
                                inv_map[cs] = bs
                        if consistent and L >= 3:
                            print(f"  ★★ {label}/{sname}[op{pos}..op{pos+L}] ≡ {cname}[{start}:] under remap (L={L} ops):")
                            print(f"     bc : {sbytes[2*pos:2*(pos+L)].hex()}")
                            print(f"     con: {cwin.hex()}")
                            print(f"     map: {mapping}")
                            break  # only report longest per start

# ─────────────────────────────────────────────────────────────────────
# G) The inter-stream boundary — bc_rcb's END(0x00) + bc_v3 start
# ─────────────────────────────────────────────────────────────────────
print()
print("="*72)
print("G) INTER-STREAM BOUNDARY: bytes spanning stream transitions")
print("="*72)
print("  bc_rcb ends with 0x00 (END). Next byte is bc_v3[0].")
print("  Can we form a useful op from bc_rcb[-1] (last b1) + 0x00 (END)?")
print("  0x00 as b1 means dst=0, s1=0. bc_rcb[-1] as b0 determines op/s2.")
print()

for label, data, bounds in [
    ('limb8',  limb8_text,    [(0x055, 'rcb[-1]+END'), (0x056, 'END+v3[0]'),
                               (0x064, 'v3[-1]+END'),  (0x065, 'END+v1[0]'),
                               (0x09f, 'v1[-1]+END'),  (0x0a0, 'END+code')]),
    ('limb11', limb11_rodata, [(0x055, 'rcb[-1]+END'), (0x056, 'END+v3[0]'),
                               (0x06c, 'v3[-1]+END'),  (0x06d, 'END+v1[0]'),
                               (0x0bd, 'v1[-1]+END'),  (0x0be, 'END+cN[0]')]),
]:
    ops = L8_OPS if label == 'limb8' else L11_OPS
    for off, desc in bounds:
        b0, b1 = data[off], data[off+1]
        d = decode(b0, b1, ops)
        status = "END (b0=0)" if b0==0 else (str(d) if d else "invalid")
        print(f"  {label} @0x{off:03x} ({desc}): {b0:02x} {b1:02x} → {status}")

# ─────────────────────────────────────────────────────────────────────
# H) Summary stats
# ─────────────────────────────────────────────────────────────────────
print()
print("="*72)
print("H) ENCODING SPACE DENSITY")
print("="*72)
for label, ops in [('limb8 (ops 0-9)', L8_OPS), ('limb11 (ops 0-10)', L11_OPS)]:
    n_valid_b0 = sum(1 for b0 in range(256) if (b0 & 0xF) in ops and b0 != 0)
    print(f"  {label}: {n_valid_b0}/256 b0 values valid ({100*n_valid_b0/256:.0f}%), all 256 b1 valid")
    print(f"    → P(random 2-byte pair valid) ≈ {100*n_valid_b0/256:.0f}%")
    print(f"    → E[run length | random bytes] ≈ {1/(1-n_valid_b0/256):.1f} ops")
