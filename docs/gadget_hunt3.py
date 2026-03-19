#!/usr/bin/env python3
"""Gadget-hunt pass 3: fine-grained analysis of remaining leads.
- Which 2 ops in limb11 native match
- Deeper remap search (opcode-sequence only, then slot consistency)
- bc_rcb internal repeats (does bc_rcb have a self-repeat?)
- What would it COST to add a CALL op to the interpreter?
"""

from collections import defaultdict

limb8_text    = open('/tmp/limb8_text.bin',   'rb').read()
limb11_text   = open('/tmp/limb11_text.bin',  'rb').read()
limb11_rodata = open('/tmp/limb11_rodata.bin','rb').read()

L8_BC  = {'bc_rcb': limb8_text[0x000:0x056],
          'bc_v3':  limb8_text[0x057:0x065],
          'bc_v1':  limb8_text[0x066:0x0a0]}
L11_BC = {'bc_rcb': limb11_rodata[0x000:0x056],
          'bc_v3':  limb11_rodata[0x057:0x06d],
          'bc_v1':  limb11_rodata[0x06e:0x0be]}

L8_CONST = {'cGX': limb8_text[0x156:0x176],
            'cGY': limb8_text[0x176:0x196],
            'cN':  limb8_text[0x196:0x1b6]}
L11_CONST = {'cN':   limb11_rodata[0x0bf:0x0df],
             'cR2N': limb11_rodata[0x0df:0x0ff],
             'cGX':  limb11_rodata[0x0ff:0x11f],
             'cGY':  limb11_rodata[0x11f:0x13f]}

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
# I) Which 2 limb11 ops appear in native code?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("I) limb11 ops appearing in native x86-64 code")
print("="*72)
all_ops = set()
for sname, sb in L11_BC.items():
    for i in range(0, len(sb), 2):
        all_ops.add((sb[i:i+2], sname, i))

hits = []
for op, sname, soff in all_ops:
    pos = L11_NATIVE.find(op)
    if pos >= 0:
        d = decode(op[0], op[1], L11_OPS)
        hits.append((op, sname, soff, pos+0x0b, d))  # +0xb for .text absolute offset

for op, sname, soff, tpos, d in sorted(hits, key=lambda x:x[3]):
    print(f"  {op.hex()} = {d[0]}({d[1]},{d[2]},{d[3]})  from {sname}[{soff}]  @ .text+0x{tpos:03x}")
    # Show surrounding bytes
    ctx = limb11_text[tpos-2:tpos+6]
    print(f"    context: ...{ctx.hex()}... (2B before, op, 4B after)")
print()

# ─────────────────────────────────────────────────────────────────────
# J) Opcode-sequence-only match (ignore all slot nibbles)
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("J) OPCODE-ONLY SEQUENCES: where do constants match bc opcode patterns?")
print("="*72)
print("  If opcodes match for N consecutive ops, a slot remap MIGHT work.")
print("  This is necessary but not sufficient for a remap win.")
print()

def opcodes(bs, stride_start=0):
    """Extract opcode nibbles from even positions."""
    return [bs[i] & 0xF for i in range(stride_start, len(bs)-1, 2)]

for label, bc_streams, consts, ops in [('limb8', L8_BC, L8_CONST, L8_OPS),
                                        ('limb11', L11_BC, L11_CONST, L11_OPS)]:
    for sname, sb in bc_streams.items():
        bc_opc = opcodes(sb)
        for cname, cd in consts.items():
            for offs in range(len(cd)):
                c_opc = []
                for k in range((len(cd)-offs)//2):
                    b0 = cd[offs+2*k]
                    if b0 == 0 or (b0 & 0xF) not in ops:
                        break
                    c_opc.append(b0 & 0xF)
                if len(c_opc) < 3:
                    continue
                # Find longest prefix of c_opc that appears somewhere in bc_opc
                for L in range(len(c_opc), 2, -1):
                    csub = c_opc[:L]
                    for bcpos in range(len(bc_opc) - L + 1):
                        if bc_opc[bcpos:bcpos+L] == csub:
                            opnames = ','.join(ops[o] for o in csub)
                            print(f"  {label}/{cname}[{offs}]: {L} opcodes match {sname}[op{bcpos}..]:  [{opnames}]")
                            # Now check slot consistency
                            mapping = {}
                            inv = {}
                            ok = True
                            for k in range(L):
                                bc_b0, bc_b1 = sb[2*(bcpos+k)], sb[2*(bcpos+k)+1]
                                c_b0, c_b1   = cd[offs+2*k],   cd[offs+2*k+1]
                                pairs = [(bc_b0>>4, c_b0>>4), (bc_b1>>4, c_b1>>4), (bc_b1&0xF, c_b1&0xF)]
                                for bs, cs in pairs:
                                    if bs in mapping and mapping[bs] != cs:
                                        ok = False; break
                                    if cs in inv and inv[cs] != bs:
                                        ok = False; break
                                    mapping[bs] = cs; inv[cs] = bs
                                if not ok: break
                            if ok:
                                print(f"    ★ CONSISTENT REMAP: {mapping}")
                            else:
                                conflict_pt = k
                                print(f"    ✗ slot conflict at op {conflict_pt}")
                            break
                    else:
                        continue
                    break
print()

# ─────────────────────────────────────────────────────────────────────
# K) bc_rcb SELF-REPEATS: does any subsequence of bc_rcb repeat?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("K) bc_rcb SELF-REPEATS (aligned, ≥4 B)")
print("="*72)
print("  If bc_rcb[i:i+L] == bc_rcb[j:j+L] with i≠j, a CALL op could")
print("  replace one copy with a dispatch to the other. Needs L ≥ ~6 B")
print("  to beat the CALL op overhead (~2B CALL + CALL handler cost).")
print()

for label, rcb in [('limb8', L8_BC['bc_rcb']), ('limb11', L11_BC['bc_rcb'])]:
    found = []
    for L in range(len(rcb), 3, -1):
        for i in range(0, len(rcb) - L + 1, 2):  # op-aligned
            sub = rcb[i:i+L]
            j = rcb.find(sub, i+2)
            if j >= 0:
                found.append((L, i, j, sub))
    if found:
        # Keep only maximal
        found.sort(key=lambda x: -x[0])
        seen = set()
        for L, i, j, sub in found:
            if any((i >= a and i+L <= a+La) or (j >= b and j+L <= b+La)
                   for La, a, b, _ in [f for f in found if f[0]>L]):
                continue  # subsumed by longer match
            if (i, j) not in seen:
                seen.add((i,j))
                print(f"  {label}/bc_rcb: {L} B @ [{i}] == [{j}]  : {sub.hex()}")
    else:
        print(f"  {label}/bc_rcb: no repeats ≥4 B")
print()

# ─────────────────────────────────────────────────────────────────────
# L) bc_v1 SELF-REPEATS: already found aa23aa23aa / 03bb03bb in pass 1
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("L) bc_v1 SELF-REPEATS (aligned, ≥4 B)")
print("="*72)
for label, v1, ops in [('limb8', L8_BC['bc_v1'], L8_OPS),
                        ('limb11', L11_BC['bc_v1'], L11_OPS)]:
    found = []
    for L in range(len(v1), 3, -1):
        for i in range(0, len(v1) - L + 1, 2):
            sub = v1[i:i+L]
            j = v1.find(sub, i+2)
            if j >= 0 and j % 2 == 0:  # op-aligned on both ends
                found.append((L, i, j, sub))
    if found:
        found.sort(key=lambda x: -x[0])
        printed = set()
        for L, i, j, sub in found[:10]:
            if (i,j) in printed: continue
            printed.add((i,j))
            # Decode
            ops_dec = [decode(sub[2*k], sub[2*k+1], ops) for k in range(L//2)]
            ops_str = '; '.join(f"{d[0]}({d[1]},{d[2]},{d[3]})" for d in ops_dec if d)
            print(f"  {label}/bc_v1: {L} B @ op{i//2} == op{j//2}  : {sub.hex()}")
            print(f"    = {ops_str}")
    else:
        print(f"  {label}/bc_v1: no repeats ≥4 B (aligned)")
print()

# ─────────────────────────────────────────────────────────────────────
# M) Cost/benefit of a CALL opcode
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("M) COST/BENEFIT: adding a CALL/LOOP opcode")
print("="*72)
print()
print("  A bytecode CALL op would let you reuse common sequences.")
print("  Cost: ~10-15 B handler + 1 jump table entry.")
print("  limb8 bc_v1 has the 'subtract 3x' pattern TWICE:")
print("    op6-8:   23 aa 23 aa 23 aa  (slot10 -= Gx, 3 times)")
print("    op13-15: 03 bb 03 bb 03 bb  (slot11 -= Qx, 3 times)")
print("  These DIFFER in slot numbers. A loop op could help IF it took")
print("  the Fsub target as a parameter. But that's just ... another op.")
print()
print("  limb11 bc_v1 pattern check:")
v1 = L11_BC['bc_v1']
for i in range(0, len(v1)-5, 2):
    if v1[i] == v1[i+2] == v1[i+4] and v1[i+1] == v1[i+3] == v1[i+5]:
        d = decode(v1[i], v1[i+1], L11_OPS)
        print(f"    3x repeat at op{i//2}: {v1[i:i+6].hex()} = 3× {d}")
print()

# ─────────────────────────────────────────────────────────────────────
# N) The real prize: tails of streams that could share their END
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("N) TAIL SHARING: can stream X's tail == stream Y's tail?")
print("="*72)
print("  If bc_v3 ended with the same 2 ops as bc_rcb's end, we could")
print("  place bc_v3 to OVERLAP bc_rcb's tail and share those bytes.")
print()
for label, bc in [('limb8', L8_BC), ('limb11', L11_BC)]:
    streams = list(bc.items())
    for i in range(len(streams)):
        for j in range(len(streams)):
            if i == j: continue
            na, sa = streams[i]
            nb, sb = streams[j]
            # Find longest common suffix
            k = 0
            while k < min(len(sa), len(sb)) and sa[-1-k] == sb[-1-k]:
                k += 1
            if k >= 2:
                print(f"  {label}: {na} and {nb} share {k}-byte tail: {sa[-k:].hex()}")
print()

# ─────────────────────────────────────────────────────────────────────
# O) Tail-into-constant: does any stream's tail appear at the HEAD of
#    the constant that follows it?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("O) TAIL→CONSTANT OVERLAP: stream tails that match the next constant")
print("="*72)
print("  limb11: bc_v1 ends at 0x0be (END), cN starts at 0x0bf.")
print("  If bc_v1's last N bytes + END matched cN's first N+1 bytes, we")
print("  could place bc_v1 to overlap cN and save N+1 bytes.")
print()
# limb11: bc_v1 (0x06e-0x0be) → cN (0x0bf)
v1_with_end = L11_BC['bc_v1'] + b'\x00'
cn = L11_CONST['cN']
for N in range(min(len(v1_with_end), len(cn)), 0, -1):
    if v1_with_end[-N:] == cn[:N]:
        print(f"  ★ limb11: bc_v1's last {N} bytes == cN's first {N} bytes: {cn[:N].hex()}")
        break
else:
    print(f"  limb11: bc_v1 tail / cN head: no overlap")
    print(f"    bc_v1 last 4 B + END: {v1_with_end[-5:].hex()}")
    print(f"    cN first 5 B:         {cn[:5].hex()}")
print()

# What IF we remapped bc_v1's last ops to MAKE them match cN?
print("  Q: could a slot remap on bc_v1's tail make it match cN's head?")
print(f"  cN[0..4] = {cn[:4].hex()}")
# cN[0] = 0x4f → op=15 INVALID. So even the FIRST byte of cN is unusable as b0.
print(f"  cN[0] = 0x4f → opcode nibble = 15 → always invalid. DEAD END.")
print()
# But what about overlapping with cN[1]?
print(f"  cN[1..5] = {cn[1:5].hex()} → cN[1]=0x25, op=5 (CHKZ). Valid!")
print(f"  If bc_v1 ended at cN-1 (one byte BEFORE cN), its END would be")
print(f"  cN[-1]=... wait, there's nothing before cN except bc_v1's END.")
print(f"  Can't back up further without a buffer byte.")
print()

# ─────────────────────────────────────────────────────────────────────
# P) The limb8 push rcx chain — semantically useful?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("P) limb8's '51 51 51 51...' run (push rcx stack alloc in fe_mul_m)")
print("="*72)
print("  .text+0x25a-0x263: 51 51 51 51 51 51 51 51 51 6a  (9 push rcx + push imm8)")
print("  51 51 decodes as SQR(5,1,5) — slot5 = slot1² in limb8.")
print("  Does ANY algorithm need repeated squaring of the same slot?")
print("  YES — fe_inv uses a square-and-multiply ladder! But it's already")
print("  native code (bt+loop), not bytecode. And 51 51 is SQR(5,1,5),")
print("  which is slot5 = slot1*slot1 — NOT slot5 = slot5*slot5. So it's")
print("  NOT a repeated-square. It squares slot1 into slot5, N times —")
print("  idempotent after the first. Useless.")
print()
print("  For limb11 (op1=Fadd), 51 51 = Fadd(5,1,5) = slot5=slot1+slot5.")
print("  N iterations: slot5 = slot1·N + slot5_init. That's an accumulator!")
print("  But limb11's fe_mul11 doesn't have the push-rcx chain (different arch).")
# Check:
run = limb11_text.find(b'\x51\x51\x51\x51')
print(f"  Does limb11/.text have 51 51 51 51?  {'YES @'+hex(run) if run>=0 else 'NO'}")
print()

# ─────────────────────────────────────────────────────────────────────
# Q) Summary: which finds are worth a closer look?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("Q) ACTIONABLE CANDIDATES")
print("="*72)
print()
print("  None found at the 'free win' level (N≥3 ops, clean terminator, useful).")
print("  Most promising LONG-SHOT candidates below.")
