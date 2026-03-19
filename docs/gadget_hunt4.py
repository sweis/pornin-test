#!/usr/bin/env python3
"""Gadget-hunt pass 4: final checks.
- Full-stream frameshift with END analysis
- Stream reordering possibilities
- The 0x01 0x02 tail check (limb8 bc_rcb has `01 02` at offset 18 AND 42)
- Sliding-constant overlap: what if bytecode stream overlapped a DIFFERENT part of a constant?
"""

limb8_text    = open('/tmp/limb8_text.bin',   'rb').read()
limb11_text   = open('/tmp/limb11_text.bin',  'rb').read()
limb11_rodata = open('/tmp/limb11_rodata.bin','rb').read()

L8_BC  = {'bc_rcb': limb8_text[0x000:0x057],   # WITH END this time
          'bc_v3':  limb8_text[0x057:0x066],
          'bc_v1':  limb8_text[0x066:0x0a1]}
L11_BC = {'bc_rcb': limb11_rodata[0x000:0x057],
          'bc_v3':  limb11_rodata[0x057:0x06e],
          'bc_v1':  limb11_rodata[0x06e:0x0bf]}

L11_CONST = {'cN':   limb11_rodata[0x0bf:0x0df],
             'cR2N': limb11_rodata[0x0df:0x0ff],
             'cGX':  limb11_rodata[0x0ff:0x11f],
             'cGY':  limb11_rodata[0x11f:0x13f]}

L8_CONST = {'cGX': limb8_text[0x156:0x176],
            'cGY': limb8_text[0x176:0x196],
            'cN':  limb8_text[0x196:0x1b6]}

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
# R) Does the frameshifted bc_rcb reach a CLEAN END?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("R) FRAMESHIFTED bc_rcb → does any odd offset reach a 0x00 b0?")
print("="*72)
print("  bc_rcb's bytes at EVEN positions (b0) are all nonzero by construction.")
print("  At ODD positions (b1), any value is allowed — including 0x00!")
print("  If a frameshifted run hits an odd-position 0x00, it terminates CLEANLY.")
print()
print("  Which b1 bytes are 0x00 in bc_rcb?")
for label, rcb, ops in [('limb8', L8_BC['bc_rcb'], L8_OPS),
                        ('limb11', L11_BC['bc_rcb'], L11_OPS)]:
    zero_b1 = [i for i in range(1, len(rcb)-1, 2) if rcb[i] == 0x00]
    print(f"  {label}/bc_rcb: b1==0x00 at byte offsets {zero_b1}")
    # For each zero b1, trace BACKWARDS to find longest frameshifted run reaching it
    for zpos in zero_b1:
        # zpos is odd. Previous frameshifted ops start at zpos-2, zpos-4, ...
        run = []
        p = zpos - 2
        while p >= 1:
            d = decode(rcb[p], rcb[p+1], ops)
            if d is None:
                break
            run.insert(0, (p, rcb[p], rcb[p+1], d))
            p -= 2
        if run:
            ops_str = '; '.join(f"{d[0]}({d[1]},{d[2]},{d[3]})" for _,_,_,d in run)
            print(f"    → back-trace from byte {zpos}: {len(run)} valid ops reach this END")
            print(f"      start@byte{run[0][0]}: [{ops_str}] + END@{zpos}")
print()

# ─────────────────────────────────────────────────────────────────────
# S) Stream REORDERING: what if we put streams in a different order?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("S) STREAM REORDERING: any order where tail(X)+END matches head(Y)?")
print("="*72)
print("  Current: bc_rcb, bc_v3, bc_v1 (limb11 has cN after)")
print("  The push-imm8 constraint means offsets must fit in 0..127.")
print("  bc_rcb=87 B, bc_v3=23 B, bc_v1=81 B. Total=191 B. Any 2 fit imm8.")
print()
for label, bc, ops in [('limb8', L8_BC, L8_OPS), ('limb11', L11_BC, L11_OPS)]:
    streams = list(bc.keys())
    # For every ordered pair (X, Y), check if X's tail bytes match something in Y
    for x in streams:
        for y in streams:
            if x == y: continue
            # X's tail (with END) should flow into Y's head (WITHOUT END)
            # Specifically: X[-k:] == Y[:k] means we save k bytes
            xb = bc[x]  # includes END
            yb = bc[y][:-1]  # Y WITHOUT END (it'll keep its own END)
            for k in range(min(len(xb), len(yb)), 0, -1):
                if xb[-k:] == yb[:k]:
                    print(f"  {label}: {x}→{y} overlap {k} B: {xb[-k:].hex()}")
                    break
print()

# ─────────────────────────────────────────────────────────────────────
# T) DEEPER REMAP: brute-force permutation search for 3-op+ const overlap
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("T) BRUTE-FORCE REMAP: any bijection σ making const match bc?")
print("="*72)
print("  For each (const, offset, bc_stream, bc_pos, length≥3):")
print("    const[off:off+2L] needs: opcode nibbles match AND")
print("    a consistent bijection exists for slot nibbles.")
print()

def try_remap(bc_bytes, c_bytes, ops):
    """Check if a slot bijection maps bc_bytes → c_bytes.
    Both must have same length (even), and opcodes MUST match."""
    L = len(bc_bytes) // 2
    fwd, rev = {}, {}
    for k in range(L):
        bb0, bb1 = bc_bytes[2*k], bc_bytes[2*k+1]
        cb0, cb1 = c_bytes[2*k], c_bytes[2*k+1]
        if (bb0 & 0xF) != (cb0 & 0xF): return None  # opcode mismatch
        if cb0 == 0: return None  # constant would END here
        if (cb0 & 0xF) not in ops: return None
        # Slot pairs: (bc_s2, c_s2), (bc_dst, c_dst), (bc_s1, c_s1)
        pairs = [(bb0>>4, cb0>>4), (bb1>>4, cb1>>4), (bb1&0xF, cb1&0xF)]
        for bs, cs in pairs:
            if bs in fwd:
                if fwd[bs] != cs: return None
            elif cs in rev:
                if rev[cs] != bs: return None
            else:
                fwd[bs] = cs; rev[cs] = bs
    return fwd

best = []
for label, bc_streams, consts, ops in [('limb8', L8_BC, L8_CONST, L8_OPS),
                                        ('limb11', L11_BC, L11_CONST, L11_OPS)]:
    for sname, sb in bc_streams.items():
        sb_ops = sb[:-1] if sb[-1] == 0 else sb  # strip END
        n_ops = len(sb_ops) // 2
        for cname, cd in consts.items():
            for coff in range(len(cd)):
                for bcop in range(n_ops):
                    for L in range(min(n_ops - bcop, (len(cd)-coff)//2), 2, -1):
                        bc_win = sb_ops[2*bcop:2*(bcop+L)]
                        c_win  = cd[coff:coff+2*L]
                        if len(c_win) < 2*L: continue
                        m = try_remap(bc_win, c_win, ops)
                        if m is not None:
                            # Check if followed by END (0x00) in constant
                            next_b = cd[coff+2*L] if coff+2*L < len(cd) else None
                            best.append((L, label, sname, bcop, cname, coff, m, next_b))
                            break  # longest only per (bcop, coff)

best.sort(key=lambda x: -x[0])
for L, label, sname, bcop, cname, coff, m, nxt in best[:8]:
    term = ' ★END★' if nxt == 0x00 else f' next=0x{nxt:02x}' if nxt else ' EOF'
    print(f"  {L} ops: {label}/{sname}[op{bcop}..{bcop+L}] ≡ {cname}[{coff}:] via remap{term}")
    print(f"    σ = {m}")
    # Is this remap feasible? Check for fixed slots that can't move
    fixed_l11 = {8:'cP', 9:'cN', 10:'b', 14:'r+n', 15:'one'}  # RCB-reserved
    fixed_l8  = {5:'cP', 4:'cN', 10:'b'}  # approximate
    fixed = fixed_l11 if label == 'limb11' else fixed_l8
    issues = []
    for bs, cs in m.items():
        if bs in fixed and bs != cs:
            issues.append(f"slot{bs}({fixed[bs]})→{cs}")
    if issues:
        print(f"    ⚠ conflicts with fixed slots: {', '.join(issues)}")
print()

# ─────────────────────────────────────────────────────────────────────
# U) The bc_rcb `01 02` repeat — worth a closer look
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("U) bc_rcb's repeated `01 02` op (Fadd(0,2,0))")
print("="*72)
for label, rcb, ops in [('limb8', L8_BC['bc_rcb'][:-1], L8_OPS),
                        ('limb11', L11_BC['bc_rcb'][:-1], L11_OPS)]:
    # Find all aligned ops that appear ≥2 times
    from collections import Counter
    opcount = Counter()
    for i in range(0, len(rcb), 2):
        opcount[rcb[i:i+2]] += 1
    dups = [(op, c) for op, c in opcount.items() if c >= 2]
    if dups:
        print(f"  {label}/bc_rcb repeated ops:")
        for op, c in sorted(dups, key=lambda x:-x[1]):
            d = decode(op[0], op[1], ops)
            positions = [i//2 for i in range(0, len(rcb), 2) if rcb[i:i+2] == op]
            print(f"    {op.hex()} = {d}  × {c}  @ op indices {positions}")
print()

# ─────────────────────────────────────────────────────────────────────
# V) What about overlapping bc_v1 with cN's INTERIOR (not head)?
# ─────────────────────────────────────────────────────────────────────
print("="*72)
print("V) SLIDING OVERLAP: bc_v1 tail against EVERY position in cN/cGX/etc")
print("="*72)
print("  If bc_v1's last K bytes == const[j:j+K] for some j>0, we could")
print("  place const to start K bytes 'inside' bc_v1, overlapping.")
print("  BUT: this requires the LINKER sees them as one block and the")
print("  decoder code's `lea rsi,[rip+cN]` is offset by j.")
print()

for label, bc_v1, consts in [('limb11', L11_BC['bc_v1'], L11_CONST),
                              ('limb8',  L8_BC['bc_v1'],  L8_CONST)]:
    for cname, cd in consts.items():
        # Find longest match between any tail of bc_v1 and any position in cd
        for k in range(min(len(bc_v1), len(cd)), 1, -1):
            tail = bc_v1[-k:]  # includes END
            pos = cd.find(tail)
            if pos >= 0:
                print(f"  ★ {label}: bc_v1's last {k} B found at {cname}[{pos}]: {tail.hex()}")
                if pos == 0:
                    print(f"     (head overlap — can place cname right after bc_v1, save {k} B)")
                else:
                    print(f"     (interior — would need cname label at +{pos}, complex)")
                break
        else:
            # Single byte (END) must appear somewhere
            if 0x00 in cd:
                p = cd.index(0x00)
                # 2-byte check: is bc_v1's last op's b1 + END somewhere?
                tail2 = bc_v1[-2:]
                p2 = cd.find(tail2)
                print(f"  {label}/{cname}: END (0x00) at {cname}[{p}]; 2B-tail {tail2.hex()} "
                      f"{'at '+str(p2) if p2>=0 else 'not found'}")
            else:
                print(f"  {label}/{cname}: no 0x00 byte anywhere (dead)")
