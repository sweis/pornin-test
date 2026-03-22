#!/usr/bin/env python3
"""
Gadget-hunt: find byte sequences in .text/.rodata that already encode
valid bytecode ops, ROP-style.

Each op is 2 bytes:
  byte 0: (s2<<4) | opcode   -- opcode ∈ {0..N}, s2 ∈ {0..15}
  byte 1: (dst<<4) | s1      -- dst, s1 ∈ {0..15}
Terminator: byte 0 == 0x00 (test al,al; jz).
"""

import sys
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────
# Load raw bytes
# ─────────────────────────────────────────────────────────────────────
limb8_text   = open('/tmp/limb8_text.bin', 'rb').read()
limb11_text  = open('/tmp/limb11_text.bin', 'rb').read()
limb11_rodata= open('/tmp/limb11_rodata.bin', 'rb').read()

# ─────────────────────────────────────────────────────────────────────
# Region maps (from symbol tables)
# ─────────────────────────────────────────────────────────────────────
# limb8 — all in .text
L8_REGIONS = [
    ('bc_rcb',      0x000, 0x057),
    ('bc_v3',       0x057, 0x066),
    ('bc_v1',       0x066, 0x0a1),
    ('native.pre',  0x0a1, 0x14c),  # fe_from_be, pt_mul, bcrun
    ('jt',          0x14c, 0x156),  # jump table (10 B)
    ('cGX',         0x156, 0x176),
    ('cGY',         0x176, 0x196),
    ('cN',          0x196, 0x1b6),
    ('native.post', 0x1b6, len(limb8_text)),  # handlers, fe_mul_m, verify
]

# limb11x24 — split across .rodata and .text
L11_RODATA_REGIONS = [
    ('bc_rcb',  0x000, 0x057),
    ('bc_v3',   0x057, 0x06e),
    ('bc_v1',   0x06e, 0x0bf),
    ('cN',      0x0bf, 0x0df),
    ('cR2N',    0x0df, 0x0ff),
    ('cGX',     0x0ff, 0x11f),
    ('cGY',     0x11f, 0x13f),
]
L11_TEXT_REGIONS = [
    ('jt',      0x000, 0x00b),  # 11-byte jump table
    ('native',  0x00b, len(limb11_text)),
]

def region_of(regions, off):
    for name, lo, hi in regions:
        if lo <= off < hi:
            return name, off - lo
    return '?', off

# ─────────────────────────────────────────────────────────────────────
# Opcode tables
# ─────────────────────────────────────────────────────────────────────
# limb11x24 (from gen_bytecode.py)
L11_OPS = {0:'Fmul', 1:'Fadd', 2:'Fsub', 3:'Nmul', 4:'CHKLT',
           5:'CHKZ', 6:'INV', 7:'NORM', 8:'SET1', 9:'COPY', 10:'COPYHI'}

# limb8 (from tv_ecdsa.S .Ljt + comments)
L8_OPS = {0:'Fmul', 1:'SQR', 2:'Fadd', 3:'Fsub', 4:'Nmul',
          5:'CHKLT', 6:'CHKZ', 7:'CHKNZ', 8:'MULCN', 9:'INV'}

def decode_op(b0, b1, ops_table):
    """Return (opname, dst, s1, s2) or None if invalid."""
    if b0 == 0x00:
        return None  # terminator
    opcode = b0 & 0x0F
    s2 = b0 >> 4
    s1 = b1 & 0x0F
    dst = b1 >> 4
    if opcode not in ops_table:
        return None
    return (ops_table[opcode], dst, s1, s2)

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Extract current bytecode streams as byte sequences
# ─────────────────────────────────────────────────────────────────────
def extract_streams(data, regions):
    """Extract bytecode streams (sans END byte) as raw bytes."""
    streams = {}
    for name, lo, hi in regions:
        if name.startswith('bc_'):
            # Strip trailing END byte
            s = data[lo:hi]
            assert s[-1] == 0x00, f"{name} doesn't end with 0x00: {s[-1]:02x}"
            streams[name] = s[:-1]  # ops only, no terminator
    return streams

l8_streams  = extract_streams(limb8_text, L8_REGIONS)
l11_streams = extract_streams(limb11_rodata, L11_RODATA_REGIONS)

print("="*72)
print("BYTECODE STREAMS")
print("="*72)
for k, v in l8_streams.items():
    print(f"  limb8  {k}: {len(v):3} B  ({len(v)//2} ops)")
for k, v in l11_streams.items():
    print(f"  limb11 {k}: {len(v):3} B  ({len(v)//2} ops)")
print()

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Enumerate 2-byte windows in NON-BYTECODE regions, decode
# ─────────────────────────────────────────────────────────────────────
def scan_windows(data, regions, ops_table, label, skip_bc=True):
    """For each 2-byte window outside bc_* regions, try decode as op."""
    results = []  # (offset, region_name, region_off, b0, b1, decoded)
    for i in range(len(data) - 1):
        rname, roff = region_of(regions, i)
        if skip_bc and rname.startswith('bc_'):
            continue
        b0, b1 = data[i], data[i+1]
        dec = decode_op(b0, b1, ops_table)
        if dec:
            results.append((i, rname, roff, b0, b1, dec))
    return results

# ─────────────────────────────────────────────────────────────────────
# STEP 3: Find longest valid RUN of ops starting at each offset
# ─────────────────────────────────────────────────────────────────────
def find_runs(data, regions, ops_table, label, skip_bc=True, min_ops=2):
    """Find maximal runs of valid 2-byte ops. A run ends at an invalid
    opcode OR a 0x00 b0 byte (terminator)."""
    runs = []
    n = len(data)
    i = 0
    while i < n - 1:
        rname, roff = region_of(regions, i)
        if skip_bc and rname.startswith('bc_'):
            i += 1
            continue
        # Count valid ops from here
        j = i
        ops = []
        while j + 1 < n:
            b0, b1 = data[j], data[j+1]
            dec = decode_op(b0, b1, ops_table)
            if dec is None:
                # b0==0 is a CLEAN terminator — note it
                terminated = (b0 == 0x00)
                break
            ops.append((b0, b1, dec))
            j += 2
        else:
            terminated = False
        if len(ops) >= min_ops:
            runs.append((i, rname, roff, ops, terminated))
        i += 1
    return runs

# ─────────────────────────────────────────────────────────────────────
# STEP 4: Find VERBATIM subsequence matches
# ─────────────────────────────────────────────────────────────────────
def find_substring(needle, haystack, haystack_regions, min_len=4, needle_name=""):
    """Find all occurrences of length-≥min_len substrings of needle in haystack.
    Returns list of (needle_off, haystack_off, length, haystack_region)."""
    hits = []
    nlen = len(needle)
    for start in range(nlen):
        for end in range(start + min_len, nlen + 1):
            sub = needle[start:end]
            pos = haystack.find(sub)
            while pos >= 0:
                # Only count if not longer-match-already-found
                rname, roff = region_of(haystack_regions, pos)
                hits.append((start, pos, len(sub), rname, roff, sub))
                pos = haystack.find(sub, pos + 1)
    # Dedupe: keep only maximal matches per (needle_off, haystack_off)
    # Sort by length descending, then filter
    hits.sort(key=lambda x: -x[2])
    kept = []
    covered = set()  # (needle_off, haystack_off) pairs that are part of a longer match
    for h in hits:
        no, ho, ln, rn, ro, sub = h
        key = (no, ho)
        if key in covered:
            continue
        kept.append(h)
        # Mark all sub-offsets covered
        for dn in range(ln - min_len + 1):
            for dh in range(ln - min_len + 1):
                if dn == dh:  # same relative shift
                    covered.add((no + dn, ho + dh))
    return kept

# ─────────────────────────────────────────────────────────────────────
# STEP 4b: Near-miss — single byte diff (for slot remap)
# ─────────────────────────────────────────────────────────────────────
def find_near_miss(needle, haystack, haystack_regions, min_len=6, max_diff=1):
    """Find substrings matching with ≤max_diff byte differences.
    A 1-byte diff might be fixable by slot remapping."""
    hits = []
    nlen, hlen = len(needle), len(haystack)
    for length in range(min_len, min(nlen, 32) + 1, 2):  # even lengths (whole ops)
        for no in range(0, nlen - length + 1, 2):  # op-aligned in needle
            nsub = needle[no:no+length]
            for ho in range(hlen - length + 1):
                hsub = haystack[ho:ho+length]
                diffs = [(k, nsub[k], hsub[k]) for k in range(length) if nsub[k] != hsub[k]]
                if 1 <= len(diffs) <= max_diff:
                    rname, roff = region_of(haystack_regions, ho)
                    hits.append((no, ho, length, rname, roff, diffs, nsub, hsub))
    # Dedupe by keeping longest per (no, ho, diff position pattern)
    hits.sort(key=lambda x: -x[2])
    seen = set()
    kept = []
    for h in hits:
        no, ho, ln, rn, ro, diffs, ns, hs = h
        # Key: normalize by the DIFF POSITION relative to both starts
        # Only report near-misses that aren't contained in a longer exact or near-miss already reported
        k = (no, ho)
        if k in seen:
            continue
        seen.add(k)
        kept.append(h)
    return kept[:30]  # cap output

# ─────────────────────────────────────────────────────────────────────
# RUN ANALYSIS
# ─────────────────────────────────────────────────────────────────────

# ── Valid op density per region ──
print("="*72)
print("STEP 2: 2-byte windows that decode as valid ops (non-bytecode regions)")
print("="*72)
for label, data, regions, ops in [
    ("limb8/.text",  limb8_text,   L8_REGIONS,        L8_OPS),
    ("limb11/.rodata", limb11_rodata, L11_RODATA_REGIONS, L11_OPS),
    ("limb11/.text", limb11_text,  L11_TEXT_REGIONS,  L11_OPS),
]:
    windows = scan_windows(data, regions, ops, label)
    by_region = defaultdict(int)
    total_win = defaultdict(int)
    for name, lo, hi in regions:
        if name.startswith('bc_'):
            continue
        total_win[name] = max(0, hi - lo - 1)
    for off, rn, ro, b0, b1, dec in windows:
        by_region[rn] += 1
    print(f"\n  {label}:")
    for name, lo, hi in regions:
        if name.startswith('bc_'):
            continue
        n = by_region[name]
        t = total_win[name]
        pct = 100*n/t if t else 0
        print(f"    {name:12}  {n:4}/{t:4} windows valid  ({pct:4.0f}%)")

# ── Longest runs ──
print()
print("="*72)
print("STEP 3: Longest runs of consecutive valid ops (≥2 ops = 4 B)")
print("="*72)
print("  (★ = run ends at a 0x00 byte — clean terminator, jumpable target!)")
for label, data, regions, ops in [
    ("limb8/.text",  limb8_text,   L8_REGIONS,        L8_OPS),
    ("limb11/.rodata", limb11_rodata, L11_RODATA_REGIONS, L11_OPS),
    ("limb11/.text", limb11_text,  L11_TEXT_REGIONS,  L11_OPS),
]:
    runs = find_runs(data, regions, ops, label, min_ops=2)
    runs.sort(key=lambda r: -len(r[3]))
    print(f"\n  {label}: {len(runs)} runs found. Top 15 by length:")
    for off, rn, ro, oplist, term in runs[:15]:
        mark = '★' if term else ' '
        opbytes = ' '.join(f'{b0:02x}{b1:02x}' for b0,b1,_ in oplist)
        opdec   = '; '.join(f'{d[0]}({d[1]},{d[2]},{d[3]})' for _,_,d in oplist)
        print(f"    {mark} +0x{off:03x}  {rn:12}+{ro:3}  {len(oplist):2} ops  [{opbytes}]")
        print(f"                                      {opdec}")

# ── Verbatim subsequence matches ──
print()
print("="*72)
print("STEP 4: Verbatim subsequence matches (bytecode → non-bytecode bytes)")
print("="*72)
print("  (Length ≥4 B = 2 ops. The dream: a long run that exists elsewhere.)")

for label, streams, hay, hay_regions in [
    ("limb8",  l8_streams,  limb8_text,  L8_REGIONS),
    ("limb11", l11_streams, limb11_rodata, L11_RODATA_REGIONS),
]:
    for sname, sbytes in streams.items():
        hits = find_substring(sbytes, hay, hay_regions, min_len=4)
        # Filter: skip hits that land in a bc_ region AND are the identity
        real_hits = []
        for no, ho, ln, rn, ro, sub in hits:
            if rn == sname and ro == no:  # self-match
                continue
            real_hits.append((no, ho, ln, rn, ro, sub))
        if real_hits:
            print(f"\n  {label}/{sname} ({len(sbytes)} B) → {label} haystack:")
            for no, ho, ln, rn, ro, sub in real_hits[:10]:
                hexs = ' '.join(f'{b:02x}' for b in sub)
                in_bc = '(in bc)' if rn.startswith('bc_') else ''
                print(f"    {ln:2} B  @ needle[{no:3}]  → {rn:12}+{ro:3}  [{hexs}]  {in_bc}")

# ── Cross-section: limb11 bytecode → .text ──
print()
print("  --- limb11 bytecode → limb11/.text (cross-section) ---")
for sname, sbytes in l11_streams.items():
    hits = find_substring(sbytes, limb11_text, L11_TEXT_REGIONS, min_len=4)
    if hits:
        print(f"\n  limb11/{sname} ({len(sbytes)} B) → limb11/.text:")
        for no, ho, ln, rn, ro, sub in hits[:8]:
            hexs = ' '.join(f'{b:02x}' for b in sub)
            print(f"    {ln:2} B  @ needle[{no:3}]  → .text/{rn:10}+{ro:3}  [{hexs}]")

# ── Inter-stream boundary ops ──
print()
print("="*72)
print("STEP 5: Inter-stream boundary ops (END byte of stream N + start of N+1)")
print("="*72)
# The END byte (0x00) of bc_rcb is followed immediately by bc_v3's first byte.
# If we skip the END (start reading 1 byte later), we get accidental 2-byte ops
# from the LAST op's b1 + the END byte. But END=0x00 as b0 is STILL a terminator.
# More interesting: what if we start at an ODD offset inside bc_rcb?
print("\n  Odd-offset reads inside bc_rcb (frameshift by 1 byte):")
for label, data, regions, ops in [
    ("limb8",  limb8_text[0x00:0x57],  [('bc_rcb',0,0x57)], L8_OPS),
    ("limb11", limb11_rodata[0x00:0x57], [('bc_rcb',0,0x57)], L11_OPS),
]:
    # Skip first byte, read as ops
    runs = find_runs(data[1:], [('rcb.shifted',0,len(data)-1)], ops, label, skip_bc=False, min_ops=3)
    runs.sort(key=lambda r: -len(r[3]))
    print(f"    {label}/bc_rcb frameshifted: {len(runs)} runs ≥3 ops. Top 5:")
    for off, rn, ro, oplist, term in runs[:5]:
        mark = '★' if term else ' '
        opdec = '; '.join(f'{d[0]}({d[1]},{d[2]},{d[3]})' for _,_,d in oplist)
        print(f"      {mark} @ byte {off+1:2}  {len(oplist):2} ops  {opdec}")

# ── Near-miss: would a slot remap make something match? ──
print()
print("="*72)
print("STEP 6: Near-miss matches (1 byte diff — fixable by slot remap?)")
print("="*72)
print("  Only considers op-aligned needle windows. 1 byte diff in a 6+ B run.")

for label, streams, hay, hay_regions in [
    ("limb8",  l8_streams,  limb8_text,  L8_REGIONS),
    ("limb11", l11_streams, limb11_rodata, L11_RODATA_REGIONS),
]:
    # Only look in constant regions — they're the most promising (stable)
    for sname, sbytes in streams.items():
        hits = find_near_miss(sbytes, hay, hay_regions, min_len=6, max_diff=1)
        # Filter to constant regions only
        hits = [h for h in hits if h[3] in ('cN','cGX','cGY','cR2N','jt','native.pre','native.post','native')]
        if hits:
            print(f"\n  {label}/{sname} → {label} constants/native (1 byte off, ≥6 B):")
            for no, ho, ln, rn, ro, diffs, ns, hs in hits[:5]:
                hexn = ' '.join(f'{b:02x}' for b in ns)
                hexh = ' '.join(f'{b:02x}' for b in hs)
                diffstr = ', '.join(f'@{k}:{a:02x}→{b:02x}' for k,a,b in diffs)
                print(f"    {ln:2} B  needle[{no:3}]  → {rn:12}+{ro:3}")
                print(f"         need: [{hexn}]")
                print(f"         have: [{hexh}]  diff: {diffstr}")
                # Interpret diff as slot remap
                for k, a, b in diffs:
                    if k % 2 == 0:  # b0 diff: (s2<<4)|op
                        da_op, da_s2 = a & 0xF, a >> 4
                        db_op, db_s2 = b & 0xF, b >> 4
                        if da_op == db_op:
                            print(f"              → pure s2 remap: slot {da_s2} ↔ {db_s2}")
                        elif da_s2 == db_s2:
                            print(f"              → opcode change: {da_op} → {db_op} (bad)")
                        else:
                            print(f"              → op+s2 both change (bad)")
                    else:  # b1 diff: (dst<<4)|s1
                        da_s1, da_dst = a & 0xF, a >> 4
                        db_s1, db_dst = b & 0xF, b >> 4
                        if da_s1 == db_s1:
                            print(f"              → pure dst remap: slot {da_dst} ↔ {db_dst}")
                        elif da_dst == db_dst:
                            print(f"              → pure s1 remap: slot {da_s1} ↔ {db_s1}")
                        else:
                            print(f"              → dst+s1 both change")

# ── Special focus: constants as potential op sources ──
print()
print("="*72)
print("STEP 7: Rodata constants — full 2-byte window decode")
print("="*72)
print("  These are FIXED (mathematical constants) — can't be changed.")
print("  But a jumpable TAIL (N ops then 0x00) would be gold.")

for label, data, regions, ops in [
    ("limb8/cGX",  limb8_text[0x156:0x176],  [('cGX',0,32)], L8_OPS),
    ("limb8/cGY",  limb8_text[0x176:0x196],  [('cGY',0,32)], L8_OPS),
    ("limb8/cN",   limb8_text[0x196:0x1b6],  [('cN',0,32)],  L8_OPS),
    ("limb11/cN",  limb11_rodata[0x0bf:0x0df], [('cN',0,32)],  L11_OPS),
    ("limb11/cR2N",limb11_rodata[0x0df:0x0ff], [('cR2N',0,32)],L11_OPS),
    ("limb11/cGX", limb11_rodata[0x0ff:0x11f], [('cGX',0,32)], L11_OPS),
    ("limb11/cGY", limb11_rodata[0x11f:0x13f], [('cGY',0,32)], L11_OPS),
]:
    print(f"\n  {label} (32 B):")
    hexline = ' '.join(f'{b:02x}' for b in data)
    print(f"    raw: {hexline}")
    # Try every 2-byte window
    for i in range(31):
        dec = decode_op(data[i], data[i+1], ops)
        if dec:
            op, d, s1, s2 = dec
            nxt = '→END' if i+2<32 and data[i+2]==0x00 else ''
            print(f"    [{i:2}] {data[i]:02x} {data[i+1]:02x}  {op:6}({d:2},{s1:2},{s2:2})  {nxt}")

# ── Jump table ──
print()
print("="*72)
print("STEP 8: Jump table bytes as ops")
print("="*72)
print("  The jump table values are handler offsets — they CHANGE per build.")
print("  But CURRENT values might encode useful ops.")

for label, jt, ops in [
    ("limb8/.Ljt",   limb8_text[0x14c:0x156],  L8_OPS),  # 10 B
    ("limb11/.Ljt",  limb11_text[0x000:0x00b], L11_OPS), # 11 B
]:
    print(f"\n  {label} ({len(jt)} B):  {' '.join(f'{b:02x}' for b in jt)}")
    for i in range(len(jt)-1):
        dec = decode_op(jt[i], jt[i+1], ops)
        if dec:
            op, d, s1, s2 = dec
            print(f"    [{i:2}] {jt[i]:02x} {jt[i+1]:02x}  {op:6}({d:2},{s1:2},{s2:2})")
