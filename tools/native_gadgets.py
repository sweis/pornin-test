#!/usr/bin/env python3
"""
native_gadgets.py — two searches on limb8/limb11x24 .text

Search 1: Offset-decoding (true x86 ROP-style)
  For each multi-byte instruction, decode bytes starting at offset >=1.
  Find cases where the offset-decode is a useful instruction/sequence.

Search 2: Suffix/prefix sharing
  Enumerate all tail sequences (N=1..5) of every basic block.
  Find duplicates that could be merged via fall-through or tail-jump.
"""

import subprocess
import re
import sys
import hashlib
from collections import defaultdict

# ---------------------------------------------------------------------------
# Disassembly parsing
# ---------------------------------------------------------------------------

DIS_LINE = re.compile(
    r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.*)$'
)
LABEL_LINE = re.compile(r'^([0-9a-f]+)\s+<([^>]+)>:$')

def parse_disassembly(path):
    """Parse objdump -d -M intel output.
    Returns: list of (addr:int, bytes:bytes, asm:str), dict label->addr"""
    insns = []
    labels = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            m = LABEL_LINE.match(line)
            if m:
                labels[m.group(2)] = int(m.group(1), 16)
                continue
            m = DIS_LINE.match(line)
            if m:
                addr = int(m.group(1), 16)
                hexbytes = bytes.fromhex(m.group(2).replace(' ', ''))
                asm = m.group(3).strip()
                # objdump splits long encodings across lines — handle continuation
                if asm == '' and insns and insns[-1][0] + len(insns[-1][1]) == addr:
                    # continuation line: append bytes to previous instruction
                    pa, pb, pasm = insns[-1]
                    insns[-1] = (pa, pb + hexbytes, pasm)
                else:
                    insns.append((addr, hexbytes, asm))
    return insns, labels

def disas_bytes(raw: bytes, max_insns=8):
    """Disassemble a byte blob via objdump. Returns list of (offset, bytes, asm)."""
    if not raw:
        return []
    p = subprocess.run(
        ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
         '/dev/stdin'],
        input=raw, capture_output=True, text=False
    )
    out = p.stdout.decode('utf-8', errors='replace')
    result = []
    for line in out.splitlines():
        m = DIS_LINE.match(line)
        if m:
            addr = int(m.group(1), 16)
            hb = bytes.fromhex(m.group(2).replace(' ', ''))
            asm = m.group(3).strip()
            if asm == '' and result:
                # continuation
                pa, pb, pasm = result[-1]
                result[-1] = (pa, pb + hb, pasm)
            else:
                result.append((addr, hb, asm))
            if len(result) >= max_insns:
                break
    return result

# ---------------------------------------------------------------------------
# Search 1: Offset-decoding
# ---------------------------------------------------------------------------

# Instructions we consider "useful" if found hidden inside another:
# - ret (c3) — the classic
# - pop reg; ret
# - xor eax,eax; ret
# - any instruction that appears verbatim elsewhere in our code
# - clean sequences that reach a ret

def normalize_asm(asm):
    """Strip addresses/comments from asm string for comparison."""
    # Remove comment after '#'
    asm = asm.split('#')[0].strip()
    # Replace absolute hex addresses in jumps/calls with placeholder
    asm = re.sub(r'\b0x[0-9a-f]+\b', 'IMM', asm)
    asm = re.sub(r'\b[0-9a-f]{2,}\b(?=\s*<)', 'ADDR', asm)  # "jmp ADDR <label>"
    asm = re.sub(r'<[^>]+>', '', asm)  # strip <label>
    asm = re.sub(r'\s+', ' ', asm).strip()
    return asm

def is_bad_insn(asm):
    """True if this decode is noise/invalid."""
    a = asm.lower()
    return ('(bad)' in a or
            a.startswith('rex') and len(a.split()) == 1 or  # lone REX prefix
            a.startswith('.byte') or
            a.startswith('lock') and '(' not in a or
            a in ('', 'ds', 'es', 'fs', 'gs', 'cs', 'ss') or
            # privileged / ring-0 / nonsensical in userspace
            any(a.startswith(x) for x in [
                'out ', 'in ', 'int ', 'int3', 'iret', 'cli', 'sti',
                'hlt', 'retf', 'lret', 'ljmp', 'lcall', 'wait',
                'fwait', 'fld', 'fst', 'fi', 'fc', 'fn', 'fs', 'ft',
                'ins', 'outs', 'enter ', 'bound ', 'arpl', 'lar',
                'lsl', 'verr', 'verw', 'sldt', 'str', 'lldt', 'ltr',
                'sgdt', 'sidt', 'lgdt', 'lidt', 'smsw', 'lmsw',
                'invlpg', 'wbinvd', 'invd', 'clts', 'rdmsr', 'wrmsr',
                'rdpmc', 'rdtsc', 'sysenter', 'sysexit', 'sysret',
                'ud2', 'cpuid', 'rsm', 'loadall',
            ]) or
            # x87/mmx/weird
            any(x in a for x in ['mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5',
                                  'mm6', 'mm7', 'st(', 'xmm', 'ymm', 'zmm',
                                  'FWORD', 'TBYTE', 'es:', 'fs:', 'gs:',
                                  'cr0', 'cr2', 'cr3', 'cr4', 'dr0', 'dr1']) or
            # memory-writing ops with addresses we don't control
            # (would fault on random pointers)
            False)

def is_flow_end(asm):
    """Does this instruction terminate a straight-line sequence?"""
    a = asm.lower().split()[0] if asm else ''
    return a in ('ret', 'jmp', 'retf', 'iret', 'lret') or a.startswith('j')

def search1_offset_decode(insns, labels, build_name, native_start, native_end):
    """For each multi-byte instruction in the native region, try offset-decoding."""
    print(f"\n{'='*70}")
    print(f"SEARCH 1: Offset-decoding — {build_name}")
    print(f"{'='*70}")

    # Build a set of all byte-sequences (length 1..4) that ALREADY appear as
    # aligned instructions in our code. An offset-decode that matches one of
    # these is "useful" in the sense that we already use it.
    our_insn_bytes = set()
    our_insn_asm = {}  # bytes -> asm
    for addr, b, asm in insns:
        if native_start <= addr < native_end and not is_bad_insn(asm):
            our_insn_bytes.add(bytes(b))
            our_insn_asm[bytes(b)] = asm

    # Map: addr -> (bytes, asm) for lookup
    by_addr = {a: (b, asm) for a, b, asm in insns}

    # Labels reversed: addr -> name (for reporting)
    addr2label = {}
    for name, a in labels.items():
        addr2label[a] = name

    # --- Category A: c3 (ret) inside an instruction ---
    print("\n--- A. ret (0xc3) as non-first byte of an instruction ---")
    c3_gadgets = []
    for addr, b, asm in insns:
        if not (native_start <= addr < native_end):
            continue
        if len(b) < 2:
            continue
        for off in range(1, len(b)):
            if b[off] == 0xc3:
                # ret is at addr+off. What's the decode from earlier offsets?
                # Try off-1, off-2, ... as entry points
                for entry in range(off, 0, -1):
                    slice_ = b[entry:off+1]
                    if len(slice_) == 1:
                        # just the ret itself at addr+off
                        c3_gadgets.append((addr, off, b, asm, entry, [('ret', b'\xc3')]))
                        continue
                    dec = disas_bytes(slice_)
                    # Must cleanly reach the ret: sum of decoded lengths == len(slice_)
                    # AND last op must be ret
                    if dec:
                        total = sum(len(db) for _, db, _ in dec)
                        if total == len(slice_) and dec[-1][2].strip() == 'ret':
                            if all(not is_bad_insn(da) for _, _, da in dec):
                                seq = [(da, db) for _, db, da in dec]
                                c3_gadgets.append((addr, off, b, asm, entry, seq))

    if not c3_gadgets:
        print("  (none found)")
    else:
        # Dedupe by (addr, entry)
        seen = set()
        for addr, c3_off, b, asm, entry, seq in c3_gadgets:
            key = (addr, entry)
            if key in seen: continue
            seen.add(key)
            lbl = addr2label.get(addr, '')
            lbl_str = f" <{lbl}>" if lbl else ""
            print(f"  @{addr:#05x}+{entry}{lbl_str}: host={b.hex()} = {asm}")
            print(f"    gadget @ +{entry}..+{c3_off}: ", end='')
            print(' ; '.join(f"{a} [{bb.hex()}]" for a, bb in seq))

    # --- Category B: offset-decode matches another instruction we already use ---
    print("\n--- B. Offset-decode that matches another of our instructions exactly ---")
    matches = []
    for addr, b, asm in insns:
        if not (native_start <= addr < native_end):
            continue
        if len(b) < 2:
            continue
        for off in range(1, len(b)):
            tail = b[off:]
            # Single-instruction exact match
            if tail in our_insn_bytes and tail != b:
                matches.append((addr, off, b, asm, tail, our_insn_asm[tail]))
            # Multi-byte prefix match — the tail decodes as an instruction we use
            # followed by more bytes (which continue into the NEXT aligned insn)
            # — that's handled in category C

    if not matches:
        print("  (none — every offset-decode is either noise or already aligned)")
    else:
        # Group by gadget bytes
        by_gadget = defaultdict(list)
        for m in matches:
            by_gadget[m[4]].append(m)
        for gb, ms in sorted(by_gadget.items(), key=lambda x: -len(x[1])):
            gasm = our_insn_asm[gb]
            # How many ALIGNED occurrences of this instruction do we have?
            aligned_count = sum(1 for a, b, _ in insns
                                if native_start <= a < native_end and b == gb)
            print(f"  gadget [{gb.hex()}] = {gasm}")
            print(f"    appears ALIGNED {aligned_count}×, HIDDEN {len(ms)}×:")
            for addr, off, b, asm, _, _ in ms[:5]:
                print(f"      @{addr:#05x}+{off}: inside {b.hex()} = {asm}")
            if len(ms) > 5:
                print(f"      ... +{len(ms)-5} more")

    # --- Category C: multi-insn gadgets that span into next aligned insn ---
    # The killer case: offset-decode inside insn N, and the decoded instruction
    # ends EXACTLY at the boundary of insn N+1 — so execution continues into
    # the aligned stream. This is a "free prefix" on an existing entry point.
    print("\n--- C. Offset-decode that re-synchronizes with aligned stream ---")
    resyncs = []
    insn_starts = set(a for a, _, _ in insns if native_start <= a < native_end)
    for i, (addr, b, asm) in enumerate(insns):
        if not (native_start <= addr < native_end):
            continue
        if len(b) < 2:
            continue
        next_addr = addr + len(b)
        for off in range(1, len(b)):
            # Decode starting at addr+off; does it cleanly hit next_addr?
            # We need to look at bytes from addr+off through at most a few
            # instructions ahead to allow re-sync at a LATER boundary.
            window = b[off:]
            # Extend window with following bytes (up to 32 B)
            j = i + 1
            while len(window) < 32 and j < len(insns):
                window += insns[j][1]
                j += 1
            dec = disas_bytes(window[:32], max_insns=6)
            pos = 0
            seq = []
            for _, db, da in dec:
                if is_bad_insn(da):
                    break
                seq.append((da, db))
                pos += len(db)
                abs_pos = addr + off + pos
                if abs_pos in insn_starts:
                    # Resync! We decoded off-grid and landed back on-grid.
                    # But is the resync point interesting? It's only useful
                    # if it's a labelled entry or a ret or similar.
                    resync_lbl = addr2label.get(abs_pos, '')
                    # Report only if: resync is a label, OR seq is short (1-2 ops),
                    # OR seq ends with flow-end
                    if resync_lbl or len(seq) <= 2:
                        resyncs.append((addr, off, b, asm, seq, abs_pos, resync_lbl))
                    break
            else:
                continue

    # Filter: the trivial "REX prefix dropped" case is boring (e.g. 48 89 XX
    # at offset 1 decodes as 89 XX = 32-bit mov). Report those separately.
    rex_drops = []
    real_resyncs = []
    for r in resyncs:
        addr, off, b, asm, seq, resync_addr, resync_lbl = r
        if off == 1 and b[0] in (0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                                  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                                  0x66, 0xf2, 0xf3):  # REX / operand-size / rep prefix
            rex_drops.append(r)
        else:
            real_resyncs.append(r)

    print(f"  Trivial prefix-drops (REX/66/F2/F3 at byte 0): {len(rex_drops)}")
    # Show a few interesting REX drops — ones where the 32-bit form differs meaningfully
    rex_interesting = []
    for addr, off, b, asm, seq, resync_addr, resync_lbl in rex_drops:
        a_norm = normalize_asm(asm).lower()
        s_norm = normalize_asm(seq[0][0]).lower() if seq else ''
        # A REX.W drop changes 64-bit → 32-bit. Interesting if the regs change
        # (e.g. r14 → esi) or if the semantic is actually different.
        # Skip if the two asm strings differ ONLY in register width name
        # (rax/eax, rdi/edi, etc.)
        def strip_width(s):
            for r64, r32 in [('rax','eax'),('rbx','ebx'),('rcx','ecx'),
                             ('rdx','edx'),('rsi','esi'),('rdi','edi'),
                             ('rbp','ebp'),('rsp','esp'),
                             ('QWORD','DWORD'), ('qword','dword')]:
                s = s.replace(r64, r32)
            return s
        if strip_width(a_norm) != strip_width(s_norm):
            # meaningfully different
            rex_interesting.append((addr, off, b, asm, seq, resync_addr, resync_lbl))

    if rex_interesting:
        print(f"    Of which {len(rex_interesting)} are semantically distinct:")
        for addr, off, b, asm, seq, resync_addr, resync_lbl in rex_interesting[:10]:
            print(f"      @{addr:#05x}+{off}: host = {asm}")
            print(f"        → {' ; '.join(a for a,_ in seq)} → resync @{resync_addr:#05x} {resync_lbl}")

    print(f"\n  Non-trivial resyncs: {len(real_resyncs)}")
    if not real_resyncs:
        print("    (none)")
    for addr, off, b, asm, seq, resync_addr, resync_lbl in real_resyncs[:20]:
        resync_str = f"<{resync_lbl}>" if resync_lbl else f"+{resync_addr-addr}"
        print(f"    @{addr:#05x}+{off}: inside [{b.hex()}] = {asm}")
        print(f"      → {' ; '.join(a for a,_ in seq)} → resync @{resync_addr:#05x} {resync_str}")
    if len(real_resyncs) > 20:
        print(f"    ... +{len(real_resyncs)-20} more")

    return c3_gadgets, matches, real_resyncs, rex_interesting


# ---------------------------------------------------------------------------
# Search 2: Suffix/prefix sharing
# ---------------------------------------------------------------------------

def search2_tail_sharing(insns, labels, build_name, native_start, native_end):
    """Find basic-block tails that could be merged."""
    print(f"\n{'='*70}")
    print(f"SEARCH 2: Suffix/prefix sharing — {build_name}")
    print(f"{'='*70}")

    # Identify basic-block boundaries:
    # - A block ENDS after: ret, jmp (unconditional), or any instruction
    #   followed by a label (fall-through into new block).
    # - A block STARTS at: any label, or after a block end.

    label_addrs = set(labels.values())
    addr2label = {a: n for n, a in labels.items()}

    # Build blocks: list of (start_addr, end_addr, [insns])
    blocks = []
    current = []
    for i, (addr, b, asm) in enumerate(insns):
        if not (native_start <= addr < native_end):
            continue
        # If this addr is a label and current is non-empty, close current
        if addr in label_addrs and current:
            blocks.append(current)
            current = []
        current.append((addr, b, asm))
        # If this insn is a block-ender, close
        a0 = asm.lower().split()[0] if asm else ''
        if a0 in ('ret', 'jmp') or (a0.startswith('j') and a0 not in ('jmp',)):
            # Unconditional jumps end blocks. Conditional jumps also end blocks
            # for our purposes (the fall-through path is the next block).
            # Actually — for TAIL sharing we care about sequences ending in
            # ret or jmp. A conditional jump doesn't end the "tail" we'd share.
            if a0 in ('ret', 'jmp'):
                blocks.append(current)
                current = []
            # For jcc, the block continues (fall-through). But the jcc IS part
            # of a tail if the tail includes it.
    if current:
        blocks.append(current)

    # Also identify blocks that end in `ret` specifically — these are the
    # mergeable tails.
    ret_blocks = [blk for blk in blocks
                  if blk and blk[-1][2].lower().strip() == 'ret']
    jmp_blocks = [blk for blk in blocks
                  if blk and blk[-1][2].lower().startswith('jmp')]

    print(f"\n  Basic blocks: {len(blocks)} total")
    print(f"    ending in ret: {len(ret_blocks)}")
    print(f"    ending in jmp: {len(jmp_blocks)}")

    # --- Tail hashing ---
    # For each ret-block, compute normalized tail byte-sequences of length 1..6.
    # A "tail of length N" is the last N instructions INCLUDING the ret.
    # Two blocks with the same tail-N can merge: one jumps to the other's
    # tail-N entry point, saving (tail_N_bytes - jump_bytes).
    # Jump cost: `jmp rel8` = 2 B if in range, `jmp rel32` = 5 B.

    print("\n--- Tail suffix analysis (ret-terminated blocks) ---")
    tail_hashes = defaultdict(list)  # bytes -> list of (block_idx, tail_len, entry_addr)
    for bi, blk in enumerate(ret_blocks):
        for n in range(1, min(len(blk)+1, 7)):
            tail = blk[-n:]
            tail_bytes = b''.join(tb for _, tb, _ in tail)
            entry_addr = tail[0][0]
            tail_hashes[tail_bytes].append((bi, n, entry_addr, tail))

    # Report duplicates
    dups = [(tb, occs) for tb, occs in tail_hashes.items()
            if len(set(bi for bi, _, _, _ in occs)) > 1]
    # Sort by (bytes saved if merged)
    dups.sort(key=lambda x: -(len(x[0]) - 2))

    if not dups:
        print("  (no duplicate tails found)")
    else:
        for tb, occs in dups:
            # Only report the MAXIMAL tail for each block-pair
            # (if tail-3 matches, tail-2 and tail-1 also match — skip those)
            block_ids = sorted(set(bi for bi, _, _, _ in occs))
            # Is there a longer tail that covers the same block set?
            is_maximal = True
            for tb2, occs2 in dups:
                if len(tb2) > len(tb):
                    bids2 = set(bi for bi, _, _, _ in occs2)
                    if set(block_ids) <= bids2:
                        is_maximal = False
                        break
            if not is_maximal:
                continue
            save = len(tb) - 2  # one copy stays; other becomes jmp rel8 (2B)
            n_copies = len(block_ids)
            total_save = save * (n_copies - 1)
            if total_save <= 0:
                continue
            print(f"\n  Tail [{tb.hex()}] ({len(tb)} B) appears in {n_copies} ret-blocks:")
            for bi, n, entry, tail in occs:
                if bi in block_ids:
                    lbl = addr2label.get(ret_blocks[bi][0][0], f"block@{ret_blocks[bi][0][0]:#x}")
                    print(f"    @{entry:#05x} ({lbl}): " +
                          ' ; '.join(a for _, _, a in tail))
                    block_ids.remove(bi)
                    if not block_ids:
                        break
            print(f"    → merge saves ~{total_save} B (keep one, {n_copies-1}× jmp rel8)")

    # --- Also check: tails that are NEAR-DUPLICATES (same mnemonics, diff operands) ---
    print("\n--- Near-duplicate tails (same asm pattern, diff operands) ---")
    pattern_hashes = defaultdict(list)
    for bi, blk in enumerate(ret_blocks):
        for n in range(2, min(len(blk)+1, 6)):
            tail = blk[-n:]
            # normalize: mnemonic only
            pat = tuple(normalize_asm(a).split()[0] if a else '' for _, _, a in tail)
            pattern_hashes[pat].append((bi, n, tail[0][0], tail))

    near = [(p, occs) for p, occs in pattern_hashes.items()
            if len(set(bi for bi, _, _, _ in occs)) > 1 and len(p) >= 2]
    near.sort(key=lambda x: -len(x[0]))

    reported_pairs = set()
    for pat, occs in near:
        block_ids = sorted(set(bi for bi, _, _, _ in occs))
        pair_key = tuple(block_ids)
        # maximal check
        is_maximal = True
        for p2, o2 in near:
            if len(p2) > len(pat):
                b2 = set(bi for bi,_,_,_ in o2)
                if set(block_ids) <= b2:
                    is_maximal = False
                    break
        if not is_maximal:
            continue
        if pair_key in reported_pairs:
            continue
        reported_pairs.add(pair_key)
        # Only report if at least 3 ops in pattern
        if len(pat) < 3:
            continue
        print(f"\n  Pattern {' ; '.join(pat)} ({len(pat)} ops):")
        shown = set()
        for bi, n, entry, tail in occs:
            if bi in shown: continue
            shown.add(bi)
            lbl = addr2label.get(ret_blocks[bi][0][0], f"block@{ret_blocks[bi][0][0]:#x}")
            tail_bytes = b''.join(tb for _, tb, _ in tail)
            print(f"    @{entry:#05x} ({lbl}, {len(tail_bytes)}B): " +
                  ' ; '.join(a for _, _, a in tail))

    # --- Prefix sharing ---
    print("\n--- Prefix analysis (blocks with common heads) ---")
    prefix_hashes = defaultdict(list)
    for bi, blk in enumerate(blocks):
        if len(blk) < 2:
            continue
        # Only look at blocks that START at a label (these are call targets)
        start = blk[0][0]
        if start not in label_addrs:
            continue
        for n in range(1, min(len(blk)+1, 5)):
            head = blk[:n]
            head_bytes = b''.join(tb for _, tb, _ in head)
            prefix_hashes[head_bytes].append((bi, n, start, head))

    pdups = [(hb, occs) for hb, occs in prefix_hashes.items()
             if len(set(bi for bi, _, _, _ in occs)) > 1 and len(hb) >= 3]
    pdups.sort(key=lambda x: -len(x[0]))

    if not pdups:
        print("  (no duplicate prefixes ≥3B among labelled entries)")
    else:
        shown_pairs = set()
        for hb, occs in pdups:
            block_ids = tuple(sorted(set(bi for bi, _, _, _ in occs)))
            # maximal
            is_max = True
            for hb2, o2 in pdups:
                if len(hb2) > len(hb) and hb2.startswith(hb):
                    b2 = set(bi for bi,_,_,_ in o2)
                    if set(block_ids) <= b2:
                        is_max = False; break
            if not is_max: continue
            if block_ids in shown_pairs: continue
            shown_pairs.add(block_ids)
            print(f"\n  Prefix [{hb.hex()}] ({len(hb)} B) shared by {len(block_ids)} labelled blocks:")
            s = set()
            for bi, n, start, head in occs:
                if bi in s: continue
                s.add(bi)
                lbl = addr2label.get(start, '')
                print(f"    @{start:#05x} <{lbl}>: " +
                      ' ; '.join(a for _, _, a in head))

    return tail_hashes, pattern_hashes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Load raw .text for byte-level scanning
    with open('/tmp/limb8_text.bin', 'rb') as f:
        limb8_text = f.read()
    with open('/tmp/limb11_text.bin', 'rb') as f:
        limb11_text = f.read()

    limb8_insns, limb8_labels = parse_disassembly('/tmp/limb8.dis')
    limb11_insns, limb11_labels = parse_disassembly('/tmp/limb11.dis')

    # limb8: native code is 0xa1..0x37b, but 0x14c..0x1b6 is jump table + constants
    # The jump table is at 0x14c..0x155 (10 bytes)
    # cGX/cGY/cN are at 0x156..0x1b5 (96 bytes)
    # So native is 0xa1..0x14c + 0x1b6..0x37b
    # For simplicity scan the whole thing but report which region.
    print("#" * 70)
    print("# limb8 (.text 891 B)")
    print("# Native regions: 0xa1..0x14c (pre-constants), 0x1b6..0x37b (post-constants)")
    print("#" * 70)
    # For Search 1, we want to scan NATIVE code only (skip bytecode + constants)
    # Easiest: filter by address ranges
    limb8_native = [(a,b,asm) for a,b,asm in limb8_insns
                    if (0xa1 <= a < 0x14c) or (0x1b6 <= a < 0x37b)]
    # But search functions work on the full list with range params; we'll do
    # two passes.
    search1_offset_decode(limb8_insns, limb8_labels, "limb8 [pre-const 0xa1..0x14c]",
                          0xa1, 0x14c)
    search1_offset_decode(limb8_insns, limb8_labels, "limb8 [post-const 0x1b6..0x37b]",
                          0x1b6, 0x37b)
    # For search 2, combine both native regions
    print(f"\n{'#'*70}")
    print("# limb8 — tail/prefix sharing across BOTH native regions")
    print(f"{'#'*70}")
    # Make a combined insn list (skip the constant gap)
    combined = [(a,b,asm) for a,b,asm in limb8_insns
                if (0xa1 <= a < 0x14c) or (0x1b6 <= a < 0x37b)]
    # For the label filter we need to adjust — pass 0xa1..0x37b and let
    # the block-builder handle it (constants will form a garbage block
    # but won't have labels so won't show up in prefix analysis)
    search2_tail_sharing(limb8_insns, limb8_labels, "limb8", 0xa1, 0x37b)

    print("\n\n")
    print("#" * 70)
    print("# limb11x24 (.text 755 B)")
    print("# Native region: 0x0b..0x2f3 (jump table is 0x00..0x0a)")
    print("#" * 70)
    search1_offset_decode(limb11_insns, limb11_labels, "limb11x24", 0x0b, 0x2f3)
    search2_tail_sharing(limb11_insns, limb11_labels, "limb11x24", 0x0b, 0x2f3)


if __name__ == '__main__':
    main()
