#!/usr/bin/env python3
"""Generate bytecode for tv_ecdsa_limb11.S.

Emits bc_rcb, bc_v3, bc_v1 as .byte directives with slot-usage
validation. The RCB schedule is tiny.S's, remapped to avoid reserved
slots (8=cP, 9=cN, 10=b, 14=r_mont, 15=cR2/n_mont).

Ops:
  0 Fmul   (mod-p Montgomery, m0inv=1)
  1 SQR    (= Fmul, s2=s1; vestigial, same handler)
  2 Fadd   (limbwise, no carry)
  3 Fsub   (limbwise)
  4 Nmul   (mod-n, m0inv=0xBC4F)
  5 CHKLT  (bpl |= (s1 >= s2))
  6 CHKZ   (bpl |= (s1 != 0)) — s1 must be NORMALIZED first
  7 INV    (s^(n-2) mod n, Fermat; dst pre-seeded with 1_mont_n)
  8 MULR2  (= Fmul, s2 forced to slot 15; Montgomery conversion)
  9 NORM   (in-place to [0,p))
  10 SET1  (dst = {1, 0, ..., 0})
  11 COPY  (dst = s1)
  12 NORMN (in-place to [0,n))
  13 CHKNZ (bpl |= (s1 == 0)) — inverse of CHKZ
"""

import sys

# MULR2 = Fmul with s2=15 (bc_run already sets rdx). SQR never used.
OPS = {'Fmul':0, 'Fadd':1, 'Fsub':2, 'Nmul':3,
       'CHKLT':4, 'CHKZ':5, 'INV':6, 'NORM':7,
       'SET1':8, 'COPY':9, 'CHKNZ':10}

def MULR2(dst, s1): return ('Fmul', dst, s1, 15)

def emit(stream_name, ops, reserved_write=frozenset()):
    print(f"{stream_name}:")
    n = 0
    for op, dst, s1, s2 in ops:
        assert 0 <= dst < 16 and 0 <= s1 < 16 and 0 <= s2 < 16, \
            f"slot out of range: {op} {dst},{s1},{s2}"
        assert dst not in reserved_write, \
            f"{stream_name}: {op} writes reserved slot {dst}"
        opn = OPS[op]
        b0 = (s2 << 4) | opn
        b1 = (dst << 4) | s1
        assert b0 != 0, f"{op} {dst},{s1},{s2} encodes as END (b0=0)"
        print(f"\t.byte\t0x{b0:02x}, 0x{b1:02x}  /* {op:6} {dst:2} ← {s1:2}, {s2:2} */")
        n += 2
    print(f"\t.byte\t0x00  /* END */")
    n += 1
    print(f"\t/* {n} B */")
    print()
    return n


# ──────────────────────────────────────────────────────────────────────
# bc_rcb: RCB-43, tiny.S schedule with 9→12, 15→13 remap.
# ──────────────────────────────────────────────────────────────────────
# tiny.S temps: 3,4,9,11,15. Our temps: 3,4,11,12,13.
# Never written by RCB: 5,6,7,8,9,10,14,15 — addend, cP, cN, b, r_mont,
# cR2/n_mont all survive across every pt_mul iteration.

def remap(s):
    return {9: 12, 15: 13}.get(s, s)

TINY_RCB = [  # decoded from tiny.S .rodata
    ('Fmul', 3, 0, 5), ('Fmul', 4, 1, 6), ('Fmul', 9, 2, 7),
    ('Fadd',11, 0, 1), ('Fadd',15, 5, 6), ('Fmul',11,11,15),
    ('Fadd',15, 3, 4), ('Fsub',11,11,15),
    ('Fadd',15, 1, 2), ('Fadd', 0, 2, 0), ('Fadd', 1, 5, 7),
    ('Fadd', 2, 6, 7), ('Fmul',15,15, 2), ('Fadd', 2, 4, 9),
    ('Fsub',15,15, 2), ('Fmul', 0, 0, 1), ('Fadd', 1, 3, 9),
    ('Fsub', 1, 0, 1), ('Fmul', 2, 9,10), ('Fsub', 0, 1, 2),
    ('Fadd', 2, 0, 0), ('Fadd', 0, 2, 0), ('Fsub', 2, 4, 0),
    ('Fadd', 0, 4, 0), ('Fmul', 1, 1,10), ('Fadd', 4, 9, 9),
    ('Fadd', 9, 4, 9), ('Fsub', 1, 1, 9), ('Fsub', 1, 1, 3),
    ('Fadd', 4, 1, 1), ('Fadd', 1, 4, 1), ('Fadd', 4, 3, 3),
    ('Fadd', 3, 4, 3), ('Fsub', 3, 3, 9), ('Fmul', 4,15, 1),
    ('Fmul', 9, 3, 1), ('Fmul', 1, 0, 2), ('Fadd', 1, 9, 1),
    ('Fmul', 0, 0,11), ('Fsub', 0, 0, 4), ('Fmul', 2,15, 2),
    ('Fmul', 4,11, 3), ('Fadd', 2, 4, 2),
]
assert len(TINY_RCB) == 43

RCB = [(op, remap(d), remap(s1), remap(s2)) for op,d,s1,s2 in TINY_RCB]

RCB_NEVER_WRITE = {5, 6, 7, 8, 9, 10, 14, 15}
for op, d, s1, s2 in RCB:
    assert d not in RCB_NEVER_WRITE, f"RCB writes slot {d} ({op})"
    b0 = (s2 << 4) | OPS[op]
    assert b0 != 0, f"RCB: {op} {d},{s1},{s2} has b0=0 — needs commute"


# ──────────────────────────────────────────────────────────────────────
# bc_v1: validation + setup. Runs before pt_mul.
# ──────────────────────────────────────────────────────────────────────
# Entry (native verify decodes these):
#   slot  2,3  = Gx_mont, Gy_mont
#   slot  5,6  = Qx, Qy (plain, from pub)
#   slot  7    = e (hash, plain) — chains rdi after Qy
#   slot  8,9  = cP, cN (limb form)
#   slot 11,12 = r, s (plain, from sig)
#   slot 14    = cR2_n (chains with cR2_p; dead before r_mont writes 14)
#   slot 15    = cR2_p
#
# Exit:
#   slot 2,3,4 = Gx_mont, Gy_mont, 1_mont_p (→ 16-18 Shamir G backup)
#   slot 5,6,7 = Qx_mont, Qy_mont, 1_mont_p (→ 19-21 Shamir Q backup)
#   slot 10    = b_mont (survives all RCB)
#   slot 11,12 = u1, u2 normalized (→ 22,23 by one contiguous movsq)
#   slot 14    = r_mont (survives RCB, bc_v3 reads)
#   slot 15    = n_mont (survives RCB, bc_v3 reads)
#
# Free during bc_v1: 0, 1, 4, 7 (and 13 once cR2_n consumed).

V1 = [
    # ── 1. Range checks (decoded inputs are canonical from fe_from_be) ──
    ('CHKLT', 0, 11, 9),  # r < n
    ('CHKLT', 0, 12, 9),  # s < n
    ('CHKLT', 0,  5, 8),  # Qx < p
    ('CHKLT', 0,  6, 8),  # Qy < p
    ('CHKNZ', 0, 11, 0),  # r != 0
    ('CHKNZ', 0, 12, 0),  # s != 0

    # ── 2. b = Gy² − Gx³ + 3Gx  (all Montgomery; Gx,Gy read-only) ──
    ('Fmul', 10,  3,  3),
    ('Fmul',  4,  2,  2),
    ('Fmul',  4,  4,  2),
    ('Fsub', 10, 10,  4),
    ('Fadd',  4,  2,  2),
    ('Fadd',  4,  4,  2),
    ('Fadd', 10, 10,  4),  # b_mont → 10

    # ── 3. Qx, Qy → Montgomery-p ──
    MULR2(5, 5),
    MULR2(6, 6),

    # ── 4. On-curve: Qy² − Qx³ + 3Qx − b ≡ 0 ──
    ('Fmul',  4,  6,  6),
    ('Fmul',  1,  5,  5),
    ('Fmul',  1,  1,  5),
    ('Fsub',  4,  4,  1),
    ('Fadd',  1,  5,  5),
    ('Fadd',  1,  1,  5),
    ('Fadd',  4,  4,  1),
    ('Fsub',  4,  4, 10),
    ('NORM',  4,  4,  0),
    ('CHKZ',  0,  4,  0),

    # ── 5. w = s⁻¹ mod n  (Montgomery-n; only s needs conversion) ──
    # INV loops from bit 254, seeded with dst = s_mont (bit 255 of n-2
    # is always 1, so iter 255 with 1_mont seed just gives s_mont — skip it).
    ('Nmul', 12, 12, 14),  # s_mont  (cR2_n @ 14 dead after this)
    ('COPY',  1, 12,  0),  # seed dst = s_mont
    ('INV',   1, 12,  0),  # w_mont → 1

    # ── 6. u1 = e·w, u2 = r·w  (MontMul(plain, mont) = plain) ──
    # r_mont first (reads r@11). Then u2 (reads r, w — both still live
    # after this since Nmul writes to 12). Then u1 → 11 overwrites r.
    # u1,u2 ≥ 0 always: the mod-n chain (e,r,s decoded canonical;
    # cR2_n canonical; MontMul(nonneg,nonneg)=nonneg). And pt_mul
    # computes (k mod n)·G for any k ≥ 0 in 264 bits. No NORMN.
    MULR2(14, 11),         # r_mont → 14
    ('Nmul', 12, 11,  1),  # u2 → 12 (r,w still live — Nmul reads only)
    ('Nmul', 11,  7,  1),  # u1 → 11 (r overwritten; e,w dead)

    # ── 7. Z = 1_mont_p for slots 4, 7  (must run BEFORE step 8) ──
    # Per HANDOFF Z-test: real-point Z must be 1_mont, not plain 1.
    ('SET1',  7,  0,  0),
    MULR2(7, 7),
    ('COPY',  4,  7,  0),

    # ── 8. n_mont = MontMul_p(n, R²_p).  Reads & writes 15; safe
    # because fe_mul11 copies inputs to its stack acc first. ──
    MULR2(15, 9),
]


# ──────────────────────────────────────────────────────────────────────
# bc_v3: projective final check. X ≡ r·Z ∨ X ≡ (r+n)·Z  (mod p)
# ──────────────────────────────────────────────────────────────────────
# After pt_mul: (X:Y:Z) at slots 0,1,2. RCB has clobbered 3,4,11,12,13.
# r_mont @ 14, n_mont @ 15 — both survived (RCB never writes them).

V3 = [
    # d1 = X − r·Z
    ('Fmul',  3, 14,  2),
    ('Fsub',  3,  0,  3),
    # d2 = X − (r+n)·Z
    ('Fadd',  4, 14, 15),
    ('Fmul',  4,  4,  2),
    ('Fsub',  4,  0,  4),
    # d1·d2 ≡ 0
    ('Fmul',  3,  3,  4),
    ('NORM',  3,  3,  0),
    ('CHKZ',  0,  3,  0),
    # ∞ check: Z ≠ 0
    ('NORM',  2,  2,  0),
    ('CHKNZ', 0,  2,  0),
]


# ──────────────────────────────────────────────────────────────────────
# Slot lifetime simulator — catches read-before-write / overwrite bugs
# ──────────────────────────────────────────────────────────────────────
READS  = {'Fmul':(1,2), 'Fadd':(1,2), 'Fsub':(1,2),
          'Nmul':(1,2), 'CHKLT':(1,2), 'CHKZ':(1,), 'INV':(0,1),
          'NORM':(1,), 'SET1':(), 'COPY':(1,), 'CHKNZ':(1,)}
WRITES = {'Fmul', 'Fadd', 'Fsub', 'Nmul', 'INV',
          'NORM', 'SET1', 'COPY'}

def simulate(name, ops, initial, must_survive):
    """Track what each slot holds. Flag reads of dead slots and
    overwrites of slots that must survive to the end."""
    live = dict(initial)  # slot → label
    errors = []
    for i, (op, dst, s1, s2) in enumerate(ops):
        args = (dst, s1, s2)
        for idx in READS[op]:
            s = args[idx]
            if s not in live:
                errors.append(f"  op{i:2} {op:6} reads dead slot {s}")
        if op in WRITES:
            live[dst] = f'{name}[{i}]'
    for s, lbl in must_survive.items():
        if live.get(s) != lbl:
            errors.append(f"  slot {s}: expected '{lbl}', got '{live.get(s)}'")
    return errors, live


# ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("/* Generated by gen_bytecode.py. DO NOT EDIT by hand. */")
    print()
    total = 0
    total += emit("bc_rcb", RCB, reserved_write=RCB_NEVER_WRITE)
    total += emit("bc_v3", V3)
    total += emit("bc_v1", V1)

    # ── Offsets for push-imm8 dispatch ──
    off_v3 = 2*len(RCB) + 1
    off_v1 = off_v3 + 2*len(V3) + 1
    print(f"\t.equ\tobc_rcb, 0")
    print(f"\t.equ\tobc_v3,  {off_v3}")
    print(f"\t.equ\tobc_v1,  {off_v1}")
    assert off_v1 < 128, f"obc_v1 = {off_v1} > 127, push imm8 won't reach"

    # ── Validation ──
    print(f"/* total bytecode: {total} B */", file=sys.stderr)
    print(f"/* obc_v3 = {off_v3}, obc_v1 = {off_v1} (margin: {127-off_v1}) */",
          file=sys.stderr)

    # RCB slot lifetime
    rcb_init = {0:'X1', 1:'Y1', 2:'Z1', 5:'X2', 6:'Y2', 7:'Z2', 10:'b'}
    errs, out = simulate('rcb', RCB, rcb_init, {})
    for e in errs: print(e, file=sys.stderr)
    print(f"/* RCB out: 0={out.get(0)} 1={out.get(1)} 2={out.get(2)} */",
          file=sys.stderr)

    # V1 slot lifetime
    v1_init = {2:'Gx', 3:'Gy', 5:'Qx', 6:'Qy', 7:'e', 8:'cP', 9:'cN',
               11:'r', 12:'s', 14:'cR2n', 15:'cR2p'}
    v1_survive = {2:'Gx', 3:'Gy', 8:'cP', 9:'cN'}
    errs, out = simulate('v1', V1, v1_init, v1_survive)
    if errs:
        print("/* V1 LIFETIME ERRORS: */", file=sys.stderr)
        for e in errs: print(e, file=sys.stderr)
        sys.exit(1)
    print(f"/* V1 out: 4={out.get(4)} 7={out.get(7)} 10={out.get(10)} "
          f"11={out.get(11)} 12={out.get(12)} 14={out.get(14)} "
          f"15={out.get(15)} */", file=sys.stderr)

    # V3 slot lifetime
    v3_init = {0:'X', 1:'Y', 2:'Z', 8:'cP', 14:'r_mont', 15:'n_mont'}
    errs, _ = simulate('v3', V3, v3_init, {})
    if errs:
        print("/* V3 LIFETIME ERRORS: */", file=sys.stderr)
        for e in errs: print(e, file=sys.stderr)
        sys.exit(1)
    print("/* V3 lifetime: clean */", file=sys.stderr)
