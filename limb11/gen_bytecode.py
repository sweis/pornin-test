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
# COPYHI: dst nibble means slot(dst+16) — reaches Shamir backup slots.
# ZERO/SET1: write 0 or 1 to limb 0, zero the rest. Shared tail.
OPS = {'Fmul':0, 'Fadd':1, 'Fsub':2, 'Nmul':3,
       'CHKLT':4, 'CHKZ':5, 'INV':6, 'NORM':7,
       'SET1':8, 'COPY':9, 'CHKNZ':10, 'COPYHI':11, 'ZERO':12}

# cR2_p DROPPED — projective scale-invariance. Q stays plain (level 0),
# G scales by Gx_mont: backup = (Gx², Gx·Gy, Gx_mont), all level 1.

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
#   slot  0,1  = r, s (plain)
#   slot  2,3  = Gx_mont, Gy_mont
#   slot  5,6  = Qx, Qy PLAIN — never converted
#   slot  7    = e
#   slot  8,9  = cP, cN
#   slot 10    = cR2_n (consumed before b-derive writes there)
#
# Exit (for pt_mul):
#   slot 2,3,4 = Gx², Gx·Gy, Gx_mont — backup G scaled by Gx (all level 1)
#   slot 5,6,7 = Qx, Qy, 1 — Q plain (level 0), Z_Q = plain 1
#   slot 10    = b_mont (RCB-safe)
#   slot 14    = r_plain (RCB-safe) — bc_v3 reads it
#   slots 0,1  = u1, u2 — COPYHI'd to 22,23
#
# LEVEL TRACKING: G@1, Q@0, b@1. RCB products of G-coord·Q-coord → level 0.
# b·t = 1+0−1 = 0 matches. Doubles: L → 4L−3. Level drifts data-dep but
# X,Y,Z always same level. Final check: X·1 vs r·Z both at L−1.

V1 = [
    # ── Range checks ──
    ('CHKLT', 0,  0, 9),  # r < n
    ('CHKLT', 0,  1, 9),  # s < n
    ('CHKLT', 0,  5, 8),  # Qx < p
    ('CHKLT', 0,  6, 8),  # Qy < p

    # ── s_mont — consume cR2_n @ 10 before b-derive writes there ──
    ('Nmul',  1,  1, 10),

    # ── b-derive (G @ 11,12; b → 10) ──
    ('Fmul', 10, 12, 12),
    ('Fmul',  4, 11, 11),
    ('Fmul',  4,  4, 11),
    ('Fsub', 10, 10,  4),
    ('Fadd',  4, 11, 11),
    ('Fadd',  4,  4, 11),
    ('Fadd', 10, 10,  4),

    # ── On-curve: Y²Z − X³ + 3XZ² − bZ³ ≡ 0, all @ level −2 ──
    # Q @ 0, b @ 1. Z=1 @ slot 15 (RCB-safe, survives for bc_v3's X·1).
    # Slot 2 free now (G moved to 11,12) — use as 3Qx temp.
    ('SET1', 15,  0,  0),  # Z = 1
    ('Fmul',  4,  6,  6),  # Qy²  @ −1
    ('Fmul',  4,  4, 15),  # Qy²·Z  @ −2
    ('Fmul', 13,  5,  5),  # Qx²  @ −1
    ('Fmul', 13, 13,  5),  # Qx³  @ −2
    ('Fsub',  4,  4, 13),
    ('Fmul', 13, 15, 15),  # Z²  @ −1
    ('Fadd',  2,  5,  5),  # 2Qx  @ 0
    ('Fadd',  2,  2,  5),  # 3Qx  @ 0
    ('Fmul',  2,  2, 13),  # 3Qx·Z²  @ −2
    ('Fadd',  4,  4,  2),
    ('Fmul', 13, 13, 15),  # Z³  @ −2
    ('Fmul', 13, 10, 13),  # b·Z³  @ −2
    ('Fsub',  4,  4, 13),
    ('NORM',  4,  4,  0),
    ('CHKZ',  0,  4,  0),

    # ── INV ──
    ('COPY', 13,  1,  0),
    ('INV',  13,  1,  0),  # w_mont → 13

    # ── u1, u2, r_plain ──
    ('COPY', 14,  0,  0),  # r_plain → 14 (RCB-safe; bc_v3 reads it)
    ('Nmul',  1,  0, 13),  # u2 → 1
    ('Nmul',  0,  7, 13),  # u1 → 0 (e @ 7 dead)

    # ── G-scale: backup = (Gx², Gx·Gy, Gx_mont) — all level 1. G @ 11,12. ──
    ('COPY',  4, 11,  0),  # Gx_mont → 4 (Z_G)
    ('Fmul',  2, 11, 11),  # Gx² → 2
    ('Fmul',  3, 11, 12),  # Gx·Gy → 3

    # ── Z_Q = plain 1 (reuse on-curve's Z @ 15) ──
    ('COPY',  7, 15,  0),

    # ── Shamir backup ──
    ('COPYHI', 0,  2, 0),  # 2,3 → 16,17 (Gx², Gx·Gy)
    ('COPYHI', 2,  4, 0),  # 4,5 → 18,19 (Gx_mont=Z_G, Qx)
    ('COPYHI', 4,  6, 0),  # 6,7 → 20,21 (Qy, 1=Z_Q)
    ('COPYHI', 6,  0, 0),  # 0,1 → 22,23 (u1, u2)

    # ── acc = (0:1:0) ──
    ('ZERO', 0, 0, 0),
    ('SET1', 1, 0, 0),
    ('ZERO', 2, 0, 0),
]


# ──────────────────────────────────────────────────────────────────────
# bc_v3: projective final check with level-alignment.
# ──────────────────────────────────────────────────────────────────────
# X,Z at unknown level L (data-dep). r_plain @ 14, n @ 9. Both level 0.
# r·Z = Fmul(r@0, Z@L) = L−1. X is at L — mismatch.
# X·1 = Fmul(X@L, 1@0) = L−1. Now both sides match.

V3 = [
    # 1 @ slot 15 survives pt_mul (RCB-safe, on-curve put it there).
    ('Fmul',  5,  0, 15),  # X·1  @ L−1
    # d1 = X·1 − r·Z
    ('Fmul',  3, 14,  2),  # r·Z  @ L−1  (r@0 · Z@L)
    ('Fsub',  3,  5,  3),
    # d2 = X·1 − (r+n)·Z
    ('Fadd',  4, 14,  9),  # r+n  @ 0  (n from slot 9, RCB-safe)
    ('Fmul',  4,  4,  2),  # (r+n)·Z  @ L−1
    ('Fsub',  4,  5,  4),
    # d1·d2 ≡ 0
    ('Fmul',  3,  3,  4),
    ('NORM',  3,  3,  0),
    ('CHKZ',  0,  3,  0),
    # ∞ check: Z ≠ 0 (Wycheproof tcId=292 — Z can be kp, NORM required)
    ('NORM',  2,  2,  0),
    ('CHKNZ', 0,  2,  0),
]


# ──────────────────────────────────────────────────────────────────────
# Slot lifetime simulator — catches read-before-write / overwrite bugs
# ──────────────────────────────────────────────────────────────────────
READS  = {'Fmul':(1,2), 'Fadd':(1,2), 'Fsub':(1,2),
          'Nmul':(1,2), 'CHKLT':(1,2), 'CHKZ':(1,), 'INV':(0,1),
          'NORM':(1,), 'SET1':(), 'COPY':(1,), 'CHKNZ':(1,),
          'COPYHI':(1,), 'ZERO':()}
WRITES = {'Fmul', 'Fadd', 'Fsub', 'Nmul', 'INV',
          'NORM', 'SET1', 'COPY', 'ZERO'}

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
    v1_init = {0:'r', 1:'s', 5:'Qx', 6:'Qy', 7:'e',
               8:'cP', 9:'cN', 10:'cR2n', 11:'Gx', 12:'Gy'}
    v1_survive = {8:'cP', 9:'cN'}
    errs, out = simulate('v1', V1, v1_init, v1_survive)
    if errs:
        print("/* V1 LIFETIME ERRORS: */", file=sys.stderr)
        for e in errs: print(e, file=sys.stderr)
        sys.exit(1)
    print(f"/* V1 out: 4={out.get(4)} 7={out.get(7)} 10={out.get(10)} "
          f"11={out.get(11)} 12={out.get(12)} 14={out.get(14)} "
          f"15={out.get(15)} */", file=sys.stderr)

    # V3 slot lifetime
    v3_init = {0:'X', 1:'Y', 2:'Z', 8:'cP', 9:'cN', 14:'r_plain', 15:'one'}
    errs, _ = simulate('v3', V3, v3_init, {})
    if errs:
        print("/* V3 LIFETIME ERRORS: */", file=sys.stderr)
        for e in errs: print(e, file=sys.stderr)
        sys.exit(1)
    print("/* V3 lifetime: clean */", file=sys.stderr)
