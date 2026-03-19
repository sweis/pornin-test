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
# ZERO dropped — Fsub(x,x)=0 (slots hold valid values at init time).
OPS = {'Fmul':0, 'Fadd':1, 'Fsub':2, 'Nmul':3,
       'CHKLT':4, 'CHKZ':5, 'INV':6, 'NORM':7,
       'SET1':8, 'COPY':9, 'COPYHI':10}
# CHKNZ dropped: encode as CHKZ with dst=1 (handler shr's dst·SLOT to flip bit).

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
    # Entry: r@13, s@14, Qx@5, Qy@6, e@7, cP@8, cN@9, cR2_n@10, Gx@11, Gy@12.
    # Free: 0,1,2,3,4. Temps: 2,3 (on-curve). INV dst: 3.

    # ── Range checks ──
    ('CHKLT', 0, 13, 9),  # r < n
    ('CHKLT', 0, 14, 9),  # s < n
    ('CHKLT', 0,  5, 8),  # Qx < p
    ('CHKLT', 0,  6, 8),  # Qy < p

    # ── s_mont → 14 (overwrite s); consumes cR2_n @ 10 ──
    ('Nmul', 14, 14, 10),

    # ── b-derive (G @ 11,12; b → 10). Gx² → slot 2, survives for G-scale. ──
    ('Fmul', 10, 12, 12),
    ('Fmul',  2, 11, 11),  # Gx² → 2 (REUSED by G-scale)
    ('Fmul',  4,  2, 11),  # Gx³ = Gx²·Gx
    ('Fsub', 10, 10,  4),
    ('Fadd',  4, 11, 11),
    ('Fadd',  4,  4, 11),
    ('Fadd', 10, 10,  4),

    # ── On-curve: Y²Z − X³ + 3XZ² − bZ³ ≡ 0, all @ level −2 ──
    # Z=1 @ 15 (RCB-safe). 3Qx temp → slot 0 (free — r moved to 13).
    # Slot 2 stays Gx² (not touched here).
    ('SET1', 15,  0,  0),  # Z = 1
    ('Fmul',  4,  6,  6),  # Qy²  @ −1
    ('Fmul',  4,  4, 15),  # Qy²·Z  @ −2
    ('Fmul',  3,  5,  5),  # Qx²  @ −1
    ('Fmul',  3,  3,  5),  # Qx³  @ −2
    ('Fsub',  4,  4,  3),
    ('Fmul',  3, 15, 15),  # Z²  @ −1
    ('Fadd',  0,  5,  5),  # 2Qx  @ 0
    ('Fadd',  0,  0,  5),  # 3Qx  @ 0
    ('Fmul',  0,  0,  3),  # 3Qx·Z²  @ −2
    ('Fadd',  4,  4,  0),
    ('Fmul',  3,  3, 15),  # Z³  @ −2
    ('Fmul',  3, 10,  3),  # b·Z³  @ −2
    ('Fsub',  4,  4,  3),
    ('NORM',  4,  4,  0),
    ('CHKZ',  0,  4,  0),

    # ── INV (s_mont @ 14; w_mont → 3) ──
    ('COPY',  3, 14,  0),
    ('INV',   3, 14,  0),

    # ── (r+n) → 14 for bc_v3 (r·Z derived as (r+n)Z − nZ); u1,u2 → 0,1 ──
    ('Fadd', 14, 13,  9),  # (r+n) @ level 0 → 14. r<n, n<2^256 → r+n<2^257.
    ('Nmul',  1, 13,  3),  # u2 = r·w → 1
    ('Nmul',  0,  7,  3),  # u1 = e·w → 0

    # ── G-scale: (Gx², Gx·Gy, Gx_mont) → 2,3,4. Gx² already @ 2 from b-derive. ──
    ('COPY',  4, 11,  0),  # Gx_mont → 4 (Z_G)
    ('Fmul',  3, 11, 12),  # Gx·Gy → 3

    # ── Z_Q = plain 1 ──
    ('COPY',  7, 15,  0),

    # ── Shamir backup ──
    ('COPYHI', 0,  2, 0),  # 2,3 → 16,17 (Gx², Gx·Gy)
    ('COPYHI', 2,  4, 0),  # 4,5 → 18,19 (Gx_mont=Z_G, Qx)
    ('COPYHI', 4,  6, 0),  # 6,7 → 20,21 (Qy, 1=Z_Q)
    ('COPYHI', 6,  0, 0),  # 0,1 → 22,23 (u1, u2)

    # ── acc = (0:1:0). Fsub(x,x)=0 — ZERO handler not needed. Both
    # slots hold valid values here (0=u1, 2=Gx²) so self-subtract is safe. ──
    ('Fsub', 0, 0, 0),
    ('SET1', 1, 0, 0),
    ('Fsub', 2, 2, 2),
]


# ──────────────────────────────────────────────────────────────────────
# bc_v3: projective final check with level-alignment.
# ──────────────────────────────────────────────────────────────────────
# X,Z at unknown level L (data-dep). r_plain @ 14, n @ 9. Both level 0.
# r·Z = Fmul(r@0, Z@L) = L−1. X is at L — mismatch.
# X·1 = Fmul(X@L, 1@0) = L−1. Now both sides match.

V3 = [
    # 1 @ 15, (r+n) @ 14 — both RCB-safe, bc_v1 put them there.
    # r·Z derived as (r+n)·Z − n·Z (saves storing r separately).
    ('Fmul',  5,  0, 15),  # X·1  @ L−1
    ('Fmul',  4, 14,  2),  # (r+n)·Z  @ L−1
    ('Fmul',  3,  9,  2),  # n·Z  @ L−1  (n @ slot 9, level 0)
    ('Fsub',  3,  4,  3),  # r·Z = (r+n)·Z − n·Z
    ('Fsub',  3,  5,  3),  # d1 = X·1 − r·Z
    ('Fsub',  4,  5,  4),  # d2 = X·1 − (r+n)·Z
    ('Fmul',  3,  3,  4),  # d1·d2
    ('NORM',  3,  3,  0),
    ('CHKZ',  0,  3,  0),
    # ∞ check (Wycheproof tcId=292 — Z can be kp, NORM required)
    ('NORM',  2,  2,  0),
    ('CHKZ',  1,  2,  0),   # dst=1 → handler flips: CHKNZ semantics
]


# ──────────────────────────────────────────────────────────────────────
# Slot lifetime simulator — catches read-before-write / overwrite bugs
# ──────────────────────────────────────────────────────────────────────
READS  = {'Fmul':(1,2), 'Fadd':(1,2), 'Fsub':(1,2),
          'Nmul':(1,2), 'CHKLT':(1,2), 'CHKZ':(1,), 'INV':(0,1),
          'NORM':(1,), 'SET1':(), 'COPY':(1,),
          'COPYHI':(1,)}
WRITES = {'Fmul', 'Fadd', 'Fsub', 'Nmul', 'INV',
          'NORM', 'SET1', 'COPY', 'CHKLT'}  # CHKLT trashes dst (Fsub scratch)

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
    v1_init = {5:'Qx', 6:'Qy', 7:'e', 8:'cP', 9:'cN',
               10:'cR2n', 11:'Gx', 12:'Gy', 13:'r', 14:'s'}
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
    v3_init = {0:'X', 1:'Y', 2:'Z', 8:'cP', 9:'cN', 14:'r_plus_n', 15:'one'}
    errs, _ = simulate('v3', V3, v3_init, {})
    if errs:
        print("/* V3 LIFETIME ERRORS: */", file=sys.stderr)
        for e in errs: print(e, file=sys.stderr)
        sys.exit(1)
    print("/* V3 lifetime: clean */", file=sys.stderr)
