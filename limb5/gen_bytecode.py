#!/usr/bin/env python3
"""Generate bytecode for limb5/tv_ecdsa.S. Forked from common/ — the
slot layout diverged: BE decode chain starts at slot 3 (disp8 reach),
all 8 backup values staged contiguous at slots 0-7 for one COPYHI.

Emits bc_rcb, bc_v3, bc_v1 as .byte directives with slot-usage
validation. The RCB schedule is tiny.S's, remapped to avoid reserved
slots (8=cP, 9=cN, 10=b, 14=r+n, 15=one). cP at 8 (not 9) so verify
can build it signed-form right after the BE chain, then chain straight
into the 4-iter LE loop without unrolling.

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
# ZERO dropped — Fsub(x,x)=0. CHKNZ dropped — CHKZ with dst=1 means
# "flip result" (rdi−r14 gives 0 or SLOT; xor ebp, that>>5).
OPS = {'Fmul':0, 'Fadd':1, 'Fsub':2, 'Nmul':3,
       'CHKLT':4, 'CHKZ':5, 'INV':6, 'NORM':7,
       'SET1':8, 'COPY':9, 'COPYHI':10}
CHKNZ_AS_CHKZ_DST1 = True  # emit CHKNZ as CHKZ with dst=1

# cR2_p DROPPED — projective scale-invariance. Q stays plain (level 0),
# G scales by Gx_mont: backup = (Gx², Gx·Gy, Gx_mont), all level 1.

def emit(stream_name, ops, reserved_write=frozenset()):
    print(f"{stream_name}:")
    n = 0
    for op, dst, s1, s2 in ops:
        if op == 'CHKNZ':
            op, dst = 'CHKZ', 1    # dst=1 → handler xors ebp bit 0
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
    # Entry: Qx@3, Qy@4, r@5, s@6, e@7, cP@8, cN@9, cR2_n@10, Gx@11, Gy@12.
    # cN stored as n−2 in rodata — bc_v1 adds 2 before range checks so
    # .Linv can `bt` directly (no bits-0..4 special case). n−2 limb 0
    # differs from n limb 0 by exactly 2 (no borrow past byte 0).
    # cP built signed-form in verify (−1, 2^42, 0, 2^30, 2^40−256);
    # Fsub-based CHKLT works with any s2 limb form since cprop
    # delivers the true sign of value(s1)−value(s2).
    # Exit stages slots 0-7 = (G.X, G.Y, G.Z, Q.X, Q.Y, Q.Z, u1, u2) for
    # one rep movsq to 16-23. Qx,Qy never move (already at 3,4). Temps
    # routed around slot 0 (Gx²) and slots 3,4,5,6 (inputs alive longer).

    # ── SET1 first (also used by on-curve later); n−2 → n via +1 +1 ──
    ('SET1', 15,  0,  0),  # slot 15 = 1 (survives to on-curve/Z_Q)
    ('Fadd',  9,  9, 15),  # n−2 → n−1 (limbwise: only limb 0 changes)
    ('Fadd',  9,  9, 15),  # n−1 → n

    # ── Range checks (CHKLT writes dst=0 as Fsub scratch) ──
    ('CHKLT', 0,  5, 9),  # r < n
    ('CHKLT', 0,  6, 9),  # s < n
    ('CHKLT', 0,  3, 8),  # Qx < p
    ('CHKLT', 0,  4, 8),  # Qy < p

    # ── s_mont → 6 (overwrite s); consumes cR2_n @ 10 ──
    ('Nmul',  6,  6, 10),

    # ── b-derive (G @ 11,12; b → 10). Gx² → slot 0, SURVIVES to G-scale. ──
    ('Fmul', 10, 12, 12),
    ('Fmul',  0, 11, 11),  # Gx² → 0 (on-curve temps avoid slot 0)
    ('Fmul', 13,  0, 11),  # Gx³
    ('Fsub', 10, 10, 13),
    ('Fadd', 13, 11, 11),
    ('Fadd', 13, 13, 11),
    ('Fadd', 10, 10, 13),

    # ── On-curve: temps 1,2,13 (slot 0 stays Gx²; 3,4 stay Qx,Qy). ──
    # slot 15 = 1 already set at top.
    ('Fmul',  2,  4,  4),  # Qy²  @ −1
    ('Fmul',  2,  2, 15),  # Qy²·Z  @ −2
    ('Fmul',  1,  3,  3),  # Qx²  @ −1
    ('Fmul',  1,  1,  3),  # Qx³  @ −2
    ('Fsub',  2,  2,  1),
    ('Fmul',  1, 15, 15),  # Z²  @ −1
    ('Fadd', 13,  3,  3),  # 2Qx  @ 0
    ('Fadd', 13, 13,  3),  # 3Qx  @ 0
    ('Fmul', 13, 13,  1),  # 3Qx·Z²  @ −2
    ('Fadd',  2,  2, 13),
    ('Fmul',  1,  1, 15),  # Z³  @ −2
    ('Fmul',  1, 10,  1),  # b·Z³  @ −2
    ('Fsub',  2,  2,  1),
    ('NORM',  2,  2,  0),
    ('CHKZ',  0,  2,  0),

    # ── INV (s_mont @ 6; w_mont → 13) ──
    ('COPY', 13,  6,  0),
    ('INV',  13,  6,  0),

    # ── (r+n) → 14; u1 → 6 (overwrites s_mont), u2 → 7 (overwrites e) ──
    ('Fadd', 14,  5,  9),  # (r+n) → 14
    ('Nmul',  6,  7, 13),  # u1 = e·w → 6
    ('Nmul',  7,  5, 13),  # u2 = r·w → 7

    # ── G-scale: (Gx², Gx·Gy, Gx_mont) → 0,1,2. Gx² already @ 0. ──
    ('Fmul',  1, 11, 12),  # Gx·Gy → 1
    ('COPY',  2, 11,  0),  # Gx_mont → 2 (Z_G)

    # ── Z_Q = plain 1 → slot 5 (r@5 consumed by u2 above) ──
    ('COPY',  5, 15,  0),

    # ── Shamir backup: slots 0-7 contiguous → one COPYHI (8 slots). ──
    ('COPYHI', 0,  0, 0),  # 0..7 → 16..23

    # ── acc = (0:1:0). ──
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
    ('CHKNZ', 0,  2,  0),
]


# ──────────────────────────────────────────────────────────────────────
# Slot lifetime simulator — catches read-before-write / overwrite bugs
# ──────────────────────────────────────────────────────────────────────
READS  = {'Fmul':(1,2), 'Fadd':(1,2), 'Fsub':(1,2),
          'Nmul':(1,2), 'CHKLT':(1,2), 'CHKZ':(1,), 'INV':(0,1),
          'NORM':(1,), 'SET1':(), 'COPY':(1,), 'CHKNZ':(1,),
          'COPYHI':(1,)}
# CHKLT is Fsub-based (writes dst as scratch).
WRITES = {'Fmul', 'Fadd', 'Fsub', 'Nmul', 'INV',
          'NORM', 'SET1', 'COPY', 'CHKLT'}

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
    v1_init = {3:'Qx', 4:'Qy', 5:'r', 6:'s', 7:'e', 8:'cP', 9:'cN',
               10:'cR2n', 11:'Gx', 12:'Gy', 15:'junk'}
    v1_survive = {8:'cP'}  # slot 9 written by n−2→n fixup; still n semantically
    errs, out = simulate('v1', V1, v1_init, v1_survive)
    if errs:
        print("/* V1 LIFETIME ERRORS: */", file=sys.stderr)
        for e in errs: print(e, file=sys.stderr)
        sys.exit(1)
    print(f"/* V1 out: 4={out.get(4)} 7={out.get(7)} 10={out.get(10)} "
          f"11={out.get(11)} 12={out.get(12)} 14={out.get(14)} "
          f"15={out.get(15)} */", file=sys.stderr)

    # V3 slot lifetime
    v3_init = {0:'X', 1:'Y', 2:'Z', 8:'cP', 9:'n', 14:'r_plus_n', 15:'one'}
    errs, _ = simulate('v3', V3, v3_init, {})
    if errs:
        print("/* V3 LIFETIME ERRORS: */", file=sys.stderr)
        for e in errs: print(e, file=sys.stderr)
        sys.exit(1)
    print("/* V3 lifetime: clean */", file=sys.stderr)
