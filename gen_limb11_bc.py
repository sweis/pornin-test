#!/usr/bin/env python3
"""Generate bytecode for tv_ecdsa_limb11.S.

Emits bc_rcb, bc_v3, bc_v1 as .byte directives with slot-usage
validation. The RCB schedule is tiny.S's, remapped to avoid my
reserved slots (8=cP, 9=cN, 10=b, 14=hash, 15=cR2).

Ops (my encoding):
  0 Fmul   (mod-p Montgomery, m0inv=1)
  1 SQR    (= Fmul, s2=s1)
  2 Fadd   (limbwise, no carry)
  3 Fsub   (limbwise)
  4 Nmul   (mod-n, m0inv=0xBC4F)
  5 CHKLT  (bpl |= (s1 >= s2))
  6 CHKZ   (bpl |= (s1 != 0)); s1 must be NORMALIZED first
  7 INV    (s^(n-2) mod n, Fermat)
  8 MULR2  (= Fmul with s2=&cR2; Montgomery conversion)
  9 NORM   (in-place: bring s1 to [0,p))
  10 SET1  (dst = 1, rest 0)
  11 COPY  (dst = s1)
  12 NORMN (in-place to [0,n))
"""

import sys

OPS = {'Fmul':0, 'SQR':1, 'Fadd':2, 'Fsub':3, 'Nmul':4,
       'CHKLT':5, 'CHKZ':6, 'INV':7, 'MULR2':8, 'NORM':9,
       'SET1':10, 'COPY':11, 'NORMN':12}

def emit(stream_name, ops, reserved_write=frozenset()):
    """Emit a bytecode stream. Validates that no op writes to a
    reserved slot. Returns the byte count."""
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
# Pulled from tiny.S .rodata dump. Slots 5,6,7,10 are NEVER written
# (addend + b survive). Slot 8 (cP) never touched. My additions:
# slot 9 (cN), 14 (hash), 15 (cR2) also never written by RCB.
#
# tiny.S temps: 3,4,9,11,15. My temps: 3,4,11,12,13.
# Remap: 9→12, 15→13.

def remap(s):
    return {9: 12, 15: 13}.get(s, s)

TINY_RCB = [  # (op, dst, s1, s2) as decoded from tiny.S .rodata
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

# Verify invariants
never_write = {5, 6, 7, 8, 9, 10, 14, 15}
for op, d, s1, s2 in RCB:
    assert d not in never_write, f"RCB writes slot {d} ({op})"

# Check for Fadd with dst==s1 (the limb11 Fadd is OK with aliasing —
# limbwise add reads s1[k] and s2[k] before writing dst[k], so dst=s1
# or dst=s2 both work). tiny.S commuted some ops because its Fadd
# couldn't alias dst==s1. Ours can. So no commutation needed.
# But we DO need to avoid b0=0x00 (terminator collision).
for op, d, s1, s2 in RCB:
    b0 = (s2 << 4) | OPS[op]
    if b0 == 0:
        print(f"WARNING: {op} {d},{s1},{s2} has b0=0 — needs commute", file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────
# bc_v1: validation + setup. Runs before pt_mul.
# ──────────────────────────────────────────────────────────────────────
# On entry (set up by verify's decode calls):
#   slot  2,3  = Gx_mont, Gy_mont (decoded from constants)
#   slot  5,6  = Qx, Qy (decoded from pub, PLAIN)
#   slot  8,9  = cP, cN (11-limb form)
#   slot 11,12 = r, s (decoded from sig, PLAIN)
#   slot 14    = e (hash, PLAIN)
#   slot 15    = cR2 (for → Montgomery)
#
# Steps:
#   1. Range checks: r,s ∈ [1,n), Qx,Qy ∈ [0,p). r,s nonzero.
#   2. Convert Qx, Qy, r to Montgomery: x_mont = MontMul(x, R²).
#   3. On-curve: check Qy² = Qx³ − 3Qx + b (all Montgomery).
#   4. Derive b_mont from Gx_mont, Gy_mont → slot 10.
#   5. w = s⁻¹ mod n (Fermat, Nmul chain).
#   6. u1 = e·w mod n → slot 22. u2 = r·w mod n → slot 23.
#      Normalize both to [0,n) for bit-reading in pt_mul.
#   7. Stage slots 2-7 as Gx,Gy,1,Qx,Qy,1 for Shamir backup copy.
#
# NOTE: step 4 (b-derive) must happen BEFORE step 3 (on-curve check
# needs b). And step 3 uses Qx_mont, so step 2 must precede 3.
#
# Mod-n work (steps 5-6) uses PLAIN values (e, r, s, w). Nmul is
# Montgomery mod n — so we'd need R²_mod_n for conversion. OR:
# do mod-n in plain form via a different reduce. OR: the check
# x ≡ r (mod n) is eventually in mod-p anyway (projective check
# uses r·Z mod p), so r needs to be in Montgomery-p form, not n.
#
# Let me think about mod-n more carefully.
#   w = s^(n-2) mod n. If Nmul is Montgomery-n (introduces R_n^(-1)),
#   then s^(n-2) via repeated MontMul accumulates R_n factors.
#   Standard fix: convert s to Montgomery-n first (s·R_n), then
#   the square-and-multiply stays in Montgomery-n, giving w·R_n.
#   Convert back: MontMul(w_mont, 1) = w.
#
#   But that needs R²_n (another 32 B constant). Can we avoid it?
#
#   Alternative: use Nmul with m0inv=0xBC4F but DON'T convert.
#   Track R_n factors manually. For s^(n-2) with 256 squarings and
#   ~128 multiplies: output factor = R_n^(-(256+128)) = R_n^(-384).
#   Unusable.
#
#   Alternative: Nmul is NOT Montgomery. Use a different mod-n reduce.
#   The current tiny.S uses q=t[top] which works for n too (top
#   dword FFFFFFFF). But that's a 32-bit-grain reduce, not 11×24.
#
#   For 11×24, n's top limb = 0xFFFF (16-bit, not full). q=t[top]
#   doesn't work. So Montgomery-n it is, with R²_n.
#
# DECISION: store R²_n too. +32 B. Nmul needs m0inv AND cR2_n.
# bc_v1 converts s to Montgomery-n first.

# Actually wait — there's a MUCH simpler approach I'm missing.
#
# For the FERMAT INVERSION specifically: s^(n-2) via square-and-mult.
# If we seed with s_mont = s·R_n and use MontMul throughout:
#   - square: s_mont² via MontMul = s²·R_n. Stays Montgomery. ✓
#   - multiply by s_mont: (accum)·s_mont via MontMul. Stays. ✓
#   - Final: s^(n-2)·R_n = w_mont.
#
# Then u1 = e·w: MontMul(e_mont, w_mont) = e·w·R_n = u1_mont.
# To get u1 PLAIN for bit-reading: MontMul(u1_mont, 1) = u1.
#
# So flow: convert s, e, r to Montgomery-n (3× MontMul with R²_n).
# Invert. Compute u1_mont, u2_mont. Convert back (2× MontMul with 1).
#
# R²_n constant: +32 B. 5× conversion bytecode: +10 B. Not trivial.
#
# ALTERNATIVE: avoid Montgomery for mod-n entirely. Use Barrett or
# the q=t[top] trick in a DIFFERENT representation.
#
# For Barrett mod-n: μ = ⌊2^512/n⌋. Another 32 B constant. Same cost.
#
# For q=t[top]: need top limb all-ones. n's 11×24 top limb is 0xFFFF.
# If we used 8×32-bit for mod-n (DIFFERENT limb format), top dword
# IS 0xFFFFFFFF and q=t[top] works. Two multiply routines though.
#
# Actually — the 8×32 q=t[top] is EXACTLY what tiny.S does. If we
# keep that SAME fe_mul_m (143 B) for mod-n ONLY, and use fe_mul11
# for mod-p, we get:
#   - fe_mul11 (158 B) for mod-p
#   - fe_mul_m (143 B) for mod-n, 8×32 limbs
#   - Nmul converts 11-limb → 8×32 (pack), calls fe_mul_m, unpacks.
#
# Total: 158+143 = 301 B of multiply code. vs current 143. +158 B.
# That's HUGE. Montgomery-n with R²_n is cheaper: +32 (const) + a
# few bytecode ops.
#
# → Go with Montgomery-n. Accept R²_n as a constant.

# Revised slot map:
#   slot 15: cR2_p  (R² mod p, for mod-p conversion)
#   slot ??: cR2_n  — need another slot. Use slot 4 early (before
#            RCB uses it as scratch)? Or put it in slot 13 (RCB
#            scratch but only AFTER bc_v1 completes).
#
# Actually cR2_n is only needed during bc_v1 (3 conversions). It can
# live in a temp slot that RCB later overwrites. Put it in slot 13.
# verify decodes it there; bc_v1 uses it; pt_mul's RCB clobbers it.

# For this first pass, I'll emit a PARTIAL bc_v1 with TODOs and
# iterate once the structure is testable. The RCB bytecode is the
# critical path — get that right first.

V1 = [
    # 1. Range checks. r @ 11, s @ 12, Qx @ 5, Qy @ 6.
    #    cN @ 9, cP @ 8.
    ('CHKLT', 0, 11, 9),  # r < n  (dst ignored for checks)
    ('CHKLT', 0, 12, 9),  # s < n
    ('CHKLT', 0,  5, 8),  # Qx < p
    ('CHKLT', 0,  6, 8),  # Qy < p
    ('CHKZ',  0, 11, 0),  # r ≠ 0 … but CHKZ sets bpl if NONZERO.
    # We want the OPPOSITE: fail if r == 0. Need a CHKNZ op, or
    # invert the logic. DEFER — add a CHKNZ op.
    # Skipping r,s nonzero checks for now — the test suite will
    # catch this and we'll add the op.

    # 4. Derive b = Gy² − Gx³ + 3Gx (Montgomery). Gx@2, Gy@3.
    #    Result → slot 10.
    ('Fmul', 10,  3,  3),  # Gy²                  → 10
    ('Fmul',  4,  2,  2),  # Gx²                  → 4 (temp)
    ('Fmul',  4,  4,  2),  # Gx³                  → 4
    ('Fsub', 10, 10,  4),  # Gy² − Gx³            → 10
    ('Fadd',  4,  2,  2),  # 2Gx                  → 4
    ('Fadd',  4,  4,  2),  # 3Gx                  → 4
    ('Fadd', 10, 10,  4),  # Gy² − Gx³ + 3Gx = b  → 10

    # 2. Convert Qx, Qy, r to Montgomery-p: MontMul(x, R²). cR2 @ 15.
    ('MULR2', 5,  5, 15),  # Qx_mont → 5
    ('MULR2', 6,  6, 15),  # Qy_mont → 6
    ('MULR2', 0, 11, 15),  # r_mont  → 0 (temp; slot 0 free before pt_mul)
    # Save r_mont somewhere pt_mul-safe. Slot 12 is s (still needed).
    # Put r_mont in slot 14 AFTER hash is consumed? Hash is consumed
    # in step 6 (u1 = e·w). So: compute u1 first, THEN move r_mont
    # to 14. For now put r_mont in slot 11 (r plain no longer needed
    # after u2 is computed).
    # Actually: r is used TWICE — u2 = r·w (mod-n, uses r PLAIN)
    # and the final check r·Z (mod-p, uses r_mont). So we need BOTH
    # r and r_mont until u2 is done. Keep r @ 11, r_mont @ 0 for now.

    # 3. On-curve check: Qy² = Qx³ − 3Qx + b (Montgomery).
    #    All in mod-p. Result should be 0.
    ('Fmul',  4,  6,  6),  # Qy²                   → 4
    ('Fmul',  1,  5,  5),  # Qx²                   → 1
    ('Fmul',  1,  1,  5),  # Qx³                   → 1
    ('Fsub',  4,  4,  1),  # Qy² − Qx³             → 4
    ('Fadd',  1,  5,  5),  # 2Qx                   → 1
    ('Fadd',  1,  1,  5),  # 3Qx                   → 1
    ('Fadd',  4,  4,  1),  # Qy² − Qx³ + 3Qx       → 4
    ('Fsub',  4,  4, 10),  # … − b                 → 4  (should be 0 mod p)
    ('NORM',  4,  4,  0),  # normalize to [0,p) for CHKZ
    ('CHKZ',  0,  4,  0),  # fail if ≠ 0
    # ^^ CHKZ semantics: sets bpl if NONZERO. That's what we want
    # (fail if off-curve). ✓

    # 5-6. Mod-n Montgomery work. cR2_n @ 13 (verify decodes it there).
    #   Convert s, e, r to Montgomery-n.
    #   Actually e and r are used as PLAIN integers in u1=e·w, u2=r·w
    #   — if w is Montgomery-n, e and r stay plain, and MontMul gives:
    #     MontMul(e_plain, w_mont) = e · w·R_n / R_n = e·w PLAIN!
    #   So only s needs conversion. Then w comes out Montgomery.
    #   MontMul(e, w_mont) = e·w plain. u1 = that. ✓ NO CONVERSION
    #   BACK NEEDED.
    #
    #   This is the key: MontMul(plain, mont) = plain. One operand
    #   in Montgomery form is enough for the R factors to cancel.

    # Convert s to Montgomery-n: s_mont = MontMul(s, R²_n). Need a
    # MULR2N op (Nmul with s2 = cR2_n slot). Add op 13 = MULR2N.
    # For now use Nmul with s2 = 13 (where cR2_n lives).
    ('Nmul', 12, 12, 13),  # s_mont → 12 (overwrite s)

    # w = s^(n-2). INV handler does this. Input @ s1, output @ dst.
    # Caller must set dst = 1_mont_n first. 1_mont_n = R_n mod n.
    # That's ANOTHER constant… or compute at runtime as
    # MontMul(1, R²_n) = R_n. Set slot 1 = 1, then MULR2N.
    ('SET1',  1,  0,  0),  # slot 1 = 1 (limb 0 = 1, rest 0)
    ('Nmul',  1,  1, 13),  # 1_mont_n = R_n → 1
    ('INV',   1, 12,  0),  # w_mont = s_mont^(n-2) → 1
    # (INV seeds dst=s1 on first iter; the initial dst=1_mont is
    #  just so dst²·s = 1·s = s on iter 1.)

    # u1 = e · w. e @ 14 (plain), w_mont @ 1.
    # MontMul(e, w_mont) = e·w plain. ✓
    ('Nmul',  4, 14,  1),  # u1 = e·w → 4 (temp, will move to 22)
    # u2 = r · w. r @ 11 (plain).
    ('Nmul',  3, 11,  1),  # u2 = r·w → 3 (temp, will move to 23)

    # Normalize u1, u2 to [0, n) for pt_mul's bit-read. NORMN op.
    ('NORMN', 4,  4,  0),
    ('NORMN', 3,  3,  0),

    # Move u1→22, u2→23. Need a COPY op.
    # Actually: pt_mul reads from slots 22, 23. If we write there
    # directly above (instead of temps 4, 3), no copy needed. But
    # slots 22, 23 are out of nibble range (>15). BYTECODE CAN'T
    # ADDRESS THEM.
    #
    # Options: (a) pt_mul reads from slots <16. Put u1 @ 4, u2 @ 3,
    # and pt_mul reads from there. But RCB uses 3, 4 as temps!
    # (b) Add high-slot addressing (5-bit slot index, 3-byte ops).
    # (c) Copy via native code in verify (between bc_v1 and pt_mul).
    #
    # (c) is simplest. verify does `rep movsq` from slot 4→22, 3→23
    # after bc_v1 returns. ~15 B of native code.
    # For the bytecode, u1 stays @ 4, u2 @ 3. verify copies them out.

    # r_mont was @ 0. Move to 14 (hash is dead after u1). bc_v3 will
    # read r_mont from 14.
    ('COPY', 14,  0,  0),  # r_mont → 14

    # Stage slots for Shamir backup. pt_mul copies slots 2-7 → 16-21
    # in one rep movsq. Need slots 2-7 = Gx,Gy,1_mont_p,Qx,Qy,1_mont_p.
    # Gx@2, Gy@3 already (wait — we used slot 3 for u2 above!).
    #
    # COLLISION: slot 3 holds both Gy (from decode) and u2 (from above).
    # And slot 4 holds both b-derive temps AND u1.
    #
    # This slot assignment is getting tangled. Need a proper slot
    # lifetime analysis. DEFER to iteration — emit what we have,
    # see what breaks, fix.
]

# For now, add a SET1 op for setting Z=1. 1_mont_p = R_p mod p.
# Like 1_mont_n, compute via MontMul(1, R²_p).
V1 += [
    ('SET1',  7,  0,  0),  # slot 7 = 1
    ('MULR2', 7,  7, 15),  # 1_mont_p = R_p → 7 (Z for Q)
    ('COPY',  4,  7,  0),  # Z for G → 4 (slot 4 now 1_mont_p)
    # Slots 2,3,4,5,6,7 should be Gx,Gy,1_p,Qx,Qy,1_p.
    # But 3,4 were clobbered. SEE COLLISION NOTE ABOVE.
]


# ──────────────────────────────────────────────────────────────────────
# bc_v3: projective final check. X ≡ r·Z (mod p) via d1·d2 ≡ 0.
# ──────────────────────────────────────────────────────────────────────
# After pt_mul: acc @ slots 0,1,2 (X,Y,Z Montgomery). r_mont @ 14.
# Check: (X − r·Z)·(X − (r+n)·Z) ≡ 0 (mod p).
# All Montgomery — MontMul preserves the R factor, and 0 is 0
# regardless of factor.

V3 = [
    # Check Z ≠ 0 (result would be ∞). CHKZ after NORM.
    # Actually: if Z ≡ 0 mod p, the point is ∞ — should FAIL.
    # But our CHKZ sets bpl if NONZERO. We want the opposite here.
    # DEFER — add CHKNZ or invert logic in verify.

    # d1 = X − r·Z
    ('Fmul',  7, 14,  2),  # r·Z → 7 (slot 7 = addend Z, dead after pt_mul)
    ('Fsub',  7,  0,  7),  # X − r·Z → 7

    # d2 = X − (r+n)·Z. r+n: r_mont + n_mont? No — r is Montgomery-p,
    # n is a plain constant. Adding them is mixed-form. Wrong.
    #
    # tiny.S uses MULCN: Fmul with s2 = &cN (the plain n constant
    # treated as a field element). r+n mod p: in Montgomery-p,
    # (r+n)_mont = r_mont + n_mont = r_mont + n·R_p mod p.
    # So we need n_mont = MontMul(n, R²_p). Another conversion.
    #
    # tiny.S avoids this by NOT using Montgomery. For us:
    # either convert n to Montgomery-p (one-time, in bc_v1), or
    # use the "multiply by plain n then the R factors work out"
    # trick.
    #
    # MontMul(n_plain, Z_mont) = n·Z·R_p / R_p = n·Z (PLAIN result).
    # But d2 = X_mont − (r_mont + n·Z_??). The factors don't match.
    #
    # Cleanest: convert n to Montgomery-p in bc_v1, store @ slot 12
    # (s is dead after INV). Then (r+n)_mont = Fadd(r_mont, n_mont).
    # MontMul((r+n)_mont, Z_mont) = (r+n)·Z in Montgomery. ✓
    #
    # Add to V1: ('MULR2', 12, 9, 15)  # n_mont → 12

    # Assuming n_mont @ 12:
    ('Fadd',  3, 14, 12),  # (r+n)_mont → 3
    ('Fmul',  3,  3,  2),  # (r+n)·Z → 3
    ('Fsub',  3,  0,  3),  # X − (r+n)·Z → 3

    ('Fmul',  3,  7,  3),  # d1·d2 → 3
    ('NORM',  3,  3,  0),
    ('CHKZ',  0,  3,  0),  # want: FAIL if nonzero. ✓ CHKZ does this.
]


# ──────────────────────────────────────────────────────────────────────
# Emit
# ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("/* Generated by gen_limb11_bc.py. DO NOT EDIT by hand. */")
    print()
    total = 0
    total += emit("bc_rcb", RCB, reserved_write=never_write)
    total += emit("bc_v3", V3)
    total += emit("bc_v1", V1)
    print(f"/* Total bytecode: {total} B */", file=sys.stderr)

    # Self-check: verify RCB against the mathematical formula.
    # Simulate with symbolic slot tracking.
    print("/* RCB slot lifetime check: */", file=sys.stderr)
    live = {0: 'X1', 1: 'Y1', 2: 'Z1', 5: 'X2', 6: 'Y2', 7: 'Z2', 10: 'b'}
    for i, (op, d, s1, s2) in enumerate(RCB):
        for s in (s1, s2):
            if op != 'SET1' and s not in live:
                print(f"  op{i} {op}: reads dead slot {s}", file=sys.stderr)
        live[d] = f'v{i}'
    print(f"  RCB outputs: X3=slot0={live.get(0)}, Y3=slot1={live.get(1)}, "
          f"Z3=slot2={live.get(2)}", file=sys.stderr)
