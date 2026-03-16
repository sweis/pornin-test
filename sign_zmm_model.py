#!/usr/bin/env python3
"""
Reference model for the all-ZMM ECDSA/P-256 signer.

Design:
  - 5×52-bit redundant limbs (one field element per ZMM, lanes 0-4)
  - AVX-512 IFMA (vpmadd52) for the schoolbook product
  - Montgomery ladder for k·G (constant-time, no secret-dependent branches)
  - cswap via XOR-mask (data-independent)
  - Secrets (k, d, intermediates) NEVER touch memory

This file validates the math before any assembly is written.
"""

# ----------------------------------------------------------------------
# P-256 parameters
# ----------------------------------------------------------------------
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
b_curve = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

R52 = 1 << 52
MASK52 = R52 - 1

# ----------------------------------------------------------------------
# 5×52 representation.  Limb i has weight 2^(52i).  Sum fits 256+ bits.
# "Loose" means limbs may exceed 2^52 (up to ~2^62 during accumulation);
# "tight" means each limb < 2^52.
# ----------------------------------------------------------------------
def to_limbs(x):
    """Split a 256-bit integer into 5 limbs of 52 bits."""
    return [(x >> (52*i)) & MASK52 for i in range(5)]

def from_limbs(L):
    """Recombine.  Handles loose limbs (may exceed 2^52)."""
    return sum(l << (52*i) for i, l in enumerate(L))

def propagate(L):
    """Carry-propagate loose → tight.  O(n) ripple."""
    out = [0]*len(L)
    c = 0
    for i, l in enumerate(L):
        v = l + c
        out[i] = v & MASK52
        c = v >> 52
    if c: out.append(c)
    return out

# ----------------------------------------------------------------------
# IFMA schoolbook multiply: models what vpmadd52 does.
#
# vpmadd52luq dst, a, b:  per-lane  dst += low52(a[51:0] * b[51:0])
# vpmadd52huq dst, a, b:  per-lane  dst += high52(a[51:0] * b[51:0])
#
# The product of two 52-bit values is 104 bits = two 52-bit halves.
# Five IFMA-pairs (one per limb of a) accumulate the full 5×5 product
# into a 9-limb result.  The lane-shift (valignq) aligns each partial
# row to the right output limb.
# ----------------------------------------------------------------------
def ifma_mul_5x5(a, b):
    """
    Model the ZMM-register schoolbook.  Returns 9 loose limbs.

    In assembly this is: for each j, broadcast a[j], then
      vpmadd52luq acc, bcast, b  — products land at limbs [j..j+4]
      vpmadd52huq acc_hi, bcast, b  — high halves land at [j+1..j+5]
    valignq slides acc by one lane per j to keep alignment.
    """
    t = [0]*10   # limb 4×4 high half lands at index 9
    for j in range(5):
        for i in range(5):
            prod = (a[j] & MASK52) * (b[i] & MASK52)  # 104-bit
            t[i+j]   += prod & MASK52    # vpmadd52luq contribution
            t[i+j+1] += prod >> 52       # vpmadd52huq contribution
    return t

# ----------------------------------------------------------------------
# Reduction mod p.  p = 2^256 − 2^224 + 2^192 + 2^96 − 1.
#
# In 52-bit limbs, 2^256 lands mid-limb (256 = 4·52 + 48), so we don't
# get the clean q=t[top] trick the scalar code uses.  Use the standard
# Solinas decomposition instead: express t·2^(52k) mod p as a small
# linear combination of lower limbs.
#
# Key identity:  2^256 ≡ 2^224 − 2^192 − 2^96 + 1  (mod p)
#
# With limb weights 2^0, 2^52, 2^104, 2^156, 2^208:
#   limb 5 has weight 2^260 = 2^256 · 2^4
#   limb 6 has weight 2^312 = 2^256 · 2^56
#   etc.
#
# So t[5]·2^260 ≡ t[5]·2^4·(2^224 − 2^192 − 2^96 + 1)  (mod p).
# Each of those powers of 2 spreads t[5] across the low 5 limbs
# (with shifts).  This is messy because 224, 192, 96 are not
# multiples of 52 — each term straddles two limbs.
#
# RATHER THAN DERIVE THE FULL SOLINAS MATRIX HERE, use the simpler
# "fold high limb" approach:  2^260 mod p is a fixed 256-bit constant.
# Multiply t[5..8] by a precomputed reduction constant and add to
# t[0..4].  Two passes converge (same ≤2-iteration argument as the
# scalar code, because p > 2^255 so the quotient is small).
# ----------------------------------------------------------------------
# 2^260 mod p — the single fold constant.  High limbs fold one at a
# time: t[k]·2^(52k) = t[k]·2^(52(k-5))·2^260 ≡ t[k]·2^(52(k-5))·C.
# Each fold brings the value closer to 5 limbs; a few passes converge.
FOLD260 = pow(2, 260, p)    # 5-limb constant
FOLD260_L = to_limbs(FOLD260)

def reduce_p(t):
    """
    Fold a loose 10-limb product down to 5 tight limbs, mod p.

    The assembly will do this as: multiply t[5..9] (treated as a second
    5-limb number) by FOLD260 using the same IFMA schoolbook, add to
    t[0..4], repeat once.  Here we just compute the correct answer to
    validate against.

    TODO: replace with the exact IFMA-modeled fold once the basic
    pipeline is verified.  For now, correctness > fidelity.
    """
    return to_limbs(from_limbs(propagate(t)) % p)

def fe_mul(a, b, mod=p):
    """Full modular multiply in limb form."""
    t = ifma_mul_5x5(a, b)
    if mod == p:
        return reduce_p(t)
    # For mod n, use generic (slower) — only ~260 calls in signing.
    return to_limbs(from_limbs(propagate(t)) % mod)

def fe_add(a, b, mod=p):
    return to_limbs((from_limbs(a) + from_limbs(b)) % mod)

def fe_sub(a, b, mod=p):
    return to_limbs((from_limbs(a) - from_limbs(b)) % mod)

def fe_inv(a, mod=p):
    return to_limbs(pow(from_limbs(a), mod-2, mod))

# ----------------------------------------------------------------------
# Constant-time conditional swap.  Models AVX-512 vpxorq/vpandq.
# ----------------------------------------------------------------------
def cswap(bit, a, b):
    """Swap a,b iff bit==1.  Returns (a', b').  Data-independent."""
    mask = -bit & ((1<<64)-1)  # 0 or all-ones (per-lane in ZMM)
    a2 = [(ai ^ ((ai ^ bi) & mask)) for ai, bi in zip(a, b)]
    b2 = [(bi ^ ((ai ^ bi) & mask)) for ai, bi in zip(a, b)]
    return a2, b2

# ----------------------------------------------------------------------
# Projective point ops (RCB complete formulas — same as the verifier,
# but in 5×52 limb form).  Reuse the completeness property: no
# branching on point-at-infinity or doubling cases.
# ----------------------------------------------------------------------
def pt_add(P, Q):
    """RCB complete addition, a=-3.  P, Q as (X,Y,Z) limb tuples."""
    X1,Y1,Z1 = P; X2,Y2,Z2 = Q
    bL = to_limbs(b_curve)
    t0 = fe_mul(X1,X2); t1 = fe_mul(Y1,Y2); t2 = fe_mul(Z1,Z2)
    t3 = fe_add(X1,Y1); t4 = fe_add(X2,Y2); t3 = fe_mul(t3,t4)
    t4 = fe_add(t0,t1); t3 = fe_sub(t3,t4); t4 = fe_add(Y1,Z1)
    t5 = fe_add(Y2,Z2); t4 = fe_mul(t4,t5); t5 = fe_add(t1,t2)
    t4 = fe_sub(t4,t5); t5 = fe_add(X1,Z1); Y3 = fe_add(X2,Z2)
    t5 = fe_mul(t5,Y3); Y3 = fe_add(t0,t2); Y3 = fe_sub(t5,Y3)
    Z3 = fe_mul(bL,t2); X3 = fe_sub(Y3,Z3); Z3 = fe_add(X3,X3)
    X3 = fe_add(X3,Z3); Z3 = fe_sub(t1,X3); X3 = fe_add(t1,X3)
    Y3 = fe_mul(bL,Y3); t1 = fe_add(t2,t2); t2 = fe_add(t1,t2)
    Y3 = fe_sub(Y3,t2); Y3 = fe_sub(Y3,t0); t1 = fe_add(Y3,Y3)
    Y3 = fe_add(t1,Y3); t1 = fe_add(t0,t0); t0 = fe_add(t1,t0)
    t0 = fe_sub(t0,t2); t1 = fe_mul(t4,Y3); t2 = fe_mul(t0,Y3)
    Y3 = fe_mul(X3,Z3); Y3 = fe_add(Y3,t2); X3 = fe_mul(t3,X3)
    X3 = fe_sub(X3,t1); Z3 = fe_mul(t4,Z3); t1 = fe_mul(t3,t0)
    Z3 = fe_add(Z3,t1)
    return (X3,Y3,Z3)

# ----------------------------------------------------------------------
# Montgomery ladder.  THE constant-time scalar mult.
#
#   R0, R1 = ∞, G
#   for i = 255 downto 0:
#     b = k[i]
#     cswap(R0, R1, b)      # mask-based, no branch
#     R1 = R0 + R1          # ALWAYS executed
#     R0 = R0 + R0          # ALWAYS executed (doubling via self-add)
#     cswap(R0, R1, b)
#   return R0 = k·G
#
# The cswap makes the memory/register access pattern independent of k.
# Both the add and double ALWAYS happen — no skip-on-zero-bit.
# ----------------------------------------------------------------------
def ladder(k, G):
    Gx_L, Gy_L = to_limbs(G[0]), to_limbs(G[1])
    one = to_limbs(1); zero = to_limbs(0)
    R0 = (zero, one, zero)              # ∞ = (0:1:0)
    R1 = (Gx_L, Gy_L, one)              # G
    for i in range(255, -1, -1):
        bit = (k >> i) & 1
        R0X,R1X = cswap(bit, R0[0], R1[0])
        R0Y,R1Y = cswap(bit, R0[1], R1[1])
        R0Z,R1Z = cswap(bit, R0[2], R1[2])
        R0, R1 = (R0X,R0Y,R0Z), (R1X,R1Y,R1Z)
        R1 = pt_add(R0, R1)             # R0+R1
        R0 = pt_add(R0, R0)             # 2·R0
        R0X,R1X = cswap(bit, R0[0], R1[0])
        R0Y,R1Y = cswap(bit, R0[1], R1[1])
        R0Z,R1Z = cswap(bit, R0[2], R1[2])
        R0, R1 = (R0X,R0Y,R0Z), (R1X,R1Y,R1Z)
    return R0

# ----------------------------------------------------------------------
# ECDSA sign.  k SUPPLIED (RFC 6979 derivation is hash-heavy, do in C).
#
#   R = k·G
#   r = R.x mod n             (public once computed — can touch memory)
#   s = k⁻¹·(e + r·d) mod n   (d and k⁻¹ are secret)
# ----------------------------------------------------------------------
def sign(d, k, e):
    R = ladder(k, (Gx, Gy))
    # Affine x: X/Z mod p (inversion is mod-p, on a PUBLIC value — R
    # is public once we commit to this k, so this inv can touch memory).
    Rx = from_limbs(fe_mul(R[0], fe_inv(R[2])))
    r = Rx % n
    if r == 0: return None  # retry with new k (astronomically rare)
    # Secret arithmetic mod n.  k⁻¹, r·d, and the sum must stay in regs.
    kinv = pow(k, n-2, n)
    s = kinv * (e + r * d) % n
    if s == 0: return None
    return (r, s)

# ----------------------------------------------------------------------
# Verify (reference — to check signatures we produce).
# ----------------------------------------------------------------------
def verify(Q, e, r, s):
    if not (0 < r < n and 0 < s < n): return False
    w = pow(s, n-2, n)
    u1, u2 = e*w % n, r*w % n
    # Naive: two separate ladders (this is the reference, not the impl)
    def smul_aff(k, P):
        R = None
        for i in range(255,-1,-1):
            if R: R = add_aff(R, R)
            if (k>>i)&1: R = add_aff(R, P)
        return R
    P = add_aff(smul_aff(u1,(Gx,Gy)), smul_aff(u2,Q))
    return P is not None and P[0] % n == r

def add_aff(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1==x2:
        if (y1+y2)%p==0: return None
        m = (3*x1*x1-3) * pow(2*y1,p-2,p) % p
    else:
        m = (y2-y1) * pow(x2-x1,p-2,p) % p
    x3=(m*m-x1-x2)%p; return (x3,(m*(x1-x3)-y1)%p)

# ======================================================================
# TESTS
# ======================================================================
if __name__ == '__main__':
    import os

    print("=== 5×52 representation round-trip ===")
    for x in [0, 1, p-1, Gx, Gy, 2**255]:
        assert from_limbs(to_limbs(x)) == x
    print("  OK")

    print("=== IFMA schoolbook × reduction ===")
    for _ in range(1000):
        a = int.from_bytes(os.urandom(32),'big') % p
        b = int.from_bytes(os.urandom(32),'big') % p
        got = from_limbs(fe_mul(to_limbs(a), to_limbs(b)))
        assert got == a*b % p, f"fe_mul fail: {a:x} × {b:x}"
    print("  OK (1000 random)")

    print("=== cswap data-independence ===")
    a, b = to_limbs(Gx), to_limbs(Gy)
    a0,b0 = cswap(0,a,b); a1,b1 = cswap(1,a,b)
    assert (a0,b0)==(a,b) and (a1,b1)==(b,a)
    print("  OK")

    print("=== Montgomery ladder vs reference ===")
    for k in [1, 2, 3, 7, 0xdeadbeef, n-1]:
        R = ladder(k, (Gx,Gy))
        Rx = from_limbs(fe_mul(R[0], fe_inv(R[2])))
        Ry = from_limbs(fe_mul(R[1], fe_inv(R[2])))
        want = None
        for i in range(255,-1,-1):
            want = add_aff(want, want)
            if (k>>i)&1: want = add_aff(want,(Gx,Gy))
        assert (Rx,Ry)==want, f"ladder fail k={k}"
    print("  OK")

    print("=== Full sign → verify round-trip ===")
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    # Public key Q = d·G
    Qp = ladder(d,(Gx,Gy))
    Qx = from_limbs(fe_mul(Qp[0], fe_inv(Qp[2])))
    Qy = from_limbs(fe_mul(Qp[1], fe_inv(Qp[2])))
    for _ in range(20):
        k = int.from_bytes(os.urandom(32),'big') % n or 1
        e = int.from_bytes(os.urandom(32),'big') % n
        sig = sign(d, k, e)
        assert sig and verify((Qx,Qy), e, *sig), "sign/verify mismatch"
    print("  OK (20 random signatures)")

    print("\n=== ALL TESTS PASS — math model ready for assembly ===")
    print("\nZMM register budget for the assembly version:")
    print("  zmm0-2   : R0 = (X:Y:Z)                    [SECRET during ladder]")
    print("  zmm3-5   : R1 = (X:Y:Z)                    [SECRET]")
    print("  zmm6     : k (the nonce)                   [SECRET — never spills]")
    print("  zmm7     : d (private key)                 [SECRET — never spills]")
    print("  zmm8-9   : p, n as 5×52 constants")
    print("  zmm10    : b (curve constant)")
    print("  zmm11-15 : pt_add temporaries t0-t4")
    print("  zmm16-18 : pt_add X3,Y3,Z3 outputs")
    print("  zmm19-27 : fe_mul accumulator + scratch (9-limb product)")
    print("  zmm28-30 : cswap mask + scratch")
    print("  zmm31    : MASK52 constant")
    print("  Total: 32 registers, no spills.  Working set never touches L1D.")
