#!/usr/bin/env python3
"""
Range analysis for signed-limb field arithmetic — version 2.

Tracks MAX-ABS per limb (not intervals; tighter) through the full
RCB×256 scalar-multiply loop. Uses the mathematical Montgomery output
bound (result < 2m) rather than propagating through carry-prop.

Two accumulator modes:
  COLUMN: acc[k] += a[i]*b[j] as a full product. Accumulator must hold
          the sum; no per-product split. Simplest inner loop (13 B).
  SPLIT128: acc[k] is 128-bit; full product added as 128-bit. Needs
            128-bit adds (add+adc). 18 B inner loop.

Key question per config: what's the max input-limb magnitude the
multiply can accept without accumulator overflow, and does the RCB
formula's worst ×7 add/sub chain stay under that?
"""

import sys, random
from dataclasses import dataclass
from typing import List

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

# ──────────────────────────────────────────────────────────────────────
@dataclass
class Cfg:
    K: int
    W: int
    acc_bits: int  # 64 or 128

    @property
    def MASK(self): return (1 << self.W) - 1
    @property
    def R(self): return 1 << (self.K * self.W)

    def split(self, x):
        return [(x >> (self.W*i)) & self.MASK for i in range(self.K)]

    def join(self, limbs):
        return sum(v << (self.W*i) for i, v in enumerate(limbs))

    def m0inv(self, m):
        m0 = m & self.MASK
        inv = 1
        for _ in range(7): inv = (inv * (2 - m0*inv)) & self.MASK
        return (-inv) & self.MASK


# ──────────────────────────────────────────────────────────────────────
# Bound tracker: BOTH limb-level (for register/accumulator fit) and
# value-level (for Montgomery convergence). The limbs can be big and
# cancel; the value is what determines the next multiply's output range.
# ──────────────────────────────────────────────────────────────────────
@dataclass
class Bounded:
    cfg: Cfg
    limb: List[int]   # max |limb_k| — for imul/add overflow check
    val: int          # max |join(limbs)| — for Montgomery convergence

    @classmethod
    def fresh_mul(cls, cfg, val_bound):
        """Post-multiply: limbs 0..K-2 carry-propagated to [0, 2^W),
        top limb absorbs the residual. The VALUE bound is the Montgomery
        output bound; the top-limb bound is derived from it."""
        # After carry-prop: limbs 0..K-2 are in [0, 2^W). The top limb
        # holds (value - low_part) >> ((K-1)*W). Worst case:
        #   |top| ≤ (|value| + low_part_max) / 2^((K-1)W)
        # where low_part_max < 2^((K-1)W). So |top| < |value|/2^((K-1)W) + 1.
        top = (val_bound >> (cfg.W * (cfg.K - 1))) + 1
        b = [cfg.MASK] * cfg.K
        b[-1] = top
        return cls(cfg, b, val_bound)

    def max_limb_bits(self):
        return max(v.bit_length() for v in self.limb) + 1

    def __add__(self, o):
        return Bounded(self.cfg,
                       [a+b for a,b in zip(self.limb, o.limb)],
                       self.val + o.val)

    __sub__ = __add__

    def __repr__(self):
        return f"B(limb≤{self.max_limb_bits()}b, val≤2^{self.val.bit_length()})"


# ──────────────────────────────────────────────────────────────────────
# Accumulator bound analysis — direct, not interval
# ──────────────────────────────────────────────────────────────────────
def mont_mul_bounds(a: Bounded, b: Bounded, m, cfg: Cfg):
    """
    Returns (peak_acc_bits, output_Bounded).

    Accumulator bound: computed from LIMB bounds (what the hardware
    sees — products of individual limb values summed per position).

    Output VALUE bound: computed from VALUE bounds via the Montgomery
    identity |result| ≤ |product|/R + m. The limbs cancel; only the
    represented integer value matters for convergence.
    """
    K, W, MASK = cfg.K, cfg.W, cfg.MASK
    m_limbs = cfg.split(m)

    # ── Accumulator peak (limb-level) ──
    acc = [0] * (2*K)
    for i in range(K):
        for j in range(K):
            acc[i+j] += a.limb[i] * b.limb[j]
    peak = max(acc)
    for i in range(K):
        q_max = MASK
        for j in range(K):
            acc[i+j] += q_max * m_limbs[j]
        acc[i+1] += acc[i] >> W
        acc[i] = 0
        peak = max(peak, max(acc))

    # ── Output value bound (Montgomery identity) ──
    # result = (product + Q·m) / R, where 0 ≤ Q < R.
    # |result| ≤ (|a·b| + R·m) / R = |a|·|b|/R + m.
    prod_bound = a.val * b.val
    out_val = prod_bound // cfg.R + m + 1

    return peak.bit_length() + 1, Bounded.fresh_mul(cfg, out_val)


# ──────────────────────────────────────────────────────────────────────
# Concrete Montgomery (correctness oracle)
# ──────────────────────────────────────────────────────────────────────
def mont_mul(a_limbs, b_limbs, m, cfg):
    K, W, MASK = cfg.K, cfg.W, cfg.MASK
    m_limbs = cfg.split(m)
    m0inv = cfg.m0inv(m)
    acc = [0] * (2*K)
    for i in range(K):
        for j in range(K):
            acc[i+j] += a_limbs[i] * b_limbs[j]
    for i in range(K):
        q = (acc[i] * m0inv) & MASK
        for j in range(K):
            acc[i+j] += q * m_limbs[j]
        acc[i+1] += acc[i] >> W
        acc[i] = 0
    # Carry-propagate acc[K..2K-1]. Limbs 0..K-2 become canonical
    # [0, 2^W); the top limb absorbs the final carry and is SIGNED.
    # This is the "signed Montgomery" contract: the represented value
    # can be negative, but it's correct mod m, and the top limb stays
    # bounded as long as inputs are bounded.
    out = []
    carry = 0
    for k in range(K):
        t = acc[K+k] + carry
        out.append(t & MASK)
        carry = t >> W      # Python >> is arithmetic (floor) — matches sar
    # Absorb final carry into top limb. out[K-1] is now signed.
    out[-1] += carry << W
    return out


# ──────────────────────────────────────────────────────────────────────
# RCB-43 formula
# ──────────────────────────────────────────────────────────────────────
RCB = [
    ('mul','t0','X1','X2'), ('mul','t1','Y1','Y2'), ('mul','t2','Z1','Z2'),
    ('add','t3','X1','Y1'), ('add','t4','X2','Y2'), ('mul','t3','t3','t4'),
    ('sub','t3','t3','t0'), ('sub','t3','t3','t1'),
    ('add','t4','Y1','Z1'), ('add','t5','Y2','Z2'), ('mul','t4','t4','t5'),
    ('sub','t4','t4','t1'), ('sub','t4','t4','t2'),
    ('add','t5','X1','Z1'), ('add','Y3','X2','Z2'), ('mul','t5','t5','Y3'),
    ('sub','t5','t5','t0'), ('sub','t5','t5','t2'),
    ('mul','Z3','b','t2'),
    ('sub','X3','t5','Z3'), ('add','Z3','X3','X3'), ('add','X3','X3','Z3'),
    ('sub','Z3','t1','X3'), ('add','X3','t1','X3'),
    ('mul','Y3','b','t5'),
    ('add','t1','t2','t2'), ('add','t2','t1','t2'),
    ('sub','Y3','Y3','t2'), ('sub','Y3','Y3','t0'),
    ('add','t1','Y3','Y3'), ('add','Y3','t1','Y3'),
    ('add','t1','t0','t0'), ('add','t0','t1','t0'), ('sub','t0','t0','t2'),
    ('mul','t1','t4','Y3'), ('mul','t2','t0','Y3'),
    ('mul','Y3','X3','Z3'), ('add','Y3','Y3','t2'),
    ('mul','X3','t3','X3'), ('sub','X3','X3','t1'),
    ('mul','Z3','t4','Z3'), ('mul','t1','t3','t0'), ('add','Z3','Z3','t1'),
]
assert len(RCB) == 43


def rcb_once(cfg, input_bound: Bounded):
    """One pass through RCB. Returns (worst_limb_in, worst_acc, out_bound)."""
    s = {k: input_bound for k in ('X1','Y1','Z1','X2','Y2','Z2','b')}
    worst_limb_in = 0
    worst_acc = 0
    for op, d, a, b in RCB:
        if op == 'mul':
            worst_limb_in = max(worst_limb_in, s[a].max_limb_bits(),
                                s[b].max_limb_bits())
            acc_bits, s[d] = mont_mul_bounds(s[a], s[b], P, cfg)
            worst_acc = max(worst_acc, acc_bits)
        else:
            s[d] = s[a] + s[b]
    # Output: the tightest of X3/Y3/Z3 (they're all fresh mults, same bound).
    return worst_limb_in, worst_acc, s['X3']


def rcb_fixpoint(cfg, max_iter=20):
    """Iterate RCB until the output value bound stabilises. This models
    the scalar-mul loop: output of one RCB becomes input to the next."""
    # Bootstrap: fresh multiply of two values in [0, m).
    # Output ≤ m²/R + m. For m < R: output < 2m.
    out = Bounded.fresh_mul(cfg, 2*P)
    trace = []
    for it in range(max_iter):
        wl, wa, out_new = rcb_once(cfg, out)
        trace.append((it, out.val.bit_length(), wl, wa,
                      out_new.val.bit_length()))
        # Converged if bit-length stabilises.
        if out_new.val.bit_length() <= out.val.bit_length():
            return wl, wa, out_new, trace, True
        # Diverged if bit-length jumps by more than a few bits — the
        # Montgomery damping (m/R) is losing to the RCB growth (C²).
        # Needed: KW > 256 + log2(C²) where C is the worst RCB
        # value-growth (×12 via the Y3 chain, so ~264).
        if out_new.val.bit_length() > out.val.bit_length() + 8:
            return wl, wa, out_new, trace, False
        out = out_new
    return wl, wa, out, trace, False


def rcb_concrete(X1,Y1,Z1, X2,Y2,Z2, b, m, cfg):
    s = {'X1':X1,'Y1':Y1,'Z1':Z1,'X2':X2,'Y2':Y2,'Z2':Z2,'b':b}
    for op, d, a, bb in RCB:
        if op == 'mul':
            s[d] = mont_mul(s[a], s[bb], m, cfg)
        elif op == 'add':
            s[d] = [x+y for x,y in zip(s[a], s[bb])]
        else:
            s[d] = [x-y for x,y in zip(s[a], s[bb])]
    return s['X3'], s['Y3'], s['Z3']


# ──────────────────────────────────────────────────────────────────────
# Correctness: scalar-mul with RCB against affine reference
# ──────────────────────────────────────────────────────────────────────
def inv_mod(a, m): return pow(a, m-2, m)

def affine_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1,y1 = P1; x2,y2 = P2
    if x1 == x2:
        if (y1+y2) % P == 0: return None
        s = (3*x1*x1 - 3) * inv_mod(2*y1, P) % P
    else:
        s = (y2-y1) * inv_mod(x2-x1, P) % P
    x3 = (s*s - x1 - x2) % P
    y3 = (s*(x1-x3) - y1) % P
    return (x3, y3)

def affine_smul(k, Pt):
    R = None
    for i in range(k.bit_length()-1, -1, -1):
        R = affine_add(R, R)
        if (k >> i) & 1:
            R = affine_add(R, Pt)
    return R


def scalar_mul_mont(k, Px, Py, cfg):
    """k·P using RCB, all Montgomery. Returns projective (X,Y,Z) in
    Montgomery form."""
    R_mod = cfg.R % P
    B_curve = (Gy*Gy - Gx*Gx*Gx + 3*Gx) % P
    # Convert to Montgomery
    to_mont = lambda x: cfg.split((x * R_mod) % P)
    Px_m, Py_m = to_mont(Px), to_mont(Py)
    Pz_m = to_mont(1)
    b_m = to_mont(B_curve)
    # Accumulator starts at ∞ = (0:1:0)
    Ax, Ay, Az = cfg.split(0), to_mont(1), cfg.split(0)
    for i in range(k.bit_length()-1, -1, -1):
        # Double: RCB(acc, acc)
        Ax, Ay, Az = rcb_concrete(Ax,Ay,Az, Ax,Ay,Az, b_m, P, cfg)
        if (k >> i) & 1:
            Ax, Ay, Az = rcb_concrete(Ax,Ay,Az, Px_m,Py_m,Pz_m, b_m, P, cfg)
    return Ax, Ay, Az


def verify_scalar_mul(cfg, n_tests=2, k_bits=8):
    """Cross-check Montgomery-RCB scalar mul against affine reference.
    Small k only — full 256-bit is 43×256×K² muls in pure Python."""
    R_mod = cfg.R % P
    R_inv = inv_mod(R_mod, P)
    random.seed(12345)
    ok = 0
    for _ in range(n_tests):
        k = random.randrange(1, 1 << k_bits)
        # Reference
        ref = affine_smul(k, (Gx, Gy))
        # Montgomery RCB
        Ax, Ay, Az = scalar_mul_mont(k, Gx, Gy, cfg)
        # Back to affine: x = X/Z in Montgomery means
        # X_mont = X·R, Z_mont = Z·R, x = X/Z.
        # To recover: X_plain = join(Ax)·R^(-1) mod P, same for Z.
        X = (cfg.join(Ax) * R_inv) % P
        Z = (cfg.join(Az) * R_inv) % P
        if Z == 0:
            got = None
        else:
            got_x = (X * inv_mod(Z, P)) % P
            got = got_x
        if ref is None:
            if got is None: ok += 1
        elif got == ref[0]:
            ok += 1
        else:
            print(f"    MISMATCH k=0x{k:x}")
            print(f"      ref x = 0x{ref[0]:x}")
            print(f"      got x = 0x{got:x}")
            return False
    return ok == n_tests


# ──────────────────────────────────────────────────────────────────────
# Analysis driver
# ──────────────────────────────────────────────────────────────────────
def analyze(K, W, acc_bits, tag=""):
    cfg = Cfg(K, W, acc_bits)
    print(f"\n{'='*72}")
    print(f"  {K}×{W} limbs ({K*W} bits; {K*W-256} over), "
          f"{acc_bits}-bit acc{'  '+tag if tag else ''}")
    print(f"{'='*72}")

    # Modulus structure
    m0i_p = cfg.m0inv(P)
    m0i_n = cfg.m0inv(N)
    p_limbs = cfg.split(P)
    print(f"  p limbs: {['0x'+hex(v)[2:] for v in p_limbs]}")
    print(f"  p m0inv: {'1 (FREE)' if m0i_p==1 else hex(m0i_p)}")
    print(f"  n m0inv: {hex(m0i_n)}")
    p_nz = sum(1 for v in p_limbs if v not in (0, cfg.MASK))
    print(f"  p: {sum(1 for v in p_limbs if v==0)} zeros, "
          f"{sum(1 for v in p_limbs if v==cfg.MASK)} all-ones, "
          f"{p_nz} random → ~{p_nz*4 + 8}B to build at runtime")

    # R² for Montgomery conversion — how sparse?
    R2 = (cfg.R * cfg.R) % P
    r2_dw = [(R2 >> (32*i)) & 0xFFFFFFFF for i in range(8)]
    r2_easy = sum(1 for v in r2_dw if v in (0, 0xFFFFFFFF))
    print(f"  R² mod p (32-bit dwords): {r2_easy}/8 trivial (00/FF)")
    print(f"    = {['0x'+hex(v)[2:] for v in r2_dw]}")

    # Slot size
    slot = K * 8
    disp8_slots = 128 // slot
    print(f"  slot: {slot}B (qword storage). "
          f"{disp8_slots} slots fit disp8 from base.")

    # RCB fixed-point
    wi, wa, out, trace, converged = rcb_fixpoint(cfg)
    limb_ok = wi <= 64
    acc_ok = wa <= acc_bits
    print(f"  RCB fixed-point: {'converged' if converged else 'DIVERGED'} "
          f"in {len(trace)} iters")
    print(f"    iter  val_in  limb_in  acc   val_out")
    for it, vi, wl, wac, vo in trace[:5]:
        print(f"    {it:4}  2^{vi:<4}  {wl:<7}  {wac:<4}  2^{vo}")
    print(f"  Stable mul-input limb: {wi} bits  "
          f"({'ok' if limb_ok else 'OVERFLOW'})")
    print(f"  Stable accumulator:    {wa} bits  "
          f"({'ok' if acc_ok else f'OVERFLOW — need {wa}-bit acc'})")
    print(f"  Stable output value:   ≤ 2^{out.val.bit_length()}  "
          f"(top limb ≤ {out.limb[-1].bit_length()} bits)")

    # Correctness
    if limb_ok and acc_ok and converged:
        print(f"  Scalar-mul correctness: ", end="", flush=True)
        if verify_scalar_mul(cfg):
            print("PASS")
        else:
            print("FAIL")
            return False
    else:
        print(f"  (skipping correctness — bounds fail)")
        return False

    return True


# ──────────────────────────────────────────────────────────────────────
# Size estimation (rough)
# ──────────────────────────────────────────────────────────────────────
def size_estimate(K, W, acc_bits):
    """Very rough byte-count estimate for each config. These are
    guesses to guide which one to actually implement; real numbers
    come from the assembler."""
    cfg = Cfg(K, W, acc_bits)
    slot = K * 8

    # Baseline = current 933
    delta = 0

    # Fadd/Fsub: current 59 B (Fadd 13 + .Lop3 46).
    # New: two tiny loops, ~16 B each = 32 B. Save 27.
    delta -= 27

    # fe_mul_m: current 143 B.
    # Inner loop:
    if acc_bits == 64:
        inner = 13  # lodsq;imul rax,rbx;add [rdi],rax;scasq;loop
    else:
        inner = 18  # lodsq;imul rbx;add;adc;lea+16;loop
    # Current has 2×18 = 36 B of inner (add + sub variants).
    # New has 1× inner (Montgomery = add only).
    delta += inner - 36

    # Carry-propagate at the end of mont_mul:
    if acc_bits == 64:
        cp = 19   # simple 64-bit carry chain
    else:
        cp = 41   # 128-bit carry chain with shrd
    # Current has ~17 B epilogue (copy + call .Lop3). .Lop3's shared
    # body we already counted in Fadd. So roughly +cp - 17.
    delta += cp - 17

    # Montgomery q setup: q = acc[i]*m0inv & MASK. For p: m0inv=1,
    # so q = acc[i] & MASK. MASK fits imm32 iff W ≤ 32.
    if W <= 32:
        delta += 0   # and ebx, imm32 — cheap
    else:
        delta += 10  # need movabs or shl/shr dance for MASK

    # Montgomery carry-shift between reduce iterations:
    if acc_bits == 64:
        delta += 8   # mov;sar;add — straightforward
    else:
        delta += 24  # 128-bit shrd dance

    # Accumulator zero-init: current pushes 9 qwords (9 B).
    # New: 2K slots × (16B if 128-bit else 8B) / 8 qwords to push.
    acc_qw = 2*K * (2 if acc_bits==128 else 1)
    delta += (acc_qw - 9)  # 1 B per extra push

    # R² constant: 32 B stored, or built at runtime if sparse.
    R2 = (cfg.R * cfg.R) % P
    r2_dw = [(R2 >> (32*i)) & 0xFFFFFFFF for i in range(8)]
    r2_easy = sum(1 for v in r2_dw if v in (0, 0xFFFFFFFF))
    # Optimistic: 4B per "hard" dword, 3B per trivial dword, +5B setup.
    r2_cost = min(32, 5 + r2_easy*1 + (8-r2_easy)*5)
    delta += r2_cost

    # Conversion bytecode: 3 MontMul ops (Qx, Qy, r) × 2B.
    delta += 6

    # Decoder: current fe_from_be is 15 B (movbe loop, 4 qwords).
    # New must split into K limbs with shifts. Roughly 20-30 B.
    # This is the hardest to estimate without coding it.
    delta += 15

    # Slot-size multiplier in bc_run decoder: current `shl rcx, 5` (3 B).
    # For slot=40: shl 3 + lea ×5 = 7 B. +4.
    # For slot=80: shl 4 + lea ×5 = 7 B. +4.
    if slot != 32:
        delta += 4

    # Displacement blowups: how many leas go from disp8 to disp32?
    # With slot=40, r8-at-slot8 trick still works (slot5 at r8-120).
    # With slot=80, it doesn't (r8-240). Estimate +3B per blowup × 3.
    if slot > 40:
        delta += 9

    return 933 + delta


# ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("="*72)
    print("CONFIGURATION ANALYSIS")
    print("="*72)

    # Montgomery convergence: need KW > ~264 (from C=12 Y3 chain).
    configs = [
        (5, 52, 128, "KW=260 — TOO TIGHT, should diverge"),
        (5, 53, 128, "KW=265 — minimum for 5-limb"),
        (5, 54, 128, "KW=270 — Thomas's choice"),
        (6, 44, 128, "KW=264 — 48B slot, barely enough"),
        (6, 45, 128, "KW=270 — comfortable 6-limb"),
        (10, 27, 64, "KW=270 — products fit 64, comfortable R"),
        (11, 24, 64, "KW=264 — barely; smallest slots for 64b"),
        (11, 25, 64, "KW=275 — comfortable 11-limb"),
    ]

    results = []
    for K, W, acc, tag in configs:
        ok = analyze(K, W, acc, tag)
        est = size_estimate(K, W, acc) if ok else None
        results.append((K, W, acc, ok, est))
        if ok:
            print(f"  → ROUGH SIZE ESTIMATE: {est} B  (delta {est-933:+d})")

    print(f"\n{'='*72}")
    print("SUMMARY")
    print(f"{'='*72}")
    print(f"{'K×W':<8} {'acc':<6} {'viable':<8} {'est.size':<10} {'vs 928':<8}")
    for K, W, acc, ok, est in results:
        if ok:
            vs = "BEATS" if est < 928 else ("ties" if est == 928 else "loses")
            print(f"{K}×{W:<5} {acc:<6} yes      {est:<10} {vs}")
        else:
            print(f"{K}×{W:<5} {acc:<6} DIVERGES -          -")
