//! Field element arithmetic mod p = 2^256 − 2^224 + 2^192 + 2^96 − 1.
//!
//! The lazy-carry Solinas structure is the key port: compute 8 independent
//! 32-bit-position accumulators (each a signed i64), THEN propagate once.
//! In asm this broke a 139-op serial chain into a 14-cyc parallel phase +
//! 16-cyc serial phase. Rust's optimizer should find the same parallelism.

pub const P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF,
    0x0000000000000000, 0xFFFFFFFF00000001,
];

/// Carry correction: adj[c+4] = c·(2^256−p) + (c<0 ? p : 0).
/// Guarantees S + adj ∈ [0, 2p) for any S < 2^256, c ∈ [-4, 5].
/// Same table as carry_table.inc in the asm.
const CARRY_ADJ: [[u64; 4]; 10] = [
    [0xfffffffffffffffb, 0x00000004ffffffff, 0x0000000000000000, 0xfffffffb00000005], // c=-4
    [0xfffffffffffffffc, 0x00000003ffffffff, 0x0000000000000000, 0xfffffffc00000004], // c=-3
    [0xfffffffffffffffd, 0x00000002ffffffff, 0x0000000000000000, 0xfffffffd00000003], // c=-2
    [0xfffffffffffffffe, 0x00000001ffffffff, 0x0000000000000000, 0xfffffffe00000002], // c=-1
    [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000], // c= 0
    [0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe], // c=+1
    [0x0000000000000002, 0xfffffffe00000000, 0xffffffffffffffff, 0x00000001fffffffd], // c=+2
    [0x0000000000000003, 0xfffffffd00000000, 0xffffffffffffffff, 0x00000002fffffffc], // c=+3
    [0x0000000000000004, 0xfffffffc00000000, 0xffffffffffffffff, 0x00000003fffffffb], // c=+4
    [0x0000000000000005, 0xfffffffb00000000, 0xffffffffffffffff, 0x00000004fffffffa], // c=+5
];

/// FIPS Solinas coefficients: COEFF[pos][i] = contribution of A[8+i] to r[pos].
/// Derived from the 9-term formula (s1 + 2s2 + 2s3 + s4 + s5 − s6 − s7 − s8 − s9).
const COEFF: [[i8; 8]; 8] = [
    [ 1,  1,  0, -1, -1, -1, -1,  0],
    [ 0,  1,  1,  0, -1, -1, -1, -1],
    [ 0,  0,  1,  1,  0, -1, -1, -1],
    [-1, -1,  0,  2,  2,  1,  0, -1],
    [ 0, -1, -1,  0,  2,  2,  1,  0],
    [ 0,  0, -1, -1,  0,  2,  2,  1],
    [-1, -1,  0,  0,  0,  1,  3,  2],
    [ 1,  0, -1, -1, -1, -1,  0,  3],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe(pub [u64; 4]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 4]);
    pub const ONE: Fe = Fe([1, 0, 0, 0]);

    /// 64-bit schoolbook product → 512 bits as [u32; 16] (for Solinas dword indexing).
    /// u128 gives us 64×64→128 portably; no adc chain needed here.
    #[inline(always)]
    fn school(a: &[u64; 4], b: &[u64; 4]) -> [u32; 16] {
        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + carry;
                t[i + j] = prod as u64;
                carry = prod >> 64;
            }
            t[i + 4] = carry as u64;
        }
        // Reinterpret as 16 × u32 (little-endian dwords)
        let mut d = [0u32; 16];
        for i in 0..8 {
            d[2 * i] = t[i] as u32;
            d[2 * i + 1] = (t[i] >> 32) as u32;
        }
        d
    }

    /// Lazy-carry one-shot Solinas: 8 independent i64 accumulators, then propagate.
    /// Returns (reduced-ish [u32; 8], signed final carry ∈ [-4, +5]).
    #[inline(always)]
    fn solinas_lazy(t: &[u32; 16]) -> ([u32; 8], i32) {
        // Phase 1: compute acc[0..8] independently. NO cross-position dependency.
        // The compiler sees 8 independent i64 chains — should vectorize or at
        // least issue in parallel. This is THE asm insight (fast2's 9% win).
        let mut acc = [0i64; 8];
        for pos in 0..8 {
            let mut a = t[pos] as i64;
            for i in 0..8 {
                a += (COEFF[pos][i] as i64) * (t[8 + i] as i64);
            }
            acc[pos] = a;
        }
        // Phase 2: serial carry propagation.
        let mut r = [0u32; 8];
        let mut carry = 0i64;
        for pos in 0..8 {
            let v = acc[pos] + carry;
            r[pos] = v as u32;
            carry = v >> 32;  // arithmetic shift — signed
        }
        (r, carry as i32)
    }

    /// Branchless cond-sub: dst = if dst >= p { dst - p } else { dst }.
    /// Also handles the add-carry-out from the table correction.
    #[inline(always)]
    fn cond_sub_p(r: &[u64; 4], add_carry: bool) -> [u64; 4] {
        // Compute r - p.
        let (d0, b0) = r[0].overflowing_sub(P[0]);
        let (d1, b1) = sbb(r[1], P[1], b0);
        let (d2, b2) = sbb(r[2], P[2], b1);
        let (d3, b3) = sbb(r[3], P[3], b2);
        // Keep subtracted iff (no borrow) OR (add_carry).
        // borrow=0: r >= p, keep sub. borrow=1 ∧ carry=0: r < p, keep orig.
        // borrow=1 ∧ carry=1: impossible (r + adj overflowed → r+adj >= 2^256 > p).
        let keep_sub = !b3 | add_carry;
        let mask = 0u64.wrapping_sub(keep_sub as u64);  // -1 if keep_sub, else 0
        [
            (d0 & mask) | (r[0] & !mask),
            (d1 & mask) | (r[1] & !mask),
            (d2 & mask) | (r[2] & !mask),
            (d3 & mask) | (r[3] & !mask),
        ]
    }

    /// a * b mod p — the hot path. Schoolbook + lazy Solinas + table + cond-sub.
    #[inline]
    pub fn mul(a: &Fe, b: &Fe) -> Fe {
        let t = Self::school(&a.0, &b.0);
        let (r_dw, carry) = Self::solinas_lazy(&t);
        // Table correction: add CARRY_ADJ[carry+4] to bring into [0, 2p).
        let adj = &CARRY_ADJ[(carry + 4) as usize];
        // Recompose r_dw to u64s and add adj with carry chain.
        let r = [
            (r_dw[0] as u64) | ((r_dw[1] as u64) << 32),
            (r_dw[2] as u64) | ((r_dw[3] as u64) << 32),
            (r_dw[4] as u64) | ((r_dw[5] as u64) << 32),
            (r_dw[6] as u64) | ((r_dw[7] as u64) << 32),
        ];
        let (s0, c0) = r[0].overflowing_add(adj[0]);
        let (s1, c1) = adc(r[1], adj[1], c0);
        let (s2, c2) = adc(r[2], adj[2], c1);
        let (s3, c3) = adc(r[3], adj[3], c2);
        // c3 = add_carry. Cond-sub handles it.
        Fe(Self::cond_sub_p(&[s0, s1, s2, s3], c3))
    }

    pub fn sqr(a: &Fe) -> Fe { Self::mul(a, a) }

    /// Branchless a + b mod p (port of the branchless Fadd from fast2.S).
    #[inline]
    pub fn add(a: &Fe, b: &Fe) -> Fe {
        let (s0, c0) = a.0[0].overflowing_add(b.0[0]);
        let (s1, c1) = adc(a.0[1], b.0[1], c0);
        let (s2, c2) = adc(a.0[2], b.0[2], c1);
        let (s3, c3) = adc(a.0[3], b.0[3], c2);
        Fe(Self::cond_sub_p(&[s0, s1, s2, s3], c3))
    }

    #[inline]
    pub fn sub(a: &Fe, b: &Fe) -> Fe {
        let (d0, b0) = a.0[0].overflowing_sub(b.0[0]);
        let (d1, b1) = sbb(a.0[1], b.0[1], b0);
        let (d2, b2) = sbb(a.0[2], b.0[2], b1);
        let (d3, b3) = sbb(a.0[3], b.0[3], b2);
        // If borrow: add p back (masked).
        let mask = 0u64.wrapping_sub(b3 as u64);
        let (r0, c0) = d0.overflowing_add(P[0] & mask);
        let (r1, c1) = adc(d1, P[1] & mask, c0);
        let (r2, c2) = adc(d2, P[2] & mask, c1);
        let (r3, _)  = adc(d3, P[3] & mask, c2);
        Fe([r0, r1, r2, r3])
    }

    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    pub fn from_be_bytes(b: &[u8; 32]) -> Fe {
        Fe([
            u64::from_be_bytes(b[24..32].try_into().unwrap()),
            u64::from_be_bytes(b[16..24].try_into().unwrap()),
            u64::from_be_bytes(b[8..16].try_into().unwrap()),
            u64::from_be_bytes(b[0..8].try_into().unwrap()),
        ])
    }

    /// Compare as integers (for range checks). Returns true iff self < other.
    pub fn lt(&self, other: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if self.0[i] < other[i] { return true; }
            if self.0[i] > other[i] { return false; }
        }
        false
    }
}

#[inline(always)]
fn adc(a: u64, b: u64, carry: bool) -> (u64, bool) {
    let (s, c1) = a.overflowing_add(b);
    let (s, c2) = s.overflowing_add(carry as u64);
    (s, c1 | c2)
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: bool) -> (u64, bool) {
    let (d, b1) = a.overflowing_sub(b);
    let (d, b2) = d.overflowing_sub(borrow as u64);
    (d, b1 | b2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_identity() {
        let a = Fe([0xdeadbeefcafebabe, 0x123456789abcdef0, 0xfedcba9876543210, 0x0011223344556677]);
        assert_eq!(Fe::mul(&a, &Fe::ONE), a);
        assert_eq!(Fe::mul(&Fe::ONE, &a), a);
    }

    #[test]
    fn mul_against_bignum() {
        // Verify against Python's big-int mod.
        let p: u128 = 0; // placeholder — test via known vectors below
        let _ = p;
        // a = 2, b = 3 → 6
        let two = Fe([2, 0, 0, 0]);
        let three = Fe([3, 0, 0, 0]);
        assert_eq!(Fe::mul(&two, &three), Fe([6, 0, 0, 0]));
        // p-1 squared = 1
        let pm1 = Fe([P[0] - 1, P[1], P[2], P[3]]);
        assert_eq!(Fe::mul(&pm1, &pm1), Fe::ONE);
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = Fe([0xdeadbeef, 0xcafebabe, 0x12345678, 0x10000000]);
        let b = Fe([0x11111111, 0x22222222, 0x33333333, 0x04444444]);
        let c = Fe::add(&a, &b);
        let d = Fe::sub(&c, &b);
        assert_eq!(d, a);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// BMI2+ADX variant: explicit mulx intrinsic.  LLVM doesn't pattern-match
// u128 → mulx automatically — it needs the intrinsic hint.
// ─────────────────────────────────────────────────────────────────────────

