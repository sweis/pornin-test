//! Scalar arithmetic mod n (curve order).
//!
//! n's low 128 bits are unstructured so no Solinas shortcut here.
//! But n has top dword 0xFFFFFFFF (same as p), so the per-window
//! q=t[top_dword] reduce trick works.  Only used for fe_inv (Fermat)
//! and the two u1,u2 Nmuls — ~420 calls per verify vs ~5000 mod-p.

pub const N: [u64; 4] = [
    0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sc(pub [u64; 4]);

impl Sc {
    pub const ZERO: Sc = Sc([0; 4]);

    /// Generic reduction: q=t[top_dword] sliding window.  Same approach as
    /// the asm's mul8 loop but in Rust with u128 (no carry-chain tricks —
    /// this is the cold path).
    #[inline]
    fn reduce512(t: &[u64; 8]) -> [u64; 4] {
        // Reinterpret as 17 dwords for the sliding window
        let mut d = [0u32; 17];
        for i in 0..8 { d[2*i] = t[i] as u32; d[2*i+1] = (t[i] >> 32) as u32; }
        let n_dw: [u32; 8] = [
            N[0] as u32, (N[0]>>32) as u32, N[1] as u32, (N[1]>>32) as u32,
            N[2] as u32, (N[2]>>32) as u32, N[3] as u32, (N[3]>>32) as u32,
        ];
        // Slide from position 8 down to 0: for each, while d[j+8]!=0, subtract q*n
        for j in (0..=8).rev() {
            loop {
                let q = d[j+8] as u64;
                if q == 0 { break; }
                let mut borrow = 0i64;
                for k in 0..8 {
                    let prod = q * (n_dw[k] as u64);
                    let v = (d[j+k] as i64) - (prod as u32 as i64) - borrow;
                    d[j+k] = v as u32;
                    borrow = (prod >> 32) as i64 - (v >> 32);
                }
                d[j+8] = (d[j+8] as i64 - borrow) as u32;
            }
        }
        // Cond-sub n
        let r = [
            (d[0] as u64) | ((d[1] as u64) << 32),
            (d[2] as u64) | ((d[3] as u64) << 32),
            (d[4] as u64) | ((d[5] as u64) << 32),
            (d[6] as u64) | ((d[7] as u64) << 32),
        ];
        let (s0, b0) = r[0].overflowing_sub(N[0]);
        let (s1, b1) = sbb(r[1], N[1], b0);
        let (s2, b2) = sbb(r[2], N[2], b1);
        let (s3, b3) = sbb(r[3], N[3], b2);
        if b3 { r } else { [s0, s1, s2, s3] }
    }

    pub fn mul(a: &Sc, b: &Sc) -> Sc {
        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut c = 0u128;
            for j in 0..4 {
                c += (a.0[i] as u128) * (b.0[j] as u128) + (t[i+j] as u128);
                t[i+j] = c as u64; c >>= 64;
            }
            t[i+4] = c as u64;
        }
        Sc(Self::reduce512(&t))
    }

    /// Fermat inversion: a^(n-2) mod n.  Square-and-multiply reading n's bits
    /// directly (the asm bt-on-cN trick — n and n−2 differ only in bits 1-4).
    pub fn inv(a: &Sc) -> Sc {
        // n−2 low byte is 0x4F vs n's 0x51.  Bits 0-3 all set, bit 4 clear.
        // For bits ≥ 5, n and n−2 agree.
        let mut r = Sc([1, 0, 0, 0]);
        for i in (0..256).rev() {
            r = Sc::mul(&r, &r);
            let bit = if i <= 4 {
                // n−2 bits 0-4: 1,1,1,1,0
                i < 4
            } else {
                (N[i / 64] >> (i % 64)) & 1 == 1
            };
            if bit { r = Sc::mul(&r, a); }
        }
        r
    }

    pub fn from_be_bytes(b: &[u8; 32]) -> Sc {
        Sc([
            u64::from_be_bytes(b[24..32].try_into().unwrap()),
            u64::from_be_bytes(b[16..24].try_into().unwrap()),
            u64::from_be_bytes(b[8..16].try_into().unwrap()),
            u64::from_be_bytes(b[0..8].try_into().unwrap()),
        ])
    }

    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    pub fn lt_n(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] < N[i] { return true; }
            if self.0[i] > N[i] { return false; }
        }
        false
    }
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: bool) -> (u64, bool) {
    let (d, b1) = a.overflowing_sub(b);
    let (d, b2) = d.overflowing_sub(borrow as u64);
    (d, b1 | b2)
}
