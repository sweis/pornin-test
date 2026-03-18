//! Top-level ECDSA/P-256 verify — Shamir's trick + projective final check.

use crate::fe::{Fe, P};
use crate::scalar::{Sc, N};
use crate::point::Point;

const GX: Fe = Fe([0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247]);
#[allow(dead_code)]
const GY: Fe = Fe([0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B]);

pub fn verify(sig: &[u8], pub_key: &[u8], hash: &[u8]) -> bool {
    if sig.len() != 64 || pub_key.len() != 65 || !(32..=64).contains(&hash.len()) {
        return false;
    }
    if pub_key[0] != 0x04 {
        return false;
    }

    let r = Sc::from_be_bytes(sig[0..32].try_into().unwrap());
    let s = Sc::from_be_bytes(sig[32..64].try_into().unwrap());
    if r.is_zero() || s.is_zero() || !r.lt_n() || !s.lt_n() {
        return false;
    }

    let qx = Fe::from_be_bytes(pub_key[1..33].try_into().unwrap());
    let qy = Fe::from_be_bytes(pub_key[33..65].try_into().unwrap());
    if !qx.lt(&P) || !qy.lt(&P) {
        return false;
    }

    // Derive b from G: b = Gy² − Gx³ + 3Gx
    let gx2 = Fe::sqr(&GX);
    let gx3 = Fe::mul(&gx2, &GX);
    let three_gx = Fe::add(&Fe::add(&GX, &GX), &GX);
    let b = Fe::sub(&Fe::add(&Fe::sqr(&GY), &three_gx), &gx3);

    // Curve check
    let qx2 = Fe::sqr(&qx);
    let qx3 = Fe::mul(&qx2, &qx);
    let three_qx = Fe::add(&Fe::add(&qx, &qx), &qx);
    let lhs = Fe::add(&Fe::sqr(&qy), &three_qx);
    if Fe::sub(&lhs, &qx3) != b {
        return false;
    }

    // Hash → scalar (truncate to 32 bytes, don't reduce mod n)
    let e = Sc::from_be_bytes(hash[..32].try_into().unwrap());

    let s_inv = Sc::inv(&s);
    let u1 = Sc::mul(&e, &s_inv);
    let u2 = Sc::mul(&r, &s_inv);

    // Windowed Shamir: 4-bit windows for both scalars.
    // G table is precomputed (constant); Q table computed per-verify (15 adds).
    // 64 windows × (4 doublings + ≤2 adds) vs old 256 × (1 doubling + ≤2 adds).
    // Same doublings, but adds drop from ~256 to ~128.  The Q-table precompute
    // costs 14 adds — net win if u2 has more than 14 set bits (it always does).
    use crate::gtable::G_TABLE;
    let q_pt = Point { x: qx, y: qy, z: Fe::ONE };
    let mut q_table = [Point::INFINITY; 16];
    q_table[1] = q_pt;
    for i in 2..16 {
        q_table[i] = Point::add(&q_table[i-1], &q_pt, &b);
    }

    let mut acc = Point::INFINITY;
    for w in (0..64).rev() {
        // 4 doublings per window (except the first — acc starts at ∞, doubling is free)
        if w != 63 {
            for _ in 0..4 { acc = Point::double(&acc, &b); }
        }
        // G-window: G_TABLE is affine (Z=1), so convert to Point for add
        let gw = nibble(&u1.0, w);
        if gw != 0 {
            let (gx, gy) = G_TABLE[gw - 1];
            let g = Point { x: gx, y: gy, z: Fe::ONE };
            acc = Point::add(&acc, &g, &b);
        }
        // Q-window
        let qw = nibble(&u2.0, w);
        if qw != 0 {
            acc = Point::add(&acc, &q_table[qw], &b);
        }
    }

    // Projective check: X ≡ r·Z ∨ X ≡ (r+n)·Z (mod p)
    if acc.z.is_zero() {
        return false;
    }
    let r_fe = Fe(r.0);
    let rz = Fe::mul(&r_fe, &acc.z);
    let diff1 = Fe::sub(&acc.x, &rz);
    let n_fe = Fe(N);
    let nz = Fe::mul(&n_fe, &acc.z);
    let diff2 = Fe::sub(&diff1, &nz);
    Fe::mul(&diff1, &diff2).is_zero()
}

#[inline(always)]
fn nibble(k: &[u64; 4], w: usize) -> usize {
    ((k[w / 16] >> ((w % 16) * 4)) & 0xF) as usize
}
