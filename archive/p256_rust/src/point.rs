//! RCB complete addition (ePrint 2015/1060, Algorithm 7 for a=−3).
//! EFD schedule with steps 14,15 hoisted before 10-13 (see tv_ecdsa_tiny.S
//! header) — not that scheduling matters in Rust, but the formula is correct.

use crate::fe::Fe;

/// Homogeneous projective: (X : Y : Z) represents (X/Z, Y/Z).
/// ∞ = (0 : 1 : 0).
#[derive(Clone, Copy, Debug)]
pub struct Point { pub x: Fe, pub y: Fe, pub z: Fe }

impl Point {
    pub const INFINITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ZERO };

    /// Complete addition — handles P+Q, 2P, P+(−P)=∞, ∞+Q=Q without branching.
    /// b is the curve constant (derived from G at setup: b = Gy² − Gx³ + 3Gx).
    pub fn add(p: &Point, q: &Point, b: &Fe) -> Point {
        let (x1, y1, z1) = (&p.x, &p.y, &p.z);
        let (x2, y2, z2) = (&q.x, &q.y, &q.z);

        let t0 = Fe::mul(x1, x2);
        let t1 = Fe::mul(y1, y2);
        let t2 = Fe::mul(z1, z2);
        let t3 = Fe::add(x1, y1);
        let t4 = Fe::add(x2, y2);
        let t3 = Fe::mul(&t3, &t4);
        let t4 = Fe::add(&t0, &t1);
        let t3 = Fe::sub(&t3, &t4);
        let t4 = Fe::add(y1, z1);
        let x3 = Fe::add(x1, z1);      // hoisted step 14
        let y3 = Fe::add(x2, z2);      // hoisted step 15
        let z3 = Fe::add(y2, z2);      // 10' (was X3-as-temp)
        let t4 = Fe::mul(&t4, &z3);
        let z3 = Fe::add(&t1, &t2);
        let t4 = Fe::sub(&t4, &z3);
        let x3 = Fe::mul(&x3, &y3);
        let y3 = Fe::add(&t0, &t2);
        let y3 = Fe::sub(&x3, &y3);
        let z3 = Fe::mul(b, &t2);
        let x3 = Fe::sub(&y3, &z3);
        let z3 = Fe::add(&x3, &x3);
        let x3 = Fe::add(&x3, &z3);
        let z3 = Fe::sub(&t1, &x3);
        let x3 = Fe::add(&t1, &x3);
        let y3 = Fe::mul(b, &y3);
        let t1 = Fe::add(&t2, &t2);
        let t2 = Fe::add(&t1, &t2);
        let y3 = Fe::sub(&y3, &t2);
        let y3 = Fe::sub(&y3, &t0);
        let t1 = Fe::add(&y3, &y3);
        let y3 = Fe::add(&t1, &y3);
        let t1 = Fe::add(&t0, &t0);
        let t0 = Fe::add(&t1, &t0);
        let t0 = Fe::sub(&t0, &t2);
        let t1 = Fe::mul(&t4, &y3);
        let t2 = Fe::mul(&t0, &y3);
        let y3 = Fe::mul(&x3, &z3);
        let y3 = Fe::add(&y3, &t2);
        let x3 = Fe::mul(&t3, &x3);
        let x3 = Fe::sub(&x3, &t1);
        let z3 = Fe::mul(&t4, &z3);
        let t1 = Fe::mul(&t3, &t0);
        let z3 = Fe::add(&z3, &t1);

        Point { x: x3, y: y3, z: z3 }
    }

    pub fn double(p: &Point, b: &Fe) -> Point {
        Self::add(p, p, b)
    }
}
