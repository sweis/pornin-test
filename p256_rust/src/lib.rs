//! P-256 ECDSA verification — pure Rust port of the asm optimizations.
//!
//! Key techniques ported from tv_ecdsa_fast2.S:
//!   - 64-bit limbs (4 × u64), schoolbook via u128
//!   - One-shot FIPS Solinas reduction (branch-free 512→256)
//!   - Lazy-carry structure: 8 independent accumulators, then one propagation
//!   - 10-entry carry correction table (c·C + (c<0?p:0))
//!   - Branchless cond-sub via mask
//!   - RCB complete addition (one formula, no edge-case branches)
//!   - Projective final check (no mod-p inversion)

#![allow(clippy::needless_range_loop)]

pub mod fe;      // field element (mod p)
pub mod scalar;  // scalar (mod n)
pub mod point;   // group ops
pub mod verify;  // top-level ECDSA verify

pub use verify::verify;
