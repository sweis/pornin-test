//! Microbench Fe::mul. Compare to asm fe_mul_m at ~60-70 cyc (fast2.S).
use p256_verify::fe::Fe;
use std::hint::black_box;

fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn main() {
    let a = Fe([0xdeadbeefcafebabe, 0x123456789abcdef0, 0xfedcba9876543210, 0x7011223344556677]);
    let b = Fe([0xaabbccddeeff0011, 0x2233445566778899, 0x99887766554433aa, 0x7b00cc00dd00ee00]);

    // Warmup
    let mut r = a;
    for _ in 0..10000 { r = Fe::mul(&r, &b); }
    black_box(r);

    const N: u64 = 10_000_000;
    let start = rdtsc();
    let mut r = a;
    for _ in 0..N { r = Fe::mul(&r, black_box(&b)); }
    let elapsed = rdtsc() - start;
    black_box(r);

    println!("Fe::mul: {:.2} cyc/call", elapsed as f64 / N as f64);
    println!("         (asm fast2.S fe_mul_m is ~60-70 cyc)");
}
