# ECDSA/P-256 verify — minimum bytes

Size-golfed ECDSA/P-256 signature verification for boot-ROM targets.
FIPS 186-5 §6.4.2. Signature is raw 64 bytes (r‖s big-endian), pubkey
is 65 bytes uncompressed (0x04‖X‖Y), hash is 32–64 bytes (truncated
to 32). Every object has **zero undefined symbols** — no libc.

Thomas Pornin posed the challenge and is competing in parallel. His
stupid-VM baseline was 766 B; we're at **620 B** (−146). His non-stupid
v7 is 928 B / 4.48M cycles.

**New session? Read `docs/SESSION_GUIDE.md` first.**

## Results

| Track | Floor | Cycles | Arch | Notes |
|---|---:|---:|---|---|
| `stupid` (SMC) | **620 B** | ~2.4G | 1-B acc-VM, MUL=bytecode | **size floor** — boot-ROM without W^X only |
| `stupid` `-DNO_SMC` | 633 B | ~239M | same, no self-mod | practical point |
| `limb8` `-DSMALL_MUL8` | 890 B | ~5.2M | 8×32 q=t[top] | prev floor, native mul |
| `limb8` default | 908 B | ~4.0M | 8×32 q=t[top] | dominates Thomas v7 both axes |
| `limb8` `-DSOLINAS_P` | 966 B | ~2.9M | 8×32 Solinas | no mul in reduce |
| `limb11x24` | 1068 B | ~12M | 11×24 Montgomery | 1077 B / 4.1M with `-DFAST` |
| `limb5x56` | 1084 B | ~3.1M | 5×56 Montgomery | byte-aligned decode |
| `limb5x54` | 1097 B | ~2.8M | 5×54 Montgomery | Thomas's arch, fastest Montgomery |
| `speed/fast2.S` | 3265 B | ~570K | BMI2+ADX | cycles corner, lazy-carry Solinas |

Full history in `docs/progress.csv`; chart at `docs/progress.png`.

## Architecture — the five big ideas

**Multiplication as bytecode (stupid/ only).** Russian-peasant
double-and-add: 8 B of bytecode replaces 80–150 B of native mul.
Structurally identical to scalar×point — one FOR/NEXT/SKIPBITZ triple
serves field mul, pt_mul, and inversion. ~100× slower (~140M cyc
base) but a boot-ROM tolerates 90 ms once at boot. See
`docs/stupid_analysis.md` for why we missed this for so long.

**Bytecode interpreter.** Field-op call sites are ~15 B each (lea
rdi/rsi/rdx + call); ~60 of them. limb* tracks: 2-byte 3-address ops,
u8 jump table. stupid/: 1-byte accumulator ISA (3-bit op + 5-bit idx)
with real CALL/RET stack. RCB's 43 ops cost 83–87 bytes; dispatch
~50 B once.

**RCB complete addition** (Renes-Costello-Batina, ePrint 2015/1060).
One 43-op formula for P+Q, 2P, P+(−P)=∞, ∞+Q=Q — no branches, no
special cases. Homogeneous projective (x=X/Z). A 3-way branch tree
(~70 B) becomes one bytecode call.

**Projective final check.** Skip mod-p inversion entirely: valid iff
`X ≡ r·Z ∨ X ≡ (r+n)·Z (mod p)`; prime p means `d1·d2 ≡ 0` is
equivalent. Runs in bytecode. Fermat inversion is mod-n only.

**q=t[top] reduce (limb8 only).** Both P-256 moduli have top 32-bit
limb `0xFFFFFFFF` and `2^256 − m < 2^224`. The reduce is
`t −= t[top]·m` — no Montgomery, no m0i, no R² constants. This is the
only limb width where it works for both p and n; all other tracks are
Montgomery (and use R-factor cancellation to drop cR² constants).

## Build & test

```
make test         # 607/607 (33 hand-picked + 574 Wycheproof) × 4 tracks
make size         # all four floors side by side
make bench        # 20-run median cycles, all tracks
make chart        # regenerate docs/progress.png
```

Per-track: `make -C limb8 size-all` for all variants; `bench20` for
cycles; `test` for the full gate. ASAN/UBSAN via the C harness.

## Directory map

```
stupid/     1-byte acc-VM, MUL=bytecode. 620 B floor. See docs/stupid_analysis.md.
limb8/      8×32 q=t[top]. Only non-Montgomery native-mul track. 890 B.
limb11x24/  11×24 Montgomery. Trick-catalogue source; most ports start here.
limb5x54/   5×54 Montgomery. Thomas's architecture. Fastest Montgomery.
limb5x56/   5×56 Montgomery. Byte-aligned limbs — 7-byte decoder.
speed/      fast/fast2/speed.S. Cycles, not bytes. BMI2+ADX.
signer/     AVX-512 constant-time signer. Separate problem.
common/     Shared: test harnesses, bench.c, track.mk, gen_bytecode.py, range_proof.py.
archive/    Superseded: C refs, early asm, Rust port.
docs/       SESSION_GUIDE.md, TRICKS_LEDGER.md, DEAD_ENDS.md, progress.csv, chart, tinyp256.tex.
```
