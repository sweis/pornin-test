# Rust port: what transferred, what didn't

**Result: pure portable Rust matches hand-tuned BMI2 assembly.**  597K cyc
vs fast2.S's 598K — within noise.  Beats fast.S (Montgomery+mulx) by 9%.
574/574 Wycheproof pass.

## What transferred (the wins)

| Technique | Port | Notes |
|---|---|---|
| **Lazy-carry Solinas** | `solinas_lazy()` | Phase 1: 8 independent `i64` accumulators; Phase 2: one propagation.  LLVM preserved the independence — IPC 3.58 vs asm's 3.00. |
| **COEFF constant-fold** | automatic | `(COEFF[pos][i] as i64) * (A[i] as i64)` with compile-time coeffs → zero `imul` instructions.  LLVM replaced ×2, ×3 with `lea`/`add`. |
| **Carry correction table** | `CARRY_ADJ` | Same 10-entry `c·C + (c<0?p:0)` table.  LLVM fused the lookup into indexed `adc`: `adc 0x8(%rcx,%r9),%rsi` — tighter than my asm's separate `lea rsi;add rsi,rax;mov rax,[rsi]`. |
| **Branchless cond-sub** | `cond_sub_p()` | Mask-and-select.  3 `cmov` in output (LLVM merged one). |
| **RCB complete addition** | `Point::add` | 43-op formula, straight-line.  12 `Fe::mul` all inlined — 5KB function. |
| **Projective final check** | `verify()` tail | `(X−rZ)·(X−(r+n)Z) == 0`.  No mod-p inversion. |
| **Shamir's trick** | verify loop | Standard. |

## What LLVM did that I didn't expect

- **No bounds check on `CARRY_ADJ[(carry+4) as usize]`.**  Can't prove
  `carry ∈ [-4,5]` from the algorithm, but the index is still unchecked
  in the generated asm.  Likely: LLVM saw the 10-element array and the
  `as usize` cast, range-analyzed the `i32 >> 32` result, and elided.
  Either way: hot path is clean.

- **Fused table lookup into adc chain.**  The asm does load-then-add;
  LLVM does `adc (base,index,scale),reg` — one op instead of two.

- **5× fewer branch-misses than asm** (195/verify vs 940).  The `if bit()`
  scalar-walk branches are laid out well.  The asm's bt-then-jnc in pt_mul
  apparently mispredicts more.

## What didn't transfer (and didn't need to)

- **mulx** — LLVM doesn't pattern-match `u128` multiply to `mulx`.
  Uses plain `mul r64` + `adc`.  **Doesn't matter**: both are carry-chain
  bound, not multiply-throughput bound.  The u128 codegen is clean.
- **adcx/adox dual chains** — no stable intrinsic, and the single-chain
  `adc` is fine here.
- All size tricks: jump table packing, push-imm8, bytecode interpreter,
  etc.  Rust code is 9.9KB vs asm's 3.3KB.  3× larger.  Irrelevant
  unless you're in a boot ROM.

## Numbers (this machine, 20-run medians)

```
Rust portable:     597K cyc  ── matches fast2
fast2.S (BMI2):    598K
fast.S  (BMI2):    659K
tiny.S+SOLINAS_P:  2962K  (MOVBE-only, 1005B)
```

```
                    Rust    fast2.S
instructions/call   3.5M    727K      ← 4.8× more insns but…
IPC                 3.58    3.00      ← …better scheduled
branch-miss/call    195     940       ← 5× fewer misses
```

## vs OpenSSL

Adding a 4-bit windowed scalar mul (960 B precomputed `[1..15]·G`) drops
us to **478K — 20% faster than our best asm.**  Still 3.2× slower than
OpenSSL's nistz256.

| Implementation | Cycles | vs OpenSSL | Precompute |
|---|---:|---:|---|
| OpenSSL nistz256 | 150K | 1.0× | 367 KB comb table |
| Rust (4-bit window) | 478K | 3.2× | 960 B (15 points) |
| fast2.S (BMI2) | 600K | 4.0× | none |
| fast.S (BMI2) | 659K | 4.4× | none |

The remaining gap is nistz256's comb table: `[0..36][0..64]·G` at 37
bit-positions.  u1·G becomes ~37 lookups + adds with **zero doublings
for the G half**.  We still do 252 doublings shared between G and Q.
That's ~252 × 43 Fe::mul = ~10800 extra field ops — at ~30 cyc each,
~320K cycles.  Matches the gap.

Porting the comb table would be straightforward (generate it in
`build.rs`, ~100KB of `.rodata`) and would likely land ~200K.  But
it's a space-for-time trade the asm project deliberately didn't take —
933-byte boot ROM and 367KB lookup tables don't coexist.

## Takeaway

The asm speed wins came from **dependency structure** (lazy carry), not
from register allocation or encoding.  LLVM handles the latter.
Express the data dependencies in Rust and the compiler does the rest.

The precompute-vs-code-size tradeoff is orthogonal.  A 960-byte table
beat all our asm.  OpenSSL's 367KB table beats everything.  Neither
has anything to do with the asm optimization work — they weren't in
scope for a boot ROM.

The size wins don't transfer.  If you need 933 bytes, write assembly.
If you need 150K cycles, precompute a comb table — in any language.

## Size/speed matrix after hand-unrolling

`Os` un-does three things that matter: it emits `imul` for `COEFF[i]*x`
(instead of constant-folding to add/sub), it re-loops the nested
schoolbook `for i/for j`, and it keeps the bounds check on
`CARRY_ADJ[(carry+4) as usize]`.  Hand-expanding all three in source
makes the code opt-level-proof:

| Config | Code | Cycles | vs fast2.S |
|---|---:|---:|---|
| O3, default inline | 12,908 B | 481K | — |
| **O3, Fe::mul `#[inline(never)]`** | **8,909 B** | **461K** | **−23%** |
| O2, Fe::mul never | 6,819 B | 470K | −22% |
| Os, Fe::mul never | 4,829 B | 546K | −9% |

The `#[inline(never)]` on `Fe::mul` is a pure win: −31% code, −4% cycles
(the hand-unrolled schoolbook schedules better when LLVM isn't trying to
cram it into 12 different callers).  O2 at 6.8KB is the sweet spot if
you care about both.  Os at 4.8KB if you REALLY care about size and can
eat 14% on speed.

`Fe::mul` outlined is 978 B.  With `Point::add` calling it 12× plus the
verify loop calling that ~130×, one outlining saves ~4KB.  The call/ret
overhead (~5 cyc) is invisible next to the ~70 cyc body.
