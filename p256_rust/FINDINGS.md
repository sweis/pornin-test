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

## Takeaway

The asm speed wins came from **dependency structure** (lazy carry), not
from register allocation or instruction encoding.  LLVM handles the
latter.  Express the algorithm's actual data dependencies in Rust and
the compiler does the rest.

The size wins don't transfer.  If you need 933 bytes, write assembly.
If you need 597K cycles, write either.
