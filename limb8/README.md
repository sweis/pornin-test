# limb8/ — 8×32 q=t[top] track

**The only W where both p AND n have all-ones top limb.** q=t[top]
reduce works for both moduli — no Montgomery, no m0inv, no R². Every
signed-limb W (24, 52, 54, 56) pays the Montgomery-n tax; W=32 doesn't.
This is the size floor of the whole project.

| Build | Bytes | Cycles | |
|---|---:|---:|---|
| `-DSMALL_MUL8` | 890 | ~5.2M | 32-bit `scasd` schoolbook — size floor |
| default | 908 | ~3.4M | 64-bit product, `dec;jnz` inner loop |
| `-DSOLINAS_P` | 966 | ~2.9M | P-256 fold, no multiplies in reduce |

Thomas v7 at 928 B / 4.48M (5×54). SMALL_MUL8 is **38 B under** on
size; default **dominates** on both axes.

## Biggest tricks in the 933→890 grind

- **n−2 in rodata, `bt` direct** (−4): dropped the cmp/jb/je that
  special-cased bits 0–4 of n vs n−2. INV reads the exponent straight
  from .rodata.
- **fe_from_be_pair fall-through** (−5): `call fe_from_be` falls into
  a second `fe_from_be` body for (r,s) and (Qx,Qy) decodes.
- **`repe scasq` CHKZ** (−4): compare-to-zero as a string op.
- **bcptr in rsi via `lodsw`** (−1): drops `add rbx,2` + push/pop rbx;
  bc_run no longer uses rbx at all.
- **`stc; jmp .Lsbb`** (−1): fail path reuses success epilogue's
  `sbb; inc`; forced CF=1 yields eax=−1→0.

## What doesn't port here

Montgomery-specific tricks from the signed-limb tracks are N/A: there
is no R-factor to cancel, no cR2 to drop, no MASK register. The
projective-scale trick (limb11x24's −25 B) requires a Montgomery
level to be the "scale" — here there isn't one.

```
make size-all    # all three variants
make test        # 607/607
make bench20     # 20-run median
```
