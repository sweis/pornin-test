# limb8/ — 8×32 q=t[top] track (formerly tv_ecdsa_tiny.S)

**The only W where both p AND n have all-ones top limb.** q=t[top]
reduce works for both — no Montgomery. All other signed-limb W's
(24, 52, 54) need Montgomery for mod-n.

| Build | Bytes | Cycles | |
|---|---:|---:|---|
| default | 930 | ~3.6M | 64-bit schoolbook product |
| `-DSMALL_MUL8` | 916 | ~4.7M | 32-bit `scasd` — size floor |
| `-DSOLINAS_P` | 988 | ~3.0M | P-256 fold, no multiplies in reduce |

The 2873 → 916 journey is in `../docs/plot_history.py` TRAIL,
`../CLAUDE.md`, and `progress.csv`. Thomas v7 at 928 B (5×54) —
back under by 12 B on SMALL_MUL8.

```
make size-all    # all three variants side by side
make test        # 607/607 on default build
make bench20     # 20-run median cycles
```
