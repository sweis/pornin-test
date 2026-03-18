# limb8/ — 8×32 q=t[top] track (formerly tv_ecdsa_tiny.S)

**The only W where both p AND n have all-ones top limb.** q=t[top]
reduce works for both — no Montgomery. All other signed-limb W's
(24, 52, 54) need Montgomery for mod-n.

| Build | Bytes | Cycles | |
|---|---:|---:|---|
| default | 947 | ~3.6M | 64-bit schoolbook product |
| `-DSMALL_MUL8` | 933 | ~4.7M | 32-bit `loop`+`scasd` — size floor |
| `-DSOLINAS_P` | 1005 | ~3.0M | P-256 fold, no multiplies in reduce |

The 2873 → 933 journey is in `../docs/plot_history.py` TRAIL and
`../CLAUDE.md`. Now superseded by Thomas v7 (928 B, 5×54) on the
size axis.

```
make size-all    # all three variants side by side
make test        # 607/607 on default build
make bench20     # 20-run median cycles
```
