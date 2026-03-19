# limb5x56/ — 5×56 signed-limb Montgomery track

**1084 B / ~3.07M cyc** (607/607). Fork of limb5x54 with W=56 — same
K=5, same 40-byte slots, same 128-bit accumulator, but **byte-aligned
decode** (7 bytes/limb exactly) and a cleaner signed cP. Currently
13 B under limb5x54.

See `CONVERSION.md` for the W=54→56 derivation.

## Why 56 over 54

| | 5×54 | 5×56 |
|---|---|---|
| Decode stride | 6.75 bytes (shrd, per-limb shift) | **7 bytes (`lodsq; dec rsi`)** |
| cP limb 4 | 0xffffffff00 (two terms) | 0xFFFFFFFF (`dec dword`, no REX) |
| Top limb bits | 40 | 32 (lodsd tail, clean) |
| m0inv_n | 53-bit | 56-bit (both need movabs — wash) |

The decode saved 13 B structurally at baseline. The cP builder saved
3 B (`inc byte` for single-bit limbs, `dec dword` for all-F's low 32).

## Biggest tricks (1125→1084)

- **shr-bitmask BE loop** (−19, 72c7de0): ebx=0b10101 encodes the
  fe_from_be call sequence — `shr ebx,1` gives CF=chain-next-decode
  and ZF=done in one 2-byte instruction. Ported back to both other
  Montgomery tracks.
- **r15=&cP + packed counter** (−12, fc89ce3): fixed the broken
  `cmp bl, W` idiom from the limb5x54 source (bit offset ≠ limb width
  when W≠64). Test is `(ebx+1) & 63 == 0` instead.
- **xlatb + r12 drop** (−10, 1f2d8cb): backport from limb11x24.
  bcptr rbx→rsi (lodsw), jump-table ptr r12→rbx, xlatb is 1 B
  vs 3 B `mov al,[rbx+rax]`. r12 ended up unused — dropped its
  push/pop/lea entirely.

## What didn't port here

- **cqo+not single-loop NORM** (limb11's −3): built and measured at
  **+1 B**. .Lcprop here writes via `add [rdi],rdx` (in-place) which
  doesn't leave rax=top — need +3 B `mov rax,[rdi]`. Top limb hits
  ~36 bits during norm → `or rdx,rax` needs REX (+1 vs limb11's
  32-bit form). −4 + 2 + 3 = +1.
- **Tail-suffix sharing**: same `pop rax;pop rax;pop rbx;ret` pair
  as limb5x54, same ~150 B gap. fe_mul5's body sits between; closing
  the gap needs −23 B from fe_mul5 first.
- **shrd single-cmp** (limb5x54's −3): no shrd here; byte-aligned
  decode doesn't need it.

```
make test size bench20    # 607/607, bytes, 20-run median
```
