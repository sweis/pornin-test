# limb5x54/ — 5×54 signed-limb Montgomery track

**1097 B / ~2.77M cyc** (607/607). Thomas at 928 B / 4.48M with the
same architecture. 169 B to go; already ~1.6× faster on cycles.

## Why 5×54

Thomas's choice. 40-byte slots put **4 slots in disp8** from r14
(vs 2 for limb11's 88 B). K²=25 products per fe_mul vs 121 — the
128-bit accumulator (shrd/adc) costs bytes but the loop runs 5× less.

The MASK tax that looked like a cost flipped to a win: `and rax, r13`
is 3 B vs imm32's 5 B. One 10-byte `movabs` in verify, recouped after
5 sites; ~10 exist. **MASK-in-r13 is the load-bearing invariant.**

Decode is the real tax: 54 bits = 6.75 bytes, not byte-aligned. Each
limb needs a different (byte-offset, bit-shift) pair. limb5x56 forked
to W=56 specifically to eliminate this.

## Biggest tricks (1324→1097)

- **Signed cP + SF-from-.Lcprop** (−20, 7f59b6a): p as five
  ±power-of-2 terms built in verify. .Lcprop's final `add` sets SF;
  CHKLT and NORM branch on it directly — no separate sign test.
- **CIOS merge** (−18, 6ff298a): schoolbook + reduce as one loop,
  r10 = &acc[i]. Same math, one outer structure.
- **fe_from_le bit-offset loop** (−15, 8064542 + 30d2ee9): the 5×
  unroll collapsed to a loop. shrd + `cmovb` preload-next-iter; one
  `cmp` serves both cmovb and jbe; iteration-0 shrd-by-0 is a nop.
- **fe_from_be falls through** (−12, 886c4ac): BE decode is in-slot
  byte reversal then fall into fe_from_le.
- **xlatb + r12 drop** (−12, a089692): lodsw bcptr freed rbx → xlatb
  for the 1-byte jump-table lookup; r12 ended up wholly unused.
- **shr-bitmask BE chain** (−10, 607d9bd): ebx=0b10101 drives
  chain-vs-pop; one `shr` yields CF=chain and ZF=done. Port from
  limb5x56; nets 1 B more here because fe_from_be leaves rsi=src+32
  so the CF=1 case is free.

## What didn't port here

- **.Lcp_shared** (limb11's −17): the carry-prop body is 64-bit
  lodsq+add+stosq over there; here it's 128-bit shrd/adc. Different
  bytes, no sharing.
- **cqo+not single-loop NORM** (limb11's −3): only −1 here. Top limb
  is <2^44 (K=5, W=54) so bit 31 is data, not sign — `or rdx, rax`
  needs REX. limb11's K=11 smears it below 2^32.
- **Tail-suffix sharing**: the only ≥3 B suffix repeat
  (`pop rax;pop rax;pop rbx;ret`) is 152 B apart — past rel8.

```
make test size bench20    # 607/607, bytes, 20-run median
make test-mul             # fe_mul5 unit test (103 vectors)
```
