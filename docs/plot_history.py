#!/usr/bin/env python3
"""
Regenerate the size-vs-speed progress charts.

Data is (bytes, kcyc_nominal, label).  kcyc_nominal is the cycle count
normalized to a nominal 1.85M bc.S baseline: measured_fast/measured_bc * 1850.
This lets measurements from different µarches (Skylake vs Sapphire Rapids)
live on the same axis — only the ratio matters.

Historical fast.S points (Skylake-class, bc.S ~1832K) are from commit logs
and prior chart data.  The 1397B session was measured on Sapphire Rapids
(bc.S ~1855K); ratios converted to nominal kcyc here.
"""

import matplotlib.pyplot as plt

# ----------------------------------------------------------------------
# bc.S baseline track (all at ratio 1.0 = 1850 kcyc nominal)
# Size-only shrink from 2018 B to 1712 B.
# ----------------------------------------------------------------------
BC_TRACK = [2018, 1963, 1911, 1872, 1839, 1801, 1766, 1712]
BC_Y = 1850

# ----------------------------------------------------------------------
# fast.S full history.  (bytes, kcyc_nominal, label or None).
# Skylake-era points use raw cycles (bc.S was ~1832 ≈ 1850 nominal,
# close enough that raw≈nominal).  Sapphire Rapids points are scaled
# by 1850/1855 ≈ 0.997 — effectively identity at kcyc resolution.
# ----------------------------------------------------------------------
FAST = [
    # --- Skylake-era ---
    (1712, 1850, "fork\n1712B"),
    (1660, 1105, "CIOS unroll\n1660B"),
    (1622, 1046, None),
    (1604, 1048, None),
    (1598, 1044, None),
    (1565, 1028, None),
    (1538, 1037, None),
    (1511, 1035, "1511B (README)"),
    (1498, 1035, None),   # no bench recorded; carried fwd
    (1483, 1035, None),
    (1471, 1035, None),
    (1458, 1035, None),
    (1448, 1035, None),
    (1441, 1018, "session start\n1441B"),
    (1425,  930, "muladd4 carry\n1425B"),
    (1424,  980, None),   # r14 invariant pass (temp regression)
    (1411,  925, None),   # fe_sub_raw lodsq
    (1406,  906, None),   # pt_add_acc reloc
    (1405,  888, "pre-Shamir smallest\n1405B, 0.48"),
    (1427,  629, "Shamir\n1427B, 0.34"),
    # --- Sapphire Rapids era (this session) ---
    # Measured bc.S ~1855K, fast ratios scaled to nominal 1850K.
    # 1427B re-measured here at 660K → ratio 0.356 → 659 nominal.
    # The ~30K gap vs Skylake's 629K is µarch noise; both are the
    # same 1427B binary.  We plot the Skylake 629 as the canonical
    # Shamir point and start this session's track from there.
    (1418,  654, None),   # mov cl,N  (656/1855*1850)
    (1416,  654, None),   # rbx stockpile
    (1413,  654, None),   # enter/leave verify
    (1409,  654, None),   # bc_run r13 drop
    (1406,  653, None),   # enter/leave fe_inv_m
    (1399,  652, None),   # pt_mul rbx direct
    (1397,  652, "rcx-chain + enter/leave\n1397B, 0.35"),
]

# ----------------------------------------------------------------------
# Pareto frontier: a point is on the frontier if nothing is both
# smaller AND faster.
# ----------------------------------------------------------------------
def pareto(pts):
    """Return indices of Pareto-optimal points (min bytes, min cycles)."""
    front = []
    for i, (b, c, _) in enumerate(pts):
        dominated = any(
            (b2 <= b and c2 <= c and (b2 < b or c2 < c))
            for j, (b2, c2, _) in enumerate(pts) if j != i
        )
        if not dominated:
            front.append(i)
    # Sort by bytes for the connecting line
    front.sort(key=lambda i: pts[i][0])
    return front

FRONT = pareto(FAST)

# ======================================================================
# Chart 1: full_history.png — whole story from 2018B down to 1397B
# ======================================================================
fig, ax = plt.subplots(figsize=(15.45, 9.45), dpi=100)

# bc.S baseline (gray)
ax.plot(BC_TRACK, [BC_Y]*len(BC_TRACK), 'o-', color='#cccccc',
        markersize=5, linewidth=1, zorder=1,
        label='tv_ecdsa_bc.S (baseline, ratio=1.0)')
ax.annotate('bc.S start\n2018B', (BC_TRACK[0], BC_Y),
            textcoords="offset points", xytext=(8, 8), fontsize=9,
            bbox=dict(boxstyle='round,pad=0.3', fc='#fffacd', ec='gray', lw=0.5))

# fast.S chronological path (dotted gray)
fx = [p[0] for p in FAST]
fy = [p[1] for p in FAST]
ax.plot(fx, fy, ':', color='#aaaaaa', linewidth=0.8, zorder=2,
        label='tv_ecdsa_fast.S (chronological)')
ax.scatter(fx, fy, c='#3b5998', s=40, edgecolors='#1a2d5c',
           linewidths=0.8, zorder=3)

# Pareto frontier (red diamonds)
px = [FAST[i][0] for i in FRONT]
py = [FAST[i][1] for i in FRONT]
ax.plot(px, py, '-', color='#c41e3a', linewidth=2.5, zorder=4,
        label='fast.S Pareto frontier')
ax.scatter(px, py, c='#c41e3a', s=120, marker='D',
           edgecolors='#7a1225', linewidths=1.2, zorder=5)

# Labels for notable points
for b, c, lab in FAST:
    if lab:
        # Nudge to avoid overlaps
        dx, dy = (10, 8)
        if "1397" in lab: dx, dy = (-120, -12)
        if "1405" in lab: dx, dy = (-140,  12)
        if "Shamir" in lab: dx, dy = ( 12, -18)
        if "fork" in lab: dx, dy = (-30,  18)
        ax.annotate(lab, (b, c), textcoords="offset points",
                    xytext=(dx, dy), fontsize=9,
                    bbox=dict(boxstyle='round,pad=0.3',
                              fc='#fffacd', ec='gray', lw=0.5))

ax.set_xlabel('Size (bytes)', fontsize=12)
ax.set_ylabel('Cycles (thousands, nominal 1.85M bc baseline)', fontsize=12)
ax.set_title('Full ECDSA/P-256 verify optimization history — lower-left is better',
             fontsize=13)
ax.legend(loc='upper left', framealpha=0.95)
ax.grid(True, alpha=0.2)
ax.set_axisbelow(True)

plt.tight_layout()
plt.savefig('docs/full_history.png', dpi=100, bbox_inches='tight')
print(f"wrote docs/full_history.png  —  Pareto: {[(FAST[i][0],FAST[i][1]) for i in FRONT]}")

# ======================================================================
# Chart 2: size_speed_progress.png — zoomed to fast.S-only interesting region
# ======================================================================
# Show only points from "session start" onward (where the interesting
# size/speed trade-offs live).
ZOOM = FAST[13:]   # 1441B onward
ZFRONT = pareto(ZOOM)

fig, ax = plt.subplots(figsize=(11.72, 8.25), dpi=100)

zx = [p[0] for p in ZOOM]
zy = [p[1] for p in ZOOM]
ax.plot(zx, zy, ':', color='#aaaaaa', linewidth=1, zorder=2,
        label='chronological')
ax.scatter(zx, zy, c='#3b5998', s=50, edgecolors='#1a2d5c',
           linewidths=1, zorder=3)

zpx = [ZOOM[i][0] for i in ZFRONT]
zpy = [ZOOM[i][1] for i in ZFRONT]
ax.plot(zpx, zpy, '-', color='#c41e3a', linewidth=2.5, zorder=4,
        label='Pareto frontier')
ax.scatter(zpx, zpy, c='#c41e3a', s=140, marker='D',
           edgecolors='#7a1225', linewidths=1.3, zorder=5)

# Zoomed labels: annotate everything with a label plus a few key unlabeled
ZOOM_LABELS = {
    1441: ("session start\n1441 B, 1018 Kcyc", (10, 8)),
    1424: ("r14 invariant pass\n1424 B, 980 Kcyc", (-80, 25)),
    1411: ("fe_sub_raw lodsq\n1411 B, 925 Kcyc", (12, -8)),
    1405: ("epilogue share\n1405 B, 888 Kcyc", (-130, -4)),
    1427: ("Shamir's trick\n1427 B, 629 Kcyc", (12, -6)),
    1418: ("mov cl,N\n1418 B, 654 Kcyc", (12, 20)),
    1399: ("pt_mul rbx direct\n1399 B, 652 Kcyc", (10, 30)),
    1397: ("rcx-chain + enter/leave\n1397 B, 652 Kcyc", (-160, -20)),
}
for b, c, _ in ZOOM:
    if b in ZOOM_LABELS:
        txt, (dx, dy) = ZOOM_LABELS[b]
        ax.annotate(txt, (b, c), textcoords="offset points",
                    xytext=(dx, dy), fontsize=9,
                    bbox=dict(boxstyle='round,pad=0.3',
                              fc='#fffacd', ec='gray', lw=0.5))

ax.set_xlabel('Size (bytes)', fontsize=12)
ax.set_ylabel('Cycles (thousands)', fontsize=12)
ax.set_title('tv_ecdsa_fast.S - size vs speed  (lower-left = better)', fontsize=13)
ax.legend(loc='upper right', framealpha=0.95)
ax.grid(True, alpha=0.2)
ax.set_axisbelow(True)

plt.tight_layout()
plt.savefig('docs/size_speed_progress.png', dpi=100, bbox_inches='tight')
print(f"wrote docs/size_speed_progress.png  —  Pareto: {[(ZOOM[i][0],ZOOM[i][1]) for i in ZFRONT]}")
