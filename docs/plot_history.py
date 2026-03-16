#!/usr/bin/env python3
"""
Size-vs-speed progress chart (docs/progress.png).

kcyc_nominal = measured * 1850 / bc_baseline — ratios transfer across µarches.
"""

import matplotlib.pyplot as plt

# bc.S baseline track (all at ratio 1.0)
BC_TRACK = [2018, 1963, 1911, 1872, 1839, 1801, 1766, 1712]
BC_Y = 1850

# Full chronological trail.  Labels only on architectural turning points.
TRAIL = [
    # --- fast.S era: 64-bit Montgomery (CIOS), mulx ---
    (1712, 1850, "fork from bc.S\n1712B"),
    (1660, 1105, None), (1622, 1046, None), (1604, 1048, None),
    (1598, 1044, None), (1565, 1028, None), (1538, 1037, None),
    (1511, 1035, None), (1498, 1035, None), (1483, 1035, None),
    (1471, 1035, None), (1458, 1035, None), (1448, 1035, None),
    (1441, 1018, None), (1425,  930, None), (1424,  980, None),
    (1411,  925, None), (1406,  906, None), (1405,  888, None),
    (1427,  629, "Shamir's trick\n1427B — speed corner"),
    (1418,  654, None), (1416,  654, None), (1413,  654, None),
    (1409,  654, None), (1406,  653, None), (1399,  652, None),
    (1397,  652, None),
    # --- tiny.S fork: trade speed for size ---
    (1374,  948, None), (1362,  948, None), (1360,  945, None),
    (1357,  950, None), (1347,  945, None), (1338,  945, None),
    (1300, 1456, "32-bit q=t[top]\nno Montgomery"),
    (1293, 7180, None), (1279, 7180, None), (1266, 7180, None),
    (1257, 7180, None), (1255, 7460, None), (1252, 7460, None),
    (1238, 7460, None), (1216, 7460, None),
    (1195, 6180, "projective check\nno mod-p inv"),
    (1193, 6200, None), (1184, 6200, None), (1177, 6290, None),
    (1160, 6300, None), (1154, 6300, None), (1149, 6300, None),
    (1146, 6300, None), (1140, 6300, None), (1136, 6300, None),
    (1124, 6300, None),
    (1105, 6186, "bt-on-cN\nno exp buffer"),
    # --- speed/size knee: loop→dec+jnz, 64-bit schoolbook ---
    (1109, 3665, None), (1111, 3268, None), (1117, 2996, None),
    (1125, 2407, None), (1098, 6186, None), (1118, 2407, None),
    (1079, 6186, None),
    (1099, 2407, None),  # default — star
]

THOMAS_V1 = (1156, 3600)
THOMAS    = (1046, 3990)
CLAUDE    = (1099, 2407)
TARGET    = 1024

def pareto(pts):
    front = []
    for i, (b, c) in enumerate(pts):
        if not any((b2 <= b and c2 <= c and (b2 < b or c2 < c))
                   for j, (b2, c2) in enumerate(pts) if j != i):
            front.append(i)
    front.sort(key=lambda i: pts[i][0])
    return front

ALL_XY = [(b, c) for b, c, _ in TRAIL] + [THOMAS, THOMAS_V1]
FRONT = pareto(ALL_XY)

# ======================================================================
fig, ax = plt.subplots(figsize=(13, 8), dpi=100)

# bc.S baseline — faded gray
ax.plot(BC_TRACK, [BC_Y]*len(BC_TRACK), 'o-', color='#d0d0d0',
        markersize=4, linewidth=1, zorder=1, label='bc.S baseline (ratio 1.0)')

# Chronological trail — dotted gray with small blue dots
tx = [p[0] for p in TRAIL]
ty = [p[1] for p in TRAIL]
ax.plot(tx, ty, ':', color='#b0b0b0', linewidth=0.7, zorder=2,
        label='optimization trail')
ax.scatter(tx, ty, c='#4a6fa5', s=22, edgecolors='#2a4670',
           linewidths=0.5, zorder=3, alpha=0.7)

# Pareto frontier — bold red
px = [ALL_XY[i][0] for i in FRONT]
py = [ALL_XY[i][1] for i in FRONT]
ax.plot(px, py, '-', color='#c41e3a', linewidth=2.8, zorder=4,
        label='Pareto frontier')
ax.scatter(px, py, c='#c41e3a', s=110, marker='D',
           edgecolors='#7a1225', linewidths=1.2, zorder=5)

# Thomas track — green circles, dotted
ttx, tty = [THOMAS_V1[0], THOMAS[0]], [THOMAS_V1[1], THOMAS[1]]
ax.plot(ttx, tty, ':', color='#2e8b57', linewidth=1.5, zorder=4,
        label='Thomas')
ax.scatter(ttx, tty, c='#2e8b57', s=90, marker='o',
           edgecolors='#1a5235', linewidths=1.2, zorder=5)
ax.annotate(f'Thomas v2\n{THOMAS[0]}B', THOMAS,
            textcoords="offset points", xytext=(12, -4), fontsize=10,
            fontweight='bold', bbox=dict(boxstyle='round,pad=0.35',
            fc='#d4f4dd', ec='#2e8b57', lw=1))
ax.annotate('v1', THOMAS_V1, textcoords="offset points", xytext=(8, 4),
            fontsize=8, color='#2e8b57')

# Claude star
ax.scatter([CLAUDE[0]], [CLAUDE[1]], c='#e07000', s=260, marker='*',
           edgecolors='#8a4500', linewidths=1.5, zorder=6,
           label=f'Claude ({CLAUDE[0]}B, ratio {CLAUDE[1]/1850:.2f})')
ax.annotate(f'Claude\n{CLAUDE[0]}B, ratio {CLAUDE[1]/1850:.2f}',
            CLAUDE, textcoords="offset points", xytext=(14, -24),
            fontsize=10, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.35', fc='#ffe4c4',
                      ec='#e07000', lw=1))

# 1024 B target line
ax.axvline(TARGET, color='#888', linestyle='--', linewidth=1.2,
           alpha=0.5, zorder=1)
ax.annotate(f'{TARGET}B\ntarget', (TARGET, 350),
            textcoords="offset points", xytext=(6, 0), fontsize=9,
            color='#666', fontweight='bold')

# Turning-point labels only — the path, not every step
LABEL_OFFSETS = {
    "fork":       (8, 10),
    "Shamir":     (12, -10),
    "32-bit":     (12, -8),
    "projective": (-8, 16),
    "bt-on-cN":   (-90, -6),
}
for b, c, lab in TRAIL:
    if lab:
        key = next((k for k in LABEL_OFFSETS if lab.lower().startswith(k.lower())), None)
        dx, dy = LABEL_OFFSETS.get(key, (10, 8))
        ax.annotate(lab, (b, c), textcoords="offset points", xytext=(dx, dy),
                    fontsize=8, bbox=dict(boxstyle='round,pad=0.25',
                    fc='#fffacd', ec='#bbb', lw=0.5, alpha=0.9))

ax.set_xlabel('Size (bytes)', fontsize=12)
ax.set_ylabel('Cycles (thousands, normalized to bc.S ≈ 1850K)', fontsize=12)
ax.set_title('ECDSA/P-256 verify — size vs speed (lower-left is better)',
             fontsize=13)
ax.legend(loc='upper left', framealpha=0.95, fontsize=9)
ax.grid(True, alpha=0.2)
ax.set_axisbelow(True)
ax.set_xlim(1000, 2050)
ax.set_ylim(200, 8000)

plt.tight_layout()
plt.savefig('docs/progress.png', dpi=100, bbox_inches='tight')
print(f"wrote docs/progress.png")
print(f"Pareto frontier: {[(ALL_XY[i][0], ALL_XY[i][1]) for i in FRONT]}")
