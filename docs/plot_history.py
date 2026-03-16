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
    (1099, 2407, None),
    # --- op6/7 merge + fe_sub_raw inline chain (−8B). .Lop8=255/255 ---
    (1071, 6186, None),   # SMALL_MUL8
    (1091, 2407, None),
    # --- RCB COMPLETE ADDITION — one formula, no 3-way branch (−59B) ---
    (1012, 7950, None),
    (1032, 3645, None),
    # --- Addend slot shift: Shamir setup → one rep movsq (−16B) ---
    #   bc_v1 stages slots 2-7 = Gx,Gy,1,Qx,Qy,1.  RCB addend moves
    #   4,5,6 → 5,6,7 (pure nibble cycle, 0 B).  Retakes size corner.
    (1005, 3475, None),
    (985,  7960, None),
    # --- Micro-grind: imul for slot12, [rdi-64] inc, drop r15, lodsb ---
    (1000, 3490, None),
    (980,  7975, None),
    (999,  3530, None),
    (979,  7975, None),
    # --- fe_inv_m: no seed copy, no r8 (−10B).  Then .Lfm = Nmul (−5B) ---
    #   bc_v1 sets dst=1; loop starts at bit 255 instead of 254.
    #   fe_mul_m doesn't preserve rdi → bracket both calls instead.
    (989,  3530, None),
    (969,  8030, None),
    (984,  3540, None),
    (964,  8115, None),
    (983,  3525, None),
    (963,  8115, None),
    # --- Layout reorders: pt_mul/.Lcadd, fe_mul_m for rel8 jmps (−6B) ---
    #   Costs ~5% cycles from new I-cache layout — accepted for size.
    (980,  3540, None),
    (960,  8085, None),
    (977,  3720, None),
    (957,  8470, "fe_inv_m + layout\n957B — size corner"),
]

# Thomas's track: v1, v2, v3 (1004B), v4 (996B).
# Post-957B: our 977B DOMINATES Thomas v4 (smaller AND faster).
# Thomas is fully off the frontier now.
THOMAS_TRACK = [(1156, 3600), (1046, 3990), (1004, 3920), (996, 4100)]
THOMAS    = (996, 4100)
CLAUDE    = (957, 8470)     # size corner — 39 B under Thomas v4
TARGET    = 1024

def pareto(pts):
    front = []
    for i, (b, c) in enumerate(pts):
        if not any((b2 <= b and c2 <= c and (b2 < b or c2 < c))
                   for j, (b2, c2) in enumerate(pts) if j != i):
            front.append(i)
    front.sort(key=lambda i: pts[i][0])
    return front

ALL_XY = [(b, c) for b, c, _ in TRAIL] + THOMAS_TRACK
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

# Thomas track — 4 points.  v3/v4 (1004B, 996B) RETAKE the size corner,
# both under 1024, both faster than our SMALL_MUL8.  v1/v2 dominated.
ttx = [p[0] for p in THOMAS_TRACK]
tty = [p[1] for p in THOMAS_TRACK]
ax.plot(ttx, tty, ':', color='#2e8b57', linewidth=1.5, zorder=4,
        label='Thomas')
ax.scatter(ttx, tty, c='#2e8b57', s=90, marker='o',
           edgecolors='#1a5235', linewidths=1.2, zorder=5)
ax.annotate(f'Thomas v4\n{THOMAS[0]}B', THOMAS,
            textcoords="offset points", xytext=(-14, 14), fontsize=10,
            fontweight='bold', ha='right',
            bbox=dict(boxstyle='round,pad=0.35', fc='#d4f4dd',
            ec='#2e8b57', lw=1))
ax.annotate(f'{THOMAS_TRACK[2][0]}B', THOMAS_TRACK[2],
            textcoords="offset points", xytext=(8, -14), fontsize=8,
            color='#2e8b57')

# Claude star — size corner, 11 B under Thomas v4.
ax.scatter([CLAUDE[0]], [CLAUDE[1]], c='#e07000', s=280, marker='*',
           edgecolors='#8a4500', linewidths=1.5, zorder=6,
           label=f'Claude {CLAUDE[0]}B')
ax.annotate(f'Claude\n{CLAUDE[0]}B — size corner',
            CLAUDE, textcoords="offset points", xytext=(14, -22),
            fontsize=10, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.35', fc='#ffe4c4',
                      ec='#e07000', lw=1))

# 1024 B target line — both Thomas and Claude now past it.
ax.axvline(TARGET, color='#888', linestyle='--', linewidth=1.5,
           alpha=0.7, zorder=1)
ax.annotate(f'{TARGET}B', (TARGET, 500),
            textcoords="offset points", xytext=(6, 0), fontsize=9,
            color='#888')

# Turning-point labels only — the path, not every step
LABEL_OFFSETS = {
    "fork":       (8, 10),
    "Shamir":     (12, -10),
    "32-bit":     (12, -8),
    "projective": (-8, 16),
    "bt-on-cN":   (-90, -6),
    "RCB":        (12, -10),
    "addend":     (12, 12),
    "fe_inv_m":   (12, 8),
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
ax.legend(loc='upper right', framealpha=0.95, fontsize=9)
ax.grid(True, alpha=0.2, which='both')
ax.set_axisbelow(True)
# Log-y: cycles span 629K → 8470K (~13:1).  Log compresses the tiny.S
# speed-for-size grind (6.2M → 8.5M) into a visible band instead of
# a wall at the top, and separates the fast.S cluster (650K-1000K)
# from the bc.S baseline (1850K).  Size stays linear — only 2:1 range.
ax.set_yscale('log')
ax.set_xlim(940, 2060)
ax.set_ylim(500, 10000)
# Clean up the log axis: major ticks at nice values, no scientific notation.
from matplotlib.ticker import ScalarFormatter, LogLocator
ax.yaxis.set_major_locator(LogLocator(base=10, subs=[1, 2, 5]))
ax.yaxis.set_major_formatter(ScalarFormatter())
ax.yaxis.set_minor_formatter(lambda x, pos: '')

plt.tight_layout()
plt.savefig('docs/progress.png', dpi=100, bbox_inches='tight')
print(f"wrote docs/progress.png")
print(f"Pareto frontier: {[(ALL_XY[i][0], ALL_XY[i][1]) for i in FRONT]}")
