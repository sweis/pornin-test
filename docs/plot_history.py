#!/usr/bin/env python3
"""
Generate the size-vs-speed progress chart (docs/progress.png).

Data is (bytes, kcyc_nominal, label).  kcyc_nominal is the cycle count
normalized to a nominal 1.85M bc.S baseline: measured_fast/measured_bc * 1850.
This lets measurements from different µarches live on the same axis —
only the ratio matters.

Historical points (Skylake-class, bc.S ~1832K) are from commit logs.
The 1427→1397 session was measured on Sapphire Rapids (bc.S ~1855K);
ratios scaled to nominal.
"""

import matplotlib.pyplot as plt
from mpl_toolkits.axes_grid1.inset_locator import inset_axes

# ----------------------------------------------------------------------
# bc.S baseline track (all at ratio 1.0 = 1850 kcyc nominal)
# ----------------------------------------------------------------------
BC_TRACK = [2018, 1963, 1911, 1872, 1839, 1801, 1766, 1712]
BC_Y = 1850

# ----------------------------------------------------------------------
# fast.S full history.  (bytes, kcyc_nominal, label or None).
# ----------------------------------------------------------------------
FAST = [
    (1712, 1850, "fork\n1712B"),
    (1660, 1105, "CIOS unroll\n1660B"),
    (1622, 1046, None),
    (1604, 1048, None),
    (1598, 1044, None),
    (1565, 1028, None),
    (1538, 1037, None),
    (1511, 1035, "1511B (README)"),
    (1498, 1035, None),
    (1483, 1035, None),
    (1471, 1035, None),
    (1458, 1035, None),
    (1448, 1035, None),
    (1441, 1018, "session start\n1441B"),
    (1425,  930, "muladd4 carry\n1425B"),
    (1424,  980, None),
    (1411,  925, None),
    (1406,  906, None),
    (1405,  888, "pre-Shamir smallest\n1405B, 0.48"),
    (1427,  629, "Shamir\n1427B, 0.34"),
    # --- 1427→1397 session (Sapphire Rapids, scaled to nominal) ---
    (1418,  654, None),   # mov cl,N
    (1416,  654, None),   # rbx stockpile
    (1413,  654, None),   # enter/leave verify
    (1409,  654, None),   # bc_run r13 drop
    (1406,  653, None),   # enter/leave fe_inv_m
    (1399,  652, None),   # pt_mul rbx direct
    (1397,  652, "rcx-chain + enter/leave\n1397B, 0.35"),
    # --- tiny.S size-only fork (speed traded, target 1024B) ---
    (1374,  948, None),   # muladd4 looped (scaled: 951/1855*1850)
    (1362,  948, None),   # r8/r15 chain
    (1360,  945, None),   # fe_cpy rep
    (1357,  950, None),   # push-loop
    (1347,  945, "B-derive\n1347B"),
    (1338,  945, None),   # Shamir one-rep
    (1300, 1456, "32-bit q=t[top]\n1300B, 0.79"),  # 1461/1855*1850
    (1293, 7180, None),   # loop everywhere (true speed)
    (1279, 7180, None),   # cdq + .Lop3 cond-sub
    (1266, 7180, None),   # INV bytecode ops
    (1257, 7180, None),
    (1255, 7460, None),
    (1252, 7460, None),
    (1238, 7460, None),   # mul8 inline
    (1216, 7460, None),
    # --- CORRECTED: prior 3990 was mismeasured. Re-benched on this
    # machine: 04934b5 (1195B) = 6.18M raw, bc.S = 1.851M → ratio 3.34.
    # The projective-check speedup was real (7460→6180) but half what
    # the chart claimed.  All points 1195→1154 re-benched to ~6.2-6.3M.
    (1195, 6180, "PROJECTIVE CHECK\n1195B, 3.34"),  # 6180/1851*1850
    (1193, 6200, None),
    (1184, 6200, None),
    (1177, 6290, None),
    (1160, 6300, "bc_v2 merged\n1160B"),           # 6310/1851*1850
    (1154, 6300, None),
    (1149, 6300, None),   # movzx+stack-m
    (1146, 6300, None),   # bt32+r8
    (1140, 6300, None),   # H-check bytecode
    (1136, 6300, None),   # push/pop
    (1124, 6300, None),   # cGX block merge
    (1105, 6186, None),   # SMALL_MUL8 — dominated by Thomas v2
    # --- Speed/size scan: loop is 80% of the penalty.  All three
    # intermediate points are Pareto vs Thomas v2 (he's smaller,
    # we're faster).  Ratios on this machine, bc.S ≈ 1.88M. ---
    (1109, 3665, None),   # +4B: mul8 loop→dec+jnz only.  ratio 2.02
    (1111, 3268, None),   # +6B: +pushzero loop fix.       ratio 1.80
    (1117, 2996, None),   # +12B: +scasd→lea.              ratio 1.62
    (1125, 2407, None),   # +8B: 64-bit schoolbook.        ratio 1.30
    # --- r13 single-use inlined (−7B, cold path, 0 cyc cost) ---
    (1098, 6186, None),   # SMALL_MUL8 — still dominated
    (1118, 2407, None),   # default — CLAUDE star
]

def pareto(pts):
    front = []
    for i, (b, c, _) in enumerate(pts):
        if not any((b2 <= b and c2 <= c and (b2 < b or c2 < c))
                   for j, (b2, c2, _) in enumerate(pts) if j != i):
            front.append(i)
    front.sort(key=lambda i: pts[i][0])
    return front

# Thomas v1 (1156B/1.95) is dominated by OUR 1117B AND by his own v2.
# Thomas v2 (1046B/3.99M) dominates our SMALL_MUL8 (1105B/6.19M) —
# he reclaimed the size corner.  But our 1117B stays Pareto: faster.
THOMAS_V1 = (1156, 3600, "Thomas v1\n1156B, 1.95")
THOMAS    = (1046, 3990, "Thomas v2\n1046B, 2.16")   # new size record
CLAUDE    = (1118, 2407, "Claude\n1118B, 1.30")       # Pareto: faster
TARGET    = 1024

ALL_PTS = FAST + [THOMAS, THOMAS_V1]
FRONT = pareto(ALL_PTS)

# ======================================================================
# Single chart: full history with inset zoom on the frontier region.
# ======================================================================
fig, ax = plt.subplots(figsize=(14, 9), dpi=100)

# bc.S baseline
ax.plot(BC_TRACK, [BC_Y]*len(BC_TRACK), 'o-', color='#cccccc',
        markersize=5, linewidth=1, zorder=1,
        label='tv_ecdsa_bc.S (baseline, ratio=1.0)')
ax.annotate('bc.S start\n2018B', (BC_TRACK[0], BC_Y),
            textcoords="offset points", xytext=(8, 8), fontsize=9,
            bbox=dict(boxstyle='round,pad=0.3', fc='#fffacd', ec='gray', lw=0.5))

# fast.S chronological path
fx = [p[0] for p in FAST]
fy = [p[1] for p in FAST]
ax.plot(fx, fy, ':', color='#aaaaaa', linewidth=0.8, zorder=2,
        label='tv_ecdsa_fast.S (chronological)')
ax.scatter(fx, fy, c='#3b5998', s=40, edgecolors='#1a2d5c',
           linewidths=0.8, zorder=3)

# Pareto frontier (ours + Thomas)
px = [ALL_PTS[i][0] for i in FRONT]
py = [ALL_PTS[i][1] for i in FRONT]
ax.plot(px, py, '-', color='#c41e3a', linewidth=2.5, zorder=4,
        label='Pareto frontier')
ax.scatter(px, py, c='#c41e3a', s=120, marker='D',
           edgecolors='#7a1225', linewidths=1.2, zorder=5)

# Thomas track: green circles joined by a dotted line (like bc.S
# track but green).  v1 → v2 shows his progression.
THOMAS_TRACK = [THOMAS_V1, THOMAS]
ttx = [p[0] for p in THOMAS_TRACK]
tty = [p[1] for p in THOMAS_TRACK]
ax.plot(ttx, tty, ':', color='#2e8b57', linewidth=1.5, zorder=4,
        label='Thomas (chronological)')
ax.scatter(ttx, tty, c='#2e8b57', s=100, marker='o',
           edgecolors='#1a5235', linewidths=1.2, zorder=5)

# v2 annotation — holds the size corner.
tb, tc, _ = THOMAS
ax.annotate(f'Thomas v2\n{tb}B, ratio {tc/1850:.2f}',
            (tb, tc), textcoords="offset points", xytext=(14, -6),
            fontsize=10, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.4', fc='#d4f4dd',
                      ec='#2e8b57', lw=1))
# v1 annotation — dominated now.
t1b, t1c, _ = THOMAS_V1
ax.annotate(f'Thomas v1\n(dominated)', (t1b, t1c),
            textcoords="offset points", xytext=(10, 4), fontsize=8,
            color='#2e8b57')

# Claude marker — Pareto-optimal: faster than Thomas v2, but v2 is
# smaller.  Neither dominates.
cb, cc, _ = CLAUDE
ax.scatter([cb], [cc], c='#e07000', s=250, marker='*',
           edgecolors='#8a4500', linewidths=1.5, zorder=6,
           label=f'Claude ({cb}B, {cc/1000:.1f}M cyc)')
ax.annotate(f'Claude\n{cb}B, ratio {cc/1850:.2f}',
            (cb, cc), textcoords="offset points", xytext=(14, -22),
            fontsize=10, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.4', fc='#ffe4c4',
                      ec='#e07000', lw=1))

# 1024 B size target — vertical marker line.
ax.axvline(TARGET, color='#2e8b57', linestyle='--', linewidth=1.5,
           alpha=0.6, zorder=1)
ax.annotate(f'target\n{TARGET}B', (TARGET, 400),
            textcoords="offset points", xytext=(6, 0), fontsize=10,
            color='#2e8b57', fontweight='bold')

# Main-axis labels
LABEL_OFFSETS = {
    "fork":     (-55, -18),
    "CIOS":     (10, 8),
    "1511":     (-35, 22),
    "session":  (10, 8),
    "muladd4":  (10, 8),
    "pre-Sham": (10, -20),
    "Shamir":   (12, -8),
    "rcx-chain":(-145, -8),
    "PROJECTIVE":(10, -22),
    "bc_v2":    (-80, -8),
    "SIZE FLOOR":(-60, 14),
}
for b, c, lab in FAST:
    if lab:
        dx, dy = next((v for k, v in LABEL_OFFSETS.items() if lab.startswith(k)), (10, 8))
        ax.annotate(lab, (b, c), textcoords="offset points", xytext=(dx, dy),
                    fontsize=9, bbox=dict(boxstyle='round,pad=0.3',
                    fc='#fffacd', ec='gray', lw=0.5))

ax.set_xlabel('Size (bytes)', fontsize=12)
ax.set_ylabel('Cycles (thousands, nominal 1.85M bc baseline)', fontsize=12)
ax.set_title('ECDSA/P-256 verify optimization history — lower-left is better',
             fontsize=13)
ax.legend(loc='upper center', framealpha=0.95)
ax.grid(True, alpha=0.2)
ax.set_axisbelow(True)
ax.set_xlim(1000, 2050)

# ----------------------------------------------------------------------
# Inset: the frontier region (1390-1440 B × 600-700 Kcyc) where the
# 1427→1397 sweep is otherwise too cramped to read.
# ----------------------------------------------------------------------
axins = inset_axes(ax, width="38%", height="28%", loc='lower right',
                   bbox_to_anchor=(0, 0.04, 0.98, 1),
                   bbox_transform=ax.transAxes)

# Only the sub-900Kcyc points
ZOOM = [(b, c, l) for b, c, l in FAST if c < 900 and b < 1440]
zx = [p[0] for p in ZOOM]
zy = [p[1] for p in ZOOM]
axins.plot(zx, zy, ':', color='#aaaaaa', linewidth=0.8, zorder=2)
axins.scatter(zx, zy, c='#3b5998', s=35, edgecolors='#1a2d5c', linewidths=0.8, zorder=3)
axins.plot(px, py, '-', color='#c41e3a', linewidth=2.5, zorder=4)
axins.scatter(px, py, c='#c41e3a', s=100, marker='D',
              edgecolors='#7a1225', linewidths=1.2, zorder=5)

# Inset labels: the two frontier points + session start/end
INSET_ANN = [
    (1427, 629, "Shamir\n1427B", (6, -4)),
    (1418, 654, "mov cl,N\n1418B", (4, 10)),
    (1397, 652, "1397B\ncurrent", (-52, -4)),
    (1405, 888, "1405B\n(dominated)", (4, -18)),
]
for b, c, txt, (dx, dy) in INSET_ANN:
    axins.annotate(txt, (b, c), textcoords="offset points", xytext=(dx, dy),
                   fontsize=8, bbox=dict(boxstyle='round,pad=0.25',
                   fc='#fffacd', ec='gray', lw=0.4))

axins.set_xlim(1390, 1435)
axins.set_ylim(615, 900)
axins.grid(True, alpha=0.2)
axins.set_axisbelow(True)
axins.tick_params(labelsize=8)
axins.set_title('frontier detail', fontsize=9)

# Shade the inset region on the main axes
ax.indicate_inset_zoom(axins, edgecolor="#888", alpha=0.4)

plt.savefig('docs/progress.png', dpi=100, bbox_inches='tight')
print(f"wrote docs/progress.png")
print(f"Pareto frontier: {[(ALL_PTS[i][0], ALL_PTS[i][1]) for i in FRONT]}")
