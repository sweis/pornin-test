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
    #   Cycle numbers below are 10-run medians.  (Earlier single-shot
    #   measurements showed a ~5% "regression" here — noise.  The move
    #   actually landed reduce's inner loop in a single DSB chunk.)
    (980,  3540, None),
    (960,  8120, None),
    (977,  3520, None),
    (957,  8060, None),
    # --- Unrolled push-zero: +3/+1 B for ~3%/2% cycles.  Kills an
    #   #ifdef; xor ecx does three jobs (zero for push, zero for
    #   mul8's mov cl,N, eax no longer needed).  960B dominates 969B.
    (978,  3450, None),
    (960,  7845, None),
    # --- mul8: drop `loop`, keep `scasd` (+4B, −39% cycles) ---
    #   `loop` was ~6.5M of SMALL_MUL8's 7.8M cycles on its own.
    #   964B fills the 960→977 gap; scasd is the real size knob now.
    (964,  4780, None),
    # --- bc_run inherit r14 (−7), Fadd commute+scratch=dst (−6),
    #   1-B terminators (−3), cP built at rbp−40 → fe_iszero inlines
    #   (−6), r8 for &cP caller-saved (−5), or→dec eax (−2).
    (957,  4520, None),
    (935,  4660, None),
    # --- EFD reschedule (hyperelliptic.org/EFD): hoist RCB steps 14,15
    #   so X1,Z1 die early → slot2 reusable as 6th temp → 5 scratch
    #   slots → slot8 free → cP@slot8 → .Lcadd [r8-96] disp8 (−2B)
    # --- -DFAST_ADVANCE: scasd→lea in SMALL_MUL8 (+6B, −10% cyc).
    #   Knocks 935B and 957B off the frontier.  Also add 947B default
    #   to TRAIL so the frontier shows all three current builds.
    (947,  3608, None),
    (939,  4265, "939B — lea advance"),
    (933,  4674, "933B — size corner"),
    # --- -DSOLINAS_P: per-window P-256 fold, no multiplies.
    #   t −= q·p  ≡  +q@0, −q@3, −q@6, +q@7, zero t[8].
    #   Same bits as mul8 (algebraically identical) so the ≤2-iter
    #   convergence holds unchanged.  mod-n stays generic.
    #   Unrolled: +58B → −15.5%.  Looped (+SOLINAS_LOOP): −6B back,
    #   +5% cyc (inc+jnz overhead).  Both Pareto.
    (999,  3118, None),
    (1005, 2965, "1005B — Solinas fold"),
    # --- tv_ecdsa_speed.S: one-shot FIPS Solinas (139 ops straight-line).
    #   Replaces 14+ sliding-window iterations with ONE branch-free pass.
    #   Branch misses 1.76M → 0.42M (−76%), IPC 1.40 → 2.68.  5p bias
    #   (all dwords fit imm8!) makes carry nonneg for the drain loop.
    #   MOVBE-only — BMI2 not needed.  The new MOVBE speed corner.
    (1567, 1349, None),
    # --- speed.S iterations: register-hoist hot dwords, unroll Fadd/Fsub,
    #   direct RCB (no bytecode dispatch).  All MOVBE-only.  Dominated on
    #   the global frontier by fast.S's BMI2 points (1338/945 beats all
    #   three), but own the MOVBE-only frontier past 1091B.
    (1482, 1305, None),
    (1718, 1191, None),
    (2647, 1092, "speed.S — MOVBE-only"),
    # --- tv_ecdsa_fast2.S: mulx+adcx/adox schoolbook + full-hoist
    #   one-shot Solinas + 10-entry carry correction table.  BMI2+ADX.
    #   Within 3% of fast.S — 3.7× fewer branch misses (62K vs 228K),
    #   but ~10M more instructions (Solinas is a separate pass).
    #   Normalized to chart's fast.S=629K: ~650K.  Between 1397 and 1427
    #   on the global frontier.
    (3201, 650, None),
    # --- LAZY-CARRY SOLINAS: break the 8-position serial carry chain.
    #   Phase 1: compute all 8 accumulators INDEPENDENTLY (each = A[pos]
    #   + Σ coeff·A[8+i], 64-bit signed).  Fully parallelizes at IPC~4.
    #   Phase 2: single 8-step carry propagation.  Old version had the
    #   carry threaded THROUGH the 139-op body (8× sar+mov serialized);
    #   now the dependency chain is ~8 ops not ~139.
    #   BEATS fast.S 50/50 head-to-head by ~9%.  New global speed corner.
    (3265, 570, "fast2.S — BEATS fast.S"),
]

# Thomas's track: v1–v7.
THOMAS_TRACK = [(1156, 3600), (1046, 3990), (1004, 3920), (996, 4100),
                (989, 4150), (955, 4325), (928, 4482)]
THOMAS    = (928, 4482)     # v7 — ON the frontier
CLAUDE    = (933, 4674)     # 20-run median; WAS size corner

# Thomas Stupid: bytecode-VM where even MUL is a bytecode subroutine
# (double-and-add, 256 iters/multiply). Native code is just the interpreter
# + 32-byte add/sub/copy. ~27× slower than limb8 but 124 B smaller.
THOMAS_STUPID = (766, 141524)

# All tracks — read from unified docs/progress.csv.
def read_unified(track_name):
    import csv
    out = []
    with open('docs/progress.csv') as f:
        for row in csv.reader(f):
            if not row or row[0].startswith('#') or row[0] == 'track':
                continue
            if row[0] != track_name:
                continue
            b, c = int(row[2]), int(row[3])
            if b > 500 and c > 0:   # skip pre-607 fe_mul-only rows
                out.append((b, c // 1000))
    return out

LIMB11_TRACK = read_unified('limb11x24')
LIMB5X54_TRACK = read_unified('limb5x54')
LIMB5X56_TRACK = read_unified('limb5x56')
LIMB8_TRACK  = read_unified('limb8')
STUPID_TRACK = read_unified('stupid')

# Join TRAIL + limb8 (limb8 IS the tiny.S continuation). Filter to self-
# Pareto: keep a point only if NO other point in the same sequence (past
# or future) dominates it. Drops the #ifdef back-and-forth and the
# superseded limb8 intermediates, keeps only enduring milestones.
# Chronological order preserved.
FULL_CHRON = [(b, c, lbl) for b, c, lbl in TRAIL] + \
             [(b, c, None) for b, c in LIMB8_TRACK]

def self_pareto_ordered(seq):
    pts = [(b, c) for b, c, _ in seq]
    shown = []
    for i, (b, c, lbl) in enumerate(seq):
        # Labeled points are architectural milestones — always shown.
        if lbl or not any(b2 <= b and c2 <= c and (b2 < b or c2 < c)
                          for j, (b2, c2) in enumerate(pts) if j != i):
            shown.append((b, c, lbl))
    return shown

TRAIL_SHOWN = self_pareto_ordered(FULL_CHRON)

def pareto(pts):
    front = []
    for i, (b, c) in enumerate(pts):
        if not any((b2 <= b and c2 <= c and (b2 < b or c2 < c))
                   for j, (b2, c2) in enumerate(pts) if j != i):
            front.append(i)
    front.sort(key=lambda i: pts[i][0])
    return front

ALL_XY = ([(b, c) for b, c, _ in TRAIL_SHOWN] + THOMAS_TRACK
          + LIMB11_TRACK + LIMB5X54_TRACK + LIMB5X56_TRACK
          + STUPID_TRACK + [THOMAS_STUPID])
FRONT = pareto(ALL_XY)

# ======================================================================
fig, ax = plt.subplots(figsize=(13, 8), dpi=100)

# bc.S baseline — faded gray
ax.plot(BC_TRACK, [BC_Y]*len(BC_TRACK), 'o-', color='#d0d0d0',
        markersize=4, linewidth=1, zorder=1, label='bc.S baseline (ratio 1.0)')

# Chronological trail (filtered, joined with limb8). Connector skips
# off-chart points (speed.S, fast2.S at >2000 B) so the line doesn't
# shoot off-right and back. Scatter still plots them (clipped by xlim).
XMAX = 2000
on_chart = [(b, c) for b, c, _ in TRAIL_SHOWN if b <= XMAX]
tx = [p[0] for p in on_chart]
ty = [p[1] for p in on_chart]
ax.plot(tx, ty, ':', color='#b0b0b0', linewidth=0.7, zorder=2,
        label='tiny.S → limb8 (8×32, non-Mont)')
ax.scatter(tx, ty, c='#4a6fa5', s=22, edgecolors='#2a4670',
           linewidths=0.5, zorder=3, alpha=0.7)
# Annotate the size floor (smallest byte count in the trail).
size_floor = min(on_chart, key=lambda p: p[0])
ax.annotate(f'{size_floor[0]}B', size_floor,
            textcoords="offset points", xytext=(-35, -12), fontsize=9,
            bbox=dict(boxstyle='round,pad=0.3', fc='#e0e8f5',
            ec='#4a6fa5', lw=0.8))

# Pareto frontier — thin line, small dots.  The frontier is dense on the
# left (many sub-1000B points separated by single bytes), so big diamonds
# just pile into a blob.  Small markers + thin line let the curve read.
# Clip off-chart points (fast2.S at 3265 B) so the line doesn't run off.
FRONT_ON = [i for i in FRONT if ALL_XY[i][0] <= XMAX]
px = [ALL_XY[i][0] for i in FRONT_ON]
py = [ALL_XY[i][1] for i in FRONT_ON]
ax.plot(px, py, '-', color='#c41e3a', linewidth=1.5, zorder=4,
        label='Pareto frontier')
ax.scatter(px, py, c='#c41e3a', s=20, marker='o',
           edgecolors='none', zorder=5)

# Thomas track.  v7 (928B, 5×54) takes the size corner.
ttx = [p[0] for p in THOMAS_TRACK]
tty = [p[1] for p in THOMAS_TRACK]
ax.plot(ttx, tty, ':', color='#2e8b57', linewidth=1.2, zorder=4,
        label='Thomas')
ax.scatter(ttx, tty, c='#2e8b57', s=25, marker='o',
           edgecolors='#1a5235', linewidths=0.6, zorder=5)
ax.annotate(f'Thomas v7 — {THOMAS[0]}B', THOMAS,
            textcoords="offset points", xytext=(12, 6), fontsize=10,
            fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.35', fc='#d4f4dd',
            ec='#2e8b57', lw=1))

# limb11x24 (11×24 signed-limb Montgomery) — purple.  Slow (loop-heavy)
# but the trick-catalogue source.  Projective R-cancel at 1219B.
if LIMB11_TRACK:
    l11x = [p[0] for p in LIMB11_TRACK]
    l11y = [p[1] for p in LIMB11_TRACK]
    ax.plot(l11x, l11y, '-', color='#8a2be2', linewidth=1.2, zorder=4,
            label='limb11x24 (11×24)')
    ax.scatter(l11x, l11y, c='#8a2be2', s=40, marker='^',
               edgecolors='#5a1b99', linewidths=0.6, zorder=5)
    tip = LIMB11_TRACK[-1]
    ax.annotate(f'11×24 — {tip[0]}B', tip,
                textcoords="offset points", xytext=(10, 8), fontsize=9,
                bbox=dict(boxstyle='round,pad=0.3', fc='#e8d5ff',
                ec='#8a2be2', lw=0.8))

# limb5x54 (5×54 signed-limb Montgomery) — teal.
if LIMB5X54_TRACK:
    l5x = [p[0] for p in LIMB5X54_TRACK]
    l5y = [p[1] for p in LIMB5X54_TRACK]
    ax.plot(l5x, l5y, '-', color='#008b8b', linewidth=1.4, zorder=4,
            label='limb5x54 (5×54)')
    ax.scatter(l5x, l5y, c='#008b8b', s=50, marker='s',
               edgecolors='#005555', linewidths=0.7, zorder=5)
    tip = LIMB5X54_TRACK[-1]
    ax.annotate(f'5×54 — {tip[0]}B', tip,
                textcoords="offset points", xytext=(10, -12), fontsize=9,
                bbox=dict(boxstyle='round,pad=0.3', fc='#d0f0f0',
                ec='#008b8b', lw=0.8))

# limb5x56 (5×56 signed-limb Montgomery) — dark cyan. Byte-aligned decode.
if LIMB5X56_TRACK:
    l6x = [p[0] for p in LIMB5X56_TRACK]
    l6y = [p[1] for p in LIMB5X56_TRACK]
    ax.plot(l6x, l6y, '-', color='#006666', linewidth=1.4, zorder=4,
            label='limb5x56 (5×56)')
    ax.scatter(l6x, l6y, c='#006666', s=50, marker='^',
               edgecolors='#003333', linewidths=0.7, zorder=5)
    tip = LIMB5X56_TRACK[-1]
    ax.annotate(f'5×56 — {tip[0]}B', tip,
                textcoords="offset points", xytext=(10, 8), fontsize=9,
                bbox=dict(boxstyle='round,pad=0.3', fc='#c0e8e8',
                ec='#006666', lw=0.8))

# stupid (bytecode-VM, MUL-as-bytecode) — orange. Our iterations on top
# of Thomas's baseline.
if STUPID_TRACK:
    sx = [p[0] for p in STUPID_TRACK]
    sy = [p[1] for p in STUPID_TRACK]
    ax.plot(sx, sy, '-', color='#ff8c00', linewidth=1.4, zorder=4,
            label='stupid (bytecode-VM)')
    ax.scatter(sx, sy, c='#ff8c00', s=50, marker='D',
               edgecolors='#cc5500', linewidths=0.7, zorder=5)
    tip = min(STUPID_TRACK, key=lambda p: p[0])
    ax.annotate(f'stupid — {tip[0]}B', tip,
                textcoords="offset points", xytext=(10, -14), fontsize=9,
                bbox=dict(boxstyle='round,pad=0.3', fc='#ffe4b5',
                ec='#ff8c00', lw=0.8))

# Thomas Stupid baseline — labeled star. The new size corner.
ax.scatter([THOMAS_STUPID[0]], [THOMAS_STUPID[1]], c='#2e8b57', s=120,
           marker='*', edgecolors='#1a5235', linewidths=1.0, zorder=6)
ax.annotate(f'Thomas Stupid — {THOMAS_STUPID[0]}B', THOMAS_STUPID,
            textcoords="offset points", xytext=(12, 6), fontsize=10,
            fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.35', fc='#d4f4dd',
            ec='#2e8b57', lw=1))

ax.set_xlabel('Size (bytes)', fontsize=12)
ax.set_ylabel('Cycles (log scale)', fontsize=12)
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
ax.set_xlim(600, 2000)    # left edge tracks stupid size floor
ax.set_ylim(500, 4000000) # stupid SMC at ~2.6G cyc (pipeline stalls)
# Human-readable cycle labels. Internal y-values are thousands-of-cycles
# (csv cycles // 1000), so y=500 → 500K, y=1000 → 1M, y=1000000 → 1G.
from matplotlib.ticker import FuncFormatter, LogLocator
def fmt_cycles(y, pos):
    c = y * 1000  # back to actual cycles
    if c >= 1e9:
        v = c / 1e9
        return f'{v:g}G'
    if c >= 1e6:
        v = c / 1e6
        return f'{v:g}M'
    v = c / 1e3
    return f'{v:g}K'
ax.yaxis.set_major_locator(LogLocator(base=10, subs=[1, 2, 5]))
ax.yaxis.set_major_formatter(FuncFormatter(fmt_cycles))
ax.yaxis.set_minor_formatter(lambda x, pos: '')

plt.tight_layout()
plt.savefig('docs/progress.png', dpi=100, bbox_inches='tight')
print(f"wrote docs/progress.png")
print(f"Pareto frontier: {[(ALL_XY[i][0], ALL_XY[i][1]) for i in FRONT]}")
