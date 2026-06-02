#!/usr/bin/env python3
"""
NetSentry — Latency percentile chart generator.

Reads results/latency.json (produced by load_test.py) if present,
otherwise uses representative values. Renders a dark-theme chart matching
the dashboard aesthetic and saves to docs/latency-percentiles.png.

Usage:
    python benchmark/plot_latency.py
"""
import json
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results", "latency.json")
OUT = os.path.join(HERE, "..", "docs", "latency-percentiles.png")

# ── Load measured data if available, else representative values ────────────
# Load level = offered requests/sec. Latency values are microseconds (µs).
if os.path.exists(RESULTS):
    with open(RESULTS) as f:
        data = json.load(f)
    loads   = data["loads"]
    p50     = data["p50"]
    p95     = data["p95"]
    p99     = data["p99"]
    source  = "measured"
else:
    # Representative values — single-box, 4 worker threads, classify path.
    # Replace by running benchmark/load_test.py to emit results/latency.json.
    loads = [1000, 5000, 10000, 25000, 50000, 100000]
    p50   = [   8,    9,    11,    14,    22,     41]
    p95   = [  19,   23,    28,    37,    58,    121]
    p99   = [  34,   41,    52,    71,   118,    243]
    source = "representative"

x = np.arange(len(loads))

# ── Style ──────────────────────────────────────────────────────────────────
BG     = "#04060a"
PANEL  = "#0a0e17"
GRID   = "#141c2e"
TEXT   = "#8a9ab8"
TICK   = "#4a5a78"
CYAN   = "#00d4ff"
AMBER  = "#ff9500"
RED    = "#ff3860"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
})

fig, ax = plt.subplots(figsize=(11, 5.2), dpi=160)
fig.patch.set_facecolor(BG)
ax.set_facecolor(PANEL)

# Lines
ax.plot(x, p50, marker="o", color=CYAN,  linewidth=2.2, markersize=6,
        markerfacecolor=BG, markeredgecolor=CYAN, markeredgewidth=1.6, label="p50 (median)")
ax.plot(x, p95, marker="s", color=AMBER, linewidth=2.2, markersize=6,
        markerfacecolor=BG, markeredgecolor=AMBER, markeredgewidth=1.6, label="p95")
ax.plot(x, p99, marker="^", color=RED,   linewidth=2.2, markersize=7,
        markerfacecolor=BG, markeredgecolor=RED, markeredgewidth=1.6, label="p99 (tail)")

# Fill under p99 for visual weight
ax.fill_between(x, 0, p99, color=RED, alpha=0.04)
ax.fill_between(x, 0, p95, color=AMBER, alpha=0.05)
ax.fill_between(x, 0, p50, color=CYAN, alpha=0.06)

# Axes
ax.set_xticks(x)
ax.set_xticklabels([f"{l//1000}k" if l >= 1000 else str(l) for l in loads])
ax.set_xlabel("Offered load  ·  requests / second", color=TEXT, fontsize=11, labelpad=10)
ax.set_ylabel("Classification latency  ·  microseconds (µs)", color=TEXT, fontsize=11, labelpad=10)

ax.set_title("NetSentry — Classification Latency vs Offered Load",
             color="#e8edf5", fontsize=14, fontweight="bold", pad=16, loc="left")

# SLO line at 100 µs
ax.axhline(100, color="#5a6a88", linewidth=1, linestyle=":", alpha=0.7)
ax.text(len(loads) - 1, 106, "100 µs SLO", color="#5a6a88", fontsize=9, ha="right")

# Grid + spines
ax.grid(True, color=GRID, linewidth=0.8, alpha=0.6)
for s in ax.spines.values():
    s.set_color(GRID)
ax.tick_params(colors=TICK, labelsize=10)

# Legend
leg = ax.legend(loc="upper left", frameon=True, facecolor=PANEL,
                edgecolor=GRID, labelcolor=TEXT, fontsize=10)

# Footer note
note = ("Single box · 4 worker threads · payload classify path"
        if source == "measured"
        else "Representative values — run benchmark/load_test.py to generate measured data")
fig.text(0.5, 0.01, note, ha="center", color=TICK, fontsize=8.5, style="italic")

fig.tight_layout(rect=[0, 0.03, 1, 1])
os.makedirs(os.path.dirname(OUT), exist_ok=True)
fig.savefig(OUT, facecolor=BG, bbox_inches="tight")
print(f"Saved {OUT} ({source} data)")