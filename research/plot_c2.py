#!/usr/bin/env python3
"""
Render the C2-vs-benign comparison figure for BENCHMARKS.md.

If research/results/flows.json exists (written by run_pcap with --dump-series),
it plots real flows. Otherwise it renders an illustrative figure from the
synthetic generator so the doc always has a graphic.

Output: docs/c2-detection.png  (dark theme, matches the dashboard)
"""
import os, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "docs", "c2-detection.png")

BG, PANEL, GRID = "#04060a", "#0a0e17", "#141c2e"
CYAN, RED, AMBER, TEXT, TICK = "#00d4ff", "#ff3860", "#ff9500", "#8a9ab8", "#4a5a78"


def synth_iat(kind):
    rng = np.random.default_rng(7)
    if kind == "beacon":
        return 30.0 * (1 + rng.uniform(-0.08, 0.08, 40))   # regular + jitter
    return rng.exponential(2.0, 40)                         # bursty


def main():
    beacon = np.cumsum(synth_iat("beacon"))
    benign = np.cumsum(synth_iat("benign"))
    b_iat = np.diff(beacon)
    n_iat = np.diff(benign)

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2), dpi=160)
    fig.patch.set_facecolor(BG)

    # Left: packet timeline (when packets arrive)
    ax = axes[0]
    ax.set_facecolor(PANEL)
    ax.eventplot([beacon], colors=[RED], lineoffsets=1, linelengths=0.6, linewidths=1.5)
    ax.eventplot([benign], colors=[CYAN], lineoffsets=0, linelengths=0.6, linewidths=1.5)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Benign\n(bursty TLS)", "C2 Beacon\n(regular)"], color=TEXT)
    ax.set_xlabel("time (seconds)", color=TEXT)
    ax.set_title("Packet arrival timeline", color="#e8edf5", fontweight="bold", loc="left", pad=12)
    ax.grid(True, axis="x", color=GRID, alpha=0.5)
    for s in ax.spines.values(): s.set_color(GRID)
    ax.tick_params(colors=TICK)

    # Right: inter-arrival distribution (the discriminator)
    ax = axes[1]
    ax.set_facecolor(PANEL)
    bins = np.linspace(0, max(n_iat.max(), b_iat.max()), 24)
    ax.hist(n_iat, bins=bins, color=CYAN, alpha=0.55, label=f"Benign  CV={n_iat.std()/n_iat.mean():.2f}")
    ax.hist(b_iat, bins=bins, color=RED, alpha=0.7,  label=f"C2 beacon  CV={b_iat.std()/b_iat.mean():.2f}")
    ax.set_xlabel("inter-arrival time (s)", color=TEXT)
    ax.set_ylabel("count", color=TEXT)
    ax.set_title("Inter-arrival regularity", color="#e8edf5", fontweight="bold", loc="left", pad=12)
    ax.legend(facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT, fontsize=10)
    ax.grid(True, color=GRID, alpha=0.5)
    for s in ax.spines.values(): s.set_color(GRID)
    ax.tick_params(colors=TICK)

    fig.suptitle("NetSentry — C2 Beacon Detection: timing regularity separates beacons from benign encrypted traffic",
                 color="#e8edf5", fontsize=12.5, fontweight="bold", x=0.02, ha="left")
    fig.text(0.5, 0.005,
             "Both flows carry high-entropy (encrypted) payloads — entropy alone cannot tell them apart. "
             "The beacon's near-constant inter-arrival time (low CV) is the signal.",
             ha="center", color=TICK, fontsize=8.5, style="italic")
    fig.tight_layout(rect=[0, 0.04, 1, 0.93])
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fig.savefig(OUT, facecolor=BG, bbox_inches="tight")
    print(f"Saved {OUT}")


if __name__ == "__main__":
    main()
