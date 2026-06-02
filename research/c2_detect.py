#!/usr/bin/env python3
"""
NetSentry — Encrypted C2 Beacon Detection (research harness)

Implements the entropy + db4-wavelet pipeline described in the NetSentry
README, and runs it against real labeled pcaps (e.g. Stratosphere IPS).

Pipeline per flow (5-tuple):
  1. Collect payload bytes per packet → Shannon entropy per packet
  2. Build the per-flow entropy time-series (one sample per packet)
  3. Also build the inter-arrival-time (IAT) series — beacons are periodic
  4. db4 discrete wavelet decomposition (4 levels) on the entropy series
  5. Periodicity test on detail coefficients + IAT autocorrelation
  6. Verdict: C2_BEACON if (high mean entropy) AND (strong periodicity)

This module is import-safe and has no side effects; the runner script drives it.
"""
from __future__ import annotations
import math
import statistics
from dataclasses import dataclass, field
from typing import Optional

import numpy as np


# ─────────────────────────────────────────────────────────────────────────────
#  Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy(data: bytes) -> float:
    """H(X) = -Σ p(x) log2 p(x) over byte values. Range 0..8 bits."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


# ─────────────────────────────────────────────────────────────────────────────
#  db4 wavelet decomposition
#  Uses PyWavelets if available (the shipped path); falls back to a pure-numpy
#  Daubechies-4 single-level transform so the harness runs even without pywt.
# ─────────────────────────────────────────────────────────────────────────────
_DB4_LO = np.array([
    0.48296291314469025, 0.83651630373746899,
    0.22414386804185735, -0.12940952255092145,
])
_DB4_HI = np.array([
    -0.12940952255092145, -0.22414386804185735,
    0.83651630373746899, -0.48296291314469025,
])


def _dwt_single(signal: np.ndarray):
    """One level of db4 DWT (periodic boundary). Returns (approx, detail)."""
    n = len(signal)
    if n < 2:
        return signal.copy(), np.zeros(0)
    if n % 2:                      # pad odd-length by symmetric extension
        signal = np.append(signal, signal[-1])
        n += 1
    ext = np.concatenate([signal, signal[:3]])   # periodic pad for 4-tap filter
    approx = np.zeros(n // 2)
    detail = np.zeros(n // 2)
    for i in range(n // 2):
        seg = ext[2 * i: 2 * i + 4]
        approx[i] = np.dot(seg, _DB4_LO)
        detail[i] = np.dot(seg, _DB4_HI)
    return approx, detail


def wavedec_db4(signal: np.ndarray, levels: int = 4):
    """4-level db4 decomposition. Returns list [cA_n, cD_n, ..., cD_1].
    Prefers PyWavelets (matches MATLAB wavedec); falls back to pure numpy."""
    try:
        import pywt
        return pywt.wavedec(signal, "db4", level=levels, mode="periodization")
    except Exception:
        coeffs = []
        a = np.asarray(signal, dtype=float)
        for _ in range(levels):
            if len(a) < 2:
                break
            a, d = _dwt_single(a)
            coeffs.append(d)
        coeffs.append(a)
        return [coeffs[-1]] + coeffs[-2::-1]


# ─────────────────────────────────────────────────────────────────────────────
#  Periodicity test — the core C2 discriminator
# ─────────────────────────────────────────────────────────────────────────────
def autocorr_periodicity(series: np.ndarray) -> float:
    """Return a 0..1 periodicity strength score via the dominant
    autocorrelation peak (excluding lag 0). Periodic beacons → high score."""
    x = np.asarray(series, dtype=float)
    if len(x) < 8:
        return 0.0
    x = x - x.mean()
    if np.allclose(x, 0):
        return 0.0
    ac = np.correlate(x, x, mode="full")[len(x) - 1:]
    ac = ac / ac[0]                      # normalize so lag0 = 1
    # search for the strongest peak at lag >= 2
    if len(ac) <= 2:
        return 0.0
    peak = float(np.max(ac[2: max(3, len(ac) // 2)]))
    return max(0.0, peak)


def iat_regularity(iat: np.ndarray) -> float:
    """Beacon timing is regular: low coefficient of variation (std/mean).
    Returns a 0..1 regularity score. Regular cadence → high score.
    This is the PRIMARY beacon discriminator — beacons call home on a
    fixed interval (+ jitter), while benign traffic is bursty/memoryless."""
    x = np.asarray(iat, dtype=float)
    x = x[x > 0]
    if len(x) < 6:
        return 0.0
    mean = x.mean()
    if mean <= 0:
        return 0.0
    cv = x.std() / mean                  # coefficient of variation
    # Beacon: cv near 0 (regular).  Bursty traffic: cv >= 1 (exponential).
    # Map cv → regularity score: cv=0 → 1.0, cv>=1 → ~0.
    return float(max(0.0, 1.0 - cv))


def wavelet_detail_energy(coeffs) -> float:
    """Fraction of signal energy in level-1/2 detail bands. Beaconing concentrates
    energy in the fine detail coefficients (the periodic call-home cadence)."""
    if len(coeffs) < 3:
        return 0.0
    # coeffs = [cA, cD_L, ..., cD_2, cD_1]; last two are finest detail
    fine = np.concatenate([np.abs(coeffs[-1]), np.abs(coeffs[-2])])
    total = np.concatenate([np.abs(c) for c in coeffs])
    e_fine = float(np.sum(fine ** 2))
    e_tot = float(np.sum(total ** 2))
    return e_fine / e_tot if e_tot > 0 else 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  Flow model
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Flow:
    key: tuple
    entropies: list = field(default_factory=list)   # per-packet payload entropy
    times: list = field(default_factory=list)       # per-packet timestamps
    total_bytes: int = 0

    def add(self, payload: bytes, ts: float):
        self.entropies.append(shannon_entropy(payload))
        self.times.append(ts)
        self.total_bytes += len(payload)

    @property
    def n_packets(self) -> int:
        return len(self.entropies)

    def iat(self) -> np.ndarray:
        """Inter-arrival times between packets."""
        if len(self.times) < 2:
            return np.zeros(0)
        return np.diff(np.array(sorted(self.times)))


# ─────────────────────────────────────────────────────────────────────────────
#  Verdict
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Verdict:
    key: tuple
    n_packets: int
    mean_entropy: float
    iat_regularity: float
    iat_periodicity: float
    detail_energy: float
    is_c2: bool
    reason: str


# Thresholds — tunable; documented in the methodology.
ENTROPY_C2_MIN   = 6.5    # encrypted/compressed payloads sit high
REGULARITY_MIN   = 0.55   # IAT regularity (1 - CV) for "beacon cadence"
MIN_PACKETS      = 8      # need enough samples to judge periodicity


def classify_flow(flow: Flow) -> Verdict:
    n = flow.n_packets
    if n < MIN_PACKETS:
        return Verdict(flow.key, n, 0, 0, 0, 0, False, "too_few_packets")

    ent = np.array(flow.entropies)
    mean_ent = float(ent.mean())

    coeffs = wavedec_db4(ent, levels=4)
    detail_e = wavelet_detail_energy(coeffs)

    iat = flow.iat()
    # Primary beacon signal: regular inter-arrival cadence (low CV).
    iat_reg = iat_regularity(iat)
    # Secondary: wavelet-detail periodicity of the IAT series itself.
    iat_period = autocorr_periodicity(iat) if len(iat) >= 8 else 0.0

    # Decision: encrypted (high entropy) AND regular beacon cadence.
    regular = iat_reg >= REGULARITY_MIN
    encrypted = mean_ent >= ENTROPY_C2_MIN
    is_c2 = encrypted and regular

    if is_c2:
        reason = f"encrypted(H={mean_ent:.2f}) + regular_cadence(r={iat_reg:.2f})"
    elif encrypted and not regular:
        reason = "encrypted_but_bursty (e.g. TLS browsing)"
    elif regular and not encrypted:
        reason = "regular_but_plaintext (e.g. health-check polling)"
    else:
        reason = "benign"

    return Verdict(flow.key, n, mean_ent, iat_reg, iat_period,
                   detail_e, is_c2, reason)
