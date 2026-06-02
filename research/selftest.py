#!/usr/bin/env python3
"""
Self-test: generate synthetic labeled flows (C2 beacons + benign) and confirm
the c2_detect pipeline separates them. This validates the ALGORITHM before
running on real pcaps. It is not a substitute for the real-data experiment —
it proves the detector logic is sound.
"""
import os, sys, random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c2_detect import Flow, classify_flow

rng = random.Random(1337)
np.random.seed(1337)


def encrypted_payload(n=200) -> bytes:
    """High-entropy bytes (simulates TLS/AES-wrapped C2)."""
    return bytes(np.random.randint(0, 256, n, dtype=np.uint8))


def plaintext_payload() -> bytes:
    """Low-entropy English-ish HTTP."""
    s = "GET /index.html HTTP/1.1 Host: example.com User-Agent: Mozilla "
    return (s * rng.randint(1, 3)).encode()


def make_c2_beacon(interval=30.0, jitter=0.1, n=40) -> Flow:
    """Encrypted payloads sent at a regular interval (+ small jitter) — the
    classic beacon: high entropy, strongly periodic call-home."""
    f = Flow(key=("10.0.0.5", "66.66.66.66", 50000, 443, 6))
    t = 0.0
    for _ in range(n):
        f.add(encrypted_payload(rng.randint(180, 220)), t)
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return f


def make_benign_tls(n=40) -> Flow:
    """Encrypted browsing: high entropy but BURSTY/aperiodic timing."""
    f = Flow(key=("10.0.0.7", "93.184.216.34", 51000, 443, 6))
    t = 0.0
    for _ in range(n):
        f.add(encrypted_payload(rng.randint(100, 1400)), t)
        t += rng.expovariate(1 / 2.0)   # bursty, memoryless gaps
    return f


def make_benign_http(n=40) -> Flow:
    """Plaintext HTTP, irregular timing."""
    f = Flow(key=("10.0.0.9", "10.1.1.1", 52000, 80, 6))
    t = 0.0
    for _ in range(n):
        f.add(plaintext_payload(), t)
        t += rng.uniform(0.2, 5.0)
    return f


def make_periodic_plaintext(n=40) -> Flow:
    """Periodic but plaintext (e.g. health-check polling) — should NOT be C2."""
    f = Flow(key=("10.0.0.11", "10.1.1.2", 53000, 80, 6))
    t = 0.0
    for _ in range(n):
        f.add(plaintext_payload(), t)
        t += 10.0
    return f


def main():
    print("Synthetic C2 detection self-test\n" + "=" * 50)

    cases = []
    for i in range(20):
        cases.append(("C2_BEACON", make_c2_beacon(interval=rng.choice([15, 30, 60]))))
    for i in range(20):
        cases.append(("BENIGN", make_benign_tls()))
    for i in range(10):
        cases.append(("BENIGN", make_benign_http()))
    for i in range(5):
        cases.append(("BENIGN", make_periodic_plaintext()))

    tp = fp = tn = fn = 0
    for label, flow in cases:
        v = classify_flow(flow)
        actual_c2 = (label == "C2_BEACON")
        if actual_c2 and v.is_c2:      tp += 1
        elif actual_c2 and not v.is_c2: fn += 1
        elif not actual_c2 and v.is_c2: fp += 1
        else:                           tn += 1

    n_c2 = tp + fn
    n_benign = tn + fp
    detection = tp / n_c2 if n_c2 else 0
    fpr = fp / n_benign if n_benign else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    f1 = 2 * precision * detection / (precision + detection) if (precision + detection) else 0

    print(f"  C2 flows           : {n_c2}")
    print(f"  Benign flows       : {n_benign}")
    print(f"  True positives     : {tp}")
    print(f"  False positives    : {fp}")
    print(f"  False negatives    : {fn}")
    print(f"  Detection rate     : {detection*100:.1f}%")
    print(f"  False-positive rate: {fpr*100:.1f}%")
    print(f"  Precision          : {precision*100:.1f}%")
    print(f"  F1 score           : {f1*100:.1f}%")
    print("=" * 50)

    ok = detection >= 0.85 and fpr <= 0.15
    print("RESULT:", "PASS — detector separates C2 from benign"
          if ok else "WEAK — thresholds need tuning")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
