# 🔬 NetSentry — Encrypted C2 Detection Research

This folder contains the experiment harness behind the NetSentry research claim:
**encrypted command-and-control (C2) beaconing can be detected without decryption
by combining payload entropy with inter-arrival timing regularity, validated
against real labeled captures.**

## The hypothesis

Signature-based IDS (Snort, Suricata) cannot inspect encrypted payloads, so they
miss encrypted C2. But a C2 implant has a tell: it *beacons* — calling home on a
near-regular interval. Two measurable signals together identify it:

1. **High payload entropy** (≈ 7.5–8.0 bits) — the traffic is encrypted/compressed
2. **Regular inter-arrival timing** (low coefficient of variation) — the beacon cadence

Benign encrypted browsing has signal 1 but not signal 2 (it's bursty). Plaintext
polling has signal 2 but not signal 1. Only C2 has both.

## Method

```
per flow (5-tuple):
  payloads → Shannon entropy per packet → mean entropy
  timestamps → inter-arrival times → regularity = 1 − (std/mean)
  entropy series → db4 wavelet (4-level) → detail-band energy
  verdict: C2 if (mean_entropy ≥ 6.5) AND (IAT regularity ≥ 0.55)
```

The db4 discrete wavelet transform (`wavedec(H, 4, "db4")`) decomposes the
per-flow entropy series; its detail coefficients expose non-stationary structure
that a plain FFT misses.

## Files

| File | Purpose |
|---|---|
| `c2_detect.py` | Core: entropy, db4 wavelet, IAT regularity, flow classifier |
| `selftest.py`  | Synthetic labeled flows → validates the algorithm (no pcap needed) |
| `run_pcap.py`  | Runs detection on real pcaps, reports metrics vs ground truth |
| `plot_c2.py`   | Renders the beacon-vs-benign comparison figure |

## Step 1 — Validate the algorithm (no data needed)

```bash
pip install -r requirements.txt
python selftest.py
```

Generates 55 synthetic labeled flows (C2 beacons + benign TLS + plaintext HTTP +
periodic-plaintext distractor) and confirms the detector separates them. Expect
100% detection / 0% false-positive on the synthetic set — this proves the logic,
not real-world performance.

## Step 2 — Get real labeled data

Download from the [Stratosphere IPS dataset](https://www.stratosphereips.org/datasets-overview):

- **Malware captures** contain real C2 beacons (Cobalt Strike, Emotet, Trickbot, …) → label `c2`
- **Normal captures** are benign background traffic → label `benign`

Also usable: [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html).

## Step 3 — Run on real pcaps

```bash
# Malware-only capture — every flow is C2
python run_pcap.py --pcap malware-capture.pcap --label c2

# Clean capture — every flow is benign
python run_pcap.py --pcap normal-capture.pcap --label benign

# Both at once for combined metrics
python run_pcap.py --pcap malware.pcap --pcap normal.pcap \
                   --truth ground_truth.json
```

Writes `results/c2_detection.json` with detection rate, false-positive rate,
precision, and F1 against the ground-truth labels.

## Step 4 — Compare against Snort

Run the same pcaps through Snort 3 with the community ruleset:

```bash
snort -c /etc/snort/snort.lua -r malware-capture.pcap -A alert_fast
```

Count how many C2 flows Snort flagged vs how many NetSentry's entropy+timing
method caught. The headline result is the *difference* — encrypted beacons Snort
misses that NetSentry catches.

## Step 5 — Render the figure

```bash
python plot_c2.py     # → ../docs/c2-detection.png
```

## Honest notes

- The synthetic self-test proves the *algorithm* is sound. Real-world numbers
  come only from Step 3 on real captures — run it before quoting any figure.
- Thresholds (`ENTROPY_C2_MIN`, `REGULARITY_MIN`) are tunable in `c2_detect.py`
  and should be calibrated on a validation split, then reported on a held-out test set.
- Flow reassembly here is per 5-tuple over the whole capture; production systems
  also handle flow timeouts and TCP stream reassembly.
