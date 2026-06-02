#!/usr/bin/env python3
"""
NetSentry — Run C2 detection on real pcap captures.

Reads one or more pcap files, reassembles flows by 5-tuple, runs the
entropy + wavelet + IAT-regularity pipeline, and reports per-flow verdicts
plus aggregate detection metrics. Optionally writes plots.

USAGE
  pip install scapy numpy scipy matplotlib pywavelets
  python research/run_pcap.py --pcap malware.pcap --label c2
  python research/run_pcap.py --pcap normal.pcap  --label benign
  # combine multiple, with a JSON ground-truth map for mixed captures:
  python research/run_pcap.py --pcap mixed.pcap --truth truth.json

GROUND TRUTH
  --label c2     : treat every flow in this pcap as C2 (malware-only capture)
  --label benign : treat every flow as benign (clean capture)
  --truth f.json : {"src_ip:dst_ip:sport:dport:proto": "c2"|"benign", ...}

DATASETS
  Stratosphere IPS: https://www.stratosphereips.org/datasets-overview
    - "malware captures" contain real C2 beacons → --label c2
    - "normal captures" are benign background  → --label benign
  CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
"""
import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c2_detect import Flow, classify_flow


def read_pcap_flows(path: str):
    """Parse a pcap into {5-tuple: Flow}. Uses scapy."""
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Raw
    except ImportError:
        sys.exit("scapy required:  pip install scapy")

    flows = {}
    n = 0
    with PcapReader(path) as pr:
        for pkt in pr:
            n += 1
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue
            l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            if l4 is None:
                continue
            proto = 6 if pkt.haslayer(TCP) else 17
            key = (str(ip.src), str(ip.dst), int(l4.sport), int(l4.dport), proto)
            payload = bytes(l4.payload) if l4.payload else b""
            ts = float(pkt.time)
            if key not in flows:
                flows[key] = Flow(key=key)
            flows[key].add(payload, ts)
    print(f"  parsed {n} packets → {len(flows)} flows from {os.path.basename(path)}")
    return flows


def key_str(key) -> str:
    return ":".join(str(x) for x in key)


def main():
    ap = argparse.ArgumentParser(description="NetSentry C2 detection on pcap")
    ap.add_argument("--pcap", required=True, action="append",
                    help="pcap file (repeatable)")
    ap.add_argument("--label", choices=["c2", "benign"], default=None,
                    help="ground-truth label for ALL flows in the pcap(s)")
    ap.add_argument("--truth", default=None,
                    help="JSON file mapping flow-key → 'c2'|'benign'")
    ap.add_argument("--out", default="research/results",
                    help="output directory for JSON + plots")
    ap.add_argument("--min-packets", type=int, default=8)
    args = ap.parse_args()

    truth = {}
    if args.truth:
        with open(args.truth) as f:
            truth = json.load(f)

    # Parse all pcaps into one flow table
    all_flows = {}
    for p in args.pcap:
        for k, fl in read_pcap_flows(p).items():
            if k in all_flows:
                all_flows[k].entropies += fl.entropies
                all_flows[k].times += fl.times
                all_flows[k].total_bytes += fl.total_bytes
            else:
                all_flows[k] = fl

    # Classify
    verdicts = []
    tp = fp = tn = fn = 0
    evaluated = 0
    for key, flow in all_flows.items():
        if flow.n_packets < args.min_packets:
            continue
        v = classify_flow(flow)
        verdicts.append(v)

        gt = truth.get(key_str(key), args.label)
        if gt is None:
            continue                       # no ground truth → skip metrics
        evaluated += 1
        actual_c2 = (gt == "c2")
        if actual_c2 and v.is_c2:      tp += 1
        elif actual_c2 and not v.is_c2: fn += 1
        elif not actual_c2 and v.is_c2: fp += 1
        else:                           tn += 1

    # Report per-flow
    print("\nPer-flow verdicts (flows with >= {} packets):".format(args.min_packets))
    print("-" * 92)
    print(f"{'flow':42} {'pkts':>5} {'H(X)':>6} {'reg':>5} {'verdict':>10}  reason")
    for v in sorted(verdicts, key=lambda x: not x.is_c2):
        print(f"{key_str(v.key):42} {v.n_packets:>5} {v.mean_entropy:>6.2f} "
              f"{v.iat_regularity:>5.2f} {'C2_BEACON' if v.is_c2 else 'benign':>10}  {v.reason}")

    # Aggregate metrics (only if ground truth available)
    if evaluated:
        n_c2 = tp + fn
        n_benign = tn + fp
        det = tp / n_c2 if n_c2 else 0
        fpr = fp / n_benign if n_benign else 0
        prec = tp / (tp + fp) if (tp + fp) else 0
        f1 = 2 * prec * det / (prec + det) if (prec + det) else 0
        print("\n" + "=" * 50)
        print("AGGREGATE METRICS")
        print(f"  Flows evaluated    : {evaluated}")
        print(f"  C2 / benign        : {n_c2} / {n_benign}")
        print(f"  Detection rate     : {det*100:.1f}%  ({tp}/{n_c2})")
        print(f"  False-positive rate: {fpr*100:.1f}%  ({fp}/{n_benign})")
        print(f"  Precision          : {prec*100:.1f}%")
        print(f"  F1 score           : {f1*100:.1f}%")
        print("=" * 50)

        os.makedirs(args.out, exist_ok=True)
        summary = {
            "flows_evaluated": evaluated, "c2": n_c2, "benign": n_benign,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "detection_rate": round(det * 100, 1),
            "false_positive_rate": round(fpr * 100, 1),
            "precision": round(prec * 100, 1),
            "f1": round(f1 * 100, 1),
        }
        with open(os.path.join(args.out, "c2_detection.json"), "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\nSaved {args.out}/c2_detection.json")
    else:
        print("\n(no ground-truth labels supplied — verdicts only, no metrics)")
        print("Re-run with --label c2  or  --label benign  or  --truth truth.json")


if __name__ == "__main__":
    main()
