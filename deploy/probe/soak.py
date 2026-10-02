#!/usr/bin/env python3
"""Put a steady parallel load on the free-plan clusters and log one CSV row
per cluster and run.

Each run starts PARALLEL downloads of the bench file at the same time, ROUNDS
times in a row, on each cluster in SOAK_CLUSTERS. A download counts as ok
when it returns 200 with the full length, and as short when it returns 200
with fewer bytes. The rust and go clusters are not soaked, because the 7-day
run compares them under the probe alone.

Rows go to ~/sallyport-probe/data/soak-YYYY-MM-DD.csv, in UTC.

    soak.py
"""

import csv
import datetime
import os
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe  # noqa: E402

SOAK_CLUSTERS = ["party-rust", "party-go"]
PARALLEL = 8
ROUNDS = 2
BENCH_FILE = "/1mb.bin"
BENCH_BYTES = 1_000_000

FIELDS = ["ts", "cluster", "n", "ok", "short", "failed", "p50_s", "max_s", "error"]


def one(cluster, results, errors, lock):
    try:
        status, n, _, total = probe.get(cluster, "bench", BENCH_FILE)
        with lock:
            results.append((status, n, total))
    except Exception as e:
        with lock:
            results.append((0, 0, 0.0))
            errors.append(repr(e))


def soak(cluster):
    results = []
    errors = []
    lock = threading.Lock()
    for _ in range(ROUNDS):
        threads = [threading.Thread(target=one, args=(cluster, results, errors, lock)) for _ in range(PARALLEL)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    ok = [r for r in results if r[0] == 200 and r[1] == BENCH_BYTES]
    short = [r for r in results if r[0] == 200 and r[1] != BENCH_BYTES]
    times = [r[2] for r in ok]
    statuses = sorted({str(r[0]) for r in results if r[0] != 200})
    if statuses:
        errors.insert(0, "status " + ",".join(statuses))
    return {
        "cluster": cluster,
        "n": len(results),
        "ok": len(ok),
        "short": len(short),
        "failed": len(results) - len(ok) - len(short),
        "p50_s": f"{statistics.median(times):.3f}" if times else "",
        "max_s": f"{max(times):.3f}" if times else "",
        "error": "; ".join(errors)[:500],
    }


def main():
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    ts = now.isoformat().replace("+00:00", "Z")
    rows = []
    for c in SOAK_CLUSTERS:
        row = soak(c)
        row["ts"] = ts
        rows.append(row)
        time.sleep(1)
    path = os.path.join(probe.BASE, "data", "soak-" + now.strftime("%Y-%m-%d") + ".csv")
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for row in rows:
            w.writerow(row)
            print(",".join(str(row[k]) for k in FIELDS), file=sys.stderr)


if __name__ == "__main__":
    main()
