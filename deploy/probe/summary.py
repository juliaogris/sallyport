#!/usr/bin/env python3
"""Print a per-cluster summary of the probe CSVs for the last N hours.

For each cluster: runs, success rate per check, p50 and p95 of each
timing, stream frame gaps, and minutes with the tunnel down. A minute
counts as tunnel down when the app service answered "offline" or no bench
request got through.

    summary.py [hours]    (default 24)
"""

import csv
import datetime
import glob
import math
import os
import sys

BASE = os.path.expanduser("~/sallyport-probe")
ORDER = ["julia", "rust", "go"]
MB10 = str(10 * 1024 * 1024)

CHECKS = {
    "download": lambda r: r["dl_status"] == "200" and r["dl_bytes"] == MB10,
    "latency": lambda r: r["lat_ok"] == "5",
    "snapshot": lambda r: r["snap_status"] == "200",
    "octo": lambda r: r["octo_status"] == "403",
    "cam": lambda r: r["cam_status"] == "200" and r["cam_gaps"] == "0",
    "octocam": lambda r: r["octocam_status"] == "200" and r["octocam_gaps"] == "0",
}
# Each timing counts only in runs where its check passed, so fast error
# answers do not pull the percentiles down.
TIMINGS = [
    ("dl_ttfb_s", "download ttfb s", "download"),
    ("dl_total_s", "download 10 MB s", "download"),
    ("lat_p50_ms", "small p50 ms", "latency"),
    ("lat_max_ms", "small max ms", "latency"),
    ("snap_s", "snapshot s", "snapshot"),
    ("octo_s", "octo s", "octo"),
]


def pct(values, p):
    """Returns the p-th percentile of values by nearest rank."""
    v = sorted(values)
    k = max(0, min(len(v) - 1, math.ceil(p / 100 * len(v)) - 1))
    return v[k]


def load(since):
    rows = []
    for path in sorted(glob.glob(os.path.join(BASE, "data", "*.csv"))):
        day = os.path.basename(path)[:10]
        if day < since.strftime("%Y-%m-%d"):
            continue
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                ts = datetime.datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
                if ts >= since:
                    rows.append(r)
    return rows


def main():
    hours = float(sys.argv[1]) if len(sys.argv) > 1 else 24
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    rows = load(since)
    print(f"last {hours:g} h, since {since:%Y-%m-%d %H:%M} UTC")
    clusters = [c for c in ORDER if any(r["cluster"] == c for r in rows)]
    for c in clusters:
        rs = [r for r in rows if r["cluster"] == c]
        print(f"\n{c}: {len(rs)} runs, tunnel down {sum(r['tunnel_down'] == '1' for r in rs)} min")
        parts = []
        for name, ok in CHECKS.items():
            key = {"download": "dl_status", "latency": "lat_ok", "snapshot": "snap_status"}.get(name, f"{name}_status")
            applicable = [r for r in rs if r[key] != ""]
            if applicable:
                n = sum(ok(r) for r in applicable)
                parts.append(f"{name} {100 * n / len(applicable):.1f}%")
        print("  ok:     " + ", ".join(parts))
        for key, label, check in TIMINGS:
            vals = [float(r[key]) for r in rs if r[key] != "" and CHECKS[check](r)]
            if vals:
                print(f"  {label:17} p50 {pct(vals, 50):8.3f}  p95 {pct(vals, 95):8.3f}  n {len(vals)}")
        for s in ("cam", "octocam"):
            vals = [r for r in rs if r[f"{s}_gaps"] != ""]
            if vals:
                gaps = sum(int(r[f"{s}_gaps"]) for r in vals)
                frames = [int(r[f"{s}_frames"]) for r in vals]
                worst = max(float(r[f"{s}_max_gap_s"]) for r in vals)
                print(f"  {s:8} stream gaps {gaps}, frames per 20 s p50 {pct(frames, 50)}, worst gap {worst:.2f} s")


if __name__ == "__main__":
    main()
