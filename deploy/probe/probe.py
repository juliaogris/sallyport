#!/usr/bin/env python3
"""Probe the three sallyport clusters once and append one CSV row per cluster.

Every request goes to the public app hosts, so it crosses Cloudflare, the
hub and the tunnel to the app service. The probe sends the hub's app
cookies, __Host-sp_app (the session ID) and __Host-sp_subject (the bearer
token), from the sessions renew.sh writes.

The checks that move data run one cluster at a time, in an order that
rotates each minute, so that no cluster always goes first. Then all MJPEG
streams are read at the same time for STREAM_SECONDS.

Rows go to ~/sallyport-probe/data/YYYY-MM-DD.csv, in UTC.

    probe.py
"""

import csv
import datetime
import http.client
import os
import socket
import ssl
import statistics
import sys
import threading
import time

BASE = os.path.expanduser("~/sallyport-probe")
DOMAIN = "example.com"
CLUSTERS = {
    "julia": {"streams": ["octocam"]},
    "rust": {"streams": ["octocam"]},
    "go": {"streams": ["octocam"]},
    # The lazy hub sleeps while nobody uses it, so it is probed only every
    # 5 minutes, and its cluster has no octo app.
    "lazy": {"streams": ["octocam"], "every": 5, "octo": False},
    # The free-plan test on example.net, in a separate Cloudflare account.
    "party": {"streams": ["octocam"], "every": 5, "octo": False, "domain": "example.net", "owner": "julia"},
}
BENCH_FILE = "/10mb.bin"
BENCH_BYTES = 10 * 1024 * 1024
LATENCY_REQUESTS = 5
STREAM_SECONDS = 20
GAP_SECONDS = 2.0
TIMEOUT = 15
CHUNK = 64 * 1024

# The cam columns are always empty. They keep the header of older CSV files.
FIELDS = [
    "ts", "cluster", "tunnel_down",
    "dl_status", "dl_bytes", "dl_ttfb_s", "dl_total_s",
    "lat_ok", "lat_p50_ms", "lat_max_ms",
    "snap_status", "snap_s",
    "cam_status", "cam_frames", "cam_gaps", "cam_max_gap_s",
    "octocam_status", "octocam_frames", "octocam_gaps", "octocam_max_gap_s",
    "octo_status", "octo_s",
    "error",
]

CTX = ssl.create_default_context()


def host(cluster, app):
    c = CLUSTERS[cluster]
    return f"{app}-{c.get('owner', cluster)}.{c.get('domain', DOMAIN)}"


def cookie(cluster, app):
    """Returns the Cookie header for the probe user's session for app."""
    d = os.path.join(BASE, "secrets", cluster, "sessions", app)
    with open(os.path.join(d, "session-id")) as f:
        sid = f.read().strip()
    with open(os.path.join(d, "bearer-token")) as f:
        subject = f.read().strip()
    return f"__Host-sp_app={sid}; __Host-sp_subject={subject}"


def connect(cluster, app):
    return http.client.HTTPSConnection(host(cluster, app), 443, timeout=TIMEOUT, context=CTX)


def get(cluster, app, path):
    """Returns (status, body bytes, seconds to first byte, total seconds)."""
    conn = connect(cluster, app)
    try:
        start = time.monotonic()
        conn.request("GET", path, headers={"Cookie": cookie(cluster, app), "User-Agent": "sallyport-probe"})
        res = conn.getresponse()
        ttfb = time.monotonic() - start
        n = 0
        while chunk := res.read(CHUNK):
            n += len(chunk)
        return res.status, n, ttfb, time.monotonic() - start
    finally:
        conn.close()


def download(cluster, row, errors):
    try:
        status, n, ttfb, total = get(cluster, "bench", BENCH_FILE)
        row.update(dl_status=status, dl_bytes=n, dl_ttfb_s=f"{ttfb:.3f}", dl_total_s=f"{total:.3f}")
    except Exception as e:
        row["dl_status"] = 0
        errors.append(f"dl: {e!r}")


def latency(cluster, row, errors):
    """Sends small requests on one kept-alive connection and times each."""
    times = []
    statuses = []
    conn = connect(cluster, "bench")
    try:
        for _ in range(LATENCY_REQUESTS):
            try:
                start = time.monotonic()
                conn.request("GET", "/", headers={"Cookie": cookie(cluster, "bench"), "User-Agent": "sallyport-probe"})
                res = conn.getresponse()
                body = res.read()
                elapsed = time.monotonic() - start
                statuses.append(res.status)
                if res.status == 200:
                    times.append(elapsed)
                elif res.status == 503 and b"offline" in body:
                    row["tunnel_down"] = 1
            except Exception as e:
                statuses.append(0)
                errors.append(f"lat: {e!r}")
                conn.close()
                conn = connect(cluster, "bench")
    finally:
        conn.close()
    row["lat_ok"] = len(times)
    if times:
        row["lat_p50_ms"] = f"{statistics.median(times) * 1000:.1f}"
        row["lat_max_ms"] = f"{max(times) * 1000:.1f}"
    if not times and row["tunnel_down"] == 0 and all(s in (0, 502, 503, 504) for s in statuses):
        row["tunnel_down"] = 1


def snapshot(cluster, row, errors):
    try:
        status, _, _, total = get(cluster, "octocam", "/snapshot")
        row.update(snap_status=status, snap_s=f"{total:.3f}")
    except Exception as e:
        row["snap_status"] = 0
        errors.append(f"snap: {e!r}")


def octo(cluster, row, errors):
    try:
        status, _, _, total = get(cluster, "octo", "/api/version")
        row.update(octo_status=status, octo_s=f"{total:.3f}")
    except Exception as e:
        row["octo_status"] = 0
        errors.append(f"octo: {e!r}")


def stream(cluster, app, row, errors):
    """Reads app's /stream for STREAM_SECONDS and counts frames and gaps.

    A gap is more than GAP_SECONDS between frames, or between the start and
    the first frame, or between the last frame and the end.
    """
    prefix = app
    frames = 0
    gaps = 0
    max_gap = 0.0
    conn = connect(cluster, app)
    start = time.monotonic()
    last = start
    try:
        conn.request("GET", "/stream", headers={"Cookie": cookie(cluster, app), "User-Agent": "sallyport-probe"})
        res = conn.getresponse()
        row[f"{prefix}_status"] = res.status
        if res.status != 200:
            return
        ctype = res.getheader("Content-Type", "")
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"') if "boundary=" in ctype else ""
        marker = ("--" + boundary.removeprefix("--")).encode() if boundary else b"\xff\xd8\xff"
        conn.sock.settimeout(GAP_SECONDS / 2)
        tail = b""
        end = start + STREAM_SECONDS
        while (now := time.monotonic()) < end:
            try:
                chunk = res.read1(CHUNK)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                errors.append(f"{prefix}: stream ended")
                break
            now = time.monotonic()
            data = tail + chunk
            n = data.count(marker)
            if n:
                gap = now - last
                if gap > GAP_SECONDS:
                    gaps += 1
                max_gap = max(max_gap, gap)
                last = now
                frames += n
            tail = data[-(len(marker) - 1):]
    except Exception as e:
        if row[f"{prefix}_status"] == "":
            row[f"{prefix}_status"] = 0
        errors.append(f"{prefix}: {e!r}")
    finally:
        conn.close()
    gap = time.monotonic() - last
    if gap > GAP_SECONDS:
        gaps += 1
    max_gap = max(max_gap, gap)
    row.update({f"{prefix}_frames": frames, f"{prefix}_gaps": gaps, f"{prefix}_max_gap_s": f"{max_gap:.2f}"})


def main():
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    ts = now.isoformat().replace("+00:00", "Z")
    names = [c for c in CLUSTERS if now.minute % CLUSTERS[c].get("every", 1) == 0]
    shift = now.minute % len(names)
    names = names[shift:] + names[:shift]

    rows = {c: {f: "" for f in FIELDS} for c in names}
    errors = {c: [] for c in names}
    for c in names:
        rows[c].update(ts=ts, cluster=c, tunnel_down=0)
        latency(c, rows[c], errors[c])
        download(c, rows[c], errors[c])
        snapshot(c, rows[c], errors[c])
        if CLUSTERS[c].get("octo", True):
            octo(c, rows[c], errors[c])

    threads = [
        threading.Thread(target=stream, args=(c, app, rows[c], errors[c]))
        for c in names
        for app in CLUSTERS[c]["streams"]
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    path = os.path.join(BASE, "data", now.strftime("%Y-%m-%d") + ".csv")
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for c in names:
            rows[c]["error"] = "; ".join(errors[c])[:500]
            w.writerow(rows[c])
            print(",".join(str(rows[c][k]) for k in FIELDS), file=sys.stderr)


if __name__ == "__main__":
    main()
