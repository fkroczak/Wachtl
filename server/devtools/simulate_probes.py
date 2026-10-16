"""Simuliert zwei Probes gegen einen laufenden Collector (Entwicklung/Demo).

python devtools/simulate_probes.py http://127.0.0.1:5000 <enrollment-token> [stunden]
"""
from __future__ import annotations

import gzip
import math
import random
import sys
import time

import requests

BASE, TOKEN = sys.argv[1].rstrip("/"), sys.argv[2]
HOURS = float(sys.argv[3]) if len(sys.argv) > 3 else 2
PROFILE = {"gateway": (0.4, 0.15, 0.0), "8.8.8.8": (12.0, 1.5, 0.004), "1.1.1.1": (9.5, 1.2, 0.002)}


def enroll(hostname: str) -> str:
    r = requests.post(f"{BASE}/api/probe/v1/enroll", json={"enrollment_token": TOKEN, "hostname": hostname,
                                                           "os": "Windows 11 Pro", "version": "0.1.0"})
    r.raise_for_status()
    return r.json()["token"]


def run(hostname: str, extra_loss: float) -> None:
    token = enroll(hostname)
    auth = {"Authorization": f"Bearer {token}"}
    checks = requests.get(f"{BASE}/api/probe/v1/config", headers=auth).json()["checks"]
    now = int(time.time())
    lines = []
    for c in checks:
        base, noise, loss = PROFILE.get(c["target"], (25.0, 3.0, 0.01))
        last = None
        for i, t in enumerate(range(now - int(HOURS * 3600), now, c["interval_s"])):
            spike = 40 if (t // 600) % 9 == 0 and c["role"] != "gateway" else 0  # alle 90 min Lastspitze
            lost = random.random() < loss + (extra_loss if c["role"] != "gateway" and spike else 0)
            ts = t * 1000
            lines.append(f'wachtl_ping_up{{check_id="{c["id"]}"}} {0 if lost else 1} {ts}')
            if not lost:
                rtt = max(0.05, base + random.gauss(0, noise) + spike * random.random() + math.sin(t / 900))
                lines.append(f'wachtl_ping_rtt_ms{{check_id="{c["id"]}"}} {rtt:.3f} {ts}')
                lines.append(f'wachtl_ping_ttl{{check_id="{c["id"]}"}} 117 {ts}')
                if last is not None and i % 60 == 0:
                    lines.append(f'wachtl_ping_jitter_ms{{check_id="{c["id"]}"}} {abs(rtt - last):.3f} {ts}')
                last = rtt
    for i in range(0, len(lines), 5000):
        chunk = "\n".join(lines[i:i + 5000]).encode()
        r = requests.post(f"{BASE}/api/probe/v1/ingest", data=gzip.compress(chunk),
                          headers={**auth, "X-Batch-Id": f"sim-{i}", "Content-Encoding": "gzip"})
        r.raise_for_status()
    requests.post(f"{BASE}/api/probe/v1/heartbeat", json={"version": "0.1.0", "buffer_items": 0, "uptime_s": 7200},
                  headers=auth).raise_for_status()
    print(f"{hostname}: {len(lines)} Werte gesendet")


run("PC-EMPFANG", 0.0)
run("SRV-DC01", 0.05)
