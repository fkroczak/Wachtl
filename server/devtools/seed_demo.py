"""Demodaten für UI-Tests (axe, Lighthouse, Playwright) und lokale Entwicklung.

Voraussetzung: laufender Collector (flask --app wachtl run) mit Fake-VictoriaMetrics, gleiche
WACHTL_*-Umgebung wie der Server, initialisierte Datenbank (flask --app wachtl init).

python devtools/seed_demo.py http://127.0.0.1:5000 [ids.json]

Legt zwei Standorte, zwei simulierte Probes mit Ping-Daten, einen Pfad- und einen WAN-Check samt
Ergebnissen sowie aktive und beendete Alarme an. Idempotent ist es nicht – für eine frische DB gedacht.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wachtl import checktypes, create_app, repo  # noqa: E402
from wachtl.db import ins  # noqa: E402
from wachtl.security import hash_token  # noqa: E402
from wachtl.services import alerts  # noqa: E402

TOKEN = "wachtl-demo-seed-token"


def main(base: str) -> dict:
    random.seed(7)
    app = create_app()
    with app.app_context():
        now = repo.now()
        site = ins("INSERT INTO sites (name, customer_no, description, created_at) VALUES (?, ?, ?, ?)",
                   ("Zentrale München", "K-1001", "Hauptsitz, 2 Etagen", now))
        ins("INSERT INTO sites (name, customer_no, description, created_at) VALUES (?, ?, ?, ?)",
            ("Filiale Augsburg", "K-1002", "", now))
        ins("INSERT INTO enrollment_tokens (site_id, token_hash, expires_at, max_uses, uses, revoked, created_at) "
            "VALUES (?, ?, ?, 5, 0, FALSE, ?)", (site, hash_token(TOKEN), now + 86400, now))

    # Ping-Daten über die echte Probe-API (Enrollment, Config, Ingest, Heartbeat)
    subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "simulate_probes.py"), base, TOKEN, "1"],
                   check=True)

    with app.app_context():
        now = repo.now()
        path = repo.create_check("Pfad zu Cloudflare", "1.1.1.1", "target", 1, 1000, "all", None, "path",
                                 checktypes.merged("path", {}))
        wan = repo.create_check("Internet-Speedtest", "", "target", 1, 1000, "all", None, "speedtest",
                                checktypes.merged("speedtest", {}))
        hops = [{"hop": 1, "ip": "192.168.1.1"}, {"hop": 2, "ip": "10.10.0.1"}, {"hop": 3, "ip": None},
                {"hop": 4, "ip": "1.1.1.1"}]
        path_hash = hashlib.sha256(json.dumps([[h["hop"], h["ip"]] for h in hops]).encode()).hexdigest()[:16]
        for probe_id in (1, 2):
            ins("INSERT INTO path_runs (probe_id, check_id, first_ts, ts, reason, reached, hops, path_hash, changed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (probe_id, path, now - 7200, now - 60, "schedule", True, json.dumps(hops), path_hash, False))
            for i in range(12):
                for direction, base_mbps in (("down", 240), ("up", 48)):
                    ins("INSERT INTO bandwidth_runs (probe_id, check_id, ts, kind, direction, peer, protocol, mbps, "
                        "jitter_ms, loss_pct, retransmits, latency_ms, duration_s, trigger, error) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (probe_id, wan, now - 7200 * i, "speedtest", direction, "speed.example", "http",
                         base_mbps + random.gauss(0, 10), None, None, 0, 12.0, 10, "schedule", None))

        def iso(t: int) -> str:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

        alerts.store_webhook({"alerts": [
            {"status": "firing", "fingerprint": "demo-1", "startsAt": iso(now - 900),
             "labels": {"alertname": "WachtlPacketLoss", "severity": "warning", "probe": "2", "cause": "wan"},
             "annotations": {"summary": "Paketverlust 6 % zu Google DNS (SRV-DC01)"}},
            {"status": "firing", "fingerprint": "demo-2", "startsAt": iso(now - 300),
             "labels": {"alertname": "WachtlTargetDown", "severity": "critical", "probe": "1"},
             "annotations": {"summary": "Cloudflare DNS nicht erreichbar (PC-EMPFANG)"}},
            {"status": "resolved", "fingerprint": "demo-3", "startsAt": iso(now - 86400), "endsAt": iso(now - 80000),
             "labels": {"alertname": "WachtlProbeOffline", "severity": "critical", "probe": "1"},
             "annotations": {"summary": "Probe PC-EMPFANG offline"}},
        ]})
    print(f"Demodaten angelegt: Pfad-Check {path}, WAN-Check {wan}")
    return {"probe": 1, "site": site, "ping_check": 2, "path_check": path, "wan_check": wan}


if __name__ == "__main__":
    ids = main(sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5000")
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w", encoding="utf-8") as fh:
            json.dump(ids, fh)
