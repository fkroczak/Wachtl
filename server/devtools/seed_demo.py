"""Demodaten für UI-Tests (axe, Lighthouse, Playwright) und lokale Entwicklung.

Voraussetzung: laufender Collector (flask --app wachtl run) mit Fake-VictoriaMetrics, gleiche
WACHTL_*-Umgebung wie der Server, initialisierte Datenbank (flask --app wachtl init).

python devtools/seed_demo.py http://127.0.0.1:5000 [ids.json]

Legt zwei Standorte, zwei simulierte Probes mit Ping-Daten, einen Pfad- und einen WAN-Check samt
Ergebnissen, aktive und beendete Alarme sowie Störungsmeldungen (offen und erledigt) an. Idempotent ist es nicht – für eine frische DB gedacht.
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

from wachtl import checktypes, create_app, findings, repo, reports, rtp  # noqa: E402
from wachtl.db import ins, q1  # noqa: E402
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

    with app.app_context():
        repo.create_check("Provider-Gateway", "100.64.0.1", "provider", 1, 1000, "all", None)

    # Ping-Daten über die echte Probe-API (Enrollment, Config, Ingest, Heartbeat)
    subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "simulate_probes.py"), base, TOKEN, "1"],
                   check=True)

    with app.app_context():
        now = repo.now()
        path = repo.create_check("Pfad zu Cloudflare", "1.1.1.1", "target", 1, 1000, "all", None, "path",
                                 checktypes.merged("path", {}))
        wan = repo.create_check("Internet-Speedtest", "", "target", 1, 1000, "all", None, "speedtest",
                                checktypes.merged("speedtest", {}))
        voice = repo.create_check("Sprache zum Server", "wachtl-server", "target", 900, 40000, "all", None, "rtp",
                                  checktypes.merged("rtp", {}))
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
            for i in range(24):
                up_loss, down_loss = max(0.0, random.gauss(0.2, 0.3)), max(0.0, random.gauss(0.4, 0.6))
                jitter_up, jitter_down = abs(random.gauss(2, 1)), abs(random.gauss(4, 2))
                rtt = 18 + abs(random.gauss(0, 4))
                r = min(rtp.r_factor(rtt / 2, j, l, rtp.CODECS["g711"], 20)
                        for j, l in ((jitter_up, up_loss), (jitter_down, down_loss)))
                ins("INSERT INTO rtp_runs (probe_id, check_id, ts, peer, codec, ptime_ms, duration_s, mode, sent, "
                    "received, rtt_ms, rtt_max_ms, loss_pct, up_loss_pct, down_loss_pct, jitter_ms, up_jitter_ms, "
                    "down_jitter_ms, out_of_order, r_factor, mos, trigger, error) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (probe_id, voice, now - 900 * i, "wachtl.example:5004", "g711", 20, 30, "wachtl", 1500,
                     int(1500 * (1 - (up_loss + down_loss) / 100)), round(rtt, 2), round(rtt * 2.5, 2),
                     round(up_loss + down_loss, 2), round(up_loss, 2), round(down_loss, 2),
                     round(max(jitter_up, jitter_down), 2), round(jitter_up, 2), round(jitter_down, 2), 0,
                     round(r, 1), round(rtp.mos(r), 2), "schedule", None))

        def iso(t: int) -> str:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

        def who(probe_id: int) -> dict:
            # Labels wie in den echten Alarmregeln (alertgen.BY_PROBE): Namen für Texte und Links
            r = q1("SELECT p.hostname, p.site_id, s.name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.id = ?",
                   (probe_id,))
            return {"probe": str(probe_id), "probe_name": r["hostname"], "site": str(r["site_id"]), "site_name": r["name"]}

        alerts.store_webhook({"alerts": [
            {"status": "firing", "fingerprint": "demo-1", "startsAt": iso(now - 900),
             "labels": {"alertname": "WachtlPacketLoss", "severity": "warning", **who(2), "cause": "wan"},
             "annotations": {"summary": "Paketverlust 6 % zu Google DNS (SRV-DC01)"}},
            {"status": "firing", "fingerprint": "demo-2", "startsAt": iso(now - 300),
             "labels": {"alertname": "WachtlTargetDown", "severity": "critical", **who(1)},
             "annotations": {"summary": "Cloudflare DNS nicht erreichbar (PC-EMPFANG)"}},
            {"status": "resolved", "fingerprint": "demo-3", "startsAt": iso(now - 86400), "endsAt": iso(now - 80000),
             "labels": {"alertname": "WachtlProbeOffline", "severity": "critical", **who(1)},
             "annotations": {"summary": "Probe PC-EMPFANG offline"}},
        ]})
        # Kurze Störung hinter dem Provider (Daten: simulate_probes.OUTAGE_AGO): Alarme wie von vmalert, schon
        # sekundengenau nachgerechnet, dazu Hop-Pings des Pfad-Checks während der Störung
        o_start, o_end = now - 1500, now - 1486
        for probe_id in (1, 2):
            refs = [("demo-wan", "WachtlWanDown", {"cause": "wan"}, "Alle Internet-Referenzen gestört")]
            refs += [(f"demo-{t}", "WachtlTargetDown", {"check_id": str(cid), "target": t, "role": "reference"},
                      f"{t} nicht erreichbar") for cid, t in ((2, "8.8.8.8"), (3, "1.1.1.1"))]
            alerts.store_webhook({"alerts": [
                {"status": "resolved", "fingerprint": f"{fp}-{probe_id}", "startsAt": iso(o_start + 12),
                 "endsAt": iso(o_end + 20), "labels": {"alertname": name, "severity": "critical", **who(probe_id), **lb},
                 "annotations": {"summary": text}} for fp, name, lb, text in refs]})
        from wachtl.db import ex
        ex("UPDATE alert_events SET exact_start = ?, exact_end = ?, refined_at = ? WHERE fingerprint LIKE 'demo-%-%'",
           (o_start, o_end, now))
        from wachtl.services import vm
        lines = []
        for t in range(now - 3600, now):
            for hop, ip, rtt in ((1, "192.168.1.1", 0.5), (2, "100.64.0.1", 3.2), (3, "80.81.192.1", 0),
                                 (4, "1.1.1.1", 9.6)):
                answered = hop != 3 and not (hop >= 3 and o_start <= t < o_end)
                lb = (f'probe="1",probe_name="PC-EMPFANG",site="{site}",site_name="Zentrale München",'
                      f'check_id="{path}",target="1.1.1.1",role="target",hop="{hop:02d}",hop_ip="{ip}"')
                lines.append(f"wachtl_hop_up{{{lb}}} {int(answered)} {t * 1000}")
                if answered:
                    lines.append(f"wachtl_hop_rtt_ms{{{lb}}} {rtt + random.random() * 0.4:.2f} {t * 1000}")
        vm.import_lines(lines)
        # Störungsmeldungen über dieselbe Prüfung wie die Probe-API (Tray-Symbol → Dienst → Server)
        probes = {1: {"id": 1, "site_id": site, "hostname": "PC-EMPFANG"},
                  2: {"id": 2, "site_id": site, "hostname": "SRV-DC01"}}
        demo_reports = [
            (1, 1200, "slow", "minutes", "Teams-Call ruckelt, Bildschirmfreigabe hängt", "KUNDE\\mmuster"),
            (2, 2 * 3600, "voice_video", "short", "Telefon hat kurz keinen Ton", "KUNDE\\abecker"),
            (1, 26 * 3600, "no_connection", "long", "Internet komplett weg, auch Outlook offline", "KUNDE\\mmuster"),
            (2, 3 * 86400, "application", "ongoing", "DATEV lädt sehr langsam", ""),
        ]
        for i, (probe_id, ago, category, duration, text, user) in enumerate(demo_reports):
            rid, _ = reports.store(probes[probe_id], reports.validate({
                "report_id": f"00000000-0000-4000-8000-{i:012d}", "occurred_at": now - ago, "category": category,
                "duration": duration, "description": text, "user": user, "hostname": probes[probe_id]["hostname"]}))
            if category == "no_connection":
                reports.set_status({"id": rid}, "done", "admin", "Störung beim Provider, behoben")
        # Client-Hinweise wie von der Probe (Kabel, Link-Geschwindigkeit)
        demo_findings = [
            ("cable_unplugged", "critical", "resolved", "Netzwerkkabel getrennt",
             "Die Netzwerkkarte „Ethernet“ hatte 2 Minuten keine Verbindung.",
             "Kabel am PC und an der Netzwerkdose prüfen; bei Wiederholung Kabel oder Switch-Port tauschen.", 5400, 120),
            ("link_speed_changed", "warning", "active", "Link-Geschwindigkeit von 1 Gbit/s auf 100 Mbit/s gesunken",
             "Die Netzwerkkarte „Ethernet“ arbeitet nur noch mit 100 Mbit/s.",
             "Kabel (mindestens Cat 5e) und Switch-Port prüfen, an beiden Seiten „Automatisch“ einstellen.", 1800, 0),
        ]
        for i, (kind, sev, state, title, msg, sol, ago, dur) in enumerate(demo_findings):
            findings.store(probes[1], findings.validate({
                "finding_id": f"00000000-0000-4000-9000-{i:012d}", "kind": kind, "severity": sev, "state": state,
                "adapter": "Ethernet", "adapter_description": "Intel(R) Ethernet Connection I219-V", "title": title,
                "message": msg, "solution": sol, "detected_at": now - ago,
                "resolved_at": now - ago + dur if state == "resolved" else None}))
    print(f"Demodaten angelegt: Pfad-Check {path}, WAN-Check {wan}")
    return {"probe": 1, "site": site, "ping_check": 2, "path_check": path, "wan_check": wan, "rtp_check": voice,
            "incident": [o_start, o_end]}


if __name__ == "__main__":
    ids = main(sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5000")
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w", encoding="utf-8") as fh:
            json.dump(ids, fh)
