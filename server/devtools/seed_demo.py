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
        # Netzwerkscan: 8 Scans im Abstand von 15 min; das Handy kommt und geht, ein Gerät mit doppelter IP
        from wachtl.services import netscan as netscan_service

        scan = repo.create_check("Netzwerkscan Büro", "auto", "target", 900, 1800000, "probe", 1, "netscan",
                                 checktypes.merged("netscan", {}))
        lan = [
            {"ip": "192.168.1.1", "mac": "3C:A6:2F:11:22:01", "hostname": "fritz.box", "rtt_ms": 0.6, "ports": [
                {"port": 80, "http_status": 301, "http_server": "box"},
                {"port": 443, "tls": True, "http_status": 200, "http_title": "FRITZ!Box", "tls_subject": "CN=fritz.box"}]},
            {"ip": "192.168.1.10", "mac": "00:15:5D:01:02:10", "hostname": "srv-dc01.kunde.local", "rtt_ms": 0.4,
             "ports": [{"port": 445}, {"port": 3389}, {"port": 53}]},
            {"ip": "192.168.1.20", "mac": "00:11:32:AA:BB:20", "hostname": "nas.kunde.local", "rtt_ms": 0.7, "ports": [
                {"port": 22, "banner": "SSH-2.0-OpenSSH_8.2"}, {"port": 5001, "tls": True, "http_status": 200,
                                                               "http_title": "Synology DiskStation"}]},
            {"ip": "192.168.1.30", "mac": "00:80:77:12:34:30", "hostname": None, "rtt_ms": 1.9,
             "ports": [{"port": 9100}, {"port": 80, "http_status": 200, "http_title": "Brother HL-L2350DW"}]},
            {"ip": "192.168.1.50", "mac": "A8:5E:45:00:00:50", "hostname": "pc-empfang.kunde.local", "self": True,
             "rtt_ms": 0.1, "ports": []},
        ]
        phone = {"ip": "192.168.1.77", "mac": "DA:A1:19:C0:FF:EE", "hostname": None, "rtt_ms": 12.0, "ports": []}
        intruder = {"ip": "192.168.1.30", "mac": "B8:27:EB:00:00:99", "hostname": "raspberrypi", "rtt_ms": 2.5,
                    "ports": [{"port": 22, "banner": "SSH-2.0-OpenSSH_7.9p1 Raspbian"}]}
        scanner = {"id": 1, "site_id": site, "hostname": "PC-EMPFANG"}
        for i, with_phone in enumerate([True, False, True, False, True, False, True, True]):
            hosts = lan + ([phone] if with_phone else []) + ([intruder] if i == 7 else [])
            netscan_service.store(scanner, {"id": scan}, netscan_service.validate(
                {"hosts": hosts, "subnets": ["192.168.1.0/24"], "duration_s": 21.4}), now - (7 - i) * 900)
        switch = _seed_topology(site, now)
    print(f"Demodaten angelegt: Pfad-Check {path}, WAN-Check {wan}")
    return {"probe": 1, "site": site, "ping_check": 2, "path_check": path, "wan_check": wan, "rtp_check": voice,
            "switch": switch}


def _seed_topology(site: int, now: int) -> int:
    """Switch-Topologie (docs/TOPOLOGIE.md): Core, Erdgeschoss, Obergeschoss, Lager – wie in den Entwürfen."""
    from wachtl import secretbox
    from wachtl.services import topology

    def mac(prefix: int, n: int) -> str:
        return f"02:00:00:{prefix:02X}:{n // 256:02X}:{n % 256:02X}"

    def snap(name, base, ports, fdb, lldp=(), poe=(), gateway=None, ips=(), arp=()):
        return {"system": {"name": name, "descr": f"{name} · Managed Switch, Firmware 7.2", "object_id": None,
                           "uptime_s": 41 * 86400 + 3600, "location": "Technikschrank", "contact": None},
                "interfaces": [{"index": i, "name": f"Port {i}", "descr": f"Port {i}", "alias": alias, "type": 6,
                                "speed_mbps": speed if up else None, "mac": mac(base, 1000 + i), "admin_up": True,
                                "oper_up": up, "in_errors": 0, "out_errors": 0, "fcs_errors": 0,
                                "duplex": "full" if up else None}
                               for i, speed, up, alias in ports],
                "fdb": [{"mac": m, "if_index": p, "vlan": 10} for m, p in fdb], "lldp": list(lldp), "cdp": [],
                "pvid": {str(i): 20 if i % 4 == 2 else 10 for i, *_ in ports},
                "poe": {"power_w": 370, "used_w": 62, "ports": list(poe)} if poe else None,
                "ips": list(ips), "arp": [{"ip": a, "mac": m} for a, m in arp], "gateway": gateway,
                "base_mac": mac(base, 0), "lldp_chassis": mac(base, 0), "duration_s": 1.4}

    def nb(port, base, port_id, name, ip):
        return {"if_index": port, "chassis_id": mac(base, 0), "port_id": port_id, "port_descr": port_id,
                "sys_name": name, "sys_descr": None, "mgmt_ip": ip, "bridge": True, "ap": False, "router": False,
                "phone": False}

    gw, empfang, nas, srv, printer = "3C:A6:2F:11:22:01", "A8:5E:45:00:00:50", "00:11:32:AA:BB:20", \
        "00:15:5D:01:02:10", "00:80:77:12:34:30"
    eg_pcs = [mac(0x40, i) for i in range(14)]
    og_pcs = [mac(0x41, i) for i in range(6)]
    desk = [mac(0x42, i) for i in range(5)]
    wlan = [mac(0x43, i) for i in range(9)]
    lager = [mac(0x44, i) for i in range(3)]
    ap = mac(0x45, 1)
    es, ng = "50:C7:BF:12:34:56", "A0:40:A0:65:43:21"          # gefunden per Rundruf: TP-Link Easy Smart, Netgear Plus
    lab = [mac(0x46, i) for i in range(2)]
    downstream_eg = [mac(2, 0), empfang, printer] + eg_pcs
    downstream_og = [mac(3, 0)] + og_pcs + desk
    core = snap("SW-Core-01", 1,
                [(1, 10000, True, "SW-EG-01"), (2, 10000, True, "Firewall"), (3, 1000, True, "SW-OG-01"),
                 (4, 1000, True, "Server HV-01"), (5, 1000, True, "AP-Empfang"), (6, 1000, True, "NAS")]
                + [(i, 1000, False, None) for i in range(7, 9)] + [(9, 100, True, "SW-Lager")]
                + [(i, 1000, i < 15, None) for i in range(10, 25)] + [(i, 10000, i < 27, None) for i in range(25, 29)],
                [(m, 1) for m in downstream_eg] + [(gw, 2)] + [(m, 3) for m in downstream_og] + [(srv, 4)]
                + [(ap, 5)] + [(m, 5) for m in wlan] + [(nas, 6)] + [(m, 9) for m in [mac(4, 0)] + lager]
                + [(m, 10) for m in [es] + lab] + [(ng, 3)],
                lldp=[nb(1, 2, "Port 25", "SW-EG-01", "192.168.1.3"),
                      {**nb(5, 0x45, "eth0", "AP-Empfang", "192.168.1.20"), "bridge": False, "ap": True}],
                gateway="192.168.1.1", ips=["192.168.1.2"], arp=[("192.168.1.1", gw)])
    eg = snap("SW-EG-01", 2, [(i, 100 if i in (7, 10, 16) else 1000, i in range(1, 19) and i not in (13, 17), None)
                              for i in range(1, 25)] + [(25, 10000, True, "Uplink Core"), (26, 10000, False, None),
                                                        (27, 10000, False, None), (28, 10000, False, None)],
              [(mac(1, 0), 25), (gw, 25), (mac(3, 0), 25), (empfang, 4), (printer, 7)]
              + [(m, i) for m, i in zip(eg_pcs, [1, 2, 3, 5, 6, 8, 9, 10, 11, 12, 14, 15, 16, 18])],
              lldp=[nb(25, 1, "Port 1", "SW-Core-01", "192.168.1.2")], poe=[1, 2, 5, 8, 10, 12, 14, 18],
              ips=["192.168.1.3"])
    og = snap("SW-OG-01", 3, [(i, 1000, i in (1, 2, 3, 5, 6, 7, 9, 10, 12, 14, 15), None) for i in range(1, 17)],
              [(mac(1, 0), 15), (gw, 15), (mac(2, 0), 15)] + [(m, p) for m, p in zip(og_pcs, (1, 2, 3, 5, 6, 7))]
              + [(m, 12) for m in desk + [ng]], ips=["192.168.1.4"])
    og["interfaces"][5]["speed_mbps"] = 100
    lag = snap("SW-Lager", 4, [(1, 1000, True, None), (2, 100, True, None), (3, 100, True, None), (4, 1000, False, None),
                                (5, 1000, True, None), (6, 1000, False, None), (7, 1000, False, None),
                                (8, 100, True, "Uplink Core")],
               [(mac(1, 0), 8), (gw, 8)] + [(m, p) for m, p in zip(lager, (1, 2, 3))], ips=["192.168.1.5"])
    secret = secretbox.seal({"version": "2c", "community": "demo"})
    ids = []
    for name, host, s, loc in (("SW-Core-01", "192.168.1.2", core, "Serverraum"),
                               ("SW-EG-01", "192.168.1.3", eg, "Erdgeschoss"),
                               ("SW-OG-01", "192.168.1.4", og, "Obergeschoss"), ("SW-Lager", "192.168.1.5", lag, "Lager")):
        ids.append(ins("INSERT INTO net_switches (site_id, name, host, port, snmp_version, secret, location, status, "
                       "last_poll, last_ok, sys_name, sys_descr, uptime_s, base_mac, snapshot, created_at, updated_at) "
                       "VALUES (?, NULL, ?, 161, '2c', ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (site, host, secret, loc, now - 240, now - 240, name, s["system"]["descr"],
                        s["system"]["uptime_s"], s["base_mac"], json.dumps(s), now - 86400, now)))
    ins("INSERT INTO net_switches (site_id, name, host, port, snmp_version, secret, status, last_poll, last_error, "
        "created_at, updated_at) VALUES (?, 'SW-Keller', '192.168.1.6', 161, '3', ?, 'active', ?, ?, ?, ?)",
        (site, secret, now - 240, "Keine Antwort von 192.168.1.6 (Zeitüberschreitung) – Adresse, Benutzer und "
         "Firewall (UDP 161) prüfen.", now - 86400, now))
    ins("INSERT INTO net_port_errors (switch_id, if_index, ts, errors) VALUES (?, 4, ?, 1204)", (ids[1], now - 3600))
    _seed_history(site, ids, {"core": core, "eg": eg, "og": og, "lager": lag}, now)
    for i in range(3):
        ins("INSERT INTO net_topo_events (site_id, switch_id, ts, kind, if_index, mac, detail) VALUES (?, ?, ?, "
            "'mac_moved', 3, ?, ?)", (site, ids[0], now - 3600 * (i + 1), og_pcs[0], f"{og_pcs[0]}: Port 3 → Port 7"))
    from wachtl.services import switchfind

    switchfind.store_discovery(site, [
        {"proto": "easysmart", "mac": es, "ip": "192.168.1.30", "model": "TL-SG105PE", "name": "SW-Labor",
         "firmware": "1.0.0 Build 20230218"},
        {"proto": "nsdp", "mac": ng, "ip": "192.168.1.31", "model": "GS108Ev3", "name": None, "firmware": "2.06.10"}], now)
    topology.refresh_findings(site, now)
    return ids[1]


def _seed_history(site: int, ids: list[int], snaps: dict, now: int) -> None:
    """Verlauf der letzten Tage: Stände zum Zurückblättern und typische Ereignisse (wie in den Entwürfen)."""
    import copy

    from wachtl.services import topo_history

    core, eg, og, lager = ids
    for sid, key in ((core, "core"), (eg, "eg"), (og, "og"), (lager, "lager")):
        topo_history.store_snapshot(sid, snaps[key], now - 3 * 86400)
    slow = copy.deepcopy(snaps["eg"])
    next(i for i in slow["interfaces"] if i["index"] == 25)["speed_mbps"] = 100
    t_slow = now - 86400 + 2 * 3600
    topo_history.store_snapshot(eg, slow, t_slow)
    topo_history.store_snapshot(eg, snaps["eg"], t_slow + 7200)
    down = copy.deepcopy(snaps["eg"])
    next(i for i in down["interfaces"] if i["index"] == 4)["oper_up"] = False
    topo_history.store_snapshot(eg, down, now - 3700)
    topo_history.store_snapshot(eg, snaps["eg"], now - 3580)

    def ev(sid, ts, kind, sev, port, detail, data=None):
        topo_history.event({"id": sid, "site_id": site}, ts, kind, sev, port, None, detail, data)

    ev(lager, now - 2 * 86400 - 3600, "switch_restart", "warning", None, "Neu gestartet (Laufzeit jetzt 2 min)")
    ev(eg, now - 2 * 86400 + 5000, "mac_moved", "info", 4, "pc-empfang.kunde.local: Port 9 → Port 4", {"from": 9, "to": 4})
    ev(og, now - 86400 - 3000, "device_new", "info", 12, "02:00:00:42:00:00 an Port 12")
    ev(eg, t_slow - 60, "link_flap", "critical", 25, "Port 25: kurz ohne Link zwischen zwei Abfragen")
    ev(eg, t_slow, "speed_changed", "warning", 25, "Port 25: 10 Gbit/s → 100 Mbit/s", {"from": 10000, "to": 100})
    ev(eg, t_slow + 7200, "speed_changed", "info", 25, "Port 25: 100 Mbit/s → 10 Gbit/s", {"from": 100, "to": 10000})
    ev(eg, now - 3700, "link_down", "info", 4, "Port 4: Link weg", {"from": "up", "to": "down", "speed": 1000})
    ev(eg, now - 3580, "link_up", "info", 4, "Port 4: Link wieder da, 1 Gbit/s", {"from": "down", "to": "up", "speed": 1000})
    ev(eg, now - 3500, "port_errors", "critical", 4, "Port 4: 1.204 fehlerhafte Pakete seit der letzten Abfrage",
       {"count": 1204})
    ev(eg, now - 40000, "link_down", "info", 6, "Port 6: Link weg", {"from": "up", "to": "down", "speed": 1000})
    ev(eg, now - 9000, "link_up", "info", 6, "Port 6: Link wieder da, 1 Gbit/s", {"from": "down", "to": "up", "speed": 1000})


if __name__ == "__main__":
    ids = main(sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5000")
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w", encoding="utf-8") as fh:
            json.dump(ids, fh)
