"""0.9: Sprachtest (RTP) – Protokoll, Reflektor, Auswertung, MOS, Server-API, Zustand, Alarm, Seiten."""
import json
import socket
import threading
import unittest

from wachtl import checktypes, repo, rtp
from wachtl.db import ex, q, q1
from wachtl.rtp import reflector, stream
from wachtl.serverprobe.runners import RtpRunner, measure_rtp
from wachtl.services import alertgen, checkstatus
from wachtl.services import settings as settings_service

from .helpers import AppTestCase

G711, G729 = rtp.CODECS["g711"], rtp.CODECS["g729"]


def vector() -> dict:
    """Gemeinsamer Prüffall mit Wachtl.Probe.Tests/RtpTests.cs: 10 gesendet, Nr. 9 auf dem Hinweg verloren,
    Nr. 4 auf dem Rückweg, Nr. 6 kommt nach Nr. 7 an. Uhr des Reflektors 4 s versetzt."""
    up = [10, 12, 10, 11, None, 10, 15, 10, 10]
    down = [10, 10, 11, 10, None, 12, 30, 10, 10]
    records = {}
    for i in range(9):
        if up[i] is None:
            continue
        t1 = 1_000_000 + i * 20_000
        records[i] = (t1, 5_000_000 + i * 20_000 + up[i] * 1000, i + 1, t1 + (up[i] + down[i]) * 1000)
    return records


class ProtocolTest(unittest.TestCase):
    def test_packet_layout(self):
        pkt = rtp.build_packet(G711, 20, 0x1_0005, 0xDEADBEEF, 123456, first=True)
        self.assertEqual(len(pkt), 12 + 160)
        self.assertEqual(pkt[0], 0x80)
        self.assertEqual(pkt[1], 0x80)                 # Marker beim ersten Paket, PT 0 = PCMU
        self.assertEqual(int.from_bytes(pkt[2:4], "big"), 5)
        self.assertEqual(int.from_bytes(pkt[4:8], "big"), (0x1_0005 * 160) & 0xFFFFFFFF)
        self.assertEqual(pkt[12:16], b"WTL1")
        p = rtp.parse(pkt)
        self.assertEqual((p.seq, p.ssrc, p.t1_us, p.t2_us, p.count, p.query), (5, 0xDEADBEEF, 123456, 0, 0, False))
        # G.729: 20 Byte Sprache, mindestens Platz für die Messfelder
        self.assertEqual(len(rtp.build_packet(G729, 20, 1, 1, 1)), 12 + 24)
        self.assertEqual(len(rtp.build_packet(G729, 40, 1, 1, 1)), 12 + 40)
        self.assertEqual(rtp.build_packet(G729, 20, 1, 1, 1)[1], 18)

    def test_parse_rejects_foreign_packets(self):
        good = rtp.build_packet(G711, 20, 1, 1, 1)
        self.assertIsNone(rtp.parse(good[:30]))
        self.assertIsNone(rtp.parse(b"\x40" + good[1:]))              # RTP-Version 1
        self.assertIsNone(rtp.parse(good[:12] + b"XXXX" + good[16:]))  # fremde Nutzlast
        self.assertIsNone(rtp.parse(good + b"\x00" * 1500))

    def test_reflector_counts_and_keeps_size(self):
        now = [100.0]
        r = reflector.Reflector(clock=lambda: now[0])
        addr = ("10.0.0.5", 40000)
        for i in range(3):
            reply = r.handle(rtp.build_packet(G711, 20, i, 7, 1000 + i), addr)
            self.assertEqual(len(reply), 172)
        p = rtp.parse(reply)
        self.assertEqual((p.count, p.t1_us, p.t2_us), (3, 1002, 100_000_000))
        q_reply = rtp.parse(r.handle(rtp.build_packet(G711, 20, 3, 7, 0, query=True), addr))
        self.assertEqual((q_reply.query, q_reply.count), (True, 3))    # Abfrage zählt nicht mit
        other = rtp.parse(r.handle(rtp.build_packet(G711, 20, 0, 8, 0), addr))
        self.assertEqual(other.count, 1)                              # anderer Strom (SSRC) zählt getrennt
        self.assertIsNone(r.handle(b"hallo", addr))
        now[0] += reflector.SESSION_IDLE_S + 20
        r.handle(rtp.build_packet(G711, 20, 0, 9, 0), ("10.0.0.6", 1))
        self.assertNotIn(("10.0.0.5", 40000, 7), r.sessions)          # alte Ströme aufgeräumt

    def test_reflector_rate_limit_per_source(self):
        r = reflector.Reflector(clock=lambda: 50.0)
        pkt = rtp.build_packet(G711, 20, 0, 1, 0)
        answered = sum(r.handle(pkt, ("192.0.2.1", 1)) is not None for _ in range(reflector.PER_SOURCE_PPS + 50))
        self.assertEqual(answered, reflector.PER_SOURCE_PPS)
        self.assertIsNotNone(r.handle(pkt, ("192.0.2.2", 1)))         # andere Adresse unbeeinflusst


class AnalysisTest(unittest.TestCase):
    def test_shared_vector(self):
        result = rtp.analyze(10, vector(), 9, G711, 20)
        self.assertEqual(result, {
            "sent": 10, "received": 8, "rtt_ms": 23.88, "rtt_max_ms": 45.0, "loss_pct": 20.0, "out_of_order": 1,
            "mode": "wachtl", "up_loss_pct": 10.0, "down_loss_pct": 11.11, "up_jitter_ms": 2.29,
            "down_jitter_ms": 6.0, "jitter_ms": 6.0, "r_factor": 63.0, "mos": 3.25})
        # ohne Abfrage am Ende: höchster Zähler aus den Antworten; G.729 verträgt Verlust schlechter
        g729 = rtp.analyze(10, vector(), None, G729, 20)
        self.assertEqual((g729["up_loss_pct"], g729["r_factor"], g729["mos"]), (10.0, 50.0, 2.58))

    def test_echo_mode(self):
        echo = {i: (t1, 0, 0, t4) for i, (t1, _, _, t4) in vector().items()}
        result = rtp.analyze(10, echo, None, G711, 20)
        self.assertEqual(result["mode"], "echo")
        self.assertNotIn("up_loss_pct", result)
        self.assertEqual((result["loss_pct"], result["jitter_ms"], result["mos"]), (20.0, 7.43, 2.57))

    def test_no_answer(self):
        result = rtp.analyze(50, {}, None, G711, 20)
        self.assertIn("keine Antwort", result["error"])
        self.assertEqual(result["loss_pct"], 100.0)

    def test_mos_scale(self):
        def m(delay, jitter, loss, codec=G711):
            return round(rtp.mos(rtp.r_factor(delay, jitter, loss, codec, 20)), 2)

        self.assertEqual(m(20, 5, 0), 4.38)
        self.assertEqual(m(20, 5, 1), 4.3)
        self.assertEqual(m(20, 5, 5), 3.87)
        self.assertEqual(m(20, 5, 0, G729), 4.06)
        self.assertEqual(m(200, 40, 0), 3.71)
        self.assertEqual(rtp.mos(-5), 1.0)
        self.assertEqual(rtp.mos(120), 4.5)
        self.assertEqual([rtp.mos_label(v) for v in (4.4, 4.1, 3.7, 3.2, 2.0, None)],
                         ["sehr gut", "gut", "ausreichend", "mangelhaft", "schlecht", "–"])


class LoopbackTest(unittest.TestCase):
    """Echter Strom über 127.0.0.1: Wachtl-Reflektor, einfacher UDP-Echo-Dienst, geschlossener Port."""

    def free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def wait_bound(self, port: int) -> None:
        """Bis der Reflektor-Thread antwortet – sonst geht das erste Paket des Tests ins Leere."""
        probe = rtp.build_packet(rtp.CODECS["g711"], 20, 0, 0x5741, 0, query=True)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("127.0.0.1", port))
            s.settimeout(0.05)
            for _ in range(100):
                try:
                    s.send(probe)
                    if s.recv(2048):
                        return
                except OSError:      # noch nicht gebunden (ICMP) oder keine Antwort
                    pass
        self.fail(f"Reflektor antwortet nicht auf Port {port}")

    def test_against_reflector(self):
        port, stop = self.free_port(), threading.Event()
        threading.Thread(target=reflector.serve, args=(port, stop, "127.0.0.1"), daemon=True).start()
        self.addCleanup(stop.set)
        self.wait_bound(port)
        result = stream.run("127.0.0.1", port, "g711", 20, 1)
        self.assertNotIn("error", result)
        self.assertEqual((result["mode"], result["sent"], result["received"]), ("wachtl", 50, 50))
        self.assertEqual((result["up_loss_pct"], result["down_loss_pct"]), (0.0, 0.0))
        self.assertGreater(result["mos"], 4.3)
        self.assertEqual(result["peer"], f"127.0.0.1:{port}")

    def test_against_plain_echo(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.2)
        stop = threading.Event()
        self.addCleanup(stop.set)
        self.addCleanup(sock.close)

        def echo():
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(2048)
                    sock.sendto(data, addr)
                except OSError:
                    pass

        threading.Thread(target=echo, daemon=True).start()
        result = stream.run("127.0.0.1", sock.getsockname()[1], "g729", 20, 1)
        self.assertEqual((result["mode"], result["received"]), ("echo", 50))
        self.assertIsNone(result.get("up_loss_pct"))

    def test_closed_port(self):
        result = stream.run("127.0.0.1", self.free_port(), "g711", 20, 1)
        self.assertIn("error", result)
        self.assertEqual(result["received"], 0)

    def test_unknown_host(self):
        result = stream.run("gibt-es-nicht.invalid", 5004, duration_s=1)
        self.assertIn("nicht auflösbar", result["error"])

    def test_runner_reports_peer_error(self):
        check = {"id": 3, "type": "rtp", "target": "wachtl-server", "params": {"duration_s": 5},
                 "peer": {"host": None, "port": None, "error": "RTP-Reflektor auf dem Wachtl-Server ist abgeschaltet"}}
        self.assertEqual(measure_rtp(check)["error"], "RTP-Reflektor auf dem Wachtl-Server ist abgeschaltet")
        reports = []
        runner = RtpRunner({**check, "params": {"schedule_min": 0}}, reports.append, measure=lambda c: {"mos": 4.4})
        runner._measure_and_report("manual")
        self.assertEqual(reports[0]["result"], {"mos": 4.4})
        self.assertEqual((reports[0]["check_id"], reports[0]["trigger"]), (3, "manual"))


class RtpServerTest(AppTestCase):
    def setUp(self):
        super().setUp()
        site = self.make_site()
        self.make_token(site, token="t", max_uses=5)
        self.a = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "t", "hostname": "PC-A"}).get_json()
        self.b = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "t", "hostname": "PC-B"}).get_json()

    def auth(self, d):
        return {"Authorization": f"Bearer {d['token']}"}

    def config(self, d):
        return self.client.get("/api/probe/v1/config", headers=self.auth(d)).get_json()

    def create(self, name="Sprache", **params) -> int:
        p = checktypes.merged("rtp", params)
        return repo.create_check(name, checktypes.target_for("rtp", p, {self.b["probe_id"]: "PC-B"}), "target",
                                 p["schedule_min"] * 60, checktypes.timeout_ms("rtp", p), "all", None, "rtp", p)

    def post(self, cid, result, probe=None, trigger="schedule"):
        return self.client.post("/api/probe/v1/results/rtp", headers=self.auth(probe or self.a),
                                json={"check_id": cid, "ts": repo.now(), "trigger": trigger, "result": result})

    def test_check_type(self):
        params, errors = checktypes.parse_params("rtp", {"peer": "server", "codec": "g729", "ptime_ms": "30",
                                                         "duration_s": "20", "dscp": "46", "schedule_min": "15",
                                                         "offset_min": "-1", "window_start": "00:00",
                                                         "window_end": "23:59", "weekdays": "1234567",
                                                         "min_mos": "3,8"})
        self.assertEqual(errors, [])
        self.assertEqual((params["codec"], params["ptime_ms"], params["min_mos"]), ("g729", 30, 3.8))
        self.assertEqual(checktypes.merged("rtp", {})["schedule_min"], 15)
        self.assertEqual(checktypes.merged("iperf", {})["schedule_min"], 60)   # Bandbreite unverändert
        _, errors = checktypes.parse_params("rtp", {"peer": "host", "host": "", "codec": "g711"})
        self.assertTrue(any("Host" in e for e in errors))
        _, errors = checktypes.parse_params("rtp", {"peer": "server", "codec": "opus"})
        self.assertTrue(any("Codec" in e for e in errors))
        p = checktypes.merged("rtp", {"peer": "host", "host": "pbx.kunde.de", "port": 7})
        self.assertEqual(checktypes.target_for("rtp", p), "pbx.kunde.de:7")
        self.assertEqual(checktypes.summary({"type": "rtp", "interval_s": 900}, p), "G.711, 20 ms, 30 s, alle 15 min")
        self.assertEqual(checktypes.timeout_ms("rtp", p), 40000)

    def test_config_resolves_peers(self):
        server = self.create("Sprache Server")
        peer = self.create("Sprache B", peer="probe", peer_probe_id=self.b["probe_id"])
        own = self.create("Sprache PBX", peer="host", host="10.1.1.1", port=7)
        cfg = self.config(self.a)
        checks = {c["id"]: c for c in cfg["checks"]}
        self.assertEqual(checks[server]["peer"], {"host": "wachtl.local", "port": 5004, "error": None})
        self.assertIn("nicht als Gegenstelle", checks[peer]["peer"]["error"])
        self.assertEqual(checks[own]["peer"], {"host": "10.1.1.1", "port": 7, "error": None})
        self.assertEqual(checks[server]["params"]["codec"], "g711")
        self.assertEqual(cfg["rtp_reflector"], {"enabled": False, "port": 5004})

        # PC-B wird Gegenstelle: Reflektor an, Adresse aus dem Heartbeat
        ex("UPDATE probes SET iperf_server = TRUE WHERE id = ?", (self.b["probe_id"],))
        self.client.post("/api/probe/v1/heartbeat", headers=self.auth(self.b), json={"addresses": ["10.0.0.20"]})
        settings_service.save({"probe_rtp_port": 15004, "rtp_enabled": False})
        self.assertEqual(self.config(self.b)["rtp_reflector"], {"enabled": True, "port": 15004})
        checks = {c["id"]: c for c in self.config(self.a)["checks"]}
        self.assertEqual(checks[peer]["peer"], {"host": "10.0.0.20", "port": 15004, "error": None})
        self.assertIn("abgeschaltet", checks[server]["peer"]["error"])
        # gegen sich selbst
        checks = {c["id"]: c for c in self.config(self.b)["checks"]}
        self.assertIn("sich selbst", checks[peer]["peer"]["error"])

    def test_results_state_pages_and_alert(self):
        cid = self.create(min_mos=3.6)
        probe = q1("SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.id = ?",
                   (self.a["probe_id"],))
        states = checkstatus.overview([probe], {})[probe["id"]]
        self.assertEqual(next(s for s in states if s.check["id"] == cid).state, "waiting")

        good = rtp.analyze(10, vector(), 9, G711, 20) | {"peer": "wachtl.local:5004", "codec": "g711",
                                                          "ptime_ms": 20, "duration_s": 30}
        good["mos"] = 4.32
        r = self.post(cid, good)
        self.assertEqual(r.status_code, 201, r.get_json())
        row = q1("SELECT * FROM rtp_runs")
        self.assertEqual((row["mos"], row["up_loss_pct"], row["down_jitter_ms"], row["mode"], row["sent"]),
                         (4.32, 10.0, 6.0, "wachtl", 10))
        self.assertTrue(any(line.startswith("wachtl_rtp_mos{") and " 4.32 " in line for line in self.imported))
        self.assertTrue(any(line.startswith("wachtl_rtp_ok{") and line.split()[-2] == "1" for line in self.imported))
        st = next(s for s in checkstatus.overview([probe], {})[probe["id"]] if s.check["id"] == cid)
        self.assertEqual((st.state, st.detail), ("ok", "MOS 4.32"))

        self.post(cid, {**good, "mos": 3.1})
        st = next(s for s in checkstatus.overview([probe], {})[probe["id"]] if s.check["id"] == cid)
        self.assertEqual((st.state, st.detail), ("warn", "MOS 3.10 unter 3.6"))

        self.post(cid, {"error": "keine Antwort von der Gegenstelle", "sent": 1500, "received": 0, "mos": 9})
        st = next(s for s in checkstatus.overview([probe], {})[probe["id"]] if s.check["id"] == cid)
        self.assertEqual(st.state, "down")
        self.assertTrue(any(line.startswith("wachtl_rtp_ok{") and line.split()[-2] == "0" for line in self.imported))
        self.assertIsNone(q1("SELECT mos FROM rtp_runs ORDER BY id DESC LIMIT 1")["mos"])   # 9 ist kein MOS

        # Fremder Check, kaputte Daten
        other = repo.create_check("Ping", "1.1.1.1", "target", 1, 1000, "all", None)
        self.assertEqual(self.post(other, good).status_code, 422)
        self.assertEqual(self.client.post("/api/probe/v1/results/rtp", headers=self.auth(self.a),
                                          json={"check_id": cid}).status_code, 400)

        # Seiten
        self.make_user()
        self.login()
        page = self.client.get(f"/probes/{self.a['probe_id']}/rtp/{cid}").get_data(as_text=True)
        self.assertIn("4.32", page)
        self.assertIn("keine Antwort von der Gegenstelle", page)
        self.assertIn('id="mos-data"', page)
        self.assertIn(f"/probes/{self.a['probe_id']}/rtp/{cid}",
                      self.client.get(f"/probes/{self.a['probe_id']}").get_data(as_text=True))
        site = self.client.get(f"/sites/{probe['site_id']}").get_data(as_text=True)
        self.assertIn(f"/probes/{self.a['probe_id']}/rtp/{cid}", site)
        overview = self.client.get("/").get_data(as_text=True)
        self.assertIn("Sprachqualität", overview)
        self.assertEqual(self.client.get(f"/probes/{self.a['probe_id']}/bandwidth/{cid}").status_code, 404)
        self.assertEqual(len(self.client.get(f"/api/v1/probes/{self.a['probe_id']}/rtp").get_json()), 3)

        # Jetzt testen -> Auftrag mit dem nächsten Heartbeat
        tok = self.session_csrf()
        self.assertEqual(self.client.post(f"/probes/{self.a['probe_id']}/checks/{cid}/run",
                                          data={"csrf_token": tok}).status_code, 302)
        hb = self.client.post("/api/probe/v1/heartbeat", headers=self.auth(self.a), json={}).get_json()
        self.assertEqual(hb["commands"][0]["type"], "run_check")
        self.assertEqual(hb["commands"][0]["check_id"], cid)

        # Alarmregel aus dem MOS-Schwellwert des Checks
        rules = alertgen.build_rules()["groups"][1]["rules"]
        voip = [r for r in rules if r["alert"] == "WachtlVoipQuality"]
        self.assertEqual(len(voip), 1)
        self.assertIn(f'wachtl_rtp_mos{{check_id="{cid}"}}', voip[0]["expr"])
        self.assertIn("< 3.6", voip[0]["expr"])
        repo.create_check("ohne Alarm", "wachtl-server", "target", 900, 40000, "all", None, "rtp",
                          checktypes.merged("rtp", {"min_mos": 0}))
        self.assertEqual(len([r for r in alertgen.build_rules()["groups"][1]["rules"]
                              if r["alert"] == "WachtlVoipQuality"]), 1)

    def test_server_probe_skips_test_against_itself(self):
        server = self.create("Sprache Server")
        peer = self.create("Sprache B", peer="probe", peer_probe_id=self.b["probe_id"])
        ex("UPDATE probes SET kind = 'server' WHERE id = ?", (self.a["probe_id"],))
        ids = {c["id"] for c in self.config(self.a)["checks"]}
        self.assertNotIn(server, ids)
        self.assertIn(peer, ids)
        self.assertIn(server, {c["id"] for c in self.config(self.b)["checks"]})

    def test_check_form_creates_rtp(self):
        self.make_user()
        self.login()
        self.assertEqual(self.client.get("/admin/checks/new/rtp").status_code, 200)
        r = self.client.post("/admin/checks", data={
            "csrf_token": self.session_csrf(), "type": "rtp", "name": "Sprache Zentrale", "peer": "probe",
            "peer_probe_id": str(self.b["probe_id"]), "codec": "g711", "ptime_ms": "20", "duration_s": "30",
            "dscp": "46", "schedule_min": "15", "offset_min": "-1", "window_start": "00:00", "window_end": "23:59",
            "weekdays": "1234567", "min_mos": "3.6", "scope": "probe", "probe_id": str(self.a["probe_id"])})
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:2000])
        c = q1("SELECT * FROM checks WHERE type = 'rtp'")
        self.assertEqual((c["target"], c["interval_s"], c["timeout_ms"]), ("probe:PC-B (Zentrale)", 900, 40000))
        self.assertEqual(json.loads(c["params"])["peer_probe_id"], self.b["probe_id"])
        # gegen sich selbst geht nicht
        r = self.client.post("/admin/checks", data={
            "csrf_token": self.session_csrf(), "type": "rtp", "name": "x", "peer": "probe",
            "peer_probe_id": str(self.b["probe_id"]), "codec": "g711", "weekdays": "1234567",
            "scope": "probe", "probe_id": str(self.b["probe_id"])})
        self.assertEqual(r.status_code, 400)

    def test_prune_and_default_rule(self):
        cid = self.create()
        self.post(cid, {"mos": 4.4, "sent": 1, "received": 1})
        ex("UPDATE rtp_runs SET ts = 1")
        repo.prune(history_days=7)
        self.assertEqual(q("SELECT id FROM rtp_runs"), [])
        self.assertIn("voip_quality", repo.alert_rules())
