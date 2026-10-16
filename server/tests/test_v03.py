"""0.3: Check-Typen, Pfade, Bandbreite, Befehle, Ausfälle, Pfadanalyse."""
import json
import time

from wachtl import checktypes, repo
from wachtl.db import ex, ins, q, q1
from wachtl.services import alertgen, outages, pathanalysis
from wachtl.services import settings as settings_service

from .helpers import AppTestCase


class CheckTypesTest(AppTestCase):
    def test_defaults_and_validation(self):
        params, errors = checktypes.parse_params("iperf", {"peer": "server", "protocol": "udp", "direction": "up",
                                                           "duration_s": "20", "streams": "4", "udp_mbps": "50,5",
                                                           "schedule_min": "60", "offset_min": "-1",
                                                           "window_start": "08:00", "window_end": "18:00",
                                                           "weekdays": "54321", "timeout_s": "60"})
        self.assertEqual(errors, [])
        self.assertEqual(params["udp_mbps"], 50.5)
        self.assertEqual(params["weekdays"], "12345")
        self.assertEqual(params["port"], 5201)  # ausgeblendet -> Standard

        _, errors = checktypes.parse_params("iperf", {"peer": "host", "host": "", "duration_s": "500"})
        self.assertTrue(any("Host" in e for e in errors))
        self.assertTrue(any("Testdauer" in e for e in errors))

        _, errors = checktypes.parse_params("iperf", {"peer": "server", "direction": "both", "duration_s": "40",
                                                      "timeout_s": "60"})
        self.assertTrue(any("Abbruch" in e for e in errors))

        _, errors = checktypes.parse_params("speedtest", {"method": "http", "down_url": "ftp://x", "up_url": ""})
        self.assertTrue(any("URL" in e for e in errors))

    def test_target_and_summary(self):
        p = checktypes.merged("speedtest", {})
        self.assertEqual(checktypes.target_for("speedtest", p), "speed.cloudflare.com")
        p = checktypes.merged("iperf", {"peer": "probe", "peer_probe_id": 7})
        self.assertEqual(checktypes.target_for("iperf", p, {7: "PC-7"}), "probe:PC-7")
        self.assertIn("alle 60 min", checktypes.summary({"type": "iperf", "interval_s": 3600}, p))


class ProbeConfigTest(AppTestCase):
    def setUp(self):
        super().setUp()
        site = self.make_site()
        self.make_token(site, token="t", max_uses=5)
        self.a = self._enroll("PC-A")
        self.b = self._enroll("PC-B")

    def _enroll(self, host):
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "t", "hostname": host})
        return r.get_json()

    def auth(self, d):
        return {"Authorization": f"Bearer {d['token']}"}

    def config(self, d):
        return self.client.get("/api/probe/v1/config", headers=self.auth(d)).get_json()

    def test_iperf_peers_resolve(self):
        server = repo.create_check("iperf Server", "wachtl-server", "target", 3600, 60000, "all", None, "iperf",
                                   checktypes.merged("iperf", {"peer": "server"}))
        peer = repo.create_check("iperf B", "probe:PC-B", "target", 3600, 60000, "probe", self.a["probe_id"], "iperf",
                                 checktypes.merged("iperf", {"peer": "probe", "peer_probe_id": self.b["probe_id"]}))
        cfg = {c["id"]: c for c in self.config(self.a)["checks"]}
        self.assertEqual(cfg[server]["peer"]["host"], "wachtl.local")
        self.assertEqual(cfg[server]["peer"]["port"], 5201)
        self.assertIn("nicht als iperf3-Gegenstelle", cfg[peer]["peer"]["error"])
        self.assertTrue(0 <= cfg[server]["params"]["offset_min"] < 60)

        # B meldet Adressen und wird Gegenstelle
        self.client.post("/api/probe/v1/heartbeat", headers=self.auth(self.b),
                         json={"addresses": ["169.254.1.2", "127.0.0.1", "10.0.0.22", "kaputt"]})
        ex("UPDATE probes SET iperf_server = TRUE, iperf_port = 5300 WHERE id = ?", (self.b["probe_id"],))
        cfg = {c["id"]: c for c in self.config(self.a)["checks"]}
        self.assertEqual(cfg[peer]["peer"], {"host": "10.0.0.22", "port": 5300, "error": None})
        b_cfg = self.config(self.b)
        self.assertEqual(b_cfg["iperf_server"], {"enabled": True, "port": 5300})

        settings_service.save({"iperf_enabled": False, "heartbeat_interval_s": 15})
        a_cfg = self.config(self.a)
        self.assertEqual(a_cfg["heartbeat_interval_s"], 15)
        cfg = {c["id"]: c for c in a_cfg["checks"]}
        self.assertIn("abgeschaltet", cfg[server]["peer"]["error"])

    def test_hop_metrics_only_for_path_checks(self):
        path = repo.create_check("Pfad", "1.1.1.1", "target", 1, 1000, "all", None, "path", checktypes.merged("path", {}))
        now_ms = int(time.time() * 1000)
        body = (f'wachtl_hop_rtt_ms{{check_id="{path}",hop="3",hop_ip="62.1.2.3"}} 9.5 {now_ms}\n'
                f'wachtl_hop_up{{check_id="{path}",hop="99",hop_ip="62.1.2.3"}} 1 {now_ms}\n'
                f'wachtl_hop_up{{check_id="1",hop="2",hop_ip="10.0.0.1"}} 1 {now_ms}\n'
                f'wachtl_ping_up{{check_id="{path}"}} 1 {now_ms}\n')
        r = self.client.post("/api/probe/v1/ingest", data=body, headers={**self.auth(self.a), "X-Batch-Id": "h1"})
        self.assertEqual(r.status_code, 204)
        self.assertEqual(len(self.imported), 1)
        self.assertIn('hop="03"', self.imported[0])
        self.assertIn('hop_ip="62.1.2.3"', self.imported[0])
        self.assertIn('target="1.1.1.1"', self.imported[0])

    def test_path_results_and_route_change(self):
        path = repo.create_check("Pfad", "1.1.1.1", "target", 1, 1000, "all", None, "path", checktypes.merged("path", {}))
        hops = [{"hop": 1, "ip": "192.168.1.1", "rtt_ms": 0.5}, {"hop": 2, "ip": None},
                {"hop": 3, "ip": "62.1.2.3", "rtt_ms": 9}, {"hop": 4, "ip": "1.1.1.1", "rtt_ms": 12}]
        url = "/api/probe/v1/results/path"
        r = self.client.post(url, headers=self.auth(self.a), json={"check_id": path, "hops": hops, "reached": True})
        self.assertEqual(r.status_code, 201)
        self.assertFalse(r.get_json()["changed"])
        # Hop 3 antwortet diesmal nicht -> kein Wechsel, Zeile wird fortgeschrieben
        hops2 = [dict(h) for h in hops]
        hops2[2] = {"hop": 3, "ip": None}
        r = self.client.post(url, headers=self.auth(self.a), json={"check_id": path, "hops": hops2, "reached": True})
        self.assertFalse(r.get_json()["changed"])
        self.assertEqual(len(q("SELECT * FROM path_runs")), 1)
        # anderer Router an Hop 3 -> Wechsel
        hops3 = [dict(h) for h in hops]
        hops3[2] = {"hop": 3, "ip": "80.9.9.9", "rtt_ms": 15}
        r = self.client.post(url, headers=self.auth(self.a), json={"check_id": path, "hops": hops3, "reached": True})
        self.assertTrue(r.get_json()["changed"])
        self.assertEqual(len(q("SELECT * FROM path_runs")), 2)
        self.assertTrue(any("wachtl_path_change" in line for line in self.imported))
        # fremder Check
        r = self.client.post(url, headers=self.auth(self.a), json={"check_id": 1, "hops": hops})
        self.assertEqual(r.status_code, 422)

    def test_bandwidth_results_and_commands(self):
        bw = repo.create_check("WAN", "speed.cloudflare.com", "reference", 3600, 90000, "all", None, "speedtest",
                               checktypes.merged("speedtest", {}))
        self.make_user()
        self.login()
        tok = self.session_csrf()
        r = self.client.post(f"/probes/{self.a['probe_id']}/checks/{bw}/run", data={"csrf_token": tok})
        self.assertEqual(r.status_code, 302)
        self.client.post(f"/probes/{self.a['probe_id']}/checks/{bw}/run", data={"csrf_token": tok})
        self.assertEqual(len(q("SELECT * FROM probe_commands")), 1)  # doppelt geklickt -> ein Auftrag

        hb = self.client.post("/api/probe/v1/heartbeat", headers=self.auth(self.a), json={}).get_json()
        self.assertEqual(hb["commands"], [{"id": 1, "type": "run_check", "check_id": bw}])
        hb = self.client.post("/api/probe/v1/heartbeat", headers=self.auth(self.a), json={}).get_json()
        self.assertEqual(hb["commands"], [])

        r = self.client.post("/api/probe/v1/results/bandwidth", headers=self.auth(self.a), json={
            "check_id": bw, "trigger": "manual", "results": [
                {"direction": "down", "mbps": 243.7, "latency_ms": 11.2, "duration_s": 10, "protocol": "http"},
                {"direction": "up", "mbps": None, "error": "Zeitüberschreitung"},
                {"direction": "sideways", "mbps": 1},
            ]})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["stored"], 2)
        rows = q("SELECT * FROM bandwidth_runs ORDER BY direction")
        self.assertEqual(rows[0]["direction"], "down")
        self.assertEqual(rows[0]["trigger"], "manual")
        self.assertEqual(rows[1]["error"], "Zeitüberschreitung")
        self.assertTrue(any('wachtl_bw_mbps{' in line and 'direction="down"' in line for line in self.imported))
        self.assertTrue(any('wachtl_bw_ok{' in line and 'direction="up"' in line and line.split()[-2] == "0"
                            for line in self.imported))

        page = self.client.get(f"/probes/{self.a['probe_id']}/bandwidth/{bw}")
        self.assertEqual(page.status_code, 200)
        self.assertIn("243.7", page.get_data(as_text=True).replace("243,7", "243.7"))

    def test_pages_and_forms(self):
        self.make_user()
        self.login()
        tok = self.session_csrf()
        for t in checktypes.TYPES:
            self.assertEqual(self.client.get(f"/admin/checks/new/{t}").status_code, 200, t)
        r = self.client.post("/admin/checks", data={
            "csrf_token": tok, "type": "iperf", "name": "iperf A-B", "peer": "probe",
            "peer_probe_id": self.b["probe_id"], "protocol": "tcp", "direction": "both", "duration_s": "10",
            "omit_s": "1", "streams": "2", "window_kb": "0", "timeout_s": "60", "schedule_min": "60",
            "offset_min": "-1", "window_start": "00:00", "window_end": "23:59", "weekdays": "1234567",
            "min_down_mbps": "100", "min_up_mbps": "0", "scope": "probe", "probe_id": self.a["probe_id"]})
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:500])
        c = q1("SELECT * FROM checks WHERE name = 'iperf A-B'")
        self.assertEqual(c["target"], "probe:PC-B (Zentrale)")
        self.assertEqual(json.loads(c["params"])["streams"], 2)
        # gegen sich selbst
        r = self.client.post("/admin/checks", data={
            "csrf_token": tok, "type": "iperf", "name": "selbst", "peer": "probe", "peer_probe_id": self.a["probe_id"],
            "scope": "probe", "probe_id": self.a["probe_id"], "duration_s": "10", "timeout_s": "60",
            "window_start": "00:00", "window_end": "23:59", "weekdays": "1234567", "schedule_min": "60",
            "offset_min": "-1", "direction": "down", "protocol": "tcp"})
        self.assertEqual(r.status_code, 400)
        # bearbeiten
        r = self.client.get(f"/admin/checks/{c['id']}/edit")
        self.assertIn('value="2"', r.get_data(as_text=True))
        rules = alertgen.build_rules()
        bw_rules = [x for x in rules["groups"][1]["rules"] if x["alert"] == "WachtlBandwidthLow"]
        self.assertEqual(len(bw_rules), 1)
        self.assertIn(f'check_id="{c["id"]}",direction="down"', bw_rules[0]["expr"])

        path = repo.create_check("Pfad", "1.1.1.1", "target", 1, 1000, "all", None, "path", checktypes.merged("path", {}))
        pid = self.a["probe_id"]
        self.client.post("/api/probe/v1/results/path", headers=self.auth(self.a), json={
            "check_id": path, "reached": True,
            "hops": [{"hop": 1, "ip": "192.168.1.1"}, {"hop": 2, "ip": None}, {"hop": 3, "ip": "1.1.1.1"}]})
        from unittest import mock
        table = {1: {"ip": "192.168.1.1", "other_ips": [], "loss": 0.0, "avg": 0.6, "min": 0.4, "max": 2.0,
                     "last": 0.5, "jitter": 0.1, "sent": 300},
                 3: {"ip": "1.1.1.1", "other_ips": ["1.0.0.1"], "loss": 15.0, "avg": 12.0, "min": 10.0, "max": 40.0,
                     "last": 11.0, "jitter": 2.0, "sent": 300}}
        with mock.patch("wachtl.services.vm.hop_table", return_value=table):
            html = self.client.get(f"/probes/{pid}/path/{path}").get_data(as_text=True)
        self.assertIn("Verlust bis Ziel", html)
        self.assertIn("auch 1.0.0.1", html)
        self.assertIn("keine Antwort", html)
        for url in (f"/probes/{pid}", f"/probes/{pid}/path/{path}", f"/probes/{pid}/path/{path}/hop/3",
                    "/outages", "/outages?range=30d&all=1", "/admin"):
            self.assertEqual(self.client.get(url).status_code, 200, url)
        r = self.client.post("/admin/measure", data={"csrf_token": tok, "iperf_enabled": "on", "iperf_host": "",
                                                     "iperf_port": "5201", "upload_interval_s": "10",
                                                     "heartbeat_interval_s": "20", "config_poll_s": "300",
                                                     "probe_iperf_port": "5201", "history_days": "400",
                                                     "outage_min_s": "30"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(settings_service.get()["heartbeat_interval_s"], 20)
        r = self.client.post(f"/probes/{pid}/settings", data={"csrf_token": tok, "iperf_server": "on",
                                                               "iperf_port": "5202", "iperf_address": ""})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(q1("SELECT iperf_server FROM probes WHERE id = ?", (pid,))["iperf_server"])


class PathAnalysisTest(AppTestCase):
    def test_real_loss_starts_at_hop(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "loss": 0, "avg": 0.5},
            {"hop": 2, "ip": "100.64.0.1", "loss": 0, "avg": 8},
            {"hop": 3, "ip": "62.1.2.3", "loss": 12, "avg": 10},
            {"hop": 4, "ip": "62.1.9.9", "loss": 11, "avg": 11},
            {"hop": 5, "ip": "1.1.1.1", "loss": 13, "avg": 12},
        ]
        a = pathanalysis.analyze(hops, "1.1.1.1")
        self.assertEqual(a.verdict, "bad")
        self.assertIn("zwischen Hop 2", a.findings[0].text)
        self.assertEqual(a.hop_marks[3], "real")

    def test_rate_limit_is_not_a_problem(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "loss": 0, "avg": 0.5},
            {"hop": 2, "ip": "62.1.2.3", "loss": 60, "avg": 30},
            {"hop": 3, "ip": None, "loss": None, "avg": None},
            {"hop": 4, "ip": "1.1.1.1", "loss": 0, "avg": 12},
        ]
        a = pathanalysis.analyze(hops)
        self.assertEqual(a.verdict, "ok")
        self.assertEqual(a.hop_marks[2], "ratelimit")
        self.assertEqual(a.hop_marks[3], "noreply")

    def test_latency_jump(self):
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "loss": 0, "avg": 1},
            {"hop": 2, "ip": "62.1.2.3", "loss": 0, "avg": 9},
            {"hop": 3, "ip": "62.2.2.2", "loss": 0, "avg": 95},
            {"hop": 4, "ip": "1.1.1.1", "loss": 0, "avg": 97},
        ]
        a = pathanalysis.analyze(hops)
        self.assertEqual(a.verdict, "warn")
        self.assertEqual(a.hop_marks[3], "jump")


class OutageTest(AppTestCase):
    def _event(self, alertname, labels, start, end=None):
        labels = {"alertname": alertname, "probe": "1", "probe_name": "PC-A", "site": "1", "site_name": "Zentrale",
                  **labels}
        ins("INSERT INTO alert_events (fingerprint, alertname, severity, status, labels, summary, starts_at, ends_at, "
            "updated_at) VALUES (?, ?, 'critical', ?, ?, ?, ?, ?, ?)",
            (f"{alertname}{start}", alertname, "resolved" if end else "firing", json.dumps(labels), alertname,
             start, end, end or start))

    def test_consequences_are_grouped(self):
        now = repo.now()
        self._event("WachtlTargetDown", {"role": "gateway", "target": "gateway"}, now - 600, now - 300)
        self._event("WachtlWanDown", {}, now - 590, now - 310)
        self._event("WachtlTargetDown", {"role": "target", "target": "10.0.0.5"}, now - 7200, now - 7000)
        self._event("WachtlLatencyHigh", {}, now - 100)
        items = outages.load(now - 86400)
        self.assertEqual(sorted(o.cause for o in items), ["gateway", "target"])
        all_items = outages.load(now - 86400, include_consequences=True)
        wan = next(o for o in all_items if o.cause == "wan")
        self.assertEqual(wan.consequence_of, "Gateway / LAN")
        s = outages.summarize(items)
        self.assertEqual(s["total"], 2)
        self.assertEqual(len(outages.load(now - 86400, min_duration=250)), 1)
