"""0.7: Ausfälle ab 5 s (sekundengenau) und Client-Hinweise der Probes."""
from __future__ import annotations

import json
import uuid
from unittest import mock

from wachtl import findings, repo
from wachtl.db import ex, ins, q, q1
from wachtl.services import outages, settings as settings_service, vm

from .helpers import AppTestCase


class ClientFindingApiTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.probe = self.enroll("PC-EMPFANG-01")
        self.pid = self.probe["probe_id"]
        self.auth = {"Authorization": f"Bearer {self.probe['token']}"}

    def item(self, **kw):
        data = {"finding_id": str(uuid.uuid4()), "kind": "cable_unplugged", "severity": "critical", "state": "active",
                "adapter": "Ethernet", "adapter_description": "Intel(R) Ethernet I219-V",
                "title": "Netzwerkkabel getrennt", "message": "Die Netzwerkkarte „Ethernet“ hat keine Verbindung.",
                "solution": "Kabel am PC und an der Netzwerkdose prüfen.", "details": {"speed_mbps": "1000"},
                "detected_at": repo.now() - 30, "resolved_at": None}
        data.update(kw)
        return data

    def post(self, *items, headers=None):
        return self.client.post("/api/probe/v1/findings", headers=self.auth if headers is None else headers,
                                json={"findings": list(items)})

    def test_store_and_resolve(self):
        f = self.item()
        r = self.post(f)
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["stored"], 1)
        row = q1("SELECT * FROM client_findings")
        self.assertEqual((row["probe_id"], row["site_id"], row["state"], row["kind"]),
                         (self.pid, 1, "active", "cable_unplugged"))
        self.assertEqual(json.loads(row["details"]), {"speed_mbps": "1000"})
        resolved = {**f, "state": "resolved", "resolved_at": repo.now()}
        self.assertEqual(self.post(resolved).status_code, 200)
        # verspätete Nachlieferung des aktiven Zustands macht ihn nicht wieder aktiv
        self.assertEqual(self.post(f).status_code, 200)
        rows = q("SELECT * FROM client_findings")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "resolved")
        self.assertGreaterEqual(rows[0]["resolved_at"], f["detected_at"])

    def test_resolution_keeps_problem_and_solution(self):
        # Die Probe schickt beim Beheben den Entwarnungstext, das Problem steht in details.problem
        f = self.item()
        self.post(f)
        self.post({**f, "state": "resolved", "resolved_at": repo.now(), "title": "Netzwerkkabel wieder verbunden",
                   "message": "Wieder verbunden (Unterbrechung 3 Min.)", "solution": "",
                   "details": {"problem": "Netzwerkkabel getrennt", "duration_s": "180"}})
        row = q1("SELECT * FROM client_findings")
        self.assertEqual((row["title"], row["solution"]), ("Netzwerkkabel getrennt", f["solution"]))
        details = json.loads(row["details"])
        self.assertEqual(details["resolution"], "Wieder verbunden (Unterbrechung 3 Min.)")
        self.assertEqual(details["speed_mbps"], "1000")
        # nur als behoben angekommen (Kabel war beim Senden schon wieder drin)
        g = self.item(state="resolved", resolved_at=repo.now(), title="Netzwerkkabel wieder verbunden",
                      message="Wieder verbunden", solution="", details={"problem": "Netzwerkkabel getrennt"})
        self.post(g)
        row = q1("SELECT * FROM client_findings WHERE finding_id = ?", (g["finding_id"],))
        self.assertEqual(row["title"], "Netzwerkkabel getrennt")
        self.make_user()
        self.login()
        self.assertIn("Wieder verbunden (Unterbrechung 3 Min.)", self.client.get(f"/probes/{self.pid}").get_data(as_text=True))

    def test_invalid_items_are_skipped(self):
        good = self.item(kind="future_kind_from_newer_probe", title="")
        r = self.post(good, self.item(severity="egal"), self.item(detected_at="gestern"), "kein Objekt")
        data = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual((data["stored"], data["rejected"]), (1, 3))
        row = q1("SELECT * FROM client_findings")
        self.assertEqual(row["title"], "future_kind_from_newer_probe")  # Titel fehlt: Art als Ersatz

    def test_bad_body_and_auth(self):
        self.assertEqual(self.client.post("/api/probe/v1/findings", headers=self.auth, json=[1]).status_code, 400)
        self.assertEqual(self.post(*[self.item() for _ in range(findings.MAX_BATCH + 1)]).status_code, 400)
        self.assertEqual(self.post(self.item(), headers={}).status_code, 401)
        ex("UPDATE probes SET status = 'disabled' WHERE id = ?", (self.pid,))
        self.assertEqual(self.post(self.item()).status_code, 403)
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM client_findings")["n"], 0)

    def test_control_chars_and_lengths(self):
        self.post(self.item(title="A\x00B" + "x" * 500, message="Zeile 1\nZeile 2\x07"))
        row = q1("SELECT * FROM client_findings")
        self.assertEqual(len(row["title"]), findings.MAX_TITLE)
        self.assertTrue(row["title"].startswith("AB"))
        self.assertEqual(row["message"], "Zeile 1\nZeile 2")

    def test_config_switch(self):
        r = self.client.get("/api/probe/v1/config", headers=self.auth)
        self.assertEqual(r.get_json()["client_findings"], {"enabled": True, "notify": True})
        settings_service.save({"client_findings_notify": False})
        r = self.client.get("/api/probe/v1/config", headers=self.auth)
        self.assertEqual(r.get_json()["client_findings"], {"enabled": True, "notify": False})
        settings_service.save({"client_findings_notify": True, "client_findings_enabled": False})
        r = self.client.get("/api/probe/v1/config", headers=self.auth)
        self.assertEqual(r.get_json()["client_findings"], {"enabled": False, "notify": False})

    def test_pages_and_admin_api(self):
        self.post(self.item(), self.item(kind="link_speed_changed", severity="warning",
                                         title="Link-Geschwindigkeit von 1 Gbit/s auf 100 Mbit/s gesunken",
                                         solution="Kabel und Switch-Port prüfen."))
        self.make_user()
        self.login()
        for url in ("/", f"/probes/{self.pid}", "/sites/1"):
            html = self.client.get(url).get_data(as_text=True)
            self.assertIn("Netzwerkkabel getrennt", html, url)
            self.assertIn("auf 100 Mbit/s gesunken", html, url)
            self.assertIn("Kabel und Switch-Port prüfen.", html, url)
        data = self.client.get("/api/v1/client-findings").get_json()
        self.assertEqual({d["kind"] for d in data}, {"cable_unplugged", "link_speed_changed"})
        self.assertEqual(data[0]["severity"], "critical")  # schwere zuerst
        self.assertEqual(self.client.get("/api/v1/client-findings?days=x").status_code, 400)


class ExactOutageTest(AppTestCase):
    def samples(self, start, down_from, down_to, end):
        return [(t, 0.0 if down_from <= t < down_to else 1.0) for t in range(start, end)]

    def test_down_intervals_and_intersect(self):
        s = self.samples(100, 110, 115, 130)
        self.assertEqual(outages.down_intervals(s), [(110, 115)])
        self.assertEqual(outages.down_intervals([(1, 0.0), (2, 0.0)]), [(1, 3)])
        self.assertEqual(outages.intersect([(0, 10)], [(5, 20)]), [(5, 10)])
        # WAN: nur die Zeit, in der alle Referenzen zugleich weg waren
        series = {"1": self.samples(100, 110, 118, 140), "2": self.samples(100, 112, 120, 140)}
        self.assertEqual(outages.exact_span(series, 130, 150, 3), (112, 118))
        self.assertIsNone(outages.exact_span(series, 130, 150, 7))

    def event(self, alertname, labels, start, end):
        return ins(
            "INSERT INTO alert_events (fingerprint, alertname, severity, status, labels, summary, starts_at, ends_at, "
            "updated_at) VALUES (?, ?, 'critical', 'resolved', ?, '', ?, ?, ?)",
            (str(uuid.uuid4()), alertname, json.dumps(labels), start, end, end))

    def test_refine_uses_raw_data(self):
        now = repo.now()
        # Alarm meldet 25 s spät und endet 20 s zu spät – die Rohdaten zeigen 5 s
        eid = self.event("WachtlTargetDown", {"probe": "7", "check_id": "3", "role": "gateway"}, now - 575, now - 555)
        raw = {"3": self.samples(now - 700, now - 600, now - 595, now - 500)}
        with mock.patch.object(vm, "up_samples", return_value=raw) as m:
            items = outages.load(now - 3600)
        m.assert_called_once()
        self.assertEqual(m.call_args[0][0], {"probe": "7", "check_id": "3"})
        o = next(i for i in items if i.id == eid)
        self.assertEqual((o.start, o.end, o.duration), (now - 600, now - 595, 5))
        row = q1("SELECT * FROM alert_events WHERE id = ?", (eid,))
        self.assertIsNotNone(row["refined_at"])
        with mock.patch.object(vm, "up_samples") as m:  # nur einmal nachrechnen
            outages.load(now - 3600)
        m.assert_not_called()

    def test_refine_wan_and_vm_error(self):
        now = repo.now()
        eid = self.event("WachtlWanDown", {"probe": "7"}, now - 575, now - 555)
        with mock.patch.object(vm, "up_samples", side_effect=vm.VMError("weg")):
            items = outages.load(now - 3600)
        self.assertEqual(next(i for i in items if i.id == eid).duration, 20)  # Alarmzeiten als Rückfall
        self.assertIsNone(q1("SELECT refined_at FROM alert_events WHERE id = ?", (eid,))["refined_at"])
        raw = {"1": self.samples(now - 700, now - 600, now - 594, now - 500),
               "2": self.samples(now - 700, now - 601, now - 595, now - 500)}
        with mock.patch.object(vm, "up_samples", return_value=raw) as m:
            items = outages.load(now - 3600)
        self.assertEqual(m.call_args[0][0], {"probe": "7", "role": "reference"})
        self.assertEqual(next(i for i in items if i.id == eid).duration, 5)

    def test_no_match_keeps_alert_times(self):
        now = repo.now()
        eid = self.event("WachtlTargetDown", {"probe": "7", "check_id": "3"}, now - 575, now - 555)
        with mock.patch.object(vm, "up_samples", return_value={"3": self.samples(now - 700, 0, 0, now - 500)}):
            items = outages.load(now - 3600)
        self.assertEqual(next(i for i in items if i.id == eid).duration, 20)
        self.assertIsNotNone(q1("SELECT refined_at FROM alert_events WHERE id = ?", (eid,))["refined_at"])

    def test_up_samples_rejects_foreign_labels(self):
        with self.assertRaises(ValueError):
            vm.up_samples({"probe": '1"} or vector(1) #'}, 0, 10)
        with self.assertRaises(ValueError):
            vm.up_samples({"job": "x"}, 0, 10)

    def test_default_rules_are_seconds(self):
        rules = repo.alert_rules()
        self.assertEqual(rules["target_down"]["threshold"], 5)
        self.assertEqual(rules["wan_down"]["threshold"], 5)
        self.assertIn("Sekunden", rules["target_down"]["name"])
