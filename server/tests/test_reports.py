"""0.5: Störungsmeldungen – Probe-API, JSON-API für Graph-Markierungen, Web-UI, Rollen, Audit."""
from __future__ import annotations

import json
import uuid
from unittest import mock

from wachtl import repo, reports
from wachtl.db import ex, q, q1

from .helpers import AppTestCase


def enroll_at(case: AppTestCase, site_id: int, hostname: str, token: str) -> dict:
    """Weitere Probe an einem vorhandenen Standort (helpers.enroll legt immer einen neuen an)."""
    case.make_token(site_id, token=token)
    r = case.client.post("/api/probe/v1/enroll", json={"enrollment_token": token, "hostname": hostname})
    case.assertEqual(r.status_code, 201, r.get_json())
    return r.get_json()


class ReportApiTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.probe = self.enroll("PC-BUCHHALTUNG-03")
        self.pid = self.probe["probe_id"]
        self.auth = {"Authorization": f"Bearer {self.probe['token']}"}

    def body(self, **kw):
        data = {"report_id": str(uuid.uuid4()), "occurred_at": repo.now() - 60, "category": "slow",
                "duration": "minutes", "description": "Teams-Call ruckelt", "user": "KUNDE\\mmuster",
                "hostname": "PC-BUCHHALTUNG-03"}
        data.update(kw)
        return data

    def post(self, data, headers=None):
        return self.client.post("/api/probe/v1/report", headers=self.auth if headers is None else headers, json=data)

    def test_new_report_is_stored(self):
        data = self.body()
        r = self.post(data)
        self.assertEqual(r.status_code, 201, r.get_json())
        rid = r.get_json()["id"]
        row = q1("SELECT * FROM incident_reports WHERE id = ?", (rid,))
        self.assertEqual(row["probe_id"], self.pid)
        self.assertEqual(row["site_id"], 1)
        self.assertEqual(row["report_id"], data["report_id"])
        self.assertEqual(row["occurred_at"], data["occurred_at"])
        self.assertEqual((row["category"], row["duration"], row["status"]), ("slow", "minutes", "open"))
        self.assertEqual(row["reported_user"], "KUNDE\\mmuster")
        self.assertEqual(row["hostname"], "PC-BUCHHALTUNG-03")
        self.assertAlmostEqual(row["received_at"], repo.now(), delta=5)

    def test_duplicate_report_id_is_idempotent(self):
        data = self.body()
        first = self.post(data)
        second = self.post({**data, "description": "nachgeliefert"})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.get_json(), second.get_json())
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM incident_reports")["n"], 1)
        # dieselbe report_id einer anderen Probe ist eine eigene Meldung
        other = enroll_at(self, 1, "PC-02", "tok-2")
        r = self.post(data, headers={"Authorization": f"Bearer {other['token']}"})
        self.assertEqual(r.status_code, 201)

    def test_auth_like_other_probe_endpoints(self):
        self.assertEqual(self.post(self.body(), headers={}).status_code, 401)
        self.assertEqual(self.post(self.body(), headers={"Authorization": "Bearer 1.falsch"}).status_code, 401)
        ex("UPDATE probes SET status = 'disabled' WHERE id = ?", (self.pid,))
        self.assertEqual(self.post(self.body()).status_code, 403)
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM incident_reports")["n"], 0)

    def test_time_window(self):
        now = repo.now()
        self.assertEqual(self.post(self.body(occurred_at=now - 7 * 86400 + 60)).status_code, 201)
        self.assertEqual(self.post(self.body(occurred_at=now + 240)).status_code, 201)
        for ts in (now - 7 * 86400 - 60, now + 400, "gestern", None, True):
            r = self.post(self.body(occurred_at=ts))
            self.assertEqual(r.status_code, 400, ts)
            self.assertIn("occurred_at", r.get_json()["error"])

    def test_validation_errors_are_german(self):
        cases = [({"category": "kaputt"}, "category ungültig"), ({"category": None}, "category ungültig"),
                 ({"duration": "ewig"}, "duration ungültig"), ({"report_id": ""}, "report_id fehlt"),
                 ({"report_id": "a b"}, "report_id fehlt"), ({"report_id": 17}, "report_id fehlt")]
        for change, text in cases:
            r = self.post(self.body(**change))
            self.assertEqual(r.status_code, 400, change)
            self.assertIn(text, r.get_json()["error"])
        r = self.client.post("/api/probe/v1/report", headers=self.auth, data="kein json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM incident_reports")["n"], 0)

    def test_texts_are_truncated_and_defaults_apply(self):
        r = self.post(self.body(description="x" * 1500 + "\x00", user="u" * 200, hostname="h" * 300,
                                duration=None))
        self.assertEqual(r.status_code, 201, r.get_json())
        row = q1("SELECT * FROM incident_reports")
        self.assertEqual(len(row["description"]), 1000)
        self.assertEqual(len(row["reported_user"]), 128)
        self.assertEqual(len(row["hostname"]), 255)
        self.assertEqual(row["duration"], "unknown")
        r = self.post(self.body(hostname="", description="", user=""))
        row = q1("SELECT * FROM incident_reports WHERE id = ?", (r.get_json()["id"],))
        self.assertEqual(row["hostname"], "PC-BUCHHALTUNG-03")       # Name der Probe
        self.assertIsNone(row["description"])

    def test_all_categories_and_durations_accepted(self):
        for cat in reports.CATEGORIES:
            self.assertEqual(self.post(self.body(category=cat)).status_code, 201, cat)
        for dur in reports.DURATIONS:
            self.assertEqual(self.post(self.body(duration=dur)).status_code, 201, dur)

    def test_report_survives_probe_deletion(self):
        self.post(self.body())
        self.make_user()
        self.login()
        self.client.post(f"/probes/{self.pid}/delete", data={"csrf_token": self.session_csrf()})
        row = q1("SELECT * FROM incident_reports")
        self.assertIsNone(row["probe_id"])
        self.assertEqual(row["hostname"], "PC-BUCHHALTUNG-03")
        self.assertIn("PC-BUCHHALTUNG-03", self.client.get("/meldungen").get_data(as_text=True))

    def test_prune_removes_old_reports(self):
        self.post(self.body())
        ex("UPDATE incident_reports SET occurred_at = ?", (repo.now() - 800 * 86400,))
        repo.prune(history_days=30)
        self.assertEqual(q("SELECT id FROM incident_reports"), [])


class ReportsJsonTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.a = self.enroll("PC-A")
        site_b = self.make_site("Filiale")
        self.b = enroll_at(self, site_b, "PC-B", "tok-b")
        self.now = repo.now()
        for probe, offset, cat in ((self.a, 3600, "slow"), (self.a, 60, "voice_video"), (self.b, 600, "other")):
            r = self.client.post("/api/probe/v1/report", headers={"Authorization": f"Bearer {probe['token']}"},
                                 json={"report_id": str(uuid.uuid4()), "occurred_at": self.now - offset,
                                       "category": cat, "duration": "short", "user": "KUNDE\\mmuster",
                                       "description": "Test"})
            self.assertEqual(r.status_code, 201)

    def get(self, **params):
        return self.client.get("/api/reports", query_string=params)

    def test_requires_login_any_role(self):
        self.assertEqual(self.get().status_code, 401)
        self.make_user("leser", "readonly")
        self.login("leser")
        self.assertEqual(self.get().status_code, 200)

    def test_contract_shape_and_filters(self):
        self.make_user("leser", "readonly")
        self.login("leser")
        body = self.get(**{"from": self.now - 7200, "to": self.now}).get_json()
        self.assertEqual(len(body["reports"]), 3)
        self.assertEqual([r["ts"] for r in body["reports"]], sorted(r["ts"] for r in body["reports"]))
        first = body["reports"][0]
        self.assertEqual(set(first), {"id", "ts", "probe_id", "probe", "site", "category", "category_label",
                                      "duration_label", "description", "user", "status"})
        self.assertEqual(first["probe"], "PC-A")
        self.assertEqual(first["site"], "Zentrale")
        self.assertEqual(first["category_label"], "Langsam / lange Ladezeiten")
        self.assertEqual(first["duration_label"], "Kurz (unter 1 Minute)")
        self.assertEqual(first["user"], "KUNDE\\mmuster")
        self.assertEqual(first["status"], "open")

        only_a = self.get(**{"from": self.now - 7200, "to": self.now, "probe_id": self.a["probe_id"]}).get_json()
        self.assertEqual({r["probe"] for r in only_a["reports"]}, {"PC-A"})
        site_b = q1("SELECT site_id FROM probes WHERE id = ?", (self.b["probe_id"],))["site_id"]
        only_b = self.get(**{"from": self.now - 7200, "to": self.now, "site_id": site_b}).get_json()
        self.assertEqual([r["probe"] for r in only_b["reports"]], ["PC-B"])
        window = self.get(**{"from": self.now - 1200, "to": self.now - 300}).get_json()
        self.assertEqual([r["category"] for r in window["reports"]], ["other"])
        # Standard: letzte 24 Stunden
        self.assertEqual(len(self.get().get_json()["reports"]), 3)

    def test_bad_parameters(self):
        self.make_user()
        self.login()
        self.assertEqual(self.get(**{"from": "gestern"}).status_code, 400)
        self.assertEqual(self.get(**{"from": self.now, "to": self.now - 10}).status_code, 400)
        self.assertEqual(self.get(probe_id="x").status_code, 400)
        self.assertIn("error", self.get(site_id="x").get_json())

    def test_series_accepts_end(self):
        self.make_user()
        self.login()
        captured = {}

        def fake_get(base, path, params):
            captured.update(params)
            return []

        with mock.patch("wachtl.services.vm._get", side_effect=fake_get):
            r = self.client.get(f"/api/v1/probes/{self.a['probe_id']}/checks/1/series?range=1h&at={self.now - 5400}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(captured["end"], self.now - 3600)
        self.assertEqual(captured["start"], self.now - 7200)
        self.assertEqual(r.get_json()["end"], self.now - 3600)
        self.assertEqual(self.client.get(f"/api/v1/probes/{self.a['probe_id']}/checks/1/series?at=x").status_code,
                         400)


class ReportPagesTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.probe = self.enroll("PC-EMPFANG")
        self.pid = self.probe["probe_id"]
        self.now = repo.now()
        r = self.client.post("/api/probe/v1/report", headers={"Authorization": f"Bearer {self.probe['token']}"},
                             json={"report_id": str(uuid.uuid4()), "occurred_at": self.now - 300,
                                   "category": "dropouts", "duration": "ongoing", "user": "KUNDE\\mmuster",
                                   "description": "WLAN bricht ab <script>"})
        self.rid = r.get_json()["id"]
        for target, value in (("wachtl.services.vm.live_status", {}), ("wachtl.services.vm.hop_table", {})):
            p = mock.patch(target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def status(self, action="done", note="", csrf=None, report_id=None):
        return self.client.post(f"/meldungen/{report_id or self.rid}/status",
                                data={"csrf_token": self.session_csrf() if csrf is None else csrf,
                                      "action": action, "note": note})

    def test_pages_show_report(self):
        self.make_user("leser", "readonly")
        self.login("leser")
        html = self.client.get("/meldungen").get_data(as_text=True)
        self.assertIn("Aussetzer / Verbindungsabbrüche", html)
        self.assertIn("Dauert noch an", html)
        self.assertIn("WLAN bricht ab &lt;script&gt;", html)
        self.assertIn("KUNDE\\mmuster", html)
        self.assertNotIn('name="note"', html)                   # Nur-lesen: keine Aktion
        self.assertIn(f"/probes/{self.pid}/checks/", html)       # Link zum Graph …
        self.assertIn(f"at={self.now - 300}", html)              # … um den Zeitpunkt
        # Navigation zeigt die offenen Meldungen barrierefrei
        self.assertRegex(html, r'aria-current="page">Meldungen <span class="nav-count" aria-hidden="true">1</span>'
                               r'<span class="sr-only"> \(1 offen\)</span>')
        for url in ("/zustand", f"/probes/{self.pid}", "/sites/1"):
            page = self.client.get(url).get_data(as_text=True)
            self.assertIn("WLAN bricht ab", page, url)
        target = self.client.get(f"/probes/{self.pid}/checks/2?at={self.now - 300}").get_data(as_text=True)
        self.assertIn(f'data-at="{self.now - 300}"', target)
        self.assertIn('data-reports-url="/api/reports?probe_id=', target)
        self.assertIn("lg-report", target)
        self.assertIn("Zeitraum um die Störungsmeldung", target)

    def test_graph_link_prefers_reference_check(self):
        self.make_user()
        self.login()
        ref = q1("SELECT id FROM checks WHERE role = 'reference' ORDER BY id LIMIT 1")["id"]
        html = self.client.get("/meldungen").get_data(as_text=True)
        self.assertIn(f"/probes/{self.pid}/checks/{ref}?at={self.now - 300}", html)

    def test_filters_and_pagination(self):
        self.make_user()
        self.login()
        self.assertIn("WLAN bricht ab", self.client.get("/meldungen?status=open").get_data(as_text=True))
        self.assertNotIn("WLAN bricht ab", self.client.get("/meldungen?status=done").get_data(as_text=True))
        self.assertIn("WLAN bricht ab", self.client.get("/meldungen?status=all&site=1").get_data(as_text=True))
        other = self.make_site("Filiale")
        self.assertNotIn("WLAN bricht ab",
                         self.client.get(f"/meldungen?status=all&site={other}").get_data(as_text=True))
        self.assertIn("Nur Meldungen von", self.client.get(f"/meldungen?probe={self.pid}").get_data(as_text=True))
        for i in range(60):
            reports.store({"id": self.pid, "site_id": 1, "hostname": "PC-EMPFANG"},
                          reports.validate({"report_id": f"r-{i}", "occurred_at": self.now - 1000 - i,
                                            "category": "other"}))
        page1 = self.client.get("/meldungen").get_data(as_text=True)
        self.assertIn("Seite 1 von 2", page1)
        self.assertIn("Ältere Meldungen", page1)
        page2 = self.client.get("/meldungen?page=2").get_data(as_text=True)
        self.assertIn("Neuere Meldungen", page2)
        self.assertEqual(self.client.get("/meldungen?page=99&status=kaputt").status_code, 200)

    def test_operator_marks_done_and_reopens_with_audit(self):
        self.make_user("op", "operator")
        self.login("op")
        r = self.status("done", "Router neu gestartet")
        self.assertEqual(r.status_code, 302)
        row = q1("SELECT * FROM incident_reports WHERE id = ?", (self.rid,))
        self.assertEqual((row["status"], row["done_by"], row["done_note"]), ("done", "op", "Router neu gestartet"))
        self.assertIsNotNone(row["done_at"])
        audit = q1("SELECT * FROM audit_log WHERE action = 'report.done'")
        self.assertEqual((audit["username"], audit["object"]), ("op", f"report:{self.rid}"))
        self.assertIn("Router neu gestartet", audit["detail"])
        html = self.client.get("/meldungen?status=done").get_data(as_text=True)
        self.assertIn("Router neu gestartet", html)
        self.assertIn("Wieder öffnen", html)
        self.assertNotIn('class="nav-count"', html)              # nichts mehr offen

        self.status("open")
        row = q1("SELECT * FROM incident_reports WHERE id = ?", (self.rid,))
        self.assertEqual(row["status"], "open")
        self.assertIsNone(row["done_by"])
        self.assertIsNotNone(q1("SELECT id FROM audit_log WHERE action = 'report.reopen'"))

    def test_redirect_keeps_filter_but_not_foreign_urls(self):
        self.make_user()
        self.login()
        r = self.client.post(f"/meldungen/{self.rid}/status", data={
            "csrf_token": self.session_csrf(), "action": "done", "next": "/meldungen?status=all&site=1"})
        self.assertEqual(r.headers["Location"], "/meldungen?status=all&site=1")
        r = self.client.post(f"/meldungen/{self.rid}/status", data={
            "csrf_token": self.session_csrf(), "action": "open", "next": "//evil.example"})
        self.assertEqual(r.headers["Location"], "/meldungen")

    def test_readonly_forbidden_and_csrf_required(self):
        self.make_user("leser", "readonly")
        self.login("leser")
        self.assertEqual(self.status().status_code, 403)
        self.make_user("op", "operator")
        self.login("op")
        self.assertEqual(self.status(csrf="falsch").status_code, 400)
        self.assertEqual(self.status(action="loeschen").status_code, 400)
        self.assertEqual(self.status(report_id=9999).status_code, 404)
        self.assertEqual(q1("SELECT status FROM incident_reports WHERE id = ?", (self.rid,))["status"], "open")
        self.assertIsNone(q1("SELECT id FROM audit_log WHERE action LIKE 'report.%'"))

    def test_bandwidth_chart_contains_reports(self):
        from wachtl import checktypes

        self.make_user()
        self.login()
        wan = repo.create_check("WAN", "", "target", 1, 1000, "all", None, "speedtest", checktypes.merged("speedtest", {}))
        html = self.client.get(f"/probes/{self.pid}/bandwidth/{wan}").get_data(as_text=True)
        data = json.loads(html.split('id="bw-data">', 1)[1].split("</script>", 1)[0])
        self.assertEqual(len(data["reports"]), 1)
        self.assertEqual(data["reports"][0]["ts"], self.now - 300)
        self.assertNotIn("<script>", html.split('id="bw-data">', 1)[1].split("</script>", 1)[0])
        self.assertIn("lg-report", html)

    def test_overview_without_reports_unchanged(self):
        ex("DELETE FROM incident_reports")
        self.make_user()
        self.login()
        html = self.client.get("/zustand").get_data(as_text=True)
        self.assertIn("Keine offenen Meldungen", html)
        self.assertNotIn('class="nav-count"', html)
        target = self.client.get(f"/probes/{self.pid}/checks/2").get_data(as_text=True)
        self.assertNotIn("lg-report", target)
        self.assertNotIn("data-at=", target)
