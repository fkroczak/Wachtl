import json
from unittest import mock

from wachtl.db import q, q1

from .helpers import AppTestCase

LIVE = {}


class WebTest(AppTestCase):
    def setUp(self):
        super().setUp()
        p = mock.patch("wachtl.services.vm.live_status", return_value=LIVE)
        p.start()
        self.addCleanup(p.stop)

    def test_login_required_and_success(self):
        self.make_user()
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        r = self.login()
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_lockout_after_failed_logins(self):
        self.make_user()
        for _ in range(5):
            self.login(password="falsch-falsch-falsch")
        r = self.login()
        self.assertEqual(r.status_code, 200)  # Formular erneut, nicht angemeldet
        self.assertIn("gesperrt", r.get_data(as_text=True))

    def test_readonly_cannot_open_admin(self):
        self.make_user("leser", "readonly")
        self.login("leser")
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.assertEqual(self.client.get("/alerts").status_code, 200)

    def test_post_without_csrf_rejected(self):
        self.make_user()
        self.login()
        r = self.client.post("/admin/sites", data={"name": "X"})
        self.assertEqual(r.status_code, 400)

    def test_admin_creates_site_token_and_check(self):
        self.make_user()
        self.login()
        tok = self.session_csrf()
        self.client.post("/admin/sites", data={"name": "Lager", "csrf_token": tok})
        site = q1("SELECT * FROM sites WHERE name = 'Lager'")
        self.assertIsNotNone(site)
        r = self.client.post("/admin/tokens", data={"site_id": site["id"], "max_uses": 3, "days": 7, "csrf_token": tok})
        html = r.get_data(as_text=True)
        self.assertIn("Install-Wachtl.ps1", html)
        self.assertIn("wachtl-", html)
        self.client.post("/admin/checks", data={"name": "Fileserver", "target": "10.1.1.10", "role": "target",
                                                "interval_s": 5, "timeout_ms": 800, "scope": "site",
                                                "site_id": site["id"], "csrf_token": tok})
        check = q1("SELECT * FROM checks WHERE name = 'Fileserver'")
        self.assertEqual(check["interval_s"], 5)
        bad = self.client.post("/admin/checks", data={"name": "X", "target": "nicht gültig!", "role": "target",
                                                      "interval_s": 1, "timeout_ms": 800, "scope": "all", "csrf_token": tok})
        self.assertEqual(bad.status_code, 302)
        self.assertIsNone(q1("SELECT id FROM checks WHERE name = 'X'"))
        self.assertGreaterEqual(len(q("SELECT * FROM audit_log")), 3)

    def test_pages_render_with_probe(self):
        self.make_user()
        data = self.enroll()
        self.login()
        for url in ("/", "/sites/1", f"/probes/{data['probe_id']}", f"/probes/{data['probe_id']}/checks/1",
                    "/alerts", "/admin", "/admin/audit", "/account"):
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_webhook_and_ack(self):
        self.make_user("op", "operator")
        payload = {"alerts": [{
            "status": "firing", "fingerprint": "abc", "startsAt": "2026-10-16T08:00:00Z", "endsAt": "0001-01-01T00:00:00Z",
            "labels": {"alertname": "WachtlTargetDown", "severity": "critical", "probe": "1", "check_id": "2"},
            "annotations": {"summary": "8.8.8.8 nicht erreichbar"},
        }]}
        self.assertEqual(self.client.post("/api/internal/alertmanager", json=payload).status_code, 401)
        self.assertEqual(self.client.post("/api/internal/alertmanager", json=payload,
                                          headers={"Authorization": "Bearer hook-secret",
                                                   "X-Forwarded-For": "1.2.3.4"}).status_code, 404)
        r = self.client.post("/api/internal/alertmanager", json=payload, headers={"Authorization": "Bearer hook-secret"})
        self.assertEqual(r.get_json(), {"stored": 1})
        payload["alerts"][0]["status"] = "resolved"
        payload["alerts"][0]["endsAt"] = "2026-10-16T08:05:00Z"
        self.client.post("/api/internal/alertmanager", json=payload, headers={"Authorization": "Bearer hook-secret"})
        ev = q1("SELECT * FROM alert_events")
        self.assertEqual(ev["status"], "resolved")
        self.assertEqual(ev["ends_at"] - ev["starts_at"], 300)

        self.app.config["ALERTMANAGER_URL"] = "http://am"
        self.login("op")
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"silenceID": "s-1"}
        resp.raise_for_status.return_value = None
        with mock.patch("wachtl.services.alerts.requests.post", return_value=resp) as post:
            self.client.post(f"/alerts/{ev['id']}/ack", data={"hours": 4, "csrf_token": self.session_csrf()})
        matchers = {m["name"]: m["value"] for m in post.call_args.kwargs["json"]["matchers"]}
        self.assertEqual(matchers, {"alertname": "WachtlTargetDown", "probe": "1", "check_id": "2"})
        ev = q1("SELECT * FROM alert_events")
        self.assertEqual((ev["acked_by"], ev["silence_id"]), ("op", "s-1"))

    def test_api_series_validates_range(self):
        self.make_user()
        data = self.enroll()
        self.login()
        r = self.client.get(f"/api/v1/probes/{data['probe_id']}/checks/1/series?range=99y")
        self.assertEqual(r.status_code, 400)
        fake = {"status": "success", "data": {"result": [{"values": [[1700000000, "1.5"], [1700000001, "NaN"]]}]}}
        resp = mock.Mock()
        resp.json.return_value = fake
        resp.raise_for_status.return_value = None
        with mock.patch("wachtl.services.vm._session.get", return_value=resp) as get:
            r = self.client.get(f"/api/v1/probes/{data['probe_id']}/checks/1/series?range=7d")
        body = r.get_json()
        self.assertEqual(body["source"], "agg")
        self.assertEqual(body["series"]["avg"], [[1700000000000, 1.5], [1700000001000, None]])
        self.assertIn("wachtl:ping_rtt_ms:avg_1m", get.call_args_list[0].kwargs["params"]["query"])


class ProbePackageTest(AppTestCase):
    def test_package_contains_setup_and_ini(self):
        import io
        import os
        import zipfile

        probe_dir = os.path.join(self.tmp, "probe")
        os.makedirs(probe_dir)
        with open(os.path.join(probe_dir, "WachtlProbeSetup-0.2.0.exe"), "wb") as f:
            f.write(b"MZ-setup")
        self.app.config.update(PROBE_DIR=probe_dir, PUBLIC_URL="https://wachtl.test", SPKI_PIN="PIN=")
        self.make_user()
        self.login()
        tok = self.session_csrf()
        self.client.post("/admin/sites", data={"name": "Lager", "csrf_token": tok})
        html = self.client.post("/admin/tokens", data={"site_id": 1, "max_uses": 5, "days": 7, "csrf_token": tok}).get_data(as_text=True)
        import re
        token = re.search(r'name="token" value="([^"]+)"', html).group(1)
        self.assertIn("Paket herunterladen", html)
        r = self.client.post("/admin/tokens/package", data={"token": token, "proxy": "http://p:3128", "csrf_token": tok})
        self.assertEqual(r.status_code, 200)
        zf = zipfile.ZipFile(io.BytesIO(r.data))
        self.assertEqual(sorted(zf.namelist()), ["LIESMICH.txt", "WachtlProbeSetup-0.2.0.exe", "wachtl-probe.ini"])
        ini = zf.read("wachtl-probe.ini").decode("utf-8-sig")
        for part in ("server=https://wachtl.test", "pin=PIN=", f"token={token}", "proxy=http://p:3128"):
            self.assertIn(part, ini)
        self.assertEqual(self.client.post("/admin/tokens/package", data={"token": "falsch", "csrf_token": tok}).status_code, 400)
        self.assertEqual(self.client.get("/admin/probe-setup").data, b"MZ-setup")
