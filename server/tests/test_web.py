import json
from unittest import mock

from wachtl.db import ex, q, q1

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

    def test_password_forgot_page_public_and_linked(self):
        self.assertIn("/passwort-vergessen", self.client.get("/login").get_data(as_text=True))
        r = self.client.get("/passwort-vergessen")
        self.assertEqual(r.status_code, 200)
        self.assertIn("passwort.sh", r.get_data(as_text=True))
        with mock.patch("wachtl.web.os.name", "nt"):
            html = self.client.get("/passwort-vergessen").get_data(as_text=True)
        self.assertIn("Startmenü", html)
        self.assertNotIn("passwort.sh", html)

    def test_admin_resets_password_and_unlocks(self):
        self.make_user()
        self.make_user("leser", "readonly")
        for _ in range(5):
            self.login("leser", password="falsch-falsch-falsch")
        self.login()
        tok = self.session_csrf()
        uid = q1("SELECT id FROM users WHERE username = 'leser'")["id"]
        r = self.client.post(f"/admin/users/{uid}/password", data={"password": "", "csrf_token": tok},
                             follow_redirects=True)
        self.assertIn("Bitte ein Passwort", r.get_data(as_text=True))
        self.client.post(f"/admin/users/{uid}/password", data={"password": "1234", "csrf_token": tok})
        self.assertIsNotNone(q1("SELECT id FROM audit_log WHERE action = 'user.password_reset'"))
        self.client.post("/logout", data={"csrf_token": tok})
        self.login("leser", password="1234")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_operator_cannot_reset_password(self):
        self.make_user()
        self.make_user("op", "operator")
        self.login("op")
        uid = q1("SELECT id FROM users WHERE username = 'admin'")["id"]
        r = self.client.post(f"/admin/users/{uid}/password",
                             data={"password": "neues-passwort-123", "csrf_token": self.session_csrf()})
        self.assertEqual(r.status_code, 403)

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
        self.assertIn("WachtlSetup", html)
        self.assertIn("wachtl-", html)
        self.client.post("/admin/checks", data={"name": "Fileserver", "target": "10.1.1.10", "role": "target",
                                                "interval_s": 5, "timeout_ms": 800, "scope": "site",
                                                "site_id": site["id"], "csrf_token": tok})
        check = q1("SELECT * FROM checks WHERE name = 'Fileserver'")
        self.assertEqual(check["interval_s"], 5)
        bad = self.client.post("/admin/checks", data={"name": "X", "target": "nicht gültig!", "role": "target",
                                                      "interval_s": 1, "timeout_ms": 800, "scope": "all", "csrf_token": tok})
        self.assertEqual(bad.status_code, 400)
        self.assertIn("Ziel ist keine gültige", bad.get_data(as_text=True))
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
        values = [[1700000000, "1.5"], [1700000001, "NaN"]]

        def fake(url, params, timeout):
            query = params["query"]
            result = ([{"metric": {"phi": phi}, "values": values} for phi in ("0.1", "0.25", "0.75", "0.9")]
                      if "phi" in query else [{"metric": {}, "values": values}])
            resp = mock.Mock()
            resp.json.return_value = {"status": "success", "data": {"result": result}}
            return resp

        ex("UPDATE alert_rules SET enabled = FALSE WHERE kind = 'packet_loss_critical'")
        with mock.patch("wachtl.services.vm._session.get", side_effect=fake) as get:
            r = self.client.get(f"/api/v1/probes/{data['probe_id']}/checks/1/series?range=7d")
        body = r.get_json()
        self.assertEqual(body["source"], "agg")
        self.assertEqual(sorted(body["series"]), ["loss", "p10", "p25", "p50", "p75", "p90"])
        self.assertEqual(body["series"]["p25"], [[1700000000000, 1.5], [1700000001000, None]])
        self.assertEqual(body["series"]["p50"], body["series"]["p25"])
        self.assertIn("wachtl:ping_rtt_ms:quantiles_1m", get.call_args_list[0].kwargs["params"]["query"])
        self.assertEqual(body["thr"], {"lat_warn_ms": 100, "lat_window_s": 300, "loss_warn_pct": 2, "loss_bad_pct": None,
                                       "loss_window_s": 300})
        with mock.patch("wachtl.services.vm._session.get", side_effect=fake) as get:
            self.client.get(f"/api/v1/probes/{data['probe_id']}/checks/1/series?range=1h")
        self.assertIn('quantiles_over_time("phi", 0.1, 0.25, 0.5, 0.75, 0.9, wachtl_ping_rtt_ms{',
                      get.call_args_list[0].kwargs["params"]["query"])


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
        self.assertIn("Setup herunterladen", html)
        r = self.client.post("/admin/tokens/package", data={"token": token, "proxy": "http://p:3128", "csrf_token": tok})
        self.assertEqual(r.status_code, 200)
        zf = zipfile.ZipFile(io.BytesIO(r.data))
        self.assertEqual(sorted(zf.namelist()), ["LIESMICH.txt", "WachtlProbeSetup-0.2.0.exe", "wachtl-probe.ini"])
        ini = zf.read("wachtl-probe.ini").decode("utf-8-sig")
        for part in ("server=https://wachtl.test", "pin=PIN=", f"token={token}", "proxy=http://p:3128"):
            self.assertIn(part, ini)
        self.assertEqual(self.client.post("/admin/tokens/package", data={"token": "falsch", "csrf_token": tok}).status_code, 400)
        self.assertEqual(self.client.get("/admin/probe-setup").data, b"MZ-setup")


class PrefilledSetupTest(AppTestCase):
    """Ein Setup für alle: Vorbelegung (Adressen, Pin, Token) hängt am Ende der Datei."""

    def setUp(self):
        super().setUp()
        import os

        self.probe_dir = os.path.join(self.tmp, "probe")
        os.makedirs(self.probe_dir)
        with open(os.path.join(self.probe_dir, "WachtlProbeSetup-0.3.0.exe"), "wb") as f:
            f.write(b"MZ-alt")
        with open(os.path.join(self.probe_dir, "WachtlSetup-0.8.3.exe"), "wb") as f:
            f.write(b"MZ" + b"x" * 5000)
        self.app.config.update(PROBE_DIR=self.probe_dir, PUBLIC_URL="https://wachtl.test:8443", SPKI_PIN="PIN=",
                               SERVER_URLS=["https://wachtl:8443", "https://10.0.0.5:8443", "https://wachtl.test:8443"])
        self.make_user()
        self.login()
        self.tok = self.session_csrf()
        self.client.post("/admin/sites", data={"name": "Filiale Nürnberg", "csrf_token": self.tok})

    def test_direct_download_from_admin_form(self):
        from wachtl import setupfile
        from wachtl.db import q1
        from wachtl.security import hash_token

        r = self.client.post("/admin/tokens", data={"site_id": 1, "max_uses": 25, "days": 30, "proxy": "",
                                                   "action": "setup", "csrf_token": self.tok})
        self.assertEqual(r.status_code, 200)
        self.assertIn('filename="WachtlSetup-Filiale-Nuernberg.exe"', r.headers["Content-Disposition"])
        self.assertTrue(r.data.startswith(b"MZ" + b"x" * 5000))
        self.assertEqual(int(r.headers["Content-Length"]), len(r.data))
        values = setupfile.read_block(r.data)
        self.assertEqual(values["role"], "client")
        self.assertEqual(values["servers"], "https://wachtl.test:8443,https://wachtl:8443,https://10.0.0.5:8443")
        self.assertEqual(values["pin"], "PIN=")
        self.assertEqual(values["site"], "Filiale Nuernberg")
        token_row = q1("SELECT * FROM enrollment_tokens WHERE token_hash = ?", (hash_token(values["token"]),))
        self.assertEqual(token_row["max_uses"], 25)

    def test_download_for_existing_token_and_errors(self):
        import re

        from wachtl import setupfile

        html = self.client.post("/admin/tokens", data={"site_id": 1, "max_uses": 2, "days": 7, "action": "token",
                                                      "csrf_token": self.tok}).get_data(as_text=True)
        token = re.search(r'name="token" value="([^"]+)"', html).group(1)
        self.assertIn("https://10.0.0.5:8443", html)
        r = self.client.post("/admin/tokens/setup", data={"token": token, "proxy": "http://proxy:3128", "csrf_token": self.tok})
        self.assertEqual(setupfile.read_block(r.data)["proxy"], "http://proxy:3128")
        self.assertEqual(self.client.post("/admin/tokens/setup", data={"token": token, "proxy": "proxy:3128",
                                                                       "csrf_token": self.tok}).status_code, 400)
        self.assertEqual(self.client.post("/admin/tokens/setup", data={"token": "falsch", "csrf_token": self.tok}).status_code, 400)
        with self.assertRaises(ValueError):
            setupfile.config_block(["https://a"], "PIN", "tok\r\nrole=server", "x")

    def test_probe_config_carries_all_server_urls(self):
        from unittest import mock

        self.app.config.update(AUTO_IPS=True)
        with mock.patch("wachtl.netinfo.local_ipv4", return_value=["10.0.0.5", "192.168.7.2"]):
            data = self.enroll()
            cfg = self.client.get("/api/probe/v1/config", headers={"Authorization": f"Bearer {data['token']}"}).get_json()
        self.assertEqual(cfg["server_urls"], ["https://wachtl.test:8443", "https://wachtl:8443", "https://10.0.0.5:8443",
                                              "https://192.168.7.2:8443"])


class LiveStatusGapsTest(AppTestCase):
    """Ziel komplett gestört: VictoriaMetrics liefert up/loss, aber keine rtt."""

    def test_pages_render_without_rtt(self):
        enrolled = self.enroll()
        self.make_user()
        self.login()

        def instant(query):
            if "rtt" in query:
                return []
            return [{"metric": {"probe": str(enrolled["probe_id"]), "check_id": "1"}, "value": [0, "0"]}]

        with mock.patch("wachtl.services.vm.instant", side_effect=instant):
            for url in ("/", "/sites/1", f"/probes/{enrolled['probe_id']}"):
                r = self.client.get(url)
                self.assertEqual(r.status_code, 200, url)


class SiteDashboardTest(AppTestCase):
    """Standort-Dashboard: Kennzahlen, ein Widget je Probe, Probleme zuerst und hervorgehoben, Mini-Graph."""

    def setUp(self):
        super().setUp()
        from wachtl import repo
        self.ok = self.enroll("PC-OK")["probe_id"]  # legt den Standort an
        site = q1("SELECT site_id FROM probes WHERE id = ?", (self.ok,))["site_id"]
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": self.make_token(site, "tok-2"),
                                                         "hostname": "PC-AUS", "os": "Windows 11", "version": "0.1.0"})
        self.off = r.get_json()["probe_id"]
        now = repo.now()
        ex("UPDATE probes SET last_seen = ?", (now,))
        ex("UPDATE probes SET last_seen = ? WHERE id = ?", (now - 3600, self.off))
        ex("DELETE FROM checks WHERE type <> 'ping'")  # nur Pings: Traceroute/Speedtest ohne Daten wären „Probleme“
        ex("UPDATE checks SET created_at = ?", (now - 3600,))
        probe = q1("SELECT * FROM probes WHERE id = ?", (self.ok,))
        self.pings = [c for c in repo.checks_for_probe(probe) if c["type"] == "ping"]
        self.live = {(str(self.ok), str(c["id"])): {"up": 1, "rtt": 12.5, "loss": 0.0} for c in self.pings}
        self.site = site
        self.make_user()
        self.login()

    def get(self, sparks=None):
        side = sparks if isinstance(sparks, Exception) else None
        with mock.patch("wachtl.services.vm.live_status", return_value=self.live), \
             mock.patch("wachtl.services.vm.site_sparklines", return_value=sparks or {}, side_effect=side):
            r = self.client.get(f"/sites/{self.site}")
        self.assertEqual(r.status_code, 200)
        return r.get_data(as_text=True)

    def test_problem_probe_first_and_highlighted(self):
        from wachtl.services import alerts
        alerts.store_webhook({"alerts": [{"status": "firing", "fingerprint": "x", "startsAt": "2026-10-16T08:00:00Z",
                                          "labels": {"alertname": "WachtlProbeOffline", "severity": "critical",
                                                     "probe": str(self.off)},
                                          "annotations": {"summary": "Probe PC-AUS offline"}}]})
        html = self.get()
        self.assertIn("Probes online", html)
        self.assertIn('<span class="num">1 / 2</span>', html)
        self.assertIn(f'href="/meldungen?site={self.site}"', html)
        self.assertIn('href="#alarme"', html)
        self.assertLess(html.index("PC-AUS</a></h3>"), html.index("PC-OK</a></h3>"))
        bad = html[html.index('class="card pw bad"'):html.index("PC-OK</a></h3>")]
        self.assertIn("Probe offline – letzter Kontakt vor 1 h", bad)
        self.assertIn("Alarm: Probe PC-AUS offline", bad)
        self.assertIn("2 Probleme", bad)
        self.assertIn('class="card pw ok"', html)
        self.assertIn("12.5 ms", html)
        self.assertIn('<details id="alle-messungen">', html)

    def test_sparkline_and_vm_failure(self):
        import time
        ref = next((c for c in self.pings if c["role"] == "reference"), self.pings[0])
        now = int(time.time())
        sparks = {(str(self.ok), str(ref["id"])): {
            "rtt": [(now - 120, 10.0), (now - 60, 20.0), (now, None)], "loss": [(now - 60, 50.0)], "jitter": 1.5}}
        html = self.get(sparks)
        self.assertIn('<svg class="spark"', html)
        self.assertIn("Latenz-Median der letzten Stunde", html)
        self.assertIn("Paketverlust in 1 von 60 Minuten", html)
        self.assertIn('height="15.0"', html)  # 50 % Verlust = halbe Höhe
        self.assertIn("1.50 ms", html)  # Jitter
        from wachtl.services import vm
        html = self.get(vm.VMError("weg"))
        self.assertIn("Kein Latenzverlauf der letzten Stunde.", html)
