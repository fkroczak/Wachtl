"""0.4: Zustand aller Check-Arten, Standardpaket, Server-Probe, Abmeldung bei der Deinstallation."""
from datetime import datetime
from unittest import mock

from wachtl import checktypes, repo, schedule, standardpaket
from wachtl.db import ex, q, q1
from wachtl.services import checkstatus

from .helpers import AppTestCase


class ScheduleTest(AppTestCase):
    def test_next_run_matches_probe_rule(self):
        after = datetime(2026, 10, 16, 10, 7)          # Freitag
        self.assertEqual(schedule.next_run(after, 60, 5), datetime(2026, 10, 16, 11, 5))
        self.assertEqual(schedule.next_run(after, 60, 5, "22:00", "04:00"), datetime(2026, 10, 16, 22, 5))
        self.assertEqual(schedule.next_run(after, 360, 0, weekdays="1"), datetime(2026, 10, 19, 0, 0))
        self.assertIsNone(schedule.next_run(after, 0, 0))

    def test_overdue(self):
        params = checktypes.merged("speedtest", {"schedule_min": 60, "offset_min": 0})
        last = int(datetime(2026, 10, 16, 10, 0).timestamp())
        self.assertIsNone(schedule.overdue_since(params, last, last, last + 3600 + 600))
        self.assertIsNotNone(schedule.overdue_since(params, last, last, last + 3 * 3600))
        self.assertIsNone(schedule.overdue_since(checktypes.merged("speedtest", {"schedule_min": 0}), None, last,
                                                 last + 10**6))


class CheckStatusTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.probe = self.enroll("PC-01")
        self.pid = self.probe["probe_id"]
        self.auth = {"Authorization": f"Bearer {self.probe['token']}"}
        self.old = repo.now() - 86400
        self.path = repo.create_check("Pfad", "1.1.1.1", "target", 5, 1000, "all", None, "path",
                                      checktypes.merged("path", {}))
        self.wan = repo.create_check("WAN", "speed.cloudflare.com", "reference", 3600, 90000, "all", None, "speedtest",
                                     checktypes.merged("speedtest", {"schedule_min": 60}))
        self.iperf = repo.create_check("iperf", "wachtl-server", "target", 3600, 60000, "all", None, "iperf",
                                       checktypes.merged("iperf", {"peer": "server", "schedule_min": 0,
                                                                   "min_down_mbps": 100}))
        ex("UPDATE checks SET created_at = ?", (self.old,))
        self.client.post("/api/probe/v1/heartbeat", headers=self.auth, json={})

    def states(self, live=None):
        p = q1("SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.id = ?",
               (self.pid,))
        return {st.check["id"]: st for st in checkstatus.overview([p], live or {})[self.pid]}

    def bw(self, check, results):
        r = self.client.post("/api/probe/v1/results/bandwidth", headers=self.auth,
                             json={"check_id": check, "results": results})
        self.assertEqual(r.status_code, 201, r.get_json())

    def test_every_check_type_is_rated(self):
        gateway = q1("SELECT id FROM checks WHERE target = 'gateway'")["id"]
        google = q1("SELECT id FROM checks WHERE target = '8.8.8.8'")["id"]
        live = {(str(self.pid), str(gateway)): {"up": 1, "rtt": 0.8, "loss": 0},
                (str(self.pid), str(google)): {"up": 0, "rtt": None, "loss": 100}}
        st = self.states(live)
        self.assertEqual(st[gateway].state, "ok")
        self.assertEqual(st[google].state, "down")
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM checks")["n"], len(st))
        cloudflare = q1("SELECT id FROM checks WHERE target = '1.1.1.1' AND type = 'ping'")["id"]
        self.assertEqual(st[cloudflare].state, "stale")        # kein einziger Messwert
        self.assertEqual(st[self.path].state, "stale")         # kein Traceroute
        self.assertEqual(st[self.wan].state, "stale")          # geplant, aber ausgeblieben
        self.assertEqual(st[self.iperf].state, "waiting")      # nur manuell

        self.client.post("/api/probe/v1/results/path", headers=self.auth,
                         json={"check_id": self.path, "reached": False, "hops": [{"hop": 1, "ip": "192.168.1.1"}]})
        self.bw(self.wan, [{"direction": "down", "error": "HTTP 403 von speed.cloudflare.com"},
                           {"direction": "up", "mbps": 40}])
        self.bw(self.iperf, [{"direction": "down", "mbps": 80}, {"direction": "up", "mbps": 300}])
        st = self.states(live)
        self.assertEqual(st[self.path].state, "warn")
        self.assertEqual(st[self.wan].state, "down")
        self.assertIn("HTTP 403", st[self.wan].detail)
        self.assertEqual(st[self.iperf].state, "warn")
        self.assertIn("80.0 < 100", st[self.iperf].detail)

        self.bw(self.wan, [{"direction": "down", "mbps": 250}, {"direction": "up", "mbps": 40}])
        self.assertEqual(self.states(live)[self.wan].state, "ok")

    def test_overview_lists_failed_measurements(self):
        self.bw(self.wan, [{"direction": "down", "error": "Zeitlimit erreicht"}])
        self.make_site("Filiale")                  # Übersicht gibt es ab zwei Standorten
        self.make_user()
        self.login()
        with mock.patch("wachtl.services.vm.live_status", return_value={}):
            html = self.client.get("/").get_data(as_text=True)
            self.assertIn("Messungen mit Problemen", html)
            self.assertIn("Zeitlimit erreicht", html)
            self.assertIn("noch kein Traceroute-Ergebnis", html)
            self.assertIn(f"/probes/{self.pid}/bandwidth/{self.wan}", html)
            self.assertIn("Checks ok / auffällig / gestört / keine Daten",
                          self.client.get("/probes?tab=alle").get_data(as_text=True))
            probe_html = self.client.get(f"/probes/{self.pid}").get_data(as_text=True)
            self.assertIn("Alle Messungen", probe_html)
            self.assertIn("Zeitlimit erreicht", probe_html)
            site_html = self.client.get("/sites/1?tab=messungen").get_data(as_text=True)
            self.assertIn("Pfad", site_html)
            self.assertIn("WAN", site_html)

    def test_offline_probe_is_one_problem(self):
        ex("UPDATE probes SET last_seen = ?", (repo.now() - 3600,))
        self.make_site("Filiale")                  # Übersicht gibt es ab zwei Standorten
        self.make_user()
        self.login()
        with mock.patch("wachtl.services.vm.live_status", return_value={}):
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn("Kein Heartbeat", html)
        self.assertNotIn("noch kein Traceroute-Ergebnis", html)


class StandardPackageTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.app.config["PUBLIC_URL"] = "https://wachtl.kunde.de"
        self.make_user()
        self.login()

    def test_creates_all_types_once(self):
        tok = self.session_csrf()
        keys = [i.key for i in standardpaket.ITEMS]
        r = self.client.post("/admin/standard-package", data={"csrf_token": tok, "scope": "all", "items": keys})
        self.assertEqual(r.status_code, 302)
        types = {c["type"] for c in q("SELECT type FROM checks")}
        self.assertEqual(types, {"ping", "path", "iperf", "speedtest", "rtp"})
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM checks WHERE target = 'gateway'")["n"], 1)  # Seed nicht doppelt
        self.assertTrue(q1("SELECT id FROM checks WHERE type = 'path' AND target = 'wachtl.kunde.de'"))
        n = q1("SELECT COUNT(*) AS n FROM checks")["n"]
        self.client.post("/admin/standard-package", data={"csrf_token": tok, "scope": "all", "items": keys})
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM checks")["n"], n)
        html = self.client.get("/admin?tab=standardpaket").get_data(as_text=True)
        self.assertIn("schon vorhanden", html)
        # alle angelegten Checks sind gültig für die Probe-Konfiguration
        probe = self.enroll("PC-02")
        cfg = self.client.get("/api/probe/v1/config", headers={"Authorization": f"Bearer {probe['token']}"}).get_json()
        self.assertEqual(len(cfg["checks"]), n)

    def test_site_scope(self):
        site = self.make_site("Filiale")
        ex("DELETE FROM checks WHERE type = 'speedtest'")  # Standard-Speedtest der Installation
        tok = self.session_csrf()
        self.client.post("/admin/standard-package", data={"csrf_token": tok, "scope": "site", "site_id": site,
                                                         "items": ["speedtest_wan"]})
        a = q1("SELECT a.* FROM check_assignments a JOIN checks c ON c.id = a.check_id WHERE c.type = 'speedtest'")
        self.assertEqual((a["scope"], a["scope_id"]), ("site", site))

    def test_without_server_hostname(self):
        self.app.config["PUBLIC_URL"] = "https://wachtl.local"
        created, skipped = standardpaket.apply(["ping_server"], "all", None, "https://wachtl.local")
        self.assertEqual(created, [])
        self.assertIn("Hostname", skipped[0])


class DeregisterTest(AppTestCase):
    def test_uninstaller_invalidates_token(self):
        probe = self.enroll("PC-weg")
        auth = {"Authorization": f"Bearer {probe['token']}"}
        site = q1("SELECT site_id FROM probes")["site_id"]
        repo.queue_command(probe["probe_id"], "retrace", 1, "test")
        r = self.client.post("/api/probe/v1/deregister", headers=auth, json={})
        self.assertEqual(r.status_code, 204)
        row = q1("SELECT * FROM probes WHERE id = ?", (probe["probe_id"],))
        self.assertEqual(row["status"], "disabled")
        self.assertIsNotNone(row["deregistered_at"])
        self.assertEqual(self.client.get("/api/probe/v1/config", headers=auth).status_code, 401)
        self.assertEqual(self.client.post("/api/probe/v1/deregister", headers=auth).status_code, 401)
        self.assertEqual(q("SELECT * FROM probe_commands WHERE delivered_at IS NULL"), [])
        self.assertTrue(q1("SELECT * FROM audit_log WHERE action = 'probe.deregister'"))
        # Reaktivieren im Web-UI geht nicht (kein gültiges Token mehr) – Neuinstallation registriert neu
        self.make_user()
        self.login()
        self.client.post(f"/probes/{probe['probe_id']}/status", data={"csrf_token": self.session_csrf(),
                                                                       "action": "enable"})
        self.assertEqual(q1("SELECT status FROM probes WHERE id = ?", (probe["probe_id"],))["status"], "disabled")
        html = self.client.get(f"/probes/{probe['probe_id']}?tab=details").get_data(as_text=True)
        self.assertIn("deinstalliert am", html)
        self.assertNotIn('value="enable"', html)   # kein Aktivieren-Knopf, der nur scheitern kann
        token = self.make_token(site, token="neu")
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": token, "hostname": "PC-weg"})
        self.assertEqual(r.get_json()["probe_id"], probe["probe_id"])
        row = q1("SELECT * FROM probes WHERE id = ?", (probe["probe_id"],))
        self.assertEqual((row["status"], row["deregistered_at"]), ("active", None))


class CheckStatusApiTest(AppTestCase):
    def test_lists_every_measurement(self):
        probe = self.enroll("PC-API")
        self.client.post("/api/probe/v1/heartbeat", headers={"Authorization": f"Bearer {probe['token']}"}, json={})
        repo.create_check("WAN", "speed.cloudflare.com", "reference", 3600, 90000, "all", None, "speedtest",
                          checktypes.merged("speedtest", {"schedule_min": 0}))
        self.make_user(role="readonly", username="leser")
        self.login("leser")
        with mock.patch("wachtl.services.vm.live_status", return_value={}):
            rows = self.client.get("/api/v1/check-status").get_json()
        self.assertEqual({r["type"] for r in rows}, {"ping", "path", "speedtest"})
        self.assertTrue(all(r["hostname"] == "PC-API" and r["online"] for r in rows))
        self.assertEqual({r["state"] for r in rows if r["type"] == "speedtest"}, {"waiting"})
        probes = self.client.get("/api/v1/probes").get_json()
        self.assertEqual(probes[0]["kind"], "probe")


class RecentOutageTest(AppTestCase):
    """Kurzer, längst behobener Ausfall: Zustand ist wieder „ok“, Übersicht muss ihn trotzdem zeigen."""

    def test_resolved_outage_visible(self):
        import json

        from wachtl.db import ins
        probe = self.enroll("SRV21FilePrint")
        pid = probe["probe_id"]
        cid = repo.create_check("d.velop AG", "185.87.179.244", "target", 1, 1000, "all", None, "ping",
                                checktypes.merged("ping", {}))
        now = repo.now()
        labels = {"alertname": "WachtlTargetDown", "probe": str(pid), "probe_name": "SRV21FilePrint",
                  "site": "1", "site_name": "Zentrale", "check_id": str(cid), "target": "185.87.179.244",
                  "role": "target"}
        ins("INSERT INTO alert_events (fingerprint, alertname, severity, status, labels, summary, starts_at, ends_at, "
            "updated_at, refined_at) VALUES ('f1', 'WachtlTargetDown', 'critical', 'resolved', ?, 'down', ?, ?, ?, ?)",
            (json.dumps(labels), now - 600, now - 575, now - 575, now))
        self.make_site("Filiale")                  # Übersicht gibt es ab zwei Standorten
        self.make_user()
        self.login()
        live = {(str(pid), str(cid)): {"up": 1, "rtt": 0.98, "loss": 0.0}}
        with mock.patch("wachtl.services.vm.live_status", return_value=live):
            html = self.client.get("/").get_data(as_text=True)
            self.assertIn("Ausfälle der letzten 24 Stunden", html)
            self.assertIn("185.87.179.244", html)
            self.assertIn(f"/probes/{pid}/checks/{cid}?at={now - 600}", html)
            site_html = self.client.get("/sites/1?tab=ereignisse").get_data(as_text=True)
            self.assertIn("Ausfälle der letzten 24 Stunden", site_html)
            self.assertIn("185.87.179.244", site_html)
            probe_html = self.client.get(f"/probes/{pid}").get_data(as_text=True)
            self.assertIn("1 Ausfall in 24 h", probe_html)
            self.assertIn("Ausfall vor", probe_html)
            # Verlauf: der gelbe Balken führt direkt in den Graphen zum Zeitpunkt des Ausfalls
            self.assertRegex(html, rf'<span class="hb-warn" title="[^"]*" data-href="/probes/{pid}/checks/{cid}\?at={now - 600}"')
            self.assertIn('href="/outages?site=1&amp;range=24h"', html)   # gleiche Liste per Tastatur
            # Zeitraum wählbar und gemerkt; Ausfall bleibt im längeren Verlauf sichtbar
            week = self.client.get("/?verlauf=7d").get_data(as_text=True)
            self.assertIn("Standorte – letzte 7 Tage", week)
            self.assertIn("je Balken 3 Stunden", week)
            self.assertIn('class="hb-warn"', week)
            self.assertIn("Standorte – letzte 7 Tage", self.client.get("/").get_data(as_text=True))
            self.assertIn("Ausfälle 7 Tage", self.client.get("/standorte").get_data(as_text=True))
            # Zeitfenster eines Balkens auf der Ausfallseite
            hit = self.client.get(f"/outages?site=1&from={now - 900}&to={now - 300}").get_data(as_text=True)
            self.assertIn("185.87.179.244", hit)
            miss = self.client.get(f"/outages?site=1&from={now - 7200}&to={now - 3600}").get_data(as_text=True)
            self.assertNotIn("185.87.179.244", miss)


class SiteHealthTest(AppTestCase):
    """Verlauf je Standort (Übersicht): Abschnitte nach schlimmster Ursache, gestörte Zeit ohne Doppelzählung."""

    def test_buckets_and_uptime(self):
        from wachtl.services.outages import Outage, site_health

        def outage(cause, start, end, site="1"):
            return Outage(id=0, cause=cause, probe="1", probe_name="p", site=site, site_name="s", target="",
                          check_id="", start=start, end=end, summary="")

        since, until = 0, 4800                                   # 4 Abschnitte à 1200 s
        items = [outage("wan", 100, 700), outage("probe", 500, 900),  # überlappend: 800 s gestört
                 outage("target", 2500, 2600), outage("wan", 0, 4800, site="2")]
        h = site_health(items, [{"id": 1, "created_at": 0}, {"id": 3, "created_at": 3000}], since, until, buckets=4)
        self.assertEqual(h[1]["cells"], ["down", "ok", "warn", "ok"])
        self.assertEqual(h[1]["down_s"], 800)
        self.assertAlmostEqual(h[1]["up"], 100 * (1 - 800 / 4800))
        self.assertEqual(h[3]["cells"], ["none", "none", "ok", "ok"])   # erst später angelegt
        self.assertEqual(h[3]["up"], 100)

    def test_overview_and_sidebar(self):
        self.enroll("PC-1")
        self.make_site("Filiale")                  # Übersicht gibt es ab zwei Standorten
        self.make_user()
        self.login()
        with mock.patch("wachtl.services.vm.live_status", return_value={}):
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn("Standorte – letzte 24 Stunden", html)
        self.assertEqual(html.count('<span class="hb-'), 2 * 48)       # je Standort 48 Balken
        self.assertIn('aria-label="Standorte"', html)                  # Standorte in der Seitenleiste
        self.assertRegex(html, r'<nav class="side-sites"[\s\S]*href="/sites/1"')
