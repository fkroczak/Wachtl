"""Regressionen aus dem UI-Audit 2026-10-26: Anmeldung, Tokens, Alarme, Audit-Log, Störungen."""
import re
from unittest import mock

from wachtl import repo
from wachtl.db import ins

from .helpers import AppTestCase


class UiAuditTest(AppTestCase):
    def setUp(self):
        super().setUp()
        p = mock.patch("wachtl.services.vm.live_status", return_value={})
        p.start()
        self.addCleanup(p.stop)
        self.make_user()

    def test_failed_login_keeps_username_and_shows_error_in_form(self):
        r = self.client.post("/login", data={"username": "admin", "password": "falsch", "csrf_token": self.csrf()})
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn('value="admin"', html)
        login = html[html.index('<div class="login">'):]
        self.assertIn('<div class="flash error" role="alert" id="login-error">', login)
        self.assertRegex(html, r'type="password"[^>]*autofocus aria-describedby="login-error"')

    def test_login_redirect_has_no_stray_question_mark(self):
        loc = self.client.get("/alerts").headers["Location"]
        self.assertTrue(loc.endswith("next=/alerts"), loc)
        loc = self.client.get("/meldungen?status=all").headers["Location"]
        self.assertIn("status", loc)

    def test_token_revoke_asks_and_creator_never_none(self):
        self.login()
        self.make_token(self.make_site())
        html = self.client.get("/admin?tab=standorte").get_data(as_text=True)
        self.assertRegex(html, r'data-confirm="Token für Zentrale widerrufen\?[^"]*"[^>]*>Widerrufen<')
        self.assertNotIn(">None<", html)

    def test_alert_history_is_paged(self):
        self.login()
        for i in range(60):
            ins("INSERT INTO alert_events (fingerprint, alertname, severity, status, labels, summary, starts_at, ends_at, "
                "updated_at) VALUES (?, 'WachtlTest', 'critical', 'resolved', '{}', ?, ?, ?, ?)",
                (f"fp{i}", f"Alarm {i}", 1000 + i, 2000 + i, 2000 + i))
        html = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("60 beendete Alarme · Seite 1 von 2", html)
        self.assertIn("Kritisch", html)
        self.assertEqual(len(re.findall(r"Alarm \d+<", html)), 50)
        self.assertIn('href="/alerts?page=2"', html)
        self.assertEqual(len(re.findall(r"Alarm \d+<", self.client.get("/alerts?page=2").get_data(as_text=True))), 10)

    def test_audit_log_labels_and_login_filter(self):
        self.login()
        repo.audit("admin", "check.create", "check:1")
        html = self.client.get("/admin/audit").get_data(as_text=True)
        self.assertIn('title="check.create">Check angelegt<', html)
        self.assertIn('title="login">Anmeldung<', html)
        self.assertIn('aria-current="page">Audit-Log<', html)
        html = self.client.get("/admin/audit?ohne_anmeldungen=1").get_data(as_text=True)
        self.assertNotIn('title="login"', html)
        self.assertIn("Check angelegt", html)

    def test_outage_range_has_readable_labels(self):
        self.login()
        html = self.client.get("/outages").get_data(as_text=True)
        self.assertIn('<option value="7d" selected>Letzte 7 Tage</option>', html)
