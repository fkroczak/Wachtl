"""Geführte Einrichtung: Standort, Messungen, Alarmierung und Token in einem Durchgang."""
from wachtl import standardpaket
from wachtl.db import q, q1
from wachtl.services import notify

from .helpers import AppTestCase


class SetupWizardTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.app.config["PUBLIC_URL"] = "https://wachtl.kunde.de"
        self.make_user()
        self.login()
        self.checks_before = len(q("SELECT id FROM checks"))

    def post(self, **data):
        base = {"csrf_token": self.session_csrf(), "site_id": "new", "site_name": "Zentrale", "scope": "all",
                "items": [i.key for i in standardpaket.ITEMS], "max_uses": "25", "days": "30"}
        return self.client.post("/admin/einrichtung", data={**base, **data})

    def test_seite_mit_standards(self):
        html = self.client.get("/admin/einrichtung").get_data(as_text=True)
        self.assertIn("1 · Standort", html)
        self.assertIn('value="25"', html)
        self.assertIn("Speedtest Internet", html)

    def test_alles_in_einem_durchgang(self):
        r = self.post(email_to="it@kunde.de", email_from="wachtl@kunde.de", smtp_smarthost="mail.kunde.de:587")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Enrollment-Token für Zentrale", r.get_data(as_text=True))
        site = q1("SELECT * FROM sites WHERE name = 'Zentrale'")
        self.assertGreater(len(q("SELECT id FROM checks")), self.checks_before)
        token = q1("SELECT * FROM enrollment_tokens WHERE site_id = ?", (site["id"],))
        self.assertEqual(token["max_uses"], 25)
        self.assertEqual(notify.get_settings()["email_to"], "it@kunde.de")

    def test_fehler_legt_nichts_an(self):
        # E-Mail ohne SMTP-Server und ein Proxy ohne Schema: nichts darf halb angelegt werden
        r = self.post(email_to="it@kunde.de", proxy="proxy:3128")
        html = r.get_data(as_text=True)
        self.assertIn("SMTP-Server", html)
        self.assertIn("Proxy bitte mit Schema", html)
        self.assertIn('id="f-smtp_smarthost-error"', html)          # Fehler steht am Feld
        self.assertIn('value="Zentrale"', html)          # Eingaben bleiben erhalten
        self.assertIsNone(q1("SELECT id FROM sites"))
        self.assertEqual(len(q("SELECT id FROM checks")), self.checks_before)
        self.assertIsNone(q1("SELECT id FROM enrollment_tokens"))

    def test_vorhandener_standort_und_doppelter_name(self):
        sid = self.make_site("Lager")
        self.assertIn("gibt es schon", self.post(site_name="Lager").get_data(as_text=True))
        r = self.post(site_id=str(sid), site_name="", scope="site", items=["speedtest_wan"], max_uses="3")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(q("SELECT id FROM sites")), 1)
        self.assertEqual(q1("SELECT scope, scope_id FROM check_assignments WHERE scope = 'site'"),
                         {"scope": "site", "scope_id": sid})

    def test_nur_admin(self):
        self.assertEqual(self.app.test_client().get("/admin/einrichtung").status_code, 302)
