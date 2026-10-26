"""Regressionstests aus dem UI-Audit 2026-10-26: Navigation, Zählweisen, Zustandswörter."""
from __future__ import annotations

import re

from wachtl import repo
from wachtl.db import ex, q1

from .helpers import AppTestCase


class UiAuditTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.make_user()
        self.pid = self.enroll()["probe_id"]
        self.sid = q1("SELECT site_id FROM probes WHERE id = ?", (self.pid,))["site_id"]
        self.make_site("Filiale")                     # zwei Standorte: Menüpunkt „Standorte“ ist sichtbar
        self.login()

    def active_nav(self, url: str) -> str:
        html = self.client.get(url).get_data(as_text=True)
        nav = html.split('aria-label="Hauptnavigation"')[1].split("</nav>")[0]
        hits = re.findall(r'<a href="[^"]*" class="active" aria-current="page"><svg[^>]*>.*?</svg>([^<]+)', nav)
        return hits[0] if hits else ""

    def test_subpages_mark_their_menu_item(self):
        self.assertEqual(self.active_nav(f"/probes/{self.pid}"), "Probes")
        self.assertEqual(self.active_nav(f"/sites/{self.sid}"), "Standorte")
        self.assertEqual(self.active_nav("/admin/audit"), "Verwaltung")
        self.assertEqual(self.active_nav("/admin/checks/new/ping"), "Verwaltung")
        self.assertEqual(self.active_nav("/admin/einrichtung"), "Verwaltung")

    def test_offline_probe_counts_as_one_problem_on_sites_page(self):
        n_checks = len(repo.checks_for_probe(q1("SELECT * FROM probes WHERE id = ?", (self.pid,))))
        self.assertGreater(n_checks, 1)                 # sonst prüft der Test nichts
        ex("UPDATE probes SET last_seen = ? WHERE id = ?", (repo.now() - 3600, self.pid))
        html = self.client.get("/standorte").get_data(as_text=True)
        tile = html.split("<main")[1].split(f'href="/sites/{self.sid}"')[1].split("</li>")[0]
        self.assertRegex(tile, r"<dt>Probleme</dt><dd[^>]*>1</dd>")

    def test_ping_tab_uses_same_state_words_as_elsewhere(self):
        html = self.client.get(f"/probes/{self.pid}?tab=ping").get_data(as_text=True)
        self.assertIn('<span class="dot stale"></span> keine Daten', html)
        self.assertNotIn("dot unknown", html)

    def test_site_without_probe_is_not_monitored(self):
        fid = q1("SELECT id FROM sites WHERE name = 'Filiale'")["id"]
        html = self.client.get("/standorte").get_data(as_text=True)
        tile = html.split("<main")[1].split(f'href="/sites/{fid}"')[1].split("</li>")[0]
        self.assertIn("nicht überwacht", tile)
        self.assertNotIn("ohne Störung", tile)
        self.assertNotIn('class="hb-ok"', tile)
