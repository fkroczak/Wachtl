"""0.8.4: Oberfläche für Einsteiger – Einstellungen als Kacheln, Messungen zuordnen, Graphen, Ampel."""
import re
from unittest import mock

from wachtl import repo
from wachtl.db import q

from .helpers import AppTestCase


class AssignmentMatrixTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.site_a, self.site_b = self.make_site("Filiale A"), self.make_site("Filiale B")
        self.p = {}
        for name, site in (("A1", self.site_a), ("A2", self.site_a), ("B1", self.site_b), ("B2", self.site_b)):
            r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": self.make_token(site, token=f"tok-{name}"),
                                                             "hostname": f"PC-{name}", "os": "Windows 11", "version": "0.8.4"})
            self.p[name] = r.get_json()["probe_id"]
        self.make_user()
        self.login()
        self.drucker = repo.create_check("Drucker", "10.0.0.9", "target", 5, 1000, "probe", self.p["A1"])

    def form(self) -> dict:
        """Aktueller Stand der Seite: alle gesetzten Haken."""
        html = self.client.get("/admin/zuordnung").get_data(as_text=True)
        data = {"csrf_token": self.session_csrf()}
        for name in re.findall(r'<input type="checkbox" name="(a-\d+-\d+)"[^>]*\bchecked\b', html):
            data[name] = "on"
        return data

    def save(self, check_id, probes):
        data = {k: v for k, v in self.form().items() if not k.startswith(f"a-{check_id}-")}
        data.update({f"a-{check_id}-{self.p[n]}": "on" for n in probes})
        return self.client.post("/admin/zuordnung", data=data)

    def scopes(self, check_id):
        return sorted((a["scope"], a["scope_id"]) for a in q("SELECT scope, scope_id FROM check_assignments WHERE check_id = ?",
                                                             (check_id,)))

    def runs_on(self, check_id):
        return {n for n, pid in self.p.items()
                if check_id in [c["id"] for c in repo.checks_for_probe(q("SELECT * FROM probes WHERE id = ?", (pid,))[0])]}

    def test_page_shows_matrix(self):
        html = self.client.get("/admin/zuordnung").get_data(as_text=True)
        self.assertIn("Messungen zuordnen", html)
        self.assertIn(f'name="a-{self.drucker}-{self.p["A1"]}"', html)
        self.assertIn('aria-label="Drucker bei PC-A1"', html)
        self.assertRegex(html, rf'name="a-{self.drucker}-{self.p["A1"]}"[^>]*checked')
        self.assertNotRegex(html, rf'name="a-{self.drucker}-{self.p["A2"]}"[^>]*checked')

    def test_simplest_scope_is_chosen(self):
        before = {c["id"]: self.scopes(c["id"]) for c in q("SELECT id FROM checks") if c["id"] != self.drucker}
        self.assertEqual(self.save(self.drucker, ["A1", "A2"]).status_code, 302)
        self.assertEqual(self.scopes(self.drucker), [("site", self.site_a)])
        self.save(self.drucker, ["A1", "A2", "B1", "B2"])
        self.assertEqual(self.scopes(self.drucker), [("all", None)])
        self.save(self.drucker, ["A1", "A2", "B1"])
        self.assertEqual(self.scopes(self.drucker), [("all", None), ("exclude_probe", self.p["B2"])])
        self.save(self.drucker, ["A2", "B1"])
        self.assertEqual(self.scopes(self.drucker), [("probe", self.p["A2"]), ("probe", self.p["B1"])])
        self.assertEqual(self.runs_on(self.drucker), {"A2", "B1"})
        # die anderen Messungen bleiben, wie sie waren
        self.assertEqual({cid: self.scopes(cid) for cid in before}, before)
        self.assertEqual(q("SELECT action FROM audit_log WHERE action = 'check.assign'")[0]["action"], "check.assign")

    def test_no_pc_is_refused(self):
        r = self.save(self.drucker, [])
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.scopes(self.drucker), [("probe", self.p["A1"])])
        self.assertIn("mindestens ein PC", self.client.get("/admin/zuordnung").get_data(as_text=True))

    def test_only_admins(self):
        self.client.post("/logout", data={"csrf_token": self.session_csrf()})
        self.make_user("leser", "readonly")
        self.login("leser")
        self.assertEqual(self.client.get("/admin/zuordnung").status_code, 403)


class SettingsStartTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.make_user()
        self.login()

    def test_start_page_has_tiles_and_sections_work(self):
        html = self.client.get("/admin").get_data(as_text=True)
        for text in ("PCs hinzufügen", "Messungen zuordnen", "Benachrichtigungen", "Noch nicht eingerichtet"):
            self.assertIn(text, html)
        self.assertNotIn('id="checks"', html)                       # keine Riesen-Seite mehr
        self.assertIn('id="checks"', self.client.get("/admin?bereich=messungen").get_data(as_text=True))
        self.assertIn('id="benachrichtigungen"', self.client.get("/admin?bereich=alarme").get_data(as_text=True))

    def test_forms_return_to_their_section(self):
        r = self.client.post("/admin/sites", data={"csrf_token": self.session_csrf(), "name": "Lager"})
        self.assertEqual(r.headers["Location"], "/admin?bereich=standorte#standorte")


class GraphsAndStatusTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.make_user()
        self.login()
        p = mock.patch("wachtl.services.vm.live_status", return_value={})
        p.start()
        self.addCleanup(p.stop)

    def test_overview_without_pcs(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("Noch keine PCs", html)

    def test_overview_names_offline_pc_and_graphs_page(self):
        probe = self.enroll("PC-01")
        from wachtl.db import ex
        ex("UPDATE probes SET last_seen = ?", (repo.now() - 3600,))
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("status-banner bad", html)
        self.assertIn("meldet sich nicht mehr", html)
        self.assertIn('class="bad" href="/probes/', html)                    # roter PC im Standort
        graphs = self.client.get("/graphen").get_data(as_text=True)
        self.assertIn("Messungen von", graphs)
        self.assertIn(f'href="/probes/{probe["probe_id"]}/checks/', graphs)
        self.assertEqual(self.client.get(f"/graphen?probe={probe['probe_id']}").status_code, 200)
        self.assertEqual(self.client.get("/graphen?probe=999").status_code, 404)
        pc = self.client.get(f"/probes/{probe['probe_id']}").get_data(as_text=True)
        self.assertIn("meldet sich nicht mehr", pc)
        self.assertIn("Graph ansehen", pc)

    def test_ping_verdict(self):
        from wachtl import web
        cases = [({"median": 9.2, "loss": 0.1}, "ok"), ({"median": 9.2, "loss": 3.0}, "warn"),
                 ({"median": 150.0, "loss": 0.0}, "warn"), ({"median": 9.2, "loss": 20.0}, "bad"),
                 ({"median": None, "loss": 100.0}, "bad"), ({"median": None, "loss": None}, "none")]
        for stats, cls in cases:
            with mock.patch("wachtl.services.vm.ping_stats", return_value={"1h": stats}):
                self.assertEqual(web.ping_verdict(1, 1)["cls"], cls, stats)
