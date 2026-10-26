"""1.0: Switch-Topologie per SNMP – Sammeln, Baum, Befunde, Pfad, Assistent, Probe-API, Seiten."""
import json
import re
import unittest
from unittest import mock

from wachtl import repo, secretbox, snmp, snmpcollect
from wachtl.db import ex, ins, q, q1
from wachtl.serverprobe import topology as probe_topology
from wachtl.services import topology

from .helpers import AppTestCase
from .snmp_agent import FakeAgent
from .topo_fixtures import CORE_MAC, DESK, EG_MAC, GW_MAC, OG_MAC, PC1, PC2, PRN, core_mib, eg_mib, og_mib


def snap_of(mib: dict) -> dict:
    with FakeAgent(mib) as agent, snmp.Session("127.0.0.1", snmp.Credentials(), port=agent.port, timeout=1) as s:
        return topology.clean_snapshot(snmpcollect.collect(s))


SNAPS = {}


def snaps() -> dict:
    if not SNAPS:
        SNAPS.update(core=snap_of(core_mib()), eg=snap_of(eg_mib()), og=snap_of(og_mib()))
    return SNAPS


def rows(**extra) -> list[dict]:
    s = snaps()
    base = {"status": "active", "last_error": None, "location": None, "host": None, "name": None}
    return [{**base, "id": 1, "sys_name": "SW-Core-01", "host": "192.168.10.2", "snapshot": json.dumps(s["core"])},
            {**base, "id": 2, "sys_name": "SW-EG-01", "host": "192.168.10.3", "snapshot": json.dumps(s["eg"])},
            {**base, "id": 3, "sys_name": "SW-OG-01", "host": "192.168.10.4", "snapshot": json.dumps(s["og"])}]


DEVICES = {PC1: {"mac": PC1, "ip": "192.168.10.41", "label": "PC-Empfang-01", "hostname": "PC-Empfang-01"},
           GW_MAC: {"mac": GW_MAC, "ip": "192.168.10.1", "label": "Firewall", "hostname": "firewall"},
           PC2: {"mac": PC2, "ip": "192.168.10.73", "label": "PC-OG-03"}}


class CollectTest(unittest.TestCase):
    def test_collect_reads_standard_mibs(self):
        s = snaps()["eg"]
        self.assertEqual(s["system"]["name"], "SW-EG-01")
        self.assertEqual(s["system"]["uptime_s"], 360000)
        self.assertEqual(s["base_mac"], EG_MAC)
        ports = {i["index"]: i for i in s["interfaces"]}
        self.assertEqual(ports[25]["speed_mbps"], 10000)
        self.assertEqual(ports[7]["speed_mbps"], 100)
        self.assertEqual(ports[4]["duplex"], "full")
        self.assertIn({"mac": PC1, "if_index": 4, "vlan": None}, s["fdb"])
        self.assertEqual(s["lldp"][0]["if_index"], 25)
        self.assertEqual(s["lldp"][0]["sys_name"], "SW-Core-01")
        self.assertEqual(s["lldp"][0]["mgmt_ip"], "192.168.10.2")
        self.assertTrue(s["lldp"][0]["bridge"])
        self.assertEqual(s["poe"]["ports"], [4])
        self.assertEqual(s["pvid"]["4"], 10)
        self.assertEqual(snaps()["core"]["gateway"], "192.168.10.1")
        self.assertEqual(snmpcollect.summary(s)["ports"], 4)

    def test_probe_poll_reports_errors_without_raising(self):
        with FakeAgent(og_mib()) as agent:
            ok = probe_topology.poll({"switch_id": 3, "host": "127.0.0.1", "port": agent.port,
                                      "credentials": {"version": "2c", "community": "public"}})
            bad = probe_topology.poll({"switch_id": 3, "host": "127.0.0.1", "port": agent.port,
                                       "credentials": {"version": "2c", "community": "falsch"}})
        self.assertEqual(ok["snapshot"]["system"]["name"], "SW-OG-01")
        self.assertIn("Zeitüberschreitung", bad["error"])


class AnalyzeTest(unittest.TestCase):
    def test_tree_from_lldp_mac_tables_and_gateway(self):
        t = topology.analyze(rows(), DEVICES, {(2, 4): 1204})
        n = t.nodes
        self.assertEqual(t.roots, ["internet"])
        self.assertEqual(n["gw"].parent, "internet")
        self.assertEqual(n["s1"].parent, "gw")
        self.assertEqual(n["s2"].parent, "s1")
        self.assertEqual(n["s2"].link.via, "lldp")
        self.assertEqual(n["s3"].parent, "s1")                      # nur über die MAC-Tabellen gefunden
        self.assertEqual(n["s3"].link.via, "mac")
        self.assertEqual(topology.link_label(t, n["s2"]), "P1 ⇄ P25 · 10G")
        self.assertEqual(topology.link_label(t, n["s3"]), "P3 ⇄ P15 · 100M")
        # Geräte am Zugangs-Port, nicht an den Uplinks
        self.assertEqual(t.locations[PC1], (2, 4))
        self.assertEqual(t.locations[PC2], (3, 1))
        self.assertEqual(t.locations[PRN], (2, 7))
        unmanaged = [x for x in n.values() if x.kind == "unmanaged"]
        self.assertEqual(len(unmanaged), 1)
        self.assertEqual(unmanaged[0].parent, "s2")
        self.assertEqual({d["mac"] for d in unmanaged[0].devices}, set(DESK))
        ports = t.switches[2]["ports"]
        self.assertEqual(ports[25].role, "uplink")
        self.assertEqual(ports[4].role, "access")
        self.assertEqual(ports[4].state, "err")
        self.assertTrue(ports[4].poe)
        kinds = {f["kind"] for f in t.findings}
        self.assertEqual(kinds, {"port_errors", "slow_link", "unmanaged"})
        err = next(f for f in t.findings if f["kind"] == "port_errors")
        self.assertEqual(err["severity"], "critical")
        self.assertIn("PC-Empfang-01", err["detail"])

    def test_path_and_layout(self):
        t = topology.analyze(rows(), DEVICES, {(2, 4): 1204})
        p = topology.path_for(t, PC2)
        self.assertEqual([h["label"] for h in p["hops"]], ["PC-OG-03", "SW-OG-01", "SW-Core-01", "Firewall", "Internet"])
        self.assertEqual(p["hops"][1]["in"], "1")
        self.assertEqual(p["hops"][1]["out"], "15")
        self.assertEqual(p["bottleneck"], 100)
        self.assertEqual([h["mac"] for h in topology.find_device(t, "pc-og")], [PC2])
        self.assertEqual([h["mac"] for h in topology.find_device(t, PC1.lower())], [PC1])
        lay = topology.layout(t)
        self.assertEqual(len(lay["boxes"]), len(t.nodes))
        self.assertTrue(all(b["x"] >= 0 for b in lay["boxes"]))
        self.assertGreater(lay["height"], 300)

    def test_without_gateway_root_is_best_connected_and_unreachable_switch(self):
        r = rows()
        r[2] = {**r[2], "last_error": "Keine Antwort", "snapshot": None}
        r[0] = {**r[0], "snapshot": json.dumps({**snaps()["core"], "gateway": None})}
        t = topology.analyze(r, {k: v for k, v in DEVICES.items() if k != GW_MAC})
        self.assertEqual(t.roots[0], "s1")
        self.assertEqual(t.nodes["s3"].status, "bad")
        self.assertIn("unreachable", {f["kind"] for f in t.findings})
        self.assertIn("s3", t.roots)                              # nicht verbunden: eigener Baum

    def test_faceplate_rows(self):
        ports = {i: topology.Port(i, f"Gi1/0/{i}", str(i), None, None, 6, 1000, True, True, "full", True,
                                  False) for i in range(1, 9)}
        ports[9] = topology.Port(9, "Te1/1/1", "1/1/1", None, None, 6, 10000, True, True, "full", True, True)
        blk = topology.faceplate(ports)[0]
        self.assertEqual([p.index for p in blk["top"]], [1, 3, 5, 7])
        self.assertEqual([p.index for p in blk["bottom"]], [2, 4, 6, 8])
        self.assertEqual([p.index for p in blk["sfp"]], [9])
        self.assertEqual(topology.port_short("GigabitEthernet1/0/24"), "1/0/24")


class CredentialsTest(AppTestCase):
    def test_parse_and_keep_secrets(self):
        c, e = topology.parse_credentials({"snmp_version": "2c", "community": "geheim"})
        self.assertEqual((c["version"], c["community"], e), ("2c", "geheim", []))
        c, e = topology.parse_credentials({"snmp_version": "2c"}, {"version": "2c", "community": "alt"})
        self.assertEqual(c["community"], "alt")
        c, e = topology.parse_credentials({"snmp_version": "3", "user": "wachtl", "sec_level": "authPriv",
                                           "auth_proto": "sha256", "auth_key": "kurz", "priv_proto": "aes256"})
        self.assertEqual({x.field for x in e}, {"auth_key", "priv_key"})
        c, e = topology.parse_credentials({"snmp_version": "3", "user": "wachtl", "sec_level": "authNoPriv",
                                           "auth_proto": "md5", "auth_key": "12345678"})
        self.assertEqual((c["priv_proto"], e), ("none", []))
        self.assertEqual(topology.credential_hint(c), "SNMPv3, Benutzer wachtl, MD5 (veraltet)")
        token = secretbox.seal(c)
        self.assertNotIn("12345678", token)
        self.assertEqual(secretbox.unseal(token), c)
        with self.assertRaises(secretbox.SecretError):
            secretbox.unseal(token, secret_key="anderer-schluessel")


class TopologyAppTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.make_user()
        self.login()
        self.site = self.make_site("Hauptsitz")
        self.agents = [FakeAgent(core_mib()).start(), FakeAgent(eg_mib(), community="eg-lesen").start(),
                       FakeAgent(og_mib(), users={"wachtl": ("sha256", "auth-passwort", "aes", "priv-passwort")},
                                 v2c=False).start()]
        for a in self.agents:
            self.addCleanup(a.stop)
        for mac, ip, name in ((PC1, "192.168.10.41", "pc-empfang-01"), (GW_MAC, "192.168.10.1", "firewall")):
            ins("INSERT INTO net_devices (site_id, dev_key, mac, ip, hostname, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (self.site, f"mac:{mac}", mac, ip, name, repo.now(), repo.now()))

    def add(self, port, **form):
        data = {"csrf_token": self.session_csrf(), "host": "127.0.0.1", "port": str(port), **form}
        r = self.client.post(f"/sites/{self.site}/topologie/switche/neu", data=data)
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:2000])
        sid = int(re.search(r"/switche/(\d+)/pruefen", r.headers["Location"]).group(1))
        page = self.client.get(r.headers["Location"]).get_data(as_text=True)
        return sid, page

    def test_wizard_all_versions_pages_and_api(self):
        core, eg, og = self.agents
        sid1, page = self.add(core.port, name="Core", snmp_version="2c", community="public")
        self.assertIn("Verbindung klappt", page)
        self.assertIn("SW-Core-01", page)
        row = q1("SELECT * FROM net_switches WHERE id = ?", (sid1,))
        self.assertEqual(row["status"], "draft")
        self.assertNotIn("public", row["secret"])                 # verschlüsselt gespeichert
        r = self.client.post(f"/sites/{self.site}/topologie/switche/{sid1}/aktivieren",
                             data={"csrf_token": self.session_csrf(), "next": "neu"})
        self.assertIn(f"wie={sid1}", r.headers["Location"])
        self.assertEqual(q1("SELECT status FROM net_switches WHERE id = ?", (sid1,))["status"], "active")
        # zweiter Switch: falsche Community → Test schlägt fehl, Hinweise; dann korrigieren
        with mock.patch.object(snmp, "Session", lambda h, c, port=161, timeout=2, retries=1: _fast_session(h, c, port)):
            sid2, page = self.add(eg.port, snmp_version="2c", community="falsch")
        self.assertIn("Test fehlgeschlagen", page)
        self.assertIn("Zeitüberschreitung", page)
        r = self.client.post(f"/sites/{self.site}/topologie/switche/{sid2}/zugang",
                             data={"csrf_token": self.session_csrf(), "host": "127.0.0.1", "port": str(eg.port),
                                   "snmp_version": "2c", "community": "eg-lesen"})
        page = self.client.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("Verbindung klappt", page)
        self.client.post(f"/sites/{self.site}/topologie/switche/{sid2}/aktivieren", data={"csrf_token": self.session_csrf()})
        # dritter Switch mit SNMPv3 (SHA-256/AES)
        sid3, page = self.add(og.port, snmp_version="3", user="wachtl", sec_level="authPriv", auth_proto="sha256",
                              auth_key="auth-passwort", priv_proto="aes", priv_key="priv-passwort")
        self.assertIn("Verbindung klappt", page, page[:3000])
        self.client.post(f"/sites/{self.site}/topologie/switche/{sid3}/aktivieren", data={"csrf_token": self.session_csrf()})
        audit = " ".join(r["detail"] or "" for r in q("SELECT detail FROM audit_log"))
        for secret in ("public", "eg-lesen", "auth-passwort", "priv-passwort"):
            self.assertNotIn(secret, audit)

        # Seiten
        tree = self.client.get(f"/sites/{self.site}/topologie").get_data(as_text=True)
        for text in ("Core", "SW-EG-01", "SW-OG-01", "firewall", "Internet", "P1 ⇄ P25 · 10G", "Nicht verwalteter"):
            self.assertIn(text, tree)
        self.assertEqual(self.client.get(f"/sites/{self.site}?tab=topologie").status_code, 302)
        cards = self.client.get(f"/sites/{self.site}/topologie/switche").get_data(as_text=True)
        self.assertIn("Aufschalten", cards)
        detail = self.client.get(f"/sites/{self.site}/topologie/switche/{sid2}?port=4").get_data(as_text=True)
        self.assertIn("pc-empfang-01", detail)
        self.assertIn("Port 4", detail)
        problems = self.client.get(f"/sites/{self.site}/topologie/probleme").get_data(as_text=True)
        self.assertIn("nur 100 Mbit/s", problems)
        self.assertIn("Nicht verwalteter Switch an SW-EG-01", problems)
        path = self.client.get(f"/sites/{self.site}/topologie/pfad?geraet=pc-empfang").get_data(as_text=True)
        self.assertIn("raus Port 25", path)
        self.assertIn("Engstelle 1 Gbit/s", path)
        self.assertEqual(self.client.get(f"/sites/{self.site}/topologie/switche/neu").status_code, 200)
        self.assertEqual(self.client.get(f"/sites/{self.site}/topologie/switche/{sid3}/zugang").status_code, 200)

        # Probe-API: nur die Server-Probe bekommt Aufträge mit Zugangsdaten
        win = self.enroll("PC-01")
        r = self.client.get("/api/probe/v1/topology/jobs", headers={"Authorization": f"Bearer {win['token']}"})
        self.assertEqual(r.status_code, 403)
        ex("UPDATE probes SET kind = 'server' WHERE id = ?", (win["probe_id"],))
        auth = {"Authorization": f"Bearer {win['token']}"}
        ex("UPDATE net_switches SET last_poll = ?", (repo.now() - 3600,))
        jobs = self.client.get("/api/probe/v1/topology/jobs", headers=auth).get_json()["jobs"]
        self.assertEqual(len(jobs), 3)
        v3 = next(j for j in jobs if j["switch_id"] == sid3)
        self.assertEqual(v3["credentials"]["auth_key"], "auth-passwort")
        # Ergebnis mit neuen Port-Fehlern und Fehlerergebnis
        with FakeAgent(eg_mib(errors=1500), community="eg-lesen") as agent2:
            result = probe_topology.poll({**next(j for j in jobs if j["switch_id"] == sid2), "port": agent2.port})
        r = self.client.post("/api/probe/v1/results/topology", json=result, headers=auth)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(q1("SELECT SUM(errors) AS n FROM net_port_errors")["n"], 1500)
        r = self.client.post("/api/probe/v1/results/topology", headers=auth,
                             json={"switch_id": sid1, "error": "Keine Antwort von 127.0.0.1"})
        self.assertEqual(r.status_code, 201)
        active = {f["kind"] for f in q("SELECT kind FROM net_topo_findings WHERE active = TRUE")}
        self.assertTrue({"port_errors", "unreachable", "slow_link", "unmanaged"} <= active, active)
        problems = self.client.get(f"/sites/{self.site}/topologie/probleme").get_data(as_text=True)
        self.assertIn("Core antwortet nicht auf SNMP", problems)
        self.assertIn("1.500 fehlerhafte Pakete", problems)
        self.assertEqual(self.client.post("/api/probe/v1/results/topology", headers=auth,
                                          json={"switch_id": 999}).status_code, 422)
        # Befund bestätigen, Switch löschen
        fid = q1("SELECT id FROM net_topo_findings WHERE kind = 'unmanaged'")["id"]
        self.client.post(f"/sites/{self.site}/topologie/probleme/{fid}/bekannt", data={"csrf_token": self.session_csrf()})
        self.assertIsNotNone(q1("SELECT ack_at FROM net_topo_findings WHERE id = ?", (fid,))["ack_at"])
        self.client.post(f"/sites/{self.site}/topologie/switche/{sid3}/loeschen", data={"csrf_token": self.session_csrf()})
        self.assertIsNone(q1("SELECT id FROM net_switches WHERE id = ?", (sid3,)))

    def test_validation_and_roles(self):
        r = self.client.post(f"/sites/{self.site}/topologie/switche/neu",
                             data={"csrf_token": self.session_csrf(), "host": "kein host!", "snmp_version": "3",
                                   "user": "", "sec_level": "authPriv", "auth_proto": "sha", "priv_proto": "aes"})
        self.assertEqual(r.status_code, 422)
        page = r.get_data(as_text=True)
        self.assertIn('role="alert"', page)
        for f in ("host", "user", "auth_key", "priv_key"):
            self.assertIn(f'href="#f-{f}"', page)
        self.assertEqual(self.client.get(f"/sites/{self.site}/topologie").status_code, 200)   # leer: Einstieg
        self.client.post("/logout", data={"csrf_token": self.session_csrf()})
        self.make_user("leser", "readonly")
        self.login("leser")
        self.assertEqual(self.client.get(f"/sites/{self.site}/topologie").status_code, 200)
        self.assertEqual(self.client.get(f"/sites/{self.site}/topologie/switche/neu").status_code, 403)


def _fast_session(host, creds, port):
    return _ORIG_SESSION(host, creds, port=port, timeout=0.3, retries=0)


_ORIG_SESSION = snmp.Session


class TopologyPagesLintTest(AppTestCase):
    """Alle Seiten der Topologie bestehen dieselben Prüfungen wie die übrigen Seiten (test_ui_quality.lint)."""

    def test_pages_pass_lint(self):
        from .test_ui_quality import lint

        self.make_user()
        self.login()
        site = self.make_site("Zentrale")
        ts = repo.now()
        ids = []
        for n, (name, snap) in enumerate((("SW-Core-01", snaps()["core"]), ("SW-EG-01", snaps()["eg"]),
                                          ("SW-OG-01", snaps()["og"])), 2):
            ids.append(ins("INSERT INTO net_switches (site_id, name, host, port, snmp_version, secret, status, last_poll, "
                           "last_ok, sys_name, snapshot, created_at, updated_at) VALUES (?, ?, ?, 161, '2c', ?, 'active', "
                           "?, ?, ?, ?, ?, ?)", (site, None, f"192.168.10.{n}", secretbox.seal({"version": "2c",
                           "community": "x"}), ts, ts, name, json.dumps(snap), ts, ts)))
        ins("INSERT INTO net_port_errors (switch_id, if_index, ts, errors) VALUES (?, 4, ?, 900)", (ids[1], ts))
        ins("INSERT INTO net_switches (site_id, host, port, snmp_version, secret, status, created_at, updated_at) "
            "VALUES (?, '192.168.10.9', 161, '3', ?, 'draft', ?, ?)", (site, secretbox.seal({"version": "3"}), ts, ts))
        for mac, ip, host in ((PC1, "192.168.10.41", "pc-empfang-01"), (GW_MAC, "192.168.10.1", "firewall")):
            ins("INSERT INTO net_devices (site_id, dev_key, mac, ip, hostname, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (site, f"mac:{mac}", mac, ip, host, ts, ts))
        topology.refresh_findings(site, ts)
        base = f"/sites/{site}/topologie"
        pages = [base, f"{base}?switch={ids[1]}", f"{base}?geraete=0", f"{base}/switche", f"{base}/probleme",
                 f"{base}/pfad", f"{base}/pfad?geraet=pc", f"{base}/pfad?geraet=pc-empfang-01",
                 f"{base}/switche/{ids[1]}", f"{base}/switche/{ids[1]}?port=4", f"{base}/switche/neu",
                 f"{base}/switche/{ids[0]}/zugang", f"{base}/switche/neu?host=192.168.10.20&wie={ids[0]}"]
        failures = {}
        for url in pages:
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, url)
            if problems := lint(r.get_data(as_text=True)):
                failures[url] = problems
        r = self.client.post(f"{base}/switche/neu", data={"csrf_token": self.session_csrf(), "host": "",
                                                          "snmp_version": "2c"})
        if problems := lint(r.get_data(as_text=True)):
            failures["Assistent mit Fehlern"] = problems
        with mock.patch.object(snmp, "Session", side_effect=snmp.SnmpTimeout("Keine Antwort (Test)")):
            r = self.client.get(f"{base}/switche/{ids[2]}/pruefen")
        self.assertIn("Test fehlgeschlagen", r.get_data(as_text=True))
        if problems := lint(r.get_data(as_text=True)):
            failures["Test fehlgeschlagen"] = problems
        self.client.post("/logout", data={"csrf_token": self.session_csrf()})
        self.assertEqual(failures, {}, json.dumps(failures, indent=1, ensure_ascii=False))
        empty = self.make_site("Leer")
        self.login()
        for url in (f"/sites/{empty}/topologie", f"/sites/{empty}/topologie/switche", f"/sites/{empty}/topologie/probleme"):
            self.assertEqual(lint(self.client.get(url).get_data(as_text=True)), [], url)


class AuditRegressionTest(AppTestCase):
    """Befunde aus dem UI-Audit 2026-10-26 (Topologie)."""

    def setUp(self):
        super().setUp()
        self.make_user()
        self.login()
        self.site = self.make_site("Hauptsitz")
        ts = repo.now()
        self.cand = {}
        for name, ip, access in (("SW-Snmp", "192.168.10.30", "snmp"), ("SW-Easy", "192.168.10.31", "easysmart")):
            self.cand[access] = ins(
                "INSERT INTO net_switch_candidates (site_id, cand_key, ip, name, access, sources, confidence, first_seen, "
                "last_seen) VALUES (?, ?, ?, ?, ?, '[]', 95, ?, ?)", (self.site, f"ip:{ip}", ip, name, access, ts, ts))
        self.sw = ins("INSERT INTO net_switches (site_id, name, host, port, snmp_version, secret, status, access, "
                      "created_at, updated_at) VALUES (?, 'Core', '127.0.0.1', 161, '2c', ?, 'active', 'snmp', ?, ?)",
                      (self.site, secretbox.seal({"community": "public"}), ts, ts))

    def test_wizard_offers_other_switches_only_for_same_access(self):
        html = self.client.get(f"/sites/{self.site}/topologie/switche/neu").get_data(as_text=True)
        snmp_li = re.search(r'<li data-show-if="access:snmp">.*?</li>', html, re.S)
        easy_li = re.search(r'<li data-show-if="access:easysmart" hidden>.*?</li>', html, re.S)
        self.assertIsNotNone(snmp_li)
        self.assertIsNotNone(easy_li)                     # SNMP gewählt → Easy-Smart-Fund ausgeblendet
        self.assertIn("disabled", easy_li.group(0))       # … und wird nicht mitgeschickt
        self.assertNotIn("disabled", snmp_li.group(0))
        self.assertNotIn(">Switch hinzufügen</a>", html)  # kein Knopf auf die eigene Seite
        # Speichern übernimmt nur Funde mit derselben Zugangsart, auch wenn beide angehakt wurden
        from wachtl import web_topology

        auch = f"{self.cand['snmp']},{self.cand['easysmart']}"
        with mock.patch.object(web_topology, "_test", return_value=(None, "Keine Antwort.")) as test:
            r = self.client.post(f"/sites/{self.site}/topologie/switche/{self.sw}/aktivieren",
                                 data={"csrf_token": self.session_csrf(), "auch": auch})
        self.assertEqual(test.call_count, 1)              # nur SW-Snmp getestet
        page = self.client.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("Nicht übernommen (Zugangsdaten passen nicht oder keine Antwort): SW-Snmp", page)
        self.assertNotIn("SW-Easy", page)

    def test_poll_keeps_port_and_names_missing_server_probe(self):
        r = self.client.post(f"/sites/{self.site}/topologie/switche/{self.sw}/abfragen",
                             data={"csrf_token": self.session_csrf(), "port": "4", "verlauf": "7d"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("port=4", r.headers["Location"])
        self.assertIn("verlauf=7d", r.headers["Location"])
        page = self.client.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("Server-Probe ist nicht eingerichtet; die Abfrage läuft erst", page)
        self.assertNotIn("gerade nicht erreichbar", page)
