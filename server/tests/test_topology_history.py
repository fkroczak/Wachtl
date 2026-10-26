"""1.0: Verlauf der Switch-Topologie – schnelle Abfrage, Ereignisse, gespeicherte Stände, Zeitreise, Seiten."""
import json
import unittest
from unittest import mock

from wachtl import repo, secretbox
from wachtl.db import ex, ins, q, q1
from wachtl.services import topo_history, topology

from .helpers import AppTestCase
from .test_topology import snaps
from .test_ui_quality import lint
from .topo_fixtures import CORE_MAC, GW_MAC, PC1, PC2


class PureTest(unittest.TestCase):
    def test_lane_replays_events_backwards(self):
        start, end = 0, 1000
        evs = [{"ts": 950, "kind": "link_up", "data_obj": {}}, {"ts": 650, "kind": "link_down", "data_obj": {}},
               {"ts": 450, "kind": "port_errors", "data_obj": {}}, {"ts": 250, "kind": "link_flap", "data_obj": {}},
               {"ts": 120, "kind": "speed_changed", "data_obj": {"from": 100, "to": 1000}}]
        cells = topo_history.lane(evs, True, 1000, start, end, 10)
        self.assertEqual(cells, ["ln-100", "ln-1", "ln-flap", "ln-1", "ln-err", "ln-1", "ln-down", "ln-down",
                                 "ln-down", "ln-down"])
        self.assertEqual(topo_history.lane([], False, None, 0, 100, 2), ["ln-down", "ln-down"])
        self.assertEqual(topo_history.lane([], True, 10000, 0, 100, 2, since=60), ["ln-none", "ln-10"])

    def test_change_time_and_important_ports(self):
        self.assertEqual(topo_history._change_ts(1000, 500, 480), 980)
        self.assertEqual(topo_history._change_ts(1000, None, 480), 1000)
        self.assertEqual(topo_history._change_ts(1000, 500, 900), 1000)        # unplausibel
        snap = snaps()["eg"]
        self.assertEqual(topo_history.important_ports(snap, {CORE_MAC}), {25})
        a = topo_history._structure(snap)
        b = json.loads(json.dumps(snap))
        b["interfaces"][0]["in_errors"] = 999                                    # Zähler ändern den Aufbau nicht
        self.assertEqual(topo_history._structure(b), a)
        b["interfaces"][0]["oper_up"] = False
        self.assertNotEqual(topo_history._structure(b), a)
        self.assertEqual(topo_history._unpack(topo_history._pack(snap)), snap)


def quick(snap: dict, uptime: int, **ports) -> dict:
    """Schnelle Abfrage aus einer vollständigen: ports = {ifIndex: dict mit Änderungen}."""
    out = []
    for i in snap["interfaces"]:
        d = {"index": i["index"], "admin_up": True, "oper_up": i["oper_up"], "speed_mbps": i["speed_mbps"],
             "in_errors": i["in_errors"] or 0, "last_change_s": 100}
        d.update(ports.get(f"p{i['index']}", {}))
        out.append(d)
    return {"system": {"uptime_s": uptime}, "interfaces": out}


class HistoryAppTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.make_user()
        self.login()
        self.site = self.make_site("Hauptsitz")
        self.t0 = repo.now() - 7200
        secret = secretbox.seal({"version": "2c", "community": "x"})
        self.ids = {}
        for name, host in (("core", "192.168.10.2"), ("eg", "192.168.10.3"), ("og", "192.168.10.4")):
            self.ids[name] = ins("INSERT INTO net_switches (site_id, host, port, snmp_version, secret, status, created_at, "
                                 "updated_at) VALUES (?, ?, 161, '2c', ?, 'active', ?, ?)",
                                 (self.site, host, secret, self.t0 - 60, self.t0 - 60))
            self.store(name, snaps()[name], self.t0)
        for mac, ip, h in ((PC1, "192.168.10.41", "pc-empfang-01"), (GW_MAC, "192.168.10.1", "firewall"),
                           (PC2, "192.168.10.73", "pc-og-03")):
            ins("INSERT INTO net_devices (site_id, dev_key, mac, ip, hostname, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (self.site, f"mac:{mac}", mac, ip, h, self.t0, self.t0))

    def sw(self, name):
        return q1("SELECT * FROM net_switches WHERE id = ?", (self.ids[name],))

    def store(self, name, data, ts, kind="full", error=None):
        snap = None if error else (topology.clean_quick(data) if kind == "quick" else topology.clean_snapshot(data))
        topology.store_result(self.sw(name), snap, error, ts, kind)

    def kinds(self, name=None):
        sql = "SELECT kind, severity, if_index FROM net_topo_events"
        rows = q(sql + " WHERE switch_id = ? ORDER BY ts, id", (self.ids[name],)) if name else q(sql + " ORDER BY ts, id")
        return [(r["kind"], r["severity"], r["if_index"]) for r in rows]

    def test_events_from_quick_and_full_polls(self):
        eg = snaps()["eg"]
        self.store("eg", quick(eg, 360000), self.t0 + 30, "quick")           # erste schnelle Abfrage: Ausgangswerte
        self.assertEqual(self.kinds("eg"), [])
        # 1) Port 4 (PC) aus, Uplink 25 kurz weg (ifLastChange), Port 7 neue Fehler
        self.store("eg", quick(eg, 360060, p4={"oper_up": False, "last_change_s": 360050},
                               p25={"last_change_s": 360030}, p7={"in_errors": 1500}), self.t0 + 60, "quick")
        self.assertEqual(self.kinds("eg"), [("link_flap", "critical", 25), ("link_down", "info", 4),
                                            ("port_errors", "critical", 7)])
        ev = q1("SELECT ts FROM net_topo_events WHERE kind = 'link_down'")
        self.assertEqual(ev["ts"], self.t0 + 60 - 10)                       # Zeitpunkt aus ifLastChange
        snap = json.loads(self.sw("eg")["snapshot"])
        self.assertFalse(next(i for i in snap["interfaces"] if i["index"] == 4)["oper_up"])
        self.assertTrue(snap["fdb"])                                          # MAC-Tabelle bleibt erhalten
        self.assertEqual(q1("SELECT SUM(errors) AS n FROM net_port_errors")["n"], 1500)
        # 2) Port 4 wieder da mit 100 Mbit/s; Uplink fällt ganz aus
        self.store("eg", quick(eg, 360120, p4={"oper_up": True, "speed_mbps": 100, "last_change_s": 360110},
                               p25={"oper_up": False, "last_change_s": 360115}, p7={"in_errors": 1500}),
                   self.t0 + 120, "quick")
        self.assertEqual(self.kinds("eg")[3:], [("link_up", "info", 4), ("link_down", "critical", 25)])  # nach Zeit
        # 3) Neustart, dann nicht erreichbar und wieder da
        self.store("eg", quick(eg, 30), self.t0 + 180, "quick")
        self.assertIn(("switch_restart", "warning", None), self.kinds("eg"))
        self.store("eg", None, self.t0 + 240, error="Keine Antwort")
        self.store("eg", None, self.t0 + 300, error="Keine Antwort")
        self.store("eg", eg, self.t0 + 360)
        k = [x[0] for x in self.kinds("eg")]
        self.assertEqual(k.count("switch_down"), 1)
        self.assertEqual(k.count("switch_up"), 1)
        # Stände: Aufbau geändert → gespeichert; reine Zähler nicht
        n = q1("SELECT COUNT(*) AS n FROM net_switch_history WHERE switch_id = ?", (self.ids["eg"],))["n"]
        self.store("eg", quick(eg, 400, p7={"in_errors": 1501}), self.t0 + 420, "quick")
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM net_switch_history WHERE switch_id = ?", (self.ids["eg"],))["n"], n)

    def test_devices_neighbors_and_time_travel(self):
        og = json.loads(json.dumps(snaps()["og"]))
        # Gerät neu an Port 1 (zweite Abfrage), dann umgesteckt an Port 15? – Port 15 ist Uplink: kein Ereignis
        og2 = json.loads(json.dumps(og))
        og2["fdb"].append({"mac": "3C:52:82:99:00:01", "if_index": 1, "vlan": None})
        self.store("og", og2, self.t0 + 300)
        self.assertEqual(self.kinds("og"), [("device_new", "info", 1)])
        self.assertIn("an Port 1", q1("SELECT detail FROM net_topo_events WHERE kind = 'device_new'")["detail"])
        eg = json.loads(json.dumps(snaps()["eg"]))
        moved = json.loads(json.dumps(eg))
        for e in moved["fdb"]:
            if e["mac"] == PC1:
                e["if_index"] = 2
        moved["lldp"] = []
        self.store("eg", moved, self.t0 + 600)
        k = self.kinds("eg")
        self.assertIn(("mac_moved", "info", 2), k)
        self.assertIn(("neighbor_changed", "warning", 25), k)
        self.assertIn("pc-empfang-01", q1("SELECT detail FROM net_topo_events WHERE kind = 'mac_moved'")["detail"])

        # Zeitreise: vor dem Umstecken hängt PC1 an Port 4, danach an Port 2
        before = topology.build(self.site, at=self.t0 + 100)
        after = topology.build(self.site)
        self.assertEqual(before.locations[PC1], (self.ids["eg"], 4))
        self.assertEqual(after.locations[PC1], (self.ids["eg"], 2))
        self.assertEqual(topology.build(self.site, at=self.t0 - 3600).switches, {})

    def test_jobs_quick_and_full(self):
        now = self.t0 + 61
        ex("UPDATE net_switches SET last_poll = ?, last_full = ?", (self.t0, self.t0))
        kinds = {j["switch_id"]: j["kind"] for j in topology.jobs(now)}
        self.assertEqual(set(kinds.values()), {"quick"})
        kinds = {j["switch_id"]: j["kind"] for j in topology.jobs(self.t0 + 301)}
        self.assertEqual(set(kinds.values()), {"full"})
        ex("UPDATE net_switches SET last_error = 'x' WHERE id = ?", (self.ids["og"],))
        self.assertNotIn(self.ids["og"], {j["switch_id"] for j in topology.jobs(now)})   # nur im vollen Takt
        ex("INSERT INTO settings (key, value, updated_at) VALUES ('measure.topo_quick_s', '0', 0)")
        self.assertEqual(topology.jobs(now), [])

    def test_pages(self):
        eg = snaps()["eg"]
        self.store("eg", quick(eg, 360060, p4={"oper_up": False, "last_change_s": 360050}, p7={"in_errors": 1500}),
                   self.t0 + 60, "quick")
        self.store("eg", quick(eg, 360120, p4={"oper_up": True, "last_change_s": 360110}), self.t0 + 120, "quick")
        ev = q1("SELECT id FROM net_topo_events WHERE kind = 'port_errors'")["id"]
        base = f"/sites/{self.site}/topologie"
        probe = self.enroll("PC-EMPFANG-01")
        ex("UPDATE probes SET site_id = ?, addresses = ? WHERE id = ?",
           (self.site, json.dumps(["192.168.10.41"]), probe["probe_id"]))
        pages = [f"{base}?seite=verlauf", f"{base}?seite=verlauf&alle=1", f"{base}?ereignis={ev}",
                 f"{base}?zeit={self.t0 + 90}", f"{base}/verlauf", f"{base}/verlauf?art=links",
                 f"{base}/verlauf?art=stoerungen&switch={self.ids['eg']}", f"{base}/verlauf?ereignis={ev}",
                 f"{base}/switche/{self.ids['eg']}", f"{base}/switche/{self.ids['eg']}?verlauf=7d",
                 f"{base}/switche/{self.ids['eg']}?verlauf=6h&port=4",
                 f"{base}/kontext?von={self.t0 + 50}&bis={self.t0 + 120}&probe={probe['probe_id']}",
                 f"{base}/kontext?von={self.t0 + 50}&bis={self.t0 + 120}"]
        failures = {}
        for url in pages:
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, url)
            if problems := lint(r.get_data(as_text=True)):
                failures[url] = problems
        self.assertEqual(failures, {}, json.dumps(failures, indent=1, ensure_ascii=False))
        self.assertIn("Port 4: Link weg", self.client.get(f"{base}?seite=verlauf&alle=1").get_data(as_text=True))
        self.assertIn("1.500 fehlerhafte Pakete", self.client.get(f"{base}?seite=verlauf").get_data(as_text=True))
        tree = self.client.get(f"{base}?ereignis={ev}").get_data(as_text=True)
        self.assertIn("Zurück zu Jetzt", tree)
        self.assertIn("tn-hl", tree)
        self.assertIn("1.500 fehlerhafte Pakete", tree)
        lanes = self.client.get(f"{base}/switche/{self.ids['eg']}").get_data(as_text=True)
        self.assertIn("Port-Verlauf", lanes)
        self.assertIn("ln-err", lanes)
        self.assertIn("ln-flap", lanes)
        ctx = self.client.get(f"{base}/kontext?von={self.t0 + 50}&bis={self.t0 + 120}&probe={probe['probe_id']}")
        html = ctx.get_data(as_text=True)
        self.assertIn("Wahrscheinliche Ursache", html)
        self.assertIn("Anschluss der Probe", html)
        self.assertEqual(self.client.get(f"{base}/kontext?von=0").status_code, 404)
