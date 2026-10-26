"""1.1: Switches automatisch finden, TP-Link Easy Smart über die Weboberfläche, wahrscheinliche Knotenpunkte."""
import json
import re
import socket
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from wachtl import easysmart, repo, secretbox, switch_oui
from wachtl.db import ex, ins, q, q1
from wachtl.serverprobe import discovery
from wachtl.serverprobe import topology as probe_topology
from wachtl.services import switchfind, topology

from .helpers import AppTestCase
from .test_topology import DEVICES, rows, snaps
from .topo_fixtures import DESK, PC2

ES_MAC = "50:C7:BF:12:34:56"          # TP-Link
NG_MAC = "A0:40:A0:65:43:21"          # Netgear


def es_pages(name="SW-Lager", mac=ES_MAC, ip="127.0.0.1", ports=5) -> dict:
    act = [6, 0, 5, 6, 0, 0, 0, 0][:ports] + [0, 0]
    pkts = []
    for n in range(ports):
        pkts += [1000 * (n + 1), 0, 2000 * (n + 1), 7 if n == 0 else 0]
    return {
        "SystemInfoRpm.htm": f"""<script>
var info_ds = {{
descriStr:[
"{name}"
],
macStr:[
"{mac.replace(':', '-')}"
],
ipStr:[
"{ip}"
],
netmaskStr:[
"255.255.255.0"
],
gatewayStr:[
"192.168.10.1"
],
firmwareStr:[
"1.0.0 Build 20230218 Rel.50633"
],
hardwareStr:[
"TL-SG105PE 2.0"
]
}};
var tip = "";
</script>""",
        "PortSettingRpm.htm": f"""<script>
var max_port_num = {ports};
var port_middle_num  = 16;
var all_info = {{
state:[{','.join('1' for _ in act)}],
trunk_info:[{','.join('0' for _ in act)}],
spd_cfg:[{','.join('1' for _ in act)}],
spd_act:[{','.join(str(a) for a in act)}],
fc_cfg:[{','.join('0' for _ in act)}],
fc_act:[{','.join('0' for _ in act)}]
}};
</script>""",
        "PortStatisticsRpm.htm": f"""<script>
var max_port_num = {ports};
var all_info = {{
state:[{','.join('1' for _ in act)}],
link_status:[{','.join(str(a) for a in act)}],
pkts:[{','.join(str(p) for p in pkts)},0,0]
}};
</script>""",
        "PoeConfigRpm.htm": """<script>
var poe_port_num = 4;
var portConfig = {
state:[2,2,2,2],
priority:[2,2,2,2],
powerlimit:[330,330,330,330],
power:[51,0,38,0],
current:[100,0,80,0],
voltage:[530,0,530,0],
pdclass:[300,0,154,0],
powerstatus:[2,0,2,0]
};
var globalConfig = {
system_power_limit:650,
system_power_consumption:89,
system_power_remain:561
};
</script>""",
    }


class FakeEasySmart:
    """Weboberfläche eines TP-Link Easy Smart Switches (nur das, was Wachtl liest)."""

    def __init__(self, user="admin", password="geheim-123", host="127.0.0.1", port=0, **kw):
        pages = es_pages(**kw)
        state = {"logged_in": False, "logins": 0, "logouts": 0}
        self.state = state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def send(self, body: str) -> None:
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
                ok = form.get("username") == [user] and form.get("password") == [password]
                state["logged_in"] = ok
                state["logins"] += 1
                self.send(f"<script>\nvar logonInfo = new Array(\n{0 if ok else 1},\n0,0);\nvar g_Lan = 1;\n</script>")

            def do_GET(self):
                path = self.path.lstrip("/")
                if path == "Logout.htm":
                    state["logged_in"] = False
                    state["logouts"] += 1
                    return self.send("<html></html>")
                if not state["logged_in"]:
                    return self.send('<script>var logonInfo = new Array(0,0);</script><form action="logon.cgi">')
                if path in pages:
                    return self.send(pages[path])
                self.send_error(404)

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.port = self.server.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_a):
        self.server.shutdown()
        self.server.server_close()


class EasySmartTest(unittest.TestCase):
    def test_page_vars(self):
        v = easysmart.page_vars('<script>var a = 5; var b = "x"; var c = new Array(1,"2", 3);\n'
                                'var d = {k:[1,2], "q": {z:0x1F}, e:[ ]};\nvar broken = ;</script>')
        self.assertEqual(v["a"], 5)
        self.assertEqual(v["b"], "x")
        self.assertEqual(v["c"], [1, "2", 3])
        self.assertEqual(v["d"], {"k": [1, 2], "q": {"z": 31}, "e": []})
        self.assertNotIn("broken", v)

    def test_collect_and_login(self):
        with FakeEasySmart() as sw:
            snap = easysmart.poll("127.0.0.1", {"user": "admin", "password": "geheim-123"}, port=sw.port)
            self.assertEqual(sw.state["logouts"], 1)            # Sitzung wieder freigegeben
            with self.assertRaisesRegex(easysmart.EasySmartError, "Benutzer oder Passwort falsch"):
                easysmart.poll("127.0.0.1", {"user": "admin", "password": "falsch"}, port=sw.port)
        clean = topology.clean_snapshot(snap)
        self.assertEqual(clean["system"]["name"], "SW-Lager")
        self.assertIn("TL-SG105PE", clean["system"]["descr"])
        self.assertEqual(clean["base_mac"], ES_MAC)
        self.assertEqual(len(clean["interfaces"]), 5)
        p1, p2, p3 = clean["interfaces"][:3]
        self.assertEqual((p1["speed_mbps"], p1["oper_up"], p1["in_errors"]), (1000, True, 7))
        self.assertFalse(p2["oper_up"])
        self.assertEqual(p3["speed_mbps"], 100)
        self.assertEqual(clean["poe"], {"power_w": 65, "used_w": 9, "ports": [1, 3]})

    def test_not_easysmart_and_unreachable(self):
        with self.assertRaisesRegex(easysmart.EasySmartError, "nicht erreichbar|Keine Antwort"):
            easysmart.poll("127.0.0.1", {"user": "a", "password": "b"}, port=_free_port(), timeout=1)

    def test_probe_poll_dispatches_by_access(self):
        with FakeEasySmart() as sw:
            res = probe_topology.poll({"switch_id": 4, "host": "127.0.0.1", "port": sw.port, "access": "easysmart",
                                       "credentials": {"user": "admin", "password": "geheim-123"}})
            self.assertEqual(res["snapshot"]["base_mac"], ES_MAC)
            res = probe_topology.poll({"switch_id": 4, "host": "127.0.0.1", "port": sw.port, "access": "easysmart",
                                       "credentials": {"user": "admin", "password": "x"}})
            self.assertIn("Anmeldung abgelehnt", res["error"])


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def es_reply(mac=ES_MAC, ip="192.168.10.30", model="TL-SG105PE", name="SW-Lager") -> bytes:
    def tlv(kind, val):
        return struct.pack("!HH", kind, len(val)) + val
    body = (tlv(1, model.encode() + b"\x00") + tlv(2, name.encode() + b"\x00") +
            tlv(3, bytes(int(x, 16) for x in mac.split(":"))) + tlv(4, socket.inet_aton(ip)) +
            tlv(7, b"1.0.0 Build 20230218\x00") + tlv(8, b"TL-SG105PE 2.0\x00") + tlv(10, b"\x05"))
    header = discovery.ES_HEADER.pack(1, 2, bytes(6), bytes(6), 1, 0, 32 + len(body) + 4, 0, 0, 0, 0)
    return discovery.es_crypt(header + body + discovery.ES_END)


def nsdp_reply(mac=NG_MAC, ip="192.168.10.31") -> bytes:
    def tlv(kind, val):
        return struct.pack("!HH", kind, len(val)) + val
    raw_mac = bytes(int(x, 16) for x in mac.split(":"))
    header = discovery.NSDP_HEADER.pack(1, 2, 0, bytes(4), bytes(6), raw_mac, bytes(2), 7, b"NSDP", bytes(4))
    return header + tlv(1, b"GS108Ev3") + tlv(3, b"Buero") + tlv(4, raw_mac) + tlv(6, socket.inet_aton(ip)) + \
        tlv(0x0D, b"2.06.10") + discovery.NSDP_END


class DiscoveryTest(unittest.TestCase):
    def test_packets(self):
        self.assertEqual(discovery.es_crypt(discovery.es_crypt(b"hallo welt")), b"hallo welt")
        req = discovery.es_crypt(discovery.es_request(b"\x01" * 6, 5))
        self.assertEqual(len(req), 36)
        self.assertTrue(req.endswith(discovery.ES_END))
        dev = discovery.es_parse(es_reply())
        self.assertEqual(dev, {"proto": "easysmart", "vendor": "TP-Link", "mac": ES_MAC, "ip": "192.168.10.30",
                               "model": "TL-SG105PE", "name": "SW-Lager", "firmware": "1.0.0 Build 20230218",
                               "hardware": "TL-SG105PE 2.0", "ports": 5})
        self.assertIsNone(discovery.es_parse(b"\x00" * 50))
        self.assertIsNone(discovery.es_parse(discovery.es_request(b"\x01" * 6, 5)[:20]))
        ng = discovery.nsdp_parse(nsdp_reply())
        self.assertEqual((ng["mac"], ng["model"], ng["ip"], ng["name"]), (NG_MAC, "GS108Ev3", "192.168.10.31", "Buero"))
        self.assertIsNone(discovery.nsdp_parse(discovery.nsdp_request(b"\x01" * 6, 1)))   # Anfrage, keine Antwort
        self.assertEqual(discovery.broadcast_addresses([("192.168.10.5", 24), ("10.0.0.1", 8)]),
                         ["255.255.255.255", "192.168.10.255"])

    def test_discover_over_udp(self):
        """Ein „Switch“ auf 127.0.0.1 antwortet an den Absender-Port – wie im LAN, nur ohne Broadcast."""
        sw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sw.bind(("127.0.0.1", discovery.ES_SEND))
        except OSError:
            self.skipTest("UDP 29808 belegt")
        stop = threading.Event()

        def serve():
            sw.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = sw.recvfrom(2048)
                except OSError:
                    continue
                if discovery.es_crypt(data)[1] == 0:
                    sw.sendto(es_reply(), (addr[0], discovery.ES_RECV))

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            found = discovery.discover(interfaces=[], listen_s=1.0, targets=["127.0.0.1"])
        finally:
            stop.set()
            t.join()
            sw.close()
        self.assertEqual([d["mac"] for d in found], [ES_MAC])


class ClassifyTest(unittest.TestCase):
    def test_vendors_models_and_access(self):
        self.assertEqual(switch_oui.vendor(ES_MAC), "TP-Link")
        self.assertEqual(switch_oui.vendor("00-13-49-AA-BB-CC"), "Zyxel")
        self.assertIsNone(switch_oui.vendor("3C:52:82:11:0A:01"))
        web = lambda title, server=None: [{"port": 80, "service": "http", "http_title": title, "http_server": server}]  # noqa: E731
        c = switchfind.classify(ES_MAC, web("TL-SG108E"))
        self.assertEqual((c["vendor"], c["model"], c["access"]), ("TP-Link", "TL-SG108E", "easysmart"))
        self.assertGreaterEqual(c["confidence"], 65)
        c = switchfind.classify("00:13:49:00:00:01", web("GS1900-24E"))
        self.assertEqual((c["model"], c["access"]), ("GS1900-24E", "snmp"))
        c = switchfind.classify("1C:7E:E5:00:00:01", web("DGS-1100-08 Web Smart Switch"))
        self.assertEqual(c["model"], "DGS-1100-08")
        c = switchfind.classify(NG_MAC, web("NETGEAR GS108Ev3"))
        self.assertEqual(c["access"], "none")                         # ProSAFE Plus: kein SNMP
        c = switchfind.classify("00:00:00:00:00:01", web("Aruba Instant On 1930 24G"))
        self.assertEqual(c["access"], "snmp")
        self.assertIsNone(switchfind.classify(ES_MAC, web("Archer AX55 Router")))   # Router, kein Switch
        self.assertIsNone(switchfind.classify("3C:52:82:11:0A:01", web("Anmeldung")))
        weak = switchfind.classify(ES_MAC, [])
        self.assertLess(weak["confidence"], switchfind.SHOW_FROM)       # nur Hersteller: nicht anzeigen
        hub = switchfind.classify(ES_MAC, [], hub_port=True)
        self.assertGreaterEqual(hub["confidence"], switchfind.SHOW_FROM)
        self.assertEqual(switchfind.label({"vendor": "TP-Link", "model": "TL-SG105PE"}), "TP-Link TL-SG105PE")
        self.assertEqual(switchfind.label({"vendor": "Netgear", "model": None, "name": "Buero"}), "Buero")


class TreeTest(unittest.TestCase):
    def test_easysmart_without_fdb_hangs_at_port_that_only_sees_it(self):
        with FakeEasySmart(ip="192.168.10.30") as sw:
            es_snap = topology.clean_snapshot(easysmart.poll("127.0.0.1", {"user": "admin", "password": "geheim-123"},
                                                             port=sw.port))
        r = rows()
        core = json.loads(r[0]["snapshot"])
        # Easy Smart hängt am Core Port 4; dahinter zwei PCs
        core["interfaces"][3]["oper_up"] = True
        core["fdb"] += [{"mac": ES_MAC, "if_index": 4, "vlan": None},
                        {"mac": "3C:52:82:33:00:01", "if_index": 4, "vlan": None},
                        {"mac": "3C:52:82:33:00:02", "if_index": 4, "vlan": None}]
        r[0]["snapshot"] = json.dumps(core)
        r.append({"status": "active", "last_error": None, "location": None, "name": None, "id": 4, "sys_name": "SW-Lager",
                  "host": "192.168.10.30", "access": "easysmart", "snapshot": json.dumps(es_snap)})
        devices = {**DEVICES, "3C:52:82:33:00:01": {"mac": "3C:52:82:33:00:01", "ip": "192.168.10.80", "label": "PC-Lager"}}
        topo = topology.analyze(r, devices)
        es = topo.nodes["s4"]
        self.assertEqual(es.parent, "s1")
        self.assertEqual(es.link.a_port, 4)
        self.assertEqual({d["mac"] for d in es.devices}, {"3C:52:82:33:00:01", "3C:52:82:33:00:02"})
        self.assertFalse(any(n.kind == "unmanaged" and n.parent == "s1" and n.link.a_port == 4 for n in topo.nodes.values()))
        self.assertNotIn("no_fdb", {f["kind"] for f in topo.findings if f.get("switch_id") == 4})
        path = topology.path_for(topo, "3C:52:82:33:00:01")
        labels = [h["label"] for h in path["hops"]]
        self.assertEqual(labels[:3], ["PC-Lager", "SW-Lager", "SW-Core-01"])
        topology.layout(topo)

    def test_candidate_vm_host_and_possible_switch(self):
        r = rows()
        og = json.loads(r[2]["snapshot"])
        vm_port, two_port = 2, 3
        port1 = next(i for i in og["interfaces"] if i["index"] == 1)
        og["interfaces"] += [{**port1, "index": n, "name": f"Port {n}", "descr": f"Port {n}"} for n in (vm_port, two_port)]
        og["fdb"] += [{"mac": f"00:50:56:00:00:0{n}", "if_index": vm_port, "vlan": None} for n in range(4)]
        og["fdb"] += [{"mac": "3C:52:82:44:00:01", "if_index": two_port, "vlan": None},
                      {"mac": "3C:52:82:44:00:02", "if_index": two_port, "vlan": None}]
        r[2]["snapshot"] = json.dumps(og)
        eg = json.loads(r[1]["snapshot"])
        desk_port = next(e["if_index"] for e in eg["fdb"] if e["mac"] == DESK[0])
        eg["fdb"].append({"mac": NG_MAC, "if_index": desk_port, "vlan": None})
        r[1]["snapshot"] = json.dumps(eg)
        cand = {"id": 7, "mac": NG_MAC, "ip": "192.168.10.31", "label": "Netgear GS108Ev3", "access": "none"}
        topo = topology.analyze(r, DEVICES, candidates=[cand])
        c = topo.nodes["c7"]
        self.assertEqual((c.kind, c.parent, c.sub), ("candidate", "s2", "ohne Abfrage"))
        self.assertEqual({d["mac"] for d in c.devices}, set(DESK))
        self.assertFalse(any(f["kind"] == "no_credentials" and f["fkey"] == "cand:7" for f in topo.findings))
        self.assertNotIn(f"u3:{vm_port}", topo.nodes)                  # VM-Host, kein Switch
        maybe = topo.nodes[f"u3:{two_port}"]
        self.assertTrue(maybe.sub.startswith("möglich"))
        self.assertEqual(topology.path_for(topo, DESK[0])["hops"][1]["label"], "Netgear GS108Ev3")
        snmp_cand = {**cand, "access": "snmp"}
        topo = topology.analyze(r, DEVICES, candidates=[snmp_cand])
        self.assertIn("cand:7", {f["fkey"] for f in topo.findings})


class FindAndEnterTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.make_user()
        self.login()
        self.site = self.make_site("Zentrale")

    def _enroll(self, hostname: str) -> dict:
        token = self.make_token(self.site, token=f"tok-{hostname}")
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": token, "hostname": hostname,
                                                         "os": "Windows 11", "version": "0.1.0"})
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def server_probe(self) -> dict:
        p = self._enroll("wachtl-server")
        ex("UPDATE probes SET kind = 'server' WHERE id = ?", (p["probe_id"],))
        return {"Authorization": f"Bearer {p['token']}"}

    def test_found_by_broadcast_netscan_and_entered_with_credentials(self):
        auth = self.server_probe()
        win = self._enroll("PC-01")
        self.assertEqual(self.client.post("/api/probe/v1/results/discovery", json={"devices": []},
                                          headers={"Authorization": f"Bearer {win['token']}"}).status_code, 403)
        sw1 = FakeEasySmart()
        with sw1, FakeEasySmart(mac="50:C7:BF:00:00:02", name="SW-Halle", host="127.0.0.2", port=sw1.port), \
                FakeEasySmart(password="anderes", mac="50:C7:BF:00:00:03", name="SW-Hof", host="127.0.0.3", port=sw1.port):
            devs = [discovery.es_parse(es_reply(ip="127.0.0.1")), discovery.es_parse(es_reply(
                mac="50:C7:BF:00:00:02", ip="127.0.0.2", name="SW-Halle")), discovery.es_parse(es_reply(
                    mac="50:C7:BF:00:00:03", ip="127.0.0.3", name="SW-Hof")), discovery.nsdp_parse(nsdp_reply())]
            r = self.client.post("/api/probe/v1/results/discovery", json={"devices": devs + [{"proto": "x"}]},
                                 headers=auth)
            self.assertEqual(r.get_json()["stored"], 4)
            # Netzwerkscan: Zyxel mit Weboberfläche
            ts = repo.now()
            dev = ins("INSERT INTO net_devices (site_id, dev_key, mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                      (self.site, "mac:00:13:49:00:00:01", "00:13:49:00:00:01", "192.168.10.40", ts, ts))
            ins("INSERT INTO net_services (device_id, port, service, http_title, first_seen, last_seen) "
                "VALUES (?, 80, 'http', 'GS1900-24E', ?, ?)", (dev, ts, ts))
            page = self.client.get(f"/sites/{self.site}/topologie/switche").get_data(as_text=True)
            for text in ("Gefundene Switches", "SW-Lager", "SW-Halle", "Buero", "Zyxel GS1900-24E", "Rundruf TP-Link",
                         "keine Abfrage möglich", "Weboberfläche (TP-Link Easy Smart)"):
                self.assertIn(text, page)
            tree = self.client.get(f"/sites/{self.site}/topologie").get_data(as_text=True)
            self.assertIn("automatisch gefunden", tree)
            cand = q1("SELECT * FROM net_switch_candidates WHERE mac = ?", (ES_MAC,))
            # Assistent aus dem Fund: Adresse, Name, Zugangsart vorbelegt; weitere Funde zum Anhaken
            page = self.client.get(f"/sites/{self.site}/topologie/switche/neu?kandidat={cand['id']}").get_data(as_text=True)
            self.assertIn('value="127.0.0.1"', page)
            self.assertRegex(page, r'<option value="easysmart"\s+selected')
            self.assertIn("SW-Halle", page)
            others = {c["name"]: c["id"] for c in q("SELECT id, name FROM net_switch_candidates WHERE id <> ?", (cand["id"],))}
            r = self.client.post(f"/sites/{self.site}/topologie/switche/neu", data={
                "csrf_token": self.session_csrf(), "access": "easysmart", "host": "127.0.0.1", "web_port": str(sw1.port),
                "web_user": "admin", "web_password": "geheim-123", "kandidat": str(cand["id"]),
                "auch": [str(others["SW-Halle"]), str(others["SW-Hof"])]})
            self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:2000])
            page = self.client.get(r.headers["Location"]).get_data(as_text=True)
            self.assertIn("Verbindung klappt", page)
            self.assertIn("liefert dieser Switch nicht", page)
            sid = int(re.search(r"/switche/(\d+)/", r.headers["Location"]).group(1))
            row = q1("SELECT * FROM net_switches WHERE id = ?", (sid,))
            self.assertEqual((row["access"], row["origin"], row["port"]), ("easysmart", "erkannt", sw1.port))
            self.assertNotIn("geheim-123", row["secret"])
            auch = re.search(r'name="auch" value="([\d,]+)"', page).group(1)
            r = self.client.post(f"/sites/{self.site}/topologie/switche/{sid}/aktivieren",
                                 data={"csrf_token": self.session_csrf(), "auch": auch})
            flash = self.client.get(r.headers["Location"]).get_data(as_text=True)
            self.assertIn("Mit denselben Zugangsdaten eingetragen: SW-Halle", flash)
            self.assertIn("Nicht übernommen", flash)
            self.assertIn("SW-Hof", flash)
            names = {r["name"] or r["sys_name"] for r in q("SELECT * FROM net_switches WHERE status = 'active'")}
            self.assertEqual(names, {"SW-Lager", "SW-Halle"})
            self.assertEqual(q1("SELECT COUNT(*) AS n FROM net_switches")["n"], 2)
            # eingetragene Funde sind abgehakt; die übrigen bleiben offen
            topology.refresh_findings(self.site, repo.now())
            states = {c["name"]: c["state"] for c in q("SELECT name, state FROM net_switch_candidates")}
            self.assertEqual(states["SW-Lager"], "added")
            self.assertEqual(states["SW-Hof"], "new")
            # Server-Probe bekommt den Auftrag mit Zugangsart
            ex("UPDATE net_switches SET last_poll = ?", (repo.now() - 3600,))
            jobs = self.client.get("/api/probe/v1/topology/jobs", headers=auth).get_json()["jobs"]
            self.assertEqual({j["access"] for j in jobs}, {"easysmart"})
            self.assertEqual(jobs[0]["credentials"]["password"], "geheim-123")
        audit = " ".join(r["detail"] or "" for r in q("SELECT detail FROM audit_log"))
        self.assertNotIn("geheim-123", audit)
        # Ausblenden und wieder anzeigen
        hof = q1("SELECT id FROM net_switch_candidates WHERE name = 'SW-Hof'")["id"]
        self.client.post(f"/sites/{self.site}/topologie/gefunden/{hof}/ignorieren", data={"csrf_token": self.session_csrf()})
        self.assertEqual(q1("SELECT state FROM net_switch_candidates WHERE id = ?", (hof,))["state"], "ignored")
        page = self.client.get(f"/sites/{self.site}/topologie/switche").get_data(as_text=True)
        self.assertIn("Ausgeblendet (1)", page)

    def test_wizard_validation_for_web_access(self):
        r = self.client.post(f"/sites/{self.site}/topologie/switche/neu", data={
            "csrf_token": self.session_csrf(), "access": "easysmart", "host": "192.168.10.30", "web_port": "80",
            "web_user": "", "web_password": ""})
        self.assertEqual(r.status_code, 422)
        page = r.get_data(as_text=True)
        for f in ("web_user", "web_password"):
            self.assertIn(f'href="#f-{f}"', page)

    def test_pages_pass_lint(self):
        from .test_ui_quality import lint

        ts = repo.now()
        s = snaps()
        for n, (name, snap) in enumerate((("SW-Core-01", s["core"]), ("SW-EG-01", s["eg"]), ("SW-OG-01", s["og"])), 2):
            ins("INSERT INTO net_switches (site_id, host, port, snmp_version, secret, status, last_poll, last_ok, sys_name, "
                "snapshot, created_at, updated_at) VALUES (?, ?, 161, '2c', ?, 'active', ?, ?, ?, ?, ?, ?)",
                (self.site, f"192.168.10.{n}", secretbox.seal({"version": "2c", "community": "x"}), ts, ts, name,
                 json.dumps(snap), ts, ts))
        switchfind.store_discovery(self.site, [discovery.es_parse(es_reply()), discovery.nsdp_parse(nsdp_reply())], ts)
        ex("UPDATE net_switch_candidates SET mac = ? WHERE mac = ?", (PC2, NG_MAC))      # Fund am OG-Switch
        topology.refresh_findings(self.site, ts)
        cand = q1("SELECT id FROM net_switch_candidates WHERE mac = ?", (ES_MAC,))["id"]
        base = f"/sites/{self.site}/topologie"
        failures = {}
        for url in (base, f"{base}/switche", f"{base}/probleme", f"{base}/switche/neu?kandidat={cand}",
                    f"{base}/switche/neu?zugang=easysmart"):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, url)
            if problems := lint(r.get_data(as_text=True)):
                failures[url] = problems
        self.assertEqual(failures, {}, json.dumps(failures, indent=1, ensure_ascii=False))
        tree = self.client.get(base).get_data(as_text=True)
        self.assertIn("gefundener Switch", tree)
        self.assertIn("ohne Abfrage", tree)


class TopologyMenuTest(AppTestCase):
    def test_menu_single_site_redirects_multiple_sites_show_cards(self):
        from .test_ui_quality import lint

        self.make_user()
        self.login()
        first = self.make_site("Zentrale")
        r = self.client.get("/topologie")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith(f"/sites/{first}/topologie"))
        page = self.client.get(f"/sites/{first}/topologie").get_data(as_text=True)
        self.assertRegex(page, r'<a href="/topologie" class="active" aria-current="page">')
        second = self.make_site("Filiale")
        switchfind.store_discovery(second, [discovery.es_parse(es_reply())], repo.now())
        r = self.client.get("/topologie")
        self.assertEqual(r.status_code, 200)
        page = r.get_data(as_text=True)
        for text in ("Zentrale", "Filiale", "Topologie öffnen", "1 braucht Zugangsdaten", f"/sites/{second}/topologie"):
            self.assertIn(text, page)
        self.assertEqual(lint(page), [])
