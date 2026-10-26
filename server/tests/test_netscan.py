"""1.0: Netzwerkscan – Check-Typ, Probe-API, Anwesenheit, IP-Konflikte, Dienste mit Links, Seite."""
import unittest

from wachtl import checktypes, repo
from wachtl.db import ex, q, q1
from wachtl.services import checkstatus, netscan

from .helpers import AppTestCase


class PureTest(unittest.TestCase):
    def test_subnets_only_private(self):
        self.assertEqual(checktypes.normalize_subnets(" AUTO "), "auto")
        self.assertEqual(checktypes.normalize_subnets("192.168.1.7/24;10.0.0.5"), "192.168.1.0/24, 10.0.0.5/32")
        for bad, text in (("8.8.8.0/24", "kein privates"), ("10.0.0.0/8", "zu groß"), ("fe80::/64", "IPv4"),
                          ("192.168.1.300/24", "CIDR"), ("127.0.0.0/24", "kein privates")):
            with self.assertRaises(ValueError) as cm:
                checktypes.normalize_subnets(bad)
            self.assertIn(text, str(cm.exception))

    def test_ports(self):
        self.assertEqual(checktypes.parse_ports("443, 22,80-82;22"), [22, 80, 81, 82, 443])
        self.assertEqual(checktypes.format_ports([21, 22, 23, 25, 80, 81, 8000]), "21-23,25,80,81,8000")
        for bad in ("0", "70000", "90-80", "abc", "", "1-2000"):
            with self.assertRaises(ValueError):
                checktypes.parse_ports(bad)
        self.assertEqual(checktypes.parse_ports(checktypes.NETSCAN_PORTS)[:3], [21, 22, 23])

    def test_identify_and_links(self):
        self.assertEqual(netscan.identify(2222, "SSH-2.0-OpenSSH_9.6"), "ssh")
        self.assertEqual(netscan.identify(8080, None, http_status=200), "http")
        self.assertEqual(netscan.identify(8443, None, tls=True, http_status=401), "https")
        self.assertEqual(netscan.identify(5900, "RFB 003.008"), "vnc")
        self.assertEqual(netscan.identify(21, "220 FRITZ!Box FTP server ready."), "ftp")
        self.assertEqual(netscan.identify(3389), "rdp")
        self.assertEqual(netscan.identify(12345), "tcp")
        self.assertEqual(netscan.link_for("ssh", "10.0.0.2", 22)["url"], "ssh://10.0.0.2")
        self.assertEqual(netscan.link_for("ssh", "10.0.0.2", 2222)["url"], "ssh://10.0.0.2:2222")
        self.assertEqual(netscan.link_for("https", "10.0.0.2", 443)["url"], "https://10.0.0.2/")
        self.assertEqual(netscan.link_for("http", "10.0.0.2", 8080)["url"], "http://10.0.0.2:8080/")
        self.assertEqual(netscan.link_for("rdp", "10.0.0.2", 3389, 7)["kind"], "rdp")
        self.assertEqual(netscan.link_for("smb", "10.0.0.2", 445)["text"], "\\\\10.0.0.2")
        self.assertIsNone(netscan.link_for("mysql", "10.0.0.2", 3306))
        self.assertIn("full address:s:10.0.0.2:3390", netscan.rdp_file("10.0.0.2", 3390))

    def test_mac(self):
        self.assertEqual(netscan.norm_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(netscan.norm_mac("a8-bb-cc-dd-ee-ff"), "A8:BB:CC:DD:EE:FF")
        self.assertIsNone(netscan.norm_mac("01:00:5e:00:00:01"))              # Multicast
        self.assertIsNone(netscan.norm_mac("ff:ff:ff:ff:ff:ff"))
        self.assertIsNone(netscan.norm_mac("kaputt"))
        self.assertTrue(netscan.random_mac("DA:A1:19:00:00:01"))
        self.assertFalse(netscan.random_mac("A8:BB:CC:DD:EE:FF"))


def host(ip, mac=None, ports=(), **kw):
    return {"ip": ip, "mac": mac, "hostname": kw.get("hostname"), "rtt_ms": 0.5, "via": ["icmp", "arp"],
            "self": kw.get("self", False), "ports": list(ports)}


class NetscanServerTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.site = self.make_site("Büro")
        self.make_token(self.site, token="t", max_uses=5)
        self.a = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "t", "hostname": "PC-A"}).get_json()
        p = checktypes.merged("netscan", {})
        self.cid = repo.create_check("Scan", checktypes.target_for("netscan", p), "target", p["schedule_min"] * 60,
                                     checktypes.timeout_ms("netscan", p), "all", None, "netscan", p)
        self.now = repo.now()

    def post(self, hosts, ts, error=None, probe=None, cid=None):
        return self.client.post("/api/probe/v1/results/netscan",
                                headers={"Authorization": f"Bearer {(probe or self.a)['token']}"},
                                json={"check_id": cid or self.cid, "ts": ts, "trigger": "schedule", "duration_s": 12.5,
                                      "subnets": ["192.168.10.0/24"], "error": error, "hosts": hosts})

    def test_config_and_validation(self):
        cfg = self.client.get("/api/probe/v1/config", headers={"Authorization": f"Bearer {self.a['token']}"}).get_json()
        check = next(c for c in cfg["checks"] if c["id"] == self.cid)
        self.assertEqual((check["type"], check["target"], check["params"]["port_scan"]), ("netscan", "auto", True))
        self.assertEqual(check["params"]["schedule_min"], 15)
        # fremder Check-Typ / kein JSON
        ping = repo.create_check("Ping", "1.1.1.1", "target", 1, 1000, "all", None)
        self.assertEqual(self.post([], self.now, cid=ping).status_code, 422)
        r = self.client.post("/api/probe/v1/results/netscan", headers={"Authorization": f"Bearer {self.a['token']}"},
                             data="x", content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_presence_returns_conflicts_and_services(self):
        router = host("192.168.10.1", "A8:BB:CC:00:00:01", hostname="fritz.box", ports=[
            {"port": 443, "tls": True, "http_status": 200, "http_title": "FRITZ!Box", "http_server": None},
            {"port": 22, "banner": "SSH-2.0-dropbear\r\n\x00"},
            {"port": 3389}, {"port": 99999}])
        printer = host("192.168.10.50", "A8:BB:CC:00:00:50")
        phone = host("192.168.10.77", "DA:00:00:00:00:77")
        t0 = self.now - 6 * 900
        # Scan 1: alles da (erster Scan → keine „neu“-Ereignisse)
        self.assertEqual(self.post([router, printer, phone], t0).status_code, 201)
        # Scans 2–6: Telefon kommt und geht (3 Wiederkehrer), Drucker konstant
        for i, with_phone in enumerate([False, True, False, True, True], start=1):
            hosts = [router, printer] + ([phone] if with_phone else [])
            self.assertEqual(self.post(hosts, t0 + i * 900).status_code, 201)
        # Scan 7: neues Gerät übernimmt die IP des Druckers → IP-Konflikt; Router ändert IP → ip_changed
        intruder = host("192.168.10.50", "A8:BB:CC:00:00:99")
        moved = dict(router, ip="192.168.10.254")
        self.assertEqual(self.post([moved, printer, intruder, phone], self.now).status_code, 201)

        devs = {d["mac"]: d for d in netscan.devices(self.site, self.now - 86400, self.now)}
        ph = devs["DA:00:00:00:00:77"]
        self.assertEqual(ph["returns"], 2)
        self.assertNotIn("irregular", ph["flags"])
        self.assertIn("random_mac", ph["flags"])
        self.assertEqual(len(ph["presence"]), 3)
        # vierter Wiederkehrer → unregelmäßig
        self.post([moved, printer], self.now + 900)
        self.post([moved, printer, phone], self.now + 1800)
        ph = next(d for d in netscan.devices(self.site, self.now - 86400, self.now + 1800) if d["mac"] == ph["mac"])
        self.assertIn("irregular", ph["flags"])

        r = devs["A8:BB:CC:00:00:01"]
        self.assertIn("ip_changed", r["flags"])
        self.assertEqual(r["ip"], "192.168.10.254")
        svc = {s["port"]: s for s in r["services"]}
        self.assertEqual(sorted(svc), [22, 443, 3389])                         # Port 99999 verworfen
        self.assertEqual(svc[443]["service"], "https")
        self.assertEqual(svc[443]["url"], "https://192.168.10.254/")
        self.assertEqual(svc[22]["banner"], "SSH-2.0-dropbear")                # Steuerzeichen entfernt
        self.assertEqual(svc[3389]["link"]["kind"], "rdp")
        self.assertIn("ip_conflict", devs["A8:BB:CC:00:00:99"]["flags"])
        self.assertIn("new", devs["A8:BB:CC:00:00:99"]["flags"])
        self.assertNotIn("new", devs["A8:BB:CC:00:00:50"]["flags"])
        kinds = [e["kind"] for e in netscan.events(self.site, self.now - 86400)]
        self.assertEqual(kinds.count("ip_conflict"), 1)
        self.assertIn("ip_changed", kinds)
        self.assertIn("new_device", kinds)
        self.assertEqual(kinds.count("device_back"), 3)  # 2 + der Wiederkehrer aus dem Nachtest

        section = netscan.report_section(self.site, self.now - 86400, self.now)
        self.assertEqual(section["runs"], 9)
        self.assertEqual(len(section["devices"]), 4)
        self.assertTrue(all("services" in d and "label" in d for d in section["devices"]))

        # Zustand des Checks
        _, latest = checkstatus.latest_runs([self.a["probe_id"]])
        probe = q1("SELECT * FROM probes WHERE id = ?", (self.a["probe_id"],))
        st = checkstatus.probe_states(probe, repo.checks_for_probe(probe), {}, {}, latest)
        scan = next(s for s in st if s.kind == "netscan")
        self.assertEqual((scan.state, scan.detail), ("ok", "3 Geräte"))

        # Seite, Links, RDP-Datei, Bezeichnung
        self.make_user()
        self.login()
        html = self.client.get(f"/sites/{self.site}?tab=netzwerk").get_data(as_text=True)
        self.assertIn('href="https://192.168.10.254/"', html)
        self.assertIn('href="ssh://192.168.10.254"', html)
        self.assertIn("IP-Konflikt", html)
        self.assertIn("unregelmäßig", html)
        self.assertIn("Jetzt scannen", html)
        rdp = self.client.get(f"/netzwerk/geraete/{r['id']}/3389.rdp")
        self.assertEqual(rdp.status_code, 200)
        self.assertIn("full address:s:192.168.10.254", rdp.get_data(as_text=True))
        self.assertEqual(self.client.get(f"/netzwerk/geraete/{r['id']}/22.rdp").status_code, 404)
        html = self.client.get("/login").get_data(as_text=True)
        resp = self.client.post(f"/netzwerk/geraete/{r['id']}/notiz",
                                data={"note": "Router Keller", "csrf_token": self.csrf()})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(q1("SELECT note FROM net_devices WHERE id = ?", (r["id"],))["note"], "Router Keller")
        self.assertIn("Router Keller", self.client.get(f"/sites/{self.site}?tab=netzwerk&zeitraum=7d").get_data(as_text=True))

    def test_error_run_and_empty_page(self):
        self.assertEqual(self.post([], self.now, error="Netz zu groß (8192 Adressen)").status_code, 201)
        run = q1("SELECT * FROM netscan_runs")
        self.assertEqual((run["error"], run["hosts_found"]), ("Netz zu groß (8192 Adressen)", 0))
        self.assertEqual(q("SELECT * FROM net_devices"), [])
        self.make_user()
        self.login()
        html = self.client.get(f"/sites/{self.site}?tab=netzwerk").get_data(as_text=True)
        self.assertIn("Netz zu groß", html)
        # ohne Scan-Check: Hinweis zum Einrichten
        ex("DELETE FROM checks WHERE id = ?", (self.cid,))
        html = self.client.get(f"/sites/{self.site}?tab=netzwerk").get_data(as_text=True)
        self.assertIn("Netzwerkscan einrichten", html)

    def test_check_form_and_run_now(self):
        self.make_user()
        self.login()
        self.assertEqual(self.client.get("/admin/checks/new/netscan").status_code, 200)
        form = {"type": "netscan", "name": "Scan 2", "scope": "all", "subnets": "8.8.8.0/24", "ports": "22",
                "port_scan": "on", "timeout_ms": "500", "parallel": "64", "max_hosts": "1024", "schedule_min": "15",
                "offset_min": "-1", "window_start": "00:00", "window_end": "23:59", "weekdays": "1234567",
                "csrf_token": self.csrf()}
        r = self.client.post("/admin/checks", data=form)
        self.assertEqual(r.status_code, 400)
        self.assertIn("kein privates Netz", r.get_data(as_text=True))
        form["subnets"] = "192.168.10.0/24"
        self.assertEqual(self.client.post("/admin/checks", data=form).status_code, 302)
        c = q1("SELECT * FROM checks WHERE name = 'Scan 2'")
        self.assertEqual((c["target"], c["interval_s"]), ("192.168.10.0/24", 900))
        r = self.client.post(f"/probes/{self.a['probe_id']}/checks/{self.cid}/run",
                             data={"csrf_token": self.csrf(), "next": f"/sites/{self.site}?tab=netzwerk"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(q1("SELECT type FROM probe_commands")["type"], "run_check")

    def test_prune(self):
        self.post([host("192.168.10.1", "A8:BB:CC:00:00:01")], self.now)
        self.assertEqual(len(q("SELECT * FROM net_devices")), 1)
        netscan.prune(self.now + 91 * 86400)
        self.assertEqual(q("SELECT * FROM net_devices"), [])
        self.assertEqual(q("SELECT * FROM netscan_runs"), [])
