"""Netzwerkscan der Server-Probe: reine Hilfsfunktionen und ein echter Scan gegen 127.0.0.1."""
import http.server
import ipaddress
import socket
import socketserver
import threading
import time
import unittest
from unittest import mock

from wachtl.serverprobe import icmp, netscan
from wachtl.serverprobe.probe import SUPPORTED, ServerProbe
from wachtl.serverprobe.runners import NetscanRunner


class PureTest(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(netscan.parse_ports("22, 80-82,22"), [22, 80, 81, 82])
        self.assertEqual(netscan.parse_ports([443, "8000-8001"]), [443, 8000, 8001])
        self.assertEqual(len(netscan.parse_ports(None)), 27)
        self.assertEqual(len(netscan.parse_ports("1-1024")), 1024)
        for bad in ("abc", "0", "70000", "90-80", "1-1025", "1-1000,2000-2100"):
            with self.assertRaises(netscan.ScanError, msg=bad):
                netscan.parse_ports(bad)

    def test_plan_networks(self):
        nets = netscan.plan_networks("auto", [("192.168.10.20", 24), ("10.1.2.3", 8), ("127.0.0.1", 8),
                                              ("169.254.3.4", 16), ("192.168.10.21", 24)])
        self.assertEqual([str(n) for n in nets], ["192.168.10.0/24", "10.1.0.0/22"])
        nets = netscan.plan_networks(" 192.168.1.0/24, 10.0.0.5/32 ", [])
        self.assertEqual([str(n) for n in nets], ["192.168.1.0/24", "10.0.0.5/32"])
        self.assertEqual([str(n) for n in netscan.plan_networks("192.168.1.7/24", [])], ["192.168.1.0/24"])
        with self.assertRaises(netscan.ScanError):
            netscan.plan_networks("auto", [("127.0.0.1", 8)])
        with self.assertRaises(netscan.ScanError):
            netscan.plan_networks("192.168.1.0/33", [])

    def test_plan_hosts(self):
        hosts = netscan.plan_hosts([ipaddress.IPv4Network("192.168.1.0/30"), ipaddress.IPv4Network("10.0.0.5/32")], 10)
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2", "10.0.0.5"])
        self.assertEqual(len(netscan.plan_hosts([ipaddress.IPv4Network("10.0.0.0/22")], 1024)), 1022)
        with self.assertRaises(netscan.ScanError):
            netscan.plan_hosts([ipaddress.IPv4Network("10.0.0.0/21")], 1024)

    def test_proc_arp(self):
        text = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
                "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
                "192.168.1.7      0x1         0x2         00:11:22:33:44:55     *        eth0\n")
        self.assertEqual(netscan.parse_proc_arp(text), {"192.168.1.1": "AA:BB:CC:DD:EE:FF",
                                                        "192.168.1.7": "00:11:22:33:44:55"})

    def test_arp_a_windows(self):
        text = ("\nSchnittstelle: 192.168.1.20 --- 0xb\n"
                "  Internetadresse       Physische Adresse     Typ\n"
                "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamisch\n"
                "  192.168.1.255         ff-ff-ff-ff-ff-ff     statisch\n"
                "  224.0.0.22            01-00-5e-00-00-16     statisch\n"
                "  192.168.1.30          00-11-22-33-44-55     dynamic\n")
        self.assertEqual(netscan.parse_arp_a(text), {"192.168.1.1": "AA:BB:CC:DD:EE:FF",
                                                     "192.168.1.30": "00:11:22:33:44:55"})

    def test_interfaces_parsers(self):
        ip = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
              "2: eth0    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0\\ valid_lft forever\n"
              "5: eth1@if6    inet 192.168.5.4/24 brd 192.168.5.255 scope global eth1\n")
        self.assertEqual(netscan.parse_ip_addr(ip), [("lo", "127.0.0.1", 8), ("eth0", "172.17.0.2", 16),
                                                     ("eth1", "192.168.5.4", 24)])
        ipconfig = ("Windows-IP-Konfiguration\n\nEthernet-Adapter Ethernet:\n\n"
                    "   Verbindungsspezifisches DNS-Suffix: fritz.box\n"
                    "   IPv6-Adresse. . . . . . . . . . . : 2001:db8::5\n"
                    "   IPv4-Adresse  . . . . . . . . . . : 192.168.178.20(Bevorzugt)\n"
                    "   Subnetzmaske  . . . . . . . . . . : 255.255.255.0\n"
                    "   Standardgateway . . . . . . . . . : 192.168.178.1\n\n"
                    "Ethernet adapter VPN:\n\n"
                    "   IPv4 Address. . . . . . . . . . . : 10.8.0.6\n"
                    "   Subnet Mask . . . . . . . . . . . : 255.255.252.0\n"
                    "   Default Gateway . . . . . . . . . :\n")
        self.assertEqual(netscan.parse_ipconfig(ipconfig), [("192.168.178.20", 24), ("10.8.0.6", 22)])

    def test_http_and_banner(self):
        raw = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
               b"<html><head><TITLE>\n  FRITZ!Box &amp; Co \xc3\xa4 </TITLE></head>")
        self.assertEqual(netscan.parse_http_response(raw), (200, "nginx/1.24", "FRITZ!Box & Co ä"))
        self.assertEqual(netscan.parse_http_response(b"HTTP/1.0 302 Found\r\nLocation: /x\r\n\r\n"),
                         (302, None, None))
        self.assertEqual(netscan.parse_http_response(b"SSH-2.0-x\r\n"), (None, None, None))
        self.assertEqual(netscan.html_title(b"<title>Gr\xfc\xdfe</title>", "iso-8859-1"), "Grüße")
        self.assertEqual(netscan.banner_text(b"SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(netscan.banner_text(b"220 ftp.example  ready\r\n230 more"), "220 ftp.example ready")
        self.assertEqual(netscan.banner_text(b"J\x00\x00\x00\n8.0.36\x00abc"), "8.0.36 abc")
        self.assertEqual(len(netscan.banner_text(b"x" * 500)), 200)
        self.assertTrue(netscan.looks_like_tls(b"\x15\x03\x01\x00\x02"))
        self.assertFalse(netscan.looks_like_tls(b"HTTP/1.1"))
        self.assertEqual(netscan.norm_mac("a-b-c-d-e-f"), "0A:0B:0C:0D:0E:0F")


class _Http(http.server.BaseHTTPRequestHandler):
    server_version = "TestHTTP/1.0"
    sys_version = ""

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()
        self.wfile.write("<html><title>Wachtl Test</title></html>".encode())

    def log_message(self, *args):
        pass


class _Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-test\r\n")
        time.sleep(0.2)


class _Threaded(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalScanTest(unittest.TestCase):
    def setUp(self):
        self.servers = [_Threaded(("127.0.0.1", 0), _Http), _Threaded(("127.0.0.1", 0), _Banner)]
        for s in self.servers:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        self.http_port = self.servers[0].server_address[1]
        self.ssh_port = self.servers[1].server_address[1]

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()

    def check(self, **params):
        ports = f"{self.http_port},{self.ssh_port},{_closed_port()}"
        return {"id": 7, "type": "netscan", "target": "127.0.0.1/32",
                "params": {"ports": ports, "timeout_ms": 500, "parallel": 8, "port_scan": True, **params}}

    def system(self):
        return {"pinger": lambda *a: icmp.Reply(False, error="TimedOut"), "interfaces": lambda: [("10.9.9.9", 24)],
                "arp": lambda: {"127.0.0.1": "AA:BB:CC:00:00:01", "10.0.0.1": "AA:BB:CC:00:00:02"},
                "resolver": lambda ip: "localhost"}

    def test_full_scan(self):
        # HTTP wird nur auf typischen HTTP-Ports versucht – der zufällige Port des Testservers zählt hier dazu
        with mock.patch.object(netscan, "HTTP_PORTS", netscan.HTTP_PORTS | {self.http_port}):
            r = netscan.run_scan(self.check(), "manual", **self.system())
        self.assertIsNone(r["error"])
        self.assertEqual((r["check_id"], r["trigger"], r["subnets"]), (7, "manual", ["127.0.0.1/32"]))
        self.assertEqual(len(r["hosts"]), 1)
        h = r["hosts"][0]
        self.assertEqual((h["ip"], h["mac"], h["hostname"], h["rtt_ms"], h["self"]),
                         ("127.0.0.1", "AA:BB:CC:00:00:01", "localhost", None, False))
        self.assertIn("tcp", h["via"])
        self.assertIn("arp", h["via"])
        ports = {p["port"]: p for p in h["ports"]}
        self.assertEqual(set(ports), {self.http_port, self.ssh_port})
        self.assertEqual(ports[self.ssh_port]["banner"], "SSH-2.0-test")
        web = ports[self.http_port]
        self.assertEqual((web["http_status"], web["http_server"], web["http_title"], web["tls"], web["banner"]),
                         (200, "TestHTTP/1.0", "Wachtl Test", False, None))
        self.assertEqual(set(web), {"port", "banner", "tls", "http_status", "http_server", "http_title",
                                    "tls_subject"})

    def test_tls_detection(self):
        import ssl
        import tempfile
        from pathlib import Path

        from .test_serverprobe import self_signed

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = self_signed(Path(tmp))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            srv = _Threaded(("127.0.0.1", 0), _Http)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            port = srv.server_address[1]
            try:
                with mock.patch.object(netscan, "HTTP_PORTS", netscan.HTTP_PORTS | {port}), \
                        mock.patch.object(netscan, "TLS_PORTS", netscan.TLS_PORTS | {port}):
                    result = netscan.scan_port("127.0.0.1", port, 1.0)
            finally:
                srv.shutdown()
                srv.server_close()
        self.assertEqual((result["tls"], result["tls_subject"], result["http_status"], result["http_title"]),
                         (True, "CN=wachtl.test", 200, "Wachtl Test"))

    def test_errors_become_result(self):
        c = self.check()
        c["target"] = "10.0.0.0/16"
        r = netscan.run_scan(c, "schedule", **self.system())
        self.assertIn("65534", r["error"])
        self.assertEqual(r["hosts"], [])
        c["target"], c["params"]["ports"] = "127.0.0.1/32", "1-5000"
        self.assertIn("1024", netscan.run_scan(c, "schedule", **self.system())["error"])

    def test_discovery_only_and_arp_and_self(self):
        c = self.check(port_scan=False)
        c["target"] = "10.0.0.0/30"
        system = {**self.system(), "interfaces": lambda: [("10.0.0.2", 30)],
                  "pinger": lambda ip, *a: icmp.Reply(ip in ("127.0.0.1", "10.0.0.2"), 0.25)}
        with mock.patch.object(netscan.net, "local_addresses", return_value=[]):
            r = netscan.run_scan(c, "schedule", tcp=lambda *a: "none", **system)
        self.assertIsNone(r["error"])
        hosts = {h["ip"]: h for h in r["hosts"]}
        self.assertEqual(set(hosts), {"10.0.0.1", "10.0.0.2"})
        self.assertEqual((hosts["10.0.0.1"]["via"], hosts["10.0.0.1"]["mac"]), (["arp"], "AA:BB:CC:00:00:02"))
        self.assertEqual((hosts["10.0.0.2"]["via"], hosts["10.0.0.2"]["rtt_ms"], hosts["10.0.0.2"]["self"]),
                         (["icmp"], 0.25, True))
        self.assertEqual(hosts["10.0.0.2"]["ports"], [])

    def test_cancel(self):
        stop = threading.Event()
        stop.set()
        c = self.check()
        r = netscan.run_scan(c, "schedule", stop, **self.system())
        self.assertEqual(r["error"], "Scan abgebrochen")


class RunnerTest(unittest.TestCase):
    def test_registered(self):
        self.assertIn("netscan", SUPPORTED)
        probe = ServerProbe("http://127.0.0.1:1", "", "/nonexistent")
        runner = probe.create_runner({"id": 3, "type": "netscan", "target": "auto", "params": {}})
        self.assertIsInstance(runner, NetscanRunner)

    def test_run_now_reports_once(self):
        reports, calls, gate = [], [], threading.Event()

        def scan(check, trigger, stop):
            calls.append(trigger)
            gate.wait(2)
            return {"check_id": check["id"], "trigger": trigger, "error": None, "hosts": []}

        runner = NetscanRunner({"id": 5, "type": "netscan", "target": "auto", "params": {"schedule_min": 0}},
                               reports.append, scan).start()
        try:
            runner.run_now()
            runner.run_now()          # während des Laufs: kein zweiter paralleler Scan
            deadline = time.monotonic() + 5
            while not calls and time.monotonic() < deadline:
                time.sleep(0.05)
            gate.set()
            while len(reports) < 1 and time.monotonic() < deadline:
                time.sleep(0.05)
        finally:
            runner.stop()
            runner.thread.join(5)
        self.assertEqual(reports[0]["trigger"], "manual")
        self.assertLessEqual(len(calls), 2)
        self.assertFalse(runner.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
