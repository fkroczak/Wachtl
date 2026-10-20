"""Server-Probe gegen die echte App: Registrierung, Konfiguration, Messwerte, Ergebnisse, Pinning."""
import datetime
import os
import ssl
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

from werkzeug.serving import make_server

from wachtl import bootstrap, checktypes, repo
from wachtl.db import ex, q, q1
from wachtl.serverprobe import api as probe_api
from wachtl.serverprobe import icmp, net
from wachtl.serverprobe.probe import ENROLL_FILE, STATE_FILE, ServerProbe

from .helpers import AppTestCase


def self_signed(folder: Path) -> tuple[str, str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wachtl.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_file, key_file = folder / "c.pem", folder / "k.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    pin = probe_api.spki_pin(cert.public_bytes(serialization.Encoding.DER))
    return str(cert_file), str(key_file), pin


class ParserTest(AppTestCase):
    def test_ping_output(self):
        ok = icmp.parse_ping_output("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.4 ms\n")
        self.assertEqual((ok.success, ok.rtt_ms, ok.ttl, ok.source), (True, 12.4, 57, "1.1.1.1"))
        hop = icmp.parse_ping_output("From 192.168.1.1 icmp_seq=1 Time to live exceeded\n")
        self.assertEqual((hop.success, hop.ttl_expired, hop.source), (False, True, "192.168.1.1"))
        self.assertEqual(icmp.parse_ping_output("1 packets transmitted, 0 received").error, "TimedOut")

    def test_real_ping_to_loopback(self):
        reply = icmp.ping("127.0.0.1", 1000, 32, 64)
        if "nicht ausführbar" in reply.error:
            self.skipTest("kein ping installiert")
        self.assertTrue(reply.success, reply.error)
        self.assertGreaterEqual(reply.rtt_ms, 0)

    def test_routes(self):
        proc = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
                "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
                "eth1\t00000000\t01010A0A\t0003\t0\t0\t50\t00000000\n")
        self.assertEqual(net.parse_proc_route(proc), "10.10.1.1")
        win = ("IPv4-Routentabelle\n  Netzwerkziel    Netzwerkmaske   Gateway    Schnittstelle Metrik\n"
               "          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.20     25\n")
        self.assertEqual(net.parse_route_print(win), "192.168.1.1")

    def test_iperf_json(self):
        r = {}
        from wachtl.serverprobe import bandwidth
        bandwidth.parse_iperf('{"end": {"sum_received": {"bits_per_second": 94000000, "seconds": 10.0}, '
                              '"sum_sent": {"retransmits": 3}}}', "tcp", r)
        self.assertEqual((r["mbps"], r["retransmits"], r["duration_s"]), (94.0, 3, 10.0))
        r = {}
        bandwidth.parse_iperf('{"error": "the server is busy running a test"}', "tcp", r)
        self.assertIn("busy", r["error"])
        self.assertIn("-R", bandwidth.iperf_args("h", 5201, "tcp", 10, 1, 4, 100, 0, True))


class ServerProbeEndToEndTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.state = Path(tempfile.mkdtemp())
        self.app.config.update(SERVER_PROBE=True, SERVER_PROBE_DIR=str(self.state), SERVER_PROBE_SITE="Wachtl-Server")
        cert, key, self.pin = self_signed(self.state)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server = make_server("127.0.0.1", 0, self.app, threaded=True, ssl_context=ctx)
        self.url = f"https://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)

    def wait(self, cond, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cond():
                return True
            time.sleep(0.1)
        return False

    def test_registers_measures_and_reports(self):
        self.assertIn("Server-Probe", bootstrap.prepare_server_probe())
        self.assertTrue((self.state / ENROLL_FILE).exists())
        self.assertIsNone(bootstrap.prepare_server_probe())        # Token liegt schon bereit
        repo.create_check("iperf Server", "wachtl-server", "target", 3600, 60000, "all", None, "iperf",
                          checktypes.merged("iperf", {"peer": "server"}))
        path = repo.create_check("Pfad", "10.9.9.9", "target", 1, 500, "all", None, "path",
                                 checktypes.merged("path", {"max_hops": 3, "probes_per_hop": 1}))
        wan = repo.create_check("WAN", "speed.example", "reference", 3600, 90000, "all", None, "speedtest",
                                checktypes.merged("speedtest", {"schedule_min": 0}))

        def fake_ping(address, timeout, size, ttl):
            if address == "10.9.9.9" and ttl < 3:
                return icmp.Reply(False, 1.0, None, f"192.168.0.{ttl}", ttl_expired=True, error="TtlExpired")
            return icmp.Reply(True, 1.5, 64, address)

        stop = threading.Event()
        def fake_measure(check):
            return [{"direction": "down", "protocol": "http", "mbps": 123.4}]

        probe = ServerProbe(self.url, self.pin, self.state, stop_event=stop, pinger=fake_ping,
                            gateway=lambda: "192.168.0.1", measure=fake_measure)
        with mock.patch("wachtl.serverprobe.probe.ServerProbe.upload_loop", lambda self: None):
            t = threading.Thread(target=probe.run, daemon=True)
            t.start()
            self.addCleanup(stop.set)
            self.assertTrue(self.wait(lambda: probe.config is not None), "keine Konfiguration")
            row = q1("SELECT * FROM probes WHERE kind = 'server'")
            self.assertIsNotNone(row)
            self.assertFalse((self.state / ENROLL_FILE).exists())
            self.assertTrue((self.state / STATE_FILE).exists())
            if os.name != "nt":
                self.assertEqual((self.state / STATE_FILE).stat().st_mode & 0o777, 0o600)
            types = sorted(c["type"] for c in probe.config["checks"])
            self.assertNotIn("iperf", types)                      # misst nicht gegen sich selbst
            self.assertEqual(types, ["path", "path", "ping", "ping", "ping", "ping", "speedtest", "speedtest"])
            # Messwerte landen im Puffer und kommen durch den Ingest
            self.assertTrue(self.wait(lambda: len(probe.buffer) >= 6))
            self.assertTrue(probe.upload_pending())
            self.assertTrue(any('wachtl_ping_up{probe="' in line for line in self.imported))
            self.assertTrue(any("wachtl_hop_up" in line and 'hop="03"' in line for line in self.imported))
            # Traceroute-Ergebnis
            self.assertTrue(self.wait(lambda: q1("SELECT * FROM path_runs WHERE check_id = ?", (path,)) is not None))
            run = q1("SELECT * FROM path_runs WHERE check_id = ?", (path,))
            self.assertTrue(run["reached"])
            # „Jetzt messen“ kommt per Heartbeat
            repo.queue_command(row["id"], "run_check", wan, "test")
            probe.handle_commands(probe.api.heartbeat({})["commands"])
            self.assertTrue(self.wait(lambda: q1("SELECT * FROM bandwidth_runs WHERE check_id = ?", (wan,)) is not None))
            self.assertEqual(q1("SELECT mbps FROM bandwidth_runs")["mbps"], 123.4)
            # Client-Hinweise dieses Servers (wachtl-probe.exe diagnose) gehen über das Probe-API
            probe.send_findings([{"finding_id": "srv-1", "kind": "adapter_disabled", "severity": "critical",
                                  "state": "active", "title": "Netzwerkkarte ausgeschaltet",
                                  "detected_at": int(time.time()), "details": {}}])
            self.assertEqual(q1("SELECT kind FROM client_findings WHERE probe_id = ?", (row["id"],))["kind"],
                             "adapter_disabled")
            stop.set()
            t.join(timeout=10)

        # nach dem Neustart: registriert, kein neuer Token
        self.assertIsNone(bootstrap.prepare_server_probe())
        # im Web-UI gelöscht -> beim nächsten Start neu registrieren
        ex("DELETE FROM probes WHERE kind = 'server'")
        self.assertIn("vorbereitet", bootstrap.prepare_server_probe())
        self.assertFalse((self.state / STATE_FILE).exists())
        # Token der Server-Probe erscheint nicht unter „Probes registrieren“
        self.make_user()
        self.login()
        self.assertNotIn("Server-Probe", self.client.get("/admin?bereich=pcs").get_data(as_text=True)
                         .split('id="enrollment"')[1])

    def test_wrong_pin_is_rejected(self):
        api = probe_api.Api(self.url, "AAAA" + self.pin[4:])
        with self.assertRaises(probe_api.ApiError) as cm:
            api.config(None)
        self.assertEqual(cm.exception.status, 495)
        self.assertEqual(probe_api.Api(self.url, self.pin).request("GET", "config")[0], 401)


class RealIperfTest(AppTestCase):
    def test_against_local_iperf3_server(self):
        import shutil
        import socket
        import subprocess

        from wachtl.serverprobe import bandwidth

        exe = shutil.which("iperf3")
        if not exe:
            self.skipTest("iperf3 nicht installiert")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        server = subprocess.Popen([exe, "-s", "-p", str(port), "-B", "127.0.0.1"], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        self.addCleanup(server.kill)
        time.sleep(0.5)
        check = {"id": 1, "type": "iperf", "peer": {"host": "127.0.0.1", "port": port, "error": None},
                 "params": checktypes.merged("iperf", {"duration_s": 1, "omit_s": 0, "direction": "both"})}
        results = bandwidth.measure(check, exe)
        self.assertEqual([r["direction"] for r in results], ["down", "up"])
        for r in results:
            self.assertNotIn("error", r, r)
            self.assertGreater(r["mbps"], 1)
        # Gegenstelle fehlt -> Fehler je Richtung, kein Absturz
        check["peer"] = {"host": None, "port": None, "error": "iperf3-Gegenstelle auf dem Wachtl-Server ist abgeschaltet"}
        self.assertIn("abgeschaltet", bandwidth.measure(check, exe)[0]["error"])


class HttpSpeedTestTest(AppTestCase):
    def test_download_upload_latency(self):
        from flask import Flask, Response, request

        from wachtl.serverprobe import bandwidth

        app = Flask("speed")

        @app.get("/down")
        def down():
            return Response((b"x" * 65536 for _ in range(200)), mimetype="application/octet-stream")

        @app.post("/up")
        def up():
            while request.stream.read(65536):
                pass
            return "", 200

        @app.get("/forbidden")
        def forbidden():
            return "", 403

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        check = {"id": 1, "type": "speedtest", "params": checktypes.merged("speedtest", {
            "down_url": base + "/down", "up_url": base + "/up", "latency_url": base + "/down",
            "duration_s": 2, "streams": 2, "timeout_s": 30})}
        results = {r["direction"]: r for r in bandwidth.measure(check)}
        self.assertGreater(results["down"]["mbps"], 1, results)
        self.assertGreater(results["up"]["mbps"], 1, results)
        self.assertIsNotNone(results["down"]["latency_ms"])
        check["params"].update(down_url=base + "/forbidden", up_url="", direction="down")
        r = bandwidth.measure(check)[0]
        self.assertIn("HTTP 403", r["error"])
