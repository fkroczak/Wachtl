"""Tests der Windows-Variante, soweit sie plattformunabhängig ist (Systembefehle im Trockenlauf)."""
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml
from cryptography import x509

from wachtl.win import certs, host, installer, serve, winsys
from wachtl.win.layout import Layout, read_env, write_env
from wachtl.win.supervisor import ProcSpec, Supervisor

INPUT = {
    "hostnames": "wachtl.kunde.local, 10.0.0.5",
    "https_port": 8443, "http_port": 8080,
    "admin_password": "ein-sicheres-passwort",
    "raw_days": 14, "agg_months": 13,
    "notify": {"email_to": "it@kunde.de", "email_from": "wachtl@kunde.de", "smtp_smarthost": "mail.kunde.de:587",
               "smtp_username": "", "smtp_password": "", "smtp_require_tls": "true", "teams_webhook_url": ""},
}


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.inst = self.tmp / "Program Files" / "Wachtl Server"
        self.data = self.tmp / "ProgramData" / "Wachtl Server"
        self.inst.mkdir(parents=True)
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)


class CertTest(TempDirTest):
    NAMES = ["wachtl.kunde.local", "10.0.0.5"]

    def files(self):
        key, crt = self.data / "wachtl.key", self.data / "wachtl.crt"
        return key, crt, *certs.ca_paths(crt)

    def openssl(self, *args):
        return subprocess.run(["openssl", *args], capture_output=True, text=True)

    def test_ca_issues_short_lived_server_certificate(self):
        key, crt, ca_key, ca_crt = self.files()
        pin, reason = certs.ensure_certificate(self.NAMES, key, crt)
        self.assertEqual(reason, "keine Wachtl-CA vorhanden")
        cmd = f"openssl x509 -in '{crt}' -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64"
        self.assertEqual(pin, subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip())
        chain = certs.load_chain(crt)
        server, ca = chain
        self.assertEqual(ca, x509.load_pem_x509_certificate(ca_crt.read_bytes()))
        self.assertEqual(certs.root_certificate(crt), ca)
        # Server: kein CA-Zertifikat, höchstens 397 Tage (Apple, Browser), von der CA signiert
        self.assertFalse(server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertLessEqual((server.not_valid_after_utc - server.not_valid_before_utc).days, 398)
        server.verify_directly_issued_by(ca)
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertGreater((ca.not_valid_after_utc - ca.not_valid_before_utc).days, 3000)
        self.assertEqual(oct(ca_key.stat().st_mode & 0o777), "0o600")
        # OpenSSL bestätigt die Kette mit der CA als einziger Vertrauensbasis, für Name und IP
        for host in ("-verify_hostname", "wachtl.kunde.local"), ("-verify_ip", "10.0.0.5"):
            r = self.openssl("verify", "-CAfile", str(ca_crt), *host, str(crt))
            self.assertIn(": OK", r.stdout, r.stderr)
        self.assertIsNone(certs.needs_renewal(crt, self.NAMES))

    def test_name_constraints_keep_ca_to_the_server(self):
        key, crt, ca_key, ca_crt = self.files()
        certs.ensure_certificate(self.NAMES, key, crt)
        nc = x509.load_pem_x509_certificate(ca_crt.read_bytes()).extensions.get_extension_for_class(x509.NameConstraints)
        self.assertTrue(nc.critical)
        self.assertEqual({str(n.value) for n in nc.value.permitted_subtrees}, {"wachtl.kunde.local", "10.0.0.5/32"})
        # ein mit dem CA-Schlüssel ausgestelltes Zertifikat für eine fremde Seite lehnt OpenSSL ab
        foreign_key, foreign_crt = self.data / "f.key", self.data / "f.crt"
        ca = (certs.load_or_create_key(ca_key), x509.load_pem_x509_certificate(ca_crt.read_bytes()))
        certs.create_certificate(["bank.example"], foreign_key, foreign_crt, ca=ca)
        r = self.openssl("verify", "-CAfile", str(ca_crt), "-verify_hostname", "bank.example", str(foreign_crt))
        self.assertNotIn(": OK", r.stdout)
        self.assertIn("permitted subtree violation", r.stdout + r.stderr)

    def test_renewal_keeps_ca_and_pin(self):
        key, crt, _, ca_crt = self.files()
        pin, _ = certs.ensure_certificate(self.NAMES, key, crt)
        ca_before = ca_crt.read_bytes()
        certs.create_certificate(self.NAMES, key, crt, days=10)
        self.assertIn("läuft in", certs.needs_renewal(crt, self.NAMES))
        pin2, reason = certs.ensure_certificate(self.NAMES, key, crt)
        self.assertIn("läuft in", reason)
        self.assertEqual(pin, pin2)
        self.assertEqual(ca_crt.read_bytes(), ca_before)          # PCs müssen nichts neu ablegen
        self.assertIsNone(certs.needs_renewal(crt, self.NAMES))

    def test_new_names_reissue_ca_with_same_key(self):
        key, crt, ca_key, ca_crt = self.files()
        pin, _ = certs.ensure_certificate(self.NAMES, key, crt)
        ca_key_before = ca_key.read_bytes()
        pin2, reason = certs.ensure_certificate(["wachtl.kunde.local", "10.0.0.6"], key, crt)
        self.assertEqual(reason, "Servernamen der Wachtl-CA haben sich geändert")
        self.assertEqual(pin, pin2)
        self.assertEqual(ca_key.read_bytes(), ca_key_before)
        san = self.openssl("x509", "-in", str(crt), "-noout", "-ext", "subjectAltName").stdout
        self.assertIn("IP Address:10.0.0.6", san)
        self.assertIsNone(certs.needs_renewal(crt, ["wachtl.kunde.local", "10.0.0.6"]))

    def test_old_self_signed_certificate_moves_to_ca_with_same_pin(self):
        key, crt, _, ca_crt = self.files()
        certs.load_or_create_key(key)
        # Zertifikat wie bis 0.9.2: selbstsigniert, 10 Jahre
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(crt), "-days", "3650",
                        "-subj", "/CN=a.local/O=Wachtl", "-addext", "subjectAltName=DNS:a.local"],
                       check=True, capture_output=True)
        pin = certs.spki_pin(crt)
        self.assertEqual(certs.root_certificate(crt), certs.load_certificate(crt))
        pin2, reason = certs.ensure_certificate(["a.local"], key, crt)
        self.assertEqual(reason, "keine Wachtl-CA vorhanden")
        self.assertEqual(pin, pin2)
        self.assertTrue(ca_crt.exists())
        self.assertIsNone(certs.needs_renewal(crt, ["a.local"]))

    def test_certificate_from_other_ca_is_replaced(self):
        key, crt, ca_key, ca_crt = self.files()
        certs.ensure_certificate(["a.local"], key, crt)
        ca_crt.unlink()
        ca_key.unlink()
        certs.create_ca(["a.local"], ca_key, ca_crt)               # neue CA, neuer Schlüssel
        self.assertEqual(certs.needs_renewal(crt, ["a.local"]), "nicht von der Wachtl-CA ausgestellt")

    def test_command_for_linux_server(self):
        with mock.patch("sys.stdout") as out:
            self.assertEqual(certs.main(["ensure", "--dir", str(self.data), "--names", "wachtl.kunde.local"]), 0)
        text = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertIn("renewed=1", text)
        self.assertIn(f"pin={certs.spki_pin(self.data / 'wachtl.crt')}", text)
        self.assertTrue((self.data / "wachtl-ca.key").exists())


class EnvLayoutTest(TempDirTest):
    def test_roundtrip_and_app_env(self):
        path = self.data / "config" / "wachtl.env"
        write_env(path, {"WACHTL_HOSTNAMES": "a,b", "WACHTL_SECRET_KEY": "x=y", "EXTRA": "1"})
        self.assertEqual(read_env(path), {"WACHTL_HOSTNAMES": "a,b", "WACHTL_SECRET_KEY": "x=y", "EXTRA": "1"})
        with self.assertRaises(ValueError):
            write_env(path, {"WACHTL_SECRET_KEY": "a\nb"})
        layout = Layout.load(self.data, self.inst)
        env = layout.app_env()
        self.assertEqual(env["WACHTL_TRUST_PROXY"], "0")
        self.assertTrue(env["WACHTL_DATABASE_URL"].startswith("sqlite:///"))
        self.assertEqual(env["WACHTL_VM_AGG_URL"], "http://127.0.0.1:8429")
        self.assertEqual(layout.hostnames, ["a", "b"])

    def test_load_without_marker(self):
        with self.assertRaises(FileNotFoundError):
            Layout.load(None, self.inst)


class InstallBase(TempDirTest):
    def do_install(self, **extra):
        run = winsys.Runner(dry_run=True)
        data = {**INPUT, "data_dir": str(self.data), "install_dir": str(self.inst), **extra}
        return installer.install(data, run, start=False), run


class InstallerTest(InstallBase):

    def test_parse_input_errors(self):
        with self.assertRaises(installer.SetupError) as ctx:
            installer.parse_input({"hostnames": "https://x:443", "https_port": 80, "http_port": 80,
                                   "admin_password": "", "data_dir": ""})
        msg = str(ctx.exception)
        for part in ("Ungültiger Servername", "verschieden", "Administrator-Passwort", "Datenordner"):
            self.assertIn(part, msg)
        cfg = installer.parse_input({**INPUT, "data_dir": "D:\\Daten", "hostnames": "fe80::1;srv"})
        self.assertEqual(cfg["hostnames"], ["fe80::1", "srv"])

    def test_install_dry_run_creates_everything(self):
        result, run = self.do_install()
        self.assertTrue(result["ok"])
        self.assertEqual(result["url"], "https://wachtl.kunde.local:8443")
        layout = Layout.load(self.data, self.inst)
        self.assertEqual(layout.env["RAW_RETENTION"], "14d")
        self.assertEqual(layout.env["WACHTL_SPKI_PIN"], result["pin"])
        self.assertEqual(certs.spki_pin(layout.cert_file), result["pin"])
        self.assertTrue((self.data / "rules" / "wachtl.yml").exists())
        am = yaml.safe_load(layout.am_config.read_text(encoding="utf-8"))
        self.assertEqual(am["receivers"][1]["email_configs"][0]["to"], "it@kunde.de")
        self.assertEqual(am["receivers"][0]["webhook_configs"][0]["url"],
                         "http://127.0.0.1:8427/api/internal/alertmanager")
        db = sqlite3.connect(layout.db_file)
        self.assertEqual(db.execute("SELECT role FROM users WHERE username='admin'").fetchone()[0], "admin")
        db.close()
        self.assertEqual((self.inst / "datadir.txt").read_text(encoding="utf-8"), str(self.data))
        xml = layout.winsw_xml.read_text(encoding="utf-8")
        self.assertIn("<id>WachtlServer</id>", xml)
        self.assertIn(f'run --data "{self.data}"', xml)
        flat = [" ".join(c) for c in run.calls]
        self.assertTrue(any("obj= NT SERVICE\\WachtlServer start= delayed-auto" in c for c in flat))
        self.assertTrue(any(c.startswith("icacls") and "*S-1-5-32-544:(OI)(CI)F" in c for c in flat))
        self.assertTrue(any("localport=8443" in c for c in flat))
        self.assertTrue(any("localport=8080" in c for c in flat))
        self.assertTrue(any(c.startswith("schtasks /Create") and "backup" in c for c in flat))
        self.assertIn(result["pin"], Path(result["info_file"]).read_text(encoding="utf-8"))
        # Zertifikat unter „Vertrauenswürdige Stammzertifizierungsstellen“ (Computer)
        trust = [c for c in run.calls if c[0] == "powershell.exe" and "X509Store('Root','LocalMachine')" in c[-1]]
        self.assertEqual(len(trust), 1)
        self.assertIn(str(certs.ca_paths(layout.cert_file)[1]), trust[0][-1])
        self.assertIn("$s.Add($c)", trust[0][-1])

    def test_reinstall_keeps_secrets_and_pin_and_resets_password(self):
        first, _ = self.do_install()
        secret = Layout.load(self.data, self.inst).env["WACHTL_SECRET_KEY"]
        second, _ = self.do_install(admin_password="ganz-neues-passwort", http_port=0)
        layout = Layout.load(self.data, self.inst)
        self.assertEqual(layout.env["WACHTL_SECRET_KEY"], secret)
        self.assertEqual(first["pin"], second["pin"])
        self.assertEqual(layout.http_port, 0)

    def test_upgrade_and_uninstall_dry_run(self):
        self.do_install()
        run = winsys.Runner(dry_run=True)
        with mock.patch.dict(os.environ, {"WACHTL_INSTALL_DIR": str(self.inst)}):
            res = installer.upgrade(None, run, start=False)
            self.assertTrue(res["ok"])
            run2 = winsys.Runner(dry_run=True)
            installer.uninstall(run2, remove_data=True)
        self.assertFalse(self.data.exists())
        self.assertTrue(any(c[:3] == ["netsh", "advfirewall", "firewall"] for c in run2.calls))
        flat = [" ".join(c) for c in run2.calls]
        # auch Regeln, die Windows selbst für die Programme angelegt hat
        self.assertTrue(any("name=all" in c and "program=" in c and "python" in c for c in flat))
        self.assertTrue(any("schtasks /Delete" in c for c in flat))
        self.assertTrue(any("X509Store('Root','LocalMachine')" in c and "$s.Remove($o)" in c and "$s.Add" not in c
                            for c in flat))

    def test_uninstall_reports_leftovers(self):
        self.do_install()

        class StubbornRunner(winsys.Runner):
            """Tut so, als hielte sich eine Firewall-Regel und die geplante Aufgabe."""
            def __call__(self, args, check=True):
                self.calls.append(list(args))
                stays = (args[:5] == ["netsh", "advfirewall", "firewall", "show", "rule"]
                         and args[5] == f"name={winsys.FW_IPERF}") or args[:2] == ["schtasks", "/Query"]
                return subprocess.CompletedProcess(args, 0 if stays else 1, "", "")

        with mock.patch.dict(os.environ, {"WACHTL_INSTALL_DIR": str(self.inst)}), \
                mock.patch.object(winsys, "port_open", return_value=False):
            res = installer.uninstall(StubbornRunner())
        self.assertEqual(res["leftovers"], [f"Firewall-Regel „{winsys.FW_IPERF}“", f"Geplante Aufgabe „{winsys.TASK_BACKUP}“"])
        self.assertIn("iperf3", res["error"])

    def test_check_ports_reports_busy_port(self):
        with socket.socket() as s:
            s.bind(("0.0.0.0", 0))
            s.listen()
            port = s.getsockname()[1]
            cfg = installer.parse_input({**INPUT, "https_port": port, "http_port": 0, "data_dir": str(self.data)})
            problems = installer.check_ports(cfg)
        self.assertTrue(any(f"Port {port}" in p for p in problems))

    def test_cli_writes_result_file_on_error(self):
        inp = self.tmp / "in.json"
        out = self.tmp / "out.json"
        inp.write_text(json.dumps({**INPUT, "admin_password": "", "data_dir": str(self.data)}), encoding="utf-8")
        code = installer.main(["install", "--input", str(inp), "--result", str(out), "--dry-run", "--no-start"])
        self.assertEqual(code, 1)
        self.assertIn("Administrator-Passwort", json.loads(out.read_text(encoding="utf-8"))["error"])


class BackupRestoreTest(InstallBase):
    def test_backup_and_restore_roundtrip(self):
        self.do_install()
        layout = Layout.load(self.data, self.inst)
        (self.data / "vm-agg" / "data").mkdir(parents=True)
        (self.data / "vm-agg" / "data" / "part.bin").write_bytes(b"aggregat")
        archive = host.backup(layout)
        self.assertTrue(archive.exists())
        # Daten verändern, dann zurückspielen
        db = sqlite3.connect(layout.db_file)
        db.execute("DELETE FROM users")
        db.commit()
        db.close()
        (self.data / "vm-agg" / "data" / "part.bin").write_bytes(b"kaputt")
        host.restore(layout, archive)
        db = sqlite3.connect(layout.db_file)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        db.close()
        self.assertEqual((self.data / "vm-agg" / "data" / "part.bin").read_bytes(), b"aggregat")


class ServeTest(unittest.TestCase):
    def call(self, app, path="/", host="srv.local", query=""):
        result = {}

        def start_response(status, headers, exc_info=None):
            result["status"], result["headers"] = status, dict(headers)

        body = b"".join(app({"PATH_INFO": path, "HTTP_HOST": host, "QUERY_STRING": query}, start_response))
        return result["status"], result["headers"], body

    def test_redirect(self):
        status, headers, _ = self.call(serve.redirect_app(443), "/login", "srv.local:80", "next=%2F")
        self.assertTrue(status.startswith("301"))
        self.assertEqual(headers["Location"], "https://srv.local/login?next=%2F")
        _, headers, _ = self.call(serve.redirect_app(8443), "/", "[fe80::1]:8080")
        self.assertEqual(headers["Location"], "https://[fe80::1]:8443/")

    def test_internal_only_and_hsts(self):
        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        internal = serve.internal_only(app)
        self.assertTrue(self.call(internal, "/healthz")[0].startswith("200"))
        self.assertTrue(self.call(internal, "/api/internal/alertmanager")[0].startswith("200"))
        self.assertTrue(self.call(internal, "/admin")[0].startswith("404"))
        self.assertIn("Strict-Transport-Security", self.call(serve.with_security_headers(app))[1])

    def test_renewed_certificate_is_served_without_restart(self):
        import ssl as _ssl

        tmp = Path(tempfile.mkdtemp())
        try:
            key, crt = tmp / "wachtl.key", tmp / "wachtl.crt"
            certs.ensure_certificate(["localhost"], key, crt)
            ca_file = certs.ca_paths(crt)[1]
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]

            def app(environ, start_response):
                start_response("200 OK", [("Content-Type", "text/plain")])
                return [b"ok"]

            servers = serve.build_servers(app, "127.0.0.1", port, 0, 0, str(crt), str(key), dev=True)
            servers.servers = servers.servers[:1]                  # nur HTTPS
            servers.threads = servers.threads[:1]
            servers.start()
            try:
                def served_serial():
                    ctx = _ssl.create_default_context(cafile=str(ca_file))  # wie ein PC mit der Wachtl-CA
                    for _ in range(50):
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=2) as raw, \
                                    ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                                return x509.load_der_x509_certificate(tls.getpeercert(True)).serial_number
                        except ConnectionRefusedError:
                            time.sleep(0.1)
                    raise AssertionError("HTTPS-Server antwortet nicht")

                first = served_serial()
                self.assertFalse(servers.reload_certificate_if_changed())
                new = certs.create_certificate(["localhost"], key, crt)
                os.utime(crt, (time.time() + 5, time.time() + 5))
                self.assertTrue(servers.reload_certificate_if_changed())
                self.assertNotEqual(first, served_serial())
                self.assertEqual(new.serial_number, served_serial())
            finally:
                servers.stop()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class SupervisorTest(unittest.TestCase):
    def test_restarts_crashed_child_and_stops_all(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            marker = tmp / "count"
            crash = f"import pathlib,time; p=pathlib.Path(r'{marker}'); p.write_text(str(int(p.read_text() or 0)+1) if p.exists() else '1'); time.sleep(0.2); raise SystemExit(2)"
            stay = "import signal,sys,time; signal.signal(signal.SIGTERM, lambda *a: (print('bye', flush=True), sys.exit(0))); print('läuft', flush=True); time.sleep(60)"
            stop = threading.Event()
            sup = Supervisor([ProcSpec("crash", [sys.executable, "-c", crash]),
                              ProcSpec("stay", [sys.executable, "-c", stay])],
                             tmp / "logs", stop_event=stop, backoff_max=0.5, grace=5, poll_interval=0.05)
            t = threading.Thread(target=sup.run)
            t.start()
            deadline = time.time() + 10
            while time.time() < deadline and (not marker.exists() or int(marker.read_text()) < 3):
                time.sleep(0.1)
            status = {s["name"]: s for s in sup.status()}
            self.assertTrue(status["stay"]["running"])
            self.assertGreaterEqual(int(marker.read_text()), 3)
            stop.set()
            t.join(timeout=15)
            self.assertFalse(t.is_alive())
            self.assertFalse(any(s["running"] for s in sup.status()))
            stay_log = (tmp / "logs" / "stay.log").read_text(encoding="utf-8")
            self.assertIn("läuft", stay_log)
            self.assertIn("bye", stay_log)
            self.assertIn("Beendet mit Code 2", (tmp / "logs" / "crash.log").read_text(encoding="utf-8"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_run_once_returns_exit_code(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            sup = Supervisor([], tmp)
            self.assertEqual(sup.run_once(ProcSpec("init", [sys.executable, "-c", "print('x'); raise SystemExit(4)"])), 4)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class HostSpecTest(InstallBase):
    def test_process_specs(self):
        self.do_install()
        layout = Layout.load(self.data, self.inst)
        specs = {s.name: s for s in host.build_specs(layout)}
        self.assertEqual(list(specs), ["vm-raw", "vm-agg", "alertmanager", "web", "vmalert", "rtp", "serverprobe"])
        self.assertEqual(specs["rtp"].args[1:], ["-m", "wachtl.rtp", "5004"])
        self.assertEqual(specs["web"].env["WACHTL_RTP_PORT"], "5004")
        probe_env = specs["serverprobe"].env
        self.assertEqual(probe_env["WACHTL_SERVER_PROBE_URL"], "https://127.0.0.1:8443")
        self.assertEqual(probe_env["WACHTL_SPKI_PIN"], layout.env["WACHTL_SPKI_PIN"])
        self.assertEqual(probe_env["WACHTL_SERVER_PROBE_DIR"], specs["web"].env["WACHTL_SERVER_PROBE_DIR"])
        layout.env["SERVER_PROBE"] = "0"
        self.assertNotIn("serverprobe", {s.name for s in host.build_specs(layout)})
        self.assertIn("-retentionPeriod=14d", specs["vm-raw"].args)
        self.assertIn("--cluster.listen-address=", specs["alertmanager"].args)
        self.assertIn("-remoteWrite.url=http://127.0.0.1:8429", specs["vmalert"].args)
        self.assertEqual(specs["web"].env["WACHTL_HTTPS_PORT"], "8443")
        self.assertEqual(specs["web"].env["WACHTL_IPERF_PORT"], "5201")

    def test_iperf_server_process_and_firewall(self):
        _, run = self.do_install(iperf_port=5301)
        flat = [" ".join(c) for c in run.calls]
        self.assertTrue(any("name=Wachtl Server iperf3" in c and "protocol=UDP" in c and "localport=5301" in c
                            for c in flat))
        layout = Layout.load(self.data, self.inst)
        layout.iperf_exe.parent.mkdir(parents=True, exist_ok=True)
        layout.iperf_exe.write_bytes(b"")
        specs = {s.name: s for s in host.build_specs(layout)}
        self.assertEqual(specs["iperf3"].args[1:], ["-s", "-p", "5301"])
        # 0 = aus: kein Prozess, keine Firewall-Regel
        _, run = self.do_install(iperf_port=0)
        self.assertFalse(any("iperf3" in " ".join(c) and "add" in c for c in run.calls))
        self.assertNotIn("iperf3", {s.name for s in host.build_specs(Layout.load(self.data, self.inst))})
        with self.assertRaises(installer.SetupError):
            installer.parse_input({**INPUT, "data_dir": "D:\\x", "iperf_port": 8443})

    def test_rtp_reflector_process_and_firewall(self):
        _, run = self.do_install(rtp_port=5104)
        flat = [" ".join(c) for c in run.calls]
        self.assertTrue(any("name=Wachtl Server RTP" in c and "protocol=UDP" in c and "localport=5104" in c
                            for c in flat))
        self.assertEqual({s.name: s for s in host.build_specs(Layout.load(self.data, self.inst))}["rtp"].args[-1],
                         "5104")
        _, run = self.do_install(rtp_port=0)
        self.assertFalse(any("Wachtl Server RTP" in " ".join(c) and "add" in c for c in run.calls))
        self.assertNotIn("rtp", {s.name for s in host.build_specs(Layout.load(self.data, self.inst))})
        with self.assertRaises(installer.SetupError):
            installer.parse_input({**INPUT, "data_dir": "D:\\x", "rtp_port": 5201})
