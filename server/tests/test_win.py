"""Tests der Windows-Variante, soweit sie plattformunabhängig ist (Systembefehle im Trockenlauf)."""
import base64
import hashlib
import io
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
    def test_pin_matches_openssl_and_survives_renewal(self):
        key, crt = self.data / "k.pem", self.data / "c.pem"
        pin, reason = certs.ensure_certificate(["wachtl.kunde.local", "10.0.0.5"], key, crt)
        self.assertEqual(reason, "kein Zertifikat vorhanden")
        cmd = f"openssl x509 -in '{crt}' -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64"
        self.assertEqual(pin, subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip())
        self.assertIsNone(certs.needs_renewal(crt, ["wachtl.kunde.local", "10.0.0.5"]))
        # neuer Name -> neues Zertifikat, gleicher Schlüssel -> gleicher Pin
        pin2, reason2 = certs.ensure_certificate(["wachtl.kunde.local", "10.0.0.6"], key, crt)
        self.assertEqual(reason2, "Servernamen haben sich geändert")
        self.assertEqual(pin, pin2)
        san = subprocess.run(["openssl", "x509", "-in", str(crt), "-noout", "-ext", "subjectAltName"],
                             capture_output=True, text=True).stdout
        self.assertIn("DNS:wachtl.kunde.local", san)
        self.assertIn("IP Address:10.0.0.6", san)

    def test_short_validity_triggers_renewal(self):
        key, crt = self.data / "k.pem", self.data / "c.pem"
        certs.create_certificate(["a.local"], key, crt, days=10)
        self.assertIn("läuft in", certs.needs_renewal(crt, ["a.local"]))


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
                                   "admin_password": "kurz", "data_dir": ""})
        msg = str(ctx.exception)
        for part in ("Ungültiger Servername", "verschieden", "12 Zeichen", "Datenordner"):
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
        inp.write_text(json.dumps({**INPUT, "admin_password": "x", "data_dir": str(self.data)}), encoding="utf-8")
        code = installer.main(["install", "--input", str(inp), "--result", str(out), "--dry-run", "--no-start"])
        self.assertEqual(code, 1)
        self.assertIn("12 Zeichen", json.loads(out.read_text(encoding="utf-8"))["error"])


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
        self.assertEqual(list(specs), ["vm-raw", "vm-agg", "alertmanager", "web", "vmalert"])
        self.assertIn("-retentionPeriod=14d", specs["vm-raw"].args)
        self.assertIn("--cluster.listen-address=", specs["alertmanager"].args)
        self.assertIn("-remoteWrite.url=http://127.0.0.1:8429", specs["vmalert"].args)
        self.assertEqual(specs["web"].env["WACHTL_HTTPS_PORT"], "8443")
