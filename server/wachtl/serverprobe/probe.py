"""Hauptschleifen der Server-Probe: registrieren, Konfiguration holen, Checks steuern, hochladen, Heartbeat."""
from __future__ import annotations

import json
import logging
import os
import platform
import socket
import threading
import time
from collections import deque
from pathlib import Path

from .. import __version__, repo
from . import icmp, net
from .api import Api, ApiError
from .runners import (BandwidthRunner, NetscanRunner, PathRunner, PingRunner, RtpRunner, Runner, ScheduledRunner,
                      check_key)
from .tray import PENDING_FILE, PendingReports, ReportRejected, TrayEndpoint, TrayService

log = logging.getLogger("wachtl.serverprobe")
ENROLL_FILE = "enroll.json"     # legt der Server beim Start an (einmaliger Enrollment-Token)
STATE_FILE = "probe.json"       # Probe-ID und Token nach der Registrierung
MAX_BUFFER = 500_000            # Zeilen; der Server ist lokal, längere Ausfälle puffert niemand
BATCH = 5000
SUPPORTED = ("ping", "path", "iperf", "speedtest", "rtp", "netscan")


def write_private(path: Path, data: dict) -> None:
    """JSON nur für den Besitzer lesbar schreiben (Token)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def probe_hostname() -> str:
    name = (os.environ.get("WACHTL_SERVER_PROBE_NAME") or socket.gethostname() or "").split(".")[0]
    return name if repo.valid_probe_hostname(name) else "wachtl-server"


class ServerProbe:
    def __init__(self, url: str, pin: str, state_dir: Path, iperf_exe: str | None = None,
                 stop_event: threading.Event | None = None, pinger=None, gateway=None, measure=None,
                 tray_port: int | None = None, public_url: str = "", measure_rtp=None):
        self.url, self.pin, self.state_dir, self.iperf_exe = url, pin, Path(state_dir), iperf_exe
        self.measurement = {"pinger": pinger or icmp.ping, "gateway": gateway or net.gateway}
        self.measure = measure
        self.measure_rtp = measure_rtp
        self.stop_event = stop_event or threading.Event()
        self.api: Api | None = None
        self.buffer: deque[str] = deque(maxlen=MAX_BUFFER)
        self.buffer_lock = threading.Lock()
        self.runners: dict[str, Runner] = {}
        self.runner_lock = threading.Lock()
        self.config: dict | None = None
        self.config_changed = threading.Event()
        self.started = time.monotonic()
        self.batch_no = 0
        self.last_contact = 0.0
        self.public_url = public_url
        self.tray_port = tray_port
        self.pending_reports = PendingReports(self.state_dir / PENDING_FILE)
        self.tray: TrayEndpoint | None = None

    # -- Registrierung ---------------------------------------------------------
    def ensure_registered(self) -> bool:
        state = read_json(self.state_dir / STATE_FILE)
        if state and state.get("token"):
            self.api = Api(self.url, self.pin, state["token"])
            return True
        enroll = read_json(self.state_dir / ENROLL_FILE)
        if not enroll or not enroll.get("token"):
            return False
        try:
            result = Api(self.url, self.pin).enroll(enroll["token"], probe_hostname(), platform.platform())
        except Exception as exc:  # noqa: BLE001 – weiter versuchen, nie abstürzen
            log.warning("Registrierung am Server fehlgeschlagen: %s", exc)
            return False
        write_private(self.state_dir / STATE_FILE, {"probe_id": result["probe_id"], "token": result["token"],
                                                    "site_name": result.get("site_name")})
        (self.state_dir / ENROLL_FILE).unlink(missing_ok=True)
        log.info("Server-Probe als Probe %s am Standort %s registriert", result["probe_id"], result.get("site_name"))
        self.api = Api(self.url, self.pin, result["token"])
        return True

    # -- Ablauf -------------------------------------------------------------------
    def run(self) -> None:
        log.info("Wachtl-Server-Probe %s startet, Server %s, Daten %s", __version__, self.url, self.state_dir)
        if self.tray_port:
            self.tray = TrayEndpoint(TrayService(self.tray_status, self.send_report, self.pending_reports,
                                                 probe_hostname(), ready=lambda: self.api is not None), self.tray_port)
            self.tray.start()
        while not self.ensure_registered():
            log.info("Warte auf Registrierung (%s vom Server) …", self.state_dir / ENROLL_FILE)
            if self.stop_event.wait(30):
                return
        loops = [threading.Thread(target=fn, daemon=True, name=fn.__name__)
                 for fn in (self.config_loop, self.upload_loop, self.heartbeat_loop, self.topology_loop)]
        for t in loops:
            t.start()
        self.stop_event.wait()
        if self.tray:
            self.tray.stop()
        self.stop_runners()
        self.upload_pending()
        log.info("Server-Probe beendet")

    # -- Tray-Symbol (Störungsmeldungen) --------------------------------------------
    def tray_status(self) -> dict:
        state = read_json(self.state_dir / STATE_FILE) or {}
        return {
            "role": "server", "name": probe_hostname(), "site": state.get("site_name") or "",
            "server_url": self.public_url or self.url, "dashboard_url": self.public_url or self.url,
            "version": __version__, "enrolled": self.api is not None,
            "connected": self.last_contact > 0 and time.time() - self.last_contact < 120,
            "last_contact": int(self.last_contact),
        }

    def send_report(self, report: dict) -> None:
        try:
            # kurzer Timeout: das Tray wartet nur 25 s, danach lieber puffern als doppelt melden lassen
            Api(self.url, self.pin, self.api.token, timeout=10).report(report)
        except ApiError as exc:
            if exc.status == 400:
                raise ReportRejected(str(exc).split(": ", 1)[-1]) from exc
            raise

    def sink(self, line: str) -> None:
        with self.buffer_lock:
            self.buffer.append(line)

    def report(self, kind: str):
        def send(payload: dict) -> None:
            for attempt in range(5):
                try:
                    self.api.result(kind, payload)
                    return
                except (ApiError, OSError) as exc:
                    log.debug("Ergebnis nicht gesendet (%s), neuer Versuch", exc)
                    if self.stop_event.wait(30 * (attempt + 1)):
                        return
            log.warning("Ergebnis von Check %s konnte nicht gesendet werden", payload.get("check_id"))
        return send

    def create_runner(self, check: dict) -> Runner:
        if check["type"] == "path":
            return PathRunner(check, self.sink, self.report("path"), **self.measurement)
        if check["type"] in ("iperf", "speedtest"):
            return BandwidthRunner(check, self.report("bandwidth"), self.iperf_exe, self.measure)
        if check["type"] == "rtp":
            return RtpRunner(check, self.report("rtp"), self.measure_rtp)
        if check["type"] == "netscan":
            return NetscanRunner(check, self.report("netscan"))
        return PingRunner(check, self.sink, **self.measurement)

    def apply_config(self, config: dict) -> None:
        wanted = {check_key(c): c for c in config.get("checks", []) if c.get("type") in SUPPORTED}
        with self.runner_lock:
            for key in [k for k in self.runners if k not in wanted]:
                self.runners.pop(key).stop()
            for key, check in wanted.items():
                if key not in self.runners:
                    self.runners[key] = self.create_runner(check).start()
            self.config = config
        types: dict[str, int] = {}
        for c in wanted.values():
            types[c["type"]] = types.get(c["type"], 0) + 1
        log.info("Konfiguration %s aktiv: %d Checks (%s)", config.get("etag"), len(wanted),
                 ", ".join(f"{n} {t}" for t, n in types.items()) or "keine")

    def stop_runners(self) -> None:
        with self.runner_lock:
            for r in self.runners.values():
                r.stop()
            self.runners.clear()

    def config_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                fresh = self.api.config(self.config.get("etag") if self.config else None)
                if fresh is not None:
                    self.apply_config(fresh)
            except ApiError as exc:
                if exc.auth_error:
                    log.error("Server lehnt das Token der Server-Probe ab (%s) – Probe deaktiviert oder gelöscht?", exc)
                    self.stop_runners()
                    self.config = None
                else:
                    log.warning("Konfiguration nicht abrufbar: %s", exc)
            except OSError as exc:
                log.warning("Konfiguration nicht abrufbar: %s", exc)
            wait = 15 if self.config is None else max(30, int(self.config.get("config_poll_s") or 300))
            self.config_changed.wait(wait)
            self.config_changed.clear()

    def upload_pending(self) -> bool:
        while True:
            with self.buffer_lock:
                batch = list(self.buffer)[:BATCH]
            if not batch:
                return True
            self.batch_no += 1
            batch_id = f"srv-{int(time.time())}-{self.batch_no}"
            try:
                self.api.ingest(batch_id, batch)
            except (ApiError, OSError) as exc:
                log.warning("Hochladen fehlgeschlagen, %d Werte bleiben im Puffer: %s", len(self.buffer), exc)
                return False
            with self.buffer_lock:
                for _ in range(len(batch)):
                    self.buffer.popleft()
            if len(batch) < BATCH:
                return True

    def upload_loop(self) -> None:
        backoff = 0
        while not self.stop_event.wait(max(2, int((self.config or {}).get("upload_interval_s") or 10)) + backoff):
            backoff = 0 if self.upload_pending() else min(300, max(5, backoff * 2))

    def topology_loop(self) -> None:
        """Switch-Abfragen per SNMP (docs/TOPOLOGIE.md); läuft nur, solange der Server Aufträge hat."""
        from . import topology

        topology.loop(lambda: self.api if self.config is not None else None, self.stop_event)

    def heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                resp = self.api.heartbeat({
                    "version": __version__, "os": f"Wachtl-Server · {platform.system()} {platform.release()}",
                    "hostname": probe_hostname(), "buffer_items": len(self.buffer),
                    "uptime_s": int(time.monotonic() - self.started), "addresses": net.local_addresses(),
                })
                self.last_contact = time.time()
                self.handle_commands(resp.get("commands") or [])
                self.pending_reports.flush(self.send_report)
                if resp.get("config_etag") != (self.config or {}).get("etag"):
                    self.config_changed.set()
            except (ApiError, OSError) as exc:
                log.debug("Heartbeat fehlgeschlagen: %s", exc)
            self.stop_event.wait(max(10, int((self.config or {}).get("heartbeat_interval_s") or 30)))

    def handle_commands(self, commands: list[dict]) -> None:
        for cmd in commands:
            with self.runner_lock:
                runner = next((r for r in self.runners.values() if r.check["id"] == cmd.get("check_id")), None)
            if cmd.get("type") == "run_check" and isinstance(runner, ScheduledRunner):
                log.info("Auftrag vom Server: Check %s jetzt messen", cmd["check_id"])
                runner.run_now()
            elif cmd.get("type") == "retrace" and isinstance(runner, PathRunner):
                log.info("Auftrag vom Server: Pfad von Check %s neu ermitteln", cmd["check_id"])
                runner.request_retrace()
            else:
                log.warning("Auftrag %s für Check %s kann nicht ausgeführt werden", cmd.get("type"), cmd.get("check_id"))
