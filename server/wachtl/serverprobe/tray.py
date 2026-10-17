"""Lokaler Endpunkt für das Tray-Symbol auf dem Windows-Server (docs/STOERUNGSMELDUNGEN.md).

Lauscht nur auf 127.0.0.1. Das Tray-Programm fragt den Zustand ab und gibt Störungsmeldungen ab; die
Server-Probe leitet sie mit ihrem Probe-Token an ``POST /api/probe/v1/report`` weiter. Ist der Server
gerade nicht erreichbar, bleibt die Meldung in ``reports-pending.json`` und wird nachgeliefert.
"""
from __future__ import annotations

import json
import logging
import math
import socket
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from ..reports import CATEGORIES, DURATIONS, MAX_AGE_S, MAX_FUTURE_S

log = logging.getLogger("wachtl.serverprobe.tray")

DEFAULT_PORT = 47251
MAX_BODY = 16 * 1024
RATE_LIMIT = 30                 # Meldungen je Stunde und Benutzer …
RATE_LIMIT_TOTAL = 300          # … und je Rechner (Terminalserver mit vielen Benutzern)
MAX_PENDING = 200
PENDING_FILE = "reports-pending.json"


class ReportRejected(Exception):
    """Der Server hat die Meldung als ungültig abgelehnt (HTTP 400) – nicht erneut senden."""


def validate(payload, now: float | None = None) -> dict:
    """Prüft eine Meldung vom Tray und liefert die bereinigten Felder; ValueError mit deutschem Text."""
    if not isinstance(payload, dict):
        raise ValueError("Ungültige Meldung.")
    now = time.time() if now is None else now
    ts = payload.get("occurred_at")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
        raise ValueError("Zeitpunkt fehlt.")
    ts = int(ts)
    if ts < now - MAX_AGE_S:
        raise ValueError("Der Zeitpunkt liegt mehr als 7 Tage zurück.")
    if ts > now + MAX_FUTURE_S:
        raise ValueError("Der Zeitpunkt liegt in der Zukunft.")
    category = payload.get("category")
    if category not in CATEGORIES:
        raise ValueError("Bitte angeben, was passiert ist.")
    duration = payload.get("duration") or "unknown"
    if duration not in DURATIONS:
        raise ValueError("Ungültige Dauer.")

    def text(key: str, limit: int) -> str:
        value = payload.get(key)
        return value.strip()[:limit] if isinstance(value, str) else ""

    return {"occurred_at": ts, "category": category, "duration": duration,
            "description": text("description", 1000), "user": text("user", 128)}


class PendingReports:
    """Noch nicht zugestellte Meldungen, als JSON-Datei – überlebt Neustarts."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def load(self) -> list[dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _save(self, items: list[dict]) -> None:
        if not items:
            self.path.unlink(missing_ok=True)
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items), encoding="utf-8")
        tmp.replace(self.path)

    def add(self, report: dict) -> None:
        with self.lock:
            items = self.load()
            items.append(report)
            self._save(items[-MAX_PENDING:])

    def count(self) -> int:
        with self.lock:
            return len(self.load())

    def flush(self, send: Callable[[dict], None]) -> int:
        """Versucht alle Meldungen zuzustellen; bricht beim ersten Netz-/Serverfehler ab. Liefert die Zahl offener.

        Gesendet wird ohne Sperre, damit Statusabfragen und neue Meldungen nicht auf den Server warten."""
        done = set()
        for report in self.load():
            try:
                send(report)
            except ReportRejected as exc:
                log.warning("Server lehnt gespeicherte Meldung %s ab: %s", report.get("report_id"), exc)
            except Exception as exc:  # noqa: BLE001 – später erneut versuchen
                log.debug("Meldung noch nicht zustellbar: %s", exc)
                break
            done.add(report.get("report_id"))
        with self.lock:
            remaining = [r for r in self.load() if r.get("report_id") not in done]
            if done:
                self._save(remaining)
            return len(remaining)


class TrayService:
    """Fachlogik des Endpunkts, ohne HTTP – testbar."""

    def __init__(self, status: Callable[[], dict], send: Callable[[dict], None], pending: PendingReports,
                 hostname: str, ready: Callable[[], bool] = lambda: True, clock: Callable[[], float] = time.time):
        self.status_fn, self.send, self.pending, self.hostname = status, send, pending, hostname
        self.ready, self.clock = ready, clock
        self.recent: dict[str, deque[float]] = {}
        self.rate_lock = threading.Lock()

    def status(self) -> dict:
        return {**self.status_fn(), "pending_reports": self.pending.count()}

    def rate_ok(self, user: str) -> bool:
        now = self.clock()
        with self.rate_lock:
            for key in list(self.recent):          # abgelaufene Treffer weg, damit die Tabelle nicht wächst
                hits = self.recent[key]
                while hits and hits[0] < now - 3600:
                    hits.popleft()
                if not hits:
                    del self.recent[key]
            mine = self.recent.setdefault(user.lower(), deque())
            if len(mine) >= RATE_LIMIT or sum(map(len, self.recent.values())) >= RATE_LIMIT_TOTAL:
                return False
            mine.append(now)
            return True

    def report(self, payload) -> tuple[int, dict]:
        try:
            fields = validate(payload, self.clock())
        except ValueError as exc:
            return 400, {"error": str(exc)}
        if not self.ready():
            return 409, {"error": "Wachtl ist noch nicht am Server registriert."}
        if not self.rate_ok(fields["user"]):
            return 429, {"error": "Zu viele Meldungen – bitte später erneut versuchen."}
        report = {"report_id": str(uuid.uuid4()), **fields, "hostname": self.hostname}
        try:
            self.send(report)
        except ReportRejected as exc:
            return 400, {"error": str(exc) or "Der Server hat die Meldung abgelehnt."}
        except Exception as exc:  # noqa: BLE001 – Server nicht erreichbar: speichern und nachliefern
            log.info("Meldung gespeichert, Server nicht erreichbar: %s", exc)
            try:
                self.pending.add(report)
            except OSError as err:
                log.error("Meldung konnte nicht gespeichert werden: %s", err)
                return 500, {"error": "Die Meldung konnte weder gesendet noch gespeichert werden."}
            return 202, {"ok": True, "delivered": False}
        log.info("Störungsmeldung %s (%s) an den Server übermittelt", report["report_id"], report["category"])
        return 202, {"ok": True, "delivered": True}


def make_handler(service: TrayService, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "wachtl-tray"
        sys_version = ""

        def log_message(self, fmt, *args):  # noqa: D102 – kein stderr-Log je Anfrage
            log.debug("%s %s", self.address_string(), fmt % args)

        def reply(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def guard(self) -> bool:
            # Browser-Schutz: eigene Kopfzeile + Host-Prüfung (DNS-Rebinding); Preflights (OPTIONS) nie erlaubt
            if self.headers.get("X-Wachtl-Tray") != "1" or (self.headers.get("Host") or "").lower() not in allowed_hosts:
                self.reply(403, {"error": "Nicht erlaubt."})
                return False
            return True

        def do_GET(self):  # noqa: N802
            if not self.guard():
                return
            if self.path.split("?")[0] == "/tray/v1/status":
                self.reply(200, service.status())
            elif self.path.split("?")[0] == "/tray/v1/report":
                self.reply(405, {"error": "Nur POST."})
            else:
                self.reply(404, {"error": "Unbekannt."})

        def do_POST(self):  # noqa: N802
            if not self.guard():
                return
            if self.path.split("?")[0] != "/tray/v1/report":
                self.reply(404 if self.path.split("?")[0] != "/tray/v1/status" else 405, {"error": "Unbekannt."})
                return
            if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                self.reply(403, {"error": "Nicht erlaubt."})
                return
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self.reply(400, {"error": "Meldung zu groß."})
                return
            try:
                payload = json.loads(self.rfile.read(length) or b"null")
            except ValueError:
                self.reply(400, {"error": "Ungültige Meldung."})
                return
            status, body = service.report(payload)
            self.reply(status, body)

        def do_OPTIONS(self):  # noqa: N802
            self.reply(403, {"error": "Nicht erlaubt."})

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS

    return Handler


class _LoopbackServer(ThreadingHTTPServer):
    # Port exklusiv belegen: sonst könnte unter Windows das Programm eines anderen Benutzers mitlauschen
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class TrayEndpoint:
    def __init__(self, service: TrayService, port: int = DEFAULT_PORT):
        self.service, self.port = service, port
        self.httpd: ThreadingHTTPServer | None = None

    def start(self) -> bool:
        try:
            self.httpd = _LoopbackServer(("127.0.0.1", self.port), make_handler(self.service, self.port))
        except OSError as exc:
            log.warning("Tray-Endpunkt 127.0.0.1:%s nicht verfügbar (%s) – Störungsmeldungen über das Symbol aus",
                        self.port, exc)
            return False
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="tray-endpoint").start()
        log.info("Tray-Endpunkt lauscht auf 127.0.0.1:%s", self.port)
        return True

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
