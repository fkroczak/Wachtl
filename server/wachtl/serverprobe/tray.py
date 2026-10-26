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


MAX_NOTICES = 50
BALLOON_MAX = 255
OUTAGE_ALERTS = ("WachtlTargetDown", "WachtlWanDown")
LINK_GRACE_S = 60       # so lange vor/nach einer eigenen Netztrennung gelten Ausfälle dieses PCs als deren Folge
LINK_HISTORY = 20


def _duration(seconds: float) -> str:
    seconds = max(int(seconds), 0)
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds} s" if seconds else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def _join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " und " + parts[-1]


def outage_text(members: list[dict]) -> tuple[str, str, str, str]:
    """Gleichzeitige Ausfälle einer Probe als ein Hinweis: (Titel, Meldung, Lösung, Schwere).

    Die wahrscheinliche Ursache steht vorn: Gateway weg → lokales Netz, nur Internet weg → Internetzugang,
    sonst einzelne Ziele. Was davon abhängt, wird nur noch gezählt."""
    where = next((m.get("where") for m in members if m.get("where")), "")
    gateway = any(m.get("alertname") == "WachtlTargetDown" and m.get("role") == "gateway" for m in members)
    wan = any(m.get("alertname") == "WachtlWanDown" for m in members)
    targets = sorted({m.get("target") or "?" for m in members
                      if m.get("alertname") == "WachtlTargetDown" and m.get("role") != "gateway"})
    severity = "critical" if any(m.get("severity") == "critical" for m in members) else (
        "warning" if any(m.get("severity") == "warning" for m in members) else "info")
    affected = (["das Internet"] if wan and gateway else []) + (
        [targets[0]] if len(targets) == 1 else [f"{len(targets)} Ziele"] if targets else [])
    if gateway:
        title = "Lokales Netz gestört"
        message = "Das Gateway (Router) antwortet nicht."
        if affected:
            message += f" Dadurch sind auch {_join(affected)} nicht erreichbar."
        solution = "Router, Switch und Netzwerkkabel dieses Standorts prüfen."
    elif wan:
        title = "Internet ausgefallen"
        message = "Keine Internet-Referenz antwortet, das lokale Netz ist erreichbar."
        if affected:
            message += f" Betroffen: {_join(affected)}."
        solution = "Internetanschluss und Router prüfen, ggf. Störung beim Provider."
    else:
        title = "Ausfall"
        message = (f"{targets[0]} ist nicht erreichbar." if len(targets) == 1
                   else f"{len(targets)} Ziele sind nicht erreichbar: {', '.join(targets[:5])}"
                   + (" …" if len(targets) > 5 else "") + ".")
        solution = ""
    if len(members) == 1 and not gateway and not wan:
        message = members[0].get("text") or message   # einzelner Ausfall: Satz des Servers mit Dauer
    return (f"{title}: {where}" if where else title), message, solution, severity


class NoticeFeed:
    """Störungen und Hinweise aller Standorte für das Tray-Symbol auf dem Wachtl-Server.

    Liefert dasselbe Format wie ``GET /tray/v1/findings`` der Windows-Probe (docs/CLIENT-HINWEISE.md): fortlaufende
    Nummer je Änderung, Zählung ab der Startzeit in ms. Laufende Alarme sind aktiv, bis der Server sie als beendet
    meldet; einmalige Ereignisse (nachträglich erkannte Ausfälle, Paketverlust, Hinweise von PCs) tragen
    ``event = true`` und erscheinen nur als Sprechblase.

    Gleichzeitige Ausfälle derselben Probe (Gateway, Internet, Ziele) werden ein Hinweis mit der wahrscheinlichen
    Ursache. Verliert dieser PC selbst das Netz (Netzwerkkarte aus, Kabel ab), erscheint genau ein Hinweis
    „Keine Netzwerkverbindung“; die Ausfälle der eigenen Probe sind dessen Folge und erscheinen nicht einzeln.
    """

    def __init__(self, clock: Callable[[], float] = time.time):
        self.lock = threading.Lock()
        self.clock = clock
        self.start = self.seq = int(clock() * 1000)
        self.entries: dict[str, dict] = {}
        self.active: dict[str, dict] = {}   # Schlüssel alert:<id> → zuletzt veröffentlichter Eintrag
        self.groups: dict[str, dict] = {}   # Probe-ID → laufender Sammel-Ausfall {"entry", "members"}
        self.absorbed: dict[str, dict] = {} # laufende Ausfälle der eigenen Probe während einer Netztrennung
        self.cursor: dict | None = None
        self.own_probe: str | None = None
        self.link_down_since: float | None = None
        self.link_periods: deque[tuple[float, float]] = deque(maxlen=LINK_HISTORY)

    def _publish(self, entry: dict) -> None:
        self.seq += 1
        entry = {**entry, "seq": self.seq}
        self.entries[entry["finding_id"]] = entry
        if len(self.entries) > MAX_NOTICES:
            for key in sorted(self.entries, key=lambda k: self.entries[k]["seq"])[:len(self.entries) - MAX_NOTICES]:
                del self.entries[key]

    @staticmethod
    def _entry(item: dict, state: str, event: bool) -> dict:
        text = (item.get("text") or "").strip()
        return {
            "finding_id": item["key"], "kind": item.get("alertname") or "", "severity": item.get("severity") or "warning",
            "state": state, "title": (item.get("title") or "Wachtl")[:120], "message": text[:500], "solution": "",
            "balloon": text[:BALLOON_MAX], "adapter": "", "detected_at": int(item.get("ts") or time.time()),
            "resolved_at": int(item["end"]) if state == "resolved" and item.get("end") else None, "event": event,
        }

    @staticmethod
    def _outage_entry(key: str, members: list[dict], event: bool) -> dict:
        title, message, solution, severity = outage_text(members)
        balloon = message + (f" Lösung: {solution}" if solution else "")
        return {
            "finding_id": key, "kind": "outage", "severity": severity, "state": "active", "title": title[:120],
            "message": message[:500], "solution": solution, "balloon": balloon[:BALLOON_MAX], "adapter": "",
            "detected_at": int(min((m.get("ts") or time.time()) for m in members)), "resolved_at": None,
            "event": event,
        }

    # -- eigene Netzwerkverbindung ---------------------------------------------------------------------------
    def set_link(self, up: bool) -> None:
        """Netzwerkverbindung dieses PCs (Default-Route vorhanden) – von der Server-Probe alle paar Sekunden."""
        with self.lock:
            now = self.clock()
            if not up and self.link_down_since is None:
                self.link_down_since = now
                # schon gemeldete Ausfälle dieses PCs sind Folge der Trennung: still beenden
                group = self.groups.pop(self.own_probe or "", None)
                if group:
                    for key, item in group["members"].items():
                        self.absorbed[key] = item
                    self._publish({**group["entry"], "state": "resolved", "quiet": True, "resolved_at": int(now)})
                self._publish({
                    "finding_id": "link", "kind": "link_down", "severity": "critical", "state": "active",
                    "title": "Keine Netzwerkverbindung",
                    "message": "Dieser PC (Wachtl-Server) hat keine Netzwerkverbindung – die Netzwerkkarte ist "
                               "deaktiviert oder das Kabel getrennt. Deshalb sind Gateway, Internet und alle Ziele "
                               "von hier aus nicht erreichbar.",
                    "solution": "Netzwerkkabel prüfen bzw. die Netzwerkkarte wieder aktivieren.",
                    "balloon": "Netzwerkkarte deaktiviert oder Kabel getrennt – Gateway, Internet und Ziele sind "
                               "von hier aus nicht erreichbar.",
                    "adapter": "", "detected_at": int(now), "resolved_at": None, "event": False,
                })
            elif up and self.link_down_since is not None:
                since, self.link_down_since = self.link_down_since, None
                self.link_periods.append((since, now))
                self._publish({"finding_id": "link", "kind": "link_down",
                               "severity": "critical", "state": "resolved",
                               "title": "Netzwerkverbindung wieder da",
                               "message": f"Die Netzwerkverbindung dieses PCs war {_duration(now - since)} getrennt.",
                               "solution": "", "balloon": f"Nach {_duration(now - since)} wieder verbunden.",
                               "adapter": "", "detected_at": int(since), "resolved_at": int(now), "event": False})

    def _caused_by_link(self, item: dict) -> bool:
        """Ausfall der eigenen Probe während (oder kurz um) eine eigene Netztrennung."""
        if self.own_probe is None or str(item.get("probe_id")) != self.own_probe:
            return False
        if self.link_down_since is not None:
            return True
        ts = item.get("ts") or 0
        end = item.get("end") or ts
        return any(start - LINK_GRACE_S <= end and ts <= stop + LINK_GRACE_S for start, stop in self.link_periods)

    # -- Hinweise vom Server ---------------------------------------------------------------------------------
    def accept(self, response: dict) -> None:
        """Antwort von ``GET /api/probe/v1/notices`` übernehmen."""
        with self.lock:
            first = self.cursor is None
            self.cursor = response.get("cursor") or self.cursor
            active_ids = {f"alert:{i}" for i in response.get("active") or []}
            now = self.clock()
            settled = self.link_down_since is None and all(now - stop > LINK_GRACE_S for _, stop in self.link_periods)
            # nach der Netztrennung: was dann noch läuft, ist eine eigene Störung
            for key in list(self.absorbed):
                if key not in active_ids:
                    del self.absorbed[key]
                elif settled:
                    self._join_group(self.absorbed.pop(key))
            changed: set[str] = set()
            late: dict[str, list[dict]] = {}
            for item in response.get("items") or []:
                if first:
                    continue  # beim Start nichts Altes nachholen, nur den Stand merken
                firing = item.get("source") == "alert" and item.get("state") == "firing" and item["key"] in active_ids
                if item.get("source") == "alert" and item.get("alertname") in OUTAGE_ALERTS:
                    if self._caused_by_link(item):
                        if firing:
                            self.absorbed[item["key"]] = item
                        continue
                    if firing:
                        changed.add(self._join_group(item, publish=False))
                    else:
                        late.setdefault(str(item.get("probe_id")), []).append(item)
                    continue
                if firing:
                    entry = self._entry(item, "active", False)
                    self.active[item["key"]] = entry
                else:
                    entry = self._entry(item, "active", True)
                self._publish(entry)
            for probe in changed:
                group = self.groups[probe]
                group["entry"] = self._outage_entry(group["entry"]["finding_id"], list(group["members"].values()), False)
                self._publish(group["entry"])
            for probe, members in late.items():
                # nachträglich erkannt und schon vorbei: ein Ereignis je Probe statt eines je Ziel
                self._publish(self._outage_entry(f"outage-late:{probe}:{members[0]['id']}", members, True))
            for key in [k for k in self.active if k not in active_ids]:
                old = self.active.pop(key)
                self._publish({**old, "state": "resolved", "title": ("Beendet: " + old["title"])[:120],
                               "resolved_at": int(time.time())})
            for probe in list(self.groups):
                group = self.groups[probe]
                for key in [k for k in group["members"] if k not in active_ids]:
                    del group["members"][key]
                if not group["members"]:
                    del self.groups[probe]
                    old = group["entry"]
                    self._publish({**old, "state": "resolved", "title": ("Beendet: " + old["title"])[:120],
                                   "resolved_at": int(time.time())})

    def _join_group(self, item: dict, publish: bool = True) -> str:
        probe = str(item.get("probe_id"))
        group = self.groups.get(probe)
        if group is None:
            group = self.groups[probe] = {"entry": {"finding_id": f"outage:{probe}:{item['id']}"}, "members": {}}
        group["members"][item["key"]] = item
        if publish:
            group["entry"] = self._outage_entry(group["entry"]["finding_id"], list(group["members"].values()), False)
            self._publish(group["entry"])
        return probe

    def since(self, since: int, notify: bool = True) -> dict:
        with self.lock:
            items = sorted((e for e in self.entries.values() if e["seq"] > since), key=lambda e: e["seq"])
            return {"notify": notify, "latest_seq": self.seq, "start_seq": self.start, "findings": items}


class TrayService:
    """Fachlogik des Endpunkts, ohne HTTP – testbar."""

    def __init__(self, status: Callable[[], dict], send: Callable[[dict], None], pending: PendingReports,
                 hostname: str, ready: Callable[[], bool] = lambda: True, clock: Callable[[], float] = time.time,
                 notices: NoticeFeed | None = None):
        self.status_fn, self.send, self.pending, self.hostname = status, send, pending, hostname
        self.ready, self.clock = ready, clock
        self.notices = notices or NoticeFeed(clock)
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
            path, _, query = self.path.partition("?")
            if path == "/tray/v1/status":
                self.reply(200, service.status())
            elif path == "/tray/v1/findings":
                since = 0
                for part in query.split("&"):
                    key, _, value = part.partition("=")
                    if key == "since" and value.isdigit():
                        since = int(value)
                self.reply(200, service.notices.since(since))
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
