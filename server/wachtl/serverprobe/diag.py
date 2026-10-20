"""Client-Hinweise für den Wachtl-Server unter Windows (docs/CLIENT-HINWEISE.md).

Die Erkennung (Kabel getrennt, Netzwerkkarte ausgeschaltet, Treiber, DHCP …) steckt in der Windows-Probe. Der Server
startet sie als ``wachtl-probe.exe diagnose``: ein Kindprozess ohne Dienst, der je Zustandsänderung eine JSON-Zeile
schreibt und endet, wenn stdin geschlossen wird. Die Server-Probe gibt die Hinweise an das Tray-Symbol
(``GET /tray/v1/findings``) und mit ihrem Token an ``POST /api/probe/v1/findings`` weiter.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

log = logging.getLogger("wachtl.serverprobe.diag")

MAX_FEED = 50
MAX_PENDING = 200
BATCH = 50
FLUSH_S = 30
RESTART_S = (30, 600)          # Wartezeit nach einem Absturz des Kindprozesses: ab 30 s, höchstens 10 min
TRAY_FIELDS = ("finding_id", "kind", "severity", "state", "title", "message", "solution", "balloon", "adapter",
               "detected_at", "resolved_at")


class FindingFeed:
    """Die letzten Hinweise für das Tray, je Hinweis der neueste Stand mit fortlaufender Nummer – wie FindingFeed der Probe.

    Die Zählung beginnt bei der Startzeit in Millisekunden, damit das Tray einen Neustart erkennt."""

    def __init__(self, start_seq: int | None = None):
        self.start = self.seq = int(time.time() * 1000) if start_seq is None else start_seq
        self.entries: dict[str, tuple[int, dict]] = {}
        self.notify = True
        self.lock = threading.Lock()

    def publish(self, finding: dict) -> int:
        with self.lock:
            self.seq += 1
            self.entries.pop(finding["finding_id"], None)
            self.entries[finding["finding_id"]] = (self.seq, finding)
            while len(self.entries) > MAX_FEED:
                self.entries.pop(next(iter(self.entries)))
            return self.seq

    def clear(self) -> None:
        with self.lock:
            self.entries.clear()

    def since(self, since: int) -> dict:
        with self.lock:
            items = [{"seq": seq, **{k: f.get(k) for k in TRAY_FIELDS}}
                     for seq, f in self.entries.values() if seq > since]
            return {"notify": self.notify, "latest_seq": self.seq, "start_seq": self.start,
                    "findings": sorted(items, key=lambda i: i["seq"])}


def parse_line(line: str) -> dict | None:
    """Eine Zeile von ``wachtl-probe.exe diagnose``; None bei Unbrauchbarem."""
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("finding_id"), str) or not data["finding_id"]:
        return None
    if data.get("state") not in ("active", "resolved") or not isinstance(data.get("kind"), str):
        return None
    return data


class Rejected(Exception):
    """Der Server lehnt die Sendung ab (HTTP 400) – nicht erneut senden."""


class Diagnostics:
    def __init__(self, exe: str | Path, send: Callable[[list[dict]], None], stop_event: threading.Event,
                 popen: Callable = subprocess.Popen, feed: FindingFeed | None = None):
        self.exe, self.send, self.stop_event, self.popen = str(exe), send, stop_event, popen
        self.feed = feed or FindingFeed()
        self.enabled = True
        self.changed = threading.Event()
        self.flush_now = threading.Event()
        self.lock = threading.Lock()
        self.active: dict[str, dict] = {}
        self.pending: dict[str, dict] = {}      # finding_id → neuester Stand für den Server
        self.proc: subprocess.Popen | None = None

    @staticmethod
    def available(exe: str | None) -> bool:
        return bool(exe) and os.name == "nt" and Path(exe).is_file()

    # -- Einstellungen (client_findings aus der Konfiguration) ---------------------------
    def configure(self, config: dict | None) -> None:
        config = config or {}
        enabled = bool(config.get("enabled", True))
        self.feed.notify = enabled and bool(config.get("notify", True))
        if enabled != self.enabled:
            log.info("Client-Hinweise für diesen Server %s", "eingeschaltet" if enabled else "ausgeschaltet")
            self.enabled = enabled
            if not enabled:
                # der Server schließt die offenen Hinweise selbst (Einstellung „überwachen“ aus)
                with self.lock:
                    self.active.clear()
                    self.pending.clear()
                self.feed.clear()
            self.changed.set()
            self._stop_child()

    # -- Hinweise ------------------------------------------------------------------------
    def handle(self, finding: dict) -> None:
        self.feed.publish(finding)
        server = {k: v for k, v in finding.items() if k != "balloon"}
        with self.lock:
            if finding["state"] == "active":
                self.active[finding["finding_id"]] = finding
            else:
                self.active.pop(finding["finding_id"], None)
            self.pending.pop(finding["finding_id"], None)
            self.pending[finding["finding_id"]] = server
            while len(self.pending) > MAX_PENDING:
                self.pending.pop(next(iter(self.pending)))
        if finding["state"] == "active":
            log.log(logging.INFO if finding.get("severity") == "info" else logging.WARNING,
                    "Client-Hinweis (%s, %s) an „%s“: %s", finding["kind"], finding.get("severity"),
                    finding.get("adapter"), finding.get("title"))
        else:
            log.info("Client-Hinweis erledigt (%s) an „%s“: %s", finding["kind"], finding.get("adapter"), finding.get("title"))
        self.flush_now.set()

    def resolve_unconfirmed(self) -> None:
        """Kindprozess beendet: was er als aktiv gemeldet hat, kann er nicht mehr erledigen."""
        now = int(time.time())
        with self.lock:
            stale = list(self.active.values())
        for f in stale:
            self.handle({**f, "state": "resolved", "resolved_at": now, "solution": "", "balloon": "",
                         "title": "Hinweis nicht mehr bestätigt",
                         "message": "Die Prüfung der Netzwerkkarten wurde neu gestartet.",
                         "details": {**(f.get("details") or {}), "problem": f.get("title") or f["kind"]}})

    def flush(self) -> int:
        """Gesammelte Hinweise an den Server; bricht beim ersten Netz-/Serverfehler ab. Liefert die Zahl offener."""
        while True:
            with self.lock:
                batch = list(self.pending.values())[:BATCH]
            if not batch:
                return 0
            try:
                self.send(batch)
            except Rejected as exc:
                log.warning("Server lehnt Client-Hinweise ab: %s", exc)
            except Exception as exc:  # noqa: BLE001 – später erneut versuchen
                log.debug("Client-Hinweise noch nicht zustellbar: %s", exc)
                with self.lock:
                    return len(self.pending)
            with self.lock:
                for f in batch:
                    if self.pending.get(f["finding_id"]) is f:
                        del self.pending[f["finding_id"]]

    # -- Abläufe ---------------------------------------------------------------------------
    def start(self) -> None:
        threading.Thread(target=self.run_child_loop, daemon=True, name="diag-child").start()
        threading.Thread(target=self.flush_loop, daemon=True, name="diag-flush").start()

    def flush_loop(self) -> None:
        while not self.stop_event.is_set():
            self.flush_now.wait(FLUSH_S)
            self.flush_now.clear()
            if not self.stop_event.is_set():
                self.flush()

    def run_child_loop(self) -> None:
        delay = RESTART_S[0]
        while not self.stop_event.is_set():
            if not self.enabled:
                self.changed.wait(60)
                self.changed.clear()
                continue
            started = time.monotonic()
            code = self.run_child()
            if self.stop_event.is_set():
                break
            self.resolve_unconfirmed()
            if not self.enabled:
                continue
            delay = RESTART_S[0] if time.monotonic() - started > 600 else min(RESTART_S[1], delay * 2)
            log.warning("Prüfung der Netzwerkkarten beendet (Code %s), neuer Start in %d s", code, delay)
            self.stop_event.wait(delay)

    def run_child(self) -> int | None:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = self.popen([self.exe, "diagnose"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                              creationflags=flags)
        except OSError as exc:
            log.warning("%s diagnose nicht startbar: %s", self.exe, exc)
            return None
        self.proc = proc
        threading.Thread(target=self._log_stderr, args=(proc,), daemon=True, name="diag-stderr").start()
        stopper = threading.Thread(target=self._stop_on_exit, args=(proc,), daemon=True, name="diag-stop")
        stopper.start()
        try:
            for line in proc.stdout:
                finding = parse_line(line.strip())
                if finding is None:
                    if line.strip():
                        log.debug("Unbrauchbare Zeile von diagnose: %.200s", line)
                    continue
                if self.enabled:
                    self.handle(finding)
        finally:
            self.proc = None
        try:
            return proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait()

    def _stop_on_exit(self, proc) -> None:
        while proc.poll() is None:
            if self.stop_event.wait(1) or self.proc is not proc:
                self._stop_child(proc)
                return

    def _stop_child(self, proc=None) -> None:
        proc = proc or self.proc
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.stdin.close()       # diagnose endet, sobald stdin zu ist
            proc.wait(timeout=5)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            proc.kill()

    @staticmethod
    def _log_stderr(proc) -> None:
        for line in proc.stderr:
            if line.strip():
                log.info("diagnose: %s", line.rstrip())
