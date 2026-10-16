"""Startet und überwacht die Teilprozesse des Windows-Dienstes.

- Ausgabe jedes Prozesses landet rotierend in logs\\<name>.log (5 × 10 MB).
- Stürzt ein Prozess ab, wird er mit wachsender Wartezeit (1 s … 60 s) neu gestartet; läuft er
  danach 5 Minuten stabil, beginnt die Wartezeit wieder bei 1 s.
- Beim Beenden werden alle Prozesse in umgekehrter Startreihenfolge sauber gestoppt
  (Windows: CTRL_BREAK an die eigene Prozessgruppe, sonst SIGTERM) und nach Ablauf
  der Frist hart beendet.

Plattformunabhängig, damit die Logik auch unter Linux getestet werden kann.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path

log = logging.getLogger("wachtl.supervisor")
IS_WINDOWS = os.name == "nt"


@dataclass
class ProcSpec:
    name: str
    args: list[str]
    env: dict[str, str] | None = None
    cwd: str | None = None


@dataclass
class _Child:
    spec: ProcSpec
    proc: subprocess.Popen | None = None
    started: float = 0.0
    backoff: float = 0.0
    next_start: float = 0.0
    restarts: int = 0
    reader: threading.Thread | None = None
    logger: logging.Logger = field(default=None)  # type: ignore[assignment]


def child_logger(name: str, log_dir: Path, max_bytes: int = 10 * 1024 * 1024, backups: int = 5) -> logging.Logger:
    logger = logging.getLogger(f"wachtl.child.{name}")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(log_dir / f"{name}.log", maxBytes=max_bytes, backupCount=backups,
                                      encoding="utf-8", delay=True)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
    return logger


def _pump(stream, logger: logging.Logger) -> None:
    try:
        for raw in iter(stream.readline, b""):
            logger.info(raw.decode("utf-8", errors="replace").rstrip())
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


class Supervisor:
    def __init__(self, specs: list[ProcSpec], log_dir: Path, stop_event: threading.Event | None = None,
                 backoff_max: float = 60.0, stable_after: float = 300.0, grace: float = 15.0,
                 poll_interval: float = 0.5):
        self.children = [_Child(spec=s) for s in specs]
        self.log_dir = log_dir
        self.stop_event = stop_event or threading.Event()
        self.backoff_max = backoff_max
        self.stable_after = stable_after
        self.grace = grace
        self.poll_interval = poll_interval

    # -- einzelner Befehl (z. B. Datenbank-Initialisierung) --------------------
    def run_once(self, spec: ProcSpec, timeout: float = 300) -> int:
        logger = child_logger(spec.name, self.log_dir)
        logger.info("---- Start: %s", " ".join(spec.args))
        proc = self._spawn(spec)
        reader = threading.Thread(target=_pump, args=(proc.stdout, logger), daemon=True)
        reader.start()
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = -1
        reader.join(timeout=5)
        logger.info("---- Ende mit Code %s", code)
        return code

    # -- Dauerbetrieb -------------------------------------------------------------
    def run(self) -> None:
        log.info("Supervisor startet %d Prozesse", len(self.children))
        for child in self.children:
            self._start(child)
        try:
            while not self.stop_event.wait(self.poll_interval):
                self._check()
        finally:
            self.stop_all()

    def status(self) -> list[dict]:
        now = time.monotonic()
        result = []
        for c in self.children:
            running = c.proc is not None and c.proc.poll() is None
            result.append({
                "name": c.spec.name,
                "running": running,
                "pid": c.proc.pid if running and c.proc else None,
                "uptime_s": int(now - c.started) if running else 0,
                "restarts": c.restarts,
            })
        return result

    def _spawn(self, spec: ProcSpec) -> subprocess.Popen:
        env = {**os.environ, **(spec.env or {})}
        kwargs: dict = {}
        if IS_WINDOWS:
            # eigene Prozessgruppe: bekommt kein Ctrl+C des Dienstes, aber gezielt CTRL_BREAK
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        return subprocess.Popen(spec.args, env=env, cwd=spec.cwd, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)

    def _start(self, child: _Child) -> None:
        if child.logger is None:
            child.logger = child_logger(child.spec.name, self.log_dir)
        child.logger.info("---- Start: %s", " ".join(child.spec.args))
        try:
            child.proc = self._spawn(child.spec)
        except OSError as exc:
            log.error("%s konnte nicht gestartet werden: %s", child.spec.name, exc)
            child.logger.info("---- Start fehlgeschlagen: %s", exc)
            child.proc = None
            self._schedule_restart(child)
            return
        child.started = time.monotonic()
        child.reader = threading.Thread(target=_pump, args=(child.proc.stdout, child.logger), daemon=True)
        child.reader.start()
        log.info("%s gestartet (PID %s)", child.spec.name, child.proc.pid)

    def _schedule_restart(self, child: _Child) -> None:
        child.backoff = min(self.backoff_max, max(1.0, child.backoff * 2))
        child.next_start = time.monotonic() + child.backoff

    def _check(self) -> None:
        now = time.monotonic()
        for child in self.children:
            if child.proc is None:
                if child.next_start and now >= child.next_start:
                    child.next_start = 0
                    child.restarts += 1
                    self._start(child)
                continue
            code = child.proc.poll()
            if code is None:
                if child.backoff and now - child.started > self.stable_after:
                    child.backoff = 0.0
                continue
            ran = now - child.started
            if ran > self.stable_after:
                child.backoff = 0.0
            log.warning("%s beendet mit Code %s nach %.0f s – Neustart folgt", child.spec.name, code, ran)
            child.logger.info("---- Beendet mit Code %s", code)
            child.proc = None
            self._schedule_restart(child)

    def stop_all(self) -> None:
        running = [c for c in reversed(self.children) if c.proc is not None and c.proc.poll() is None]
        for child in running:
            log.info("Stoppe %s", child.spec.name)
            self._signal_stop(child.proc)
        deadline = time.monotonic() + self.grace
        for child in running:
            try:
                child.proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                log.warning("%s reagiert nicht – wird beendet", child.spec.name)
                child.proc.kill()
                child.proc.wait(timeout=5)
            child.logger.info("---- Gestoppt (Code %s)", child.proc.returncode)
        for child in self.children:
            if child.reader:
                child.reader.join(timeout=2)
        log.info("Alle Prozesse gestoppt")

    @staticmethod
    def _signal_stop(proc: subprocess.Popen) -> None:
        try:
            if IS_WINDOWS:
                os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
            else:
                proc.terminate()
        except OSError:
            proc.kill()


def install_stop_handlers(stop_event: threading.Event) -> None:
    """Ctrl+C (WinSW beim Dienst-Stopp), Ctrl+Break und SIGTERM beenden den Supervisor sauber."""
    def handler(signum, _frame):
        log.info("Stoppsignal %s empfangen", signum)
        stop_event.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), handler)
