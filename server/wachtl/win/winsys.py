"""Windows-Systembefehle: Dienst, Berechtigungen, Firewall, geplante Aufgabe.

Alle Aufrufe laufen über ``Runner``; Tests ersetzen ihn durch einen Rekorder.
Konten werden über SIDs angesprochen (SYSTEM = S-1-5-18, Administratoren = S-1-5-32-544),
damit es auch auf deutschsprachigen Windows-Servern funktioniert.
"""
from __future__ import annotations

import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from .layout import SERVICE_ACCOUNT, SERVICE_ID, Layout

log = logging.getLogger("wachtl.winsys")
SID_SYSTEM = "*S-1-5-18"
SID_ADMINS = "*S-1-5-32-544"
FW_HTTPS = "Wachtl Server HTTPS"
FW_HTTP = "Wachtl Server HTTP"
TASK_BACKUP = "Wachtl Server Backup"


class SystemError_(RuntimeError):
    pass


@dataclass
class Runner:
    dry_run: bool = False
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        self.calls.append(list(args))
        log.info("> %s", subprocess.list2cmdline(args))
        if self.dry_run:
            return subprocess.CompletedProcess(args, 0, "", "")
        # Konsolenprogramme (netstat, sc) schreiben in der OEM-Codepage
        proc = subprocess.run(args, capture_output=True, text=True, errors="replace",
                              encoding="oem" if os.name == "nt" else None)
        output = (proc.stdout + proc.stderr).strip()
        if output:
            log.info("  %s", output.replace("\n", "\n  "))
        if check and proc.returncode != 0:
            raise SystemError_(f"Befehl fehlgeschlagen ({proc.returncode}): {subprocess.list2cmdline(args)}\n{output}")
        return proc


# -- WinSW-Konfiguration ------------------------------------------------------
def winsw_xml(layout: Layout) -> str:
    args = f'-m wachtl.win.host run --data "{layout.data_dir}"'
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- Vom Wachtl-Setup erzeugt. Dienst: {SERVICE_ID} -->
<service>
  <id>{SERVICE_ID}</id>
  <name>Wachtl Server</name>
  <description>Wachtl Netzwerk-Monitoring: Collector, Dashboard, Zeitreihen und Alarmierung.</description>
  <executable>{escape(str(layout.python))}</executable>
  <arguments>{escape(args)}</arguments>
  <workingdirectory>{escape(str(layout.install_dir))}</workingdirectory>
  <startmode>Automatic</startmode>
  <delayedAutoStart/>
  <stopparentprocessfirst>true</stopparentprocessfirst>
  <stoptimeout>45sec</stoptimeout>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <resetfailure>1 day</resetfailure>
  <logpath>{escape(str(layout.logs))}</logpath>
  <log mode="roll"/>
  <env name="PYTHONUNBUFFERED" value="1"/>
  <env name="PYTHONUTF8" value="1"/>
  <env name="WACHTL_INSTALL_DIR" value={quoteattr(str(layout.install_dir))}/>
</service>
"""


# -- Dienst ------------------------------------------------------------------------
def service_state(run: Runner) -> str | None:
    """RUNNING, STOPPED, … oder None, wenn der Dienst nicht existiert (sprachunabhängig)."""
    proc = run(["sc.exe", "query", SERVICE_ID], check=False)
    if proc.returncode != 0:
        return None
    for state in ("RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING", "PAUSED"):
        if state in proc.stdout:
            return state
    return None if run.dry_run else "UNKNOWN"


def install_service(layout: Layout, run: Runner) -> None:
    # WinSW liest die XML bei jedem Dienststart – bei einem Update genügt das Überschreiben.
    layout.winsw_xml.parent.mkdir(parents=True, exist_ok=True)
    layout.winsw_xml.write_text(winsw_xml(layout), encoding="utf-8")
    if service_state(run) is None:
        run([str(layout.winsw_exe), "install"])
    # virtuelles Dienstkonto statt LocalSystem, verzögerter Autostart
    run(["sc.exe", "config", SERVICE_ID, "obj=", SERVICE_ACCOUNT, "start=", "delayed-auto"])


def uninstall_service(layout: Layout, run: Runner) -> None:
    if service_state(run) is None:
        return
    stop_service(run)
    if layout.winsw_exe.exists():
        run([str(layout.winsw_exe), "uninstall"], check=False)
    if service_state(run) is not None:
        run(["sc.exe", "delete", SERVICE_ID], check=False)


def start_service(run: Runner) -> None:
    run(["sc.exe", "start", SERVICE_ID], check=False)


def stop_service(run: Runner, timeout: float = 90) -> None:
    if service_state(run) in (None, "STOPPED"):
        return
    run(["sc.exe", "stop", SERVICE_ID], check=False)
    deadline = time.monotonic() + timeout
    while not run.dry_run and time.monotonic() < deadline:
        if service_state(run) in ("STOPPED", None):
            return
        time.sleep(1)
    if not run.dry_run:
        raise SystemError_("Dienst WachtlServer hat sich nicht beendet.")


# -- Berechtigungen ---------------------------------------------------------------
def secure_data_dir(layout: Layout, run: Runner) -> None:
    """Datenordner: nur SYSTEM, Administratoren und das Dienstkonto; Unterordner erben."""
    run(["icacls", str(layout.data_dir), "/inheritance:r",
         "/grant:r", f"{SID_SYSTEM}:(OI)(CI)F",
         "/grant:r", f"{SID_ADMINS}:(OI)(CI)F",
         "/grant:r", f"{SERVICE_ACCOUNT}:(OI)(CI)M",
         "/C", "/Q"])
    run(["icacls", str(layout.data_dir / "*"), "/reset", "/T", "/C", "/Q"], check=False)
    # Programmordner: Dienstkonto braucht Lesen/Ausführen
    run(["icacls", str(layout.install_dir), "/grant", f"{SERVICE_ACCOUNT}:(OI)(CI)RX", "/C", "/Q"])


# -- Firewall -----------------------------------------------------------------------
def configure_firewall(layout: Layout, run: Runner) -> None:
    remove_firewall(run)
    run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_HTTPS}", "dir=in", "action=allow",
         "protocol=TCP", f"localport={layout.https_port}", "profile=any"])
    if layout.http_port:
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_HTTP}", "dir=in", "action=allow",
             "protocol=TCP", f"localport={layout.http_port}", "profile=any"])


def remove_firewall(run: Runner) -> None:
    for name in (FW_HTTPS, FW_HTTP):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], check=False)


# -- tägliche Sicherung ---------------------------------------------------------------
def schedule_backup(layout: Layout, run: Runner, at: str = "02:15") -> None:
    cmd = f'"{layout.install_dir / "wachtl-server.cmd"}" backup'
    run(["schtasks", "/Create", "/F", "/TN", TASK_BACKUP, "/SC", "DAILY", "/ST", at,
         "/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", cmd])


def remove_backup_task(run: Runner) -> None:
    run(["schtasks", "/Delete", "/F", "/TN", TASK_BACKUP], check=False)


# -- Hilfen -----------------------------------------------------------------------------
def port_free(port: int, host: str = "0.0.0.0") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def owner_of_port(port: int, run: Runner) -> str:
    """Prozessname, der einen Port belegt (für verständliche Fehlermeldungen)."""
    try:
        out = run(["netstat", "-ano", "-p", "TCP"], check=False).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[1].endswith(f":{port}") and parts[3].upper() in ("LISTENING", "ABHÖREN"):
                pid = parts[4]
                task = run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], check=False).stdout
                name = task.split(",")[0].strip('"') if task else "?"
                return f"{name} (PID {pid})"
    except (OSError, SystemError_):
        pass
    return "unbekannter Prozess"


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
