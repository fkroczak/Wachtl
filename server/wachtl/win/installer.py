"""Einrichtung des Wachtl Servers unter Windows – wird vom Setup-Assistenten aufgerufen.

    python -m wachtl.win.installer install   --input setup.json --result result.json
    python -m wachtl.win.installer upgrade   [--result result.json]
    python -m wachtl.win.installer uninstall [--remove-data]
    python -m wachtl.win.installer check-ports --input setup.json

``setup.json`` (vom Assistenten in dessen Temp-Ordner geschrieben, danach gelöscht):

    {"hostnames": "wachtl.kunde.local, 10.0.0.5", "https_port": 443, "http_port": 80,
     "data_dir": "C:\\\\ProgramData\\\\Wachtl Server", "admin_password": "…",
     "raw_days": 30, "agg_months": 13,
     "notify": {"email_to": "", "email_from": "", "smtp_smarthost": "", "smtp_username": "",
                "smtp_password": "", "smtp_require_tls": "true", "teams_webhook_url": ""}}

Jeder Schritt wird in <Daten>\\logs\\setup.log protokolliert. Exit-Code 0 = Erfolg;
bei Fehlern steht eine verständliche Meldung in result.json ("error").
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import shutil
import sys
import time
import urllib.request
from pathlib import Path

from ..netinfo import with_local_ips
from . import certs, winsys
from .layout import DEFAULTS, Layout, public_url, write_env

log = logging.getLogger("wachtl.installer")
IS_WINDOWS = os.name == "nt"


class SetupError(RuntimeError):
    """Fehler mit einer Meldung, die der Assistent dem Benutzer zeigt."""


# -- Eingaben ---------------------------------------------------------------------
def parse_input(data: dict) -> dict:
    hostnames = data.get("hostnames", "")
    if isinstance(hostnames, str):
        hostnames = [h.strip() for h in hostnames.replace(";", ",").split(",")]
    hostnames = [h for h in hostnames if h]
    errors = []
    if not hostnames:
        errors.append("Bitte mindestens einen Servernamen oder eine IP-Adresse angeben.")
    for h in hostnames:
        is_ipv6 = h.count(":") > 1
        if " " in h or "/" in h or (":" in h and not is_ipv6):
            errors.append(f"Ungültiger Servername: {h} (ohne https:// und ohne Port angeben)")

    def num(key: str, default: int, lo: int, hi: int, label: str) -> int:
        try:
            value = int(data.get(key, default))
        except (TypeError, ValueError):
            errors.append(f"{label} muss eine Zahl sein.")
            return default
        if not lo <= value <= hi:
            errors.append(f"{label} muss zwischen {lo} und {hi} liegen.")
        return value

    https_port = num("https_port", 443, 1, 65535, "HTTPS-Port")
    http_port = num("http_port", 80, 0, 65535, "HTTP-Port")
    if http_port and http_port == https_port:
        errors.append("HTTP- und HTTPS-Port müssen verschieden sein.")
    iperf_port = num("iperf_port", 5201, 0, 65535, "iperf3-Port")
    if iperf_port and iperf_port in (https_port, http_port):
        errors.append("Der iperf3-Port muss sich von den Web-Ports unterscheiden.")
    rtp_port = num("rtp_port", 5004, 0, 65535, "RTP-Port")
    if rtp_port and rtp_port == iperf_port:
        errors.append("Der RTP-Port (UDP) muss sich vom iperf3-Port unterscheiden.")
    raw_days = num("raw_days", 30, 1, 365, "Aufbewahrung Rohdaten (Tage)")
    agg_months = num("agg_months", 13, 1, 120, "Aufbewahrung Verlauf (Monate)")
    password = str(data.get("admin_password", ""))
    if data.get("require_password", True) and not password:
        errors.append("Bitte ein Administrator-Passwort eingeben.")
    data_dir = str(data.get("data_dir", "")).strip().rstrip("\\/")
    if len(data_dir) <= 2 and data_dir.endswith(":"):
        errors.append("Bitte einen Unterordner wählen, nicht die Wurzel eines Laufwerks (z. B. D:\\Wachtl).")
    if not data_dir:
        errors.append("Bitte einen Datenordner angeben.")
    notify = {k: str(v) for k, v in (data.get("notify") or {}).items()}
    from ..services.notify import validate

    errors += validate(notify)
    if errors:
        raise SetupError("\n".join(errors))
    return {"hostnames": hostnames, "auto_ips": bool(data.get("auto_ips", True)),
            "https_port": https_port, "http_port": http_port, "iperf_port": iperf_port, "rtp_port": rtp_port,
            "raw_days": raw_days,
            "agg_months": agg_months, "admin_password": password, "data_dir": Path(data_dir), "notify": notify}


def check_ports(cfg: dict, layout: Layout | None = None, run: winsys.Runner | None = None) -> list[str]:
    """Belegte Ports mit verständlicher Meldung."""
    run = run or winsys.Runner()
    wanted = [("HTTPS", cfg["https_port"], "0.0.0.0")]
    if cfg["http_port"]:
        wanted.append(("HTTP", cfg["http_port"], "0.0.0.0"))
    if cfg.get("iperf_port"):
        wanted.append(("iperf3", cfg["iperf_port"], "0.0.0.0"))
    internal = {**DEFAULTS, **(layout.env if layout else {})}
    for key in ("PORT_INTERNAL", "PORT_VM_RAW", "PORT_VM_AGG", "PORT_VMALERT", "PORT_ALERTMANAGER"):
        wanted.append((key.removeprefix("PORT_").lower(), int(internal[key]), "127.0.0.1"))
    problems = []
    for label, port, host in wanted:
        if not winsys.port_free(port, host):
            owner = winsys.owner_of_port(port, run) if IS_WINDOWS else "anderer Prozess"
            hint = " (z. B. IIS – anderen Port wählen oder IIS-Bindung entfernen)" if port in (80, 443) else ""
            problems.append(f"Port {port} ({label}) ist belegt durch {owner}{hint}.")
    return problems


# -- Schritte ---------------------------------------------------------------------------
def write_configuration(layout: Layout, cfg: dict) -> str:
    """Konfigurationsdatei und Zertifikat. Vorhandene Geheimnisse bleiben erhalten."""
    layout.ensure_dirs()
    env = dict(layout.env)
    # IP-Adressen des Servers mit ins Zertifikat, damit auch der Browser über die IP ohne Namensfehler öffnet
    hostnames = cfg["hostnames"] if cfg.get("auto_ips") is False else with_local_ips(cfg["hostnames"])
    if hostnames != cfg["hostnames"]:
        log.info("Lokale IP-Adressen ergänzt: %s", ", ".join(hostnames[len(cfg["hostnames"]):]))
    cfg["hostnames"] = hostnames
    env["WACHTL_HOSTNAMES"] = ",".join(cfg["hostnames"])
    env["WACHTL_PUBLIC_URL"] = public_url(cfg["hostnames"][0], cfg["https_port"])
    env["WACHTL_HTTPS_PORT"] = str(cfg["https_port"])
    env["WACHTL_HTTP_PORT"] = str(cfg["http_port"])
    env["PORT_IPERF"] = str(cfg.get("iperf_port", 5201))
    env["PORT_RTP"] = str(cfg.get("rtp_port", 5004))
    env["RAW_RETENTION"] = f"{cfg['raw_days']}d"
    env["AGG_RETENTION"] = str(cfg["agg_months"])
    env["WACHTL_SECRET_KEY"] = env.get("WACHTL_SECRET_KEY") or secrets.token_urlsafe(48)
    env["WACHTL_WEBHOOK_SECRET"] = env.get("WACHTL_WEBHOOK_SECRET") or secrets.token_urlsafe(32)
    layout.env = env
    pin, reason = certs.ensure_certificate(cfg["hostnames"], layout.key_file, layout.cert_file)
    if reason:
        log.info("Zertifikat ausgestellt (%s)", reason)
    env["WACHTL_SPKI_PIN"] = pin
    write_env(layout.env_file, env)
    log.info("Konfiguration geschrieben: %s", layout.env_file)
    return pin


def initialize_database(layout: Layout, cfg: dict) -> list[str]:
    os.environ.update(layout.app_env())
    from .. import bootstrap, create_app

    with create_app().app_context():
        messages = bootstrap.initialize(reload=False, notify_settings=cfg["notify"] or None)
        if cfg["admin_password"]:
            # auch bei einer Neuinstallation über vorhandene Daten gilt das eingegebene Passwort
            messages.append(f"Benutzer 'admin' {bootstrap.set_user('admin', cfg['admin_password'], 'admin')}")
    for m in messages:
        log.info(m)
    return messages


def wait_healthy(layout: Layout, timeout: float = 180) -> bool:
    deadline = time.monotonic() + timeout
    url = layout.internal_url + "/healthz"
    while time.monotonic() < deadline:
        try:
            # ohne System-Proxy: auf Kundenservern zeigt der IE-Proxy sonst auch für 127.0.0.1 ins Leere
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except OSError:
            pass
        time.sleep(2)
    return False


def write_setup_info(layout: Layout) -> Path:
    path = layout.data_dir / "setup-info.txt"
    text = f"""Wachtl Server
=============

Adresse:        {layout.env['WACHTL_PUBLIC_URL']}
Anmeldung:      admin (Passwort wie im Setup festgelegt)
Passwort vergessen: Startmenü > Wachtl > Admin-Passwort zurücksetzen
SPKI-Pin:       {layout.env['WACHTL_SPKI_PIN']}
Zertifikat:     {layout.cert_file}
Datenordner:    {layout.data_dir}
Programmordner: {layout.install_dir}

Probes installieren:
  Im Web-UI unter Verwaltung > Probes registrieren einen Token erzeugen.
  Der fertige Befehl für die PCs steht dort.

Browser-Warnung abstellen:
  Zertifikat per Gruppenrichtlinie als vertrauenswürdige Stammzertifizierungsstelle verteilen
  (Computerkonfiguration > Richtlinien > Windows-Einstellungen > Sicherheitseinstellungen >
   Richtlinien für öffentliche Schlüssel > Vertrauenswürdige Stammzertifizierungsstellen).

Verwaltung (PowerShell als Administrator):
  & "{layout.install_dir}\\wachtl-server.cmd" status
  & "{layout.install_dir}\\wachtl-server.cmd" backup
  & "{layout.install_dir}\\wachtl-server.cmd" create-user admin
  Restart-Service WachtlServer
"""
    path.write_text(text, encoding="utf-8")
    return path


def system_setup(layout: Layout, run: winsys.Runner) -> None:
    """Dienst, Berechtigungen, Firewall, geplante Sicherung (nur Windows)."""
    (layout.install_dir / "datadir.txt").write_text(str(layout.data_dir), encoding="utf-8")
    winsys.install_service(layout, run)
    winsys.secure_data_dir(layout, run)
    winsys.configure_firewall(layout, run)
    winsys.schedule_backup(layout, run)


# -- Befehle --------------------------------------------------------------------------------
def install(data: dict, run: winsys.Runner, start: bool = True) -> dict:
    cfg = parse_input(data)
    layout = Layout.load(cfg["data_dir"], data.get("install_dir"))
    log.info("Installation: Programm %s, Daten %s", layout.install_dir, layout.data_dir)
    already = IS_WINDOWS and winsys.service_state(run) == "RUNNING"
    if already:
        winsys.stop_service(run)
    if not run.dry_run:
        problems = check_ports(cfg, layout, run)
        if problems:
            raise SetupError("\n".join(problems))
    pin = write_configuration(layout, cfg)
    initialize_database(layout, cfg)
    if IS_WINDOWS or run.dry_run:
        system_setup(layout, run)
    info = write_setup_info(layout)
    healthy = None
    if start and IS_WINDOWS:
        winsys.start_service(run)
        healthy = wait_healthy(layout)
        if not healthy:
            raise SetupError("Der Dienst wurde installiert, antwortet aber nicht. "
                             f"Bitte die Logdateien in {layout.logs} prüfen (supervisor.log, web.log).")
    return {"ok": True, "url": layout.env["WACHTL_PUBLIC_URL"], "pin": pin, "info_file": str(info),
            "cert_file": str(layout.cert_file), "data_dir": str(layout.data_dir), "healthy": healthy}


def upgrade(data_dir: str | None, run: winsys.Runner, start: bool = True) -> dict:
    layout = Layout.load(data_dir)
    log.info("Update: Programm %s, Daten %s", layout.install_dir, layout.data_dir)
    if IS_WINDOWS or run.dry_run:
        system_setup(layout, run)
    write_setup_info(layout)
    if start and IS_WINDOWS:
        winsys.start_service(run)  # Migrationen laufen beim Start (init)
        if not wait_healthy(layout):
            raise SetupError(f"Der Dienst antwortet nach dem Update nicht. Logdateien: {layout.logs}")
    return {"ok": True, "url": layout.env["WACHTL_PUBLIC_URL"], "pin": layout.env["WACHTL_SPKI_PIN"],
            "data_dir": str(layout.data_dir)}


def uninstall(run: winsys.Runner, remove_data: bool = False) -> dict:
    """Dienst, Firewall-Regeln, geplante Sicherung entfernen und prüfen, dass nichts offen bleibt.

    Die Server-Probe ist ein Teilprozess des Dienstes und endet mit ihm; sie hat keine eigenen Regeln.
    """
    try:
        layout = Layout.load()
    except FileNotFoundError:
        layout = None
    programs: list[Path] = []
    if layout is not None:
        winsys.uninstall_service(layout, run)
        # Regeln, die Windows beim ersten Start für python.exe/iperf3.exe angeboten hat, gleich mit entfernen
        programs = [layout.python, layout.iperf_exe] + [layout.binary(n) for n in
                                                         ("victoria-metrics", "vmalert", "alertmanager")]
    winsys.remove_firewall(run, programs)
    winsys.remove_backup_task(run)
    if remove_data and layout is not None and layout.data_dir.exists():
        shutil.rmtree(layout.data_dir, ignore_errors=True)
    leftovers = [] if run.dry_run else check_removed(layout, run)
    for item in leftovers:
        log.warning("Nach der Deinstallation noch vorhanden: %s", item)
    return {"ok": True, "leftovers": leftovers, "error": "\n".join(leftovers)}


def check_removed(layout: Layout | None, run: winsys.Runner) -> list[str]:
    """Was nach der Deinstallation noch da ist und ein Risiko wäre: Dienst, Firewall-Regeln, offene Ports."""
    left = []
    if winsys.service_state(run) is not None:
        left.append("Dienst WachtlServer (wird nach einem Neustart entfernt)")
    for name in (winsys.FW_HTTPS, winsys.FW_HTTP, winsys.FW_IPERF, winsys.FW_RTP):
        if winsys.firewall_rule_exists(name, run):
            left.append(f"Firewall-Regel „{name}“")
    if winsys.backup_task_exists(run):
        left.append(f"Geplante Aufgabe „{winsys.TASK_BACKUP}“")
    if layout is not None:
        ports = {layout.https_port, layout.http_port, layout.port("IPERF")} - {0}   # TCP; RTP (UDP) endet mit dem Dienst
        for port in sorted(ports):
            if winsys.port_open(port):
                left.append(f"Port {port} ist noch offen ({winsys.owner_of_port(port, run)})")
    return left


def _setup_log(data_dir: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if data_dir:
        (data_dir / "logs").mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(data_dir / "logs" / "setup.log", encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=handlers, force=True)


def write_result(path: Path, result: dict) -> None:
    """JSON oder – für den Setup-Assistenten – INI in UTF-16 (GetIniString liest das zuverlässig)."""
    if path.suffix.lower() == ".ini":
        lines = ["[result]", f"ok={'1' if result.get('ok') else '0'}"]
        for key in ("url", "pin", "info_file", "cert_file", "data_dir", "error"):
            value = str(result.get(key) or "").replace("\r", "").replace("\n", "\\n")
            lines.append(f"{key}={value}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-16")  # Textmodus macht unter Windows \r\n daraus
    else:
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wachtl.win.installer")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "check-ports"):
        p = sub.add_parser(name)
        p.add_argument("--input", required=True)
        p.add_argument("--result")
        p.add_argument("--no-start", action="store_true")
        p.add_argument("--dry-run", action="store_true", help="Systembefehle nur protokollieren")
    p = sub.add_parser("upgrade")
    p.add_argument("--data")
    p.add_argument("--result")
    p.add_argument("--no-start", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("uninstall")
    p.add_argument("--remove-data", action="store_true")
    p.add_argument("--result")
    args = parser.parse_args(argv)

    run = winsys.Runner(dry_run=getattr(args, "dry_run", False))
    result: dict
    data_dir = None
    try:
        if args.command in ("install", "check-ports"):
            data = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
            data_dir = Path(str(data.get("data_dir", ""))) if data.get("data_dir") else None
            _setup_log(data_dir)
            if args.command == "check-ports":
                cfg = parse_input({**data, "require_password": False})
                problems = check_ports(cfg, None, run)
                result = {"ok": not problems, "error": "\n".join(problems)}
            else:
                result = install(data, run, start=not args.no_start)
        elif args.command == "upgrade":
            _setup_log(Path(args.data) if args.data else None)
            result = upgrade(args.data, run, start=not args.no_start)
        else:
            _setup_log(None)
            result = uninstall(run, args.remove_data)
    except SetupError as exc:
        log.error("%s", exc)
        result = {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 – Assistent bekommt immer eine Meldung
        log.exception("Unerwarteter Fehler")
        hint = f" Details: {data_dir / 'logs' / 'setup.log'}" if data_dir else ""
        result = {"ok": False, "error": f"Unerwarteter Fehler: {exc}.{hint}"}
    if getattr(args, "result", None):
        write_result(Path(args.result), result)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
