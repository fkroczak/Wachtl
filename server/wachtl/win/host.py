"""Wachtl Server unter Windows: Dienstprozess und Verwaltungsbefehle.

    wachtl-server.cmd status                 Zustand von Dienst, Ports und Speicher
    wachtl-server.cmd backup                 Sicherung nach <Daten>\\backups (läuft täglich als geplante Aufgabe)
    wachtl-server.cmd restore <datei.zip>    Sicherung zurückspielen (stoppt und startet den Dienst)
    wachtl-server.cmd create-user <name>     Benutzer anlegen / Passwort zurücksetzen
    wachtl-server.cmd create-token --site X  Enrollment-Token erzeugen (--uses 10 --days 7)
    wachtl-server.cmd probes                 registrierte Probes und ihr Zustand
    wachtl-server.cmd logs                   Ordner mit den Logdateien anzeigen

Intern: ``run`` (vom Dienst gestartet) und ``init`` (Datenbank/Regeln vor dem Start).
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import logging
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import urllib.request
import zipfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import certs, winsys
from .layout import Layout, server_probe_env, write_env
from .supervisor import ProcSpec, Supervisor, install_stop_handlers

log = logging.getLogger("wachtl.host")


def setup_logging(layout: Layout | None, name: str, console: bool = True) -> None:
    handlers: list[logging.Handler] = []
    if layout is not None:
        layout.logs.mkdir(parents=True, exist_ok=True)
        handlers.append(RotatingFileHandler(layout.logs / f"{name}.log", maxBytes=5 * 1024 * 1024, backupCount=5,
                                            encoding="utf-8"))
    if console:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=handlers, force=True)


def apply_app_env(layout: Layout) -> None:
    os.environ.update(layout.app_env())


# -- Prozessliste -----------------------------------------------------------------
def build_specs(layout: Layout) -> list[ProcSpec]:
    py = str(layout.python)
    d = layout.data_dir
    app_env = layout.app_env()
    specs = [
        ProcSpec("vm-raw", [str(layout.binary("victoria-metrics")),
                            f"-storageDataPath={d / 'vm-raw'}",
                            f"-retentionPeriod={layout.env['RAW_RETENTION']}",
                            f"-httpListenAddr=127.0.0.1:{layout.port('VM_RAW')}",
                            "-search.maxPointsPerTimeseries=100000",
                            "-loggerTimezone=Local"]),
        ProcSpec("vm-agg", [str(layout.binary("victoria-metrics")),
                            f"-storageDataPath={d / 'vm-agg'}",
                            f"-retentionPeriod={layout.env['AGG_RETENTION']}",
                            f"-httpListenAddr=127.0.0.1:{layout.port('VM_AGG')}",
                            "-loggerTimezone=Local"]),
        ProcSpec("alertmanager", [str(layout.binary("alertmanager")),
                                  f"--config.file={layout.am_config}",
                                  f"--storage.path={d / 'alertmanager' / 'data'}",
                                  f"--web.listen-address=127.0.0.1:{layout.port('ALERTMANAGER')}",
                                  f"--web.external-url={layout.env['WACHTL_PUBLIC_URL']}/alerts",
                                  "--cluster.listen-address="]),
        ProcSpec("web", [py, "-m", "wachtl.win.serve"], env=app_env, cwd=str(layout.install_dir)),
        ProcSpec("vmalert", [str(layout.binary("vmalert")),
                             f"-rule={d / 'rules' / '*.yml'}",
                             f"-datasource.url={layout.local('VM_RAW')}",
                             f"-remoteWrite.url={layout.local('VM_AGG')}",
                             f"-remoteRead.url={layout.local('VM_AGG')}",
                             f"-notifier.url={layout.local('ALERTMANAGER')}",
                             "-evaluationInterval=15s",
                             "-rule.evalDelay=30s",
                             f"-httpListenAddr=127.0.0.1:{layout.port('VMALERT')}",
                             f"-external.url={layout.env['WACHTL_PUBLIC_URL']}/alerts",
                             "-loggerTimezone=Local"]),
    ]
    if layout.port("IPERF") and layout.iperf_exe.exists():
        # Gegenstelle für iperf3-Messungen der Probes (Check „Bandbreite intern“, Gegenstelle Wachtl-Server)
        specs.append(ProcSpec("iperf3", [str(layout.iperf_exe), "-s", "-p", str(layout.port("IPERF"))],
                              cwd=str(layout.iperf_exe.parent)))
    if layout.port("RTP"):
        # Gegenstelle für Sprachtests der Probes (Check „Sprache (RTP)“, Gegenstelle Wachtl-Server)
        specs.append(ProcSpec("rtp", [py, "-m", "wachtl.rtp", str(layout.port("RTP"))],
                              env={"PYTHONUTF8": "1"}, cwd=str(layout.install_dir)))
    if layout.env.get("SERVER_PROBE", "1") != "0":
        # Server misst selbst – dieselben Checks wie die Probes (wachtl.serverprobe)
        specs.append(ProcSpec("serverprobe", [py, "-m", "wachtl.serverprobe"], env=server_probe_env(layout),
                              cwd=str(layout.install_dir)))
    return specs


# -- Befehle ---------------------------------------------------------------------------
def cmd_init(layout: Layout, _args) -> int:
    """Datenbank migrieren, Regeln und Alertmanager-Konfiguration schreiben (ohne Neuladen)."""
    layout.ensure_dirs()
    (layout.data_dir / "alertmanager" / "data").mkdir(parents=True, exist_ok=True)
    apply_app_env(layout)
    from .. import bootstrap, create_app

    with create_app().app_context():
        for msg in bootstrap.initialize(reload=False):
            log.info(msg)
    return 0


def renew_certificate_if_needed(layout: Layout) -> None:
    pin, reason = certs.ensure_certificate(layout.hostnames, layout.key_file, layout.cert_file)
    if reason:
        log.warning("Zertifikat neu ausgestellt (%s); Pin unverändert: %s", reason, pin == layout.env["WACHTL_SPKI_PIN"])
        if pin != layout.env["WACHTL_SPKI_PIN"]:
            layout.env["WACHTL_SPKI_PIN"] = pin
            write_env(layout.env_file, layout.env)


def cmd_run(layout: Layout, _args) -> int:
    setup_logging(layout, "supervisor")
    log.info("Wachtl Server startet, Daten in %s", layout.data_dir)
    try:
        renew_certificate_if_needed(layout)
    except Exception:  # noqa: BLE001 – ohne Zertifikat startet nur der Webserver nicht
        log.exception("Zertifikatsprüfung fehlgeschlagen")
    stop = threading.Event()
    install_stop_handlers(stop)
    sup = Supervisor(build_specs(layout), layout.logs, stop_event=stop)
    py = str(layout.python)
    code = sup.run_once(ProcSpec("init", [py, "-m", "wachtl.win.host", "init", "--data", str(layout.data_dir)],
                                 cwd=str(layout.install_dir)))
    if code != 0:
        log.error("Initialisierung fehlgeschlagen (Code %s) – Details in logs\\init.log", code)
        return code
    sup.run()
    return 0


def _get_json(url: str, timeout: float = 3) -> dict | None:
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (OSError, ValueError):
        return None


def _dir_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if path.exists() else 0


def cmd_status(layout: Layout, _args) -> int:
    run = winsys.Runner()
    state = winsys.service_state(run) if os.name == "nt" else "(nur unter Windows)"
    print(f"Dienst WachtlServer:  {state or 'nicht installiert'}")
    print(f"Adresse:              {layout.env['WACHTL_PUBLIC_URL']}")
    print(f"SPKI-Pin:             {layout.env['WACHTL_SPKI_PIN']}")
    print(f"Programmordner:       {layout.install_dir}")
    print(f"Datenordner:          {layout.data_dir}")
    health = _get_json(layout.internal_url + "/healthz")
    print(f"Collector:            {'ok, Version ' + health['version'] if health else 'nicht erreichbar'}")
    checks = [("HTTPS", layout.https_port), ("HTTP-Umleitung", layout.http_port),
              ("VictoriaMetrics raw", layout.port("VM_RAW")), ("VictoriaMetrics agg", layout.port("VM_AGG")),
              ("vmalert", layout.port("VMALERT")), ("Alertmanager", layout.port("ALERTMANAGER"))]
    for name, port in checks:
        if port:
            print(f"  {name:<20} :{port:<6} {'läuft' if winsys.port_open(port) else 'AUS'}")
    try:
        cert = certs.load_certificate(layout.cert_file)
        print(f"Zertifikat gültig bis {cert.not_valid_after_utc:%d.%m.%Y}")
    except OSError:
        print("Zertifikat fehlt")
    for sub in ("data", "vm-raw", "vm-agg", "backups"):
        print(f"  {sub:<10} {_dir_size(layout.data_dir / sub) / 1024 / 1024:8.1f} MB")
    return 0 if health else 1


def cmd_logs(layout: Layout, _args) -> int:
    print(layout.logs)
    if os.name == "nt":
        os.startfile(layout.logs)  # type: ignore[attr-defined]  # noqa: S606
    return 0


def cmd_create_user(layout: Layout, args) -> int:
    password = os.environ.get("WACHTL_NEW_PASSWORD") or getpass.getpass("Neues Passwort (min. 12 Zeichen): ")
    if not os.environ.get("WACHTL_NEW_PASSWORD") and getpass.getpass("Wiederholen: ") != password:
        print("Passwörter stimmen nicht überein.")
        return 1
    apply_app_env(layout)
    from .. import bootstrap, create_app

    with create_app().app_context():
        try:
            print(f"Benutzer {args.username} {bootstrap.set_user(args.username, password, args.role)}")
        except ValueError as exc:
            print(exc)
            return 1
    return 0


def cmd_create_token(layout: Layout, args) -> int:
    """Enrollment-Token auf der Kommandozeile (z. B. für Skripte und Tests)."""
    apply_app_env(layout)
    from .. import create_app, repo

    with create_app().app_context():
        site_id = repo.ensure_site(args.site)
        token = repo.create_enrollment_token(site_id, args.uses, args.days, "cli")
    print(token)
    return 0


def cmd_probes(layout: Layout, _args) -> int:
    apply_app_env(layout)
    from .. import create_app, repo
    from ..db import q

    with create_app().app_context():
        rows = q("SELECT p.id, p.hostname, s.name AS site, p.version, p.last_seen, p.status FROM probes p "
                 "JOIN sites s ON s.id = p.site_id ORDER BY s.name, p.hostname")
        for r in rows:
            state = "deaktiviert" if r["status"] != "active" else ("online" if repo.probe_online(r) else "offline")
            print(f"{r['id']:>4}  {r['hostname']:<24} {r['site']:<20} {r['version'] or '-':<8} {state}")
        if not rows:
            print("Keine Probes registriert.")
    return 0


# -- Sicherung ----------------------------------------------------------------------------
def _fs_url(path: Path) -> str:
    return "fs://" + str(path).replace("\\", "/")


def backup(layout: Layout, target_dir: Path | None = None) -> Path:
    target_dir = target_dir or layout.backups
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = target_dir / f"wachtl-{stamp}.zip"
    with tempfile.TemporaryDirectory(prefix="wachtl-backup-") as tmp:
        work = Path(tmp)
        # SQLite konsistent über die Online-Backup-API
        if layout.db_file.exists():
            src = sqlite3.connect(layout.db_file)
            dst = sqlite3.connect(work / "wachtl.db")
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
        # 1-min-Aggregate: im Betrieb per Snapshot (vmbackup), bei gestopptem Dienst als Ordnerkopie
        agg_port = layout.port("VM_AGG")
        vmbackup = layout.binary("vmbackup")
        if winsys.port_open(agg_port) and vmbackup.exists():
            import subprocess

            subprocess.run([str(vmbackup), f"-storageDataPath={layout.data_dir / 'vm-agg'}",
                            f"-snapshot.createURL={layout.local('VM_AGG')}/snapshot/create",
                            f"-dst={_fs_url(work / 'vm-agg')}", "-loggerLevel=ERROR"], check=True)
        elif not winsys.port_open(agg_port) and (layout.data_dir / "vm-agg").exists():
            shutil.copytree(layout.data_dir / "vm-agg", work / "vm-agg-files")
        else:
            log.warning("vm-agg läuft, aber vmbackup fehlt – Aggregate nicht gesichert")
        shutil.copy2(layout.env_file, work / "wachtl.env")
        shutil.copytree(layout.data_dir / "certs", work / "certs")
        (work / "backup.json").write_text(json.dumps({"created": stamp, "data_dir": str(layout.data_dir)}),
                                          encoding="utf-8")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(work.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(work).as_posix())
    _prune_backups(target_dir, int(layout.env.get("BACKUP_KEEP_DAYS", "14")))
    return archive


def _prune_backups(directory: Path, keep_days: int) -> None:
    cutoff = dt.datetime.now().timestamp() - keep_days * 86400
    for f in directory.glob("wachtl-*.zip"):
        if f.stat().st_mtime < cutoff:
            f.unlink()


def cmd_backup(layout: Layout, args) -> int:
    setup_logging(layout, "backup")
    archive = backup(layout, Path(args.target) if args.target else None)
    log.info("Sicherung erstellt: %s (%.1f MB)", archive, archive.stat().st_size / 1024 / 1024)
    return 0


def restore(layout: Layout, archive: Path) -> None:
    """Spielt eine Sicherung zurück. Der Dienst muss gestoppt sein."""
    if winsys.port_open(layout.port("VM_AGG")) or winsys.port_open(layout.port("INTERNAL")):
        raise RuntimeError("Der Dienst läuft noch. Bitte zuerst stoppen.")
    with tempfile.TemporaryDirectory(prefix="wachtl-restore-") as tmp:
        work = Path(tmp)
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                if name.startswith("/") or ".." in Path(name).parts:
                    raise RuntimeError(f"Ungültiger Pfad in der Sicherung: {name}")
            zf.extractall(work)
        if (work / "wachtl.db").exists():
            for suffix in ("", "-wal", "-shm"):
                Path(str(layout.db_file) + suffix).unlink(missing_ok=True)
            layout.db_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(work / "wachtl.db", layout.db_file)
        agg = layout.data_dir / "vm-agg"
        if (work / "vm-agg").exists():
            import subprocess

            subprocess.run([str(layout.binary("vmrestore")), f"-src={_fs_url(work / 'vm-agg')}",
                            f"-storageDataPath={agg}", "-loggerLevel=ERROR"], check=True)
        elif (work / "vm-agg-files").exists():
            shutil.rmtree(agg, ignore_errors=True)
            shutil.copytree(work / "vm-agg-files", agg)
        # Geheimnisse und Zertifikat übernehmen, Ports/Pfade dieser Installation behalten
        restored = {**layout.env}
        from .layout import read_env

        old = read_env(work / "wachtl.env")
        for key in ("WACHTL_SECRET_KEY", "WACHTL_WEBHOOK_SECRET", "WACHTL_SPKI_PIN", "WACHTL_HOSTNAMES",
                    "WACHTL_PUBLIC_URL"):
            if old.get(key):
                restored[key] = old[key]
        write_env(layout.env_file, restored)
        shutil.rmtree(layout.data_dir / "certs", ignore_errors=True)
        shutil.copytree(work / "certs", layout.data_dir / "certs")


def cmd_restore(layout: Layout, args) -> int:
    setup_logging(layout, "backup")
    archive = Path(args.archive)
    if not archive.exists():
        print(f"Datei nicht gefunden: {archive}")
        return 1
    if not args.yes and input("Aktuelle Daten werden überschrieben. Fortfahren? (ja/nein) ").strip().lower() != "ja":
        return 1
    run = winsys.Runner()
    if os.name == "nt":
        winsys.stop_service(run)
    restore(layout, archive)
    log.info("Sicherung %s zurückgespielt", archive)
    if os.name == "nt":
        winsys.start_service(run)
        log.info("Dienst gestartet")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wachtl-server", description="Wachtl Server (Windows)")
    parser.add_argument("--data", help="Datenordner (Standard: aus datadir.txt im Programmordner)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Dienstprozess (startet alle Komponenten)")
    sub.add_parser("init", help="Datenbank und Konfiguration vorbereiten")
    sub.add_parser("status", help="Zustand anzeigen")
    sub.add_parser("logs", help="Logordner anzeigen")
    p = sub.add_parser("backup", help="Sicherung erstellen")
    p.add_argument("--target", help="Zielordner (Standard: <Daten>\\backups)")
    p = sub.add_parser("restore", help="Sicherung zurückspielen")
    p.add_argument("archive")
    p.add_argument("--yes", action="store_true", help="ohne Rückfrage")
    p = sub.add_parser("create-token", help="Enrollment-Token erzeugen")
    p.add_argument("--site", required=True, help="Standortname (wird angelegt, falls neu)")
    p.add_argument("--uses", type=int, default=1)
    p.add_argument("--days", type=int, default=7)
    sub.add_parser("probes", help="Registrierte Probes anzeigen")
    p = sub.add_parser("create-user", help="Benutzer anlegen oder Passwort zurücksetzen")
    p.add_argument("username")
    p.add_argument("--role", choices=["admin", "operator", "readonly"], default="admin")

    # --data darf auch hinter dem Befehl stehen (so ruft der Dienst auf)
    args, rest = parser.parse_known_args(argv)
    if rest:
        extra = argparse.ArgumentParser(add_help=False)
        extra.add_argument("--data")
        more, unknown = extra.parse_known_args(rest)
        if unknown:
            parser.error(f"Unbekannte Argumente: {' '.join(unknown)}")
        args.data = more.data or args.data
    layout = Layout.load(args.data)
    if args.command not in ("run", "backup", "restore"):
        setup_logging(None, args.command)
    handler = {
        "run": cmd_run, "init": cmd_init, "status": cmd_status, "logs": cmd_logs, "backup": cmd_backup,
        "restore": cmd_restore, "create-user": cmd_create_user, "create-token": cmd_create_token,
        "probes": cmd_probes,
    }[args.command]
    return handler(layout, args)


if __name__ == "__main__":
    sys.exit(main())
