"""Gemeinsame Einrichtungsschritte für ``flask init`` (Linux/Docker) und den Windows-Setup."""
from __future__ import annotations

from . import repo
from .db import ex, get_conn, get_db, ins, q1
from .security import hash_password, password_problem
from .services import alertgen, notify


def initialize(admin_password: str | None = None, reload: bool = True,
               notify_settings: dict[str, str] | None = None) -> list[str]:
    """Datenbank migrieren, Standards anlegen, Konfigurationsdateien schreiben.

    Muss in einem App-Kontext laufen. Gibt eine Liste von Meldungen zurück.
    """
    messages = [f"Migration {v:03d} angewendet" for v in get_db().migrate(get_conn())]
    messages += [f"Angelegt: {item}" for item in repo.seed_defaults()]
    if admin_password and q1("SELECT id FROM users LIMIT 1") is None:
        set_user("admin", admin_password, "admin")
        messages.append("Benutzer 'admin' angelegt")
    if notify_settings is not None:
        if q1("SELECT key FROM settings WHERE key LIKE 'notify.%' LIMIT 1") is None:
            notify.save_settings(notify_settings)
            messages.append("Benachrichtigungen übernommen")
    elif notify.import_from_env():
        messages.append("Benachrichtigungen aus der Umgebung übernommen")
    if msg := prepare_server_probe():
        messages.append(msg)
    messages.append(f"Regeldatei geschrieben: {alertgen.write_rules(reload=reload)}")
    if path := notify.write_config(reload=reload):
        messages.append(f"Alertmanager-Konfiguration geschrieben: {path}")
    return messages


def set_user(username: str, password: str, role: str) -> str:
    """Benutzer anlegen oder Passwort/Rolle zurücksetzen (inkl. Entsperren)."""
    if problem := password_problem(password):
        raise ValueError(problem)
    existing = q1("SELECT id FROM users WHERE username = ?", (username,))
    if existing:
        ex(
            "UPDATE users SET password_hash = ?, role = ?, failed_logins = 0, locked_until = NULL WHERE id = ?",
            (hash_password(password), role, existing["id"]),
        )
        result = "aktualisiert"
    else:
        ins(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, repo.now()),
        )
        result = "angelegt"
    repo.audit("setup", f"user.{result}", username, role)
    return result


def prepare_server_probe() -> str | None:
    """Einmaligen Enrollment-Token für die Server-Probe bereitlegen, falls sie (noch) nicht registriert ist.

    Ist die Probe registriert und im Web-UI deaktiviert, bleibt sie deaktiviert. Wurde sie im Web-UI
    gelöscht, registriert sie sich beim nächsten Start neu.
    """
    from pathlib import Path

    from flask import current_app

    from .security import hash_token
    from .serverprobe.probe import ENROLL_FILE, STATE_FILE, read_json, write_private

    cfg = current_app.config
    if not cfg.get("SERVER_PROBE") or not cfg.get("SERVER_PROBE_DIR"):
        return None
    folder = Path(cfg["SERVER_PROBE_DIR"])
    state = read_json(folder / STATE_FILE)
    if state and state.get("token"):
        probe = q1("SELECT token_hash FROM probes WHERE id = ?", (int(state.get("probe_id") or 0),))
        if probe and probe["token_hash"] == hash_token(state["token"]):
            return None
        (folder / STATE_FILE).unlink(missing_ok=True)       # im Web-UI gelöscht oder neu registriert
    pending = read_json(folder / ENROLL_FILE)
    if pending and pending.get("token"):
        row = q1("SELECT * FROM enrollment_tokens WHERE token_hash = ?", (hash_token(pending["token"]),))
        if row and not row["revoked"] and row["uses"] < row["max_uses"] and row["expires_at"] > repo.now():
            return None
    site_id = repo.ensure_site(cfg["SERVER_PROBE_SITE"])
    token = repo.create_enrollment_token(site_id, 1, 30, "setup", "Server-Probe", probe_kind="server")
    try:
        write_private(folder / ENROLL_FILE, {"token": token})
    except OSError as exc:
        return f"Server-Probe: {folder / ENROLL_FILE} nicht schreibbar ({exc})"
    return f"Server-Probe: Registrierung vorbereitet ({cfg['SERVER_PROBE_SITE']})"
