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
