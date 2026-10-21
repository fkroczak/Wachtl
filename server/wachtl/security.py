"""Authentifizierung: Web-Sessions mit Rollen, CSRF-Schutz, Probe-Tokens."""
from __future__ import annotations

import functools
import hashlib
import hmac
import secrets
import time

from flask import abort, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import ex, q1

ROLES = ("readonly", "operator", "admin")
ROLE_LABELS = {"readonly": "Nur lesen", "operator": "Operator", "admin": "Administrator"}
MAX_FAILED_LOGINS = 5
LOCK_SECONDS = 15 * 60


# -- Passwörter und Tokens --------------------------------------------------
def hash_password(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def verify_password(pw_hash: str, password: str) -> bool:
    return check_password_hash(pw_hash, password)


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def password_problem(password: str) -> str | None:
    if not password:
        return "Bitte ein Passwort eingeben."
    return None


# -- Web-Login --------------------------------------------------------------
def try_login(username: str, password: str) -> tuple[dict | None, str | None]:
    """Prüft Zugangsdaten inkl. Sperre nach Fehlversuchen."""
    now = int(time.time())
    user = q1("SELECT * FROM users WHERE username = ?", (username,))
    if user is None:
        verify_password(hash_password("x"), password)  # gleiche Laufzeit wie bei Treffern
        return None, "Benutzername oder Passwort falsch."
    if user["locked_until"] and user["locked_until"] > now:
        return None, "Konto vorübergehend gesperrt. Bitte später erneut versuchen."
    if not verify_password(user["password_hash"], password):
        failed = user["failed_logins"] + 1
        locked = now + LOCK_SECONDS if failed >= MAX_FAILED_LOGINS else None
        ex(
            "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
            (0 if locked else failed, locked, user["id"]),
        )
        return None, "Benutzername oder Passwort falsch."
    ex("UPDATE users SET failed_logins = 0, locked_until = NULL, last_login = ? WHERE id = ?", (now, user["id"]))
    return user, None


def login_user(user: dict) -> None:
    session.clear()
    session["uid"] = user["id"]
    session["csrf"] = new_secret(16)
    session.permanent = True


def current_user() -> dict | None:
    uid = session.get("uid")
    if g.get("user_uid", "-") == uid:
        return g.user
    g.user_uid = uid
    g.user = q1("SELECT id, username, role, theme, contrast FROM users WHERE id = ?", (uid,)) if uid else None
    return g.user


def has_role(user: dict | None, minimum: str) -> bool:
    return bool(user) and ROLES.index(user["role"]) >= ROLES.index(minimum)


def login_required(minimum: str = "readonly", api: bool = False):
    """Decorator für Web- und Admin-API-Routen mit Mindestrolle."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                if api:
                    return jsonify(error="nicht angemeldet"), 401
                return redirect(url_for("web.login", next=request.full_path))
            if not has_role(user, minimum):
                if api:
                    return jsonify(error="keine Berechtigung"), 403
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# -- CSRF -------------------------------------------------------------------
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = new_secret(16)
    return session["csrf"]


def check_csrf() -> None:
    """Für alle zustandsändernden Session-Requests (Formular oder Header)."""
    if request.method not in ("GET", "HEAD", "OPTIONS") and not csrf_ok():
        abort(400, "CSRF-Prüfung fehlgeschlagen. Bitte Seite neu laden.")


def csrf_ok() -> bool:
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf", "")
    # Bytes vergleichen: compare_digest wirft bei Nicht-ASCII-Strings einen TypeError (500)
    return bool(expected) and hmac.compare_digest(sent.encode(), expected.encode())


# -- Probe-Authentifizierung -----------------------------------------------
def probe_auth(fn):
    """Erwartet ``Authorization: Bearer <probe_id>.<secret>``."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Token fehlt"), 401
        token = header[7:].strip()
        probe_id, _, secret = token.partition(".")
        if not probe_id.isdigit() or not secret:
            return jsonify(error="Token ungültig"), 401
        probe = q1(
            "SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.id = ?",
            (int(probe_id),),
        )
        if probe is None or not hmac.compare_digest(probe["token_hash"], hash_token(token)):
            return jsonify(error="Token ungültig"), 401
        if probe["status"] != "active":
            return jsonify(error="Probe ist deaktiviert"), 403
        g.probe = probe
        return fn(*args, **kwargs)

    return wrapper
