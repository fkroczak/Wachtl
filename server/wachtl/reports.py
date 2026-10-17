"""Störungsmeldungen von Benutzern (0.5): Kategorien, Prüfung, Speichern und Abfragen.

Die Texte für Art und Dauer stehen nur hier – Probe-API, JSON-API und Web-UI nutzen dieselben.
Vertrag: docs/STOERUNGSMELDUNGEN.md
"""
from __future__ import annotations

import re

from . import repo
from .db import ex, ins, q, q1

CATEGORIES = {
    "no_connection": "Keine Verbindung / Internet weg",
    "slow": "Langsam / lange Ladezeiten",
    "dropouts": "Aussetzer / Verbindungsabbrüche",
    "voice_video": "Telefonie oder Video gestört",
    "application": "Bestimmte Anwendung oder Website betroffen",
    "other": "Sonstiges",
}
DURATIONS = {
    "unknown": "Unbekannt",
    "short": "Kurz (unter 1 Minute)",
    "minutes": "Einige Minuten (1–15 Minuten)",
    "long": "Länger (über 15 Minuten)",
    "ongoing": "Dauert noch an",
}
STATUS_LABELS = {"open": "offen", "done": "erledigt"}

MAX_AGE_S = 7 * 86400          # occurred_at höchstens 7 Tage alt …
MAX_FUTURE_S = 300             # … und höchstens 5 Minuten in der Zukunft (Uhrabweichung)
MAX_DESCRIPTION, MAX_USER, MAX_HOSTNAME, MAX_NOTE = 1000, 128, 255, 500
REPORT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ReportError(ValueError):
    """Ungültige Meldung; der Text geht als ``400 {"error": …}`` an die Probe."""


def _text(value, limit: int) -> str:
    # Steuerzeichen (u. a. NUL, das PostgreSQL in TEXT ablehnt) entfernen, Zeilenumbrüche behalten
    return _CONTROL.sub("", str(value if value is not None else "")).strip()[:limit]


def validate(data, now: int | None = None) -> dict:
    """Körper von ``POST /api/probe/v1/report`` prüfen und normalisieren."""
    if not isinstance(data, dict):
        raise ReportError("JSON-Objekt erwartet.")
    now = repo.now() if now is None else now
    report_id = data.get("report_id")
    if not isinstance(report_id, str) or not REPORT_ID_RE.match(report_id.strip()):
        raise ReportError("report_id fehlt oder ist ungültig (UUID erwartet).")
    raw_ts = data.get("occurred_at")
    if isinstance(raw_ts, bool):
        raw_ts = None
    try:
        occurred_at = int(float(raw_ts))
    except (TypeError, ValueError, OverflowError):
        raise ReportError("occurred_at fehlt oder ist keine Unix-Zeit in Sekunden.") from None
    if not now - MAX_AGE_S <= occurred_at <= now + MAX_FUTURE_S:
        raise ReportError("occurred_at muss zwischen jetzt − 7 Tagen und jetzt + 5 Minuten liegen.")
    category = data.get("category")
    if category not in CATEGORIES:
        raise ReportError("category ungültig – erlaubt: " + ", ".join(CATEGORIES) + ".")
    duration = data.get("duration") or "unknown"
    if duration not in DURATIONS:
        raise ReportError("duration ungültig – erlaubt: " + ", ".join(DURATIONS) + ".")
    return {
        "report_id": report_id.strip().lower(),
        "occurred_at": occurred_at,
        "category": category,
        "duration": duration,
        "description": _text(data.get("description"), MAX_DESCRIPTION),
        "user": _text(data.get("user"), MAX_USER),
        "hostname": _text(data.get("hostname"), MAX_HOSTNAME),
    }


def store(probe: dict, values: dict) -> tuple[int, bool]:
    """Meldung speichern. Liefert (id, neu); dieselbe report_id derselben Probe wird nicht doppelt gespeichert."""
    existing = q1("SELECT id FROM incident_reports WHERE probe_id = ? AND report_id = ?",
                  (probe["id"], values["report_id"]))
    if existing:
        return int(existing["id"]), False
    # Zwei gleichzeitige Zustellungen derselben Meldung scheitern am UNIQUE-Index (500); die Probe wiederholt dann.
    rid = ins(
        "INSERT INTO incident_reports (probe_id, site_id, report_id, occurred_at, received_at, category, duration, "
        "description, reported_user, hostname, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')",
        (probe["id"], probe["site_id"], values["report_id"], values["occurred_at"], repo.now(),
         values["category"], values["duration"], values["description"] or None, values["user"] or None,
         values["hostname"] or probe["hostname"]),
    )
    return rid, True


# -- Abfragen ----------------------------------------------------------------
_SELECT = (
    "SELECT r.*, p.hostname AS probe_name, s.name AS site_name "
    "FROM incident_reports r LEFT JOIN probes p ON p.id = r.probe_id LEFT JOIN sites s ON s.id = r.site_id"
)


def _decorate(row: dict) -> dict:
    row["category_label"] = CATEGORIES.get(row["category"], row["category"])
    row["duration_label"] = DURATIONS.get(row["duration"], row["duration"])
    row["status_label"] = STATUS_LABELS.get(row["status"], row["status"])
    row["probe_label"] = row.get("probe_name") or row.get("hostname") or "unbekannt"
    return row


def _where(status: str | None = None, site_id: int | None = None, probe_id: int | None = None,
           since: int | None = None, until: int | None = None) -> tuple[str, list]:
    clauses, params = [], []
    if status in STATUS_LABELS:
        clauses.append("r.status = ?")
        params.append(status)
    if site_id is not None:
        clauses.append("r.site_id = ?")
        params.append(site_id)
    if probe_id is not None:
        clauses.append("r.probe_id = ?")
        params.append(probe_id)
    if since is not None:
        clauses.append("r.occurred_at >= ?")
        params.append(since)
    if until is not None:
        clauses.append("r.occurred_at <= ?")
        params.append(until)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def search(status: str | None = None, site_id: int | None = None, probe_id: int | None = None,
           since: int | None = None, until: int | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
    where, params = _where(status, site_id, probe_id, since, until)
    rows = q(f"{_SELECT}{where} ORDER BY r.occurred_at DESC, r.id DESC LIMIT ? OFFSET ?",
             (*params, int(limit), int(offset)))
    return [_decorate(r) for r in rows]


def count(status: str | None = None, site_id: int | None = None, probe_id: int | None = None,
          since: int | None = None) -> int:
    where, params = _where(status, site_id, probe_id, since)
    return int(q1(f"SELECT COUNT(*) AS n FROM incident_reports r{where}", params)["n"])


def get(report_id: int) -> dict | None:
    row = q1(f"{_SELECT} WHERE r.id = ?", (report_id,))
    return _decorate(row) if row else None


def chart_item(r: dict) -> dict:
    """Eine Meldung im Format von ``GET /api/reports`` (Graph-Markierungen)."""
    return {
        "id": r["id"], "ts": r["occurred_at"], "probe_id": r["probe_id"], "probe": r["probe_label"],
        "site": r.get("site_name") or "", "category": r["category"], "category_label": r["category_label"],
        "duration_label": r["duration_label"], "description": r.get("description") or "",
        "user": r.get("reported_user") or "", "status": r["status"],
    }


def for_chart(since: int, until: int, probe_id: int | None = None, site_id: int | None = None,
              limit: int = 1000) -> list[dict]:
    rows = search(None, site_id, probe_id, since, until, limit=limit)
    rows.reverse()  # zeitlich aufsteigend wie die Messreihen
    return [chart_item(r) for r in rows]


def set_status(report: dict, status: str, username: str, note: str = "") -> None:
    if status == "done":
        ex("UPDATE incident_reports SET status = 'done', done_by = ?, done_at = ?, done_note = ? WHERE id = ?",
           (username, repo.now(), _text(note, MAX_NOTE) or None, report["id"]))
    elif status == "open":
        ex("UPDATE incident_reports SET status = 'open', done_by = NULL, done_at = NULL, done_note = NULL WHERE id = ?",
           (report["id"],))
    else:
        raise ValueError(status)
