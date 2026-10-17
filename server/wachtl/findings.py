"""Client-Hinweise (0.8): was eine Probe auf ihrem PC selbst erkennt – Kabel getrennt, Link-Geschwindigkeit,
Treiberfehler, keine DHCP-Adresse … Die Probe zeigt sie dem Benutzer als Sprechblase und liefert sie hierher.

Titel, Text und Lösungsvorschlag kommt von der Probe (gleicher Wortlaut wie in der Sprechblase).
Vertrag: docs/CLIENT-HINWEISE.md
"""
from __future__ import annotations

import json
import re

from . import repo
from .db import ex, ins, q, q1

KINDS = {
    "cable_unplugged": "Netzwerkkabel getrennt",
    "wifi_disconnected": "WLAN getrennt",
    "link_speed_changed": "Link-Geschwindigkeit geändert",
    "link_speed_low": "Link-Geschwindigkeit niedrig",
    "link_flapping": "Verbindung instabil",
    "driver_error": "Treiber- oder Gerätefehler",
    "nic_reset": "Netzwerkkarte wird zurückgesetzt",
    "apipa": "Keine Adresse vom DHCP-Server",
    "no_gateway": "Kein Standard-Gateway",
    "nic_errors": "Übertragungsfehler der Netzwerkkarte",
}
SEVERITIES = {"info": "Info", "warning": "Warnung", "critical": "Kritisch"}
STATES = {"active": "aktiv", "resolved": "behoben"}

MAX_BATCH = 50
MAX_AGE_S = 30 * 86400
MAX_FUTURE_S = 300
MAX_TITLE, MAX_TEXT, MAX_ADAPTER, MAX_DETAILS, MAX_DETAIL_VALUE = 120, 500, 255, 20, 200
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class FindingError(ValueError):
    """Ungültiger Hinweis bzw. ungültige Sendung."""


def _text(value, limit: int) -> str:
    return _CONTROL.sub("", str(value if value is not None else "")).strip()[:limit]


def _ts(value, name: str) -> int:
    if isinstance(value, bool):
        raise FindingError(f"{name} ist keine Unix-Zeit.")
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        raise FindingError(f"{name} fehlt oder ist keine Unix-Zeit in Sekunden.") from None


def validate(item, now: int | None = None) -> dict:
    """Einen Hinweis prüfen und normalisieren. Unbekannte Arten sind erlaubt (neuere Probe-Version)."""
    if not isinstance(item, dict):
        raise FindingError("JSON-Objekt erwartet.")
    now = repo.now() if now is None else now
    fid = item.get("finding_id")
    if not isinstance(fid, str) or not ID_RE.match(fid.strip()):
        raise FindingError("finding_id fehlt oder ist ungültig.")
    kind = item.get("kind")
    if not isinstance(kind, str) or not KIND_RE.match(kind):
        raise FindingError("kind fehlt oder ist ungültig.")
    severity = item.get("severity")
    if severity not in SEVERITIES:
        raise FindingError("severity ungültig – erlaubt: " + ", ".join(SEVERITIES) + ".")
    state = item.get("state")
    if state not in STATES:
        raise FindingError("state ungültig – erlaubt: active, resolved.")
    detected_at = _ts(item.get("detected_at"), "detected_at")
    if not now - MAX_AGE_S <= detected_at <= now + MAX_FUTURE_S:
        raise FindingError("detected_at muss zwischen jetzt − 30 Tagen und jetzt + 5 Minuten liegen.")
    resolved_at = None
    if state == "resolved":
        resolved_at = _ts(item.get("resolved_at") or now, "resolved_at")
        resolved_at = min(max(resolved_at, detected_at), now + MAX_FUTURE_S)
    title = _text(item.get("title"), MAX_TITLE) or KINDS.get(kind, kind)
    details = item.get("details") or {}
    if not isinstance(details, dict):
        raise FindingError("details muss ein JSON-Objekt sein.")
    clean = {}
    for key, value in list(details.items())[:MAX_DETAILS]:
        clean[_text(key, 40)] = _text(value, MAX_DETAIL_VALUE)
    return {
        "finding_id": fid.strip(), "kind": kind, "severity": severity, "state": state, "title": title,
        "message": _text(item.get("message"), MAX_TEXT), "solution": _text(item.get("solution"), MAX_TEXT),
        "adapter": _text(item.get("adapter"), MAX_ADAPTER),
        "adapter_description": _text(item.get("adapter_description"), MAX_ADAPTER),
        "details": clean, "detected_at": detected_at, "resolved_at": resolved_at,
    }


def validate_batch(data, now: int | None = None) -> tuple[list[dict], list[str]]:
    """Körper von ``POST /api/probe/v1/findings``. Ungültige Einträge werden einzeln übersprungen."""
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise FindingError('JSON-Objekt mit Liste "findings" erwartet.')
    items = data["findings"]
    if len(items) > MAX_BATCH:
        raise FindingError(f"Höchstens {MAX_BATCH} Hinweise je Sendung.")
    valid, errors = [], []
    for i, item in enumerate(items):
        try:
            valid.append(validate(item, now))
        except FindingError as exc:
            errors.append(f"Eintrag {i + 1}: {exc}")
    return valid, errors


def store(probe: dict, values: dict) -> bool:
    """Speichern oder aktualisieren. Ein behobener Hinweis wird durch eine ältere Nachlieferung nicht wieder aktiv."""
    ts = repo.now()
    existing = q1("SELECT id, state FROM client_findings WHERE probe_id = ? AND finding_id = ?",
                  (probe["id"], values["finding_id"]))
    details = json.dumps(values["details"], ensure_ascii=False, sort_keys=True)
    if values["state"] == "resolved" and values["details"].get("problem"):
        # Die Probe schickt beim Beheben den Entwarnungstext („wieder verbunden“) und das Problem in details.
        resolution = (values["message"] or values["title"])[:MAX_DETAIL_VALUE]
        values = {**values, "title": values["details"]["problem"][:MAX_TITLE],
                  "details": {**values["details"], "resolution": resolution}}
    if existing:
        if existing["state"] == "resolved" and values["state"] == "active":
            return False
        if values["state"] == "resolved":
            # Problem, Text und Lösungsvorschlag des aktiven Hinweises bleiben stehen
            old = q1("SELECT details FROM client_findings WHERE id = ?", (existing["id"],))
            merged = {**json.loads(old["details"] or "{}"), **values["details"]}
            ex("UPDATE client_findings SET state = 'resolved', resolved_at = ?, details = ?, updated_at = ? "
               "WHERE id = ?",
               (values["resolved_at"], json.dumps(merged, ensure_ascii=False, sort_keys=True), ts, existing["id"]))
            return False
        ex("UPDATE client_findings SET kind = ?, severity = ?, state = ?, adapter = ?, adapter_description = ?, "
           "title = ?, message = ?, solution = ?, details = ?, detected_at = ?, resolved_at = ?, updated_at = ? "
           "WHERE id = ?",
           (values["kind"], values["severity"], values["state"], values["adapter"] or None,
            values["adapter_description"] or None, values["title"], values["message"] or None,
            values["solution"] or None, details, values["detected_at"], values["resolved_at"], ts, existing["id"]))
        return False
    ins("INSERT INTO client_findings (probe_id, site_id, finding_id, kind, severity, state, adapter, "
        "adapter_description, title, message, solution, details, detected_at, resolved_at, received_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (probe["id"], probe["site_id"], values["finding_id"], values["kind"], values["severity"], values["state"],
         values["adapter"] or None, values["adapter_description"] or None, values["title"],
         values["message"] or None, values["solution"] or None, details, values["detected_at"],
         values["resolved_at"], ts, ts))
    return True


def close_stale(probe_id: int | None, before: int, reason: str) -> int:
    """Aktive Hinweise schließen, die die Probe nicht mehr bestätigen kann (Neustart des Dienstes, Überwachung aus).

    Besteht das Problem weiter, meldet die Probe es nach dem Neustart mit neuer finding_id erneut.
    """
    ts = repo.now()
    sql = "SELECT id, details FROM client_findings WHERE state = 'active' AND detected_at < ?"
    params: list = [before]
    if probe_id is not None:
        sql += " AND probe_id = ?"
        params.append(probe_id)
    rows = q(sql, params)
    for r in rows:
        details = {**json.loads(r["details"] or "{}"), "resolution": reason}
        ex("UPDATE client_findings SET state = 'resolved', resolved_at = ?, details = ?, updated_at = ? WHERE id = ?",
           (ts, json.dumps(details, ensure_ascii=False, sort_keys=True), ts, r["id"]))
    return len(rows)


# -- Abfragen ----------------------------------------------------------------
_SELECT = (
    "SELECT f.*, p.hostname AS probe_name, s.name AS site_name "
    "FROM client_findings f JOIN probes p ON p.id = f.probe_id LEFT JOIN sites s ON s.id = f.site_id"
)
_ORDER = (" ORDER BY CASE f.state WHEN 'active' THEN 0 ELSE 1 END, "
          "CASE f.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, f.detected_at DESC, f.id DESC")


def _decorate(row: dict) -> dict:
    row["kind_label"] = KINDS.get(row["kind"], row["title"])
    row["severity_label"] = SEVERITIES.get(row["severity"], row["severity"])
    row["state_label"] = STATES.get(row["state"], row["state"])
    row["details"] = json.loads(row["details"] or "{}")
    end = row["resolved_at"] or repo.now()
    row["duration_s"] = max(int(end) - int(row["detected_at"]), 0)
    return row


def search(probe_id: int | None = None, site_id: int | None = None, since: int | None = None,
           active_only: bool = False, limit: int = 50) -> list[dict]:
    """Aktive Hinweise immer, behobene ab ``since`` – aktive und schwere zuerst."""
    clauses, params = [], []
    if probe_id is not None:
        clauses.append("f.probe_id = ?")
        params.append(probe_id)
    if site_id is not None:
        clauses.append("f.site_id = ?")
        params.append(site_id)
    if active_only:
        clauses.append("f.state = 'active'")
    elif since is not None:
        clauses.append("(f.state = 'active' OR f.detected_at >= ? OR f.resolved_at >= ?)")
        params += [since, since]
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return [_decorate(r) for r in q(f"{_SELECT}{where}{_ORDER} LIMIT ?", (*params, int(limit)))]


def count_active(probe_id: int | None = None) -> int:
    if probe_id is None:
        return int(q1("SELECT COUNT(*) AS n FROM client_findings WHERE state = 'active'")["n"])
    return int(q1("SELECT COUNT(*) AS n FROM client_findings WHERE state = 'active' AND probe_id = ?",
                  (probe_id,))["n"])


def api_item(r: dict) -> dict:
    return {k: r[k] for k in ("id", "probe_id", "probe_name", "site_name", "finding_id", "kind", "severity", "state",
                              "adapter", "adapter_description", "title", "message", "solution", "details",
                              "detected_at", "resolved_at", "received_at")}
