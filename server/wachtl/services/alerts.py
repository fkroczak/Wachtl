"""Alarm-Historie (Webhook von Alertmanager) und Bestätigung per Stummschaltung."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import requests
from flask import current_app

from ..db import ex, ins, q1
from ..repo import now

log = logging.getLogger(__name__)
_ZERO_TIME = "0001-01-01T00:00:00Z"


def _ts(value: str | None) -> int | None:
    if not value or value.startswith("0001-"):
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def store_webhook(payload: dict) -> int:
    """Alertmanager-Webhook (Version 4) in ``alert_events`` übernehmen."""
    count = 0
    for a in payload.get("alerts", []):
        labels = a.get("labels", {})
        if labels.get("disturbance"):
            continue  # vom Server selbst erkannte Störung, steht schon sekundengenau in alert_events
        fingerprint = a.get("fingerprint") or json.dumps(labels, sort_keys=True)
        starts_at = _ts(a.get("startsAt")) or now()
        status = "resolved" if a.get("status") == "resolved" else "firing"
        ends_at = _ts(a.get("endsAt")) if status == "resolved" else None
        summary = (a.get("annotations") or {}).get("summary", "")
        existing = q1(
            "SELECT id FROM alert_events WHERE fingerprint = ? AND starts_at = ?", (fingerprint, starts_at)
        )
        if existing:
            ex(
                "UPDATE alert_events SET status = ?, ends_at = ?, summary = ?, updated_at = ? WHERE id = ?",
                (status, ends_at, summary, now(), existing["id"]),
            )
        else:
            ins(
                "INSERT INTO alert_events (fingerprint, alertname, severity, status, labels, summary, starts_at, "
                "ends_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fingerprint,
                    labels.get("alertname", "?"),
                    labels.get("severity"),
                    status,
                    json.dumps(labels, sort_keys=True),
                    summary,
                    starts_at,
                    ends_at,
                    now(),
                ),
            )
        count += 1
    return count


def acknowledge(event: dict, username: str, hours: int, comment: str) -> str | None:
    """Stummschaltung in Alertmanager anlegen und Bestätigung vermerken."""
    labels = json.loads(event["labels"])
    matchers = [
        {"name": k, "value": labels[k], "isRegex": False, "isEqual": True}
        for k in ("alertname", "probe", "check_id")
        if k in labels
    ]
    start = datetime.now(timezone.utc)
    body = {
        "matchers": matchers,
        "startsAt": start.isoformat().replace("+00:00", "Z"),
        "endsAt": (start + timedelta(hours=hours)).isoformat().replace("+00:00", "Z"),
        "createdBy": username,
        "comment": comment or "Bestätigt in Wachtl",
    }
    silence_id = None
    url = current_app.config.get("ALERTMANAGER_URL")
    if url:
        try:
            r = requests.post(url + "/api/v2/silences", json=body, timeout=10)
            r.raise_for_status()
            silence_id = r.json().get("silenceID")
        except (requests.RequestException, ValueError) as exc:
            log.warning("Stummschaltung fehlgeschlagen: %s", exc)
            raise RuntimeError("Alertmanager nicht erreichbar – Alarm nicht bestätigt.") from exc
    ex(
        "UPDATE alert_events SET acked_by = ?, acked_at = ?, silence_id = ?, updated_at = ? WHERE id = ?",
        (username, now(), silence_id, now(), event["id"]),
    )
    return silence_id
