"""Neue Ereignisse für Live-Benachrichtigungen: Web-UI (Hinweis unten rechts, Desktop-Benachrichtigung) und das
Tray-Symbol auf dem Wachtl-Server.

Quelle sind die Alarm-Historie (Ausfälle, jeder Paketverlust, WAN, Probe offline, Latenz …) und die
Client-Hinweise der PCs (Kabel getrennt, WLAN, Treiber …). Der Stand („Cursor“) ist die jeweils höchste ID.
"""
from __future__ import annotations

import json

from ..db import q, q1

TITLES = {
    "WachtlTargetDown": "Ausfall",
    "WachtlWanDown": "Internet ausgefallen",
    "WachtlPacketLossAny": "Paketverlust",
    "WachtlPacketLoss": "Paketverlust",
    "WachtlPacketLossCritical": "Starker Paketverlust",
    "WachtlProbeOffline": "Probe offline",
    "WachtlLatencyHigh": "Latenz hoch",
    "WachtlJitterHigh": "Jitter hoch",
    "WachtlRouteChanged": "Pfad geändert",
    "WachtlBandwidthLow": "Bandbreite zu niedrig",
    "WachtlVoipQuality": "Sprachqualität schlecht",
    "WachtlTest": "Testnachricht",
}
MAX_ITEMS = 50


def cursor() -> dict[str, int]:
    a = q1("SELECT MAX(id) AS n FROM alert_events")
    f = q1("SELECT MAX(id) AS n FROM client_findings")
    return {"a": int((a or {}).get("n") or 0), "f": int((f or {}).get("n") or 0)}


def alert_where(labels: dict) -> str:
    where = labels.get("probe_name") or ""
    if labels.get("site_name"):
        where = f"{where} ({labels['site_name']})" if where else labels["site_name"]
    return where


def alert_title(alertname: str, labels: dict) -> str:
    title = TITLES.get(alertname, "Alarm")
    if alertname == "WachtlTargetDown" and labels.get("role") == "gateway":
        title = "Gateway ausgefallen"
    where = alert_where(labels)
    return f"{title}: {where}" if where else title


def alert_item(r: dict) -> dict:
    labels = json.loads(r.get("labels") or "{}")
    return {
        "key": f"alert:{r['id']}", "source": "alert", "id": r["id"], "alertname": r["alertname"],
        "severity": r.get("severity") or "warning", "state": r["status"],
        "title": alert_title(r["alertname"], labels), "text": r.get("summary") or r["alertname"],
        "ts": r.get("exact_start") or r["starts_at"], "end": r.get("exact_end") or r.get("ends_at"),
        "probe_id": labels.get("probe"), "check_id": labels.get("check_id"), "site_id": labels.get("site"),
        # für das Zusammenfassen gleichzeitiger Ausfälle einer Probe im Tray (serverprobe/tray.py)
        "where": alert_where(labels), "role": labels.get("role") or "", "target": labels.get("target") or "",
    }


def finding_item(r: dict) -> dict:
    where = r.get("probe_name") or "?"
    if r.get("site_name"):
        where += f" ({r['site_name']})"
    text = r.get("message") or ""
    if r.get("solution") and r["state"] == "active":
        text += f" Lösung: {r['solution']}"
    return {
        "key": f"finding:{r['id']}", "source": "finding", "id": r["id"], "alertname": r["kind"],
        "severity": r["severity"], "state": "firing" if r["state"] == "active" else "resolved",
        "title": f"{r['title']} – {where}", "text": text.strip(), "ts": r["detected_at"], "end": r.get("resolved_at"),
        "probe_id": str(r["probe_id"]), "check_id": None, "site_id": str(r.get("site_id") or ""),
    }


def since(a: int, f: int, limit: int = MAX_ITEMS) -> list[dict]:
    """Ereignisse mit höherer ID als der Stand, älteste zuerst."""
    alerts = q("SELECT * FROM alert_events WHERE id > ? ORDER BY id LIMIT ?", (int(a), limit))
    findings = q("SELECT f.*, p.hostname AS probe_name, s.name AS site_name FROM client_findings f "
                 "LEFT JOIN probes p ON p.id = f.probe_id LEFT JOIN sites s ON s.id = f.site_id "
                 "WHERE f.id > ? ORDER BY f.id LIMIT ?", (int(f), limit))
    items = [alert_item(r) for r in alerts] + [finding_item(r) for r in findings]
    return sorted(items, key=lambda i: i["ts"] or 0)


def active_alert_ids() -> list[int]:
    return [int(r["id"]) for r in q("SELECT id FROM alert_events WHERE status = 'firing' ORDER BY id")]


def active_count() -> int:
    return int((q1("SELECT COUNT(*) AS n FROM alert_events WHERE status = 'firing'") or {}).get("n") or 0)
