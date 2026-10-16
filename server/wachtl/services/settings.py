"""Allgemeine Einstellungen (Tabelle ``settings``), im Web-UI unter Verwaltung › Messung änderbar."""
from __future__ import annotations

from urllib.parse import urlparse

from flask import current_app

from ..checktypes import Field, _convert
from ..db import ex, q, q1
from ..repo import now

PREFIX = "measure."

FIELDS: tuple[Field, ...] = (
    Field("iperf_enabled", "iperf3-Gegenstelle auf dem Wachtl-Server", "bool", True, group="iperf3-Server",
          help="Probes können gegen den Wachtl-Server messen."),
    Field("iperf_host", "Adresse für Probes", "host", "", group="iperf3-Server",
          help="Leer = Hostname aus der Server-URL. Bei NAT die von den Standorten erreichbare Adresse."),
    Field("iperf_port", "Port für Probes", "int", 5201, 1, 65535, group="iperf3-Server",
          help="Bei Portweiterleitung der äußere Port; der Server selbst lauscht auf dem bei der Installation gewählten Port."),
    Field("upload_interval_s", "Messwerte hochladen alle", "int", 10, 2, 300, unit="s", group="Probes"),
    Field("heartbeat_interval_s", "Heartbeat alle", "int", 30, 10, 300, unit="s", group="Probes",
          help="Bestimmt auch, wie schnell „Jetzt messen“ ankommt."),
    Field("config_poll_s", "Konfiguration spätestens abrufen alle", "int", 300, 30, 3600, unit="s", group="Probes"),
    Field("probe_iperf_port", "Standard-Port der iperf3-Gegenstelle auf Probes", "int", 5201, 1, 65535, group="Probes"),
    Field("history_days", "Pfad- und Bandbreitenverlauf aufbewahren", "int", 400, 7, 3650, unit="Tage",
          group="Aufbewahrung"),
    Field("outage_min_s", "Ausfälle anzeigen ab", "int", 0, 0, 3600, unit="s", group="Aufbewahrung",
          help="Kürzere Störungen tauchen nicht in der Ausfallübersicht auf."),
)
BY_KEY = {f.key: f for f in FIELDS}


def get() -> dict:
    values = {f.key: f.default for f in FIELDS}
    for row in q("SELECT key, value FROM settings WHERE key LIKE ?", (PREFIX + "%",)):
        key = row["key"].removeprefix(PREFIX)
        f = BY_KEY.get(key)
        if f is None:
            continue
        if f.kind == "bool":
            values[key] = row["value"] == "true"
        else:
            try:
                values[key] = _convert(f, row["value"])
            except ValueError:
                pass
    return values


def parse(form) -> tuple[dict, list[str]]:
    values, errors = {}, []
    for f in FIELDS:
        raw = form.get(f.key)
        if f.kind == "bool":
            values[f.key] = raw == "on"
            continue
        try:
            values[f.key] = _convert(f, (raw or "").strip())
        except ValueError as exc:
            errors.append(f"{f.label}: {exc}")
    return values, errors


def save(values: dict) -> list[str]:
    """Speichert und gibt die geänderten Schlüssel zurück."""
    current = get()
    changed = []
    ts = now()
    for key, value in values.items():
        if key not in BY_KEY or current.get(key) == value:
            continue
        text = ("true" if value else "false") if isinstance(value, bool) else str(value)
        if q1("SELECT key FROM settings WHERE key = ?", (PREFIX + key,)):
            ex("UPDATE settings SET value = ?, updated_at = ? WHERE key = ?", (text, ts, PREFIX + key))
        else:
            ex("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)", (PREFIX + key, text, ts))
        changed.append(key)
    return changed


def iperf_server_address(values: dict | None = None) -> tuple[str, int] | None:
    values = values or get()
    if not values["iperf_enabled"]:
        return None
    host = values["iperf_host"] or urlparse(current_app.config["PUBLIC_URL"]).hostname or ""
    return (host, int(values["iperf_port"])) if host else None
