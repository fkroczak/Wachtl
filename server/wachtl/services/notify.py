"""Benachrichtigungen: Einstellungen in der Datenbank, daraus erzeugte Alertmanager-Konfiguration.

Die Datei wird von der App geschrieben und Alertmanager per ``/-/reload`` neu geladen –
so lassen sich E-Mail und Teams im Web-UI ändern, auf Linux wie auf Windows.
"""
from __future__ import annotations

import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone

import requests
import yaml
from flask import current_app

from ..db import ex, q, q1
from ..repo import now

log = logging.getLogger(__name__)

# Schlüssel -> Umgebungsvariable für den einmaligen Import bei der Ersteinrichtung
FIELDS = {
    "email_to": "ALERT_EMAIL_TO",
    "email_from": "ALERT_EMAIL_FROM",
    "smtp_smarthost": "SMTP_SMARTHOST",
    "smtp_username": "SMTP_USERNAME",
    "smtp_password": "SMTP_PASSWORD",
    "smtp_require_tls": "SMTP_REQUIRE_TLS",
    "teams_webhook_url": "TEAMS_WEBHOOK_URL",
}
SECRET_FIELDS = {"smtp_password"}

INHIBIT_RULES = [
    # Probe offline: keine Folgealarme dieser Probe
    {"source_matchers": ['alertname="WachtlProbeOffline"'],
     "target_matchers": ['alertname=~"WachtlTargetDown|WachtlWanDown|WachtlPacketLoss.*|WachtlLatencyHigh'
                         '|WachtlJitterHigh|WachtlBandwidthLow|WachtlRouteChanged"'],
     "equal": ["probe"]},
    # Gateway oder WAN weg: Bandbreiten-, Jitter- und Pfadalarme derselben Probe sind Folgen
    {"source_matchers": ['alertname=~"WachtlWanDown|WachtlTargetDown"', 'role=~"gateway|"'],
     "target_matchers": ['alertname=~"WachtlBandwidthLow|WachtlJitterHigh|WachtlRouteChanged"'], "equal": ["probe"]},
    # Gateway weg: Internet- und Zielalarme derselben Probe unterdrücken
    {"source_matchers": ['alertname="WachtlTargetDown"', 'role="gateway"'],
     "target_matchers": ['role=~"reference|target"'], "equal": ["probe"]},
    {"source_matchers": ['alertname="WachtlTargetDown"', 'role="gateway"'],
     "target_matchers": ['alertname="WachtlWanDown"'], "equal": ["probe"]},
    # WAN weg: Einzelalarme der Internet-Referenzen unterdrücken
    {"source_matchers": ['alertname="WachtlWanDown"'], "target_matchers": ['role="reference"'], "equal": ["probe"]},
    # Kritischer Paketverlust ersetzt die Warnung
    {"source_matchers": ['alertname="WachtlPacketLossCritical"'], "target_matchers": ['alertname="WachtlPacketLoss"'],
     "equal": ["probe", "check_id"]},
]


class NotifyError(RuntimeError):
    pass


# -- Einstellungen ------------------------------------------------------------
def get_settings() -> dict[str, str]:
    values = {k: "" for k in FIELDS}
    values["smtp_require_tls"] = "true"
    for row in q("SELECT key, value FROM settings WHERE key LIKE 'notify.%'"):
        values[row["key"].removeprefix("notify.")] = row["value"]
    return values


def save_settings(new: dict[str, str]) -> None:
    ts = now()
    for key in FIELDS:
        if key not in new:
            continue
        value = str(new[key]).strip()
        full = f"notify.{key}"
        if q1("SELECT key FROM settings WHERE key = ?", (full,)):
            ex("UPDATE settings SET value = ?, updated_at = ? WHERE key = ?", (value, ts, full))
        else:
            ex("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)", (full, value, ts))


def import_from_env() -> bool:
    """Einmalig: Werte aus der Umgebung übernehmen, solange noch nichts gespeichert ist."""
    if q1("SELECT key FROM settings WHERE key LIKE 'notify.%' LIMIT 1"):
        return False
    values = {k: os.environ.get(env, "") for k, env in FIELDS.items()}
    values["smtp_require_tls"] = values["smtp_require_tls"] or "true"
    save_settings(values)
    return True


def validate(values: dict[str, str]) -> list[str]:
    errors = []
    if values.get("email_to"):
        if "@" not in values["email_to"]:
            errors.append("E-Mail-Empfänger ist ungültig.")
        if not values.get("smtp_smarthost") or ":" not in values["smtp_smarthost"]:
            errors.append("SMTP-Server bitte als host:port angeben, z. B. mail.kunde.de:587.")
        if "@" not in values.get("email_from", ""):
            errors.append("Absenderadresse ist ungültig.")
    url = values.get("teams_webhook_url", "")
    if url and not url.startswith("https://"):
        errors.append("Teams-Webhook muss mit https:// beginnen.")
    return errors


# -- Alertmanager-Konfiguration ---------------------------------------------------
def build_config(settings: dict[str, str], internal_url: str, webhook_secret: str) -> dict:
    notify: dict = {"name": "notify"}
    config: dict = {}
    if settings.get("email_to"):
        glob = {
            "smtp_smarthost": settings["smtp_smarthost"],
            "smtp_from": settings["email_from"],
            "smtp_require_tls": settings.get("smtp_require_tls", "true").lower() in ("1", "true", "ja", "on"),
        }
        if settings.get("smtp_username"):
            glob["smtp_auth_username"] = settings["smtp_username"]
            glob["smtp_auth_password"] = settings.get("smtp_password", "")
        config["global"] = glob
        notify["email_configs"] = [
            {"to": addr.strip(), "send_resolved": True} for addr in settings["email_to"].split(",") if addr.strip()
        ]
    if settings.get("teams_webhook_url"):
        notify["msteamsv2_configs"] = [{"webhook_url": settings["teams_webhook_url"], "send_resolved": True}]

    config["route"] = {
        "receiver": "notify",
        "group_by": ["alertname", "site", "probe"],
        "group_wait": "30s",
        "group_interval": "5m",
        "repeat_interval": "4h",
        "routes": [
            {"receiver": "wachtl-history", "group_by": ["..."], "group_wait": "0s", "group_interval": "1m",
             "repeat_interval": "12h", "continue": True},
            {"receiver": "notify"},
        ],
    }
    config["inhibit_rules"] = INHIBIT_RULES
    config["receivers"] = [
        {
            "name": "wachtl-history",
            "webhook_configs": [{
                "url": internal_url.rstrip("/") + "/api/internal/alertmanager",
                "send_resolved": True,
                "http_config": {"authorization": {"type": "Bearer", "credentials": webhook_secret}},
            }],
        },
        notify,
    ]
    return config


def write_config(reload: bool = True) -> str | None:
    path = current_app.config.get("AM_CONFIG")
    if not path:
        return None
    cfg = build_config(get_settings(), current_app.config["INTERNAL_URL"], current_app.config["WEBHOOK_SECRET"])
    content = "# Automatisch von Wachtl erzeugt – Änderungen bitte im Web-UI unter Verwaltung › Benachrichtigungen.\n"
    content += yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True, width=200)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".am-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, 0o644)  # Alertmanager-Container läuft als eigener Benutzer und muss lesen können
    os.replace(tmp, path)
    if reload:
        reload_alertmanager()
    return path


def reload_alertmanager() -> bool:
    url = current_app.config.get("ALERTMANAGER_URL")
    if not url:
        return False
    try:
        requests.post(url + "/-/reload", timeout=10).raise_for_status()
        return True
    except requests.RequestException as exc:
        log.warning("Alertmanager konnte nicht neu geladen werden: %s", exc)
        return False


def send_test(username: str) -> None:
    """Testalarm direkt an Alertmanager – geht an alle eingetragenen Empfänger."""
    url = current_app.config.get("ALERTMANAGER_URL")
    if not url:
        raise NotifyError("Alertmanager ist nicht konfiguriert.")
    start = datetime.now(timezone.utc)
    alert = [{
        "labels": {"alertname": "WachtlTest", "severity": "info", "site_name": "Test", "probe": "test",
                   "nonce": start.strftime("%H%M%S")},
        "annotations": {"summary": f"Testnachricht von Wachtl, ausgelöst von {username}"},
        "startsAt": start.isoformat().replace("+00:00", "Z"),
        "endsAt": (start + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
    }]
    try:
        requests.post(url + "/api/v2/alerts", json=alert, timeout=10).raise_for_status()
    except requests.RequestException as exc:
        raise NotifyError(f"Alertmanager nicht erreichbar: {exc}") from exc
