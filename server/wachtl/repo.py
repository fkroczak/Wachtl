"""Fachliche Datenzugriffe, die von API, Web-UI und CLI gemeinsam genutzt werden."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time

from .db import ex, ins, q, q1

CHECK_ROLES = {"gateway": "Gateway", "reference": "Referenz (Internet)", "target": "Ziel"}
ALLOWED_INTERVALS = (1, 5, 10, 30, 60)
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
PROBE_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

# Standard-Alarme: kind -> (Name, Schwellwert, Fenster s, for s, Stufe)
DEFAULT_ALERT_RULES = {
    "probe_offline": ("Probe offline (Sekunden ohne Heartbeat)", 120, 86400, 0, "critical"),
    "target_down": ("Ziel nicht erreichbar (aufeinanderfolgende Fehler)", 3, 0, 0, "critical"),
    "wan_down": ("Alle Internet-Referenzen gestört (Sekunden)", 30, 0, 0, "critical"),
    "packet_loss_warning": ("Paketverlust Warnung (%)", 2, 300, 60, "warning"),
    "packet_loss_critical": ("Paketverlust kritisch (%)", 10, 300, 60, "critical"),
    "latency_high": ("Latenz Durchschnitt (ms)", 100, 300, 60, "warning"),
}

DEFAULT_CHECKS = (
    # name, target, role
    ("Gateway", "gateway", "gateway"),
    ("Google DNS", "8.8.8.8", "reference"),
    ("Cloudflare DNS", "1.1.1.1", "reference"),
)


def now() -> int:
    return int(time.time())


def audit(username: str | None, action: str, obj: str = "", detail: str = "") -> None:
    ins(
        "INSERT INTO audit_log (ts, username, action, object, detail) VALUES (?, ?, ?, ?, ?)",
        (now(), username, action, obj, detail[:2000]),
    )


# -- Validierung ------------------------------------------------------------
def valid_target(target: str) -> bool:
    if target == "gateway":
        return True
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(target))


def valid_probe_hostname(hostname: str) -> bool:
    return bool(PROBE_HOST_RE.match(hostname or ""))


# -- Checks und Konfiguration ----------------------------------------------
def checks_for_probe(probe: dict) -> list[dict]:
    """Alle aktiven Checks, die dieser Probe zugewiesen sind (global, Standort, Probe)."""
    return q(
        """
        SELECT DISTINCT c.id, c.name, c.type, c.target, c.role, c.interval_s, c.timeout_ms, c.params
        FROM checks c
        JOIN check_assignments a ON a.check_id = c.id
        WHERE c.enabled = TRUE
          AND (a.scope = 'all'
               OR (a.scope = 'site' AND a.scope_id = ?)
               OR (a.scope = 'probe' AND a.scope_id = ?))
        ORDER BY c.id
        """,
        (probe["site_id"], probe["id"]),
    )


def probe_config(probe: dict) -> tuple[dict, str]:
    """Konfiguration für eine Probe und ihr ETag (Hash des Inhalts)."""
    checks = []
    for c in checks_for_probe(probe):
        checks.append(
            {
                "id": c["id"],
                "type": c["type"],
                "target": c["target"],
                "role": c["role"],
                "interval_s": c["interval_s"],
                "timeout_ms": min(c["timeout_ms"], c["interval_s"] * 1000),
                "params": json.loads(c["params"] or "{}"),
            }
        )
    payload = {
        "probe_id": probe["id"],
        "checks": checks,
        "upload_interval_s": 10,
        "heartbeat_interval_s": 30,
        "config_poll_s": 300,
    }
    etag = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    payload["etag"] = etag
    return payload, etag


def check_map_for_probe(probe: dict) -> dict[str, dict]:
    return {str(c["id"]): c for c in checks_for_probe(probe)}


def create_check(name: str, target: str, role: str, interval_s: int, timeout_ms: int,
                 scope: str, scope_id: int | None) -> int:
    ts = now()
    cid = ins(
        "INSERT INTO checks (name, type, target, role, interval_s, timeout_ms, params, enabled, created_at, updated_at) "
        "VALUES (?, 'ping', ?, ?, ?, ?, '{}', TRUE, ?, ?)",
        (name, target, role, interval_s, timeout_ms, ts, ts),
    )
    ins(
        "INSERT INTO check_assignments (check_id, scope, scope_id) VALUES (?, ?, ?)",
        (cid, scope, scope_id),
    )
    return cid


# -- Seed -------------------------------------------------------------------
def seed_defaults() -> list[str]:
    """Standard-Alarmregeln und Standard-Checks anlegen, falls noch nicht vorhanden."""
    created = []
    for kind, (name, threshold, window_s, for_s, severity) in DEFAULT_ALERT_RULES.items():
        if q1("SELECT id FROM alert_rules WHERE kind = ?", (kind,)) is None:
            ins(
                "INSERT INTO alert_rules (kind, name, threshold, window_s, for_s, severity, enabled, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, TRUE, ?)",
                (kind, name, threshold, window_s, for_s, severity, now()),
            )
            created.append(f"Alarmregel {kind}")
    if q1("SELECT id FROM checks LIMIT 1") is None:
        for name, target, role in DEFAULT_CHECKS:
            create_check(name, target, role, 1, 1000, "all", None)
            created.append(f"Check {name}")
    return created


def alert_rules() -> dict[str, dict]:
    return {r["kind"]: r for r in q("SELECT * FROM alert_rules ORDER BY id")}


# -- Status -----------------------------------------------------------------
ONLINE_SECONDS = 90


def probe_online(probe: dict) -> bool:
    return bool(probe.get("last_seen")) and now() - probe["last_seen"] <= ONLINE_SECONDS


def scope_label(scope: str, scope_id, sites: dict, probes: dict) -> str:
    if scope == "all":
        return "Alle Probes"
    if scope == "site":
        return f"Standort {sites.get(scope_id, {}).get('name', scope_id)}"
    return f"Probe {probes.get(scope_id, {}).get('hostname', scope_id)}"


def prune(ingest_days: int = 2, audit_days: int = 730, alert_days: int = 730) -> None:
    ts = now()
    ex("DELETE FROM ingest_batches WHERE received_at < ?", (ts - ingest_days * 86400,))
    ex("DELETE FROM audit_log WHERE ts < ?", (ts - audit_days * 86400,))
    ex("DELETE FROM alert_events WHERE status = 'resolved' AND ends_at < ?", (ts - alert_days * 86400,))


def probe_setup_file(probe_dir: str) -> "Path | None":
    """Neueste WachtlProbeSetup-*.exe im Probe-Ordner (vom Server-Setup beigelegt)."""
    from pathlib import Path

    if not probe_dir:
        return None
    files = sorted(Path(probe_dir).glob("WachtlProbeSetup-*.exe"), key=lambda f: f.stat().st_mtime)
    return files[-1] if files else None


def probe_ini(server_url: str, pin: str, token: str = "", proxy: str = "") -> str:
    return (
        "; Wachtl Probe – Vorbelegung für den Setup-Assistenten. Neben WachtlProbeSetup-*.exe ablegen.\r\n"
        "[wachtl]\r\n"
        f"server={server_url}\r\npin={pin}\r\ntoken={token}\r\nproxy={proxy}\r\n"
    )


def create_enrollment_token(site_id: int, max_uses: int, days: int, created_by: str, description: str = "") -> str:
    from .security import hash_token, new_secret

    token = "wachtl-" + new_secret(24)
    ins(
        "INSERT INTO enrollment_tokens (site_id, token_hash, description, expires_at, max_uses, uses, revoked, "
        "created_by, created_at) VALUES (?, ?, ?, ?, ?, 0, FALSE, ?, ?)",
        (site_id, hash_token(token), description[:200], now() + days * 86400, max_uses, created_by, now()),
    )
    audit(created_by, "token.create", f"site:{site_id}", f"{max_uses} Nutzungen, {days} Tage")
    return token


def ensure_site(name: str) -> int:
    row = q1("SELECT id FROM sites WHERE name = ?", (name,))
    if row:
        return int(row["id"])
    return ins("INSERT INTO sites (name, created_at) VALUES (?, ?)", (name, now()))
