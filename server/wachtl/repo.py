"""Fachliche Datenzugriffe, die von API, Web-UI und CLI gemeinsam genutzt werden."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time

from .db import ex, ins, q, q1

CHECK_ROLES = {"gateway": "Gateway", "reference": "Referenz (Internet)", "target": "Ziel"}
ALLOWED_INTERVALS = (1, 2, 5, 10, 15, 30, 60, 120, 300)
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
PROBE_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

# Standard-Alarme: kind -> (Name, Schwellwert, Fenster s, for s, Stufe)
DEFAULT_ALERT_RULES = {
    "probe_offline": ("Probe offline (Sekunden ohne Heartbeat)", 120, 86400, 0, "critical"),
    "target_down": ("Ziel nicht erreichbar ab (Sekunden ohne Antwort)", 5, 0, 0, "critical"),
    "wan_down": ("Alle Internet-Referenzen gestört ab (Sekunden)", 5, 0, 0, "critical"),
    "packet_loss_warning": ("Paketverlust Warnung (%)", 2, 300, 60, "warning"),
    "packet_loss_critical": ("Paketverlust kritisch (%)", 10, 300, 60, "critical"),
    "latency_high": ("Latenz Durchschnitt (ms)", 100, 300, 60, "warning"),
    "jitter_high": ("Jitter Durchschnitt (ms)", 30, 300, 60, "warning"),
    "route_change": ("Pfad geändert (Alarm bleibt Sekunden stehen)", 900, 0, 0, "info"),
    "bandwidth_low": ("Bandbreite unter Schwellwert des Checks (Messungen in Folge)", 2, 0, 0, "warning"),
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
    """Alle aktiven Checks, die dieser Probe zugewiesen sind (global, Standort, Probe).

    Die Server-Probe misst kein iperf3 gegen den Wachtl-Server – das wäre eine Messung gegen sich selbst.
    """
    rows = q(
        """
        SELECT DISTINCT c.id, c.name, c.type, c.target, c.role, c.interval_s, c.timeout_ms, c.params, c.created_at
        FROM checks c
        JOIN check_assignments a ON a.check_id = c.id
        WHERE c.enabled = TRUE
          AND (a.scope = 'all'
               OR (a.scope = 'site' AND a.scope_id = ?)
               OR (a.scope = 'probe' AND a.scope_id = ?))
          AND NOT EXISTS (SELECT 1 FROM check_assignments x
                          WHERE x.check_id = c.id AND x.scope = 'exclude_probe' AND x.scope_id = ?)
        ORDER BY c.id
        """,
        (probe["site_id"], probe["id"], probe["id"]),
    )
    if probe.get("kind") == "server":
        rows = [c for c in rows if not is_server_iperf(c)]
    return rows


def is_server_iperf(check: dict) -> bool:
    if check["type"] != "iperf":
        return False
    params = json.loads(check.get("params") or "{}")
    return params.get("peer", "server") == "server"


def _schedule_offset(probe_id: int, check_id: int, schedule_min: int, offset_min: int) -> int:
    """Fester Versatz je Probe und Check, damit nicht alle Probes zur selben Minute messen."""
    if not schedule_min:
        return 0
    if offset_min >= 0:
        return offset_min % schedule_min
    digest = hashlib.sha256(f"{probe_id}:{check_id}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % schedule_min


def probe_iperf_endpoint(peer: dict, default_port: int = 5201) -> tuple[str | None, int]:
    """Adresse, unter der eine andere Probe ihren iperf3-Server anbietet."""
    host = peer.get("iperf_address")
    if not host:
        addresses = json.loads(peer.get("addresses") or "[]")
        host = addresses[0] if addresses else peer.get("last_ip")
    return host, int(peer.get("iperf_port") or default_port)


def probe_config(probe: dict) -> tuple[dict, str]:
    """Konfiguration für eine Probe und ihr ETag (Hash des Inhalts)."""
    from . import checktypes
    from .services import settings as settings_service

    settings = settings_service.get()
    server_iperf = None
    checks = []
    for c in checks_for_probe(probe):
        ctype = c["type"]
        params = checktypes.merged(ctype, json.loads(c["params"] or "{}"))
        item = {
            "id": c["id"],
            "type": ctype,
            "target": c["target"],
            "role": c["role"],
            "interval_s": c["interval_s"],
            "timeout_ms": min(c["timeout_ms"], c["interval_s"] * 1000),
            "params": params,
        }
        if ctype in checktypes.SCHEDULED_TYPES:
            params["offset_min"] = _schedule_offset(probe["id"], c["id"], params["schedule_min"], params["offset_min"])
            peer_host, peer_port, peer_error = None, None, None
            if ctype == "iperf" and params["peer"] == "server":
                if server_iperf is None:
                    server_iperf = settings_service.iperf_server_address(settings) or ("", 0)
                peer_host, peer_port = server_iperf
                if not peer_host:
                    peer_error = "iperf3-Gegenstelle auf dem Wachtl-Server ist abgeschaltet"
            elif ctype == "iperf" and params["peer"] == "probe":
                peer = q1("SELECT * FROM probes WHERE id = ?", (params["peer_probe_id"],))
                if peer is None:
                    peer_error = "Gegenstellen-Probe existiert nicht mehr"
                elif peer["id"] == probe["id"]:
                    peer_error = "Probe kann nicht gegen sich selbst messen"
                elif not peer["iperf_server"]:
                    peer_error = f"Probe {peer['hostname']} ist nicht als iperf3-Gegenstelle eingerichtet"
                else:
                    peer_host, peer_port = probe_iperf_endpoint(peer, settings["probe_iperf_port"])
            elif ctype == "iperf" or params.get("method") == "iperf":
                peer_host, peer_port = params["host"], params["port"]
            item["peer"] = {"host": peer_host, "port": peer_port, "error": peer_error}
        checks.append(item)
    payload = {
        "probe_id": probe["id"],
        "checks": checks,
        "iperf_server": {
            "enabled": bool(probe.get("iperf_server")),
            "port": int(probe.get("iperf_port") or settings["probe_iperf_port"]),
        },
        "server_urls": server_urls(),
        "upload_interval_s": settings["upload_interval_s"],
        "heartbeat_interval_s": settings["heartbeat_interval_s"],
        "config_poll_s": settings["config_poll_s"],
        "client_findings": {
            "enabled": bool(settings["client_findings_enabled"]),
            "notify": bool(settings["client_findings_enabled"] and settings["client_findings_notify"]),
        },
    }
    etag = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    payload["etag"] = etag
    return payload, etag


def check_map_for_probe(probe: dict) -> dict[str, dict]:
    return {str(c["id"]): c for c in checks_for_probe(probe)}


def create_check(name: str, target: str, role: str, interval_s: int, timeout_ms: int,
                 scope: str, scope_id: int | None, ctype: str = "ping", params: dict | None = None) -> int:
    ts = now()
    cid = ins(
        "INSERT INTO checks (name, type, target, role, interval_s, timeout_ms, params, enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?)",
        (name, ctype, target, role, interval_s, timeout_ms, json.dumps(params or {}, sort_keys=True), ts, ts),
    )
    ins(
        "INSERT INTO check_assignments (check_id, scope, scope_id) VALUES (?, ?, ?)",
        (cid, scope, scope_id),
    )
    return cid


def update_check(check_id: int, name: str, target: str, role: str, interval_s: int, timeout_ms: int,
                 scope: str, scope_id: int | None, params: dict) -> None:
    ex(
        "UPDATE checks SET name = ?, target = ?, role = ?, interval_s = ?, timeout_ms = ?, params = ?, updated_at = ? "
        "WHERE id = ?",
        (name, target, role, interval_s, timeout_ms, json.dumps(params, sort_keys=True), now(), check_id),
    )
    # Ausnahmen einzelner Probes („für diese Probe entfernen“) bleiben beim Bearbeiten erhalten
    ex("DELETE FROM check_assignments WHERE check_id = ? AND scope <> 'exclude_probe'", (check_id,))
    ins("INSERT INTO check_assignments (check_id, scope, scope_id) VALUES (?, ?, ?)", (check_id, scope, scope_id))


# -- Aufträge an Probes ------------------------------------------------------
COMMAND_TYPES = ("run_check", "retrace")
COMMAND_TTL_S = 3600


def queue_command(probe_id: int, ctype: str, check_id: int | None, username: str) -> int:
    if ctype not in COMMAND_TYPES:
        raise ValueError(ctype)
    pending = q1(
        "SELECT id FROM probe_commands WHERE probe_id = ? AND type = ? AND check_id = ? AND delivered_at IS NULL",
        (probe_id, ctype, check_id),
    )
    if pending:
        return int(pending["id"])
    return ins(
        "INSERT INTO probe_commands (probe_id, type, check_id, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
        (probe_id, ctype, check_id, username, now()),
    )


def take_commands(probe_id: int) -> list[dict]:
    """Offene Aufträge abholen und als zugestellt markieren (veraltete werden verworfen)."""
    ts = now()
    rows = q(
        "SELECT id, type, check_id FROM probe_commands WHERE probe_id = ? AND delivered_at IS NULL AND created_at > ? "
        "ORDER BY id",
        (probe_id, ts - COMMAND_TTL_S),
    )
    if rows:
        ex("UPDATE probe_commands SET delivered_at = ? WHERE probe_id = ? AND delivered_at IS NULL", (ts, probe_id))
    return [{"id": r["id"], "type": r["type"], "check_id": r["check_id"]} for r in rows]


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
        # Neue Installation: Standardpaket (Ping Gateway, drei Internet-Referenzen, Wachtl-Server, Traceroute
        # ins Internet und zum Server, Speedtest) für alle Probes. iperf3 belastet das LAN und bleibt Wahl.
        from flask import current_app

        from . import standardpaket
        keys = [i.key for i in standardpaket.ITEMS if i.key not in standardpaket.NOT_DEFAULT]
        done, _skipped = standardpaket.apply(keys, "all", None, current_app.config.get("PUBLIC_URL", ""))
        if not done:  # ohne App-Konfiguration: wenigstens Gateway und Internet
            for name, target, role in DEFAULT_CHECKS:
                create_check(name, target, role, 1, 1000, "all", None)
                created.append(f"Check {name}")
        created += [f"Check {item.name}" for _cid, item in done]
    return created


def alert_rules() -> dict[str, dict]:
    return {r["kind"]: r for r in q("SELECT * FROM alert_rules ORDER BY id")}


def graph_thresholds() -> dict[str, float | None]:
    """Schwellen der aktiven Alarmregeln für den Latenzgraphen (Linien, Hinterlegung, Farbe nach Verlust)."""
    rules = alert_rules()

    def thr(kind: str, key: str = "threshold") -> float | None:
        r = rules.get(kind)
        return r[key] if r and r["enabled"] else None

    return {"lat_warn_ms": thr("latency_high"), "lat_window_s": thr("latency_high", "window_s"),
            "loss_warn_pct": thr("packet_loss_warning"), "loss_bad_pct": thr("packet_loss_critical"),
            "loss_window_s": thr("packet_loss_warning", "window_s") or thr("packet_loss_critical", "window_s")}


# -- Status -----------------------------------------------------------------
ONLINE_SECONDS = 90


def probe_online(probe: dict) -> bool:
    return bool(probe.get("last_seen")) and now() - probe["last_seen"] <= ONLINE_SECONDS


def scope_label(scope: str, scope_id, sites: dict, probes: dict) -> str:
    if scope == "all":
        return "Alle Probes"
    if scope == "site":
        return f"Standort {sites.get(scope_id, {}).get('name', scope_id)}"
    if scope == "exclude_probe":
        return f"außer {probes.get(scope_id, {}).get('hostname', scope_id)}"
    return f"Probe {probes.get(scope_id, {}).get('hostname', scope_id)}"


def remove_check_from_probe(check_id: int, probe: dict) -> str:
    """Check bei einer Probe entfernen. Gilt er nur für sie, wird er gelöscht; sonst bekommt die Probe eine Ausnahme.

    Gibt "deleted" oder "excluded" zurück.
    """
    scopes = [a for a in q("SELECT scope, scope_id FROM check_assignments WHERE check_id = ? AND scope <> 'exclude_probe'",
                           (check_id,))]
    only_this = scopes and all(a["scope"] == "probe" and a["scope_id"] == probe["id"] for a in scopes)
    if only_this:
        ex("DELETE FROM checks WHERE id = ?", (check_id,))
        return "deleted"
    if q1("SELECT id FROM check_assignments WHERE check_id = ? AND scope = 'probe' AND scope_id = ?",
          (check_id, probe["id"])):
        ex("DELETE FROM check_assignments WHERE check_id = ? AND scope = 'probe' AND scope_id = ?", (check_id, probe["id"]))
    if not q1("SELECT id FROM check_assignments WHERE check_id = ? AND scope = 'exclude_probe' AND scope_id = ?",
              (check_id, probe["id"])):
        ins("INSERT INTO check_assignments (check_id, scope, scope_id) VALUES (?, 'exclude_probe', ?)",
            (check_id, probe["id"]))
    return "excluded"


def excluded_checks(probe: dict) -> list[dict]:
    """Checks, die für diese Probe entfernt wurden, aber noch für andere gelten (zum Wiederherstellen)."""
    return q(
        "SELECT c.id, c.name, c.type, c.target FROM checks c JOIN check_assignments x ON x.check_id = c.id "
        "WHERE x.scope = 'exclude_probe' AND x.scope_id = ? ORDER BY c.name",
        (probe["id"],),
    )


def prune(ingest_days: int = 2, audit_days: int = 730, alert_days: int = 730, history_days: int | None = None) -> None:
    ts = now()
    if history_days is None:
        from .services import settings as settings_service

        history_days = settings_service.get()["history_days"]
    ex("DELETE FROM path_runs WHERE ts < ?", (ts - history_days * 86400,))
    ex("DELETE FROM bandwidth_runs WHERE ts < ?", (ts - history_days * 86400,))
    ex("DELETE FROM probe_commands WHERE created_at < ?", (ts - 7 * 86400,))
    ex("DELETE FROM ingest_batches WHERE received_at < ?", (ts - ingest_days * 86400,))
    ex("DELETE FROM audit_log WHERE ts < ?", (ts - audit_days * 86400,))
    ex("DELETE FROM alert_events WHERE status = 'resolved' AND ends_at < ?", (ts - alert_days * 86400,))
    ex("DELETE FROM incident_reports WHERE occurred_at < ?", (ts - alert_days * 86400,))


def probe_setup_file(probe_dir: str) -> "Path | None":
    """Neuestes Setup im Probe-Ordner (WachtlSetup-*.exe, ältere Server: WachtlProbeSetup-*.exe)."""
    from .setupfile import find_setup

    return find_setup(probe_dir)


def server_urls() -> list[str]:
    """Alle Adressen, unter denen Probes den Server erreichen können – Name zuerst, dann weitere Namen und IPs.

    Die Probe prüft nur den Schlüssel-Pin, nicht den Namen im Zertifikat: jede Adresse funktioniert,
    auch eine IP, wenn die Namensauflösung am Standort fehlt.
    """
    from urllib.parse import urlparse

    from flask import current_app

    cfg = current_app.config
    urls: list[str] = []

    def add(url: str) -> None:
        url = url.strip().rstrip("/")
        if url.startswith("https://") and url not in urls:
            urls.append(url)

    add(cfg["PUBLIC_URL"])
    for url in cfg.get("SERVER_URLS") or []:
        add(url)
    if cfg.get("AUTO_IPS"):
        from .netinfo import local_ipv4

        port = urlparse(cfg["PUBLIC_URL"]).port
        for ip in local_ipv4():
            add(f"https://{ip}" + (f":{port}" if port and port != 443 else ""))
    return urls


def probe_ini(server_url: str, pin: str, token: str = "", proxy: str = "") -> str:
    return (
        "; Wachtl Probe – Vorbelegung für den Setup-Assistenten. Neben WachtlProbeSetup-*.exe ablegen.\r\n"
        "[wachtl]\r\n"
        f"server={server_url}\r\npin={pin}\r\ntoken={token}\r\nproxy={proxy}\r\n"
    )


def create_enrollment_token(site_id: int, max_uses: int, days: int, created_by: str, description: str = "",
                            probe_kind: str = "probe") -> str:
    from .security import hash_token, new_secret

    token = "wachtl-" + new_secret(24)
    ins(
        "INSERT INTO enrollment_tokens (site_id, token_hash, description, expires_at, max_uses, uses, revoked, "
        "created_by, created_at, probe_kind) VALUES (?, ?, ?, ?, ?, 0, FALSE, ?, ?, ?)",
        (site_id, hash_token(token), description[:200], now() + days * 86400, max_uses, created_by, now(),
         probe_kind),
    )
    audit(created_by, "token.create", f"site:{site_id}", f"{max_uses} Nutzungen, {days} Tage")
    return token


def ensure_site(name: str) -> int:
    row = q1("SELECT id FROM sites WHERE name = ?", (name,))
    if row:
        return int(row["id"])
    return ins("INSERT INTO sites (name, created_at) VALUES (?, ?)", (name, now()))
