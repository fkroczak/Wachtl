"""Netzwerkscan (docs/NETZWERKSCAN.md): Ergebnisse der Probes speichern und auswerten.

Gerät = je Standort eindeutig über die MAC-Adresse, ohne MAC über die IP. Anwesenheit wird als
Zeiträume geführt: ein Gerät, das in aufeinanderfolgenden Scans derselben Probe gesehen wird, verlängert
seinen Zeitraum; fehlt es und kommt wieder, beginnt ein neuer („Wiederkehrer“). Viele Wiederkehrer =
unregelmäßiges Gerät, ein möglicher Störer.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass

from .. import repo
from ..db import ex, ins, q, q1

log = logging.getLogger(__name__)

MAX_HOSTS = 4096
MAX_PORTS_PER_HOST = 256
TEXT_MAX = 200
IRREGULAR_RETURNS = 3          # ab so vielen Wiederkehrern in 24 h gilt ein Gerät als unregelmäßig
NEW_DEVICE_S = 86400
KEEP_DAYS = 90
MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

EVENT_LABELS = {
    "ip_conflict": "IP-Konflikt",
    "ip_changed": "IP-Adresse gewechselt",
    "new_device": "Neues Gerät",
    "device_back": "Gerät wieder da",
}
FLAG_LABELS = {
    "irregular": "unregelmäßig",
    "new": "neu",
    "ip_conflict": "IP-Konflikt",
    "ip_changed": "IP gewechselt",
    "random_mac": "zufällige MAC",
}

# Dienst → (Bezeichnung, Link-Schema). Schema None = kein Link aus dem Browser möglich.
SERVICES = {
    "ssh": ("SSH", "ssh"),
    "http": ("HTTP (Weboberfläche)", "http"),
    "https": ("HTTPS (Weboberfläche)", "https"),
    "rdp": ("Remotedesktop (RDP)", "rdp"),
    "vnc": ("VNC", "vnc"),
    "ftp": ("FTP", "ftp"),
    "telnet": ("Telnet", "telnet"),
    "smb": ("Windows-Freigabe (SMB)", "smb"),
    "smtp": ("SMTP (E-Mail)", None),
    "dns": ("DNS", None),
    "mqtt": ("MQTT", None),
    "mysql": ("MySQL/MariaDB", None),
    "postgres": ("PostgreSQL", None),
    "printer": ("Drucker", None),
    "sip": ("SIP (Telefonie)", None),
    "rtsp": ("RTSP (Kamera/Video)", None),
    "msrpc": ("Windows-RPC", None),
    "netbios": ("NetBIOS", None),
    "imap": ("IMAP (E-Mail)", None),
    "pop3": ("POP3 (E-Mail)", None),
    "tcp": ("offener TCP-Port", None),
}
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb", 515: "printer", 554: "rtsp", 587: "smtp",
    631: "printer", 993: "imap", 995: "pop3", 1883: "mqtt", 3306: "mysql", 3389: "rdp", 5060: "sip",
    5432: "postgres", 5900: "vnc", 5901: "vnc", 8006: "https", 8080: "http", 8443: "https", 9100: "printer",
}


def _text(value) -> str | None:
    if value is None:
        return None
    text = _CONTROL.sub("", str(value)).strip()[:TEXT_MAX]
    return text or None


def _int(value, lo: int, hi: int) -> int | None:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def _float(value, lo: float, hi: float) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def norm_mac(value) -> str | None:
    if not isinstance(value, str):
        return None
    mac = value.strip().upper().replace("-", ":")
    if not MAC_RE.match(mac) or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    if int(mac[:2], 16) & 1:        # Multicast
        return None
    return mac


def random_mac(mac: str | None) -> bool:
    """Lokal verwaltete MAC (zweites Bit gesetzt): meist ein Handy/Laptop mit privater WLAN-Adresse."""
    return bool(mac) and bool(int(mac[:2], 16) & 2)


def identify(port: int, banner: str | None = None, tls: bool = False, http_status: int | None = None,
             http_server: str | None = None, http_title: str | None = None) -> str:
    """Dienst aus Port, Banner und HTTP-/TLS-Antwort."""
    b = (banner or "").lstrip()
    upper = b.upper()
    if upper.startswith("SSH-"):
        return "ssh"
    if upper.startswith("RFB "):
        return "vnc"
    if http_status is not None or http_server or http_title or upper.startswith("HTTP/"):
        return "https" if tls else "http"
    if tls:
        return "https" if port in (443, 8443, 8006, 4443, 9443) or port not in PORT_SERVICES else PORT_SERVICES[port]
    if upper.startswith("220") and ("FTP" in upper or port == 21):
        return "ftp"
    if upper.startswith("220") and ("SMTP" in upper or "ESMTP" in upper or port in (25, 587)):
        return "smtp"
    if upper.startswith("* OK") and "IMAP" in upper:
        return "imap"
    if upper.startswith("+OK"):
        return "pop3"
    if b.startswith("\xff") or "LOGIN:" in upper[:200]:
        return "telnet"
    return PORT_SERVICES.get(port, "tcp")


def link_for(service: str, ip: str, port: int, device_id: int | None = None) -> dict | None:
    """Link zum Starten der Verbindung vom Browser-PC aus: {"url", "text", "kind"} oder None.

    kind: url (normaler Link), rdp (Datei herunterladen), copy (nur zum Kopieren, z. B. \\\\ip)."""
    scheme = SERVICES.get(service, ("", None))[1]
    host = f"[{ip}]" if ":" in ip else ip
    default = {"http": 80, "https": 443, "ssh": 22, "ftp": 21, "telnet": 23, "vnc": 5900}
    suffix = "" if default.get(scheme) == port else f":{port}"
    if scheme in ("http", "https"):
        return {"url": f"{scheme}://{host}{suffix}/", "text": f"{scheme}://{host}{suffix}", "kind": "url"}
    if scheme in ("ssh", "ftp", "telnet", "vnc"):
        return {"url": f"{scheme}://{host}{suffix}", "text": f"{scheme}://{host}{suffix}", "kind": "url"}
    if scheme == "rdp":
        return {"url": None, "text": f"{ip}:{port}" if port != 3389 else ip, "kind": "rdp", "device_id": device_id,
                "port": port}
    if scheme == "smb":
        return {"url": None, "text": f"\\\\{ip}", "kind": "copy"}
    return None


def rdp_file(ip: str, port: int) -> str:
    """Inhalt einer .rdp-Datei für mstsc (Windows-Remotedesktop)."""
    address = ip if port == 3389 else f"{ip}:{port}"
    return "\r\n".join([
        f"full address:s:{address}", "prompt for credentials:i:1", "administrative session:i:0",
        "screen mode id:i:2", "authentication level:i:2", "",
    ])


# -- Prüfen der Sendung ---------------------------------------------------------
class ScanError(ValueError):
    pass


@dataclass
class Host:
    ip: str
    mac: str | None
    hostname: str | None
    rtt_ms: float | None
    via: list[str]
    is_self: bool
    ports: list[dict]

    @property
    def key(self) -> str:
        return f"mac:{self.mac}" if self.mac else f"ip:{self.ip}"


def validate(data) -> dict:
    if not isinstance(data, dict):
        raise ScanError("JSON-Objekt erwartet")
    hosts_raw = data.get("hosts") if isinstance(data.get("hosts"), list) else []
    hosts: list[Host] = []
    seen: set[tuple] = set()
    for item in hosts_raw[:MAX_HOSTS]:
        if not isinstance(item, dict):
            continue
        try:
            ip = ipaddress.ip_address(str(item.get("ip", "")).strip())
        except ValueError:
            continue
        mac = norm_mac(item.get("mac"))
        if (str(ip), mac) in seen:
            continue
        seen.add((str(ip), mac))
        ports: list[dict] = []
        for p in (item.get("ports") if isinstance(item.get("ports"), list) else [])[:MAX_PORTS_PER_HOST]:
            if not isinstance(p, dict):
                continue
            port = _int(p.get("port"), 1, 65535)
            if port is None or any(x["port"] == port for x in ports):
                continue
            entry = {
                "port": port, "banner": _text(p.get("banner")), "tls": bool(p.get("tls")),
                "http_status": _int(p.get("http_status"), 100, 599), "http_server": _text(p.get("http_server")),
                "http_title": _text(p.get("http_title")), "tls_subject": _text(p.get("tls_subject")),
            }
            entry["service"] = identify(port, entry["banner"], entry["tls"], entry["http_status"],
                                        entry["http_server"], entry["http_title"])
            ports.append(entry)
        via = [v for v in (item.get("via") if isinstance(item.get("via"), list) else []) if v in ("icmp", "arp", "tcp")]
        hosts.append(Host(str(ip), mac, _text(item.get("hostname")), _float(item.get("rtt_ms"), 0, 60000), via,
                          bool(item.get("self")), sorted(ports, key=lambda x: x["port"])))
    subnets = [s for s in (_text(x) for x in (data.get("subnets") or [])[:32] if isinstance(data.get("subnets"), list))
               if s]
    return {
        "hosts": hosts, "subnets": subnets, "error": _text(data.get("error")),
        "duration_s": _float(data.get("duration_s"), 0, 86400),
        "trigger": "manual" if data.get("trigger") == "manual" else "schedule",
    }


# -- Speichern --------------------------------------------------------------------
def _event(site_id: int, device_id: int | None, run_id: int, ts: int, kind: str, ip: str | None, detail: str) -> None:
    ins("INSERT INTO net_events (site_id, device_id, run_id, ts, kind, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (site_id, device_id, run_id, ts, kind, ip, detail[:300]))


def _device(site_id: int, h: Host, ts: int) -> tuple[dict, bool]:
    row = q1("SELECT * FROM net_devices WHERE site_id = ? AND dev_key = ?", (site_id, h.key))
    if row:
        return row, False
    try:
        ins("INSERT INTO net_devices (site_id, dev_key, mac, ip, hostname, is_probe, rtt_ms, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (site_id, h.key, h.mac, h.ip, h.hostname, h.is_self, h.rtt_ms, ts, ts))
    except Exception:  # noqa: BLE001 – gleichzeitig von einer zweiten Probe angelegt
        pass
    return q1("SELECT * FROM net_devices WHERE site_id = ? AND dev_key = ?", (site_id, h.key)), True


def store(probe: dict, check: dict, values: dict, ts: int) -> int:
    """Scan speichern und auswerten. Gibt die ID des Laufs zurück."""
    site_id = int(probe["site_id"])
    hosts: list[Host] = values["hosts"]
    prev = q1("SELECT id, ts FROM netscan_runs WHERE probe_id = ? AND check_id = ? AND error IS NULL "
              "ORDER BY ts DESC, id DESC LIMIT 1", (probe["id"], check["id"]))
    run_id = ins(
        "INSERT INTO netscan_runs (probe_id, check_id, site_id, ts, duration_s, subnets, hosts_found, trigger, error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (probe["id"], check["id"], site_id, ts, values["duration_s"], json.dumps(values["subnets"]), len(hosts),
         values["trigger"], values["error"]),
    )
    if values["error"]:
        return run_id
    first_run = prev is None

    # IP-Konflikt im selben Scan: eine IP mit mehreren MACs
    macs_by_ip: dict[str, set[str]] = {}
    for h in hosts:
        if h.mac:
            macs_by_ip.setdefault(h.ip, set()).add(h.mac)

    for h in hosts:
        dev, created = _device(site_id, h, ts)
        if dev is None:
            continue
        ip_changed = bool(dev["ip"] and dev["ip"] != h.ip and h.mac)
        ex("UPDATE net_devices SET ip = ?, hostname = COALESCE(?, hostname), rtt_ms = ?, last_seen = ?, "
           "last_run_id = ?, is_probe = ?, ip_changes = ip_changes + ? WHERE id = ?",
           (h.ip, h.hostname, h.rtt_ms, ts, run_id, bool(dev["is_probe"]) or h.is_self, 1 if ip_changed else 0,
            dev["id"]))
        if ip_changed:
            _event(site_id, dev["id"], run_id, ts, "ip_changed", h.ip, f"vorher {dev['ip']}")
        if created and not first_run:
            _event(site_id, dev["id"], run_id, ts, "new_device", h.ip,
                   h.hostname or h.mac or "ohne Namen")

        # Anwesenheit fortschreiben oder neuen Zeitraum beginnen
        pres = q1("SELECT * FROM net_presence WHERE device_id = ? AND probe_id = ? AND check_id = ? "
                  "ORDER BY last_ts DESC, id DESC LIMIT 1", (dev["id"], probe["id"], check["id"]))
        if pres and prev and pres["last_run_id"] == prev["id"]:
            ex("UPDATE net_presence SET last_ts = ?, last_run_id = ?, ip = ? WHERE id = ?",
               (ts, run_id, h.ip, pres["id"]))
        else:
            ins("INSERT INTO net_presence (device_id, probe_id, check_id, first_ts, last_ts, last_run_id, ip) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (dev["id"], probe["id"], check["id"], ts, ts, run_id, h.ip))
            if pres:
                _event(site_id, dev["id"], run_id, ts, "device_back", h.ip,
                       f"nach {_human(ts - pres['last_ts'])} wieder erreichbar")

        # Konflikt: dieselbe IP gleichzeitig mit mehreren MACs, oder kurz zuvor bei einem anderen Gerät
        others = macs_by_ip.get(h.ip, set()) - {h.mac} if h.mac else set()
        if not others and h.mac:
            other = q1("SELECT mac FROM net_devices WHERE site_id = ? AND ip = ? AND id <> ? AND mac IS NOT NULL "
                       "AND last_seen >= ?", (site_id, h.ip, dev["id"], (prev["ts"] if prev else ts) - 60))
            if other and other["mac"] != h.mac:
                others = {other["mac"]}
        if others and not q1("SELECT id FROM net_events WHERE site_id = ? AND kind = 'ip_conflict' AND ip = ? "
                             "AND ts >= ?", (site_id, h.ip, ts - 3600)):
            _event(site_id, dev["id"], run_id, ts, "ip_conflict", h.ip,
                   f"{h.ip} gehört gleichzeitig zu {', '.join(sorted(others | {h.mac}))}")

        for p in h.ports:
            row = q1("SELECT id FROM net_services WHERE device_id = ? AND port = ?", (dev["id"], p["port"]))
            vals = (p["service"], p["tls"], p["banner"], p["http_status"], p["http_server"], p["http_title"],
                    p["tls_subject"], ts)
            if row:
                ex("UPDATE net_services SET service = ?, tls = ?, banner = ?, http_status = ?, http_server = ?, "
                   "http_title = ?, tls_subject = ?, last_seen = ? WHERE id = ?", (*vals, row["id"]))
            else:
                ins("INSERT INTO net_services (device_id, port, service, tls, banner, http_status, http_server, "
                    "http_title, tls_subject, last_seen, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (dev["id"], p["port"], *vals, ts))
    return run_id


def prune(ts: int | None = None) -> None:
    ts = ts or repo.now()
    limit = ts - KEEP_DAYS * 86400
    ex("DELETE FROM netscan_runs WHERE ts < ?", (limit,))
    ex("DELETE FROM net_presence WHERE last_ts < ?", (limit,))
    ex("DELETE FROM net_events WHERE ts < ?", (limit,))
    ex("DELETE FROM net_devices WHERE last_seen < ?", (limit,))


# -- Auswertung -------------------------------------------------------------------
def _human(seconds: int) -> str:
    seconds = max(int(seconds), 0)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} Tagen"


def device_label(d: dict) -> str:
    return d.get("note") or d.get("hostname") or d.get("ip") or d.get("mac") or "?"


def _latest_runs(site_id: int | None) -> dict[tuple[int, int], dict]:
    where, params = ("WHERE site_id = ?", (site_id,)) if site_id is not None else ("", ())
    rows = q("SELECT r.* FROM netscan_runs r JOIN (SELECT MAX(id) AS id FROM netscan_runs " + where +
             " GROUP BY probe_id, check_id) m ON m.id = r.id", params)
    return {(r["probe_id"], r["check_id"]): r for r in rows}


def devices(site_id: int | None, since: int, until: int | None = None, active_only: bool = False) -> list[dict]:
    """Geräte mit Anwesenheit, Wiederkehrern, Merkmalen und Diensten (für Seite und Bericht)."""
    until = until or repo.now()
    where, params = ["d.last_seen >= ?", "d.first_seen <= ?"], [since, until]
    if site_id is not None:
        where.append("d.site_id = ?")
        params.append(site_id)
    rows = q("SELECT d.*, s.name AS site_name FROM net_devices d JOIN sites s ON s.id = d.site_id WHERE "
             + " AND ".join(where) + " ORDER BY d.site_id, d.ip", params)
    if not rows:
        return []
    ids = [r["id"] for r in rows]
    marks = ",".join("?" * len(ids))
    presence: dict[int, list[dict]] = {}
    for p in q(f"SELECT * FROM net_presence WHERE device_id IN ({marks}) ORDER BY first_ts", ids):
        presence.setdefault(p["device_id"], []).append(p)
    services: dict[int, list[dict]] = {}
    for s in q(f"SELECT * FROM net_services WHERE device_id IN ({marks}) ORDER BY port", ids):
        services.setdefault(s["device_id"], []).append(s)
    # beide Geräte eines Konflikts markieren: das Ereignis hängt nur an einem, die IP teilen sich beide
    conflicts = q("SELECT DISTINCT site_id, ip FROM net_events WHERE kind = 'ip_conflict' AND ts >= ? AND ts <= ?",
                  (since, until))
    conflict_ips = {(c["site_id"], c["ip"]) for c in conflicts}
    latest = _latest_runs(site_id)
    latest_ids = {r["id"] for r in latest.values()}
    out = []
    for r in rows:
        pres = presence.get(r["id"], [])
        first_pres = {}
        for p in pres:          # erster Zeitraum je Probe/Check zählt nicht als Wiederkehr
            first_pres.setdefault((p["probe_id"], p["check_id"]), p["id"])
        returns = [p for p in pres if p["id"] not in first_pres.values() and since <= p["first_ts"] <= until]
        returns_24h = sum(1 for p in pres if p["id"] not in first_pres.values() and p["first_ts"] >= until - 86400)
        online = any(p["last_run_id"] in latest_ids for p in pres) or r["last_run_id"] in latest_ids
        flags = []
        if returns_24h >= IRREGULAR_RETURNS or len(returns) >= IRREGULAR_RETURNS * max((until - since) // 86400, 1):
            flags.append("irregular")
        if r["first_seen"] >= until - NEW_DEVICE_S and _site_has_older_runs(r):
            flags.append("new")
        if (r["site_id"], r["ip"]) in conflict_ips or any((r["site_id"], p["ip"]) in conflict_ips for p in pres
                                                           if p["last_ts"] >= since):
            flags.append("ip_conflict")
        if r["ip_changes"]:
            flags.append("ip_changed")
        if random_mac(r["mac"]):
            flags.append("random_mac")
        svc = []
        for s in services.get(r["id"], []):
            label = SERVICES.get(s["service"], (s["service"], None))[0]
            svc.append({**s, "label": label, "link": link_for(s["service"], r["ip"], s["port"], r["id"]),
                        "url": (link_for(s["service"], r["ip"], s["port"], r["id"]) or {}).get("url"),
                        "current": s["last_seen"] >= r["last_seen"] - 60})
        out.append({
            **r, "label": device_label(r), "online": online, "returns": len(returns), "returns_24h": returns_24h,
            "flags": flags, "flag_labels": [FLAG_LABELS[f] for f in flags], "services": svc, "presence": pres,
        })
    return out


def _site_has_older_runs(device: dict) -> bool:
    """„Neu“ nur, wenn der Standort schon vor dem Gerät gescannt wurde (sonst ist alles neu)."""
    return q1("SELECT id FROM netscan_runs WHERE site_id = ? AND ts < ? AND error IS NULL LIMIT 1",
              (device["site_id"], device["first_seen"])) is not None


def events(site_id: int | None, since: int, until: int | None = None, limit: int = 500) -> list[dict]:
    until = until or repo.now()
    where, params = ["e.ts >= ?", "e.ts <= ?"], [since, until]
    if site_id is not None:
        where.append("e.site_id = ?")
        params.append(site_id)
    rows = q("SELECT e.*, s.name AS site_name, d.hostname, d.ip AS dev_ip, d.mac, d.note FROM net_events e "
             "JOIN sites s ON s.id = e.site_id LEFT JOIN net_devices d ON d.id = e.device_id WHERE "
             + " AND ".join(where) + f" ORDER BY e.ts DESC LIMIT {int(limit)}", params)
    for r in rows:
        r["kind_label"] = EVENT_LABELS.get(r["kind"], r["kind"])
        r["device_label"] = device_label({"note": r["note"], "hostname": r["hostname"], "ip": r["dev_ip"] or r["ip"],
                                          "mac": r["mac"]})
    return rows


def presence_bar(pres: list[dict], since: int, until: int, monitored_from: int | None, cells: int = 48,
                 step_hint: int = 900) -> list[str]:
    """Anwesenheit als Zellen: „on“ = gesehen, „off“ = gescannt, aber nicht gesehen, „none“ = noch nicht gescannt."""
    step = (until - since) / cells
    out: list[str] = []
    for i in range(cells):
        a, b = since + i * step, since + (i + 1) * step
        if any(p["first_ts"] - step_hint / 2 < b and p["last_ts"] + step_hint / 2 > a for p in pres):
            out.append("on")
        elif monitored_from is None or b <= monitored_from:
            out.append("none")
        else:
            out.append("off")
    return out


def runs(site_id: int, since: int) -> list[dict]:
    return q("SELECT r.*, p.hostname AS probe_name FROM netscan_runs r JOIN probes p ON p.id = r.probe_id "
             "WHERE r.site_id = ? AND r.ts >= ? ORDER BY r.ts DESC LIMIT 200", (site_id, since))


def report_section(site_id: int | None, since: int, until: int) -> dict:
    """Daten für den PDF-Bericht (services/report_pdf.py)."""
    where, params = ["ts >= ?", "ts <= ?"], [since, until]
    if site_id is not None:
        where.append("site_id = ?")
        params.append(site_id)
    stat = q1("SELECT COUNT(*) AS n, MAX(ts) AS last FROM netscan_runs WHERE " + " AND ".join(where), params) or {}
    devs = devices(site_id, since, until)
    return {
        "runs": int(stat.get("n") or 0), "last_scan": stat.get("last"),
        "devices": [{k: d[k] for k in ("id", "site_name", "ip", "mac", "hostname", "vendor", "label", "first_seen",
                                       "last_seen", "online", "returns", "flags")}
                     | {"services": [{"port": s["port"], "service": s["service"], "label": s["label"], "url": s["url"]}
                                     for s in d["services"]]}
                     for d in devs],
        "events": [{k: e[k] for k in ("ts", "kind", "kind_label", "ip", "detail", "device_label", "site_name")}
                   for e in events(site_id, since, until)],
    }
