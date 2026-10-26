"""Switch-Topologie (docs/TOPOLOGIE.md): Abfragen speichern, Baum bauen, Auffälligkeiten erkennen, Pfad verfolgen.

Ablauf: Die Server-Probe fragt jeden Switch per SNMP ab (snmpcollect.py) und schickt die Momentaufnahme
hierher. Daraus entsteht bei jedem Seitenaufruf der Baum:

1. Verbindungen zwischen Switches aus LLDP/CDP (die Switches nennen ihre Nachbarn samt Port).
2. Fehlt LLDP, aus den MAC-Tabellen: A sieht B an Port p und B sieht A an Port q, und kein dritter Switch
   liegt dazwischen (die Mengen der dahinter gesehenen Switches sind disjunkt) → Kabel A.p ⇄ B.q.
3. Geräte hängen an dem Port, an dem ihre MAC gelernt wurde und der keine Verbindung zu einem Switch ist.
   Viele Geräte an einem Port ohne LLDP-Nachbarn → vermutlich ein nicht verwalteter Switch.
4. Wurzel: der Switch, an dem das Standard-Gateway hängt; sonst der mit den meisten Verbindungen.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field

from .. import repo
from ..db import ex, ins, q, q1
from ..snmpcollect import PHYSICAL_TYPES

log = logging.getLogger(__name__)

SNMP_VERSIONS = (("2c", "SNMPv2c (Community)"), ("3", "SNMPv3 (Benutzer und Passwort, verschlüsselt)"),
                 ("1", "SNMPv1 (Community, sehr alte Geräte)"))
SEC_LEVELS = (("authPriv", "Anmeldung und Verschlüsselung (empfohlen)"), ("authNoPriv", "nur Anmeldung"),
              ("noAuthNoPriv", "ohne Anmeldung und Verschlüsselung"))
AUTH_CHOICES = (("sha", "SHA-1"), ("sha256", "SHA-256"), ("sha512", "SHA-512"), ("sha224", "SHA-224"),
                ("sha384", "SHA-384"), ("md5", "MD5 (veraltet)"))
PRIV_CHOICES = (("aes", "AES-128"), ("aes256", "AES-256"), ("aes192", "AES-192"), ("aes256c", "AES-256 (Cisco)"),
                ("aes192c", "AES-192 (Cisco)"), ("des", "DES (veraltet)"))
ERRORS_WARN = 50                 # neue Eingangsfehler in 24 h, ab denen ein Port auffällt
ERRORS_CRIT = 1000
UNMANAGED_MIN_MACS = 3           # so viele Geräte an einem Port ohne Nachbarn → nicht verwalteter Switch vermutet
FLAP_MOVES = 3                   # so oft dieselbe MAC zwischen Ports in 24 h → Schleifenverdacht
KEEP_DAYS = 90
TEXT_MAX = 200
MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
SFP_RE = re.compile(r"sfp|^xg|^te|tengig|^10g|25g|40g|^xe-|hundredgig|fortygig|twentyfive", re.I)
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
KIND_LABELS = {
    "unreachable": "Switch antwortet nicht", "port_errors": "Port-Fehler", "slow_link": "Langsame Verbindung",
    "half_duplex": "Halbduplex", "mac_flap": "Schleifenverdacht", "unmanaged": "Nicht verwalteter Switch",
    "no_credentials": "Switch ohne Zugangsdaten", "no_fdb": "Keine MAC-Tabelle",
}


# -- Zugangsdaten -------------------------------------------------------------------
def credentials(sw: dict):
    """Gespeicherte Zugangsdaten als snmp.Credentials (entschlüsselt)."""
    from .. import secretbox, snmp

    data = secretbox.unseal(sw["secret"])
    return snmp.Credentials(**{k: data.get(k, d) for k, d in (
        ("version", "2c"), ("community", ""), ("user", ""), ("auth_proto", "none"), ("auth_key", ""),
        ("priv_proto", "none"), ("priv_key", ""), ("context", ""))})


def parse_credentials(form, existing: dict | None = None) -> tuple[dict, list]:
    """Formular des Assistenten → Zugangsdaten. Leere Passwortfelder behalten den gespeicherten Wert."""
    from ..checktypes import FieldError

    existing = existing or {}
    errors: list = []
    version = form.get("snmp_version", "2c")
    if version not in ("1", "2c", "3"):
        errors.append(FieldError("SNMP-Version: bitte auswählen.", "snmp_version"))
        version = "2c"
    out = {"version": version, "community": "", "user": "", "auth_proto": "none", "auth_key": "",
           "priv_proto": "none", "priv_key": "", "context": ""}

    def secret(key: str) -> str:
        value = form.get(key) or ""
        return value if value else (existing.get(key, "") if existing.get("version") == version or
                                    (version != "3" and existing.get("version") in ("1", "2c")) else "")

    if version in ("1", "2c"):
        out["community"] = secret("community")
        if not out["community"]:
            errors.append(FieldError("Community: bitte eintragen (steht in der Weboberfläche des Switches unter SNMP).",
                                     "community"))
        elif len(out["community"]) > 64 or not out["community"].isprintable():
            errors.append(FieldError("Community: höchstens 64 druckbare Zeichen.", "community"))
        return out, errors
    out["user"] = (form.get("user") or "").strip()
    if not out["user"] or len(out["user"]) > 32 or not out["user"].isprintable():
        errors.append(FieldError("Benutzer: 1 bis 32 Zeichen.", "user"))
    level = form.get("sec_level", "authPriv")
    if level not in dict(SEC_LEVELS):
        errors.append(FieldError("Sicherheitsstufe: bitte auswählen.", "sec_level"))
        level = "authPriv"
    if level in ("authNoPriv", "authPriv"):
        out["auth_proto"] = form.get("auth_proto", "sha")
        if out["auth_proto"] not in dict(AUTH_CHOICES):
            errors.append(FieldError("Anmeldeverfahren: bitte auswählen.", "auth_proto"))
            out["auth_proto"] = "sha"
        out["auth_key"] = secret("auth_key")
        if not 8 <= len(out["auth_key"]) <= 64:
            errors.append(FieldError("Passwort Anmeldung: 8 bis 64 Zeichen.", "auth_key"))
    if level == "authPriv":
        out["priv_proto"] = form.get("priv_proto", "aes")
        if out["priv_proto"] not in dict(PRIV_CHOICES):
            errors.append(FieldError("Verschlüsselungsverfahren: bitte auswählen.", "priv_proto"))
            out["priv_proto"] = "aes"
        out["priv_key"] = secret("priv_key")
        if not 8 <= len(out["priv_key"]) <= 64:
            errors.append(FieldError("Passwort Verschlüsselung: 8 bis 64 Zeichen.", "priv_key"))
    out["context"] = (form.get("context") or "").strip()[:32]
    return out, errors


def sec_level(creds: dict) -> str:
    if creds.get("priv_proto", "none") != "none":
        return "authPriv"
    return "authNoPriv" if creds.get("auth_proto", "none") != "none" else "noAuthNoPriv"


def credential_hint(creds: dict) -> str:
    """Zugang ohne Geheimnisse beschreiben (Tabelle, Audit-Log)."""
    if creds.get("version") in ("1", "2c"):
        return f"SNMPv{creds['version']}, Community"
    parts = [f"SNMPv3, Benutzer {creds.get('user')}"]
    if creds.get("auth_proto", "none") != "none":
        parts.append(dict(AUTH_CHOICES).get(creds["auth_proto"], creds["auth_proto"]))
    if creds.get("priv_proto", "none") != "none":
        parts.append(dict(PRIV_CHOICES).get(creds["priv_proto"], creds["priv_proto"]))
    return ", ".join(parts)


# -- Aufträge für die Server-Probe ------------------------------------------------------
def intervals() -> tuple[int, int]:
    """(vollständige Abfrage in s, schnelle Abfrage in s; 0 = aus) aus Verwaltung › Messung."""
    from . import settings as settings_service

    v = settings_service.get()
    return int(v["topo_full_min"]) * 60, int(v["topo_quick_s"])


def jobs(ts: int | None = None, limit: int = 40) -> list[dict]:
    """Fällige Abfragen mit entschlüsselten Zugangsdaten: vollständig (Intervall, „Jetzt abfragen“, erste Abfrage)
    oder schnell (nur Port-Status). Nicht erreichbare Switches nur im Takt der vollständigen Abfrage."""
    from ..secretbox import SecretError, unseal

    ts = ts or repo.now()
    full_s, quick_s = intervals()
    out = []
    for sw in q("SELECT id, host, port, secret, last_full, last_poll, last_error, poll_requested, "
                "CASE WHEN snapshot IS NULL THEN 0 ELSE 1 END AS has_snapshot FROM net_switches WHERE status = 'active' "
                "ORDER BY CASE WHEN poll_requested IS NULL THEN 1 ELSE 0 END, COALESCE(last_poll, 0)"):
        full = (not sw["last_full"] or sw["last_full"] <= ts - full_s or not sw["has_snapshot"]
                or (sw["poll_requested"] and sw["poll_requested"] >= (sw["last_poll"] or 0)))
        quick = (quick_s and not sw["last_error"] and sw["has_snapshot"]
                 and (sw["last_poll"] or 0) <= ts - quick_s + 5)
        if not full and not quick:
            continue
        try:
            creds = unseal(sw["secret"])
        except SecretError as exc:
            ex("UPDATE net_switches SET last_poll = ?, last_full = ?, last_error = ? WHERE id = ?",
               (ts, ts, str(exc), sw["id"]))
            continue
        out.append({"switch_id": sw["id"], "host": sw["host"], "port": sw["port"], "credentials": creds,
                    "kind": "full" if full else "quick"})
        if len(out) >= limit:
            break
    return out


# -- Ergebnis speichern -----------------------------------------------------------------
def _text(v, limit: int = TEXT_MAX) -> str | None:
    if v is None:
        return None
    t = "".join(ch for ch in str(v) if ch.isprintable()).strip()[:limit]
    return t or None


def _int(v, lo: int = 0, hi: int = 2 ** 63) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def _mac(v) -> str | None:
    if not isinstance(v, str):
        return None
    m = v.strip().upper().replace("-", ":")
    return m if MAC_RE.match(m) else None


def _ip(v) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v).strip())) if v else None
    except ValueError:
        return None


def clean_quick(data) -> dict:
    """Schnelle Abfrage prüfen: Laufzeit und je Port Status, Geschwindigkeit, Fehler, letzte Änderung."""
    if not isinstance(data, dict) or not isinstance(data.get("interfaces"), list):
        raise ValueError("Momentaufnahme fehlt")
    out = []
    for i in data["interfaces"][:1024]:
        if isinstance(i, dict) and (idx := _int(i.get("index"), 1, 2 ** 31)) is not None:
            out.append({"index": idx, "admin_up": bool(i.get("admin_up")), "oper_up": bool(i.get("oper_up")),
                        "speed_mbps": _int(i.get("speed_mbps"), 0, 10 ** 7), "in_errors": _int(i.get("in_errors")),
                        "last_change_s": _int(i.get("last_change_s"))})
    sysd = data.get("system") if isinstance(data.get("system"), dict) else {}
    return {"quick": True, "system": {"uptime_s": _int(sysd.get("uptime_s"))}, "interfaces": out}


def merge_quick(old: dict, quick: dict) -> dict:
    """Schnelle Abfrage in die letzte vollständige einarbeiten (MAC-Tabelle und Nachbarn bleiben)."""
    new = json.loads(json.dumps(old))
    by_idx = {i["index"]: i for i in quick["interfaces"]}
    for i in new.get("interfaces") or []:
        qi = by_idx.get(i["index"])
        if qi:
            for k in ("admin_up", "oper_up", "in_errors", "last_change_s"):
                i[k] = qi[k]
            if qi["oper_up"] and qi["speed_mbps"]:
                i["speed_mbps"] = qi["speed_mbps"]
    new.setdefault("system", {})["uptime_s"] = quick["system"]["uptime_s"]
    return new


def clean_snapshot(data) -> dict:
    """Momentaufnahme der Probe prüfen und kürzen – nur bekannte Felder mit passenden Typen."""
    if not isinstance(data, dict):
        raise ValueError("Momentaufnahme fehlt")
    sysd = data.get("system") if isinstance(data.get("system"), dict) else {}
    lst = lambda key, n: [x for x in (data.get(key) if isinstance(data.get(key), list) else [])[:n]  # noqa: E731
                          if isinstance(x, dict)]
    interfaces = []
    for i in lst("interfaces", 1024):
        idx = _int(i.get("index"), 1, 2 ** 31)
        if idx is None:
            continue
        interfaces.append({
            "index": idx, "name": _text(i.get("name"), 80) or f"Port {idx}", "descr": _text(i.get("descr"), 120),
            "alias": _text(i.get("alias"), 120), "type": _int(i.get("type"), 0, 1000),
            "speed_mbps": _int(i.get("speed_mbps"), 0, 10 ** 7), "mac": _mac(i.get("mac")),
            "admin_up": bool(i.get("admin_up")), "oper_up": bool(i.get("oper_up")),
            "in_errors": _int(i.get("in_errors")), "out_errors": _int(i.get("out_errors")),
            "fcs_errors": _int(i.get("fcs_errors")),
            "duplex": i.get("duplex") if i.get("duplex") in ("half", "full") else None,
            "last_change_s": _int(i.get("last_change_s")),
        })
    ids = {i["index"] for i in interfaces}
    fdb = []
    for e in lst("fdb", 20000):
        mac, ifi = _mac(e.get("mac")), _int(e.get("if_index"))
        if mac and ifi in ids:
            fdb.append({"mac": mac, "if_index": ifi, "vlan": _int(e.get("vlan"), 0, 4095)})

    def neighbor(e: dict, keys: tuple[str, ...]) -> dict:
        n = {"if_index": _int(e.get("if_index")) if _int(e.get("if_index")) in ids else None,
             "mgmt_ip": _ip(e.get("mgmt_ip"))}
        for k in keys:
            n[k] = _text(e.get(k), 300 if k == "sys_descr" else 120)
        for k in ("bridge", "ap", "router", "phone"):
            n[k] = bool(e.get(k))
        return n

    poe = data.get("poe") if isinstance(data.get("poe"), dict) else None
    return {
        "system": {"name": _text(sysd.get("name"), 120), "descr": _text(sysd.get("descr"), 400),
                   "object_id": _text(sysd.get("object_id"), 120), "uptime_s": _int(sysd.get("uptime_s")),
                   "location": _text(sysd.get("location"), 120), "contact": _text(sysd.get("contact"), 120)},
        "interfaces": interfaces, "fdb": fdb,
        "lldp": [neighbor(e, ("chassis_id", "port_id", "port_descr", "sys_name", "sys_descr")) for e in lst("lldp", 4096)],
        "cdp": [neighbor(e, ("device_id", "port_id", "platform")) for e in lst("cdp", 4096)],
        "pvid": {str(k): v for k, v in (data.get("pvid") or {}).items()
                 if _int(k) in ids and _int(v, 1, 4095)} if isinstance(data.get("pvid"), dict) else {},
        "poe": {"power_w": _int(poe.get("power_w"), 0, 100000), "used_w": _int(poe.get("used_w"), 0, 100000),
                "ports": [p for p in (poe.get("ports") or [])[:1024] if _int(p) in ids]} if poe else None,
        "ips": [ip for ip in (_ip(x) for x in (data.get("ips") or [])[:256]) if ip],
        "arp": [{"ip": _ip(a.get("ip")), "mac": _mac(a.get("mac"))} for a in lst("arp", 5000)
                if _ip(a.get("ip")) and _mac(a.get("mac"))],
        "gateway": _ip(data.get("gateway")), "base_mac": _mac(data.get("base_mac")),
        "lldp_chassis": _text(data.get("lldp_chassis"), 120), "duration_s": data.get("duration_s")
        if isinstance(data.get("duration_s"), (int, float)) else None,
    }


def store_result(sw: dict, snapshot: dict | None, error: str | None, ts: int, kind: str = "full") -> None:
    """Abfrage speichern: Fehler oder Momentaufnahme; Änderungen als Verlauf; Befunde neu.

    kind = quick: nur Port-Status, wird in die letzte vollständige Abfrage eingearbeitet."""
    from . import topo_history

    full = kind != "quick"
    if error or snapshot is None:
        if not sw.get("last_error") and sw.get("last_ok"):
            topo_history.event(sw, ts, "switch_down", "critical", None, None,
                               f"Antwortet nicht mehr: {_text(error) or 'Abfrage fehlgeschlagen'}")
        ex("UPDATE net_switches SET last_poll = ?, last_full = ?, last_error = ?, poll_requested = NULL WHERE id = ?",
           (ts, ts if full else sw.get("last_full"), (_text(error) or "Abfrage fehlgeschlagen"), sw["id"]))
        refresh_findings(sw["site_id"], ts)
        return
    old = json.loads(sw["snapshot"]) if sw.get("snapshot") else None
    if not full:
        if not old:
            ex("UPDATE net_switches SET last_poll = ? WHERE id = ?", (ts, sw["id"]))
            return
        snapshot = merge_quick(old, snapshot)
    changes = 0
    if sw.get("last_error") and sw.get("last_ok"):
        topo_history.event(sw, ts, "switch_up", "info", None, None,
                           f"Wieder erreichbar (nicht erreichbar seit {_ago(sw.get('last_poll'))})")
        changes += 1
    if old or full:
        if full:                     # vollständige Abfrage: Switch-MACs neu lesen (neuer Switch, neue Ports)
            from flask import current_app

            _SITE_MACS.pop((current_app.config["DATABASE_URL"], sw["site_id"]), None)
        macs, labels = _site_macs(sw["site_id"])
        # erste Abfrage: gegen einen leeren Stand vergleichen – merkt sich die Geräte, ohne sie als neu zu melden
        base = old or {"system": {}, "interfaces": [], "fdb": None, "lldp": None}
        changes += topo_history.record(sw, base, snapshot, ts, full, macs, labels)
    topo_history.store_snapshot(sw["id"], snapshot, ts)
    s = snapshot["system"]
    if full:
        ex("UPDATE net_switches SET last_poll = ?, last_full = ?, last_ok = ?, last_error = NULL, poll_requested = NULL, "
           "sys_name = ?, sys_descr = ?, sys_object_id = ?, sys_location = ?, uptime_s = ?, base_mac = ?, snapshot = ?, "
           "updated_at = ? WHERE id = ?",
           (ts, ts, ts, s["name"], s["descr"], s["object_id"], s["location"], s["uptime_s"],
            snapshot.get("base_mac"), json.dumps(snapshot, separators=(",", ":")), ts, sw["id"]))
    else:
        ex("UPDATE net_switches SET last_poll = ?, last_ok = ?, last_error = NULL, uptime_s = ?, snapshot = ?, "
           "updated_at = ? WHERE id = ?",
           (ts, ts, s.get("uptime_s"), json.dumps(snapshot, separators=(",", ":")), ts, sw["id"]))
    if full or changes or sw.get("last_error"):
        refresh_findings(sw["site_id"], ts)


_SITE_MACS: dict[tuple[str, int], tuple[float, set[str]]] = {}


def _site_macs(site_id: int) -> tuple[set[str], dict[str, str]]:
    """MAC-Adressen der Switches eines Standorts (zählen nicht als Geräte) und Namen der Geräte aus dem Netzwerkscan.

    Die Switch-MACs sind fünf Minuten zwischengespeichert – die schnelle Abfrage läuft jede Minute für jeden Switch."""
    import time

    from flask import current_app

    key = (current_app.config["DATABASE_URL"], site_id)
    hit = _SITE_MACS.get(key)
    if hit and time.monotonic() - hit[0] < 300:
        macs = hit[1]
    else:
        macs = set()
        for r in q("SELECT base_mac, snapshot FROM net_switches WHERE site_id = ?", (site_id,)):
            if r["base_mac"]:
                macs.add(r["base_mac"])
            snap = json.loads(r["snapshot"]) if r["snapshot"] else {}
            macs |= {i["mac"] for i in snap.get("interfaces") or [] if i.get("mac")}
        _SITE_MACS[key] = (time.monotonic(), macs)
    labels = {d["mac"]: d["note"] or d["hostname"] or d["ip"] or d["mac"]
              for d in q("SELECT mac, ip, hostname, note FROM net_devices WHERE site_id = ? AND mac IS NOT NULL",
                         (site_id,))}
    return macs, labels


def prune(ts: int | None = None) -> None:
    from . import topo_history

    topo_history.prune(ts, KEEP_DAYS)
    limit = (ts or repo.now()) - KEEP_DAYS * 86400
    ex("DELETE FROM net_port_errors WHERE ts < ?", (limit,))
    ex("DELETE FROM net_topo_events WHERE ts < ?", (limit,))
    ex("DELETE FROM net_topo_findings WHERE active = FALSE AND last_seen < ?", (limit,))


# -- Baum ---------------------------------------------------------------------------
def count_text(n: int) -> str:
    return f"{n} Gerät" if n == 1 else f"{n} Geräte"


def speed_text(mbps: int | None) -> str:
    if not mbps:
        return "–"
    if mbps >= 1000:
        return f"{mbps / 1000:g} Gbit/s"
    return f"{mbps} Mbit/s"


def speed_short(mbps: int | None) -> str:
    if not mbps:
        return ""
    return f"{mbps / 1000:g}G" if mbps >= 1000 else f"{mbps}M"


def speed_class(mbps: int | None) -> str:
    if not mbps:
        return "sp-none"
    return "sp-10" if mbps >= 10000 else "sp-1" if mbps >= 1000 else "sp-100"


def port_short(name: str | None) -> str:
    """„GigabitEthernet1/0/24“ → „1/0/24“, „Port 7“ → „7“ – kurz für Linien und Frontansicht."""
    if not name:
        return "?"
    if len(name) <= 5:
        return name
    m = re.search(r"(\d+(?:/\d+)*)\s*$", name)
    return m.group(1) if m else name[:8]


@dataclass
class Port:
    index: int
    name: str
    short: str
    descr: str | None
    alias: str | None
    type: int | None
    speed: int | None
    up: bool
    admin_up: bool
    duplex: str | None
    physical: bool
    sfp: bool
    poe: bool = False
    vlan: int | None = None
    errors_24h: int = 0
    macs: list[str] = field(default_factory=list)
    devices: list[dict] = field(default_factory=list)
    neighbor: dict | None = None            # LLDP/CDP-Nachbar (Anzeige)
    link: "Link | None" = None              # Verbindung zu einem Knoten im Baum
    sees_switches: bool = False             # dahinter liegen weitere verwaltete Switches
    role: str = "free"                      # uplink | downlink | access | free | down

    @property
    def state(self) -> str:
        """Klasse für Frontansicht und Tabellen."""
        if not self.up:
            return "free"
        if self.errors_24h >= ERRORS_WARN:
            return "err"
        return speed_class(self.speed)


@dataclass
class Link:
    a: str                      # Knoten-ID
    a_port: int | None
    b: str
    b_port: int | None
    b_port_text: str | None
    speed: int | None
    via: str                    # lldp | cdp | mac | gateway | vermutet


@dataclass
class Node:
    id: str
    kind: str                   # switch | neighbor | unmanaged | ap | gateway | internet
    label: str
    sub: str = ""
    switch_id: int | None = None
    status: str = "ok"          # ok | warn | bad | off
    ip: str | None = None
    parent: str | None = None
    link: Link | None = None    # Verbindung zum Elternknoten
    children: list[str] = field(default_factory=list)
    devices: list[dict] = field(default_factory=list)   # Geräte direkt an diesem Knoten (nicht verwaltet / AP)
    findings: list[int] = field(default_factory=list)   # Nummern der Befunde (Problem-Ansicht)


@dataclass
class Topology:
    nodes: dict[str, Node]
    roots: list[str]
    switches: dict[int, dict]                  # switch_id → {"row", "ports": {ifIndex: Port}, "node"}
    links: list[Link]
    locations: dict[str, tuple[int, int]]      # MAC → (switch_id, ifIndex)
    devices: dict[str, dict]                   # MAC → Gerät (Netzwerkscan, ARP)
    gateway_ip: str | None = None
    findings: list[dict] = field(default_factory=list)


def _norm(name: str | None) -> str:
    return (name or "").strip().lower().split(".")[0]


def switch_label(sw: dict) -> str:
    return sw.get("name") or sw.get("sys_name") or sw.get("host") or f"Switch {sw.get('id')}"


def build(site_id: int, ts: int | None = None, at: int | None = None) -> Topology:
    """Baum eines Standorts aus den gespeicherten Abfragen und dem Netzwerkscan; mit ``at`` im Stand von damals."""
    from . import topo_history

    ts = at or ts or repo.now()
    rows = topo_history.rows_at(site_id, at) if at else \
        q("SELECT * FROM net_switches WHERE site_id = ? AND status <> 'draft' ORDER BY id", (site_id,))
    errs: dict[tuple[int, int], int] = {}
    if rows:
        marks = ",".join("?" * len(rows))
        for r in q(f"SELECT switch_id, if_index, SUM(errors) AS n FROM net_port_errors WHERE switch_id IN ({marks}) "
                   "AND ts >= ? GROUP BY switch_id, if_index", [r["id"] for r in rows] + [ts - 86400]):
            errs[(r["switch_id"], r["if_index"])] = int(r["n"] or 0)
    devices: dict[str, dict] = {}
    for d in q("SELECT id, mac, ip, hostname, note, is_probe FROM net_devices WHERE site_id = ? AND mac IS NOT NULL",
               (site_id,)):
        devices[d["mac"]] = {"mac": d["mac"], "ip": d["ip"], "hostname": d["hostname"], "device_id": d["id"],
                             "label": d["note"] or d["hostname"] or d["ip"] or d["mac"], "is_probe": bool(d["is_probe"])}
    return analyze(rows, devices, errs)


def analyze(rows: list[dict], devices: dict[str, dict], errs: dict[tuple[int, int], int] | None = None) -> Topology:
    """Reine Auswertung (ohne Datenbank, testbar)."""
    errs = errs or {}
    devices = {m: dict(d) for m, d in devices.items()}
    nodes: dict[str, Node] = {}
    switches: dict[int, dict] = {}
    links: list[Link] = []
    ident_mac: dict[str, str] = {}
    ident_ip: dict[str, str] = {}
    ident_name: dict[str, str] = {}

    # 1. Verwaltete Switches und ihre Ports
    for r in rows:
        snap = json.loads(r["snapshot"]) if isinstance(r.get("snapshot"), str) and r["snapshot"] else (r.get("snapshot") or {})
        nid = f"s{r['id']}"
        failing = bool(r.get("last_error"))
        status = "off" if r.get("status") == "disabled" else "bad" if failing else "ok" if snap else "off"
        node = Node(nid, "switch", switch_label(r), r.get("location") or (snap.get("system") or {}).get("location") or "",
                    switch_id=r["id"], status=status, ip=r.get("host"))
        nodes[nid] = node
        poe = set((snap.get("poe") or {}).get("ports") or [])
        pvid = {int(k): v for k, v in (snap.get("pvid") or {}).items()}
        ports: dict[int, Port] = {}
        for i in snap.get("interfaces") or []:
            physical = i.get("type") in PHYSICAL_TYPES
            ports[i["index"]] = Port(
                i["index"], i["name"], port_short(i["name"]), i.get("descr"), i.get("alias"), i.get("type"),
                i.get("speed_mbps") if i.get("oper_up") else None, bool(i.get("oper_up")), bool(i.get("admin_up")),
                i.get("duplex"), physical, physical and bool(SFP_RE.search(i["name"] or "") or
                                                              SFP_RE.search(i.get("descr") or "")),
                poe=i["index"] in poe, vlan=pvid.get(i["index"]), errors_24h=errs.get((r["id"], i["index"]), 0))
        for e in snap.get("fdb") or []:
            p = ports.get(e["if_index"])
            if p is not None and e["mac"] not in p.macs:
                p.macs.append(e["mac"])
        for a in snap.get("arp") or []:
            d = devices.setdefault(a["mac"], {"mac": a["mac"], "ip": a["ip"], "label": a["ip"]})
            d.setdefault("ip", a["ip"])
        switches[r["id"]] = {"row": r, "ports": ports, "node": nid, "snapshot": snap}
        for m in {snap.get("base_mac"), _mac(snap.get("lldp_chassis"))} | {i.get("mac") for i in snap.get("interfaces") or []}:
            if m:
                ident_mac.setdefault(m, nid)
        for ip in set(snap.get("ips") or []) | ({r["host"]} if _ip(r.get("host")) else set()):
            ident_ip.setdefault(ip, nid)
        for n in (r.get("sys_name"), r.get("name"), (snap.get("system") or {}).get("name")):
            if _norm(n):
                ident_name.setdefault(_norm(n), nid)

    def resolve_port(sid: int, text: str | None) -> int | None:
        if not text:
            return None
        t = text.strip().lower()
        for p in switches[sid]["ports"].values():
            if t in {(p.name or "").lower(), (p.descr or "").lower(), (p.alias or "").lower()}:
                return p.index
        mac = _mac(text)
        if mac:
            for i in switches[sid]["snapshot"].get("interfaces") or []:
                if i.get("mac") == mac:
                    return i["index"]
        return None

    linked: dict[frozenset, Link] = {}

    def add_link(a: str, ap: int | None, b: str, bp: int | None, bp_text: str | None, speed, via: str) -> None:
        key = frozenset({(a, ap), (b, bp)}) if bp is not None else frozenset({(a, ap), (b, bp_text)})
        pair = frozenset({a, b})
        for k, existing in linked.items():
            if frozenset({existing.a, existing.b}) == pair and ((existing.a == a and existing.a_port == ap) or
                                                                 (existing.b == a and existing.b_port == ap)):
                if existing.b_port is None and existing.b == b and bp is not None:
                    existing.b_port = bp
                return
        linked[key] = Link(a, ap, b, bp, bp_text, speed, via)

    # 2. Nachbarn aus LLDP/CDP
    for sid, s in switches.items():
        me = s["node"]
        for kind in ("lldp", "cdp"):
            for e in s["snapshot"].get(kind) or []:
                ap = e.get("if_index")
                port = s["ports"].get(ap) if ap else None
                name = e.get("sys_name") or e.get("device_id")
                target = (ident_mac.get(_mac(e.get("chassis_id")) or "") or ident_ip.get(e.get("mgmt_ip") or "")
                          or ident_name.get(_norm(name)))
                if port is not None:
                    port.neighbor = {"name": name or e.get("chassis_id"), "port": e.get("port_descr") or e.get("port_id"),
                                     "ip": e.get("mgmt_ip"), "platform": e.get("sys_descr") or e.get("platform"),
                                     "via": kind.upper(), "phone": e.get("phone"), "ap": e.get("ap"),
                                     "bridge": e.get("bridge"), "router": e.get("router")}
                if target == me:
                    continue
                if target:
                    tsid = nodes[target].switch_id
                    bp = resolve_port(tsid, e.get("port_id")) or resolve_port(tsid, e.get("port_descr"))
                    add_link(me, ap, target, bp, e.get("port_descr") or e.get("port_id"),
                             port.speed if port else None, kind)
                elif e.get("bridge") or e.get("router") or e.get("ap"):
                    key = _mac(e.get("chassis_id")) or e.get("mgmt_ip") or _norm(name) or f"{me}:{ap}"
                    nid = f"n:{key}"
                    if nid not in nodes:
                        kind_ = "ap" if e.get("ap") and not e.get("bridge") else "gateway" if e.get("router") and not \
                            e.get("bridge") else "neighbor"
                        nodes[nid] = Node(nid, kind_, name or e.get("mgmt_ip") or "Nachbar",
                                          (e.get("sys_descr") or e.get("platform") or "")[:60], ip=e.get("mgmt_ip"),
                                          status="ok" if kind_ != "neighbor" else "warn")
                        if _mac(e.get("chassis_id")):
                            ident_mac[_mac(e.get("chassis_id"))] = nid
                    add_link(me, ap, nid, None, e.get("port_descr") or e.get("port_id"),
                             port.speed if port else None, kind)

    # 3. Verbindungen aus den MAC-Tabellen (wo LLDP fehlt)
    sees: dict[tuple[int, int], set[int]] = {}
    for sid, s in switches.items():
        for p in s["ports"].values():
            seen = {nodes[ident_mac[m]].switch_id for m in p.macs if m in ident_mac
                    and nodes[ident_mac[m]].switch_id not in (None, sid)}
            if seen:
                sees[(sid, p.index)] = seen
                p.sees_switches = True
    lldp_pairs = {frozenset({lk.a, lk.b}) for lk in linked.values()}
    for (a, ap), sa in sees.items():
        for b in sa:
            if a > b or frozenset({f"s{a}", f"s{b}"}) in lldp_pairs:
                continue
            for (b2, bq), sb in sees.items():
                if b2 == b and a in sb and not (sa - {b}) & (sb - {a}):
                    pa, pb = switches[a]["ports"][ap], switches[b]["ports"][bq]
                    add_link(f"s{a}", ap, f"s{b}", bq, pb.name, pa.speed or pb.speed, "mac")
                    break
    links = list(linked.values())
    link_ports: set[tuple[str, int | None]] = set()
    for lk in links:
        link_ports.add((lk.a, lk.a_port))
        link_ports.add((lk.b, lk.b_port))
        for nid, pidx in ((lk.a, lk.a_port), (lk.b, lk.b_port)):
            sid = nodes[nid].switch_id
            if sid is not None and pidx in switches[sid]["ports"]:
                switches[sid]["ports"][pidx].link = lk

    # 4. Geräte an Zugangs-Ports; viele Geräte ohne Nachbarn → nicht verwalteter Switch vermutet
    locations: dict[str, tuple[int, int]] = {}
    for sid, s in switches.items():
        for p in s["ports"].values():
            if p.link or p.sees_switches:
                continue
            own = [m for m in p.macs if m not in ident_mac]
            for m in own:
                locations.setdefault(m, (sid, p.index))
            p.devices = [devices.get(m) or {"mac": m, "label": m} for m in own]
            nb = p.neighbor or {}
            if nb.get("ap") or (len(own) >= UNMANAGED_MIN_MACS and not nb.get("phone")):
                is_ap = bool(nb.get("ap"))
                nid = f"u{sid}:{p.index}"
                nodes[nid] = Node(nid, "ap" if is_ap else "unmanaged",
                                  nb.get("name") or ("Access Point" if is_ap else "Nicht verwalteter Switch?"),
                                  count_text(len(own)) if not is_ap else f"{max(len(own) - 1, 0)} WLAN-Geräte",
                                  status="ok" if is_ap else "warn", devices=p.devices)
                lk = Link(s["node"], p.index, nid, None, nb.get("port"), p.speed, "vermutet" if not is_ap else "lldp")
                links.append(lk)
                p.link = lk

    # 5. Gateway und Wurzel
    gw_ip = next((sw["snapshot"].get("gateway") for sw in switches.values() if sw["snapshot"].get("gateway")), None)
    gw_mac = next((m for m, d in devices.items() if gw_ip and d.get("ip") == gw_ip), None)
    root = None
    if gw_mac and gw_mac in locations:
        sid, pidx = locations[gw_mac]
        gw = devices[gw_mac]
        gid = "gw"
        nodes[gid] = Node(gid, "gateway", gw.get("label") or gw.get("hostname") or f"Gateway {gw_ip}", gw_ip or "",
                          ip=gw_ip)
        lk = Link(f"s{sid}", pidx, gid, None, None, switches[sid]["ports"][pidx].speed, "gateway")
        links.append(lk)
        port = switches[sid]["ports"][pidx]
        port.link = lk
        port.devices = [d for d in port.devices if d.get("mac") != gw_mac]
        root = gid
    else:
        routers = [n for n in nodes.values() if n.kind == "gateway"]
        if routers:
            root = routers[0].id
    adj: dict[str, list[tuple[str, Link]]] = {}
    for lk in links:
        adj.setdefault(lk.a, []).append((lk.b, lk))
        adj.setdefault(lk.b, []).append((lk.a, lk))
    if root is None and switches:
        def switch_links(n: str) -> int:
            return sum(1 for o, _lk in adj.get(n, []) if nodes[o].kind in ("switch", "neighbor"))

        root = max((s["node"] for s in switches.values()), key=lambda n: (switch_links(n), -nodes[n].switch_id))
    roots: list[str] = []
    seen_nodes: set[str] = set()
    order = [root] if root else []
    order += sorted((n for n in nodes if nodes[n].kind == "switch"), key=lambda n: (-len(adj.get(n, [])), n))
    order += [n for n in nodes if nodes[n].kind not in ("switch",)]
    for start in order:
        if start in seen_nodes:
            continue
        roots.append(start)
        seen_nodes.add(start)
        queue = [start]
        while queue:
            cur = queue.pop(0)
            for nxt, lk in sorted(adj.get(cur, []), key=lambda x: (nodes[x[0]].kind != "switch", nodes[x[0]].label)):
                if nxt in seen_nodes:
                    continue
                seen_nodes.add(nxt)
                nodes[nxt].parent, nodes[nxt].link = cur, lk
                nodes[cur].children.append(nxt)
                queue.append(nxt)
    if "gw" in nodes and nodes["gw"].parent is None:
        nodes["internet"] = Node("internet", "internet", "Internet", "")
        nodes["gw"].parent = "internet"
        nodes["internet"].children.append("gw")
        nodes["gw"].link = Link("internet", None, "gw", None, None, None, "gateway")
        roots = ["internet" if r == "gw" else r for r in roots]

    # Rollen der Ports: Uplink zeigt zum Elternknoten
    for sid, s in switches.items():
        node = nodes[s["node"]]
        for p in s["ports"].values():
            if not p.up:
                p.role = "down" if p.admin_up else "free"
            elif p.link:
                up_link = node.link is p.link
                p.role = "uplink" if up_link else "downlink"
            elif p.sees_switches:
                p.role = "uplink" if node.parent is None else "downlink"
            elif p.devices or p.neighbor:
                p.role = "access"
            else:
                p.role = "free"

    topo = Topology(nodes, roots, switches, links, locations, devices, gw_ip)
    topo.findings = findings(topo)
    return topo


def link_port_of(topo: Topology, lk: Link, node_id: str) -> str | None:
    """Port-Kurzname einer Verbindung auf der Seite eines Knotens."""
    nid_port = lk.a_port if lk.a == node_id else lk.b_port if lk.b == node_id else None
    sid = topo.nodes[node_id].switch_id
    if sid is not None and nid_port in topo.switches.get(sid, {}).get("ports", {}):
        return topo.switches[sid]["ports"][nid_port].short
    if lk.b == node_id and lk.b_port_text:
        return port_short(lk.b_port_text)
    return None


def link_label(topo: Topology, node: Node) -> str:
    """Beschriftung der Linie zum Elternknoten: „P1 ⇄ P25 · 10G“."""
    lk = node.link
    if not lk:
        return ""
    up = link_port_of(topo, lk, node.parent) if node.parent else None
    down = link_port_of(topo, lk, node.id)
    def tag(p: str | None) -> str | None:
        return (f"P{p}" if p[0].isdigit() else p) if p else None

    ports = " ⇄ ".join(x for x in (tag(up), tag(down)) if x)
    return " · ".join(x for x in (ports, speed_short(lk.speed)) if x)


# -- Befunde ----------------------------------------------------------------------------
def findings(topo: Topology) -> list[dict]:
    out: list[dict] = []

    def add(kind, severity, key, title, detail, node=None, switch_id=None, if_index=None, host=None):
        out.append({"kind": kind, "severity": severity, "fkey": key, "title": title, "detail": detail, "node": node,
                    "switch_id": switch_id, "if_index": if_index, "host": host})

    for sid, s in topo.switches.items():
        r, node = s["row"], topo.nodes[s["node"]]
        if r.get("last_error") and r.get("status") == "active":
            add("unreachable", "critical", f"unreachable:{sid}", f"{node.label} antwortet nicht auf SNMP",
                f"{r['last_error'].rstrip('.')}. Letzte erfolgreiche Abfrage: {_ago(r.get('last_ok'))}.", node.id, sid)
        snap = s["snapshot"]
        if snap and not snap.get("fdb") and not snap.get("lldp") and not snap.get("cdp"):
            add("no_fdb", "info", f"no_fdb:{sid}", f"{node.label} liefert keine MAC-Tabelle und keine Nachbarn",
                "Ohne MAC-Tabelle (BRIDGE-MIB) und LLDP lässt sich nicht erkennen, was an den Ports hängt. "
                "Bei Cisco-Switches mit mehreren VLANs liefert SNMPv2c die Tabelle je VLAN nur mit „Community@VLAN“.",
                node.id, sid)
        for p in s["ports"].values():
            who = _port_who(topo, p)
            if p.errors_24h >= ERRORS_WARN:
                add("port_errors", "critical" if p.errors_24h >= ERRORS_CRIT else "warning",
                    f"errors:{sid}:{p.index}", f"Eingangsfehler an {node.label} Port {p.short}",
                    f"{p.errors_24h:,} fehlerhafte Pakete".replace(",", ".") + f" in 24 Stunden{who}. Meist Kabel, "
                    "Dose oder Stecker – Patchkabel tauschen, Dose prüfen.", node.id, sid, p.index)
            if p.up and p.duplex == "half":
                add("half_duplex", "warning", f"duplex:{sid}:{p.index}", f"Halbduplex an {node.label} Port {p.short}",
                    f"Der Port arbeitet nur im Halbduplex{who}. Meist stehen Switch und Gerät auf unterschiedlichen "
                    "Einstellungen (fest eingestellt gegen automatisch).", node.id, sid, p.index)
    for nid, node in topo.nodes.items():
        lk = node.link
        if lk and node.kind in ("switch", "neighbor", "ap") and lk.speed and lk.speed < 1000 and lk.via != "vermutet":
            parent = topo.nodes.get(node.parent)
            add("slow_link", "warning", f"slow:{lk.a}:{lk.a_port}", f"Verbindung zu {node.label} nur {speed_text(lk.speed)}",
                f"{parent.label if parent else '?'} ⇄ {node.label} ({link_label(topo, node)}). Beide Seiten könnten "
                "meist 1 Gbit/s – häufig ein Kabel mit nur vier Adern, ein beschädigter Stecker oder ein alter Port.",
                nid, node.switch_id or (parent.switch_id if parent else None))
        if node.kind == "unmanaged":
            parent = topo.nodes.get(node.parent)
            p = topo.switches[parent.switch_id]["ports"].get(lk.a_port) if parent and parent.switch_id else None
            add("unmanaged", "info", f"unmanaged:{lk.a}:{lk.a_port}", f"Nicht verwalteter Switch an "
                f"{parent.label if parent else '?'} Port {p.short if p else '?'}",
                f"{len(node.devices)} Geräte hängen an einem Port. Wahrscheinlich ein Tisch-Switch oder ein "
                "anderes Gerät ohne SNMP.", nid, parent.switch_id if parent else None, lk.a_port)
        if node.kind == "neighbor":
            add("no_credentials", "info", f"nocred:{node.id}", f"{node.label} ohne Zugangsdaten",
                f"Per LLDP/CDP gefunden{f' ({node.ip})' if node.ip else ''}, aber nicht abgefragt. "
                "Mit Zugangsdaten erscheinen auch seine Ports und Geräte.", nid, host=node.ip)
    out.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["title"]))
    return out


def _port_who(topo: Topology, p: Port) -> str:
    if p.devices:
        names = ", ".join(d.get("label") or d["mac"] for d in p.devices[:2])
        return f" (Gerät: {names}{' …' if len(p.devices) > 2 else ''})"
    if p.neighbor:
        return f" (Nachbar: {p.neighbor.get('name')})"
    return ""


def _ago(ts: int | None) -> str:
    if not ts:
        return "noch nie"
    from datetime import datetime

    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")


def refresh_findings(site_id: int, ts: int) -> list[dict]:
    """Befunde neu berechnen und speichern (erstes Auftreten bleibt erhalten)."""
    topo = build(site_id, ts)
    current = list(topo.findings)
    # Schleifenverdacht aus dem Verlauf: dieselbe MAC wechselt in 24 h mehrfach den Port
    for r in q("SELECT e.switch_id, e.mac, COUNT(*) AS n FROM net_topo_events e WHERE e.site_id = ? "
               "AND e.kind = 'mac_moved' AND e.ts >= ? GROUP BY e.switch_id, e.mac", (site_id, ts - 86400)):
        if int(r["n"]) >= FLAP_MOVES and r["switch_id"] in topo.switches:
            node = topo.nodes[topo.switches[r["switch_id"]]["node"]]
            dev = topo.devices.get(r["mac"], {})
            current.append({"kind": "mac_flap", "severity": "warning", "fkey": f"flap:{r['switch_id']}:{r['mac']}",
                            "title": f"Möglicher Kabelkreis an {node.label}",
                            "detail": f"{dev.get('label') or r['mac']} wechselte in 24 Stunden {r['n']}-mal den Port. "
                                      "Prüfen, ob zwei Kabel dieselben Switches verbinden oder ein Gerät doppelt "
                                      "angeschlossen ist.", "node": node.id, "switch_id": r["switch_id"],
                            "if_index": None, "host": None})
    keys = set()
    for f in current:
        keys.add(f["fkey"])
        row = q1("SELECT id FROM net_topo_findings WHERE site_id = ? AND fkey = ?", (site_id, f["fkey"]))
        if row:
            ex("UPDATE net_topo_findings SET kind = ?, severity = ?, switch_id = ?, if_index = ?, title = ?, detail = ?, "
               "last_seen = ?, active = TRUE WHERE id = ?",
               (f["kind"], f["severity"], f["switch_id"], f["if_index"], f["title"], f["detail"], ts, row["id"]))
        else:
            ins("INSERT INTO net_topo_findings (site_id, fkey, kind, severity, switch_id, if_index, title, detail, "
                "first_seen, last_seen, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE)",
                (site_id, f["fkey"], f["kind"], f["severity"], f["switch_id"], f["if_index"], f["title"], f["detail"],
                 ts, ts))
    for row in q("SELECT id, fkey FROM net_topo_findings WHERE site_id = ? AND active = TRUE", (site_id,)):
        if row["fkey"] not in keys:
            ex("UPDATE net_topo_findings SET active = FALSE, ack_by = NULL, ack_at = NULL WHERE id = ?", (row["id"],))
    return current


def stored_findings(site_id: int, topo: Topology) -> list[dict]:
    """Aktive Befunde mit „seit“ und Bestätigung, verknüpft mit dem Knoten im Baum; nummeriert."""
    rows = {r["fkey"]: r for r in q("SELECT * FROM net_topo_findings WHERE site_id = ? AND active = TRUE", (site_id,))}
    out = []
    live = list(topo.findings)
    live_keys = {f["fkey"] for f in live}
    for key, r in rows.items():          # Schleifenverdacht stammt aus dem Verlauf und fehlt in topo.findings
        if key not in live_keys and r["kind"] == "mac_flap":
            live.append({"kind": r["kind"], "severity": r["severity"], "fkey": key, "title": r["title"],
                         "detail": r["detail"], "switch_id": r["switch_id"], "if_index": r["if_index"], "host": None,
                         "node": topo.switches[r["switch_id"]]["node"] if r["switch_id"] in topo.switches else None})
    live.sort(key=lambda f: (bool(rows.get(f["fkey"], {}).get("ack_at")), SEVERITY_ORDER[f["severity"]], f["title"]))
    for n, f in enumerate(live, 1):
        r = rows.get(f["fkey"]) or {}
        item = {**f, "no": n, "id": r.get("id"), "first_seen": r.get("first_seen"), "ack_by": r.get("ack_by"),
                "ack_at": r.get("ack_at"), "kind_label": KIND_LABELS.get(f["kind"], f["kind"])}
        out.append(item)
        if f.get("node") in topo.nodes and not item["ack_at"]:
            topo.nodes[f["node"]].findings.append(n)
    return out


# -- Pfad eines Geräts ----------------------------------------------------------------
def find_device(topo: Topology, query: str) -> list[dict]:
    """Geräte, deren Name, IP oder MAC zur Suche passt und deren Port bekannt ist."""
    t = (query or "").strip().lower()
    if not t:
        return []
    mac = _mac(query)
    hits = []
    for m, (sid, pidx) in topo.locations.items():
        d = topo.devices.get(m) or {"mac": m, "label": m}
        texts = [(d.get(k) or "").lower() for k in ("label", "hostname", "ip")]
        if (mac and m == mac) or any(t == x for x in texts) or any(t in x for x in texts if x):
            hits.append({**d, "mac": m, "switch_id": sid, "if_index": pidx})
    hits.sort(key=lambda h: (0 if t in ((h.get("label") or "").lower(), (h.get("ip") or "")) else 1,
                             h.get("label") or ""))
    return hits[:20]


def path_for(topo: Topology, mac: str) -> dict | None:
    """Weg vom Gerät bis zur Wurzel: Liste von Abschnitten (Gerät, Switches, Gateway, Internet)."""
    loc = topo.locations.get(mac)
    if not loc:
        return None
    sid, pidx = loc
    dev = topo.devices.get(mac) or {"mac": mac, "label": mac}
    sw = topo.switches[sid]
    port = sw["ports"][pidx]
    hops = [{"kind": "device", "label": dev.get("label") or mac, "sub": dev.get("ip") or mac, "device": dev}]
    links = [{"speed": port.speed, "text": f"Port {port.short}", "errors": port.errors_24h, "duplex": port.duplex,
              "state": port.state}]
    cur = topo.nodes[sw["node"]]
    in_port = port
    while cur is not None:
        out_port = None
        if cur.switch_id is not None and cur.link:
            out_idx = cur.link.a_port if cur.link.a == cur.id else cur.link.b_port
            out_port = topo.switches[cur.switch_id]["ports"].get(out_idx)
        hops.append({"kind": cur.kind, "label": cur.label, "sub": cur.ip or cur.sub, "node": cur.id,
                     "switch_id": cur.switch_id, "in": in_port.short if in_port else None,
                     "out": out_port.short if out_port else None,
                     "problem": in_port.errors_24h >= ERRORS_WARN if in_port else False})
        if not cur.parent:
            break
        parent = topo.nodes[cur.parent]
        lk = cur.link
        p_idx = lk.a_port if lk.a == parent.id else lk.b_port
        parent_port = topo.switches[parent.switch_id]["ports"].get(p_idx) if parent.switch_id is not None else None
        links.append({"speed": lk.speed, "text": link_label(topo, cur) or
                      ("Internet-Anschluss" if parent.kind == "internet" else "Verbindung"),
                      "errors": max(parent_port.errors_24h if parent_port else 0, out_port.errors_24h if out_port else 0),
                      "duplex": None, "state": speed_class(lk.speed)})
        in_port = parent_port
        cur = parent
    speeds = [lk["speed"] for lk in links if lk["speed"]]
    return {"device": dev, "hops": hops, "links": links, "bottleneck": min(speeds) if speeds else None,
            "problems": sum(1 for lk in links if lk["errors"] >= ERRORS_WARN) +
            sum(1 for lk in links if lk["speed"] and lk["speed"] < 1000 and lk is not links[0])}


# -- Darstellung: Baum als SVG ------------------------------------------------------------
NODE_W, NODE_H, GAP_X, GAP_Y, CHIP_H = 180, 56, 20, 92, 28


def layout(topo: Topology, show_devices: bool = True) -> dict:
    """Koordinaten für den Baum (SVG): Knoten, Linien, Beschriftungen, Geräte-Chips."""
    widths: dict[str, int] = {}

    def kids(nid: str) -> list[str]:
        return topo.nodes[nid].children

    def chip(nid: str) -> str | None:
        node = topo.nodes[nid]
        if not show_devices:
            return None
        if node.kind == "switch":
            n = sum(len(p.devices) for p in topo.switches[node.switch_id]["ports"].values()
                    if not (p.link and p.link.via in ("vermutet", "lldp") and p.link.b.startswith("u")))
            return count_text(n) if n else None
        if node.kind in ("unmanaged", "ap") and node.devices:
            return count_text(len(node.devices))
        return None

    def width(nid: str) -> int:
        c = kids(nid)
        w = max(NODE_W, sum(width(x) for x in c) + GAP_X * (len(c) - 1)) if c else NODE_W
        widths[nid] = w
        return w

    boxes, lines, labels, chips = [], [], [], []
    max_y = 0

    def place(nid: str, left: int, depth: int) -> None:
        nonlocal max_y
        node = topo.nodes[nid]
        w = widths[nid]
        cx = left + w // 2
        y = 16 + depth * (NODE_H + GAP_Y)
        boxes.append({"node": node, "x": cx - NODE_W // 2, "y": y, "cx": cx})
        max_y = max(max_y, y + NODE_H)
        c = chip(nid)
        if c and not kids(nid):
            chips.append({"x": cx - 60, "y": y + NODE_H + 22, "w": 120, "text": c, "lx": cx,
                          "ly1": y + NODE_H, "ly2": y + NODE_H + 22})
            max_y = max(max_y, y + NODE_H + 22 + CHIP_H)
        elif c:
            boxes[-1]["chip"] = c
        cl = left
        for k in kids(nid):
            kw = widths[k]
            kcx = cl + kw // 2
            ky = 16 + (depth + 1) * (NODE_H + GAP_Y)
            mid = y + NODE_H + GAP_Y // 2 - 14
            lk = topo.nodes[k].link
            lines.append({"d": f"M{cx} {y + NODE_H} V{mid} H{kcx} V{ky}", "cls": speed_class(lk.speed if lk else None),
                          "dashed": bool(lk and lk.via in ("vermutet",)), "via": lk.via if lk else ""})
            text = link_label(topo, topo.nodes[k])
            if text:
                tw = int(len(text) * 6.4) + 12
                labels.append({"x": kcx + 6, "y": ky - 30, "w": tw, "text": text,
                               "slow": bool(lk and lk.speed and lk.speed < 1000)})
            place(k, cl, depth + 1)
            cl += kw + GAP_X

    # Hauptbaum oben; Switches ohne Verbindung (oder eigene Teilbäume) in einer Zeile darunter
    total_w = 0
    if topo.roots:
        width(topo.roots[0])
        place(topo.roots[0], 0, 0)
        total_w = widths[topo.roots[0]]
    others = topo.roots[1:]
    if others:
        depth = (max_y - 16) // (NODE_H + GAP_Y) + 1
        x0 = 0
        for r in others:
            width(r)
            place(r, x0, depth)
            x0 += widths[r] + GAP_X
        total_w = max(total_w, x0 - GAP_X)
    return {"boxes": boxes, "lines": lines, "labels": labels, "chips": chips, "node_w": NODE_W,
            "width": max(total_w, NODE_W) + 120, "height": max_y + 24}


def faceplate(ports: dict[int, Port]) -> list[dict]:
    """Ports für die Frontansicht: Kupfer in zwei Reihen (ungerade oben), SFP/Uplink-Ports rechts; je 48 ein Block."""
    phys = [p for p in sorted(ports.values(), key=lambda p: p.index) if p.physical]
    copper = [p for p in phys if not p.sfp]
    sfp = [p for p in phys if p.sfp]
    blocks = []
    for i in range(0, max(len(copper), 1), 48):
        chunk = copper[i:i + 48]
        blocks.append({"top": chunk[0::2], "bottom": chunk[1::2], "sfp": sfp if i == 0 else []})
    if not copper and sfp:
        blocks = [{"top": [], "bottom": [], "sfp": sfp}]
    return blocks
