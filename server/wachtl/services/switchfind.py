"""Switches automatisch finden (docs/TOPOLOGIE.md#switches-automatisch-finden).

Quellen – alle ohne Anmeldung am Gerät:

- Netzwerkscan der Probes: MAC-Adresse (Hersteller) und Weboberfläche (Titel, Server-Kennung → Modell).
- LLDP/CDP der schon eingetragenen Switches: Nachbarn, die sich als Bridge melden.
- Rundruf der Server-Probe: TP-Link Easy Smart und Netgear ProSAFE Plus melden Modell, Name, MAC und IP.

Ergebnis je Standort: Liste gefundener Switches mit Hersteller, Modell, Sicherheit (0–100) und Zugangsart
(SNMP, Weboberfläche oder keine). Wachtl probiert keine Zugangsdaten aus – fehlen sie, fragt das Web-UI
danach („Zugangsdaten eingeben“). Switches, die sich gar nicht abfragen lassen, erscheinen trotzdem im Baum.
"""
from __future__ import annotations

import json
import re

from .. import repo, switch_oui
from ..db import ex, ins, q, q1

SHOW_FROM = 50          # ab dieser Sicherheit erscheint ein Fund in der Liste
WEB_PORTS = (80, 443, 8080, 8443)
# Modellbezeichnungen gängiger Switches (Titel der Weboberfläche, LLDP-Beschreibung, Rundruf)
MODEL_RE = re.compile(
    r"\b(TL-S[GX]\d{3,4}[A-Z]*|SG\d{4}[A-Z]*(?:-\d+[A-Z]*)?|SX\d{4}[A-Z]*|"               # TP-Link
    r"D[GEX]S-\d{3,4}[A-Z0-9/-]*|"                                                       # D-Link
    r"X?GS\d{3,4}[A-Z0-9]*(?:-\d+[A-Z0-9]*)?|XS\d{3,4}[A-Z0-9-]*|M4\d{3}[A-Z0-9-]*|"     # Netgear, Zyxel
    r"JL\d{3}A|J\d{4}[AB]|\d{4}[A-Z]? ?\d{1,2}G\w*|"                                      # Aruba / HPE (1930 24G …)
    r"USW-[A-Za-z0-9-]+|US-\d{1,2}(?:-\d+W?)?|"                                          # Ubiquiti UniFi
    r"CRS\d{3}[A-Za-z0-9+-]*|CSS\d{3}[A-Za-z0-9+-]*|"                                    # MikroTik
    r"CBS\d{3}[A-Z0-9-]*|SG\d{3}[A-Z]?-\d{2}[A-Z]*|C9\d{3}[A-Z0-9-]*|WS-C\d{4}[A-Z0-9-]*|"  # Cisco
    r"GS-\d{4}[A-Z0-9+]*)(?:v\d+)?\b")                                                 # LANCOM; „v3“ = Revision
SWITCH_WORDS = re.compile(r"switch|procurve|instant on|easy smart|prosafe|smart managed|jetstream|omada|catalyst|"
                          r"web smart|smart switch", re.I)
NOT_SWITCH = re.compile(r"\b(router|archer|deco|camera|kamera|tapo|nvr|printer|drucker|fritz|access point|eap\d|"
                        r"extender|repeater)\b", re.I)
EASYSMART_RE = re.compile(r"\bTL-SG1\d{2,3}[DMP]?P?E\b|\bTL-SG10\d{1,2}[A-Z]*E\b", re.I)
NETGEAR_PLUS_RE = re.compile(r"\bGS\d{3}(?:E|EP|PE|EPP)(?:v\d+)?\b|\bJGS\d{3}[A-Z]*E\b", re.I)
ACCESS_LABELS = {"snmp": "SNMP", "easysmart": "Weboberfläche (TP-Link Easy Smart)", "none": "keine Abfrage möglich"}
SOURCE_LABELS = {"oui": "Hersteller der MAC-Adresse", "web": "Weboberfläche", "lldp": "LLDP", "cdp": "CDP",
                 "easysmart": "Rundruf TP-Link", "nsdp": "Rundruf Netgear", "port": "viele Geräte an einem Port"}


def access_for(vendor: str | None, model: str | None, proto: str | None = None) -> str:
    """Wie sich der Switch abfragen lässt: TP-Link Easy Smart über die Weboberfläche, Netgear Plus gar nicht."""
    if proto == "easysmart" or (model and EASYSMART_RE.search(model)):
        return "easysmart"
    if proto == "nsdp" or (vendor == "Netgear" and model and NETGEAR_PLUS_RE.search(model)):
        return "none"
    return "snmp"


def _model(*texts: str | None) -> str | None:
    for t in texts:
        if t and (m := MODEL_RE.search(t)):
            return m.group(1)[:40]
    return None


def classify(mac: str | None, services: list[dict], hub_port: bool = False) -> dict | None:
    """Gerät aus dem Netzwerkscan bewerten. hub_port = hängt an einem Port mit weiteren Geräten.

    Gibt None zurück, wenn nichts für einen Switch spricht."""
    vendor = switch_oui.vendor(mac)
    web = [s for s in services if s.get("port") in WEB_PORTS or s.get("service") in ("http", "https")]
    texts = [x for s in web for x in (s.get("http_title"), s.get("http_server"), s.get("tls_subject")) if x]
    blob = " ".join(texts)
    model = _model(*texts)
    if NOT_SWITCH.search(blob) and not SWITCH_WORDS.search(blob):
        return None
    score, sources = 0, []
    if vendor:
        score += 30
        sources.append("oui")
    if model:
        score += 50
        sources.append("web")
    elif SWITCH_WORDS.search(blob):
        score += 40
        sources.append("web")
    elif vendor and web:
        score += 10                       # Netzwerkhersteller mit Weboberfläche: Router, AP oder Switch
    if hub_port and vendor:
        score += 25
        sources.append("port")
    if not sources or score < 20:
        return None
    return {"vendor": vendor, "model": model, "access": access_for(vendor, model), "sources": sources,
            "confidence": min(score, 95)}


# -- Speichern ---------------------------------------------------------------------------
def _upsert(site_id: int, ts: int, mac: str | None, ip: str | None, found: dict) -> None:
    key = f"mac:{mac}" if mac else f"ip:{ip}"
    row = q1("SELECT * FROM net_switch_candidates WHERE site_id = ? AND cand_key = ?", (site_id, key))
    if row is None and mac and ip:          # zuerst nur per IP bekannt (LLDP ohne MAC), jetzt mit MAC
        row = q1("SELECT * FROM net_switch_candidates WHERE site_id = ? AND cand_key = ?", (site_id, f"ip:{ip}"))
        if row:
            ex("UPDATE net_switch_candidates SET cand_key = ?, mac = ? WHERE id = ?", (key, mac, row["id"]))
    if row is None:
        ins("INSERT INTO net_switch_candidates (site_id, cand_key, mac, ip, vendor, model, name, firmware, access, "
            "sources, confidence, state, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)",
            (site_id, key, mac, ip, found.get("vendor"), found.get("model"), found.get("name"), found.get("firmware"),
             found["access"], json.dumps(found["sources"]), found["confidence"], ts, ts))
        return
    sources = sorted(set(json.loads(row["sources"] or "[]")) | set(found["sources"]))
    # Rundruf und LLDP wissen es genauer als Hersteller und Titel: deren Angaben gewinnen
    sure = found["confidence"] >= (row["confidence"] or 0)
    access = found["access"] if sure or row["access"] == "snmp" and found["access"] != "snmp" else row["access"]
    ex("UPDATE net_switch_candidates SET ip = COALESCE(?, ip), vendor = COALESCE(?, vendor), model = ?, name = ?, "
       "firmware = COALESCE(?, firmware), access = ?, sources = ?, confidence = ?, last_seen = ? WHERE id = ?",
       (ip, found.get("vendor"), (found.get("model") if sure else None) or row["model"] or found.get("model"),
        (found.get("name") if sure else None) or row["name"] or found.get("name"), found.get("firmware"), access,
        json.dumps(sources), max(found["confidence"], row["confidence"] or 0), ts, row["id"]))


def store_discovery(site_id: int, devices: list, ts: int) -> int:
    """Ergebnis des Rundrufs der Server-Probe übernehmen. Gibt die Zahl gültiger Geräte zurück."""
    from .topology import _ip, _mac, _text

    n = 0
    for d in devices[:512] if isinstance(devices, list) else []:
        if not isinstance(d, dict) or d.get("proto") not in ("easysmart", "nsdp"):
            continue
        mac = _mac(d.get("mac"))
        if not mac:
            continue
        model = _text(d.get("model"), 60) or _model(_text(d.get("hardware"), 80))
        vendor = "TP-Link" if d["proto"] == "easysmart" else "Netgear"
        _upsert(site_id, ts, mac, _ip(d.get("ip")), {
            "vendor": vendor, "model": model, "name": _text(d.get("name"), 80), "firmware": _text(d.get("firmware"), 80),
            "access": access_for(vendor, model, d["proto"]), "sources": [d["proto"]], "confidence": 95})
        n += 1
    return n


def refresh(site_id: int, ts: int | None = None) -> None:
    """Funde des Standorts aus Netzwerkscan und LLDP/CDP neu bewerten; eingetragene Switches abhaken."""
    from . import topology

    ts = ts or repo.now()
    topo = topology.build(site_id, ts, with_candidates=False)
    hub = {m for s in topo.switches.values() for p in s["ports"].values()
           if not p.link and not p.sees_switches and len(p.macs) >= 2 for m in p.macs}
    services: dict[int, list[dict]] = {}
    for s in q("SELECT s.* FROM net_services s JOIN net_devices d ON d.id = s.device_id WHERE d.site_id = ?", (site_id,)):
        services.setdefault(s["device_id"], []).append(s)
    for d in q("SELECT id, mac, ip, hostname FROM net_devices WHERE site_id = ? AND last_seen >= ?",
               (site_id, ts - 30 * 86400)):
        found = classify(d["mac"], services.get(d["id"], []), hub_port=d["mac"] in hub)
        if found and found["confidence"] >= SHOW_FROM - 20:
            _upsert(site_id, ts, d["mac"], d["ip"], {**found, "name": d["hostname"]})
    for n in topo.nodes.values():
        if n.kind == "neighbor" and (n.ip or n.mac):
            _upsert(site_id, ts, n.mac, n.ip, {"vendor": switch_oui.vendor(n.mac), "model": _model(n.sub, n.label),
                                               "name": n.label, "access": "snmp", "sources": [n.via or "lldp"],
                                               "confidence": 90})
    # schon eingetragen?
    rows = q("SELECT id, host, base_mac, snapshot FROM net_switches WHERE site_id = ?", (site_id,))
    by_ip = {r["host"]: r["id"] for r in rows}
    by_mac = {r["base_mac"]: r["id"] for r in rows if r["base_mac"]}
    for r in rows:
        snap = json.loads(r["snapshot"]) if r["snapshot"] else {}
        for ip in snap.get("ips") or []:
            by_ip.setdefault(ip, r["id"])
        for i in snap.get("interfaces") or []:
            if i.get("mac"):
                by_mac.setdefault(i["mac"], r["id"])
    for c in q("SELECT * FROM net_switch_candidates WHERE site_id = ?", (site_id,)):
        sid = by_mac.get(c["mac"]) or by_ip.get(c["ip"])
        if sid and (c["state"] != "added" or c["switch_id"] != sid):
            ex("UPDATE net_switch_candidates SET state = 'added', switch_id = ? WHERE id = ?", (sid, c["id"]))
        elif not sid and c["state"] == "added":
            ex("UPDATE net_switch_candidates SET state = 'new', switch_id = NULL WHERE id = ?", (c["id"],))


def candidates(site_id: int, states: tuple[str, ...] = ("new",)) -> list[dict]:
    """Gefundene Switches zum Anzeigen (ab SHOW_FROM), sicherste zuerst."""
    marks = ",".join("?" * len(states))
    out = []
    for c in q(f"SELECT * FROM net_switch_candidates WHERE site_id = ? AND state IN ({marks}) AND confidence >= ? "
               "ORDER BY confidence DESC, ip", (site_id, *states, SHOW_FROM)):
        c = dict(c)
        c["sources"] = json.loads(c["sources"] or "[]")
        c["label"] = label(c)
        c["sources_text"] = ", ".join(SOURCE_LABELS.get(s, s) for s in c["sources"])
        c["access_text"] = ACCESS_LABELS.get(c["access"], c["access"])
        c["sure"] = "sicher" if c["confidence"] >= 85 else "wahrscheinlich" if c["confidence"] >= 65 else "möglich"
        out.append(c)
    return out


def label(c: dict) -> str:
    """Anzeigename: eigener Name des Switches, sonst Hersteller und Modell."""
    vendor, model = c.get("vendor"), c.get("model")
    if c.get("name"):
        return c["name"]
    if model:
        return f"{vendor} {model}" if vendor and not model.lower().startswith(vendor.lower()[:4]) else model
    return f"{vendor}-Switch" if vendor else (c.get("ip") or "Switch")
