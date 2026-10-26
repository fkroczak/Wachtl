"""Daten eines Switches per SNMP abfragen (docs/TOPOLOGIE.md): System, Ports, MAC-Tabelle, Nachbarn, PoE, VLAN.

Nur Standard-MIBs, damit es mit Switches aller Hersteller funktioniert:
SNMPv2-MIB, IF-MIB, EtherLike-MIB, BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB, CISCO-CDP-MIB, POWER-ETHERNET-MIB, IP-MIB.
Fehlt eine Tabelle (Switch kennt sie nicht), bleibt sie leer – nur das System muss antworten.
Läuft in der Server-Probe (regelmäßig) und im Web-UI (Assistent „Verbindung testen“).
"""
from __future__ import annotations

import logging
import time

from . import snmp

log = logging.getLogger(__name__)

SYS = "1.3.6.1.2.1.1"
IF_ENTRY = "1.3.6.1.2.1.2.2.1"
IFX_ENTRY = "1.3.6.1.2.1.31.1.1.1"
DOT3_ENTRY = "1.3.6.1.2.1.10.7.2.1"
BRIDGE_ADDR = "1.3.6.1.2.1.17.1.1.0"
BRIDGE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"
FDB_PORT, FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.2", "1.3.6.1.2.1.17.4.3.1.3"
QFDB_PORT, QFDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.2", "1.3.6.1.2.1.17.7.1.2.2.1.3"
PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
LLDP_LOC = "1.0.8802.1.1.2.1.3"
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_MAN = "1.0.8802.1.1.2.1.4.2.1.3"
CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"
POE_MAIN = "1.3.6.1.2.1.105.1.3.1.1"
POE_PORT_STATUS = "1.3.6.1.2.1.105.1.1.1.6"
IP_ADDR_IF = "1.3.6.1.2.1.4.20.1.2"
ARP_MAC = "1.3.6.1.2.1.4.22.1.2"
DEFAULT_ROUTE = "1.3.6.1.2.1.4.21.1.7.0.0.0.0"

MAX_FDB = 20000
MAX_ARP = 5000
MAX_IF = 1024
# Port-Typen, die als Anschluss am Gerät zählen (Ethernet in seinen Varianten)
PHYSICAL_TYPES = {6, 7, 26, 62, 69, 117}


def _text(v, limit: int = 200) -> str | None:
    if v is None:
        return None
    if isinstance(v, bytes):
        v = v.decode("utf-8", errors="replace")
    text = "".join(ch for ch in str(v) if ch >= " " or ch == "\t").strip()
    return text[:limit] or None


def mac_str(raw) -> str | None:
    if isinstance(raw, (bytes, bytearray)) and len(raw) == 6 and any(raw) and raw != b"\xff" * 6:
        return ":".join(f"{b:02X}" for b in raw)
    if isinstance(raw, (bytes, bytearray)) and len(raw) == 17:            # manche Switches liefern Text
        text = raw.decode("ascii", errors="ignore").upper().replace("-", ":")
        return text if len(text.split(":")) == 6 else None
    return None


def _suffix(oid: str, base: str) -> tuple[int, ...]:
    return tuple(int(x) for x in oid[len(base) + 1:].split(".") if x)


def _table(sess: snmp.Session, base: str, max_rows: int = 20000) -> list[tuple[tuple[int, ...], object]]:
    """Unterbaum lesen; Index als Zahlen-Tupel. Fehler (Tabelle unbekannt) → leer."""
    try:
        return [(_suffix(oid, base), v) for oid, v in sess.walk(base, max_rows=max_rows)]
    except snmp.SnmpTimeout:
        raise
    except snmp.SnmpError as exc:
        log.debug("Tabelle %s nicht lesbar: %s", base, exc)
        return []


def _column(rows, col: int) -> dict[tuple[int, ...], object]:
    return {idx[1:]: v for idx, v in rows if idx and idx[0] == col}


def system(sess: snmp.Session) -> dict:
    """Kurzabfrage: Systemgruppe. Fehler (keine Antwort, falsche Zugangsdaten) gehen als SnmpError hinaus."""
    v = sess.get([f"{SYS}.1.0", f"{SYS}.2.0", f"{SYS}.3.0", f"{SYS}.4.0", f"{SYS}.5.0", f"{SYS}.6.0"])
    if all(x is None for x in v.values()):
        raise snmp.SnmpError("Der Switch antwortet, liefert aber keine Systemdaten (SNMPv2-MIB) – "
                             "Zugriffsrechte (View) der Community bzw. des Benutzers prüfen.")
    uptime = v.get(f"{SYS}.3.0")
    return {
        "descr": _text(v.get(f"{SYS}.1.0"), 400), "object_id": _text(v.get(f"{SYS}.2.0")),
        "uptime_s": int(uptime) // 100 if isinstance(uptime, int) else None,
        "contact": _text(v.get(f"{SYS}.4.0")), "name": _text(v.get(f"{SYS}.5.0")),
        "location": _text(v.get(f"{SYS}.6.0")),
    }


def quick(sess: snmp.Session) -> dict:
    """Schnelle Abfrage (jede Minute): Laufzeit und je Port Status, Geschwindigkeit, Fehler, letzte Änderung.

    Wenige Pakete je Switch. Kurze Aussetzer zwischen zwei Abfragen fallen über ifLastChange auf
    (Laufzeit des Switches bei der letzten Statusänderung des Ports)."""
    started = time.monotonic()
    up = sess.get([f"{SYS}.3.0"]).get(f"{SYS}.3.0")
    if not isinstance(up, int):
        raise snmp.SnmpError("Der Switch liefert keine Laufzeit (sysUpTime) – Zugriffsrechte prüfen.")
    cols = {}
    for col in (7, 8, 9, 14):
        cols[col] = {idx[0]: v for idx, v in _table(sess, f"{IF_ENTRY}.{col}", MAX_IF) if idx}
    hs = {idx[0]: v for idx, v in _table(sess, f"{IFX_ENTRY}.15", MAX_IF) if idx}
    interfaces = []
    for i in sorted(cols[8])[:MAX_IF]:
        interfaces.append({
            "index": i, "admin_up": cols[7].get(i) == 1, "oper_up": cols[8].get(i) == 1,
            "speed_mbps": hs.get(i) if isinstance(hs.get(i), int) and hs.get(i) else None,
            "in_errors": cols[14].get(i) if isinstance(cols[14].get(i), int) else None,
            "last_change_s": cols[9][i] // 100 if isinstance(cols[9].get(i), int) else None,
        })
    return {"quick": True, "system": {"uptime_s": up // 100}, "interfaces": interfaces,
            "duration_s": round(time.monotonic() - started, 2)}


def collect(sess: snmp.Session) -> dict:
    """Vollständige Abfrage eines Switches als JSON-fähiges Wörterbuch."""
    started = time.monotonic()
    out: dict = {"system": system(sess)}

    # Ports
    ift = _table(sess, IF_ENTRY, MAX_IF * 22)
    ifx = _table(sess, IFX_ENTRY, MAX_IF * 20)
    dot3 = _table(sess, DOT3_ENTRY, MAX_IF * 20)
    descr, itype, speed, phys = (_column(ift, c) for c in (2, 3, 5, 6))
    admin, oper, in_err, out_err, changed = (_column(ift, c) for c in (7, 8, 14, 20, 9))
    name, hspeed, alias = (_column(ifx, c) for c in (1, 15, 18))
    fcs, duplex = _column(dot3, 3), _column(dot3, 19)
    interfaces = []
    for idx in sorted(set(descr) | set(name))[:MAX_IF]:
        i = idx[0]
        mbps = hspeed.get(idx) if isinstance(hspeed.get(idx), int) and hspeed.get(idx) else None
        if mbps is None and isinstance(speed.get(idx), int):
            mbps = speed[idx] // 1_000_000 if speed[idx] < 4_294_967_295 else None
        interfaces.append({
            "index": i, "name": _text(name.get(idx)) or _text(descr.get(idx)) or f"Port {i}",
            "descr": _text(descr.get(idx)), "alias": _text(alias.get(idx)),
            "type": itype.get(idx) if isinstance(itype.get(idx), int) else None, "speed_mbps": mbps,
            "mac": mac_str(phys.get(idx)), "admin_up": admin.get(idx) == 1, "oper_up": oper.get(idx) == 1,
            "in_errors": in_err.get(idx) if isinstance(in_err.get(idx), int) else None,
            "out_errors": out_err.get(idx) if isinstance(out_err.get(idx), int) else None,
            "fcs_errors": fcs.get(idx) if isinstance(fcs.get(idx), int) else None,
            "duplex": {2: "half", 3: "full"}.get(duplex.get(idx)),
            "last_change_s": changed[idx] // 100 if isinstance(changed.get(idx), int) else None,
        })
    out["interfaces"] = interfaces
    if_ids = {i["index"] for i in interfaces}

    # Bridge: Port-Nummer → ifIndex, eigene MAC
    try:
        base = sess.get([BRIDGE_ADDR]).get(BRIDGE_ADDR)
    except snmp.SnmpTimeout:
        raise
    except snmp.SnmpError:
        base = None
    bport = {idx[0]: v for idx, v in _table(sess, BRIDGE_PORT_IF, 4096) if idx and isinstance(v, int)}
    out["bridge_ports"] = {str(k): v for k, v in bport.items()}

    def to_if(port: int) -> int | None:
        return bport.get(port) or (port if port in if_ids else None)

    # MAC-Tabelle: Q-BRIDGE (mit VLAN) bevorzugt, sonst BRIDGE-MIB
    fdb = []
    qrows = _table(sess, QFDB_PORT.rsplit(".", 1)[0], MAX_FDB * 2)
    qport, qstat = _column(qrows, 2), _column(qrows, 3)
    for idx, port in qport.items():
        if len(idx) != 7 or not isinstance(port, int) or not port or qstat.get(idx, 3) not in (3, 5):
            continue
        mac = mac_str(bytes(idx[1:]))
        if mac and (ifi := to_if(port)):
            fdb.append({"mac": mac, "if_index": ifi, "vlan": idx[0]})
    if not fdb:
        rows = _table(sess, FDB_PORT.rsplit(".", 1)[0], MAX_FDB * 2)
        fport, fstat = _column(rows, 2), _column(rows, 3)
        for idx, port in fport.items():
            if len(idx) != 6 or not isinstance(port, int) or not port or fstat.get(idx, 3) not in (3, 5):
                continue
            mac = mac_str(bytes(idx))
            if mac and (ifi := to_if(port)):
                fdb.append({"mac": mac, "if_index": ifi, "vlan": None})
    out["fdb"] = fdb[:MAX_FDB]
    out["pvid"] = {str(ifi): v for p, v in ((idx[0], v) for idx, v in _table(sess, PVID, 4096) if idx)
                   if isinstance(v, int) and (ifi := to_if(p))}

    # LLDP
    try:
        loc = sess.get([f"{LLDP_LOC}.1.0", f"{LLDP_LOC}.2.0"])
    except snmp.SnmpTimeout:
        raise
    except snmp.SnmpError:
        loc = {}
    loc_subtype, loc_chassis = loc.get(f"{LLDP_LOC}.1.0"), loc.get(f"{LLDP_LOC}.2.0")
    lport = _table(sess, LLDP_LOC_PORT, 4096 * 3)
    lport_id, lport_desc = _column(lport, 3), _column(lport, 4)
    by_name: dict[str, int] = {}
    for i in interfaces:
        for key in (i["name"], i["descr"], i["alias"]):
            if key:
                by_name.setdefault(key.lower(), i["index"])

    def lldp_if(num: int) -> int | None:
        for raw in (lport_id.get((num,)), lport_desc.get((num,))):
            t = _text(raw)
            if t and t.lower() in by_name:
                return by_name[t.lower()]
        return num if num in if_ids else bport.get(num)

    rem = _table(sess, LLDP_REM, 4096 * 12)
    cols = {c: _column(rem, c) for c in (4, 5, 6, 7, 8, 9, 10, 12)}
    mgmt: dict[tuple[int, int], str] = {}
    for idx, _v in _table(sess, LLDP_REM_MAN, 4096):
        # Index: timeMark.localPort.remIndex.addrSubtype.addrLen.addr…
        if len(idx) >= 9 and idx[3] == 1 and idx[4] == 4:
            mgmt.setdefault((idx[1], idx[2]), ".".join(str(x) for x in idx[5:9]))
    lldp = []
    for idx in cols[5]:
        if len(idx) != 3:
            continue
        caps = cols[12].get(idx)
        caps = caps[0] if isinstance(caps, bytes) and caps else 0
        lldp.append({
            "if_index": lldp_if(idx[1]), "local_port": idx[1],
            "chassis_id": _chassis(cols[4].get(idx), cols[5].get(idx)),
            "port_id": _port_id(cols[6].get(idx), cols[7].get(idx)),
            "port_descr": _text(cols[8].get(idx)), "sys_name": _text(cols[9].get(idx)),
            "sys_descr": _text(cols[10].get(idx), 300), "mgmt_ip": mgmt.get((idx[1], idx[2])),
            "bridge": bool(caps & 0x20), "ap": bool(caps & 0x10), "router": bool(caps & 0x08),
            "phone": bool(caps & 0x04),
        })
    out["lldp"] = lldp
    out["lldp_chassis"] = _chassis(loc_subtype, loc_chassis)

    # CDP (Cisco und kompatible)
    cdp_rows = _table(sess, CDP_CACHE, 4096 * 10)
    c = {k: _column(cdp_rows, k) for k in (3, 4, 6, 7, 8, 9)}
    cdp = []
    for idx, dev in c[6].items():
        if len(idx) != 2:
            continue
        addr = c[4].get(idx)
        ip = ".".join(str(b) for b in addr) if c[3].get(idx) == 1 and isinstance(addr, bytes) and len(addr) == 4 else None
        capb = c[9].get(idx)
        cap = int.from_bytes(capb, "big") if isinstance(capb, bytes) and len(capb) <= 4 else 0
        cdp.append({"if_index": idx[0] if idx[0] in if_ids else None, "device_id": _text(dev),
                    "port_id": _text(c[7].get(idx)), "platform": _text(c[8].get(idx)), "mgmt_ip": ip,
                    "bridge": bool(cap & 0x0A), "router": bool(cap & 0x01), "phone": bool(cap & 0x80)})
    out["cdp"] = cdp

    # PoE: Leistung gesamt, Ports mit Stromversorgung (Port-Nummer meist = Bridge-Port)
    main = _table(sess, POE_MAIN, 200)
    power = sum(v for idx, v in main if idx and idx[0] == 2 and isinstance(v, int)) or None
    used = sum(v for idx, v in main if idx and idx[0] == 4 and isinstance(v, int)) if power else None
    poe_ports = [ifi for idx, v in _table(sess, POE_PORT_STATUS, 4096)
                 if len(idx) == 2 and v == 3 and (ifi := to_if(idx[1]))]
    out["poe"] = {"power_w": power, "used_w": used, "ports": sorted(set(poe_ports))} if power or poe_ports else None

    # Verwaltungs-Adressen, ARP-Tabelle (IP ↔ MAC) und Standard-Gateway
    out["ips"] = sorted({".".join(str(x) for x in idx) for idx, _v in _table(sess, IP_ADDR_IF, 256)
                         if len(idx) == 4 and idx[0] != 127})
    arp = []
    for idx, v in _table(sess, ARP_MAC, MAX_ARP):
        if len(idx) == 5 and (mac := mac_str(v)):
            arp.append({"ip": ".".join(str(x) for x in idx[1:]), "mac": mac})
    out["arp"] = arp[:MAX_ARP]
    try:
        gw = sess.get([DEFAULT_ROUTE]).get(DEFAULT_ROUTE)
    except snmp.SnmpTimeout:
        raise
    except snmp.SnmpError:
        gw = None
    out["gateway"] = gw if isinstance(gw, str) and gw != "0.0.0.0" else None
    out["base_mac"] = mac_str(base) or (out["lldp_chassis"] if _is_mac(out["lldp_chassis"]) else None)
    out["duration_s"] = round(time.monotonic() - started, 2)
    return out


def _is_mac(v) -> bool:
    return isinstance(v, str) and len(v) == 17 and v.count(":") == 5


def _chassis(subtype, raw) -> str | None:
    """LLDP-Chassis-ID lesbar: MAC (Subtyp 4), Netzadresse (5) oder Text."""
    if subtype == 4 and (mac := mac_str(raw)):
        return mac
    if subtype == 5 and isinstance(raw, bytes) and len(raw) == 5 and raw[0] == 1:
        return ".".join(str(b) for b in raw[1:])
    if isinstance(raw, bytes) and (mac := mac_str(raw)):
        return mac
    return _text(raw)


def _port_id(subtype, raw) -> str | None:
    if subtype == 3 and (mac := mac_str(raw)):
        return mac
    return _text(raw)


def summary(snapshot: dict) -> dict:
    """Kurzfassung für den Assistenten: was der Switch geliefert hat."""
    ifs = [i for i in snapshot.get("interfaces") or [] if i.get("type") in PHYSICAL_TYPES]
    return {
        "name": (snapshot.get("system") or {}).get("name"), "descr": (snapshot.get("system") or {}).get("descr"),
        "uptime_s": (snapshot.get("system") or {}).get("uptime_s"),
        "ports": len(ifs), "ports_up": sum(1 for i in ifs if i.get("oper_up")),
        "macs": len(snapshot.get("fdb") or []), "neighbors": len(snapshot.get("lldp") or []) + len(snapshot.get("cdp") or []),
        "poe": bool(snapshot.get("poe")), "vlans": bool(snapshot.get("pvid")), "duration_s": snapshot.get("duration_s"),
    }
