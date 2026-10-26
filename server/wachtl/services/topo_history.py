"""Verlauf der Switch-Topologie (docs/TOPOLOGIE.md, Abschnitt „Verlauf“).

- Ereignisse aus dem Vergleich zweier Abfragen: Link weg/da, kurz ohne Link (ifLastChange), Geschwindigkeit,
  Port-Fehler, Neustart, Switch nicht erreichbar/wieder da, Nachbar neu/weg, Gerät neu/umgesteckt.
- Gespeicherte Stände je Switch (bei Änderungen am Aufbau, sonst stündlich) zum Zurückblättern.
- Auswertungen für die Seiten: Zeitleiste, Chronik, Port-Verlauf, Störung im Kontext.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import zlib

from .. import repo
from ..db import ex, ins, q, q1

ERRORS_EVENT = 10                 # so viele neue Fehler zwischen zwei Abfragen ergeben ein Ereignis
ERRORS_CRIT = 1000
HISTORY_EVERY_S = 3600            # ohne Änderung am Aufbau höchstens stündlich einen Stand speichern
HISTORY_DENSE_DAYS = 7            # danach nur Änderungen und ein Stand je Tag
ACCESS_MAX_MACS = 8               # mehr Geräte an einem Port = vermutlich Uplink, dort keine Geräte-Ereignisse

KINDS = {
    # Art: (Bezeichnung, Gruppe für Filter, erkannt über)
    "link_down": ("Link weg", "links", "Port-Status (IF-MIB)"),
    "link_up": ("Link wieder da", "links", "Port-Status (IF-MIB)"),
    "link_flap": ("Kurz ohne Link", "links", "Zeitpunkt der letzten Statusänderung (ifLastChange)"),
    "speed_changed": ("Geschwindigkeit geändert", "links", "Geschwindigkeit (IF-MIB)"),
    "port_errors": ("Port-Fehler", "links", "Fehlerzähler (IF-MIB)"),
    "device_new": ("Gerät neu", "geraete", "MAC-Tabelle (BRIDGE-MIB)"),
    "mac_moved": ("Gerät umgesteckt", "geraete", "MAC-Tabelle (BRIDGE-MIB)"),
    "neighbor_changed": ("Nachbar geändert", "switche", "LLDP/CDP"),
    "switch_down": ("Switch nicht erreichbar", "switche", "SNMP-Abfrage"),
    "switch_up": ("Switch wieder erreichbar", "switche", "SNMP-Abfrage"),
    "switch_restart": ("Switch neu gestartet", "switche", "Systemlaufzeit (SNMPv2-MIB)"),
}
FILTERS = {"alle": "Alles", "stoerungen": "Störungen", "links": "Links und Ports", "geraete": "Geräte",
           "switche": "Switches"}
SEVERITY_TEXT = {"critical": "Störung", "warning": "Warnung", "info": "Info"}


def event(sw: dict, ts: int, kind: str, severity: str, if_index: int | None, mac: str | None, detail: str,
          data: dict | None = None) -> None:
    ins("INSERT INTO net_topo_events (site_id, switch_id, ts, kind, severity, if_index, mac, detail, data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (sw["site_id"], sw["id"], int(ts), kind, severity, if_index, mac, detail[:300],
         json.dumps(data, separators=(",", ":")) if data else None))


def _speed(mbps) -> str:
    if not mbps:
        return "–"
    return f"{mbps / 1000:g} Gbit/s" if mbps >= 1000 else f"{mbps} Mbit/s"


def _neighbors(snap: dict) -> dict[int, str]:
    out: dict[int, str] = {}
    for e in (snap.get("lldp") or []) + (snap.get("cdp") or []):
        if e.get("if_index"):
            out[e["if_index"]] = e.get("sys_name") or e.get("device_id") or e.get("chassis_id") or "?"
    return out


def important_ports(snap: dict, switch_macs: set[str]) -> set[int]:
    """Ports zu anderen Switches, Access Points oder Routern: dort ist „Link weg“ eine Störung, kein PC, der ausgeht."""
    out = {e["if_index"] for e in (snap.get("lldp") or []) + (snap.get("cdp") or [])
           if e.get("if_index") and (e.get("bridge") or e.get("router") or e.get("ap"))}
    counts: dict[int, int] = {}
    for e in snap.get("fdb") or []:
        counts[e["if_index"]] = counts.get(e["if_index"], 0) + 1
        if e["mac"] in switch_macs:
            out.add(e["if_index"])
    out |= {i for i, n in counts.items() if n > ACCESS_MAX_MACS}
    return out


def _change_ts(ts: int, uptime: int | None, last_change: int | None) -> int:
    """Zeitpunkt der Statusänderung aus Laufzeit und ifLastChange; sonst der Abfragezeitpunkt."""
    if uptime is None or last_change is None or last_change > uptime:
        return ts
    return max(ts - (uptime - last_change), ts - 3600)


def record(sw: dict, old: dict, new: dict, ts: int, full: bool, switch_macs: set[str], labels: dict[str, str]) -> int:
    """Zwei Abfragen vergleichen und Ereignisse speichern. Gibt die Zahl der Ereignisse zurück."""
    count = 0

    def ev(*args, **kw):
        nonlocal count
        count += 1
        event(sw, *args, **kw)

    up_new, up_old = new["system"].get("uptime_s"), old["system"].get("uptime_s")
    restarted = up_new is not None and up_old is not None and up_new < up_old
    if restarted:
        ev(ts - up_new, "switch_restart", "warning", None, None, f"Neu gestartet (Laufzeit jetzt {up_new // 60} min)")
    before = {i["index"]: i for i in old.get("interfaces") or []}
    important = important_ports(old, switch_macs)
    for i in new["interfaces"]:
        o = before.get(i["index"])
        if not o:
            continue
        idx, name = i["index"], i.get("name") or o.get("name") or f"Port {i['index']}"
        if not restarted and i.get("in_errors") is not None and o.get("in_errors") is not None:
            delta = max(0, i["in_errors"] - o["in_errors"])
            if delta:
                ins("INSERT INTO net_port_errors (switch_id, if_index, ts, errors) VALUES (?, ?, ?, ?)",
                    (sw["id"], idx, ts, delta))
            if delta >= ERRORS_EVENT:
                ev(ts, "port_errors", "critical" if delta >= ERRORS_CRIT else "warning", idx, None,
                   f"{name}: {delta:,} fehlerhafte Pakete seit der letzten Abfrage".replace(",", "."), {"count": delta})
        when = _change_ts(ts, up_new, i.get("last_change_s"))
        if bool(o.get("oper_up")) != bool(i.get("oper_up")):
            if i.get("oper_up"):
                ev(when, "link_up", "info", idx, None, f"{name}: Link wieder da, {_speed(i.get('speed_mbps'))}",
                   {"from": "down", "to": "up", "speed": i.get("speed_mbps")})
            else:
                why = " (am Switch abgeschaltet)" if not i.get("admin_up") else ""
                ev(when, "link_down", "critical" if idx in important and i.get("admin_up") else "info", idx, None,
                   f"{name}: Link weg{why}", {"from": "up", "to": "down", "speed": o.get("speed_mbps")})
        elif not restarted and i.get("oper_up") and i.get("last_change_s") is not None and \
                o.get("last_change_s") is not None and i["last_change_s"] != o["last_change_s"]:
            ev(when, "link_flap", "critical" if idx in important else "warning", idx, None,
               f"{name}: kurz ohne Link zwischen zwei Abfragen")
        if i.get("oper_up") and o.get("oper_up") and i.get("speed_mbps") and o.get("speed_mbps") and \
                i["speed_mbps"] != o["speed_mbps"]:
            slower = i["speed_mbps"] < o["speed_mbps"]
            ev(ts, "speed_changed", "warning" if slower and (idx in important or i["speed_mbps"] < 1000) else "info",
               idx, None, f"{name}: {_speed(o['speed_mbps'])} → {_speed(i['speed_mbps'])}",
               {"from": o["speed_mbps"], "to": i["speed_mbps"]})
    if not full:
        return count

    # Nachbarn (LLDP/CDP) je Port
    nb_old, nb_new = _neighbors(old), _neighbors(new)
    names = {i["index"]: i.get("name") or f"Port {i['index']}" for i in new["interfaces"]}
    if old.get("lldp") is not None and old.get("fdb") is not None:
        for idx in sorted(set(nb_old) | set(nb_new)):
            a, b = nb_old.get(idx), nb_new.get(idx)
            if a == b:
                continue
            text = (f"neuer Nachbar {b}" if not a else f"Nachbar {a} nicht mehr gemeldet" if not b
                    else f"Nachbar {a} → {b}")
            ev(ts, "neighbor_changed", "warning", idx, None, f"{names.get(idx, idx)}: {text}", {"from": a, "to": b})

    # Geräte: neu an einem Zugangs-Port oder an einem anderen Port als zuvor
    access = {i["index"] for i in new["interfaces"]} - important_ports(new, switch_macs)
    known = {r["mac"]: r for r in q("SELECT * FROM net_topo_macs WHERE switch_id = ?", (sw["id"],))}
    first_full = not known          # erste vollständige Abfrage mit Geräten: nur merken, nicht melden
    for e in new.get("fdb") or []:
        mac, idx = e["mac"], e["if_index"]
        if idx not in access or mac in switch_macs:
            continue
        row = known.get(mac)
        label = labels.get(mac) or mac
        if row is None:
            ins("INSERT INTO net_topo_macs (switch_id, mac, if_index, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                (sw["id"], mac, idx, ts, ts))
            known[mac] = {"mac": mac, "if_index": idx}
            if not first_full:
                ev(ts, "device_new", "info", idx, mac, f"{label} an {names.get(idx, idx)}")
        elif row["if_index"] != idx:
            ex("UPDATE net_topo_macs SET if_index = ?, last_seen = ? WHERE switch_id = ? AND mac = ?",
               (idx, ts, sw["id"], mac))
            ev(ts, "mac_moved", "info", idx, mac,
               f"{label}: {names.get(row['if_index'], row['if_index'])} → {names.get(idx, idx)}",
               {"from": row["if_index"], "to": idx})
        else:
            ex("UPDATE net_topo_macs SET last_seen = ? WHERE switch_id = ? AND mac = ?", (ts, sw["id"], mac))
    return count


# -- Gespeicherte Stände -------------------------------------------------------------------
def _structure(snap: dict) -> str:
    """Prüfsumme über den Aufbau (Ports, Geschwindigkeit, Nachbarn) – ohne Zähler und Laufzeit."""
    ports = [(i["index"], bool(i.get("oper_up")), bool(i.get("admin_up")), i.get("speed_mbps"))
             for i in snap.get("interfaces") or []]
    nbs = sorted(_neighbors(snap).items())
    return hashlib.sha256(json.dumps([ports, nbs], separators=(",", ":")).encode()).hexdigest()[:24]


def _pack(snap: dict) -> str:
    return base64.b64encode(zlib.compress(json.dumps(snap, separators=(",", ":")).encode(), 6)).decode()


def _unpack(text: str) -> dict:
    return json.loads(zlib.decompress(base64.b64decode(text)))


def store_snapshot(switch_id: int, snap: dict, ts: int) -> bool:
    """Stand speichern, wenn sich der Aufbau geändert hat oder der letzte älter als eine Stunde ist."""
    h = _structure(snap)
    last = q1("SELECT ts, hash FROM net_switch_history WHERE switch_id = ? ORDER BY ts DESC, id DESC LIMIT 1",
              (switch_id,))
    if last and last["hash"] == h and ts - last["ts"] < HISTORY_EVERY_S:
        return False
    ins("INSERT INTO net_switch_history (switch_id, ts, hash, snapshot) VALUES (?, ?, ?, ?)",
        (switch_id, ts, h, _pack(snap)))
    return True


def snapshot_at(switch_id: int, ts: int) -> tuple[int, dict] | None:
    row = q1("SELECT ts, snapshot FROM net_switch_history WHERE switch_id = ? AND ts <= ? ORDER BY ts DESC, id DESC "
             "LIMIT 1", (switch_id, ts))
    return (row["ts"], _unpack(row["snapshot"])) if row else None


def rows_at(site_id: int, ts: int) -> list[dict]:
    """Switches eines Standorts im Stand von ts (für den Baum in der Vergangenheit)."""
    out = []
    for r in q("SELECT * FROM net_switches WHERE site_id = ? AND status <> 'draft' AND created_at <= ? ORDER BY id",
               (site_id, ts)):
        found = snapshot_at(r["id"], ts)
        last = q1("SELECT kind, ts FROM net_topo_events WHERE switch_id = ? AND kind IN ('switch_down', 'switch_up') "
                  "AND ts <= ? ORDER BY ts DESC, id DESC LIMIT 1", (r["id"], ts))
        down = bool(last and last["kind"] == "switch_down")
        out.append({**r, "snapshot": json.dumps(found[1]) if found else None, "last_ok": found[0] if found else None,
                    "last_error": "antwortete zu diesem Zeitpunkt nicht" if down else None,
                    "status": "active" if r["status"] == "disabled" else r["status"]})
    return out


def prune(ts: int | None = None, keep_days: int = 90) -> None:
    """Ältere Stände ausdünnen: nach 7 Tagen nur noch Änderungen am Aufbau und einer je Tag."""
    ts = ts or repo.now()
    ex("DELETE FROM net_switch_history WHERE ts < ?", (ts - keep_days * 86400,))
    for sw in q("SELECT DISTINCT switch_id FROM net_switch_history WHERE ts < ?", (ts - HISTORY_DENSE_DAYS * 86400,)):
        prev_hash, prev_day = None, None
        drop = []
        for r in q("SELECT id, ts, hash FROM net_switch_history WHERE switch_id = ? AND ts < ? ORDER BY ts",
                   (sw["switch_id"], ts - HISTORY_DENSE_DAYS * 86400)):
            day = r["ts"] // 86400
            if r["hash"] == prev_hash and day == prev_day:
                drop.append(r["id"])
            prev_hash, prev_day = r["hash"], day
        for i in range(0, len(drop), 500):
            chunk = drop[i:i + 500]
            ex(f"DELETE FROM net_switch_history WHERE id IN ({','.join('?' * len(chunk))})", chunk)
    ex("DELETE FROM net_topo_macs WHERE last_seen < ?", (ts - keep_days * 86400,))


# -- Zeitleiste und Chronik ------------------------------------------------------------------
def _port_names(switch_ids: set[int]) -> dict[tuple[int, int], str]:
    from .topology import port_short

    out = {}
    if not switch_ids:
        return out
    marks = ",".join("?" * len(switch_ids))
    for r in q(f"SELECT id, snapshot FROM net_switches WHERE id IN ({marks})", list(switch_ids)):
        for i in (json.loads(r["snapshot"]) if r["snapshot"] else {}).get("interfaces") or []:
            out[(r["id"], i["index"])] = port_short(i.get("name"))
    return out


def events(site_id: int, *, before: int | None = None, after: int | None = None, art: str = "alle",
           switch_id: int | None = None, switch_ids: list[int] | None = None, limit: int = 100) -> list[dict]:
    where, params = ["e.site_id = ?"], [site_id]
    if before is not None:
        where.append("e.ts < ?")
        params.append(before)
    if after is not None:
        where.append("e.ts >= ?")
        params.append(after)
    if switch_id:
        where.append("e.switch_id = ?")
        params.append(switch_id)
    if switch_ids is not None:
        if not switch_ids:
            return []
        where.append(f"e.switch_id IN ({','.join('?' * len(switch_ids))})")
        params += switch_ids
    if art == "stoerungen":
        where.append("e.severity IN ('critical', 'warning')")
    elif art in ("links", "geraete", "switche"):
        kinds = [k for k, v in KINDS.items() if v[1] == art]
        where.append(f"e.kind IN ({','.join('?' * len(kinds))})")
        params += kinds
    rows = q("SELECT e.*, w.name AS sw_name, w.sys_name, w.host FROM net_topo_events e "
             "LEFT JOIN net_switches w ON w.id = e.switch_id WHERE " + " AND ".join(where) +
             f" ORDER BY e.ts DESC, e.id DESC LIMIT {int(limit)}", params)
    names = _port_names({r["switch_id"] for r in rows if r["switch_id"]})
    for r in rows:
        decorate(r, names)
    return rows


def decorate(r: dict, names: dict | None = None) -> dict:
    info = KINDS.get(r["kind"], (r["kind"], "switche", "–"))
    r["kind_label"], r["group"], r["via"] = info
    r["switch_label"] = r.get("sw_name") or r.get("sys_name") or r.get("host") or "Switch"
    r["port"] = (names or {}).get((r["switch_id"], r["if_index"])) if r.get("if_index") else None
    r["data_obj"] = json.loads(r["data"]) if r.get("data") else {}
    r["severity_text"] = SEVERITY_TEXT.get(r["severity"], r["severity"])
    return r


def event_by_id(site_id: int, event_id: int) -> dict | None:
    r = q1("SELECT e.*, w.name AS sw_name, w.sys_name, w.host FROM net_topo_events e LEFT JOIN net_switches w "
           "ON w.id = e.switch_id WHERE e.id = ? AND e.site_id = ?", (event_id, site_id))
    return decorate(r, _port_names({r["switch_id"]} if r and r["switch_id"] else set())) if r else None


def neighbor_event(site_id: int, ts: int, newer: bool, important: bool) -> dict | None:
    """Nächstes Ereignis vor bzw. nach ts (für „Früher“ / „Später“)."""
    sev = "AND severity IN ('critical', 'warning') " if important else ""
    if newer:
        return q1(f"SELECT id, ts FROM net_topo_events WHERE site_id = ? AND ts > ? {sev}ORDER BY ts, id LIMIT 1",
                  (site_id, ts))
    return q1(f"SELECT id, ts FROM net_topo_events WHERE site_id = ? AND ts < ? {sev}ORDER BY ts DESC, id DESC LIMIT 1",
              (site_id, ts))


def group_by_day(rows: list[dict]) -> list[tuple[str, list[dict]]]:
    from datetime import datetime, timedelta

    today = datetime.now().date()
    names = {today: "Heute", today - timedelta(days=1): "Gestern"}
    days = ("Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag")
    out: list[tuple[str, list[dict]]] = []
    for r in rows:
        d = datetime.fromtimestamp(r["ts"]).date()
        label = names.get(d) or f"{days[d.weekday()]}, {d.strftime('%d.%m.%Y')}"
        if not out or out[-1][0] != label:
            out.append((label, []))
        out[-1][1].append(r)
    return out


# -- Port-Verlauf -------------------------------------------------------------------------------
RANGES = {"6h": ("6 Stunden", 6 * 3600, 72), "24h": ("24 Stunden", 86400, 96), "7d": ("7 Tage", 7 * 86400, 168)}


def lane(evs: list[dict], up_now: bool, speed_now: int | None, start: int, end: int, cells: int,
         since: int | None = None) -> list[str]:
    """Zustand eines Ports je Abschnitt, rückwärts aus dem jetzigen Zustand und den Ereignissen berechnet."""
    from .topology import speed_class

    step = (end - start) / cells
    up, speed = up_now, speed_now
    evs = sorted((e for e in evs if e["ts"] > start), key=lambda e: (e["ts"], e.get("id") or 0), reverse=True)
    i = 0

    def undo(e: dict) -> None:
        nonlocal up, speed
        d = e.get("data_obj") or {}
        if e["kind"] == "link_down":
            up = True
        elif e["kind"] == "link_up":
            up = False
        elif e["kind"] == "speed_changed" and d.get("from"):
            speed = d["from"]

    while i < len(evs) and evs[i]["ts"] > end:
        undo(evs[i])
        i += 1
    out = [""] * cells
    for b in range(cells - 1, -1, -1):
        t0, t1 = start + b * step, start + (b + 1) * step
        end_up, end_speed = up, speed
        kinds = set()
        while i < len(evs) and evs[i]["ts"] > t0:
            kinds.add(evs[i]["kind"])
            undo(evs[i])
            i += 1
        if since and t1 <= since:
            out[b] = "ln-none"
        elif "port_errors" in kinds:
            out[b] = "ln-err"
        elif "link_flap" in kinds or ("link_down" in kinds and "link_up" in kinds):
            out[b] = "ln-flap"
        elif "link_down" in kinds or "link_up" in kinds or not end_up:
            out[b] = "ln-down"
        else:
            out[b] = "ln-" + speed_class(end_speed).removeprefix("sp-") if end_speed else "ln-up"
    return out


def port_lanes(sw: dict, ports: dict, range_key: str, now: int | None = None) -> dict:
    now = now or repo.now()
    label, span, cells = RANGES.get(range_key, RANGES["24h"])
    start = now - span
    evs: dict[int, list[dict]] = {}
    for r in q("SELECT id, ts, kind, if_index, data FROM net_topo_events WHERE switch_id = ? AND ts > ? "
               "AND if_index IS NOT NULL", (sw["id"], start)):
        r["data_obj"] = json.loads(r["data"]) if r["data"] else {}
        evs.setdefault(r["if_index"], []).append(r)
    lanes = []
    for p in sorted(ports.values(), key=lambda p: p.index):
        if not p.physical:
            continue
        row = lane(evs.get(p.index, []), p.up, p.speed, start, now, cells, sw.get("created_at"))
        who = p.neighbor.get("name") if p.neighbor else (p.devices[0].get("label") if p.devices else "")
        counts = {k: row.count(k) for k in ("ln-down", "ln-flap", "ln-err")}
        events_n = len(evs.get(p.index, []))
        summary = (f"Port {p.short}: " + ("ohne Änderung" if not events_n else
                   f"{events_n} Ereignisse") + (f", {counts['ln-flap']} Abschnitte mit Aussetzern" if counts["ln-flap"] else "")
                   + (f", {counts['ln-err']} mit Fehlern" if counts["ln-err"] else "")
                   + (", jetzt ohne Link" if not p.up else f", jetzt {_speed(p.speed)}"))
        lanes.append({"port": p, "who": who, "cells": row, "summary": summary, "events": events_n})
    axis = [start + span * k // 4 for k in range(5)]
    return {"lanes": lanes, "range": range_key, "label": label, "cells": cells, "axis": axis, "ranges": RANGES}


# -- Störung im Kontext -----------------------------------------------------------------------
def _probe_mac(site_id: int, probe: dict) -> str | None:
    addrs = set(json.loads(probe.get("addresses") or "[]")) | ({probe["last_ip"]} if probe.get("last_ip") else set())
    host = (probe.get("hostname") or "").lower()
    for d in q("SELECT mac, ip, hostname, is_probe FROM net_devices WHERE site_id = ? AND mac IS NOT NULL", (site_id,)):
        name = (d["hostname"] or "").split(".")[0].lower()
        if (d["ip"] and d["ip"] in addrs) or (host and name == host):
            return d["mac"]
    return None


def context(site_id: int, probe: dict | None, start: int, end: int) -> dict:
    """Zeitfenster um eine Störung: Paketverlust der Probe, Ports auf ihrem Weg, Erreichbarkeit der Switches,
    Ereignisse – und eine Einschätzung, ob die Ursache im Switch-Netz liegt."""
    from . import vm
    from .topology import ERRORS_WARN, build, path_for

    span = max(end - start, 60)
    pad = max(900, span)
    w0, w1 = start - pad, min(end + pad, repo.now())
    if w1 - w0 > 6 * 3600:
        w0 = max(w0, start - 1800)
        w1 = min(w1, w0 + 6 * 3600)
    cells = 120
    step = (w1 - w0) / cells
    topo = build(site_id)
    mac = _probe_mac(site_id, probe) if probe else None
    path = path_for(topo, mac) if mac else None
    out = {"start": start, "end": end, "w0": w0, "w1": w1, "cells": cells, "probe": probe, "mac": mac, "path": path,
           "loss": None, "lanes": [], "events": [], "verdict": None, "axis": [w0 + (w1 - w0) * k // 4 for k in range(5)],
           "win_from": int((start - w0) / step), "win_to": max(int((end - w0) / step), int((start - w0) / step) + 1)}

    # Paketverlust der Probe (1-min-Werte, je Abschnitt der höchste)
    if probe:
        try:
            series = vm.report_ping_series(probe["id"], int(w0), int(w1), 60)
            best = next((s for s in series.values() if s.get("role") == "gateway"), None) or \
                max(series.values(), key=lambda s: sum(v for _t, v in s["series"].get("loss", [])), default=None)
            if best:
                vals = [0.0] * cells
                for t, v in best["series"].get("loss", []):
                    b = int((t - w0) / step)
                    if 0 <= b < cells:
                        vals[b] = max(vals[b], v)
                out["loss"] = [{"v": v, "lvl": 0 if v < 1 else 1 if v < 20 else 2 if v < 80 else 3} for v in vals]
                out["loss_target"] = best.get("target") or ""
        except vm.VMError:
            out["loss_error"] = "Messwerte gerade nicht abrufbar."

    # Ports auf dem Weg der Probe (oder alle Switches, wenn das Gerät keinem Port zugeordnet ist)
    lanes, involved = [], []
    if path:
        for idx, h in enumerate(path["hops"]):
            if not h.get("switch_id"):
                continue
            sw = topo.switches[h["switch_id"]]
            involved.append(h["switch_id"])
            for which in ("in", "out"):
                short = h.get(which)
                port = next((p for p in sw["ports"].values() if p.short == short), None) if short else None
                if port:
                    lanes.append((sw, port, f"{h['label']} · Port {port.short}",
                                  "Anschluss der Probe" if idx == 1 and which == "in" else
                                  ("Richtung Internet" if which == "out" else "von unten")))
    else:
        involved = list(topo.switches)
    evs = events(site_id, after=int(w0), before=int(w1) + 1, switch_ids=involved, limit=300)
    by_port: dict[tuple[int, int], list[dict]] = {}
    for e in evs:
        if e.get("if_index"):
            by_port.setdefault((e["switch_id"], e["if_index"]), []).append(e)
    for sw, port, name, sub in lanes:
        cells_ = lane(by_port.get((sw["row"]["id"], port.index), []), port.up, port.speed, int(w0), int(w1), cells)
        out["lanes"].append({"name": name, "sub": sub, "cells": cells_,
                             "bad": any(c in ("ln-down", "ln-flap", "ln-err") for c in
                                        cells_[out["win_from"]:out["win_to"] + 1])})
    for sid in involved:
        sw = topo.switches[sid]
        sevs = [e for e in evs if e["switch_id"] == sid and e["kind"] in ("switch_down", "switch_up")]
        reach = []
        up = not sw["row"].get("last_error")
        cur = sorted(sevs, key=lambda e: e["ts"], reverse=True)
        k = 0
        for b in range(cells - 1, -1, -1):
            t0 = w0 + b * step
            end_up = up
            while k < len(cur) and cur[k]["ts"] > t0:
                up = cur[k]["kind"] == "switch_down"
                k += 1
            reach.append("ln-1" if end_up else "ln-down")
        reach.reverse()
        out["lanes"].append({"name": topo.nodes[sw["node"]].label, "sub": "per SNMP erreichbar", "cells": reach,
                             "bad": "ln-down" in reach[out["win_from"]:out["win_to"] + 1]})
    out["events"] = [e for e in evs if start - 300 <= e["ts"] <= end + 300] or evs[:20]

    # Einschätzung
    window_evs = [e for e in evs if start - 120 <= e["ts"] <= end + 120 and e["severity"] in ("critical", "warning")]
    first_port = lanes[0] if lanes else None
    # am Anschluss der Probe zählt jede Änderung (auch „Link weg“ der Stufe Info)
    hit = min((e for e in evs if start - 120 <= e["ts"] <= end + 120 and first_port
               and e["switch_id"] == first_port[0]["row"]["id"] and e.get("if_index") == first_port[1].index),
              key=lambda e: e["ts"], default=None)
    if hit:
        out["verdict"] = ("bad", f"der Anschluss der Probe ({first_port[2]}). "
                          f"Zur selben Zeit: {hit['detail']}. Meist Kabel, Dose oder Stecker.")
    elif window_evs:
        e = window_evs[0]
        out["verdict"] = ("warn", f"Zur selben Zeit im Switch-Netz: {e['switch_label']} – {e['detail']}. "
                          "Das kann die Störung erklären.")
    elif path and any(lk["errors"] >= ERRORS_WARN for lk in path["links"]):
        out["verdict"] = ("warn", "Auf dem Weg der Probe gibt es Port-Fehler in den letzten 24 Stunden – "
                          "das kann kurze Aussetzer erklären.")
    else:
        out["verdict"] = ("ok", "Im Switch-Netz gab es zu dieser Zeit keine Auffälligkeit. Die Ursache liegt eher "
                          "außerhalb (Gateway, Internetanschluss) oder am PC selbst.")
    return out
