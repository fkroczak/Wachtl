"""PDF-Bericht: sammelt und bewertet alle Störungen, Messreihen und Hinweise eines Zeitraums.

Ergebnis sind einfache dicts (ohne PDF-Bezug, testbar). Gerendert wird in ``report_pdf.py``.

Leitfrage des Berichts: Wo liegt das Problem – beim Provider, im lokalen Netz, an einem PC oder an einer
einzelnen Gegenstelle? Die Einschätzung ist regelbasiert (siehe ``verdict``) und nennt die entscheidenden Belege.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import statistics
import time
from collections import defaultdict
from datetime import datetime

from .. import findings as finding_service
from .. import repo
from .. import reports as report_service
from ..db import q
from . import outages, pathanalysis, vm
from . import settings as settings_service

log = logging.getLogger(__name__)

MAX_PERIOD_S = 400 * 86400
RAW_DETAIL_S = 30 * 86400          # Rohdaten (1 s) liegen 30 Tage vor
CLUSTER_GAP_S = 60                 # Ausfälle eines Standorts mit höchstens 60 s Abstand = eine Störung
SHORT_S = 60                       # Kurzausfall
SERIES_POINTS = 480                # Punkte je Verlaufsgraph
MAX_INCIDENTS = 500                # Zeilen in der Störungsliste
MAX_ANOMALIES = 60
MAX_PATHS = 12
MAX_ROWS = 300                     # Hinweise, Meldungen

# Auffällige Zeiträume (Leitungsqualität)
LOSS_PCT = 1.0
JITTER_MS = 30.0
LATENCY_FACTOR = 2.0
LATENCY_MIN_RISE_MS = 15.0

SECTIONS = {
    "zeitstrahl": "Zeitstrahl und Tagesübersicht",
    "qualitaet": "Leitungsqualität und Schwankungen",
    "stoerungen": "Störungsliste",
    "pfad": "Pfadanalyse",
    "bandbreite": "Bandbreite und Sprachqualität",
    "kunde": "Kundenseitige Hinweise und Meldungen",
    "netzwerk": "Netzwerk (Scan)",
    "anhang": "Anhang: Messmethode",
}

LANES = (
    ("gateway", "Gateway / LAN"),
    ("wan", "Internet / WAN"),
    ("target", "Ziele"),
    ("probe", "Probe offline"),
    ("loss", "Paketverlust"),
)
LANE_OF = {"gateway": "gateway", "wan": "wan", "target": "target", "reference": "target", "probe": "probe",
           "loss": "loss"}

# Client-Hinweise, die auf den PC bzw. die Verkabelung beim Kunden zeigen
CUSTOMER_KINDS = {"cable_unplugged", "wifi_disconnected", "link_speed_changed", "link_speed_low", "link_flapping",
                  "driver_error", "nic_reset", "apipa", "no_gateway", "nic_errors"}

CATEGORIES = {
    "provider": {
        "title": "Internetanschluss / Provider",
        "text": "Das lokale Netz war erreichbar, die Störungen liegen auf dem Weg ins Internet.",
        "advice": "Störung beim Provider melden und diesen Bericht als Nachweis beilegen.",
    },
    "lan": {
        "title": "Lokales Netz / Router beim Kunden",
        "text": "Schon das eigene Gateway (Router) war gestört. Das Problem liegt vor dem Internetanschluss.",
        "advice": "Router, Switches, Verkabelung und Stromversorgung beim Kunden prüfen, bevor der Provider "
                  "eingeschaltet wird.",
    },
    "pc": {
        "title": "Einzelner PC / Probe",
        "text": "Betroffen war nur ein PC, andere PCs am selben Standort hatten zur gleichen Zeit keine Störung.",
        "advice": "Den betroffenen PC prüfen: Netzwerkkabel, Netzwerkkarte, Energiesparen und Treiber.",
    },
    "target": {
        "title": "Einzelnes Ziel / Gegenstelle",
        "text": "Internet und lokales Netz waren in Ordnung, nur einzelne Ziele waren nicht erreichbar.",
        "advice": "Die Gegenstelle bzw. deren Betreiber prüfen. Der Internetanschluss ist unauffällig.",
    },
    "none": {
        "title": "Keine erheblichen Störungen",
        "text": "Im Zeitraum gab es keine Ausfälle von Internet oder lokalem Netz.",
        "advice": "Keine Maßnahme nötig.",
    },
}


# -- Formatierung (auch vom PDF genutzt) ----------------------------------------
def fmt_ts(ts: int | float | None, seconds: bool = True) -> str:
    if ts is None:
        return "–"
    return datetime.fromtimestamp(int(ts)).strftime("%d.%m.%Y %H:%M:%S" if seconds else "%d.%m.%Y %H:%M")


def fmt_dur(seconds: int | float | None) -> str:
    """Dauer kurz und genau: „5 s“, „2 min 13 s“, „1 h 05 min“, „3 d 4 h“."""
    if seconds is None:
        return "–"
    s = max(int(round(seconds)), 0)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    if s < 86400:
        return f"{s // 3600} h {s % 3600 // 60:02d} min"
    return f"{s // 86400} d {s % 86400 // 3600} h"


def fmt_num(v: float | None, unit: str = "", digits: int | None = None) -> str:
    if v is None:
        return "–"
    if digits is None:
        digits = 2 if abs(v) < 10 else 1 if abs(v) < 100 else 0
    text = f"{v:.{digits}f}".replace(".", ",")
    return f"{text} {unit}".strip()


# -- Intervalle --------------------------------------------------------------
def union(spans) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for a, b in sorted(spans):
        if b <= a:
            continue
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def intersect_all(groups: list[list[tuple[int, int]]]) -> list[tuple[int, int]]:
    if not groups:
        return []
    cur = union(groups[0])
    for g in groups[1:]:
        cur = union(outages.intersect(cur, union(g)))
    return cur


def total(spans) -> int:
    return sum(b - a for a, b in spans)


# -- Ausfälle und Störungen ------------------------------------------------------
def load_outages(site_id: int | None, since: int, until: int) -> list[dict]:
    """Alle Ausfälle im Zeitraum, inklusive Folgestörungen (gekennzeichnet), auf den Zeitraum begrenzt."""
    items = outages.load(since, str(site_id) if site_id is not None else None, 0, include_consequences=True)
    out = []
    for o in items:
        if o.start >= until:
            continue
        end = o.end if o.end is not None else repo.now()
        out.append({
            "id": o.id, "cause": o.cause, "cause_label": o.cause_label, "probe": o.probe,
            "probe_name": o.probe_name, "site": o.site, "site_name": o.site_name, "target": o.target,
            "check_id": o.check_id, "start": o.start, "end": o.end, "ongoing": o.end is None,
            "duration": max(end - o.start, 0), "consequence_of": o.consequence_of, "summary": o.summary,
            # auf den Berichtszeitraum begrenzt, für Summen und Zeitstrahl
            "a": max(o.start, since), "b": max(min(end, until), max(o.start, since)),
        })
    # Rolle (Gateway, Referenz, Ziel) eines Paketverlusts steht nur in den Labels des Alarms
    loss_ids = [o["id"] for o in out if o["cause"] == "loss"]
    roles = {}
    for chunk in (loss_ids[i:i + 500] for i in range(0, len(loss_ids), 500)):
        marks = ", ".join("?" for _ in chunk)
        for r in q(f"SELECT id, labels FROM alert_events WHERE id IN ({marks})", chunk):
            roles[r["id"]] = (json.loads(r["labels"] or "{}")).get("role", "")
    for o in out:
        o["role"] = roles.get(o["id"], "")
    out.sort(key=lambda o: (o["start"], -outages.PRIORITY[o["cause"]]))
    return out


def cluster(items: list[dict], gap: int = CLUSTER_GAP_S) -> list[dict]:
    """Gleichzeitige oder dicht folgende Ausfälle eines Standorts zu einer Störung zusammenfassen."""
    by_site: dict[str, list[dict]] = defaultdict(list)
    for o in sorted(items, key=lambda o: o["start"]):
        by_site[o["site"]].append(o)
    groups: list[list[dict]] = []
    for lst in by_site.values():
        cur: list[dict] = []
        cur_end = 0
        for o in lst:
            o_end = o["start"] + o["duration"]
            if cur and o["start"] <= cur_end + gap:
                cur.append(o)
                cur_end = max(cur_end, o_end)
            else:
                if cur:
                    groups.append(cur)
                cur, cur_end = [o], o_end
        if cur:
            groups.append(cur)
    incidents = []
    for members in groups:
        main = [m for m in members if not m["consequence_of"]] or members
        primary = max(main, key=lambda m: (outages.PRIORITY[m["cause"]], m["duration"]))
        start = min(m["start"] for m in members)
        end = max(m["start"] + m["duration"] for m in members)
        probes = sorted({m["probe_name"] for m in members if m["probe"]})
        targets = sorted({m["target"] for m in members if m["target"] and m["cause"] not in ("probe", "wan")})
        causes = sorted({m["cause"] for m in members}, key=lambda c: -outages.PRIORITY[c])
        # Dauer = Zeit ohne Verbindung (Vereinigung), nicht die Spanne: zwei 5-s-Aussetzer mit 50 s Abstand
        # bleiben zwei kurze Aussetzer und werden nicht zu einer 60-s-Störung
        down = union((m["start"], m["start"] + m["duration"]) for m in members)
        ongoing = any(m["ongoing"] for m in members)
        incidents.append({
            "site": primary["site"], "site_name": primary["site_name"], "cause": primary["cause"],
            "cause_label": primary["cause_label"], "causes": causes,
            "cause_labels": [outages.CAUSES[c][0] for c in causes],
            "start": start, "end": None if ongoing else end, "ongoing": ongoing,
            "duration": total(down), "span": end - start, "parts": len(down),
            "longest_part": max((b - a for a, b in down), default=0),
            "short": not ongoing and max((b - a for a, b in down), default=0) < SHORT_S,
            "probes": probes, "probe_ids": sorted({m["probe"] for m in members if m["probe"]}),
            "targets": targets, "members": members,
            "consequences": sum(1 for m in members if m["consequence_of"]),
            "a": min(m["a"] for m in members), "b": max(m["b"] for m in members),
        })
    incidents.sort(key=lambda i: i["start"])
    for n, inc in enumerate(incidents, 1):
        inc["no"] = n
    return incidents


def _active_probes(probes: list[dict], site: str) -> list[dict]:
    return [p for p in probes if str(p["site_id"]) == site and p["status"] == "active"]


def scope_of(inc: dict, probes: list[dict]) -> str:
    """site = alle aktiven Probes des Standorts betroffen (oder nur eine vorhanden), single = nur eine von mehreren."""
    active = _active_probes(probes, inc["site"])
    if len(active) <= 1:
        return "site"
    affected = set(inc["probe_ids"])
    if len(affected) >= 2 or affected >= {str(p["id"]) for p in active}:
        return "site"
    return "single"


def site_down_spans(items: list[dict], probes: list[dict], site: str) -> list[tuple[int, int]]:
    """Zeit, in der am Standort kein PC ins Internet kam: alle aktiven Probes zugleich mit Gateway-, WAN-
    oder Offline-Störung. Mit nur einer Probe zählt ihre Störung allein."""
    active = _active_probes(probes, site)
    mine = [o for o in items if o["site"] == site and o["cause"] in outages.SEVERE]
    per_probe: dict[str, list] = defaultdict(list)
    for o in mine:
        per_probe[o["probe"]].append((o["a"], o["b"]))
    if len(active) <= 1:
        return union(s for spans in per_probe.values() for s in spans)
    return intersect_all([per_probe.get(str(p["id"]), []) for p in active])


# -- Messreihen (Leitungsqualität) ------------------------------------------------
def series_step(since: int, until: int) -> int:
    step = max((until - since) // SERIES_POINTS, 60)
    return int(math.ceil(step / 60) * 60)


def _pct(values: list[float], phi: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    pos = phi * (len(s) - 1)
    lo = int(pos)
    return s[lo] + (s[min(lo + 1, len(s) - 1)] - s[lo]) * (pos - lo)


def _mean(values) -> float | None:
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def _combine(series_list: list[list[tuple[int, float]]], how=None) -> list[tuple[int, float]]:
    """Mehrere Reihen (z. B. alle Internet-Referenzen) zu einer: Mittel je Zeitpunkt."""
    pts: dict[int, list[float]] = defaultdict(list)
    for s in series_list:
        for ts, v in s:
            pts[ts].append(v)
    fn = how or (lambda vs: sum(vs) / len(vs))
    return sorted((ts, fn(vs)) for ts, vs in pts.items())


def _check_stats(entry: dict, step: int) -> dict:
    s = entry["series"]
    avg = [v for _, v in s.get("avg", [])]
    loss = [v for _, v in s.get("loss", [])]
    return {
        "lat_avg": _mean(avg), "lat_p95": _pct(avg, 0.95),
        "lat_max": max((v for _, v in s.get("max", [])), default=None),
        "lat_min_p10": min((v for _, v in s.get("p10", [])), default=None),
        "loss_avg": _mean(loss),
        "loss_max": max((v for _, v in s.get("loss_max", s.get("loss", []))), default=None),
        "jitter_avg": _mean(v for _, v in s.get("jitter", [])),
        "jitter_max": max((v for _, v in s.get("jitter", [])), default=None),
        "loss_minutes": int(sum(v for _, v in s["loss_minutes"])) if "loss_minutes" in s else None,
        "lost_s": int(round(sum(v for _, v in s["lost_s"]))) if "lost_s" in s else None,
        "points": len(avg),
    }


def detect_anomalies(probe: dict, internet: dict, gateway: dict | None, step: int,
                     incidents: list[dict]) -> list[dict]:
    """Abschnitte mit hoher Latenz, Verlust oder Jitter ins Internet – mit Vergleich zum Gateway.

    ``internet``/``gateway``: {"avg": [(ts, v)], "loss": …, "jitter": …}; ein Wert bei ts gilt für (ts − step, ts].
    """
    avg = dict(internet.get("avg", []))
    loss = dict(internet.get("loss_max") or internet.get("loss", []))
    jitter = dict(internet.get("jitter", []))
    base = statistics.median(avg.values()) if avg else None
    gw = gateway or {}
    gw_avg = dict(gw.get("avg", []))
    gw_loss = dict(gw.get("loss_max") or gw.get("loss", []))
    gw_jit = dict(gw.get("jitter", []))
    gw_base = statistics.median(gw_avg.values()) if gw_avg else None
    lat_limit = max(base * LATENCY_FACTOR, base + LATENCY_MIN_RISE_MS) if base is not None else None

    flagged = []
    for ts in sorted(set(avg) | set(loss) | set(jitter)):
        kinds = set()
        if lat_limit is not None and (avg.get(ts) or 0) > lat_limit:
            kinds.add("latency")
        if (loss.get(ts) or 0) > LOSS_PCT:
            kinds.add("loss")
        if (jitter.get(ts) or 0) > JITTER_MS:
            kinds.add("jitter")
        if kinds:
            flagged.append((ts, kinds))
    periods: list[dict] = []
    for ts, kinds in flagged:
        if periods and ts - periods[-1]["last"] <= 2 * step:
            p = periods[-1]
            p["last"] = ts
            p["kinds"] |= kinds
            p["ts"].append(ts)
        else:
            periods.append({"first": ts, "last": ts, "kinds": set(kinds), "ts": [ts]})
    out = []
    for p in periods:
        ts_all = [t for t in sorted(set(avg) | set(loss) | set(jitter)) if p["first"] <= t <= p["last"]]
        start, end = p["first"] - step, p["last"]
        gw_vals_loss = [gw_loss[t] for t in ts_all if t in gw_loss]
        gw_vals_lat = [gw_avg[t] for t in ts_all if t in gw_avg]
        gw_vals_jit = [gw_jit[t] for t in ts_all if t in gw_jit]
        gw_lat_max = max(gw_vals_lat, default=None)
        if not gw_avg and not gw_loss:
            where, gw_state = "unklar", "kein Gateway-Check"
        else:
            gw_bad = ((max(gw_vals_loss, default=0) > LOSS_PCT / 2)
                      or (gw_base is not None and gw_lat_max is not None
                          and gw_lat_max > max(gw_base * LATENCY_FACTOR, gw_base + 10))
                      or max(gw_vals_jit, default=0) > JITTER_MS)
            where = "lan" if gw_bad else "provider"
            gw_state = "ebenfalls auffällig" if gw_bad else "sauber"
        during = any(i["a"] < end and i["b"] > start and i["probe_ids"] and str(probe["id"]) in i["probe_ids"]
                     for i in incidents)
        out.append({
            "probe_id": probe["id"], "probe_name": probe["hostname"], "site_name": probe["site_name"],
            "start": start, "end": end, "duration": end - start,
            "kinds": sorted(p["kinds"], key=["loss", "latency", "jitter"].index),
            "kind_label": ", ".join({"loss": "Verlust", "latency": "Latenz", "jitter": "Jitter"}[k]
                                    for k in sorted(p["kinds"], key=["loss", "latency", "jitter"].index)),
            "lat_max": max((avg[t] for t in ts_all if t in avg), default=None), "lat_base": base,
            "loss_max": max((loss[t] for t in ts_all if t in loss), default=None),
            "jitter_max": max((jitter[t] for t in ts_all if t in jitter), default=None),
            "gw_loss_max": max(gw_vals_loss, default=None), "gw_lat_max": gw_lat_max,
            "gw_state": gw_state, "where": where, "during_outage": during,
        })
    return out


def quality(probes: list[dict], since: int, until: int, incidents: list[dict], state: dict) -> list[dict]:
    """Je Probe: Verläufe Gateway vs. Internet, Kennzahlen je Check und auffällige Zeiträume."""
    step = series_step(since, until)
    out = []
    for p in probes:
        if not state["vm_ok"]:
            break
        try:
            data = vm.report_ping_series(p["id"], since, until, step)
        except vm.VMError as exc:
            log.warning("Messreihen für den Bericht nicht abrufbar: %s", exc)
            state["vm_ok"] = False
            state["notes"].append("Die Messdatenbank (VictoriaMetrics) war nicht erreichbar. Verläufe, "
                                  "Leitungsqualität und Hop-Werte fehlen in diesem Bericht.")
            break
        if not data:
            continue
        checks = []
        for cid, entry in sorted(data.items(), key=lambda kv: ({"gateway": 0, "reference": 1}.get(kv[1]["role"], 2),
                                                                kv[1]["target"])):
            checks.append({"check_id": cid, "role": entry["role"], "target": entry["target"],
                           "role_label": repo.CHECK_ROLES.get(entry["role"], entry["role"] or "Ziel"),
                           **_check_stats(entry, step)})
        gw_entries = [e for e in data.values() if e["role"] == "gateway"]
        ref_entries = [e for e in data.values() if e["role"] == "reference"]

        def merged(entries: list[dict], how=None) -> dict:
            keys = {k for e in entries for k in e["series"]}
            return {k: _combine([e["series"].get(k, []) for e in entries],
                                # Verlust gemittelt: eine einzelne gedrosselte Referenz ist noch kein Leitungsproblem
                                how=max if k in ("max", "p90") and how is None else how) for k in keys}

        gateway = merged(gw_entries) if gw_entries else None
        internet = merged(ref_entries) if ref_entries else None
        found = detect_anomalies(p, internet, gateway, step, incidents) if internet else []
        # Verlust nur während eines Ausfalls steht schon in der Störungsliste
        anomalies = [a for a in found if not (a["during_outage"] and a["kinds"] == ["loss"])]
        out.append({
            "probe_id": p["id"], "probe_name": p["hostname"], "site_name": p["site_name"], "step": step,
            "since": since, "until": until, "gateway": gateway, "internet": internet, "checks": checks,
            "anomalies": anomalies, "outage_loss_periods": len(found) - len(anomalies),
            "gateway_stats": _check_stats({"series": gateway}, step) if gateway else None,
            "internet_stats": _check_stats({"series": internet}, step) if internet else None,
        })
    return out


# -- Pfade ----------------------------------------------------------------------
def owner_guess(ip: str | None, hop: int) -> str:
    if not ip:
        return "keine Antwort"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unbekannt"
    if hop == 1 or addr.is_private:
        return "LAN / privat"
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return "Provider (CGNAT)"
    return "Provider / Internet"


def paths(probe_ids: list[int], since: int, until: int, state: dict) -> list[dict]:
    if not probe_ids:
        return []
    marks = ", ".join("?" for _ in probe_ids)
    pairs = q(f"SELECT r.probe_id, r.check_id, c.name AS check_name, c.target, p.hostname, s.name AS site_name, "
              f"MAX(r.ts) AS last_ts, COUNT(*) AS runs "
              f"FROM path_runs r JOIN probes p ON p.id = r.probe_id JOIN sites s ON s.id = p.site_id "
              f"LEFT JOIN checks c ON c.id = r.check_id "
              f"WHERE r.probe_id IN ({marks}) AND r.ts >= ? AND r.first_ts <= ? "
              f"GROUP BY r.probe_id, r.check_id, c.name, c.target, p.hostname, s.name "
              f"ORDER BY s.name, p.hostname, c.name LIMIT ?", (*probe_ids, since, until, MAX_PATHS))
    out = []
    for pr in pairs:
        runs = q("SELECT * FROM path_runs WHERE probe_id = ? AND check_id = ? AND ts >= ? AND first_ts <= ? "
                 "ORDER BY ts DESC, id DESC", (pr["probe_id"], pr["check_id"], since, until))
        current = json.loads(runs[0]["hops"]) if runs else []
        changes = sum(1 for r in runs if r["changed"] and since <= r["first_ts"] <= until)
        measured = {}
        if state["vm_ok"]:
            try:
                measured = vm.report_hop_table(pr["probe_id"], pr["check_id"], since, until)
            except vm.VMError as exc:
                log.warning("Hop-Werte für den Bericht nicht abrufbar: %s", exc)
                state["vm_ok"] = False
        trace = {h["hop"]: h for h in current}
        rows = []
        for n in sorted(set(trace) | set(measured)):
            m = measured.get(n, {})
            ip = m.get("ip") or (trace.get(n) or {}).get("ip")
            rows.append({"hop": n, "ip": ip, "other_ips": m.get("other_ips", []), "loss": m.get("loss"),
                         "avg": m.get("avg"), "max": m.get("max"), "jitter": m.get("jitter"),
                         "owner": owner_guess(ip, n), "segment": pathanalysis.segment(ip, n)})
        analysis = pathanalysis.analyze(rows, pr["target"] or "")
        for r in rows:
            r["mark"] = analysis.hop_marks.get(r["hop"], "")
        origin = next((f for f in analysis.findings
                       if f.level in ("warn", "bad") and f.hop and "verlust" in f.text.lower()),
                      None)
        origin_row = next((r for r in rows if origin and r["hop"] == origin.hop), None)
        out.append({
            "probe_id": pr["probe_id"], "probe_name": pr["hostname"], "site_name": pr["site_name"],
            "check_id": pr["check_id"], "check_name": pr["check_name"] or f"Pfad {pr['check_id']}",
            "target": pr["target"] or "", "rows": rows, "has_values": bool(measured),
            "findings": [{"level": f.level, "text": f.text} for f in analysis.findings],
            "verdict": analysis.verdict, "changes": changes, "runs": len(runs),
            "paths": len({r["path_hash"] for r in runs}), "last_ts": pr["last_ts"],
            "loss_origin": ({"hop": origin_row["hop"], "ip": origin_row["ip"], "owner": origin_row["owner"],
                             "where": "lan" if origin_row["owner"].startswith("LAN") else "provider"}
                            if origin_row else None),
        })
    return out


# -- Bandbreite und Sprache ---------------------------------------------------------
def _stats(values: list[float]) -> dict | None:
    if not values:
        return None
    s = sorted(values)
    return {"count": len(s), "min": s[0], "max": s[-1], "avg": sum(s) / len(s), "median": s[len(s) // 2]}


def bandwidth(probe_ids: list[int], since: int, until: int) -> list[dict]:
    if not probe_ids:
        return []
    marks = ", ".join("?" for _ in probe_ids)
    rows = q(f"SELECT b.*, c.name AS check_name, c.type AS check_type, c.params, p.hostname, s.name AS site_name "
             f"FROM bandwidth_runs b JOIN probes p ON p.id = b.probe_id JOIN sites s ON s.id = p.site_id "
             f"LEFT JOIN checks c ON c.id = b.check_id "
             f"WHERE b.probe_id IN ({marks}) AND b.ts >= ? AND b.ts <= ? ORDER BY b.ts", (*probe_ids, since, until))
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        groups[(r["site_name"], r["hostname"], r["check_id"], r["direction"])].append(r)
    out = []
    for (site_name, host, check_id, direction), runs in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1],
                                                                                                kv[0][2], kv[0][3])):
        first = runs[0]
        params = json.loads(first["params"] or "{}") if first["params"] else {}
        thr = float(params.get("min_down_mbps" if direction == "down" else "min_up_mbps") or 0)
        ok = [r["mbps"] for r in runs if r["mbps"] is not None and not r["error"]]
        out.append({
            "site_name": site_name, "probe_name": host, "check_name": first["check_name"] or str(check_id),
            "kind": first["kind"], "direction": direction, "direction_label": "Download" if direction == "down"
            else "Upload", "peer": first["peer"] or "", "stats": _stats(ok), "threshold": thr or None,
            "below": sum(1 for v in ok if thr and v < thr), "errors": sum(1 for r in runs if r["error"]),
            "runs": len(runs),
        })
    return out


def voice(probe_ids: list[int], since: int, until: int) -> list[dict]:
    if not probe_ids:
        return []
    marks = ", ".join("?" for _ in probe_ids)
    rows = q(f"SELECT r.*, c.name AS check_name, c.params, p.hostname, s.name AS site_name "
             f"FROM rtp_runs r JOIN probes p ON p.id = r.probe_id JOIN sites s ON s.id = p.site_id "
             f"LEFT JOIN checks c ON c.id = r.check_id "
             f"WHERE r.probe_id IN ({marks}) AND r.ts >= ? AND r.ts <= ? ORDER BY r.ts", (*probe_ids, since, until))
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        groups[(r["site_name"], r["hostname"], r["check_id"])].append(r)
    out = []
    for (site_name, host, check_id), runs in sorted(groups.items()):
        first = runs[0]
        params = json.loads(first["params"] or "{}") if first["params"] else {}
        min_mos = float(params.get("min_mos", 3.6) or 0)
        good = [r for r in runs if not r["error"] and r["mos"] is not None]
        out.append({
            "site_name": site_name, "probe_name": host, "check_name": first["check_name"] or str(check_id),
            "peer": first["peer"] or "", "codec": first["codec"] or "", "runs": len(runs),
            "errors": len(runs) - len(good), "min_mos": min_mos or None,
            "mos": _stats([r["mos"] for r in good]),
            "below": sum(1 for r in good if min_mos and r["mos"] < min_mos),
            "loss_avg": _mean(r["loss_pct"] for r in good), "jitter_max": max((r["jitter_ms"] for r in good
                                                                                if r["jitter_ms"] is not None),
                                                                               default=None),
            "rtt_avg": _mean(r["rtt_ms"] for r in good),
        })
    return out


# -- Kundenseite -------------------------------------------------------------------
def client_findings(site_id: int | None, since: int, until: int) -> list[dict]:
    sql = ("SELECT f.*, p.hostname AS probe_name, s.name AS site_name FROM client_findings f "
           "JOIN probes p ON p.id = f.probe_id LEFT JOIN sites s ON s.id = COALESCE(f.site_id, p.site_id) "
           "WHERE f.detected_at <= ? AND (f.resolved_at IS NULL OR f.resolved_at >= ?)")
    params: list = [until, since]
    if site_id is not None:
        sql += " AND COALESCE(f.site_id, p.site_id) = ?"
        params.append(site_id)
    rows = q(sql + " ORDER BY f.detected_at, f.id LIMIT ?", (*params, MAX_ROWS + 1))
    out = []
    for r in rows:
        end = r["resolved_at"] or min(repo.now(), until)
        out.append({
            "id": r["id"], "probe_id": r["probe_id"], "probe_name": r["probe_name"], "site_name": r["site_name"] or "",
            "kind": r["kind"], "kind_label": finding_service.KINDS.get(r["kind"], r["title"]), "title": r["title"],
            "message": r["message"] or "", "severity": r["severity"],
            "severity_label": finding_service.SEVERITIES.get(r["severity"], r["severity"]),
            "adapter": r["adapter"] or "", "detected_at": r["detected_at"], "resolved_at": r["resolved_at"],
            "duration": max(int(end) - int(r["detected_at"]), 0), "customer_side": r["kind"] in CUSTOMER_KINDS,
        })
    return out


def user_reports(site_id: int | None, since: int, until: int) -> list[dict]:
    rows = report_service.search(None, site_id, None, since, until, limit=MAX_ROWS + 1)
    rows.reverse()
    return [{"id": r["id"], "ts": r["occurred_at"], "probe_name": r["probe_label"], "site_name": r.get("site_name")
             or "", "category_label": r["category_label"], "duration_label": r["duration_label"],
             "description": r.get("description") or "", "user": r.get("reported_user") or "",
             "status_label": r["status_label"]} for r in rows]


def netscan_section(site_id: int | None, since: int, until: int, state: dict) -> dict | None:
    try:
        from . import netscan  # kommt mit 1.0 (Netzwerkscan)
        return netscan.report_section(site_id, since, until)
    except (ImportError, AttributeError):
        return None
    except Exception as exc:  # noqa: BLE001 – der Bericht soll trotzdem entstehen
        log.exception("Netzwerkscan für den Bericht nicht lesbar")
        state["notes"].append(f"Netzwerkscan nicht auswertbar: {exc}")
        return None


# -- Tagesübersicht und Uhrzeiten ----------------------------------------------------
WEEKDAYS = ("Mo", "Di", "Mi", "Do", "Fr", "Sa", "So")


def daily(incidents: list[dict], down: list[tuple[int, int]], since: int, until: int) -> list[dict]:
    days = []
    d = datetime.fromtimestamp(since).replace(hour=0, minute=0, second=0, microsecond=0)
    while True:
        a = int(d.timestamp())
        if a >= until:
            break
        # nächster Tagesbeginn über 26 h und Abrunden: stimmt auch an Tagen mit Zeitumstellung
        b = int(datetime.fromtimestamp(a + 26 * 3600).replace(hour=0, minute=0, second=0).timestamp())
        lo, hi = max(a, since), min(b, until)
        mine = [i for i in incidents if lo <= i["start"] < hi]
        days.append({
            "day": a, "label": f"{WEEKDAYS[d.weekday()]} {d.strftime('%d.%m.')}",
            "count": len(mine), "short": sum(1 for i in mine if i["short"]),
            "severe": sum(1 for i in mine if i["cause"] in outages.SEVERE),
            "down_s": total(outages.intersect(down, [(lo, hi)])),
            "longest": max((i["duration"] for i in mine), default=0),
        })
        d = datetime.fromtimestamp(b)
    return days


def hours(incidents: list[dict]) -> list[int]:
    out = [0] * 24
    for i in incidents:
        out[datetime.fromtimestamp(i["start"]).hour] += 1
    return out


# -- Einschätzung ----------------------------------------------------------------------
def _w(duration: int) -> float:
    return 1 + min(duration / 600, 2)


def verdict(incidents: list[dict], probes: list[dict], quality_items: list[dict], path_items: list[dict],
            finding_items: list[dict], vm_ok: bool) -> dict:
    """Regelbasierte Einschätzung, wo das Problem liegt.

    Punkte je Kategorie:
    * Internet/WAN-Störung, Gateway erreichbar, ganzer Standort betroffen -> Provider
    * Gateway-Störung (alle PCs) -> lokales Netz; nur ein PC von mehreren -> einzelner PC
    * ganzer Standort offline -> Provider (halbes Gewicht: auch Strom möglich)
    * nur einzelne Ziele -> Ziel
    * auffällige Zeiträume: Gateway sauber/Internet schlecht -> Provider, Gateway auch schlecht -> lokales Netz
    * Pfadanalyse: Verlust beginnt im Providernetz bzw. im LAN
    * Client-Hinweise (Kabel, Link, Treiber) -> einzelner PC
    """
    score = defaultdict(float)
    ev: dict[str, dict] = defaultdict(lambda: defaultdict(lambda: {"n": 0, "s": 0}))

    def add(cat: str, key: str, points: float, seconds: int = 0) -> None:
        score[cat] += points
        ev[cat][key]["n"] += 1
        ev[cat][key]["s"] += seconds

    for inc in incidents:
        sc = scope_of(inc, probes)
        c, d = inc["cause"], inc["duration"]
        if c == "wan":
            add("provider" if sc == "site" else "pc", "wan" if sc == "site" else "wan_single", _w(d), d)
        elif c == "gateway":
            add("lan" if sc == "site" else "pc", "gateway" if sc == "site" else "gateway_single", _w(d), d)
        elif c == "probe":
            if sc == "site":
                add("provider", "offline", 0.5 * _w(d), d)
            else:
                add("pc", "offline_single", 0.3 * _w(d), d)
        elif c == "loss":
            target_role = _loss_role(inc)
            cat = {"gateway": "lan", "reference": "provider"}.get(target_role, "target")
            add(cat, f"loss_{cat}", 0.7 * _w(d), d)
        else:
            add("target", "target", 0.5, d)
    for qi in quality_items:
        for a in qi["anomalies"]:
            if a["during_outage"] and "loss" in a["kinds"] and len(a["kinds"]) == 1:
                continue  # Verlust während eines Ausfalls ist schon gezählt
            if a["where"] == "provider":
                add("provider", "anomaly", 0.5, a["duration"])
            elif a["where"] == "lan":
                add("lan", "anomaly", 0.5, a["duration"])
    for cat in ("provider", "lan"):
        if ev[cat]["anomaly"]["n"] > 8:  # höchstens 4 Punkte aus Schwankungen
            score[cat] -= 0.5 * (ev[cat]["anomaly"]["n"] - 8)
    for pi in path_items:
        o = pi["loss_origin"]
        if o:
            add(o["where"], "path", 2.0)
    customer = [f for f in finding_items if f["customer_side"]]
    for _ in customer[:6]:
        add("pc", "finding", 0.5)
    if len(customer) > 6:
        ev["pc"]["finding"]["n"] = len(customer)

    totals = sum(max(v, 0) for v in score.values())
    ranked = sorted(((v, k) for k, v in score.items() if v > 0), reverse=True)
    if totals < 0.5 or not ranked:
        cat, conf = "none", "hoch" if vm_ok else "niedrig"
        share = 1.0
    else:
        top, cat = ranked[0]
        share = top / totals
        if share >= 0.7 and top >= 3:
            conf = "hoch"
        elif share >= 0.5 and top >= 1.5:
            conf = "mittel"
        else:
            conf = "niedrig"
        if not vm_ok and conf == "hoch":
            conf = "mittel"
    bullets = _bullets(cat, ev, incidents, probes, path_items, customer, vm_ok)
    second = None
    if cat != "none" and len(ranked) > 1 and ranked[1][0] >= 0.25 * totals:
        second = {"key": ranked[1][1], "title": CATEGORIES[ranked[1][1]]["title"]}
        bullets.append(f"Daneben gibt es Hinweise auf: {second['title']}.")
    return {"key": cat, **CATEGORIES[cat], "confidence": conf, "share": share, "bullets": bullets[:6],
            "second": second, "scores": {k: round(v, 2) for k, v in score.items()}}


def _loss_role(inc: dict) -> str:
    return next((m.get("role") or "" for m in inc["members"] if m["cause"] == "loss"), "")


def _bullets(cat: str, ev: dict, incidents: list[dict], probes: list[dict], path_items: list[dict],
             customer: list[dict], vm_ok: bool) -> list[str]:
    e = ev[cat]
    out = []
    if cat == "provider":
        if e["wan"]["n"]:
            out.append(f"{e['wan']['n']} × Internet gestört, das Gateway war dabei erreichbar "
                       f"(zusammen {fmt_dur(e['wan']['s'])}). Alle Internet-Referenzen fielen gleichzeitig aus.")
        if e["offline"]["n"]:
            out.append(f"{e['offline']['n']} × war der ganze Standort offline (alle PCs zugleich, zusammen "
                       f"{fmt_dur(e['offline']['s'])}). Ursache kann die Leitung oder der Strom sein.")
        if e["anomaly"]["n"]:
            out.append(f"{e['anomaly']['n']} auffällige Zeiträume mit Verlust, Latenz oder Jitter nur ins "
                       "Internet. Die Verbindung zum Gateway war zur gleichen Zeit sauber.")
        if e["loss_provider"]["n"]:
            out.append(f"{e['loss_provider']['n']} × starker Paketverlust zu Internet-Referenzen.")
    elif cat == "lan":
        if e["gateway"]["n"]:
            out.append(f"{e['gateway']['n']} × war das eigene Gateway (Router) nicht erreichbar "
                       f"(zusammen {fmt_dur(e['gateway']['s'])}).")
        if e["anomaly"]["n"]:
            out.append(f"{e['anomaly']['n']} auffällige Zeiträume, in denen schon die Verbindung zum Gateway "
                       "Verlust oder hohe Latenz zeigte.")
        if e["loss_lan"]["n"]:
            out.append(f"{e['loss_lan']['n']} × starker Paketverlust schon zum Gateway.")
    elif cat == "pc":
        single = e["wan_single"]["n"] + e["gateway_single"]["n"] + e["offline_single"]["n"]
        if single:
            out.append(f"{single} Störungen betrafen nur einen PC, andere PCs am Standort waren zur gleichen Zeit "
                       "ungestört.")
        if customer:
            kinds = sorted({f["kind_label"] for f in customer})
            out.append(f"{len(customer)} Hinweise der PCs selbst: {', '.join(kinds[:4])}.")
    elif cat == "target":
        n = e["target"]["n"] + e["loss_target"]["n"]
        names = sorted({t for i in incidents if i["cause"] in ("target", "reference", "loss") for t in i["targets"]})
        out.append(f"{n} Störungen betrafen nur einzelne Ziele ({', '.join(names[:4]) or 'unbekannt'}). "
                   "Gateway und Internet waren dabei erreichbar.")
    else:
        out.append("Keine Ausfälle von Internet, Gateway oder Standort im Zeitraum.")
        if incidents:
            out.append(f"{len(incidents)} kleinere Ereignisse ohne Bedeutung für den Anschluss (siehe Störungsliste).")
    for pi in path_items:
        o = pi["loss_origin"]
        if o and o["where"] == cat:
            out.append(f"Pfad zu {pi['target']} ({pi['probe_name']}): Verlust beginnt ab Hop {o['hop']} "
                       f"({o['ip']}) – Bereich {o['owner']}.")
            break
    pattern = time_pattern(incidents)
    if pattern and cat != "none":
        out.append(pattern)
    if not vm_ok:
        out.append("Messreihen fehlen (Messdatenbank nicht erreichbar). Die Einschätzung beruht nur auf den Alarmen.")
    return out


def time_pattern(incidents: list[dict], min_count: int = 5) -> str | None:
    """Häufung zu einer Tageszeit: mindestens die Hälfte der schweren Störungen in einem 4-h-Fenster an 3+ Tagen."""
    severe = [i for i in incidents if i["cause"] in outages.SEVERE]
    if len(severe) < min_count:
        return None
    best = None
    for h in range(24):
        hits = [i for i in severe if (datetime.fromtimestamp(i["start"]).hour - h) % 24 < 4]
        days = {datetime.fromtimestamp(i["start"]).date() for i in hits}
        if len(hits) * 2 >= len(severe) and len(days) >= 3 and (best is None or len(hits) > best[1]):
            best = (h, len(hits), len(days))
    if best is None:
        return None
    h, n, days = best
    return (f"Häufung zur gleichen Tageszeit: {n} von {len(severe)} Störungen begannen zwischen {h:02d}:00 und "
            f"{(h + 4) % 24:02d}:00 Uhr (an {days} Tagen).")


# -- Gesamt --------------------------------------------------------------------------
def collect(site_id: int | None, since: int, until: int, sections: list[str] | None = None,
            meta: dict | None = None) -> dict:
    """Alle Daten für den Bericht. ``sections`` = Schlüssel aus SECTIONS (None = alle)."""
    started = time.monotonic()
    sections = [s for s in (sections if sections is not None else SECTIONS) if s in SECTIONS]
    state = {"vm_ok": True, "notes": []}
    sites = q("SELECT * FROM sites WHERE id = ? ORDER BY name", (site_id,)) if site_id is not None \
        else q("SELECT * FROM sites ORDER BY name")
    site_ids = [s["id"] for s in sites]
    probes = []
    if site_ids:
        marks = ", ".join("?" for _ in site_ids)
        probes = q(f"SELECT p.id, p.hostname, p.site_id, p.status, p.kind, p.created_at, p.last_seen, "
                   f"s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id "
                   f"WHERE p.site_id IN ({marks}) ORDER BY s.name, p.hostname", site_ids)
    # Probes, die im Zeitraum gar nicht existierten, nicht auswerten
    probes = [p for p in probes if (p["created_at"] or 0) <= until]
    probe_ids = [p["id"] for p in probes]

    items = load_outages(site_id, since, until)
    if site_id is None:
        items = [o for o in items if o["site"] in {str(s) for s in site_ids}]
    incidents = cluster(items)

    # Verfügbarkeit je Standort
    site_rows, down_all = [], []
    for s in sites:
        begin = max(since, s["created_at"] or since)
        span = max(until - begin, 0)
        down = [(max(a, begin), b) for a, b in site_down_spans(items, probes, str(s["id"])) if b > begin]
        down_all += down
        mine = [i for i in incidents if i["site"] == str(s["id"])]
        site_rows.append({
            "id": s["id"], "name": s["name"], "customer_no": s.get("customer_no") or "",
            "description": s.get("description") or "", "probes": len(_active_probes(probes, str(s["id"]))),
            "span": span, "down_s": total(down), "availability": 100 * (1 - total(down) / span) if span else None,
            "incidents": len(mine), "short": sum(1 for i in mine if i["short"]),
        })
    span_sum = sum(r["span"] for r in site_rows)
    down_sum = sum(r["down_s"] for r in site_rows)

    quality_items = quality(probes, since, until, incidents, state) if probes else []
    path_items = paths(probe_ids, since, until, state)
    finding_items = client_findings(site_id, since, until)
    report_items = user_reports(site_id, since, until)
    if site_id is None:
        allowed = {s["name"] for s in sites}
        finding_items = [f for f in finding_items if f["site_name"] in allowed or not f["site_name"]]

    severe = [i for i in incidents if i["cause"] in outages.SEVERE]
    gw_loss = _mean(qi["gateway_stats"]["loss_avg"] for qi in quality_items if qi["gateway_stats"])
    inet = [qi["internet_stats"] for qi in quality_items if qi["internet_stats"]]
    lat_all = [v for qi in quality_items if qi["internet"] for _, v in qi["internet"].get("avg", [])]
    kpis = {
        "availability": 100 * (1 - down_sum / span_sum) if span_sum else None,
        "down_s": down_sum,
        "incidents": len(incidents), "severe": len(severe),
        "short": sum(1 for i in incidents if i["short"]),
        "longest": max(incidents, key=lambda i: i["duration"]) if incidents else None,
        "outage_s": total(union((i["a"], i["b"]) for i in incidents)),
        "loss_gateway": gw_loss,
        "loss_internet": _mean(s["loss_avg"] for s in inet),
        "latency_avg": _mean(lat_all), "latency_p95": _pct(lat_all, 0.95),
        "jitter_avg": _mean(s["jitter_avg"] for s in inet),
        "loss_minutes": sum(s["loss_minutes"] or 0 for s in inet) if any(s["loss_minutes"] is not None
                                                                         for s in inet) else None,
        "anomalies": sum(len(qi["anomalies"]) for qi in quality_items),
        "reports": len(report_items), "findings": sum(1 for f in finding_items if f["customer_side"]),
    }

    overall = verdict(incidents, probes, quality_items, path_items, finding_items, state["vm_ok"])
    per_site = []
    if len(sites) > 1:
        for s in sites:
            sid = str(s["id"])
            v = verdict([i for i in incidents if i["site"] == sid], probes,
                        [qi for qi in quality_items if qi["site_name"] == s["name"]],
                        [pi for pi in path_items if pi["site_name"] == s["name"]],
                        [f for f in finding_items if f["site_name"] == s["name"]], state["vm_ok"])
            per_site.append({"site": s["name"], **v})

    rules = repo.alert_rules()
    timeline = {
        "lanes": [{"key": k, "label": label} for k, label in LANES],
        "items": [{"lane": LANE_OF[o["cause"]], "a": o["a"], "b": o["b"], "consequence": bool(o["consequence_of"])}
                  for o in items],
        "reports": [r["ts"] for r in report_items],
        "findings": [f["detected_at"] for f in finding_items if f["customer_side"] and f["detected_at"] >= since],
    }
    netscan = netscan_section(site_id, since, until, state) if "netzwerk" in sections else None
    if since < repo.now() - RAW_DETAIL_S:
        state["notes"].append("Ein Teil des Zeitraums liegt mehr als 30 Tage zurück. Für diese Zeit sind nur noch "
                              "1-Minuten-Werte gespeichert. Ausfälle bleiben sekundengenau, wenn sie damals "
                              "nachgerechnet wurden.")
    meta = dict(meta or {})
    return {
        "meta": {
            "customer": meta.get("customer") or "", "author": meta.get("author") or "",
            "remark": meta.get("remark") or "", "generated_at": repo.now(),
            "since": since, "until": until, "site_id": site_id,
            "site_label": sites[0]["name"] if site_id is not None and sites else "Alle Standorte",
            "customer_no": (sites[0].get("customer_no") or "") if site_id is not None and sites else "",
            "timezone": time.strftime("%Z") or "Ortszeit des Servers",
        },
        "sections": sections,
        "sites": site_rows, "probes": probes,
        "kpis": kpis, "verdict": overall, "site_verdicts": per_site,
        "incidents": incidents, "outages": items,
        "timeline": timeline,
        "daily": daily(incidents, union(down_all), since, until), "hours": hours(incidents),
        "quality": quality_items, "paths": path_items,
        "bandwidth": bandwidth(probe_ids, since, until), "voice": voice(probe_ids, since, until),
        "findings": finding_items, "reports": report_items, "netscan": netscan,
        "method": {
            "target_down_s": (rules.get("target_down") or {}).get("threshold", 5),
            "wan_down_s": (rules.get("wan_down") or {}).get("threshold", 5),
            "probe_offline_s": (rules.get("probe_offline") or {}).get("threshold", 120),
            "loss_warn": (rules.get("packet_loss_warning") or {}).get("threshold", 2),
            "loss_crit": (rules.get("packet_loss_critical") or {}).get("threshold", 10),
            "outage_min_s": settings_service.get()["outage_min_s"],
            "step": series_step(since, until), "cluster_gap": CLUSTER_GAP_S,
        },
        "vm_ok": state["vm_ok"], "notes": state["notes"],
        "build_s": round(time.monotonic() - started, 2),
    }
