"""Zustand aller Checks einer Probe – Ping, Pfad, iperf3, WAN und Sprache in einer gemeinsamen Bewertung.

Die Übersicht, die Standort- und die Probe-Seite zählen damit dieselben Zustände, und
„Messungen mit Problemen“ listet jede Messung, die gerade nicht funktioniert:

=========  ==========================================================================
ok         Messung läuft und ist unauffällig
warn       Messung läuft, aber auffällig (Verlust, Ziel im Traceroute nicht erreicht,
           Bandbreite oder MOS unter Schwellwert)
down       Messung schlägt fehl (Ziel antwortet nicht, iperf3/Speedtest-/Sprachtest-Fehler)
stale      Messung bleibt aus (keine aktuellen Werte, geplante Messung überfällig)
waiting    noch kein Ergebnis, aber auch noch nicht fällig (neu angelegt, nur manuell)
=========  ==========================================================================
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .. import checktypes, httperrors, repo, schedule
from ..db import q

STATE_LABELS = {"ok": "ok", "warn": "auffällig", "down": "gestört", "stale": "keine Daten", "waiting": "wartet"}
PROBLEM_STATES = ("down", "warn", "stale")
KIND_LABELS = {"ping": "Ping", "path": "Pfad", "iperf": "iperf3", "speedtest": "WAN", "rtp": "Sprache",
               "netscan": "Netzwerk"}
# so lange darf ein Dauerping ohne Wert bleiben, bevor er als „keine Daten“ gilt
PING_STALE_S = 180
LOSS_WARN_PCT = 2


@dataclass
class CheckState:
    check: dict
    state: str
    detail: str = ""
    ts: int | None = None
    values: dict = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return self.check["type"]

    @property
    def label(self) -> str:
        return STATE_LABELS[self.state]

    @property
    def problem(self) -> bool:
        return self.state in PROBLEM_STATES


def latest_runs(probe_ids: list[int] | None = None) -> tuple[dict, dict]:
    """Letzter Pfad je (Probe, Check) und letzte Bandbreitenmessung je (Probe, Check, Richtung).

    Der letzte Sprachtest steht mit Richtung ``rtp`` bei den Bandbreitenmessungen.
    """
    where, params = "", ()
    if probe_ids is not None:
        if not probe_ids:
            return {}, {}
        where = f" WHERE probe_id IN ({','.join('?' * len(probe_ids))})"
        params = tuple(probe_ids)
    paths = {(r["probe_id"], r["check_id"]): r for r in q(
        "SELECT p.* FROM path_runs p JOIN (SELECT MAX(id) AS id FROM path_runs" + where +
        " GROUP BY probe_id, check_id) m ON m.id = p.id", params)}
    bandwidth: dict = {}
    for r in q("SELECT b.* FROM bandwidth_runs b JOIN (SELECT MAX(id) AS id FROM bandwidth_runs" + where +
               " GROUP BY probe_id, check_id, direction) m ON m.id = b.id", params):
        bandwidth[(r["probe_id"], r["check_id"], r["direction"])] = r
    for r in q("SELECT r.* FROM rtp_runs r JOIN (SELECT MAX(id) AS id FROM rtp_runs" + where +
               " GROUP BY probe_id, check_id) m ON m.id = r.id", params):
        bandwidth[(r["probe_id"], r["check_id"], "rtp")] = r
    for r in q("SELECT r.* FROM netscan_runs r JOIN (SELECT MAX(id) AS id FROM netscan_runs" + where +
               " GROUP BY probe_id, check_id) m ON m.id = r.id", params):
        bandwidth[(r["probe_id"], r["check_id"], "netscan")] = r
    return paths, bandwidth


def _ping_state(c: dict, v: dict | None, now: int) -> CheckState:
    if not v or v.get("up") is None:
        age = now - int(c.get("created_at") or 0)
        if age < PING_STALE_S:
            return CheckState(c, "waiting", "neu angelegt, erste Werte folgen")
        return CheckState(c, "stale", "seit über 3 min kein Messwert")
    vals = {"rtt": v.get("rtt"), "loss": v.get("loss")}
    if v["up"] == 0:
        return CheckState(c, "down", "Ziel antwortet nicht", values=vals)
    if (v.get("loss") or 0) > LOSS_WARN_PCT:
        return CheckState(c, "warn", f"Paketverlust {v['loss']:.1f} % (5 min)", values=vals)
    return CheckState(c, "ok", values=vals)


def _path_state(c: dict, run: dict | None, now: int) -> CheckState:
    params = checktypes.merged("path", json.loads(c["params"] or "{}"))
    trace_s = int(params["trace_interval_min"]) * 60
    if run is None:
        if now - int(c.get("created_at") or 0) < 300:
            return CheckState(c, "waiting", "erster Traceroute läuft")
        return CheckState(c, "stale", "noch kein Traceroute-Ergebnis")
    hops = len(json.loads(run["hops"] or "[]"))
    vals = {"hops": hops, "reached": bool(run["reached"])}
    if now - int(run["ts"]) > 3 * trace_s + 300:
        return CheckState(c, "stale", f"letzter Traceroute vor {(now - int(run['ts'])) // 60} min", run["ts"], vals)
    if not run["reached"]:
        return CheckState(c, "warn", f"Ziel im Traceroute nicht erreicht ({hops} Hops)", run["ts"], vals)
    return CheckState(c, "ok", f"{hops} Hops", run["ts"], vals)


def _bandwidth_state(probe: dict, c: dict, runs: dict, now: int) -> CheckState:
    params = checktypes.merged(c["type"], json.loads(c["params"] or "{}"))
    params["offset_min"] = repo._schedule_offset(probe["id"], c["id"], params["schedule_min"], params["offset_min"])
    down, up = runs.get("down"), runs.get("up")
    vals = {"down": down, "up": up}
    latest = max((r for r in (down, up) if r), key=lambda r: r["ts"], default=None)
    overdue = schedule.overdue_since(params, latest["ts"] if latest else None, int(c.get("created_at") or 0), now)
    if latest is None:
        if overdue:
            return CheckState(c, "stale", "geplante Messung ist ausgeblieben", values=vals)
        plan = "wartet auf die erste geplante Messung" if params["schedule_min"] else "nur manuell, noch nicht gemessen"
        return CheckState(c, "waiting", plan, values=vals)
    # nur die Richtungen der letzten Messung bewerten (eine Richtung kann abgeschaltet worden sein)
    current = [r for r in (down, up) if r and latest["ts"] - r["ts"] <= 600]
    errors = [r for r in current if r["error"] or r["mbps"] is None]
    if errors:
        e = errors[0]
        arrow = "↓" if e["direction"] == "down" else "↑"
        return CheckState(c, "down", f"{arrow} {httperrors.explain(e['error']) or 'kein Ergebnis'}", latest["ts"], vals)
    low = []
    for r in current:
        limit = params.get("min_down_mbps" if r["direction"] == "down" else "min_up_mbps") or 0
        if limit and r["mbps"] < limit:
            low.append(f"{'↓' if r['direction'] == 'down' else '↑'} {r['mbps']:.1f} < {limit:g} Mbit/s")
    if overdue:
        return CheckState(c, "stale", f"geplante Messung überfällig, letzte vor {(now - latest['ts']) // 3600} h",
                          latest["ts"], vals)
    if low:
        return CheckState(c, "warn", "unter Schwellwert: " + ", ".join(low), latest["ts"], vals)
    return CheckState(c, "ok", "", latest["ts"], vals)


def _rtp_state(probe: dict, c: dict, run: dict | None, now: int) -> CheckState:
    params = checktypes.merged("rtp", json.loads(c["params"] or "{}"))
    params["offset_min"] = repo._schedule_offset(probe["id"], c["id"], params["schedule_min"], params["offset_min"])
    vals = {"rtp": run}
    overdue = schedule.overdue_since(params, run["ts"] if run else None, int(c.get("created_at") or 0), now)
    if run is None:
        if overdue:
            return CheckState(c, "stale", "geplanter Sprachtest ist ausgeblieben", values=vals)
        plan = "wartet auf den ersten geplanten Test" if params["schedule_min"] else "nur manuell, noch nicht gemessen"
        return CheckState(c, "waiting", plan, values=vals)
    if run["error"] or run["mos"] is None:
        return CheckState(c, "down", run["error"] or "kein Ergebnis", run["ts"], vals)
    detail = f"MOS {run['mos']:.2f}"
    if overdue:
        return CheckState(c, "stale", f"geplanter Test überfällig, letzter vor {(now - run['ts']) // 60} min",
                          run["ts"], vals)
    if params["min_mos"] and run["mos"] < params["min_mos"]:
        return CheckState(c, "warn", f"{detail} unter {params['min_mos']:g}", run["ts"], vals)
    return CheckState(c, "ok", detail, run["ts"], vals)


def _netscan_state(probe: dict, c: dict, run: dict | None, now: int) -> CheckState:
    params = checktypes.merged("netscan", json.loads(c["params"] or "{}"))
    params["offset_min"] = repo._schedule_offset(probe["id"], c["id"], params["schedule_min"], params["offset_min"])
    params["timeout_s"] = 900          # ein Scan dauert länger als ein Bandbreitentest
    vals = {"netscan": run}
    overdue = schedule.overdue_since(params, run["ts"] if run else None, int(c.get("created_at") or 0), now)
    if run is None:
        if overdue:
            return CheckState(c, "stale", "geplanter Netzwerkscan ist ausgeblieben", values=vals)
        plan = "wartet auf den ersten Scan" if params["schedule_min"] else "nur manuell, noch nicht gescannt"
        return CheckState(c, "waiting", plan, values=vals)
    if run["error"]:
        return CheckState(c, "down", run["error"], run["ts"], vals)
    detail = f"{run['hosts_found']} Geräte"
    if overdue:
        return CheckState(c, "stale", f"geplanter Scan überfällig, letzter vor {(now - run['ts']) // 60} min",
                          run["ts"], vals)
    return CheckState(c, "ok", detail, run["ts"], vals)


def probe_states(probe: dict, checks: list[dict], live: dict, paths: dict, bandwidth: dict,
                 now: int | None = None) -> list[CheckState]:
    """Zustand je zugewiesenem Check einer Probe (``checks`` aus ``repo.checks_for_probe``)."""
    now = now or repo.now()
    out = []
    for c in checks:
        if c["type"] == "ping":
            out.append(_ping_state(c, live.get((str(probe["id"]), str(c["id"]))), now))
        elif c["type"] == "path":
            out.append(_path_state(c, paths.get((probe["id"], c["id"])), now))
        elif c["type"] == "rtp":
            out.append(_rtp_state(probe, c, bandwidth.get((probe["id"], c["id"], "rtp")), now))
        elif c["type"] == "netscan":
            out.append(_netscan_state(probe, c, bandwidth.get((probe["id"], c["id"], "netscan")), now))
        elif c["type"] in checktypes.BANDWIDTH_TYPES:
            runs = {d: bandwidth.get((probe["id"], c["id"], d)) for d in ("down", "up")}
            out.append(_bandwidth_state(probe, c, runs, now))
    return out


def counts(states: list[CheckState]) -> dict[str, int]:
    result = {"ok": 0, "warn": 0, "down": 0, "stale": 0, "waiting": 0}
    for s in states:
        result[s.state] += 1
    return result


def overview(probes: list[dict], live: dict) -> dict[int, list[CheckState]]:
    """Zustände aller Probes auf einmal (Übersicht, Standort)."""
    paths, bandwidth = latest_runs([p["id"] for p in probes])
    now = repo.now()
    return {p["id"]: probe_states(p, repo.checks_for_probe(p), live, paths, bandwidth, now) for p in probes}
