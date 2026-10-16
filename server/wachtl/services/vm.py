"""Zugriff auf VictoriaMetrics: Import und fest definierte Abfragen.

Benutzer schicken nie eigenes PromQL – das Dashboard ruft nur diese
Funktionen auf, damit Labels und Zeiträume immer kontrolliert bleiben.
"""
from __future__ import annotations

import logging
import math
import time

import requests
from flask import current_app

log = logging.getLogger(__name__)
_session = requests.Session()

RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
STAT_WINDOWS = ("1m", "5m", "15m", "1h", "24h")


class VMError(RuntimeError):
    pass


def _cfg(key: str) -> str:
    return current_app.config[key]


def import_lines(lines: list[str]) -> None:
    if not lines:
        return
    url = _cfg("VM_RAW_URL") + "/api/v1/import/prometheus"
    try:
        r = _session.post(url, data=("\n".join(lines) + "\n").encode("utf-8"), timeout=15)
    except requests.RequestException as exc:
        raise VMError(f"VictoriaMetrics nicht erreichbar: {exc}") from exc
    if r.status_code >= 300:
        raise VMError(f"VictoriaMetrics-Import fehlgeschlagen: HTTP {r.status_code} {r.text[:200]}")


def _get(base: str, path: str, params: dict) -> list[dict]:
    try:
        r = _session.get(base + path, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as exc:
        raise VMError(f"Abfrage fehlgeschlagen: {exc}") from exc
    if data.get("status") != "success":
        raise VMError(f"Abfrage fehlgeschlagen: {data.get('error')}")
    return data["data"]["result"]


def instant(query: str, agg: bool = False) -> list[dict]:
    base = _cfg("VM_AGG_URL") if agg else _cfg("VM_RAW_URL")
    return _get(base, "/api/v1/query", {"query": query})


def _sel(probe_id: int, check_id: int) -> str:
    return f'probe="{int(probe_id)}",check_id="{int(check_id)}"'


def _num(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(f) or math.isinf(f) else round(f, 3)


def ping_series(probe_id: int, check_id: int, range_key: str) -> dict:
    """Latenz (avg/min/max) und Paketverlust für den Graphen der Ziel-Detailseite."""
    span = RANGES.get(range_key, 3600)
    end = int(time.time())
    start = end - span
    use_agg = span > current_app.config["RAW_QUERY_MAX_S"]
    step = max(span // 600, 60 if use_agg else 1)
    sel = _sel(probe_id, check_id)
    w = f"{step}s"
    if use_agg:
        queries = {
            "avg": f"avg_over_time(wachtl:ping_rtt_ms:avg_1m{{{sel}}}[{w}])",
            "min": f"min_over_time(wachtl:ping_rtt_ms:min_1m{{{sel}}}[{w}])",
            "max": f"max_over_time(wachtl:ping_rtt_ms:max_1m{{{sel}}}[{w}])",
            "loss": f"avg_over_time(wachtl:ping_loss_ratio_1m{{{sel}}}[{w}]) * 100",
        }
        base = _cfg("VM_AGG_URL")
    else:
        queries = {
            "avg": f"avg_over_time(wachtl_ping_rtt_ms{{{sel}}}[{w}])",
            "min": f"min_over_time(wachtl_ping_rtt_ms{{{sel}}}[{w}])",
            "max": f"max_over_time(wachtl_ping_rtt_ms{{{sel}}}[{w}])",
            "loss": f"(1 - avg_over_time(wachtl_ping_up{{{sel}}}[{w}])) * 100",
        }
        base = _cfg("VM_RAW_URL")
    series = {}
    for key, query in queries.items():
        result = _get(base, "/api/v1/query_range", {"query": query, "start": start, "end": end, "step": step})
        values = result[0]["values"] if result else []
        series[key] = [[int(ts) * 1000, _num(v)] for ts, v in values]
    return {"range": range_key, "step_s": step, "source": "agg" if use_agg else "raw", "series": series}


def ping_stats(probe_id: int, check_id: int) -> dict[str, dict]:
    """Min, Max, Durchschnitt, Median, Jitter, Verlust für 1 min bis 24 h."""
    sel = _sel(probe_id, check_id)
    stats: dict[str, dict] = {}
    for w in STAT_WINDOWS:
        if w == "24h":
            agg = True
            q = {
                "min": f"min_over_time(wachtl:ping_rtt_ms:min_1m{{{sel}}}[24h])",
                "max": f"max_over_time(wachtl:ping_rtt_ms:max_1m{{{sel}}}[24h])",
                "avg": f"avg_over_time(wachtl:ping_rtt_ms:avg_1m{{{sel}}}[24h])",
                "median": f"quantile_over_time(0.5, wachtl:ping_rtt_ms:p50_1m{{{sel}}}[24h])",
                "jitter": f"avg_over_time(wachtl:ping_jitter_ms:avg_1m{{{sel}}}[24h])",
                "loss": f"avg_over_time(wachtl:ping_loss_ratio_1m{{{sel}}}[24h]) * 100",
            }
        else:
            agg = False
            q = {
                "min": f"min_over_time(wachtl_ping_rtt_ms{{{sel}}}[{w}])",
                "max": f"max_over_time(wachtl_ping_rtt_ms{{{sel}}}[{w}])",
                "avg": f"avg_over_time(wachtl_ping_rtt_ms{{{sel}}}[{w}])",
                "median": f"quantile_over_time(0.5, wachtl_ping_rtt_ms{{{sel}}}[{w}])",
                "jitter": f"avg_over_time(wachtl_ping_jitter_ms{{{sel}}}[{max_window(w)}])",
                "loss": f"(1 - avg_over_time(wachtl_ping_up{{{sel}}}[{w}])) * 100",
            }
        row = {}
        for key, query in q.items():
            result = instant(query, agg=agg)
            row[key] = _num(result[0]["value"][1]) if result else None
        stats[w] = row
    return stats


def max_window(w: str) -> str:
    """Jitter kommt nur minütlich – kürzere Fenster auf 2 min aufweiten."""
    return "2m" if w == "1m" else w


def live_status() -> dict[tuple[str, str], dict]:
    """Aktueller Zustand aller (Probe, Check)-Paare für Übersichten."""
    queries = {
        "up": "last_over_time(wachtl_ping_up[2m])",
        "rtt": "avg_over_time(wachtl_ping_rtt_ms[1m])",
        "loss": "(1 - avg_over_time(wachtl_ping_up[5m])) * 100",
    }
    status: dict[tuple[str, str], dict] = {}
    for key, query in queries.items():
        for item in instant(query):
            m = item["metric"]
            k = (m.get("probe", ""), m.get("check_id", ""))
            status.setdefault(k, {})[key] = _num(item["value"][1])
    return status
