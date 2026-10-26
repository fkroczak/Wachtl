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


def _metric_names(hop: int | None) -> dict[str, str]:
    """Rohdaten- und Aggregat-Namen für Ziel-Pings bzw. Hop-Pings eines Pfad-Checks."""
    kind = "hop" if hop is not None else "ping"
    return {
        "rtt": f"wachtl_{kind}_rtt_ms", "up": f"wachtl_{kind}_up", "jitter": f"wachtl_{kind}_jitter_ms",
        "avg_1m": f"wachtl:{kind}_rtt_ms:avg_1m", "min_1m": f"wachtl:{kind}_rtt_ms:min_1m",
        "max_1m": f"wachtl:{kind}_rtt_ms:max_1m", "p50_1m": f"wachtl:{kind}_rtt_ms:p50_1m",
        "q_1m": f"wachtl:{kind}_rtt_ms:quantiles_1m",
        "loss_1m": f"wachtl:{kind}_loss_ratio_1m", "jitter_1m": f"wachtl:{kind}_jitter_ms:avg_1m",
    }


def _hop_sel(probe_id: int, check_id: int, hop: int | None) -> str:
    sel = _sel(probe_id, check_id)
    return sel if hop is None else sel + f',hop="{int(hop):02d}"'


QUANTILES = ("0.1", "0.25", "0.5", "0.75", "0.9")


def ping_series(probe_id: int, check_id: int, range_key: str, hop: int | None = None,
                at: int | None = None) -> dict:
    """Smokeping-Graph der Ziel- bzw. Hop-Detailseite: Quantile p10/p25/p50/p75/p90, Paketverlust und Jitter je Schritt.

    ``at`` (Unix-Sekunden) legt das Fenster mittig um diesen Zeitpunkt, z. B. eine Störungsmeldung;
    ohne ``at`` endet es jetzt.
    """
    span = RANGES.get(range_key, 3600)
    now = int(time.time())
    end = now if at is None else max(min(int(at) + span // 2, now), now - 400 * 86400)
    start = end - span
    use_agg = span > current_app.config["RAW_QUERY_MAX_S"]
    step = max(span // 600, 60 if use_agg else 1)
    sel = _hop_sel(probe_id, check_id, hop)
    m = _metric_names(hop)
    w = f"{step}s"
    # mehrere Hop-IPs (Lastverteilung) werden zusammengefasst, Quantile je phi
    hops = (lambda e: f"avg({e})") if hop is not None else (lambda e: e)
    if use_agg:
        # shortcut: Quantile langer Zeiträume sind Mittel der Minuten-Quantile (wie Smokepings RRD-Konsolidierung),
        # nicht exakt; Bänder fehlen für Zeiten vor dem Update (Regel quantiles_1m neu), der Median nicht.
        # Exakt ginge nur mit Histogrammen je Minute – nachrüsten, falls kurze Spitzen in 7d/30d verschwinden.
        queries = {
            "q": f"avg by (phi) (avg_over_time({m['q_1m']}{{{sel}}}[{w}]))",
            "p50": hops(f"avg_over_time({m['p50_1m']}{{{sel}}}[{w}])"),
            "loss": hops(f"avg_over_time({m['loss_1m']}{{{sel}}}[{w}]) * 100"),
            "jitter": hops(f"avg_over_time({m['jitter_1m']}{{{sel}}}[{w}])"),
        }
        base = _cfg("VM_AGG_URL")
    else:
        queries = {
            "q": f'avg by (phi) (quantiles_over_time("phi", {", ".join(QUANTILES)}, {m["rtt"]}{{{sel}}}[{w}]))',
            "loss": hops(f"(1 - avg_over_time({m['up']}{{{sel}}}[{w}])) * 100"),
            # Jitter kommt nur einmal je Jitter-Fenster (meist 60 s): kürzere Schritte auf 2 min aufweiten
            "jitter": hops(f"avg_over_time({m['jitter']}{{{sel}}}[{max(step, 120)}s])"),
        }
        base = _cfg("VM_RAW_URL")
    series = {f"p{round(float(phi) * 100)}": [] for phi in QUANTILES}
    for key, query in queries.items():
        for item in _get(base, "/api/v1/query_range", {"query": query, "start": start, "end": end, "step": step}):
            name = f"p{round(float(item['metric']['phi']) * 100)}" if key == "q" else key
            series[name] = [[int(ts) * 1000, _num(v)] for ts, v in item["values"]]
    series.setdefault("loss", [])
    series.setdefault("jitter", [])
    return {"range": range_key, "step_s": step, "source": "agg" if use_agg else "raw", "series": series,
            "start": start, "end": end}


def ping_stats(probe_id: int, check_id: int, hop: int | None = None) -> dict[str, dict]:
    """Min, Max, Durchschnitt, Median, Jitter, Verlust für 1 min bis 24 h."""
    sel = _hop_sel(probe_id, check_id, hop)
    m = _metric_names(hop)
    stats: dict[str, dict] = {}
    for w in STAT_WINDOWS:
        if w == "24h":
            agg = True
            q = {
                "min": f"min_over_time({m['min_1m']}{{{sel}}}[24h])",
                "max": f"max_over_time({m['max_1m']}{{{sel}}}[24h])",
                "avg": f"avg_over_time({m['avg_1m']}{{{sel}}}[24h])",
                "median": f"quantile_over_time(0.5, {m['p50_1m']}{{{sel}}}[24h])",
                "jitter": f"avg_over_time({m['jitter_1m']}{{{sel}}}[24h])",
                "loss": f"avg_over_time({m['loss_1m']}{{{sel}}}[24h]) * 100",
            }
        else:
            agg = False
            q = {
                "min": f"min_over_time({m['rtt']}{{{sel}}}[{w}])",
                "max": f"max_over_time({m['rtt']}{{{sel}}}[{w}])",
                "avg": f"avg_over_time({m['rtt']}{{{sel}}}[{w}])",
                "median": f"quantile_over_time(0.5, {m['rtt']}{{{sel}}}[{w}])",
                "jitter": f"avg_over_time({m['jitter']}{{{sel}}}[{max_window(w)}])",
                "loss": f"(1 - avg_over_time({m['up']}{{{sel}}}[{w}])) * 100",
            }
        row = {}
        for key, query in q.items():
            query = f"avg({query})" if hop is not None else query
            result = instant(query, agg=agg)
            row[key] = _num(result[0]["value"][1]) if result else None
        stats[w] = row
    return stats


HOP_WINDOWS = ("1m", "5m", "15m", "1h", "6h", "24h")


def hop_table(probe_id: int, check_id: int, window: str = "5m") -> dict[int, dict]:
    """Je Hop: Verlust, Latenz (letzte/avg/min/max), Jitter und Anzahl Antworten – wie MTR."""
    sel = _sel(probe_id, check_id)
    agg = window == "24h"
    if agg:
        q = {
            "loss": f"avg_over_time(wachtl:hop_loss_ratio_1m{{{sel}}}[24h]) * 100",
            "avg": f"avg_over_time(wachtl:hop_rtt_ms:avg_1m{{{sel}}}[24h])",
            "min": f"min_over_time(wachtl:hop_rtt_ms:min_1m{{{sel}}}[24h])",
            "max": f"max_over_time(wachtl:hop_rtt_ms:max_1m{{{sel}}}[24h])",
            "jitter": f"avg_over_time(wachtl:hop_jitter_ms:avg_1m{{{sel}}}[24h])",
            "last": f"last_over_time(wachtl:hop_rtt_ms:avg_1m{{{sel}}}[10m])",
        }
    else:
        q = {
            "loss": f"(1 - avg_over_time(wachtl_hop_up{{{sel}}}[{window}])) * 100",
            "avg": f"avg_over_time(wachtl_hop_rtt_ms{{{sel}}}[{window}])",
            "min": f"min_over_time(wachtl_hop_rtt_ms{{{sel}}}[{window}])",
            "max": f"max_over_time(wachtl_hop_rtt_ms{{{sel}}}[{window}])",
            "jitter": f"avg_over_time(wachtl_hop_jitter_ms{{{sel}}}[{max_window(window)}])",
            "last": f"last_over_time(wachtl_hop_rtt_ms{{{sel}}}[1m])",
            "sent": f"count_over_time(wachtl_hop_up{{{sel}}}[{window}])",
        }
    hops: dict[int, dict] = {}
    for key, query in q.items():
        for item in instant(query, agg=agg):
            labels = item["metric"]
            try:
                hop = int(labels.get("hop", ""))
            except ValueError:
                continue
            entry = hops.setdefault(hop, {"ips": {}})
            ip_entry = entry["ips"].setdefault(labels.get("hop_ip", ""), {})
            ip_entry[key] = _num(item["value"][1])
    # je Hop die IP mit den meisten Messungen als Hauptwert, weitere IPs als Lastverteilung anzeigen
    for hop, entry in hops.items():
        ips = entry["ips"]
        main = max(ips, key=lambda ip: (ips[ip].get("sent") or 0, ips[ip].get("avg") is not None))
        entry.update(ips[main])
        entry["ip"] = main
        entry["other_ips"] = sorted(ip for ip in ips if ip != main)
    return hops


def up_samples(labels: dict[str, str], start: int, end: int) -> dict[str, list[tuple[int, float]]]:
    """Rohwerte von ``wachtl_ping_up`` (1 = Antwort, 0 = keine) je Check zwischen start und end.

    Nur feste Label-Namen; Werte werden geprüft, damit kein fremdes PromQL entsteht.
    """
    parts = []
    for key, value in labels.items():
        if key not in ("probe", "check_id", "role") or not str(value).replace("_", "").isalnum():
            raise ValueError(f"unzulässiges Label {key}={value!r}")
        parts.append(f'{key}="{value}"')
    span = max(int(end) - int(start), 1)
    result = _get(_cfg("VM_RAW_URL"), "/api/v1/query",
                  {"query": f"wachtl_ping_up{{{','.join(parts)}}}[{span}s]", "time": int(end)})
    out: dict[str, list[tuple[int, float]]] = {}
    for item in result:
        values = [(int(float(ts)), float(v)) for ts, v in item.get("values", [])]
        out.setdefault(item["metric"].get("check_id", ""), []).extend(values)
    return {k: sorted(v) for k, v in out.items()}


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
            status.setdefault(k, dict.fromkeys(queries))[key] = _num(item["value"][1])
    return status


def site_sparklines(site_id: int | None = None) -> dict[tuple[str, str], dict]:
    """Je (Probe, Check) eines Standorts (ohne site_id: aller Standorte): Latenz-Median und Verlust je Minute der
    letzten Stunde, Jitter (5 min).

    Zwei Bereichs- und eine Sofortabfrage – für die Mini-Graphen der Probe-Kacheln.
    """
    end = int(time.time())
    sel = f'site="{int(site_id)}"' if site_id is not None else 'site!=""'
    out: dict[tuple[str, str], dict] = {}

    def entry(m: dict) -> dict:
        return out.setdefault((m.get("probe", ""), m.get("check_id", "")), {"rtt": [], "loss": [], "jitter": None})

    for key, query in (("rtt", f"quantile_over_time(0.5, wachtl_ping_rtt_ms{{{sel}}}[60s])"),
                       ("loss", f"(1 - avg_over_time(wachtl_ping_up{{{sel}}}[60s])) * 100")):
        params = {"query": query, "start": end - 3600, "end": end, "step": 60}
        for item in _get(_cfg("VM_RAW_URL"), "/api/v1/query_range", params):
            entry(item["metric"])[key] = [(int(float(ts)), _num(v)) for ts, v in item["values"]]
    for item in instant(f"avg_over_time(wachtl_ping_jitter_ms{{{sel}}}[5m])"):
        entry(item["metric"])["jitter"] = _num(item["value"][1])
    return out


# -- PDF-Bericht: Verläufe und Hop-Werte über einen frei gewählten Zeitraum (1-min-Aggregate, 13 Monate) ------
def _range(query: str, start: int, end: int, step: int) -> list[dict]:
    return _get(_cfg("VM_AGG_URL"), "/api/v1/query_range",
                {"query": query, "start": int(start), "end": int(end), "step": int(step)})


def report_ping_series(probe_id: int, start: int, end: int, step: int) -> dict[str, dict]:
    """Je Ping-Check einer Probe: Latenz (Mittel, Max, p10/p90), Verlust (Mittel, Max), Jitter, Minuten mit
    Verlust und verlorene Sekunden je Schritt. Ein Wert bei ``ts`` gilt für den Abschnitt (ts − step, ts].

    Wirft VMError, wenn VictoriaMetrics nicht antwortet; nur die Zusatzwerte (Minuten mit Verlust) dürfen fehlen.
    """
    sel = f'probe="{int(probe_id)}"'
    w = f"{int(step)}s"
    required = {
        "avg": f"avg_over_time(wachtl:ping_rtt_ms:avg_1m{{{sel}}}[{w}])",
        "max": f"max_over_time(wachtl:ping_rtt_ms:max_1m{{{sel}}}[{w}])",
        "q": f"avg_over_time(wachtl:ping_rtt_ms:quantiles_1m{{{sel}}}[{w}])",
        "loss": f"avg_over_time(wachtl:ping_loss_ratio_1m{{{sel}}}[{w}]) * 100",
        "jitter": f"avg_over_time(wachtl:ping_jitter_ms:avg_1m{{{sel}}}[{w}])",
    }
    optional = {
        "loss_max": f"max_over_time(wachtl:ping_loss_ratio_1m{{{sel}}}[{w}]) * 100",
        "loss_minutes": f"count_gt_over_time(wachtl:ping_loss_ratio_1m{{{sel}}}[{w}], 0)",
        "lost_s": f"sum_over_time(wachtl:ping_loss_ratio_1m{{{sel}}}[{w}]) * 60",
    }
    out: dict[str, dict] = {}
    for key, query in [*required.items(), *optional.items()]:
        try:
            result = _range(query, start, end, step)
        except VMError:
            if key in required:
                raise
            continue
        for item in result:
            m = item["metric"]
            entry = out.setdefault(m.get("check_id", ""), {"role": m.get("role", ""), "target": m.get("target", ""),
                                                           "series": {}})
            name = f"p{round(float(m['phi']) * 100)}" if key == "q" and m.get("phi") else key
            points = entry["series"].setdefault(name, {})
            for ts, v in item["values"]:
                v = _num(v)
                if v is not None:
                    points.setdefault(int(float(ts)), []).append(v)
    # mehrere Reihen je Check (z. B. Ziel oder Name geändert) zu einem Wert je Zeitpunkt zusammenfassen
    for entry in out.values():
        entry["series"] = {name: sorted((ts, sum(vs) / len(vs)) for ts, vs in pts.items())
                           for name, pts in entry["series"].items()}
    return out


def report_hop_table(probe_id: int, check_id: int, start: int, end: int) -> dict[int, dict]:
    """Je Hop eines Pfad-Checks: Verlust, Latenz (Mittel, Max) und Jitter über den ganzen Zeitraum."""
    sel = _sel(probe_id, check_id)
    w = f"{max(int(end) - int(start), 60)}s"
    queries = {
        "loss": f"avg_over_time(wachtl:hop_loss_ratio_1m{{{sel}}}[{w}]) * 100",
        "avg": f"avg_over_time(wachtl:hop_rtt_ms:avg_1m{{{sel}}}[{w}])",
        "max": f"max_over_time(wachtl:hop_rtt_ms:max_1m{{{sel}}}[{w}])",
        "jitter": f"avg_over_time(wachtl:hop_jitter_ms:avg_1m{{{sel}}}[{w}])",
        "minutes": f"count_over_time(wachtl:hop_rtt_ms:avg_1m{{{sel}}}[{w}])",
    }
    hops: dict[int, dict] = {}
    for key, query in queries.items():
        for item in _get(_cfg("VM_AGG_URL"), "/api/v1/query", {"query": query, "time": int(end)}):
            labels = item["metric"]
            try:
                hop = int(labels.get("hop", ""))
            except ValueError:
                continue
            ip_entry = hops.setdefault(hop, {"ips": {}})["ips"].setdefault(labels.get("hop_ip", ""), {})
            ip_entry[key] = _num(item["value"][1])
    for entry in hops.values():
        ips = entry["ips"]
        main = max(ips, key=lambda ip: (ips[ip].get("minutes") or 0, ips[ip].get("avg") is not None))
        entry.update(ips[main])
        entry["ip"] = main
        entry["other_ips"] = sorted(ip for ip in ips if ip and ip != main)
    return hops
