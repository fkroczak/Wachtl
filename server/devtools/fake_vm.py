"""Minimaler VictoriaMetrics-Ersatz für lokale Entwicklung und End-to-End-Tests.

Versteht genau die Abfrageformen, die Wachtl stellt (…_over_time über einen Selektor,
optional ``1 - … * 100``, ``quantiles_over_time``, außen ``avg(…)`` bzw. ``avg by (phi) (…)``). Für echte Installationen immer VictoriaMetrics verwenden.
Start: python devtools/fake_vm.py 18428
"""
from __future__ import annotations

import json
import re
import statistics
import sys
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

STORE: dict[tuple, list[tuple[float, float]]] = defaultdict(list)
LOCK = threading.Lock()
LINE = re.compile(r'^([\w:]+)\{(.*)\}\s+(\S+)\s+(\d+)$')
LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
QUERY = re.compile(
    r'^\(?(?P<one>1 - )?(?P<fn>\w+)\((?P<args>(?:[\w."]+, )*)(?P<metric>[\w:]+)(?:\{(?P<sel>[^}]*)\})?'
    r'\[(?P<win>\w+)\]\)\)?(?P<pct> \* 100)?$'
)
OUTER = re.compile(r'^avg(?P<by> by \(phi\))? ?\((?P<inner>.*)\)$')
AGG_MAP = {  # Recording Rules auf Rohdaten abbilden
    "wachtl:ping_rtt_ms:avg_1m": "wachtl_ping_rtt_ms",
    "wachtl:ping_rtt_ms:min_1m": "wachtl_ping_rtt_ms",
    "wachtl:ping_rtt_ms:max_1m": "wachtl_ping_rtt_ms",
    "wachtl:ping_rtt_ms:p50_1m": "wachtl_ping_rtt_ms",
    "wachtl:ping_jitter_ms:avg_1m": "wachtl_ping_jitter_ms",
    "wachtl:ping_rtt_ms:quantiles_1m": "wachtl_ping_rtt_ms",
    "wachtl:hop_rtt_ms:avg_1m": "wachtl_hop_rtt_ms",
    "wachtl:hop_rtt_ms:min_1m": "wachtl_hop_rtt_ms",
    "wachtl:hop_rtt_ms:max_1m": "wachtl_hop_rtt_ms",
    "wachtl:hop_rtt_ms:p50_1m": "wachtl_hop_rtt_ms",
    "wachtl:hop_rtt_ms:quantiles_1m": "wachtl_hop_rtt_ms",
    "wachtl:hop_jitter_ms:avg_1m": "wachtl_hop_jitter_ms",
}


def quantile(vals: list[float], phi: float) -> float:
    s = sorted(vals)
    pos = phi * (len(s) - 1)
    lo = int(pos)
    return s[lo] + (s[min(lo + 1, len(s) - 1)] - s[lo]) * (pos - lo)


def dur(s: str) -> float:
    m = re.match(r"^(\d+)(ms|s|m|h|d)$", s)
    return int(m.group(1)) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def evaluate(query: str, t: float) -> list[tuple[dict, float]]:
    outer = OUTER.match(query.strip())
    if not outer:
        return evaluate_inner(query, t)
    groups: dict[str, list[float]] = defaultdict(list)
    for labels, v in evaluate_inner(outer["inner"], t):
        groups[labels.get("phi", "") if outer["by"] else ""].append(v)
    return [({"phi": k} if k else {}, statistics.fmean(v)) for k, v in groups.items()]


def evaluate_inner(query: str, t: float) -> list[tuple[dict, float]]:
    m = QUERY.match(query.strip())
    if not m:
        raise ValueError(f"nicht unterstützt: {query}")
    metric, fn = m["metric"], m["fn"]
    args = [a.strip('"') for a in m["args"].split(", ") if a]
    invert = bool(m["one"])
    if metric in ("wachtl:ping_loss_ratio_1m", "wachtl:hop_loss_ratio_1m"):
        metric, fn, invert = metric.replace(":", "_", 1).replace("_loss_ratio_1m", "_up"), "avg_over_time", True
    if metric.endswith(":quantiles_1m"):  # Minuten-Quantile: hier direkt aus den Rohdaten des Fensters
        fn, args = "quantiles_over_time", ["phi", "0.1", "0.25", "0.75", "0.9"]
    metric = AGG_MAP.get(metric, metric)
    sel = dict(LABEL.findall(m["sel"] or ""))
    win = dur(m["win"])
    out = []
    with LOCK:
        items = [(k, v) for k, v in STORE.items() if k[0] == metric]
    for key, samples in items:
        labels = dict(key[1])
        if any(labels.get(k) != v for k, v in sel.items()):
            continue
        vals = [v for ts, v in samples if t - win < ts <= t]
        if not vals:
            continue
        if fn == "quantiles_over_time":
            out += [({**labels, args[0]: phi}, quantile(vals, float(phi))) for phi in args[1:]]
            continue
        val = {
            "avg_over_time": statistics.fmean, "min_over_time": min, "max_over_time": max,
            "quantile_over_time": lambda x: quantile(x, float(args[0])), "last_over_time": lambda x: x[-1],
            "count_over_time": len, "sum_over_time": sum,
        }[fn](vals)
        if invert:
            val = 1 - val
        if m["pct"]:
            val *= 100
        out.append(({k: v for k, v in labels.items()}, val))
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.startswith("/api/v1/import/prometheus"):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            with LOCK:
                for line in body.splitlines():
                    mm = LINE.match(line.strip())
                    if mm:
                        name, lbl, val, ts = mm.groups()
                        key = (name, tuple(sorted(LABEL.findall(lbl))))
                        STORE[key].append((int(ts) / 1000, float(val)))
                for v in STORE.values():
                    v.sort()
            self.send_response(204)
            self.end_headers()
        else:
            self.send(404, {"status": "error"})

    def do_GET(self):
        url = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            if url.path == "/api/v1/query":
                t = float(qs.get("time", time.time()))
                res = [{"metric": l, "value": [t, str(v)]} for l, v in evaluate(qs["query"], t)]
                self.send(200, {"status": "success", "data": {"resultType": "vector", "result": res}})
            elif url.path == "/api/v1/query_range":
                start, end, step = float(qs["start"]), float(qs["end"]), float(qs["step"])
                series: dict[tuple, list] = {}
                t = start
                while t <= end:
                    for labels, v in evaluate(qs["query"], t):
                        series.setdefault(tuple(sorted(labels.items())), []).append([t, str(round(v, 4))])
                    t += step
                res = [{"metric": dict(k), "values": v} for k, v in series.items()]
                self.send(200, {"status": "success", "data": {"resultType": "matrix", "result": res}})
            else:
                self.send(404, {"status": "error", "error": "unbekannt"})
        except (KeyError, ValueError) as exc:
            self.send(422, {"status": "error", "error": str(exc)})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18428
    print(f"fake VictoriaMetrics auf :{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
