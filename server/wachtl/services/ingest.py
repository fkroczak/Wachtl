"""Prüft Messwert-Batches der Probes und setzt vertrauenswürdige Labels.

Eingang (Prometheus-Textformat, Zeitstempel in ms), z. B.::

    wachtl_ping_rtt_ms{check_id="3",target="8.8.8.8"} 12.41 1760620800000

Die Probe darf nur ``check_id`` mitschicken. Alle anderen Labels (probe, site,
target, role …) setzt der Collector aus der Datenbank. So kann keine Probe
Daten für andere Probes oder Checks einliefern.
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass

ALLOWED_METRICS = {
    "wachtl_ping_rtt_ms",
    "wachtl_ping_up",
    "wachtl_ping_ttl",
    "wachtl_ping_jitter_ms",
}
MAX_AGE_MS = 8 * 86400 * 1000      # Puffer der Probe hält 7 Tage
MAX_FUTURE_MS = 5 * 60 * 1000      # Uhrabweichung

_LINE_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\{(.*)\}\s+(\S+)\s+(\d{10,16})$")
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


@dataclass
class IngestResult:
    lines: list[str]
    accepted: int
    rejected: int
    reasons: dict[str, int]


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(pairs: dict[str, str]) -> str:
    return ",".join(f'{k}="{_escape(str(v))}"' for k, v in pairs.items())


def process(body: str, probe: dict, checks: dict[str, dict], now_ms: int | None = None) -> IngestResult:
    """Zeilen prüfen und mit Server-Labels neu schreiben.

    :param probe: Probe-Datensatz inkl. ``site_name``
    :param checks: zugewiesene Checks der Probe, Schlüssel = check_id als String
    """
    now_ms = now_ms or int(time.time() * 1000)
    out: list[str] = []
    reasons: dict[str, int] = {}

    def reject(reason: str) -> None:
        reasons[reason] = reasons.get(reason, 0) + 1

    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            reject("format")
            continue
        name, label_str, value_str, ts_str = m.groups()
        if name not in ALLOWED_METRICS:
            reject("metric")
            continue
        sent = dict(_LABEL_RE.findall(label_str))
        check = checks.get(sent.get("check_id", ""))
        if check is None:
            reject("check_id")
            continue
        try:
            value = float(value_str)
        except ValueError:
            reject("value")
            continue
        if math.isnan(value) or math.isinf(value):
            reject("value")
            continue
        ts = int(ts_str)
        if ts < 10**12:  # Sekunden statt Millisekunden
            ts *= 1000
        if ts < now_ms - MAX_AGE_MS or ts > now_ms + MAX_FUTURE_MS:
            reject("timestamp")
            continue
        labels = {
            "probe": str(probe["id"]),
            "probe_name": probe["hostname"],
            "site": str(probe["site_id"]),
            "site_name": probe["site_name"],
            "check_id": str(check["id"]),
            "target": check["target"],
            "role": check["role"],
        }
        out.append(f"{name}{{{_labels(labels)}}} {value_str} {ts}")

    rejected = sum(reasons.values())
    return IngestResult(lines=out, accepted=len(out), rejected=rejected, reasons=reasons)


def heartbeat_lines(probe: dict, buffer_items: int, now_s: int) -> list[str]:
    labels = _labels(
        {
            "probe": str(probe["id"]),
            "probe_name": probe["hostname"],
            "site": str(probe["site_id"]),
            "site_name": probe["site_name"],
        }
    )
    ts = now_s * 1000
    return [
        f"wachtl_probe_last_seen{{{labels}}} {now_s} {ts}",
        f"wachtl_probe_buffer_items{{{labels}}} {int(buffer_items)} {ts}",
    ]
