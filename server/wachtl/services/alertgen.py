"""Erzeugt die vmalert-Regeldatei aus der Datenbank und lädt vmalert neu.

Gruppe 1: Recording Rules – 1-min-Aggregate, die vmalert nach vm-agg schreibt.
Gruppe 2: Alarmregeln mit den Schwellwerten aus der Tabelle ``alert_rules``.
"""
from __future__ import annotations

import json
import logging
import math
import os
import tempfile
from collections import defaultdict

import requests
import yaml
from flask import current_app

from .. import checktypes, repo
from ..db import q

log = logging.getLogger(__name__)

RULES_FILE = "wachtl.yml"
BY_TARGET = "probe, probe_name, site, site_name, check_id, target, role"
BY_PROBE = "probe, probe_name, site, site_name"

RECORDING_RULES = [
    ("wachtl:ping_rtt_ms:min_1m", "min_over_time(wachtl_ping_rtt_ms[1m])"),
    ("wachtl:ping_rtt_ms:max_1m", "max_over_time(wachtl_ping_rtt_ms[1m])"),
    ("wachtl:ping_rtt_ms:avg_1m", "avg_over_time(wachtl_ping_rtt_ms[1m])"),
    ("wachtl:ping_rtt_ms:p50_1m", "quantile_over_time(0.5, wachtl_ping_rtt_ms[1m])"),
    # Rauch-Bänder des Graphen (p10–p90, p25–p75), eine Reihe je Quantil (Label phi)
    ("wachtl:ping_rtt_ms:quantiles_1m", 'quantiles_over_time("phi", 0.1, 0.25, 0.75, 0.9, wachtl_ping_rtt_ms[1m])'),
    ("wachtl:ping_loss_ratio_1m", "1 - avg_over_time(wachtl_ping_up[1m])"),
    ("wachtl:ping_jitter_ms:avg_1m", "avg_over_time(wachtl_ping_jitter_ms[1m])"),
    ("wachtl:hop_rtt_ms:avg_1m", "avg_over_time(wachtl_hop_rtt_ms[1m])"),
    ("wachtl:hop_rtt_ms:min_1m", "min_over_time(wachtl_hop_rtt_ms[1m])"),
    ("wachtl:hop_rtt_ms:max_1m", "max_over_time(wachtl_hop_rtt_ms[1m])"),
    ("wachtl:hop_rtt_ms:p50_1m", "quantile_over_time(0.5, wachtl_hop_rtt_ms[1m])"),
    ("wachtl:hop_rtt_ms:quantiles_1m", 'quantiles_over_time("phi", 0.1, 0.25, 0.75, 0.9, wachtl_hop_rtt_ms[1m])'),
    ("wachtl:hop_jitter_ms:avg_1m", "avg_over_time(wachtl_hop_jitter_ms[1m])"),
    ("wachtl:hop_loss_ratio_1m", "1 - avg_over_time(wachtl_hop_up[1m])"),
    ("wachtl:bw_mbps:last_1m", "last_over_time(wachtl_bw_mbps[1m])"),
    ("wachtl:path_change:max_1m", "max_over_time(wachtl_path_change[1m])"),
]


# vmalert wertet alle 15 s aus; so weit (plus Reserve) schaut die Ausfallerkennung sekundenweise zurück.
LOOKBACK_S = 20


def _fmt_s(seconds: float) -> str:
    return f"{int(seconds)}s"


def outage_window(threshold_s: float, interval_s: int) -> tuple[int, str]:
    """Pings in Folge und Zeitfenster für „mindestens threshold_s Sekunden ohne Antwort“.

    Mindestens 2 Pings, damit ein einzelnes verlorenes Paket bei langen Intervallen kein Ausfall ist.
    Das Fenster enthält n (bis n + 1) Pings: n × Intervall + ein halbes Intervall Reserve.
    """
    interval_s = max(int(interval_s), 1)
    n = max(2, math.ceil(max(threshold_s, 1) / interval_s))
    return n, f"{int((n * interval_s + interval_s / 2) * 1000)}ms"


def _recent(inner: str) -> str:
    """Wahr, solange ``inner`` in den letzten LOOKBACK_S Sekunden zu irgendeiner Sekunde wahr war."""
    return f"count_over_time(({inner})[{LOOKBACK_S}s:1s]) > 0"


def build_rules() -> dict:
    rules = repo.alert_rules()
    alert_list: list[dict] = []

    def add(alert: str, kind: str, expr: str, summary: str, extra_labels: dict | None = None) -> None:
        r = rules.get(kind)
        if not r or not r["enabled"]:
            return
        labels = {"severity": r["severity"], "kind": kind}
        labels.update(extra_labels or {})
        item = {
            "alert": alert,
            "expr": expr,
            "labels": labels,
            "annotations": {"summary": summary},
        }
        if r["for_s"]:
            item["for"] = _fmt_s(r["for_s"])
        alert_list.append(item)

    if "probe_offline" in rules:
        thr = rules["probe_offline"]["threshold"]
        add(
            "WachtlProbeOffline",
            "probe_offline",
            f"(time() - max by ({BY_PROBE}) (max_over_time(wachtl_probe_last_seen[24h]))) > {thr:g}",
            "Probe {{ $labels.probe_name }} ({{ $labels.site_name }}) sendet seit {{ $value | humanizeDuration }} nichts mehr",
        )

    # Ausfall = mindestens "threshold" Sekunden keine Antwort. Wie viele Pings in Folge das sind, hängt vom
    # Intervall ab: eine Regel je Intervall. vmalert wertet nur alle 15 s aus – die Unterabfrage prüft deshalb
    # jede Sekunde der letzten LOOKBACK_S, damit auch ein 5-s-Ausfall zwischen zwei Auswertungen auffällt.
    if "target_down" in rules:
        thr = float(rules["target_down"]["threshold"])
        by_interval: dict[int, list[str]] = defaultdict(list)
        for c in q("SELECT id, interval_s FROM checks WHERE enabled = TRUE AND type = 'ping'"):
            by_interval[int(c["interval_s"])].append(str(c["id"]))
        for interval, ids in sorted(by_interval.items()):
            n, window = outage_window(thr, interval)
            sel = f'check_id=~"{"|".join(sorted(ids, key=int))}"'
            inner = (f"(max by ({BY_TARGET}) (max_over_time(wachtl_ping_up{{{sel}}}[{window}])) == 0)"
                     f" and (sum by ({BY_TARGET}) (count_over_time(wachtl_ping_up{{{sel}}}[{window}])) >= {n})")
            add(
                "WachtlTargetDown",
                "target_down",
                _recent(inner),
                f"{{{{ $labels.target }}}} von {{{{ $labels.probe_name }}}} ({{{{ $labels.site_name }}}}) "
                f"nicht erreichbar (mindestens {thr:g} s keine Antwort)",
                {"interval": str(interval)},
            )

    if "wan_down" in rules:
        thr = float(rules["wan_down"]["threshold"])
        intervals = [int(c["interval_s"]) for c in q(
            "SELECT interval_s FROM checks WHERE enabled = TRUE AND type = 'ping' AND role = 'reference'")]
        n, window = outage_window(thr, max(intervals or [1]))
        sel = 'role="reference"'
        inner = (f"(max by ({BY_PROBE}) (max_over_time(wachtl_ping_up{{{sel}}}[{window}])) == 0)"
                 f" and (min by ({BY_PROBE}) (count_over_time(wachtl_ping_up{{{sel}}}[{window}])) >= {n})")
        add(
            "WachtlWanDown",
            "wan_down",
            _recent(inner),
            "Alle Internet-Referenzen von {{ $labels.probe_name }} ({{ $labels.site_name }}) gestört – vermutlich WAN-Problem",
            {"cause": "wan"},
        )

    for kind, alert in (("packet_loss_warning", "WachtlPacketLoss"), ("packet_loss_critical", "WachtlPacketLossCritical")):
        if kind in rules:
            r = rules[kind]
            add(
                alert,
                kind,
                f"(1 - avg_over_time(wachtl_ping_up[{_fmt_s(r['window_s'])}])) * 100 > {r['threshold']:g}",
                "Paketverlust {{ $value | printf \"%.1f\" }} % zu {{ $labels.target }} von "
                "{{ $labels.probe_name }} ({{ $labels.site_name }})",
            )

    if "latency_high" in rules:
        r = rules["latency_high"]
        add(
            "WachtlLatencyHigh",
            "latency_high",
            f"avg_over_time(wachtl_ping_rtt_ms[{_fmt_s(r['window_s'])}]) > {r['threshold']:g}",
            "Latenz {{ $value | printf \"%.0f\" }} ms zu {{ $labels.target }} von "
            "{{ $labels.probe_name }} ({{ $labels.site_name }})",
        )

    if "jitter_high" in rules:
        r = rules["jitter_high"]
        add(
            "WachtlJitterHigh",
            "jitter_high",
            f"avg_over_time(wachtl_ping_jitter_ms[{_fmt_s(max(r['window_s'], 120))}]) > {r['threshold']:g}",
            "Jitter {{ $value | printf \"%.1f\" }} ms zu {{ $labels.target }} von "
            "{{ $labels.probe_name }} ({{ $labels.site_name }})",
        )

    if "route_change" in rules:
        r = rules["route_change"]
        add(
            "WachtlRouteChanged",
            "route_change",
            f"max_over_time(wachtl_path_change[{_fmt_s(max(r['threshold'], 60))}]) > 0",
            "Pfad von {{ $labels.probe_name }} ({{ $labels.site_name }}) zu {{ $labels.target }} hat sich geändert",
        )

    # Bandbreite: Schwellwerte stehen je Check; "N Messungen in Folge unter Schwellwert"
    if "bandwidth_low" in rules:
        n = max(int(rules["bandwidth_low"]["threshold"]), 1)
        for c in q("SELECT id, type, params FROM checks WHERE enabled = TRUE AND type IN ('iperf', 'speedtest')"):
            p = checktypes.merged(c["type"], json.loads(c["params"] or "{}"))
            if not p["schedule_min"]:
                continue  # nur manuell: kein Zeitfenster für "in Folge"
            window = _fmt_s(p["schedule_min"] * 60 * n + p["schedule_min"] * 30 + p["timeout_s"])
            for direction, key, label in (("down", "min_down_mbps", "Download"), ("up", "min_up_mbps", "Upload")):
                minimum = float(p.get(key) or 0)
                if minimum <= 0:
                    continue
                sel = f'check_id="{c["id"]}",direction="{direction}"'
                add(
                    "WachtlBandwidthLow",
                    "bandwidth_low",
                    f"(max by ({BY_TARGET}, direction) (max_over_time(wachtl_bw_mbps{{{sel}}}[{window}])) < {minimum:g})"
                    f" and (sum by ({BY_TARGET}, direction) (count_over_time(wachtl_bw_mbps{{{sel}}}[{window}])) >= {n})",
                    f"{label} {{{{ $value | printf \"%.1f\" }}}} Mbit/s von {{{{ $labels.probe_name }}}} "
                    f"({{{{ $labels.site_name }}}}) zu {{{{ $labels.target }}}} unter {minimum:g} Mbit/s",
                    {"direction": direction},
                )

    # Sprachqualität: MOS-Schwelle je Check; "N Tests in Folge darunter" wie bei der Bandbreite
    if "voip_quality" in rules:
        n = max(int(rules["voip_quality"]["threshold"]), 1)
        for c in q("SELECT id, params FROM checks WHERE enabled = TRUE AND type = 'rtp'"):
            p = checktypes.merged("rtp", json.loads(c["params"] or "{}"))
            minimum = float(p.get("min_mos") or 0)
            if not p["schedule_min"] or minimum <= 0:
                continue
            window = _fmt_s(p["schedule_min"] * 60 * n + p["schedule_min"] * 30 + p["duration_s"] + 60)
            sel = f'check_id="{c["id"]}"'
            add(
                "WachtlVoipQuality",
                "voip_quality",
                f"(max by ({BY_TARGET}) (max_over_time(wachtl_rtp_mos{{{sel}}}[{window}])) < {minimum:g})"
                f" and (sum by ({BY_TARGET}) (count_over_time(wachtl_rtp_mos{{{sel}}}[{window}])) >= {n})",
                f"Sprachqualität MOS {{{{ $value | printf \"%.2f\" }}}} von {{{{ $labels.probe_name }}}} "
                f"({{{{ $labels.site_name }}}}) zu {{{{ $labels.target }}}} unter {minimum:g}",
            )

    return {
        "groups": [
            {
                "name": "wachtl-recording",
                "interval": "1m",
                "rules": [{"record": name, "expr": expr} for name, expr in RECORDING_RULES],
            },
            {"name": "wachtl-alerts", "interval": "15s", "rules": alert_list},
        ]
    }


def write_rules(reload: bool = True) -> str:
    """Regeldatei atomar schreiben und vmalert neu laden. Gibt den Pfad zurück."""
    rules_dir = current_app.config["RULES_DIR"]
    os.makedirs(rules_dir, exist_ok=True)
    path = os.path.join(rules_dir, RULES_FILE)
    content = "# Automatisch von Wachtl erzeugt – Änderungen bitte im Web-UI vornehmen.\n"
    content += yaml.safe_dump(build_rules(), sort_keys=False, allow_unicode=True, width=200)
    fd, tmp = tempfile.mkstemp(dir=rules_dir, prefix=".wachtl-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    if reload:
        reload_vmalert()
    return path


def reload_vmalert() -> bool:
    url = current_app.config.get("VMALERT_URL")
    if not url:
        return False
    try:
        r = requests.get(url + "/-/reload", timeout=10)
        r.raise_for_status()
        return True
    except requests.RequestException as exc:
        log.warning("vmalert konnte nicht neu geladen werden: %s", exc)
        return False
