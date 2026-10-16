"""Erzeugt die vmalert-Regeldatei aus der Datenbank und lädt vmalert neu.

Gruppe 1: Recording Rules – 1-min-Aggregate, die vmalert nach vm-agg schreibt.
Gruppe 2: Alarmregeln mit den Schwellwerten aus der Tabelle ``alert_rules``.
"""
from __future__ import annotations

import logging
import os
import tempfile
from collections import defaultdict

import requests
import yaml
from flask import current_app

from .. import repo
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
    ("wachtl:ping_loss_ratio_1m", "1 - avg_over_time(wachtl_ping_up[1m])"),
    ("wachtl:ping_jitter_ms:avg_1m", "avg_over_time(wachtl_ping_jitter_ms[1m])"),
]


def _fmt_s(seconds: float) -> str:
    return f"{int(seconds)}s"


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

    # "N aufeinanderfolgende Fehler" hängt vom Intervall ab: eine Regel je Intervall.
    if "target_down" in rules:
        n = max(int(rules["target_down"]["threshold"]), 1)
        by_interval: dict[int, list[str]] = defaultdict(list)
        for c in q("SELECT id, interval_s FROM checks WHERE enabled = TRUE AND type = 'ping'"):
            by_interval[int(c["interval_s"])].append(str(c["id"]))
        for interval, ids in sorted(by_interval.items()):
            window = f"{int((interval * n + interval / 2) * 1000)}ms"
            sel = f'check_id=~"{"|".join(sorted(ids, key=int))}"'
            add(
                "WachtlTargetDown",
                "target_down",
                f"(max by ({BY_TARGET}) (max_over_time(wachtl_ping_up{{{sel}}}[{window}])) == 0)"
                f" and (sum by ({BY_TARGET}) (count_over_time(wachtl_ping_up{{{sel}}}[{window}])) >= {n})",
                f"{{{{ $labels.target }}}} von {{{{ $labels.probe_name }}}} ({{{{ $labels.site_name }}}}) "
                f"nicht erreichbar ({n} Pings in Folge fehlgeschlagen)",
                {"interval": str(interval)},
            )

    if "wan_down" in rules:
        r = rules["wan_down"]
        add(
            "WachtlWanDown",
            "wan_down",
            f'max by ({BY_PROBE}) (max_over_time(wachtl_ping_up{{role="reference"}}[{_fmt_s(r["threshold"])}])) == 0',
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
