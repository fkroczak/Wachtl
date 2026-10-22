"""Ausfallübersicht: Störungen aus den Alarmen, nach Ursache eingeordnet.

Reihenfolge der Ursachen (höhere schlucken gleichzeitige niedrigere derselben Probe):
Probe/Standort offline > Gateway/LAN > WAN/Internet > einzelnes Ziel.
"""
from __future__ import annotations

import json
import logging
import statistics
from dataclasses import dataclass

from .. import repo
from ..db import ex, q
from ..repo import now
from . import vm

log = logging.getLogger(__name__)

CAUSES = {
    "probe": ("Probe / Standort offline", "Probe meldet sich nicht – Standort ohne Strom oder Netz, PC aus oder Dienst gestoppt."),
    "gateway": ("Gateway / LAN", "Das Default-Gateway antwortet nicht – Problem im lokalen Netz oder am Router."),
    "wan": ("WAN / Internet", "Gateway erreichbar, aber alle Internet-Referenzen gestört – Internetanschluss oder Provider."),
    "reference": ("Einzelne Internet-Referenz", "Nur eine Referenz gestört, das Internet insgesamt ist erreichbar."),
    "target": ("Ziel", "Ein überwachtes Ziel ist nicht erreichbar, Gateway und Internet sind in Ordnung."),
    "loss": ("Starker Paketverlust", "Ziel erreichbar, aber mit kritischem Paketverlust."),
}
PRIORITY = {"probe": 5, "gateway": 4, "wan": 3, "loss": 2, "reference": 1, "target": 1}
OUTAGE_ALERTS = ("WachtlProbeOffline", "WachtlTargetDown", "WachtlWanDown", "WachtlPacketLossCritical")

# Alarme starten und enden versetzt: Auswertung alle 15 s, 30 s Verzögerung für spät hochgeladene Werte und
# 20 s Rückblick der Regel. Der echte Ausfall liegt daher bis zu SEARCH_BEFORE_S vor dem Alarmbeginn.
SEARCH_BEFORE_S = 90
REFINE_MAX_SPAN_S = 6 * 3600   # längere Ausfälle nicht sekundengenau nachrechnen (Abfrageaufwand)
REFINE_PER_LOAD = 20


@dataclass
class Outage:
    id: int
    cause: str
    probe: str
    probe_name: str
    site: str
    site_name: str
    target: str
    check_id: str
    start: int
    end: int | None
    summary: str
    consequence_of: str | None = None

    @property
    def duration(self) -> int:
        return (self.end or now()) - self.start

    @property
    def cause_label(self) -> str:
        return CAUSES[self.cause][0]


def classify(alertname: str, labels: dict) -> str | None:
    if alertname == "WachtlProbeOffline":
        return "probe"
    if alertname == "WachtlWanDown":
        return "wan"
    if alertname == "WachtlPacketLossCritical":
        return "loss"
    if alertname == "WachtlTargetDown":
        return {"gateway": "gateway", "reference": "reference"}.get(labels.get("role", ""), "target")
    return None


def down_intervals(samples: list[tuple[int, float]]) -> list[tuple[int, int]]:
    """Zeiträume ohne Antwort: vom ersten fehlgeschlagenen Ping bis zum nächsten erfolgreichen."""
    if not samples:
        return []
    gaps = [b[0] - a[0] for a, b in zip(samples, samples[1:]) if b[0] > a[0]]
    step = max(int(statistics.median(gaps)), 1) if gaps else 1
    out: list[tuple[int, int]] = []
    begin = None
    for ts, value in samples:
        if value <= 0 and begin is None:
            begin = ts
        elif value > 0 and begin is not None:
            out.append((begin, ts))
            begin = None
    if begin is not None:
        out.append((begin, samples[-1][0] + step))
    return out


def intersect(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out = []
    for s1, e1 in a:
        for s2, e2 in b:
            s, e = max(s1, s2), min(e1, e2)
            if s < e:
                out.append((s, e))
    return sorted(out)


def exact_span(series: dict[str, list[tuple[int, float]]], start: int, end: int,
               min_s: float) -> tuple[int, int] | None:
    """Sekundengenauer Ausfall im Suchbereich: alle Reihen zugleich ohne Antwort (WAN = alle Referenzen)."""
    intervals: list[tuple[int, int]] | None = None
    for samples in series.values():
        own = down_intervals(samples)
        intervals = own if intervals is None else intersect(intervals, own)
    hits = [(s, e) for s, e in intervals or []
            if e >= start - SEARCH_BEFORE_S and s <= end and e - s >= min_s]
    if not hits:
        return None
    return min(s for s, _ in hits), max(e for _, e in hits)


def refine_pending(limit: int = REFINE_PER_LOAD) -> int:
    """Beendete Ausfälle (Ziel, Gateway, WAN) aus den 1-s-Rohdaten sekundengenau nachrechnen.

    Der Alarm selbst ist bis zu 15 s spät und endet bis zu 20 s zu spät. Gibt die Zahl der bearbeiteten zurück.
    """
    rows = q(
        "SELECT * FROM alert_events WHERE alertname IN ('WachtlTargetDown', 'WachtlWanDown') "
        "AND status = 'resolved' AND refined_at IS NULL AND ends_at IS NOT NULL AND ends_at < ? "
        "ORDER BY starts_at DESC LIMIT ?",
        (now() - 60, limit),
    )
    if not rows:
        return 0
    rules = repo.alert_rules()
    done = 0
    for r in rows:
        labels = json.loads(r["labels"])
        start, end = int(r["starts_at"]), int(r["ends_at"])
        exact = None
        if end - start <= REFINE_MAX_SPAN_S and labels.get("probe"):
            if r["alertname"] == "WachtlWanDown":
                sel, kind = {"probe": labels["probe"], "role": "reference"}, "wan_down"
            else:
                sel, kind = {"probe": labels["probe"], "check_id": labels.get("check_id", "")}, "target_down"
            thr = float((rules.get(kind) or {}).get("threshold") or 5)
            try:
                series = vm.up_samples(sel, start - SEARCH_BEFORE_S - 30, end + 30)
            except vm.VMError as exc:
                log.warning("Ausfalldauer nicht nachrechenbar: %s", exc)
                break  # VictoriaMetrics gestört: später erneut, nicht jede Zeile warten lassen
            except ValueError:
                series = {}
            # Toleranz: der erste und letzte Ping können je knapp eine Sekunde fehlen
            exact = exact_span(series, start, end, max(thr - 2, 1))
        ex("UPDATE alert_events SET exact_start = ?, exact_end = ?, refined_at = ? WHERE id = ?",
           (exact[0] if exact else None, exact[1] if exact else None, now(), r["id"]))
        done += 1
    return done


def load(since: int, site_id: str | None = None, min_duration: int = 0, include_consequences: bool = False,
         refine: bool = True) -> list[Outage]:
    if refine:
        refine_pending()
    placeholders = ", ".join("?" for _ in OUTAGE_ALERTS)
    rows = q(
        f"SELECT * FROM alert_events WHERE alertname IN ({placeholders}) AND (ends_at IS NULL OR ends_at >= ?) "
        "ORDER BY starts_at DESC LIMIT 5000",
        (*OUTAGE_ALERTS, since),
    )
    items: list[Outage] = []
    for r in rows:
        labels = json.loads(r["labels"])
        cause = classify(r["alertname"], labels)
        if cause is None:
            continue
        if r["status"] == "firing":
            end = None
        else:
            end = r["ends_at"] or r["updated_at"]
        start = r["starts_at"]
        if r.get("exact_start") and r.get("exact_end") and end is not None:
            start, end = r["exact_start"], r["exact_end"]
        items.append(Outage(
            id=r["id"], cause=cause, probe=labels.get("probe", ""), probe_name=labels.get("probe_name", "?"),
            site=labels.get("site", ""), site_name=labels.get("site_name", "?"), target=labels.get("target", ""),
            check_id=labels.get("check_id", ""), start=start, end=end, summary=r["summary"] or r["alertname"],
        ))
    mark_consequences(items)
    out = [o for o in items
           if (site_id is None or o.site == site_id)
           and o.duration >= min_duration
           and (include_consequences or o.consequence_of is None)]
    return out


def mark_consequences(items: list[Outage]) -> None:
    """Störung als Folge markieren, wenn zur selben Zeit an derselben Probe eine übergeordnete Ursache bestand."""
    ts = now()
    by_probe: dict[str, list[Outage]] = {}
    for o in items:
        by_probe.setdefault(o.probe, []).append(o)
    for group in by_probe.values():
        for o in group:
            o_end = o.end or ts
            for other in group:
                if other is o or PRIORITY[other.cause] <= PRIORITY[o.cause]:
                    continue
                # Überlappung, mit 2 min Toleranz (Alarme lösen leicht versetzt aus)
                if other.start - 120 <= o_end and o.start <= (other.end or ts) + 120:
                    o.consequence_of = other.cause_label
                    break


def summarize(items: list[Outage]) -> dict:
    by_cause: dict[str, dict] = {}
    by_site: dict[str, dict] = {}
    for o in items:
        c = by_cause.setdefault(o.cause, {"label": o.cause_label, "count": 0, "seconds": 0})
        c["count"] += 1
        c["seconds"] += o.duration
        s = by_site.setdefault(o.site_name, {"count": 0, "seconds": 0, "site": o.site})
        s["count"] += 1
        s["seconds"] += o.duration
    return {
        "by_cause": sorted(by_cause.items(), key=lambda kv: -PRIORITY[kv[0]]),
        "by_site": sorted(by_site.items(), key=lambda kv: -kv[1]["seconds"]),
        "total": len(items),
        "active": sum(1 for o in items if o.end is None),
    }
