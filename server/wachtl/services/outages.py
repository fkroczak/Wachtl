"""Ausfallübersicht: Störungen aus den Alarmen, nach Ursache eingeordnet.

Reihenfolge der Ursachen (höhere schlucken gleichzeitige niedrigere derselben Probe):
Probe/Standort offline > Gateway/LAN > WAN/Internet > einzelnes Ziel.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from ..db import q
from ..repo import now

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


def load(since: int, site_id: str | None = None, min_duration: int = 0, include_consequences: bool = False) -> list[Outage]:
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
        items.append(Outage(
            id=r["id"], cause=cause, probe=labels.get("probe", ""), probe_name=labels.get("probe_name", "?"),
            site=labels.get("site", ""), site_name=labels.get("site_name", "?"), target=labels.get("target", ""),
            check_id=labels.get("check_id", ""), start=r["starts_at"], end=end, summary=r["summary"] or r["alertname"],
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
