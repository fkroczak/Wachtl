"""Bewertet einen Pfad Hop für Hop – wie man eine MTR-Ausgabe liest.

Grundregeln:
* Verlust, der an einem Hop beginnt und sich bis zum Ziel fortsetzt, ist echt.
  Das Problem liegt zwischen dem letzten sauberen Hop und diesem Hop.
* Verlust nur an einem Zwischen-Hop, während spätere Hops sauber sind, ist meist
  ICMP-Ratenbegrenzung des Routers und kein Problem.
* Ein Latenzsprung, der bis zum Ziel bestehen bleibt, zeigt eine langsame Strecke
  (z. B. Überlast oder weiter Weg); ein Sprung nur an einem Hop ist meist langsame
  ICMP-Antwort des Routers selbst.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

LOSS_WARN = 2.0          # % ab hier gilt ein Hop als verlustbehaftet
LOSS_CRIT = 10.0
JUMP_MS = 20.0           # Mindest-Latenzsprung
JUMP_RATIO = 0.5         # … und mindestens +50 %
CARRY_RATIO = 0.5        # spätere Hops müssen mindestens halb so viel Verlust/Sprung zeigen


@dataclass
class Finding:
    level: str           # ok | info | warn | bad
    text: str
    hop: int | None = None


@dataclass
class Analysis:
    findings: list[Finding] = field(default_factory=list)
    verdict: str = "ok"
    hop_marks: dict[int, str] = field(default_factory=dict)   # hop -> real | ratelimit | noreply | jump


def segment(ip: str | None, hop: int) -> str:
    """Grobe Einordnung, wo ein Hop liegt."""
    if hop == 1:
        return "Gateway / lokales Netz"
    if not ip:
        return "unbekannt"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unbekannt"
    if addr.is_private:
        return "lokales Netz / Router des Standorts"
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return "Zugangsnetz des Providers (CGNAT)"
    return "Provider / Internet"


def analyze(hops: list[dict], target: str = "") -> Analysis:
    """
    :param hops: sortierte Liste mit ``hop``, ``ip``, ``loss`` (%), ``avg`` (ms); fehlende Werte = None
    """
    a = Analysis()
    responding = [h for h in hops if h.get("ip") and h.get("loss") is not None]
    for h in hops:
        if not h.get("ip"):
            a.hop_marks[h["hop"]] = "noreply"
    if not responding:
        a.findings.append(Finding("info", "Noch keine Messwerte für die Hops."))
        a.verdict = "info"
        return a

    last = responding[-1]
    dest_loss = last["loss"] or 0.0

    # Verlust: erster Hop, ab dem alle folgenden (inkl. Ziel) ebenfalls Verlust zeigen
    origin = None
    if dest_loss >= LOSS_WARN:
        for i, h in enumerate(responding):
            if (h["loss"] or 0) < LOSS_WARN:
                continue
            rest = responding[i:]
            if all((r["loss"] or 0) >= max(LOSS_WARN, h["loss"] * CARRY_RATIO) for r in rest):
                origin = h
                break
        if origin is None:
            origin = last
        prev = next((r for r in reversed(responding) if r["hop"] < origin["hop"]), None)
        between = (f"zwischen Hop {prev['hop']} ({prev['ip']}) und Hop {origin['hop']} ({origin['ip']})"
                   if prev else f"bei Hop {origin['hop']} ({origin['ip']})")
        level = "bad" if dest_loss >= LOSS_CRIT else "warn"
        a.findings.append(Finding(
            level,
            f"Paketverlust {dest_loss:.1f} % bis zum Ziel. Er beginnt {between} und setzt sich bis zum Ziel fort – "
            f"Bereich: {segment(origin['ip'], origin['hop'])}.",
            origin["hop"],
        ))
        for r in responding:
            if r["hop"] >= origin["hop"] and (r["loss"] or 0) >= LOSS_WARN:
                a.hop_marks[r["hop"]] = "real"

    # Verlust nur an Zwischen-Hops (Rate-Limit)
    limited = [h for h in responding[:-1]
               if (h["loss"] or 0) >= LOSS_WARN and a.hop_marks.get(h["hop"]) != "real"]
    for h in limited:
        a.hop_marks[h["hop"]] = "ratelimit"
    if limited:
        names = ", ".join(f"Hop {h['hop']} ({h['loss']:.0f} %)" for h in limited)
        a.findings.append(Finding(
            "info",
            f"{names}: Verlust nur an diesem Router, spätere Hops sind sauber – der Router beantwortet Pings "
            "gedrosselt (ICMP-Ratenbegrenzung). Kein Problem für den Datenverkehr.",
        ))

    # Latenzsprung, der bis zum Ziel bestehen bleibt
    for i in range(1, len(responding)):
        prev, cur = responding[i - 1], responding[i]
        if prev.get("avg") is None or cur.get("avg") is None:
            continue
        jump = cur["avg"] - prev["avg"]
        if jump < JUMP_MS or jump < prev["avg"] * JUMP_RATIO:
            continue
        rest = [r for r in responding[i:] if r.get("avg") is not None]
        if all(r["avg"] - prev["avg"] >= jump * CARRY_RATIO for r in rest):
            a.hop_marks.setdefault(cur["hop"], "jump")
            a.findings.append(Finding(
                "warn" if jump >= 50 else "info",
                f"Latenzsprung +{jump:.0f} ms zwischen Hop {prev['hop']} und Hop {cur['hop']} ({cur['ip']}), "
                f"bleibt bis zum Ziel bestehen – Bereich: {segment(cur['ip'], cur['hop'])}.",
                cur["hop"],
            ))
            break

    noreply = [h["hop"] for h in hops if not h.get("ip") and h["hop"] < last["hop"]]
    if noreply:
        a.findings.append(Finding(
            "info",
            f"Hop {', '.join(map(str, noreply))} antwortet nicht auf Pings. Das ist bei vielen Routern so eingestellt "
            "und kein Fehler, solange spätere Hops antworten.",
        ))

    if not any(f.level in ("warn", "bad") for f in a.findings):
        a.findings.insert(0, Finding(
            "ok",
            f"Pfad zu {target or 'Ziel'} unauffällig: {dest_loss:.1f} % Verlust am Ziel"
            + (f", {last['avg']:.1f} ms" if last.get("avg") is not None else "") + ".",
        ))
    levels = {f.level for f in a.findings}
    a.verdict = "bad" if "bad" in levels else "warn" if "warn" in levels else "ok"
    return a
