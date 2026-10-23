"""Störungen: gleichzeitige Ausfälle eines Standorts gebündelt und aus den Rohdaten eingeordnet.

Ein Ausfall (``outages``) betrifft ein Ziel an einer Probe. Fällt die Leitung kurz aus, sind mehrere Ziele
gleichzeitig weg – das ist **eine** Störung. Die Analyse zeigt für ein Zeitfenster jede Messung des
Standorts sekundengenau (Ziel-Pings und die Hops der Traceroutes) und leitet daraus ab, bis wohin das
Netz während der Störung noch antwortete.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field

from .. import repo
from ..db import q
from . import outages, vm

MERGE_GAP_S = 60          # Ausfälle mit höchstens so viel Abstand gehören zur selben Störung
MAX_POINTS = 900          # Auflösung der Analyse: höchstens so viele Schritte je Reihe
MAX_WINDOW_S = 7 * 86400
LOSS_PCT = 2.0           # darunter (und ohne 2 Pakete in Folge) gelten einzelne Verluste als normal
DOWN_RATIO = 0.8          # ab diesem Verlust im Kernzeitraum gilt eine Reihe als ausgefallen

# Weg vom Standort nach außen: Reihenfolge der Spuren im Dashboard und der Einordnung
LAYERS = ("gateway", "provider", "reference", "datacenter", "target")
LANE_LABELS = {"probe": "Probes", "gateway": "Gateway / LAN", "provider": "Provider-Netz",
               "reference": "Internet", "datacenter": "Rechenzentrum", "target": "Weitere Ziele"}
CAUSE_LANE = {"probe": "probe", "gateway": "gateway", "provider": "provider", "wan": "reference",
              "reference": "reference"}


@dataclass
class Incident:
    site: str
    site_name: str
    start: int
    end: int | None
    items: list = field(default_factory=list)

    @property
    def duration(self) -> int:
        return (self.end or repo.now()) - self.start

    @property
    def main(self):
        """Wichtigster Ausfall: höchste Ursache, bei Gleichstand der früheste."""
        return max(self.items, key=lambda o: (outages.PRIORITY[o.cause], -o.start))

    @property
    def cause_label(self) -> str:
        return self.main.cause_label

    @property
    def probes(self) -> list[str]:
        return sorted({o.probe_name for o in self.items})

    @property
    def probe_refs(self) -> list[tuple[str, str]]:
        """(Probe-ID, Name) für Links."""
        return sorted({(o.probe, o.probe_name) for o in self.items}, key=lambda p: p[1])

    @property
    def targets(self) -> list[str]:
        seen: list[str] = []
        for o in sorted(self.items, key=lambda o: o.start):
            name = o.target or {"probe": "Probe", "wan": "alle Internet-Referenzen"}.get(o.cause, o.cause_label)
            if name not in seen:
                seen.append(name)
        return seen

    @property
    def end_key(self) -> int:
        return self.end or 0


def lane_of(o) -> str:
    return CAUSE_LANE.get(o.cause) or (o.role if o.role in LANE_LABELS else "target")


def cluster(items: list, gap: int = MERGE_GAP_S) -> list[Incident]:
    """Ausfälle je Standort zu Störungen bündeln (überlappend oder höchstens ``gap`` Sekunden auseinander)."""
    ts = repo.now()
    out: list[Incident] = []
    by_site: dict[str, list] = {}
    for o in items:
        by_site.setdefault(o.site, []).append(o)
    for site, group in by_site.items():
        group.sort(key=lambda o: o.start)
        cur: Incident | None = None
        for o in group:
            if cur is not None and o.start <= (cur.end or ts) + gap:
                cur.items.append(o)
                if cur.end is not None:
                    cur.end = None if o.end is None else max(cur.end, o.end)
                continue
            cur = Incident(site=site, site_name=o.site_name, start=o.start, end=o.end, items=[o])
            out.append(cur)
    out.sort(key=lambda i: i.start, reverse=True)
    return out


def load(since: int, site_id: int | None = None, refine: bool = True) -> list[Incident]:
    from . import settings as settings_service

    min_s = settings_service.get()["outage_min_s"]
    items = outages.load(since, str(site_id) if site_id is not None else None, min_s,
                         include_consequences=True, refine=refine)
    return cluster(items)


def summary(incidents: list[Incident]) -> dict:
    return {
        "count": len(incidents),
        "active": sum(1 for i in incidents if i.end is None),
        "seconds": sum(i.duration for i in incidents),
        "longest": max((i.duration for i in incidents), default=0),
    }


# -- Zeitachsen ---------------------------------------------------------------
TICKS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)


def nice_window(start: int, end: int, pad: int | None = None) -> tuple[int, int, int]:
    """Fenster um [start, end] mit Rand, an einer runden Teilung ausgerichtet: (von, bis, Teilung).

    Die Teilung ergibt 4 bis 12 gleich breite Spalten für die Zeitachse.
    """
    span = max(end - start, 1)
    pad = max(30, span // 2) if pad is None else pad
    lo, hi = start - pad, end + pad
    tick = next((t for t in TICKS if (hi - lo) / t <= 10), 86400)
    lo, hi = lo // tick * tick, -(-hi // tick) * tick
    while (hi - lo) // tick < 4:
        lo -= tick
        hi += tick
    return lo, hi, tick


def step_for(span: int) -> int:
    return max(1, math.ceil(span / MAX_POINTS))


# -- Analyse ------------------------------------------------------------------
@dataclass
class Lane:
    probe: str
    probe_name: str
    check_id: str
    target: str
    role: str
    hop: int | None = None
    hop_ip: str = ""
    check_name: str = ""
    path_target: str = ""
    up: dict = field(default_factory=dict)
    rtt: dict = field(default_factory=dict)
    sample_s: int = 1
    # Auswertung im Kernzeitraum
    status: str = "nodata"        # ok | loss | down | nodata | silent (Hop antwortet auch sonst nicht)
    loss_pct: float | None = None
    down: list = field(default_factory=list)   # [(von, bis)]
    first_loss: int | None = None
    rtt_before: float | None = None
    rtt_during: float | None = None
    rtt_max: float | None = None

    @property
    def label(self) -> str:
        if self.hop is not None:
            return f"Hop {self.hop}" + (f" · {self.hop_ip}" if self.hop_ip else "")
        return self.target

    @property
    def role_label(self) -> str:
        if self.hop is not None:
            return f"Pfad zu {self.path_target}"
        return repo.CHECK_ROLES.get(self.role, self.role)

    @property
    def down_seconds(self) -> int:
        return sum(e - s for s, e in self.down)


def _sample_step(points: dict, step: int) -> int:
    """Abstand zweier Messungen (Ping-Intervall), mindestens ein Schritt."""
    ts = sorted(points)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    return max(int(statistics.median(gaps)) if gaps else step, step)


def _evaluate(lane: Lane, core_start: int, core_end: int, window_start: int, step: int) -> None:
    lane.sample_s = _sample_step(lane.up, step)
    inside = [(t, v) for t, v in sorted(lane.up.items()) if core_start - lane.sample_s < t < core_end]
    before = [v for t, v in lane.up.items() if t < core_start - lane.sample_s]
    if inside:
        lane.loss_pct = round((1 - statistics.fmean(v for _, v in inside)) * 100, 1)
        lost = [t for t, v in inside if v < 1]
        lane.first_loss = lost[0] if lost else None
    samples = [(t, v) for t, v in sorted(lane.up.items())]
    lane.down = [(s, e) for s, e in outages.down_intervals([(t, 1.0 if v > 0 else 0.0) for t, v in samples])
                 if e > window_start]
    rtt_before = [v for t, v in lane.rtt.items() if t < core_start]
    rtt_during = [v for t, v in lane.rtt.items() if core_start <= t <= core_end]
    lane.rtt_before = round(statistics.median(rtt_before), 2) if rtt_before else None
    lane.rtt_during = round(statistics.median(rtt_during), 2) if rtt_during else None
    lane.rtt_max = max(lane.rtt.values()) if lane.rtt else None
    if lane.hop is not None and before and max(before) == 0:
        lane.status = "silent"    # Router beantwortet Pings grundsätzlich nicht: keine Aussage möglich
    elif lane.loss_pct is None:
        lane.status = "nodata"
    elif lane.loss_pct >= DOWN_RATIO * 100 or (
            core_end - core_start >= 2 * lane.sample_s
            and sum(max(0, min(e, core_end) - max(s, core_start)) for s, e in lane.down)
            >= 0.5 * (core_end - core_start)):
        lane.status = "down"
    elif lane.loss_pct >= LOSS_PCT or any(min(e, core_end) - max(s, core_start) >= 2 * lane.sample_s
                                          for s, e in lane.down):
        lane.status = "loss"   # einzelne verlorene Pakete sind normal und kein Hinweis auf die Ursache
    else:
        lane.status = "ok"


def analyze(site_id: int, core_start: int, core_end: int, window: tuple[int, int, int] | None = None,
            hops: bool = True) -> dict:
    """Alle Messreihen des Standorts im Fenster um [core_start, core_end] auswerten und einordnen.

    ``window`` = (von, bis, Teilung) legt das Fenster fest (Tagesansicht), sonst mit Rand um den Kern.
    """
    w_start, w_end, tick = window or nice_window(core_start, core_end)
    w_end = min(w_end, max(repo.now(), core_end))
    step = step_for(w_end - w_start)
    raw = vm.window_series(site_id, w_start, w_end, step)
    checks = {str(c["id"]): c for c in q("SELECT id, name, target, type FROM checks")}
    lanes: list[Lane] = []
    for (probe, check_id, hop), entry in raw.items():
        if hop and not hops:
            continue
        lb = entry["labels"]
        c = checks.get(check_id, {})
        lane = Lane(probe=probe, probe_name=lb.get("probe_name", probe), check_id=check_id,
                    target=lb.get("target", ""), role=lb.get("role", "target"),
                    hop=int(hop) if hop else None, hop_ip=", ".join(sorted(entry["ips"])),
                    check_name=c.get("name", ""), path_target=lb.get("target", ""),
                    up=entry["up"], rtt=entry["rtt"])
        _evaluate(lane, core_start, core_end, w_start, step)
        lanes.append(lane)
    order = {r: i for i, r in enumerate(LAYERS)}
    lanes.sort(key=lambda ln: (ln.probe_name, ln.hop is not None, ln.check_id if ln.hop is not None else "",
                               order.get(ln.role, 9) if ln.hop is None else 0, ln.hop or 0, ln.target))
    by_probe: dict[str, list[Lane]] = {}
    for ln in lanes:
        by_probe.setdefault(ln.probe_name, []).append(ln)
    return {
        "start": w_start, "end": w_end, "tick": tick, "step": step, "lanes": lanes,
        "probes": [{"name": name, "probe": ls[0].probe, "lanes": ls, "findings": diagnose(ls)}
                   for name, ls in by_probe.items()],
    }


def _names(lanes: list[Lane]) -> str:
    return ", ".join(ln.target for ln in lanes)


def diagnose(lanes: list[Lane]) -> list[tuple[str, str]]:
    """Einordnung je Probe: (Stufe ok|warn|bad|info, Satz). Erst die Ziel-Pings Schicht für Schicht, dann die Pfade."""
    pings = [ln for ln in lanes if ln.hop is None and ln.status != "nodata"]
    out: list[tuple[str, str]] = []
    if not pings:
        return [("info", "Keine Ping-Messwerte in diesem Zeitraum – Probe offline oder Daten bereits gelöscht.")]
    layer = {r: [ln for ln in pings if ln.role == r] for r in LAYERS}
    bad = [ln for ln in pings if ln.status in ("down", "loss")]
    if not bad:
        out.append(("ok", "Alle Ziele haben in diesem Zeitraum ohne Verlust geantwortet."))
    elif all(ln.status in ("down", "loss") for ln in pings) and len(pings) > 1:
        out.append(("bad", "Alle Ziele waren gleichzeitig gestört – auch das Gateway. Probe, Netzwerkkarte, "
                           "Switch oder Router am Standort prüfen."))
    else:
        reached: list[Lane] = []
        for role in LAYERS:
            items = layer[role]
            if not items:
                continue
            failed = [ln for ln in items if ln.status in ("down", "loss")]
            if not failed:
                reached += items
                continue
            where = repo.CHECK_ROLES[role]
            if reached:
                ok_txt = f"Bis {_names(reached[-3:])} ({repo.CHECK_ROLES[reached[-1].role]}) war alles erreichbar. "
            else:
                ok_txt = ""
            fail_txt = f"Gestört: {_names(failed)} ({where})."
            if role == "gateway":
                hint = " Das Problem liegt im lokalen Netz oder am Router des Standorts."
            elif role == "provider":
                hint = (" Das Gateway am Standort antwortete, das Netz des Providers dahinter nicht – "
                        "die Störung liegt beim Provider.")
            elif role == "reference" and len(failed) == len(items):
                hint = (" Das Netz des Providers antwortete, das Internet dahinter nicht – Übergang oder "
                        "Upstream des Providers prüfen lassen." if layer["provider"] else
                        " Gateway erreichbar, Internet nicht – Internetanschluss bzw. Provider.")
            elif role in ("reference", "datacenter", "target") and len(failed) < len(items):
                hint = " Andere Ziele derselben Art antworteten – die Störung betrifft nur diese Ziele."
            else:
                hint = ""
            out.append(("bad" if any(ln.status == "down" for ln in failed) else "warn", ok_txt + fail_txt + hint))
            break
    # Pfade: bis zu welchem Hop kamen während der Störung noch Antworten?
    paths: dict[str, list[Lane]] = {}
    for ln in lanes:
        if ln.hop is not None and ln.status not in ("nodata", "silent"):
            paths.setdefault(ln.check_id, []).append(ln)
    for hops in paths.values():
        hops.sort(key=lambda ln: ln.hop)
        first_bad = next((ln for ln in hops if ln.status == "down"), None)
        if first_bad is None:
            continue
        # nur echte Abbrüche: ab hier bleiben alle späteren Hops ebenfalls weg
        later = [ln for ln in hops if ln.hop > first_bad.hop]
        if later and not all(ln.status in ("down", "loss") for ln in later):
            continue
        before = [ln for ln in hops if ln.hop < first_bad.hop and ln.status in ("ok", "loss")]
        last_ok = before[-1] if before else None
        txt = f"Traceroute zu {first_bad.path_target}: "
        txt += (f"Hop {last_ok.hop} ({last_ok.hop_ip or '?'}) antwortete weiter, " if last_ok else "")
        txt += f"ab Hop {first_bad.hop} ({first_bad.hop_ip or '?'}) keine Antwort mehr."
        if last_ok:
            txt += f" Die Unterbrechung liegt zwischen Hop {last_ok.hop} und Hop {first_bad.hop}."
        out.append(("bad", txt))
    order = sorted((ln for ln in bad if ln.first_loss is not None), key=lambda ln: ln.first_loss)
    if len(order) > 1 and order[-1].first_loss - order[0].first_loss >= 2:
        out.append(("info", f"Zuerst betroffen: {order[0].target}, "
                            f"{order[-1].first_loss - order[0].first_loss} s vor {order[-1].target}."))
    jumps = [ln for ln in pings if ln.rtt_before and ln.rtt_during and ln.rtt_during > max(2 * ln.rtt_before,
                                                                                          ln.rtt_before + 20)]
    if jumps:
        out.append(("warn", "Latenz stieg während der Störung deutlich: " + ", ".join(
            f"{ln.target} {ln.rtt_before:g} → {ln.rtt_during:g} ms" for ln in jumps[:4]) + "."))
    return out


# -- Darstellung ----------------------------------------------------------------
W = 1000  # Breite der SVG-Spuren (viewBox), Höhe je Spur 20


DASH_RANGES = {"24h": (86400, 3600 * 3, 300), "7d": (7 * 86400, 86400, 1800)}   # Spanne, Teilung, Schritt


def dash_window(range_key: str) -> tuple[int, int, int, int]:
    """Fenster der Dashboard-Zeitleiste, endet an der nächsten vollen Teilung (Ortszeit): (von, bis, Teilung, Schritt)."""
    from datetime import datetime, timedelta

    span, tick, step = DASH_RANGES[range_key]
    now = datetime.now()
    if tick >= 86400:
        end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    else:
        end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    end_ts = int(end.timestamp())
    return end_ts - span, end_ts, tick, step


def heat_class(loss_ratio: float, thr: dict) -> str | None:
    pct = loss_ratio * 100
    if pct <= 0:
        return None
    warn = thr.get("loss_warn_pct") or 2
    bad = thr.get("loss_bad_pct") or 10
    return "h3" if pct >= bad else "h2" if pct >= warn else "h1"


def x_of(t: int, start: int, end: int) -> float:
    return round(max(0.0, min(W, (t - start) / max(end - start, 1) * W)), 2)


def lane_runs(lane: Lane, start: int, end: int) -> list[tuple[float, float, str]]:
    """Zusammenhängende Abschnitte gleichen Zustands als (x, Breite, Klasse) für die SVG-Spur."""
    runs: list[list] = []
    # grobe Schritte (Tagesansicht): einzelne verlorene Pakete im Schritt nicht als Verlust färben
    ok_min = 1.0 if lane.sample_s <= 1 else 0.97
    for t, v in sorted(lane.up.items()):
        cls = "s-ok" if v >= ok_min else "s-silent" if lane.status == "silent" else "s-down" if v <= 0 else "s-loss"
        t_end = t + lane.sample_s
        if runs and runs[-1][2] == cls and t - runs[-1][1] <= lane.sample_s:
            runs[-1][1] = t_end
        else:
            runs.append([t, t_end, cls])
    out = []
    for a, b, cls in runs:
        x1, x2 = x_of(a, start, end), x_of(b, start, end)
        if x2 > x1:
            # Verlust nie schmaler als 2 Einheiten, damit 1-s-Lücken im Tagesfenster sichtbar bleiben
            out.append((x1, max(x2 - x1, 2.0 if cls in ("s-down", "s-loss") else 0.0), cls))
    return out


def lane_line(lane: Lane, start: int, end: int, height: float = 20.0) -> str:
    """Laufzeit als Linie in der Spur (oben = höchster Wert der Spur); Lücken unterbrechen die Linie."""
    if not lane.rtt or not lane.rtt_max:
        return ""
    top = lane.rtt_max * 1.1
    parts, prev = [], None
    for t, v in sorted(lane.rtt.items()):
        cmd = "L" if prev is not None and t - prev <= lane.sample_s * 2 else "M"
        parts.append(f"{cmd}{x_of(t + lane.sample_s // 2, start, end)} {round(height - 2 - v / top * (height - 4), 1)}")
        prev = t
    return " ".join(parts)


def axis(start: int, end: int, tick: int) -> list[int]:
    return list(range(start, end, tick))


def provider_text(site_name: str, core_start: int, core_end: int, analysis: dict, fmt_dt, fmt_duration) -> str:
    """Nüchterne Zusammenfassung zum Weitergeben an den Provider (Zeiten in Serverzeit)."""
    lines = [f"Störung am Standort {site_name}",
             f"Zeitraum: {fmt_dt(core_start)} bis {fmt_dt(core_end)} ({fmt_duration(core_end - core_start)})",
             ""]
    for p in analysis["probes"]:
        pings = [ln for ln in p["lanes"] if ln.hop is None and ln.status != "nodata"]
        if not pings:
            continue
        lines.append(f"Messpunkt {p['name']} (Ping im {pings[0].sample_s}-s-Takt):")
        for ln in pings:
            if ln.status == "ok":
                state = "erreichbar, kein Verlust" if not ln.loss_pct else "erreichbar, nur einzelne Pakete verloren"
            else:
                spans = [f"{fmt_dt(s)[-8:]}–{fmt_dt(e)[-8:]} ({e - s} s)" for s, e in ln.down
                         if e > core_start - 60 and s < core_end + 60]
                state = f"{ln.loss_pct:g} % Verlust" + (f", keine Antwort {', '.join(spans)}" if spans else "")
            lines.append(f"  - {ln.target} [{repo.CHECK_ROLES.get(ln.role, ln.role)}]: {state}")
        for level, text in p["findings"]:
            if level != "ok":
                lines.append(f"  > {text}")
        lines.append("")
    lines.append("Gemessen mit Wachtl. Zeiten in Serverzeit.")
    return "\n".join(lines)
