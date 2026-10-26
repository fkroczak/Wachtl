"""PDF-Bericht mit reportlab: Einschätzung, Zeitstrahl, Leitungsqualität, Störungsliste, Pfade, Bandbreite,
Kundenseite, Netzwerkscan und Messmethode.

Daten kommen fertig aus ``report_data.collect``. Schrift ist Helvetica (Standardschrift jedes PDF-Betrachters);
sie kann nur Zeichen aus Windows-1252, deshalb läuft jeder Text durch ``clean``.
"""
from __future__ import annotations

import io
import math
from datetime import datetime, timedelta
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, PolyLine, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from .report_data import MAX_ANOMALIES, MAX_INCIDENTS, SECTIONS, fmt_dur, fmt_num, fmt_ts

# -- Farben (wie app.css, druckfreundlich) --------------------------------------------
INK = colors.HexColor("#15171a")
MUTED = colors.HexColor("#5b616b")
BORDER = colors.HexColor("#d5d9df")
SOFT = colors.HexColor("#f4f5f7")
ACCENT = colors.HexColor("#0060e0")
ACCENT_SOFT = colors.HexColor("#e8f0fe")
BAD = colors.HexColor("#c42b2b")
BAD_FILL = colors.HexColor("#d93a3a")
BAD_SOFT = colors.HexColor("#fbe9e9")
WARN = colors.HexColor("#b87400")
WARN_SOFT = colors.HexColor("#fdf3e1")
OK = colors.HexColor("#1f7a4d")
OK_SOFT = colors.HexColor("#e6f4ec")
OFF = colors.HexColor("#7a808a")
BAND = colors.HexColor("#c9d7ee")
JITTER = colors.HexColor("#b0457a")
REPORT = colors.HexColor("#7a4a9e")
EMPTY = colors.HexColor("#eef0f3")

LANE_COLORS = {"gateway": BAD_FILL, "wan": BAD, "target": WARN, "probe": OFF, "loss": colors.HexColor("#d08a00")}
VERDICT_COLORS = {"provider": BAD, "lan": WARN, "pc": WARN, "target": ACCENT, "none": OK}
VERDICT_SOFT = {"provider": BAD_SOFT, "lan": WARN_SOFT, "pc": WARN_SOFT, "target": ACCENT_SOFT, "none": OK_SOFT}
WHERE_LABELS = {"provider": "Provider", "lan": "lokales Netz", "unklar": "unklar"}

PAGE_W, PAGE_H = A4
MARGIN_X = 17 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X

_REPLACE = {"→": "->", "←": "<-", "≥": ">=", "≤": "<=", "≈": "~", "−": "-", "⚠": "!", "✓": "ok", "✔": "ok",
            "×": "x", " ": " ", " ": " ", " ": " "}


def clean(text) -> str:
    """Nur Zeichen, die Helvetica (WinAnsi) kennt; Steuerzeichen raus."""
    s = "" if text is None else str(text)
    for a, b in _REPLACE.items():
        s = s.replace(a, b)
    s = "".join(ch for ch in s if ch in "\n\t" or ord(ch) >= 32)
    return s.encode("cp1252", errors="replace").decode("cp1252")


def e(text) -> str:
    """Text für Paragraph-Markup: bereinigt und maskiert."""
    return escape(clean(text)).replace("\n", "<br/>")


# -- Stile ------------------------------------------------------------------------
def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName="Helvetica", fontSize=9, leading=12.2, textColor=INK)
    return {
        "base": base,
        "small": ParagraphStyle("small", parent=base, fontSize=7.6, leading=9.6),
        "muted": ParagraphStyle("muted", parent=base, fontSize=8, leading=10.4, textColor=MUTED),
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.4, leading=9.2),
        "cellb": ParagraphStyle("cellb", parent=base, fontName="Helvetica-Bold", fontSize=7.4, leading=9.2),
        "head": ParagraphStyle("head", parent=base, fontName="Helvetica-Bold", fontSize=7.4, leading=9.2,
                               textColor=MUTED),
        "title": ParagraphStyle("title", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=24),
        "subtitle": ParagraphStyle("subtitle", parent=base, fontSize=11, leading=14, textColor=MUTED),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=14, leading=18, spaceBefore=4,
                             spaceAfter=6, textColor=INK),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=10.5, leading=13.5,
                             spaceBefore=8, spaceAfter=4),
        "verdict": ParagraphStyle("verdict", parent=base, fontName="Helvetica-Bold", fontSize=15, leading=19),
        "kpi": ParagraphStyle("kpi", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=16),
        "kpilabel": ParagraphStyle("kpilabel", parent=base, fontSize=7.4, leading=9, textColor=MUTED),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=10, bulletIndent=1, spaceBefore=1.5),
        "right": ParagraphStyle("right", parent=base, alignment=TA_RIGHT),
    }


S = _styles()


def P(markup: str, style: str = "base") -> Paragraph:
    return Paragraph(markup, S[style])


def heading(text: str, key: str, level: int = 0) -> Paragraph:
    p = Paragraph(e(text), S["h1" if level == 0 else "h2"])
    p._bookmark = (key, clean(text), level)  # Inhaltsverzeichnis des PDF-Betrachters
    return p


def table(rows: list[list], widths: list[float], head: bool = True, zebra: bool = True,
          extra: list | None = None, repeat: bool = True) -> Table:
    """Tabelle mit Kopfzeile, feinen Linien und Zebra-Streifen. Zellen: str (wird maskiert) oder Flowable."""
    data = []
    for i, row in enumerate(rows):
        style = "head" if head and i == 0 else "cell"
        data.append([c if not isinstance(c, str) else P(e(c), style) for c in row])
    t = Table(data, colWidths=widths, repeatRows=1 if head and repeat else 0)
    cmds = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, BORDER),
    ]
    if head:
        cmds += [("LINEBELOW", (0, 0), (-1, 0), 0.8, MUTED), ("BACKGROUND", (0, 0), (-1, 0), SOFT)]
    if zebra:
        for i in range(1 if head else 0, len(data)):
            if i % 2 == 0:
                cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fafbfc")))
    t.setStyle(TableStyle(cmds + (extra or [])))
    return t


def empty(text: str = "Keine Daten im Zeitraum.") -> Paragraph:
    return P(e(text), "muted")


# -- Achsen und Zeit ------------------------------------------------------------------
TICKS = [(3600, "h"), (3 * 3600, "h"), (6 * 3600, "h"), (12 * 3600, "h"), (86400, "d"), (2 * 86400, "d"),
         (7 * 86400, "d"), (14 * 86400, "d"), (30 * 86400, "d"), (61 * 86400, "d")]


def time_ticks(since: int, until: int, max_ticks: int = 9) -> list[tuple[int, str]]:
    span = max(until - since, 1)
    step, kind = next(((s, k) for s, k in TICKS if span / s <= max_ticks), TICKS[-1])
    out = []
    if kind == "h":
        t = datetime.fromtimestamp(since).replace(minute=0, second=0, microsecond=0)
        while int(t.timestamp()) < since or t.hour % (step // 3600):
            t += timedelta(hours=1)
        while int(t.timestamp()) <= until:
            label = t.strftime("%d.%m. %H:%M") if t.hour == 0 or not out else t.strftime("%H:%M")
            out.append((int(t.timestamp()), label))
            t += timedelta(seconds=step)
    else:
        t = datetime.fromtimestamp(since).replace(hour=0, minute=0, second=0, microsecond=0)
        if int(t.timestamp()) < since:
            t += timedelta(days=1)
        days = step // 86400
        if days == 7:
            while t.weekday() != 0:
                t += timedelta(days=1)
        while int(t.timestamp()) <= until:
            out.append((int(t.timestamp()), t.strftime("%d.%m.%y" if days >= 30 else "%d.%m.")))
            t = (t + timedelta(days=days, hours=3)).replace(hour=0)
    return out


def nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def _axis(d: Drawing, x0: float, y0: float, w: float, since: int, until: int, grid_top: float | None = None,
          labels: bool = True) -> None:
    span = max(until - since, 1)
    d.add(Line(x0, y0, x0 + w, y0, strokeColor=MUTED, strokeWidth=0.5))
    for ts, label in time_ticks(since, until):
        x = x0 + (ts - since) / span * w
        if grid_top is not None:
            d.add(Line(x, y0, x, grid_top, strokeColor=EMPTY, strokeWidth=0.4))
        d.add(Line(x, y0, x, y0 - 2.5, strokeColor=MUTED, strokeWidth=0.5))
        if labels:
            d.add(String(x, y0 - 9, clean(label), fontName="Helvetica", fontSize=6.3, fillColor=MUTED,
                         textAnchor="middle"))


# -- Zeitstrahl ------------------------------------------------------------------------
MIN_W = 1.5   # pt: auch ein 5-s-Ausfall im 30-Tage-Bericht bleibt sichtbar


def timeline_drawing(data: dict) -> Drawing:
    tl = data["timeline"]
    since, until = data["meta"]["since"], data["meta"]["until"]
    label_w, lane_h, gap = 82, 13, 3
    lanes = tl["lanes"]
    rows = len(lanes) + 1
    h = rows * (lane_h + gap) + 26
    d = Drawing(CONTENT_W, h)
    x0, w = label_w, CONTENT_W - label_w - 4
    span = max(until - since, 1)

    def X(ts):
        return x0 + (min(max(ts, since), until) - since) / span * w

    top = h - 4
    y_axis = top - rows * (lane_h + gap) - 2
    _axis(d, x0, y_axis, w, since, until, grid_top=top)
    for i, lane in enumerate(lanes):
        y = top - (i + 1) * (lane_h + gap) + gap
        d.add(Rect(x0, y, w, lane_h, fillColor=SOFT, strokeColor=None))
        d.add(String(x0 - 5, y + 3.6, clean(lane["label"]), fontName="Helvetica", fontSize=7.2, fillColor=INK,
                     textAnchor="end"))
        color = LANE_COLORS.get(lane["key"], BAD)
        for it in sorted((it for it in tl["items"] if it["lane"] == lane["key"]), key=lambda it: it["consequence"],
                         reverse=True):
            xa = X(it["a"])
            ww = max(X(it["b"]) - xa, MIN_W)
            c = colors.Color(color.red, color.green, color.blue, alpha=0.35 if it["consequence"] else 1)
            d.add(Rect(min(xa, x0 + w - ww), y + 1, ww, lane_h - 2, fillColor=c, strokeColor=None))
    # Meldungen (Dreieck) und Client-Hinweise (Raute)
    y = top - (len(lanes) + 1) * (lane_h + gap) + gap
    d.add(Rect(x0, y, w, lane_h, fillColor=SOFT, strokeColor=None))
    d.add(String(x0 - 5, y + 3.6, "Meldungen / PC-Hinweise", fontName="Helvetica", fontSize=7.2, fillColor=INK,
                 textAnchor="end"))
    for ts in tl["reports"]:
        x = X(ts)
        d.add(Polygon([x - 3, y + lane_h - 2, x + 3, y + lane_h - 2, x, y + 2], fillColor=REPORT, strokeColor=None))
    for ts in tl["findings"]:
        x = X(ts)
        cy = y + lane_h / 2
        d.add(Polygon([x, cy + 4, x + 3, cy, x, cy - 4, x - 3, cy], fillColor=WARN, strokeColor=None))
    return d


def legend_line(items: list[tuple[colors.Color, str, str]]) -> Drawing:
    """Legende: (Farbe, Form, Text), Form = box | line | tri | dia | dash."""
    d = Drawing(CONTENT_W, 11)
    x = 0
    for color, shape, text in items:
        if shape == "box":
            d.add(Rect(x, 2, 9, 6, fillColor=color, strokeColor=None))
        elif shape == "line":
            d.add(Line(x, 5, x + 10, 5, strokeColor=color, strokeWidth=1.6))
        elif shape == "dash":
            d.add(Line(x, 5, x + 10, 5, strokeColor=color, strokeWidth=0.8, strokeDashArray=[2, 1.5]))
        elif shape == "tri":
            d.add(Polygon([x + 1, 9, x + 8, 9, x + 4.5, 1], fillColor=color, strokeColor=None))
        elif shape == "dia":
            d.add(Polygon([x + 4.5, 9.5, x + 8, 5, x + 4.5, 0.5, x + 1, 5], fillColor=color, strokeColor=None))
        label = clean(text)
        d.add(String(x + 13, 2.2, label, fontName="Helvetica", fontSize=6.8, fillColor=MUTED))
        x += 13 + len(label) * 3.3 + 12
    return d


# -- Tage und Uhrzeiten ------------------------------------------------------------------
def _day_color(day: dict) -> colors.Color:
    if day["down_s"] >= 600:
        return BAD
    if day["down_s"] > 0 or day["severe"]:
        return colors.HexColor("#e88a8a")
    if day["count"]:
        return colors.HexColor("#efc274")
    return EMPTY


def days_drawing(days: list[dict]) -> Drawing:
    """Ein Kästchen je Tag. Bis 31 Tage in einer Zeile mit Zahl, länger als Kalender (Wochen x Wochentage)."""
    if len(days) <= 31:
        cell = min(CONTENT_W / max(len(days), 1), 40)
        h = 40
        d = Drawing(CONTENT_W, h)
        for i, day in enumerate(days):
            x = i * cell
            d.add(Rect(x + 1, 14, cell - 2, 22, fillColor=_day_color(day), strokeColor=None))
            if day["count"]:
                d.add(String(x + cell / 2, 22, str(day["count"]), fontName="Helvetica-Bold", fontSize=7.5,
                             fillColor=colors.white if day["down_s"] >= 600 else INK, textAnchor="middle"))
            if len(days) <= 16 or i % 2 == 0:
                d.add(String(x + cell / 2, 5, clean(day["label"][3:] if len(days) > 10 else day["label"]),
                             fontName="Helvetica", fontSize=5.8 if len(days) > 10 else 6.5, fillColor=MUTED,
                             textAnchor="middle"))
        return d
    first = datetime.fromtimestamp(days[0]["day"])
    offset = first.weekday()
    weeks = (len(days) + offset + 6) // 7
    left = 18
    cell = min((CONTENT_W - left) / max(weeks, 1), 14)
    h = 7 * cell + 16
    d = Drawing(CONTENT_W, h)
    for r, name in enumerate(("Mo", "Mi", "Fr")):
        d.add(String(0, h - 4 - (r * 2 + 1) * cell + cell * 0.25, name, fontName="Helvetica", fontSize=6,
                     fillColor=MUTED))
    last_month = None
    for i, day in enumerate(days):
        k = i + offset
        col, row = k // 7, k % 7
        x, y = left + col * cell, h - 4 - (row + 1) * cell
        d.add(Rect(x + 0.6, y + 0.6, cell - 1.2, cell - 1.2, fillColor=_day_color(day), strokeColor=None))
        month = datetime.fromtimestamp(day["day"]).strftime("%m.%y")
        if month != last_month and row <= 1:
            d.add(String(x, 2, month, fontName="Helvetica", fontSize=6, fillColor=MUTED))
            last_month = month
    return d


def hours_drawing(hours: list[int]) -> Drawing:
    h, left = 70, 18
    d = Drawing(CONTENT_W, h)
    w = CONTENT_W - left
    bw = w / 24
    top = max(hours) or 1
    ymax = nice_max(top)
    base = 12
    ph = h - base - 6
    for v in (0, ymax):
        y = base + v / ymax * ph
        d.add(Line(left, y, left + w, y, strokeColor=EMPTY if v else MUTED, strokeWidth=0.4))
        d.add(String(left - 3, y - 2, f"{ymax:g}" if v else "0", fontName="Helvetica", fontSize=6,
                     fillColor=MUTED, textAnchor="end"))
    for i, v in enumerate(hours):
        if v:
            d.add(Rect(left + i * bw + 1.2, base, bw - 2.4, v / ymax * ph, fillColor=BAD_FILL, strokeColor=None))
        d.add(String(left + i * bw + bw / 2, 3, f"{i:02d}", fontName="Helvetica", fontSize=6, fillColor=MUTED,
                     textAnchor="middle"))
    return d


# -- Leitungsqualität -------------------------------------------------------------------
def _segments(points: list[tuple[int, float]], step: int) -> list[list[tuple[int, float]]]:
    """Linie an Datenlücken unterbrechen."""
    segs, cur, last = [], [], None
    for ts, v in points:
        if last is not None and ts - last > 1.6 * step:
            segs.append(cur)
            cur = []
        cur.append((ts, v))
        last = ts
    if cur:
        segs.append(cur)
    return segs


def _loss_color(pct: float) -> colors.Color:
    if pct >= 50:
        return BAD
    if pct >= 5:
        return BAD_FILL
    if pct >= 1:
        return colors.HexColor("#e88a8a")
    return colors.HexColor("#f2c0c0")


def quality_drawing(qi: dict) -> Drawing:
    since, until, step = qi["since"], qi["until"], qi["step"]
    inet, gw = qi["internet"] or {}, qi["gateway"] or {}
    left, right = 82, 4
    w = CONTENT_W - left - right
    lat_h, strip_h, jit_h = 92, 10, 34
    h = lat_h + 2 * (strip_h + 4) + jit_h + 40
    d = Drawing(CONTENT_W, h)
    span = max(until - since, 1)

    def X(ts):
        return left + (min(max(ts, since), until) - since) / span * w

    # Latenz
    y0 = h - 6 - lat_h
    lat_values = [v for _, v in inet.get("p90", []) or inet.get("avg", [])] + [v for _, v in gw.get("avg", [])]
    lat_values.sort()
    ref = lat_values[int(0.98 * (len(lat_values) - 1))] if lat_values else 1
    ymax = nice_max(ref * 1.25)

    def Y(v):
        return y0 + min(v, ymax) / ymax * lat_h

    d.add(Rect(left, y0, w, lat_h, fillColor=None, strokeColor=EMPTY, strokeWidth=0.4))
    for frac in (0.5, 1):
        y = y0 + frac * lat_h
        d.add(Line(left, y, left + w, y, strokeColor=EMPTY, strokeWidth=0.4))
        d.add(String(left - 3, y - 2.2, f"{ymax * frac:g} ms", fontName="Helvetica", fontSize=6.2, fillColor=MUTED,
                     textAnchor="end"))
    d.add(String(0, y0 + lat_h - 8, "Latenz", fontName="Helvetica-Bold", fontSize=7.2, fillColor=INK))
    d.add(String(0, y0 + lat_h - 17, "Mittel und p10-p90", fontName="Helvetica", fontSize=6.2, fillColor=MUTED))
    p10, p90 = dict(inet.get("p10", [])), dict(inet.get("p90", []))
    band = sorted(ts for ts in p10 if ts in p90)
    for seg in _segments([(ts, 0) for ts in band], step):
        pts = [(X(ts - step), Y(p90[ts])) for ts, _ in seg[:1]] + [(X(ts), Y(p90[ts])) for ts, _ in seg]
        low = [(X(ts), Y(p10[ts])) for ts, _ in reversed(seg)] + [(X(seg[0][0] - step), Y(p10[seg[0][0]]))]
        flat = [c for xy in pts + low for c in xy]
        if len(flat) >= 6:
            d.add(Polygon(flat, fillColor=BAND, strokeColor=None))
    for series, color, width in ((gw.get("avg", []), OK, 0.9), (inet.get("avg", []), ACCENT, 1.0)):
        for seg in _segments(series, step):
            pts = [c for ts, v in seg for c in (X(ts), Y(v))]
            if len(pts) == 2:
                pts += [pts[0] + 0.8, pts[1]]
            d.add(PolyLine(pts, strokeColor=color, strokeWidth=width))
        over = [ts for ts, v in series if v > ymax]
        for ts in over:
            d.add(Line(X(ts), y0 + lat_h, X(ts), y0 + lat_h - 3, strokeColor=color, strokeWidth=1))

    # Verlust als Streifen: jede Minute mit Verlust wird sichtbar (Maximum der Minutenwerte je Abschnitt)
    y = y0 - 5 - strip_h
    for label, src in (("Verlust Internet", inet), ("Verlust Gateway", gw)):
        d.add(Rect(left, y, w, strip_h, fillColor=SOFT, strokeColor=None))
        d.add(String(left - 3, y + 2.6, label, fontName="Helvetica", fontSize=6.6, fillColor=INK, textAnchor="end"))
        series = src.get("loss_max") or src.get("loss") or []
        if not src:
            d.add(String(left + 4, y + 2.6, "kein Check", fontName="Helvetica", fontSize=6.2, fillColor=MUTED))
        for ts, v in series:
            if v and v > 0.05:
                xa = X(ts - step)
                ww = max(X(ts) - xa, MIN_W)
                d.add(Rect(xa, y + 0.5, ww, strip_h - 1, fillColor=_loss_color(v), strokeColor=None))
        y -= strip_h + 4

    # Jitter
    jy0 = y - jit_h + strip_h - 2
    jit_vals = sorted(v for _, v in inet.get("jitter", []) + gw.get("jitter", []))
    jref = jit_vals[int(0.98 * (len(jit_vals) - 1))] if jit_vals else 1
    jmax = nice_max(max(jref * 1.25, 5))
    d.add(Rect(left, jy0, w, jit_h, fillColor=None, strokeColor=EMPTY, strokeWidth=0.4))
    d.add(String(0, jy0 + jit_h - 8, "Jitter", fontName="Helvetica-Bold", fontSize=7.2, fillColor=INK))
    d.add(String(left - 3, jy0 + jit_h - 2.2, f"{jmax:g} ms", fontName="Helvetica", fontSize=6.2, fillColor=MUTED,
                 textAnchor="end"))
    if jmax >= 30:
        ty = jy0 + 30 / jmax * jit_h
        d.add(Line(left, ty, left + w, ty, strokeColor=WARN, strokeWidth=0.6, strokeDashArray=[2, 1.5]))
    for series, color, width in ((gw.get("jitter", []), OK, 0.7), (inet.get("jitter", []), JITTER, 0.9)):
        for seg in _segments(series, step):
            pts = [c for ts, v in seg for c in (X(ts), jy0 + min(v, jmax) / jmax * jit_h)]
            if len(pts) == 2:
                pts += [pts[0] + 0.8, pts[1]]
            d.add(PolyLine(pts, strokeColor=color, strokeWidth=width))
    _axis(d, left, jy0, w, since, until)
    return d


# -- Seitenrahmen --------------------------------------------------------------------------
def _canvas_class(footer: str, generated: str):
    class NumberedCanvas(pdfcanvas.Canvas):
        """Kopf- und Fußzeile mit „Seite x von y“ (Gesamtzahl erst am Ende bekannt)."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages: list[dict] = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            n = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._decorate(n)
                super().showPage()
            super().save()

        def _decorate(self, n: int) -> None:
            page = self._pageNumber
            self.saveState()
            self.setStrokeColor(BORDER)
            self.setLineWidth(0.5)
            self.line(MARGIN_X, 13 * mm, PAGE_W - MARGIN_X, 13 * mm)
            self.setFont("Helvetica", 7)
            self.setFillColor(MUTED)
            self.drawString(MARGIN_X, 9 * mm, clean(f"{footer} · Seite {page} von {n}"))
            self.drawRightString(PAGE_W - MARGIN_X, 9 * mm, clean(f"Erstellt {generated}"))
            if page > 1:
                self.setFillColor(ACCENT)
                self.rect(MARGIN_X, PAGE_H - 11 * mm, 2.2, 3.6 * mm, stroke=0, fill=1)
                self.setFillColor(INK)
                self.setFont("Helvetica-Bold", 7.5)
                self.drawString(MARGIN_X + 5, PAGE_H - 10.2 * mm, "Wachtl Netzwerkbericht")
                self.setFont("Helvetica", 7.5)
                self.setFillColor(MUTED)
                self.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 10.2 * mm, clean(footer.split(" · ", 1)[1]))
            self.restoreState()

    return NumberedCanvas


class _Doc(SimpleDocTemplate):
    def afterFlowable(self, flowable):
        mark = getattr(flowable, "_bookmark", None)
        if mark:
            key, title, level = mark
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, level=level, closed=level > 0)


# -- Abschnitte -------------------------------------------------------------------------------
def period_text(meta: dict) -> str:
    return f"{fmt_ts(meta['since'], False)} bis {fmt_ts(meta['until'], False)}"


def _kpi(value: str, label: str, tone: colors.Color | None = None) -> list:
    style = ParagraphStyle("k", parent=S["kpi"], textColor=tone or INK)
    return [Paragraph(e(value), style), P(e(label), "kpilabel")]


def cover(data: dict) -> list:
    meta, k, v = data["meta"], data["kpis"], data["verdict"]
    out = [
        Table([[P("<b>Wachtl</b>", "muted"), P(e(f"Erstellt am {fmt_ts(meta['generated_at'], False)}"), "right")]],
              colWidths=[CONTENT_W / 2] * 2, style=[("LEFTPADDING", (0, 0), (-1, -1), 0),
                                                    ("RIGHTPADDING", (0, 0), (-1, -1), 0)]),
        Spacer(1, 4),
        P("Netzwerk-Störungsbericht", "title"),
        P(e(f"{meta['site_label']} · {period_text(meta)}"), "subtitle"),
        Spacer(1, 10),
    ]
    info = [["Kunde", meta["customer"] or "–"],
            ["Standort", meta["site_label"] + (f" (Kd.-Nr. {meta['customer_no']})" if meta["customer_no"] else "")],
            ["Zeitraum", f"{fmt_ts(meta['since'])} bis {fmt_ts(meta['until'])} "
                         f"({fmt_dur(meta['until'] - meta['since'])})"],
            ["Erstellt", f"{fmt_ts(meta['generated_at'])}" + (f" von {meta['author']}" if meta["author"] else "")],
            ["Messpunkte", ", ".join(f"{p['hostname']} ({p['site_name']})" for p in data["probes"]
                                     if p["status"] == "active")[:600] or "keine aktiven Probes"]]
    out.append(table([[P(e(a), "cellb"), P(e(b), "cell")] for a, b in info], [28 * mm, CONTENT_W - 28 * mm],
                     head=False, zebra=False))
    out.append(Spacer(1, 12))

    color, soft = VERDICT_COLORS[v["key"]], VERDICT_SOFT[v["key"]]
    box = [P("EINSCHÄTZUNG: WO LIEGT DAS PROBLEM?", "head"), Spacer(1, 2),
           Paragraph(e(v["title"]), ParagraphStyle("vt", parent=S["verdict"], textColor=color)),
           P(e(f"Sicherheit der Einschätzung: {v['confidence']}. {v['text']}"), "base"), Spacer(1, 4)]
    for b in v["bullets"]:
        box.append(Paragraph(e(b), S["bullet"], bulletText="•"))
    box += [Spacer(1, 4), P(f"<b>Empfehlung:</b> {e(v['advice'])}", "base")]
    vt = Table([[box]], colWidths=[CONTENT_W])
    vt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), soft), ("LINEBEFORE", (0, 0), (0, -1), 4, color),
                            ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                            ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    out += [vt, Spacer(1, 12)]

    avail = k["availability"]
    longest = k["longest"]
    cells = [
        _kpi(fmt_num(avail, "%", 3 if avail is not None and avail > 99.9 else 2) if avail is not None else "–",
             "Verfügbarkeit Internet", BAD if avail is not None and avail < 99.5 else None),
        _kpi(str(k["incidents"]), f"Störungen (davon {k['severe']} Internet/LAN)", BAD if k["severe"] else None),
        _kpi(str(k["short"]), "davon Kurzausfälle unter 60 s"),
        _kpi(fmt_dur(longest["duration"]) if longest else "–",
             "längste Störung" + (f", {fmt_ts(longest['start'], False)}" if longest else "")),
        _kpi(fmt_dur(k["down_s"]), "Ausfallzeit Internet (Standort ohne Verbindung)"),
        _kpi(f"{fmt_num(k['loss_gateway'], '%')} / {fmt_num(k['loss_internet'], '%')}",
             "Paketverlust Ø Gateway / Internet"),
        _kpi(f"{fmt_num(k['latency_avg'], 'ms')} / {fmt_num(k['latency_p95'], 'ms')}",
             "Latenz Internet Ø / 95 %-Wert"),
        _kpi(fmt_num(k["jitter_avg"], "ms"), "Jitter Internet Ø"),
    ]
    grid = Table([cells[:4], cells[4:]], colWidths=[CONTENT_W / 4] * 4)
    grid.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, BORDER), ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                              ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 6),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LEFTPADDING", (0, 0), (-1, -1), 7)]))
    out.append(grid)
    extra = []
    if k["loss_minutes"] is not None:
        extra.append(f"Minuten mit Paketverlust ins Internet: {k['loss_minutes']}")
    if k["anomalies"]:
        extra.append(f"auffällige Zeiträume: {k['anomalies']}")
    extra.append(f"Störungsmeldungen von Benutzern: {k['reports']}")
    extra.append(f"Hinweise der PCs (Kabel, Link, Treiber): {k['findings']}")
    out += [Spacer(1, 4), P(e(" · ".join(extra)), "muted")]

    if data["site_verdicts"]:
        out += [Spacer(1, 10), P("<b>Nach Standort</b>", "base"), Spacer(1, 3)]
        rows = [["Standort", "Verfügbarkeit", "Störungen", "kurz", "Ausfallzeit", "Einschätzung"]]
        by_name = {s["name"]: s for s in data["sites"]}
        for sv in data["site_verdicts"]:
            s = by_name.get(sv["site"], {})
            rows.append([sv["site"], fmt_num(s.get("availability"), "%", 2) if s.get("availability") is not None
                         else "–", str(s.get("incidents", 0)), str(s.get("short", 0)), fmt_dur(s.get("down_s", 0)),
                         f"{sv['title']} ({sv['confidence']})"])
        out.append(table(rows, [42 * mm, 22 * mm, 17 * mm, 11 * mm, 22 * mm, CONTENT_W - 114 * mm]))
    if meta["remark"]:
        rt = Table([[[P("<b>Bemerkung an den Provider</b>", "base"), Spacer(1, 2), P(e(meta["remark"]), "base")]]],
                   colWidths=[CONTENT_W])
        rt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, BORDER), ("LEFTPADDING", (0, 0), (-1, -1), 9),
                                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        out += [Spacer(1, 10), rt]
    for note in data["notes"]:
        out += [Spacer(1, 6), P(f"<b>Hinweis:</b> {e(note)}", "muted")]
    out += [Spacer(1, 8), P(e("Alle Zeiten in Ortszeit des Wachtl-Servers. Wie gemessen und bewertet wird, steht im "
                              "Anhang."), "muted")]
    return out


def section_timeline(data: dict) -> list:
    out = [heading("Zeitstrahl", "zeitstrahl"),
           P(e("Jede Störung im Zeitraum, nach Ebene getrennt. Auch sehr kurze Ausfälle (wenige Sekunden) sind als "
               "schmaler Strich eingezeichnet. Blasse Balken sind Folgestörungen: Fällt das Gateway aus, ist auch "
               "das Internet weg."), "muted"), Spacer(1, 6), timeline_drawing(data),
           legend_line([(BAD, "box", "Ausfall"), (WARN, "box", "einzelnes Ziel"), (OFF, "box", "Probe offline"),
                        (REPORT, "tri", "Meldung eines Benutzers"), (WARN, "dia", "Hinweis eines PCs (Kabel, Link)")])]
    days = data["daily"]
    out += [Spacer(1, 6), heading("Störungen je Tag", "tage", 1),
            P(e("Zahl = Störungen an diesem Tag. Rot: Internet oder Standort ohne Verbindung (dunkel ab 10 min), "
                "gelb: nur einzelne Ziele oder Paketverlust."), "muted"), Spacer(1, 4), days_drawing(days)]
    if any(data["hours"]):
        out += [Spacer(1, 6), heading("Störungen nach Uhrzeit", "uhrzeit", 1),
                P(e("Beginn der Störungen je Stunde, über alle Tage. Häufungen zu bestimmten Uhrzeiten deuten auf "
                    "Zwangstrennung, Überlast am Abend oder zeitgesteuerte Geräte."), "muted"),
                Spacer(1, 4), hours_drawing(data["hours"])]
    busy = [d for d in days if d["count"]]
    if busy:
        rows = [["Tag", "Störungen", "davon unter 60 s", "Internet/LAN", "Ausfallzeit Internet", "längste"]]
        for d in busy[:120]:
            rows.append([fmt_ts(d["day"], False)[:10], str(d["count"]), str(d["short"]), str(d["severe"]),
                         fmt_dur(d["down_s"]), fmt_dur(d["longest"])])
        out += [Spacer(1, 6), table(rows, [28 * mm, 22 * mm, 28 * mm, 24 * mm, 34 * mm, CONTENT_W - 136 * mm])]
        if len(busy) > 120:
            out.append(P(e(f"Nur die ersten 120 von {len(busy)} Tagen mit Störungen."), "muted"))
    return out


def section_quality(data: dict) -> list:
    out = [heading("Leitungsqualität und Schwankungen", "qualitaet"),
           P(e("Je PC: Latenz zum eigenen Gateway (grün) und ins Internet (blau, Mittel aller Referenzziele, Band = "
               "10-90 % der Pings), Paketverlust als Streifen (jede Minute mit Verlust wird sichtbar) und Jitter. "
               "Entscheidend für die Ursache ist der Vergleich: Ist das Gateway sauber und nur das Internet "
               "schlecht, liegt das Problem hinter dem Router."), "muted")]
    if not data["quality"]:
        msg = ("Keine Messreihen: die Messdatenbank war nicht erreichbar." if not data["vm_ok"]
               else "Keine Ping-Messungen im Zeitraum.")
        return out + [Spacer(1, 4), empty(msg)]
    for qi in data["quality"]:
        block = [CondPageBreak(120 * mm), heading(f"{qi['probe_name']} ({qi['site_name']})", f"q{qi['probe_id']}", 1),
                 quality_drawing(qi),
                 legend_line([(OK, "line", "Gateway"), (ACCENT, "line", "Internet Ø"), (BAND, "box", "Internet p10-p90"),
                              (BAD_FILL, "box", "Verlust"), (JITTER, "line", "Jitter Internet"),
                              (WARN, "dash", "30 ms")]),
                 P(e(f"Ein Wert je {fmt_dur(qi['step'])}."), "muted"), Spacer(1, 4)]
        rows = [["Ziel", "Rolle", "Latenz Ø", "95 %", "Max", "Verlust Ø", "Max/min", "Min. mit Verlust",
                 "verlorene Pings", "Jitter Ø"]]
        for c in qi["checks"]:
            rows.append([c["target"] or c["check_id"], c["role_label"], fmt_num(c["lat_avg"], "ms"),
                         fmt_num(c["lat_p95"], "ms"), fmt_num(c["lat_max"], "ms"), fmt_num(c["loss_avg"], "%"),
                         fmt_num(c["loss_max"], "%"),
                         "–" if c["loss_minutes"] is None else str(c["loss_minutes"]),
                         "–" if c["lost_s"] is None else f"ca. {c['lost_s']}", fmt_num(c["jitter_avg"], "ms")])
        block.append(table(rows, [32 * mm, 21 * mm, 15 * mm, 15 * mm, 15 * mm, 15 * mm, 15 * mm, 17 * mm, 17 * mm,
                                  CONTENT_W - 162 * mm]))
        out += block
        an = qi["anomalies"]
        out.append(Spacer(1, 4))
        if not an:
            out.append(P(e("Keine auffälligen Zeiträume (Verlust über 1 %, Latenz über dem Doppelten des Üblichen, "
                           "Jitter über 30 ms)."), "muted"))
            continue
        out.append(P(f"<b>Auffällige Zeiträume</b> {e(f'({len(an)})')}", "base"))
        rows = [["Beginn", "Ende", "Dauer", "Art", "Internet: Latenz max (üblich)", "Verlust max", "Jitter max",
                 "Gateway", "Bereich"]]
        for a in an[:MAX_ANOMALIES]:
            gw = a["gw_state"] + (f" ({fmt_num(a['gw_loss_max'], '%')})" if a["gw_loss_max"] else "")
            rows.append([fmt_ts(a["start"], False), fmt_ts(a["end"], False), fmt_dur(a["duration"]), a["kind_label"],
                         f"{fmt_num(a['lat_max'], 'ms')} ({fmt_num(a['lat_base'], 'ms')})",
                         fmt_num(a["loss_max"], "%"), fmt_num(a["jitter_max"], "ms"), gw,
                         WHERE_LABELS.get(a["where"], a["where"]) + (" · Ausfall" if a["during_outage"] else "")])
        hl = [("TEXTCOLOR", (8, i), (8, i), BAD) for i, a in enumerate(an[:MAX_ANOMALIES], 1)
              if a["where"] == "provider"]
        out.append(table(rows, [24 * mm, 24 * mm, 15 * mm, 18 * mm, 26 * mm, 14 * mm, 14 * mm, 20 * mm,
                                CONTENT_W - 155 * mm], extra=hl))
        if len(an) > MAX_ANOMALIES:
            out.append(P(e(f"Nur die ersten {MAX_ANOMALIES} von {len(an)} Zeiträumen."), "muted"))
    return out


def section_incidents(data: dict) -> list:
    inc = data["incidents"]
    out = [heading("Störungsliste", "stoerungen"),
           P(e(f"Alle Störungen, zeitlich sortiert. Gleichzeitige Ausfälle eines Standorts (bis "
               f"{data['method']['cluster_gap']} s Abstand) sind zu einer Störung zusammengefasst. Zeiten "
               "sekundengenau aus den 1-s-Messwerten, soweit verfügbar. Kurz = unter 60 s."), "muted"), Spacer(1, 4)]
    if not inc:
        return out + [empty("Keine Störungen im Zeitraum.")]
    rows = [["Nr", "Beginn", "Ende", "Dauer", "Ursache", "Standort / betroffen", "Ziele / Hinweis"]]
    extra = []
    for n, i in enumerate(inc[:MAX_INCIDENTS], 1):
        cause = i["cause_label"]
        others = [c for c in i["cause_labels"] if c != cause]
        hint = []
        if i["targets"]:
            hint.append(", ".join(i["targets"][:6]))
        if others:
            hint.append("Folgen: " + ", ".join(others))
        dur = fmt_dur(i["duration"]) + (" (läuft)" if i["ongoing"] else "")
        rows.append([str(i["no"]), fmt_ts(i["start"]), "läuft noch" if i["ongoing"] else fmt_ts(i["end"]),
                     P(("<b>%s</b>" % e(dur)) + (" <font color='#c42b2b'>kurz</font>" if i["short"] else ""), "cell"),
                     cause, f"{i['site_name']}: " + (", ".join(i["probes"][:6]) or "–"), " · ".join(hint) or "–"])
        if i["cause"] in ("wan", "gateway", "probe"):
            extra.append(("TEXTCOLOR", (4, n), (4, n), BAD))
    out.append(table(rows, [9 * mm, 29 * mm, 29 * mm, 20 * mm, 27 * mm, 34 * mm, CONTENT_W - 148 * mm], extra=extra))
    if len(inc) > MAX_INCIDENTS:
        out.append(P(e(f"Liste gekürzt: {MAX_INCIDENTS} von {len(inc)} Störungen. Für alle Einträge einen kürzeren "
                       "Zeitraum wählen."), "muted"))
    return out


def section_paths(data: dict) -> list:
    out = [heading("Pfadanalyse", "pfad"),
           P(e("Traceroute mit Dauerpings auf jeden Hop. Verlust, der an einem Hop beginnt und bis zum Ziel bleibt, "
               "ist echt. Verlust nur an einem Zwischen-Hop ist meist gedrosselte Antwort des Routers "
               "(ICMP-Ratenbegrenzung) und kein Fehler. Werte gemittelt über den Zeitraum."), "muted"),
           Spacer(1, 4)]
    if not data["paths"]:
        return out + [empty("Keine Pfadmessungen im Zeitraum.")]
    marks = {"real": "echter Verlust", "ratelimit": "Drosselung", "jump": "Latenzsprung", "noreply": "keine Antwort"}
    for pi in data["paths"]:
        block = [heading(f"{pi['probe_name']} -> {pi['target'] or pi['check_name']}",
                         f"p{pi['probe_id']}_{pi['check_id']}", 1)]
        o = pi["loss_origin"]
        if o:
            block.append(P(f"<b><font color='#c42b2b'>Verlust beginnt ab Hop {o['hop']} ({e(o['ip'])})</font></b>"
                           f" – Bereich: {e(o['owner'])}.", "base"))
        for f in pi["findings"]:
            if f["level"] != "ok" or not o:
                block.append(Paragraph(e(f["text"]), S["bullet"], bulletText="•"))
        block.append(P(e(f"Pfadwechsel im Zeitraum: {pi['changes']} · verschiedene Pfade: {pi['paths']} · "
                         f"zuletzt ermittelt {fmt_ts(pi['last_ts'], False)}"), "muted"))
        if not pi["has_values"]:
            block.append(P(e("Keine Hop-Werte aus der Messdatenbank – nur der ermittelte Weg."), "muted"))
        rows = [["Hop", "IP-Adresse", "Bereich", "Verlust Ø", "Latenz Ø", "Max", "Jitter", "Bewertung"]]
        extra = []
        for n, r in enumerate(pi["rows"], 1):
            ip = r["ip"] or "*"
            if r["other_ips"]:
                ip += f" (+{len(r['other_ips'])})"
            rows.append([str(r["hop"]), ip, r["owner"], fmt_num(r["loss"], "%"), fmt_num(r["avg"], "ms"),
                         fmt_num(r["max"], "ms"), fmt_num(r["jitter"], "ms"), marks.get(r["mark"], "")])
            if r["mark"] == "real":
                extra.append(("TEXTCOLOR", (3, n), (3, n), BAD))
                extra.append(("TEXTCOLOR", (7, n), (7, n), BAD))
        block += [Spacer(1, 3), table(rows, [10 * mm, 34 * mm, 34 * mm, 18 * mm, 18 * mm, 18 * mm, 16 * mm,
                                             CONTENT_W - 148 * mm], extra=extra), Spacer(1, 6)]
        out.append(KeepTogether(block) if len(pi["rows"]) <= 25 else block[0])
        if len(pi["rows"]) > 25:
            out += block[1:]
    return out


def section_bandwidth(data: dict) -> list:
    out = [heading("Bandbreite und Sprachqualität", "bandbreite")]
    bw, vo = data["bandwidth"], data["voice"]
    out.append(heading("Bandbreite", "bw", 1))
    if not bw:
        out.append(empty("Keine Bandbreitenmessungen im Zeitraum."))
    else:
        rows = [["PC", "Messung", "Richtung", "Messungen", "Min", "Ø", "Max", "Schwelle", "darunter", "Fehler"]]
        extra = []
        for n, b in enumerate(bw, 1):
            s = b["stats"] or {}
            rows.append([b["probe_name"], b["check_name"], b["direction_label"], str(b["runs"]),
                         fmt_num(s.get("min"), "Mbit/s"), fmt_num(s.get("avg"), "Mbit/s"),
                         fmt_num(s.get("max"), "Mbit/s"), fmt_num(b["threshold"], "Mbit/s") if b["threshold"] else "–",
                         str(b["below"]), str(b["errors"])])
            if b["below"]:
                extra.append(("TEXTCOLOR", (8, n), (8, n), BAD))
        out.append(table(rows, [26 * mm, 30 * mm, 16 * mm, 15 * mm, 17 * mm, 17 * mm, 17 * mm, 17 * mm, 14 * mm,
                                CONTENT_W - 169 * mm], extra=extra))
    out.append(heading("Sprachqualität (RTP-Test, MOS)", "mos", 1))
    if not vo:
        out.append(empty("Keine Sprachtests im Zeitraum."))
    else:
        rows = [["PC", "Gegenstelle", "Tests", "MOS min", "MOS Ø", "Schwelle", "darunter", "Verlust Ø", "Jitter max",
                 "Laufzeit Ø"]]
        for v in vo:
            m = v["mos"] or {}
            rows.append([v["probe_name"], v["peer"] or v["check_name"], str(v["runs"]), fmt_num(m.get("min"), "", 2),
                         fmt_num(m.get("avg"), "", 2), fmt_num(v["min_mos"], "", 1), str(v["below"]),
                         fmt_num(v["loss_avg"], "%"), fmt_num(v["jitter_max"], "ms"), fmt_num(v["rtt_avg"], "ms")])
        out.append(table(rows, [26 * mm, 34 * mm, 12 * mm, 15 * mm, 15 * mm, 15 * mm, 15 * mm, 16 * mm, 17 * mm,
                                CONTENT_W - 165 * mm]))
        out.append(P(e("MOS 4,3 = sehr gut, ab 3,6 brauchbar, unter 3,1 schlecht verständlich."), "muted"))
    return out


def section_customer(data: dict) -> list:
    out = [heading("Kundenseitige Hinweise und Meldungen", "kunde"),
           P(e("Was die PCs selbst erkannt haben (Kabel getrennt, Link-Geschwindigkeit, Treiber) und was Benutzer "
               "gemeldet haben. Solche Hinweise zeigen auf die Seite des Kunden – sie stehen hier vollständig, damit "
               "das Bild ehrlich bleibt."), "muted"), heading("Hinweise der PCs", "hinweise", 1)]
    fi = data["findings"]
    if not fi:
        out.append(empty("Keine Hinweise der PCs im Zeitraum."))
    else:
        rows = [["Erkannt", "Behoben", "PC", "Hinweis", "Netzwerkkarte", "Stufe"]]
        for f in fi[:300]:
            rows.append([fmt_ts(f["detected_at"]), fmt_ts(f["resolved_at"]) if f["resolved_at"] else "aktiv",
                         f["probe_name"], f"{f['kind_label']}" + (f": {f['message']}" if f["message"] else ""),
                         f["adapter"] or "–", f["severity_label"]])
        out.append(table(rows, [28 * mm, 28 * mm, 24 * mm, CONTENT_W - 132 * mm, 34 * mm, 18 * mm]))
    out.append(heading("Meldungen von Benutzern", "meldungen", 1))
    rp = data["reports"]
    if not rp:
        out.append(empty("Keine Meldungen im Zeitraum."))
    else:
        rows = [["Zeitpunkt", "PC", "Benutzer", "Art", "Dauer", "Beschreibung"]]
        for r in rp[:300]:
            rows.append([fmt_ts(r["ts"]), r["probe_name"], r["user"] or "–", r["category_label"], r["duration_label"],
                         r["description"][:300] or "–"])
        out.append(table(rows, [28 * mm, 24 * mm, 24 * mm, 30 * mm, 24 * mm, CONTENT_W - 130 * mm]))
        out.append(P(e("Zeitpunkt = vom Benutzer angegebener Beginn der Störung."), "muted"))
    return out


def _link(text: str, url: str | None) -> str:
    if not url:
        return e(text)
    return f'<link href="{escape(clean(url), {chr(34): "&quot;"})}" color="#0060e0">{e(text)}</link>'


def section_netscan(data: dict) -> list:
    out = [heading("Netzwerk (Scan)", "netzwerk")]
    ns = data["netscan"]
    if not ns or not ns.get("runs"):
        return out + [empty("Kein Netzwerkscan im Zeitraum.")]
    devices = ns.get("devices") or []
    flags = lambda f: [d for d in devices if f in (d.get("flags") or [])]  # noqa: E731
    out.append(P(e(f"{len(devices)} Geräte · {ns['runs']} Scans · letzter Scan "
                   f"{fmt_ts(ns.get('last_scan'), False)}. Unregelmäßige Geräte (kommen und gehen) und doppelte "
                   "IP-Adressen können kurze Störungen im lokalen Netz verursachen."), "muted"))
    irregular = flags("irregular")
    out.append(heading("Unregelmäßige Geräte", "ns_irr", 1))
    if irregular:
        rows = [["Gerät", "IP", "MAC / Hersteller", "Wiederkehr", "zuletzt gesehen"]]
        for d in sorted(irregular, key=lambda d: -(d.get("returns") or 0))[:80]:
            rows.append([d.get("label") or d.get("hostname") or "–", d.get("ip") or "–",
                         " / ".join(x for x in (d.get("mac"), d.get("vendor")) if x) or "–",
                         str(d.get("returns") or 0), fmt_ts(d.get("last_seen"), False)])
        out.append(table(rows, [44 * mm, 28 * mm, 52 * mm, 20 * mm, CONTENT_W - 144 * mm]))
    else:
        out.append(empty("Keine."))
    events = ns.get("events") or []
    conflicts = [ev for ev in events if ev.get("kind") == "ip_conflict"]
    out.append(heading("IP-Konflikte", "ns_conf", 1))
    if conflicts:
        rows = [["Zeitpunkt", "IP", "Gerät", "Details"]]
        for ev in conflicts[:80]:
            rows.append([fmt_ts(ev.get("ts")), ev.get("ip") or "–", ev.get("device_label") or "–",
                         ev.get("detail") or ""])
        out.append(table(rows, [28 * mm, 26 * mm, 44 * mm, CONTENT_W - 98 * mm]))
    else:
        out.append(empty("Keine doppelten IP-Adressen erkannt."))
    new = flags("new")
    out.append(heading("Neue Geräte im Zeitraum", "ns_new", 1))
    if new:
        rows = [["Gerät", "IP", "MAC / Hersteller", "zuerst gesehen"]]
        for d in sorted(new, key=lambda d: d.get("first_seen") or 0)[:80]:
            rows.append([d.get("label") or "–", d.get("ip") or "–",
                         " / ".join(x for x in (d.get("mac"), d.get("vendor")) if x) or "–",
                         fmt_ts(d.get("first_seen"), False)])
        out.append(table(rows, [50 * mm, 28 * mm, 60 * mm, CONTENT_W - 138 * mm]))
    else:
        out.append(empty("Keine."))
    out.append(heading("Geräte und Dienste", "ns_inv", 1))
    if devices:
        rows = [["IP", "Name", "MAC / Hersteller", "Dienste", "Status"]]
        for d in sorted(devices, key=lambda d: _ip_key(d.get("ip")))[:400]:
            services = ", ".join(_link(f"{s.get('label') or s.get('service')} {s.get('port')}", s.get("url"))
                                 for s in (d.get("services") or [])[:12])
            rows.append([d.get("ip") or "–", d.get("label") or d.get("hostname") or "–",
                         " / ".join(x for x in (d.get("mac"), d.get("vendor")) if x) or "–",
                         P(services or "–", "cell"), "online" if d.get("online") else "offline"])
        out.append(table(rows, [26 * mm, 38 * mm, 46 * mm, CONTENT_W - 126 * mm, 16 * mm]))
        if len(devices) > 400:
            out.append(P(e(f"Nur 400 von {len(devices)} Geräten."), "muted"))
    return out


def _ip_key(ip):
    try:
        return tuple(int(x) for x in str(ip).split("."))
    except ValueError:
        return (999,)


def section_method(data: dict) -> list:
    m = data["method"]
    lines = [
        ("Messung", "Windows-Dienst (Wachtl-Probe) auf PCs am Standort. Ping (ICMP) im Sekundentakt zum eigenen "
                    "Gateway (Router) und zu mehreren Internet-Referenzen, z. B. öffentlichen DNS-Servern. Jede "
                    "Antwort wird mit Laufzeit gespeichert; Jitter = mittlere Schwankung der Laufzeit."),
        ("Ausfall", f"Ein Ziel gilt als ausgefallen, wenn es mindestens {m['target_down_s']:g} s nicht antwortet. "
                    f"Internet (WAN) gilt als gestört, wenn alle Referenzen zugleich mindestens {m['wan_down_s']:g} s "
                    f"nicht antworten, das Gateway aber schon. Beginn und Ende werden aus den 1-s-Messwerten "
                    "sekundengenau nachgerechnet."),
        ("Probe offline", f"Ein PC meldet sich länger als {m['probe_offline_s']:g} s nicht beim Wachtl-Server. "
                          "Das kann auch ein ausgeschalteter PC sein. Fallen alle PCs eines Standorts zugleich aus, "
                          "hat der Standort keine Verbindung (Leitung oder Strom)."),
        ("Folgestörung", "Fällt eine übergeordnete Ebene aus, sind die darunter liegenden zwangsläufig mit gestört "
                         "(Reihenfolge: Probe/Standort, Gateway/LAN, Internet, einzelnes Ziel). Sie werden als "
                         "Folge gekennzeichnet und nicht doppelt gezählt."),
        ("Verfügbarkeit", "Anteil der Zeit, in der der Standort ins Internet kam. Nicht verfügbar = alle aktiven PCs "
                          "zugleich mit Gateway-, Internet- oder Offline-Störung."),
        ("Paketverlust", f"Anteil unbeantworteter Pings. Alarm ab {m['loss_warn']:g} % (Warnung) bzw. "
                         f"{m['loss_crit']:g} % (kritisch) über 5 min. Minuten mit Paketverlust zählen jede Minute, "
                         "in der mindestens ein Ping verloren ging – auch Aussetzer unter der Ausfallschwelle."),
        ("Auffällig", "Ein Abschnitt ist auffällig bei Verlust über 1 %, Jitter über 30 ms oder Latenz über dem "
                      "Doppelten des üblichen Werts (Median im Zeitraum, mindestens +15 ms). Ist das Gateway zur "
                      "gleichen Zeit sauber, liegt die Ursache hinter dem Router (Provider)."),
        ("Einschätzung", "Regelbasiert aus allen Störungen, Schwankungen, Pfaden und PC-Hinweisen: Für jede Ebene "
                         "werden Belege gezählt und nach Dauer gewichtet. Die Sicherheit ist hoch, wenn eine Ebene "
                         "deutlich überwiegt."),
        ("Datenquellen", "Rohdaten (1 s) 30 Tage, Minutenwerte 13 Monate (VictoriaMetrics); Alarme, Pfade, "
                         f"Bandbreite, Meldungen in der Wachtl-Datenbank. Graphen: ein Wert je {fmt_dur(m['step'])}. "
                         "Zeiten in Ortszeit des Servers."),
    ]
    rows = [[P(f"<b>{e(a)}</b>", "cell"), P(e(b), "cell")] for a, b in lines]
    return [heading("Anhang: Messmethode", "anhang"),
            table(rows, [28 * mm, CONTENT_W - 28 * mm], head=False, zebra=False)]


RENDERERS = {
    "zeitstrahl": section_timeline, "qualitaet": section_quality, "stoerungen": section_incidents,
    "pfad": section_paths, "bandbreite": section_bandwidth, "kunde": section_customer, "netzwerk": section_netscan,
    "anhang": section_method,
}


def render(data: dict, invariant: bool = False) -> bytes:
    meta = data["meta"]
    footer = f"Wachtl · {meta['site_label']} · {period_text(meta)}"
    buf = io.BytesIO()
    doc = _Doc(buf, pagesize=A4, leftMargin=MARGIN_X, rightMargin=MARGIN_X, topMargin=16 * mm,
               bottomMargin=18 * mm, title=clean(f"Netzwerk-Störungsbericht {meta['site_label']}"),
               author=clean(meta["author"] or "Wachtl"), subject=clean(period_text(meta)), creator="Wachtl",
               invariant=1 if invariant else 0)
    story = cover(data)
    first = True
    for key in SECTIONS:
        if key not in data["sections"]:
            continue
        if key in ("zeitstrahl", "stoerungen", "anhang", "netzwerk", "qualitaet") or first:
            story.append(PageBreak())
        else:
            story += [Spacer(1, 10), CondPageBreak(60 * mm)]
        first = False
        story += RENDERERS[key](data)
    doc.build(story, canvasmaker=_canvas_class(footer, fmt_ts(meta["generated_at"], False)))
    return buf.getvalue()
