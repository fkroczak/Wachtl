"""Zeitplan der Bandbreitenmessungen – dieselbe Regel wie in der Windows-Probe (Bandwidth/Schedule.cs).

Alle ``schedule_min`` Minuten ab Mitternacht plus Versatz, nur im Zeitfenster und an den gewählten
Wochentagen (Ortszeit). Intervalle über einen Tag zählen ab Montag 00:00. Der Server nutzt die Regel,
um überfällige Messungen zu erkennen, die Server-Probe, um selbst zu messen.
"""
from __future__ import annotations

from datetime import datetime, timedelta


def parse_time_of_day(value: str | None) -> int | None:
    try:
        h, m = str(value or "").split(":")
        h, m = int(h), int(m)
    except ValueError:
        return None
    return h * 60 + m if 0 <= h <= 23 and 0 <= m <= 59 else None


def allowed(t: datetime, start_min: int, end_min: int, weekdays: str) -> bool:
    if str(t.isoweekday()) not in weekdays:
        return False
    tod = t.hour * 60 + t.minute
    return start_min <= tod <= end_min if start_min <= end_min else (tod >= start_min or tod <= end_min)


def next_run(after: datetime, schedule_min: int, offset_min: int, window_start: str = "00:00",
             window_end: str = "23:59", weekdays: str = "1234567") -> datetime | None:
    """Nächster Messzeitpunkt nach ``after`` (naive Ortszeit) oder None (nur manuell)."""
    if schedule_min <= 0:
        return None
    start = parse_time_of_day(window_start)
    end = parse_time_of_day(window_end)
    start = 0 if start is None else start
    end = 1439 if end is None else end
    days = weekdays.strip() if weekdays and weekdays.strip() else "1234567"
    weekly = schedule_min > 1440
    period_minutes = 10080 if weekly else 1440
    period = timedelta(days=7 if weekly else 1)
    first = after.replace(hour=0, minute=0, second=0, microsecond=0)
    if weekly:
        first -= timedelta(days=first.weekday())
    offset = offset_min % schedule_min
    for p in range(15):
        period_start = first + period * p
        for m in range(offset, period_minutes, schedule_min):
            t = period_start + timedelta(minutes=m)
            if t > after and allowed(t, start, end, days):
                return t
    return None


def overdue_since(params: dict, last_ts: int | None, created_ts: int, now_ts: int, grace_s: int = 900) -> int | None:
    """Seit wann eine geplante Messung fehlt (Unix-Sekunden) oder None, wenn alles im Plan ist.

    Erwartet wird die erste planmäßige Messung nach der letzten (bzw. nach dem Anlegen des Checks);
    ist sie plus Testdauer und ``grace_s`` verstrichen, gilt der Check als überfällig.
    """
    schedule_min = int(params.get("schedule_min") or 0)
    if schedule_min <= 0:
        return None
    base = datetime.fromtimestamp(last_ts if last_ts else created_ts)
    expected = next_run(base, schedule_min, int(params.get("offset_min") or 0), params.get("window_start", "00:00"),
                        params.get("window_end", "23:59"), str(params.get("weekdays") or "1234567"))
    if expected is None:
        return None
    runtime = int(params.get("timeout_s") or 60) * 2
    due = int(expected.timestamp()) + runtime + grace_s
    return int(expected.timestamp()) if now_ts > due else None
