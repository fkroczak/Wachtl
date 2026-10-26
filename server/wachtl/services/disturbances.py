"""Störungen direkt aus den 1-s-Rohdaten erkennen, sobald sie beim Server ankommen.

Die Alarmregeln von vmalert sehen nur Werte, die rechtzeitig da sind. Verliert ein PC selbst das Netz (Kabel,
Switch, WLAN), puffert die Probe ihre Messwerte und lädt sie erst danach hoch – für vmalert ist das zu spät, der
Ausfall fiel bisher unter den Tisch. Hier wird jeder eingehende Ping ausgewertet, egal wie spät er kommt:

=====  ================================================================================
down   Ziel antwortet mindestens ``target_down`` Sekunden nicht (Gateway, Referenz, Ziel)
wan    alle Internet-Referenzen einer Probe zugleich ohne Antwort (``wan_down``)
loss   einzelne Pings verloren, zu kurz für einen Ausfall – jeder verlorene Ping zählt;
       die Störung endet nach ``packet_loss_any.window_s`` Sekunden ohne Verlust
=====  ================================================================================

Jede Störung geht als Alarm an Alertmanager (E-Mail, Teams, Alarm-Historie) – auch nachträglich erkannte.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone

import json

import requests
from flask import current_app, g

from .. import repo
from ..db import ex, ins, q, q1

log = logging.getLogger(__name__)

KINDS = ("down", "wan", "loss")
GAP_S = 300            # so lange ohne Werte: offene Störungen enden mit dem letzten bekannten Ping
STALE_S = 600          # offene Störung ohne neue Werte wird beim nächsten Durchlauf geschlossen
LATE_S = 30            # erst so spät angekommen: „nachträglich erkannt“
REPOST_S = 60          # laufende Störung an Alertmanager erneut melden (sonst gilt sie dort als beendet)
ALERT_TTL_S = 300      # Gültigkeit einer gemeldeten laufenden Störung bei Alertmanager
LATE_FIRING_S = 120    # nachträglich erkannte, schon beendete Störung so lange als aktiv melden, damit sie zugestellt wird
NOTIFY_MAX_AGE_S = 86400  # ältere Nachlieferungen werden gezeigt, aber nicht mehr per E-Mail/Teams gemeldet

ALERTNAMES = {"down": "WachtlTargetDown", "wan": "WachtlWanDown", "loss": "WachtlPacketLossAny"}
RULE_OF = {"down": "target_down", "wan": "wan_down", "loss": "packet_loss_any"}


def _settings() -> dict:
    rules = repo.alert_rules()

    def rule(kind: str) -> dict:
        return rules.get(kind) or {}

    loss = rule("packet_loss_any")
    return {
        "down_s": float(rule("target_down").get("threshold") or 5),
        "wan_s": float(rule("wan_down").get("threshold") or 5),
        "quiet_s": int(loss.get("window_s") or 60),
        "rules": rules,
    }


def fails_needed(threshold_s: float, interval_s: int) -> int:
    """Pings ohne Antwort in Folge für „mindestens threshold_s Sekunden“ (wie die Alarmregeln, mindestens 2)."""
    interval_s = max(int(interval_s or 1), 1)
    return max(2, math.ceil(max(threshold_s, 1) / interval_s))


# -- Auswertung je Ping ---------------------------------------------------------------------------------------
def _load_track(probe_id: int, check_id: int) -> dict:
    row = q1("SELECT * FROM ping_tracks WHERE probe_id = ? AND check_id = ?", (probe_id, check_id))
    if row:
        row["_new"] = False
        return row
    return {"probe_id": probe_id, "check_id": check_id, "last_ts": 0, "fail_start": None, "fail_last": None,
            "fail_n": 0, "down_id": None, "loss_id": None, "loss_last": None, "loss_lost": 0, "loss_sent": 0,
            "loss_sent_at": 0, "_new": True}


TRACK_FIELDS = ("last_ts", "fail_start", "fail_last", "fail_n", "down_id", "loss_id", "loss_last", "loss_lost",
                "loss_sent", "loss_sent_at")


def _save_track(t: dict) -> None:
    values = tuple(t[k] for k in TRACK_FIELDS)
    if t.pop("_new", False):
        ex(f"INSERT INTO ping_tracks (probe_id, check_id, {', '.join(TRACK_FIELDS)}) "
           f"VALUES (?, ?, {', '.join('?' for _ in TRACK_FIELDS)})", (t["probe_id"], t["check_id"], *values))
    else:
        ex(f"UPDATE ping_tracks SET {', '.join(k + ' = ?' for k in TRACK_FIELDS)} WHERE probe_id = ? AND check_id = ?",
           (*values, t["probe_id"], t["check_id"]))


def _touch(dist_id: int) -> None:
    """Störung für den Abgleich mit der Alarm-Historie vormerken (siehe sync_events)."""
    g.setdefault("disturbances_touched", set()).add(int(dist_id))


def _open(kind: str, probe: dict, check: dict | None, start: int, now_s: int, late: bool) -> int:
    dist_id = ins(
        "INSERT INTO disturbances (probe_id, site_id, check_id, kind, role, target, check_name, start_ts, end_ts, "
        "lost, sent, detected_at, late, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?)",
        (probe["id"], probe.get("site_id"), check["id"] if check else None, kind,
         check["role"] if check else "reference", check["target"] if check else "", check["name"] if check else "",
         int(start), now_s, bool(late), now_s),
    )
    _touch(dist_id)
    return dist_id


def _close(dist_id: int, end: int, now_s: int, lost: int | None = None, sent: int | None = None) -> None:
    row = q1("SELECT start_ts FROM disturbances WHERE id = ?", (dist_id,))
    if row is None:
        return
    ex("UPDATE disturbances SET end_ts = ?, lost = COALESCE(?, lost), sent = COALESCE(?, sent), updated_at = ? "
       "WHERE id = ?", (max(int(end), int(row["start_ts"])), lost, sent, now_s, dist_id))
    _touch(dist_id)


def _end_streak_as_loss(t: dict, probe: dict, check: dict, now_s: int, late: bool) -> None:
    """Kurze Serie ohne Antwort (kein Ausfall) als Paketverlust zählen."""
    if t["loss_id"] is None:
        t["loss_id"] = _open("loss", probe, check, t["fail_start"] // 1000, now_s, late)
        t["loss_lost"], t["loss_sent"] = 0, t["fail_n"]
    t["loss_lost"] += t["fail_n"]
    t["loss_last"] = t["fail_last"]
    t["loss_sent_at"] = t["loss_sent"]
    ex("UPDATE disturbances SET lost = ?, sent = ?, updated_at = ? WHERE id = ?",
       (t["loss_lost"], t["loss_sent_at"], now_s, t["loss_id"]))
    _touch(t["loss_id"])


def _close_loss(t: dict, interval_ms: int, now_s: int) -> None:
    _close(t["loss_id"], (t["loss_last"] + interval_ms) // 1000, now_s, t["loss_lost"], t["loss_sent_at"])
    t["loss_id"], t["loss_last"], t["loss_lost"], t["loss_sent"], t["loss_sent_at"] = None, None, 0, 0, 0


def _close_gap(t: dict, probe: dict, check: dict, interval_ms: int, now_s: int) -> None:
    """Keine Werte mehr (Probe aus, Check entfernt): offene Störungen mit dem letzten bekannten Ping beenden."""
    if t["down_id"] is not None:
        _close(t["down_id"], (t["last_ts"] + interval_ms) // 1000, now_s)
        t["down_id"] = None
    elif t["fail_start"] is not None and check is not None:
        _end_streak_as_loss(t, probe, check, now_s, False)
    t["fail_start"], t["fail_last"], t["fail_n"] = None, None, 0
    if t["loss_id"] is not None:
        _close_loss(t, interval_ms, now_s)


def track(probe: dict, samples: dict[str, list[tuple[int, float]]], checks: dict[str, dict],
          now_s: int | None = None) -> bool:
    """Neue Ping-Werte einer Probe auswerten (``samples``: check_id → [(ts_ms, up)]). True, wenn sich etwas änderte."""
    now_s = now_s or repo.now()
    cfg = _settings()
    changed = False
    batch_start = None
    for check_id, items in samples.items():
        check = checks.get(str(check_id))
        if not check or check.get("type", "ping") != "ping" or not items:
            continue
        interval_ms = max(int(check.get("interval_s") or 1), 1) * 1000
        need = fails_needed(cfg["down_s"], int(check.get("interval_s") or 1))
        quiet_ms = cfg["quiet_s"] * 1000
        t = _load_track(probe["id"], int(check["id"]))
        before = (t["down_id"], t["loss_id"], t["loss_lost"])
        for ts, value in sorted(items):
            if ts <= t["last_ts"]:
                continue  # schon ausgewertet (Wiederholung) oder älter als der Stand
            late = now_s - ts / 1000 > LATE_S
            batch_start = ts if batch_start is None else min(batch_start, ts)
            if t["last_ts"] and ts - t["last_ts"] > GAP_S * 1000:
                _close_gap(t, probe, check, interval_ms, now_s)
            if value <= 0:
                if t["fail_start"] is None:
                    t["fail_start"], t["fail_n"] = ts, 0
                t["fail_n"] += 1
                t["fail_last"] = ts
                if t["loss_id"] is not None:
                    t["loss_sent"] += 1
                if t["down_id"] is None and t["fail_n"] >= need:
                    t["down_id"] = _open("down", probe, check, t["fail_start"] // 1000, now_s, late)
            else:
                if t["fail_start"] is not None:
                    if t["down_id"] is not None:
                        _close(t["down_id"], ts // 1000, now_s)
                        t["down_id"] = None
                        if t["loss_id"] is not None:   # Pings des Ausfalls nicht als Verlust zählen
                            t["loss_sent"] = max(t["loss_sent"] - t["fail_n"], 0)
                    else:
                        _end_streak_as_loss(t, probe, check, now_s, late)
                    t["fail_start"], t["fail_last"], t["fail_n"] = None, None, 0
                if t["loss_id"] is not None:
                    t["loss_sent"] += 1
                    if ts - t["loss_last"] > quiet_ms:
                        _close_loss(t, interval_ms, now_s)
            t["last_ts"] = ts
        _save_track(t)
        changed = changed or before != (t["down_id"], t["loss_id"], t["loss_lost"])
    if batch_start is not None:
        changed = derive_wan(probe, checks, batch_start // 1000, now_s, cfg["wan_s"]) or changed
    return changed


# -- WAN: alle Internet-Referenzen zugleich ---------------------------------------------------------------
def _intersect(a: list[tuple[int, float]], b: list[tuple[int, float]]) -> list[tuple[int, float]]:
    out = []
    for s1, e1 in a:
        for s2, e2 in b:
            s, e = max(s1, s2), min(e1, e2)
            if s < e:
                out.append((s, e))
    return sorted(out)


def derive_wan(probe: dict, checks: dict[str, dict], since: int, now_s: int, threshold_s: float) -> bool:
    """WAN-Störungen aus den Ausfällen der Internet-Referenzen ab ``since`` ableiten bzw. anpassen."""
    refs = sorted(int(c["id"]) for c in checks.values() if c.get("type", "ping") == "ping" and c["role"] == "reference")
    if not refs:
        return False
    lo = since - GAP_S
    downs = q("SELECT check_id, start_ts, end_ts FROM disturbances WHERE probe_id = ? AND kind = 'down' "
              "AND role = 'reference' AND (end_ts IS NULL OR end_ts >= ?)", (probe["id"], lo))
    by_check: dict[int, list[tuple[int, float]]] = {}
    for d in downs:
        by_check.setdefault(int(d["check_id"]), []).append(
            (int(d["start_ts"]), math.inf if d["end_ts"] is None else int(d["end_ts"])))
    spans: list[tuple[int, float]] | None = None
    if all(cid in by_check for cid in refs):
        for cid in refs:
            spans = by_check[cid] if spans is None else _intersect(spans, by_check[cid])
    spans = [(s, e) for s, e in spans or [] if (min(e, now_s) - s) >= max(threshold_s - 1, 1)]
    existing = q("SELECT id, start_ts, end_ts FROM disturbances WHERE probe_id = ? AND kind = 'wan' "
                 "AND (end_ts IS NULL OR end_ts >= ?) ORDER BY start_ts", (probe["id"], lo))
    used: set[int] = set()
    changed = False
    for s, e in spans:
        end = None if e == math.inf else int(e)
        match = next((w for w in existing if w["id"] not in used and w["start_ts"] - 5 <= (end or now_s)
                      and s <= (w["end_ts"] if w["end_ts"] is not None else now_s) + 5), None)
        if match:
            used.add(match["id"])
            if (match["start_ts"], match["end_ts"]) != (s, end):
                ex("UPDATE disturbances SET start_ts = ?, end_ts = ?, updated_at = ? WHERE id = ?",
                   (s, end, now_s, match["id"]))
                _touch(match["id"])
                changed = True
        else:
            wid = _open("wan", probe, None, s, now_s, now_s - s > LATE_S + threshold_s)
            if end is not None:
                _close(wid, end, now_s)
            changed = True
    for w in existing:   # offen, aber nicht mehr alle Referenzen gestört
        if w["id"] not in used and w["end_ts"] is None:
            last = max((int(d["end_ts"]) for d in downs if d["end_ts"] is not None), default=now_s)
            _close(w["id"], last, now_s)
            changed = True
    return changed


def close_stale(now_s: int | None = None) -> int:
    """Offene Störungen von Checks, für die seit STALE_S nichts mehr kam (Probe aus, Check gelöscht), beenden."""
    now_s = now_s or repo.now()
    rows = q("SELECT * FROM ping_tracks WHERE (down_id IS NOT NULL OR loss_id IS NOT NULL OR fail_start IS NOT NULL) "
             "AND last_ts < ?", ((now_s - STALE_S) * 1000,))
    for t in rows:
        t["_new"] = False
        check = q1("SELECT id, name, target, role, interval_s FROM checks WHERE id = ?", (t["check_id"],))
        probe = q1("SELECT id, site_id FROM probes WHERE id = ?", (t["probe_id"],)) or {"id": t["probe_id"]}
        interval_ms = max(int((check or {}).get("interval_s") or 1), 1) * 1000
        _close_gap(t, probe, check, interval_ms, now_s)
        _save_track(t)
    if rows:
        for w in q("SELECT d.id, d.probe_id FROM disturbances d WHERE d.kind = 'wan' AND d.end_ts IS NULL"):
            if not q1("SELECT id FROM disturbances WHERE probe_id = ? AND kind = 'down' AND role = 'reference' "
                      "AND end_ts IS NULL", (w["probe_id"],)):
                last = q1("SELECT MAX(end_ts) AS e FROM disturbances WHERE probe_id = ? AND kind = 'down' "
                          "AND role = 'reference'", (w["probe_id"],))
                _close(w["id"], (last or {}).get("e") or now_s, now_s)
    return len(rows)


# -- Texte ----------------------------------------------------------------------------------------------
def loss_pct(d: dict) -> float | None:
    return 100.0 * d["lost"] / d["sent"] if d.get("lost") and d.get("sent") else None


def _clock(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%d.%m. %H:%M:%S")


def _span(d: dict) -> str:
    if d["end_ts"] is None:
        return f"seit {_clock(d['start_ts'])}"
    secs = max(int(d["end_ts"]) - int(d["start_ts"]), 1)
    dur = f"{secs} s" if secs < 120 else f"{secs // 60} min {secs % 60:02d} s"
    return f"{_clock(d['start_ts'])} bis {datetime.fromtimestamp(d['end_ts']).strftime('%H:%M:%S')} ({dur})"


def describe(d: dict) -> str:
    """Ein Satz für Hinweis, E-Mail und Teams."""
    where = f"{d.get('probe_name') or '?'} ({d.get('site_name') or '?'})"
    target = d.get("check_name") or d.get("target") or "?"
    if d.get("target") and d.get("check_name") and d["target"] not in d["check_name"]:
        target = f"{d['check_name']} ({d['target']})"
    late = ", nachträglich erkannt (Werte kamen später an)" if d.get("late") else ""
    if d["kind"] == "wan":
        return f"Internet gestört: alle Referenzen ohne Antwort von {where}, {_span(d)}{late}"
    if d["kind"] == "down":
        what = "Gateway antwortet nicht" if d.get("role") == "gateway" else f"{target} nicht erreichbar"
        return f"Ausfall: {what} von {where}, {_span(d)}{late}"
    lost, sent = d.get("lost") or 0, d.get("sent") or 0
    count = f"{lost} {'Ping' if lost == 1 else 'Pings'} ohne Antwort"
    if sent > lost:
        count = f"{lost} von {sent} Pings ohne Antwort ({loss_pct(d):.3g} %)"
    return f"Paketverlust zu {target} von {where}: {count}, {_span(d)}{late}"


# -- Benachrichtigung über Alertmanager -------------------------------------------------------------------
def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def _labels(d: dict, rule: dict) -> dict:
    labels = {
        "alertname": ALERTNAMES[d["kind"]], "severity": rule.get("severity") or "warning", "kind": RULE_OF[d["kind"]],
        "probe": str(d["probe_id"]), "probe_name": d.get("probe_name") or "", "site": str(d.get("site_id") or ""),
        "site_name": d.get("site_name") or "", "source": "wachtl", "disturbance": str(d["id"]),
    }
    if d["kind"] == "wan":
        labels["cause"] = "wan"
    else:
        labels.update(check_id=str(d["check_id"] or ""), target=d.get("target") or "", role=d.get("role") or "")
    return labels


def post_pending(now_s: int | None = None, limit: int = 100) -> int:
    """Neue, laufende und beendete Störungen an Alertmanager melden. Gibt die Zahl der gemeldeten zurück."""
    now_s = now_s or repo.now()
    rows = q(
        "SELECT d.*, p.hostname AS probe_name, s.name AS site_name FROM disturbances d "
        "LEFT JOIN probes p ON p.id = d.probe_id LEFT JOIN sites s ON s.id = d.site_id "
        "WHERE d.posted_state IS NULL OR (d.posted_state = 'firing' AND (d.end_ts IS NOT NULL OR d.posted_at < ?)) "
        "ORDER BY d.id LIMIT ?", (now_s - REPOST_S, limit))
    if not rows:
        return 0
    url = current_app.config.get("ALERTMANAGER_URL")
    rules = repo.alert_rules()
    alerts, done = [], []
    for d in rows:
        rule = rules.get(RULE_OF[d["kind"]]) or {}
        closed = d["end_ts"] is not None
        if d["posted_state"] is None:
            too_old = (d["end_ts"] or now_s) < now_s - NOTIFY_MAX_AGE_S
            if not rule.get("enabled") or too_old or not url:
                done.append((d["id"], "skipped"))
                continue
            if d["kind"] == "loss" and (d.get("lost") or 0) < max(rule.get("threshold") or 1, 1):
                if closed:
                    done.append((d["id"], "skipped"))
                continue  # Verlust noch unter der Meldeschwelle
        if not closed:
            ends, state = now_s + ALERT_TTL_S, "firing"
        elif d["posted_state"] is None:
            ends, state = now_s + LATE_FIRING_S, "resolved"  # erst aktiv, damit E-Mail/Teams sie zustellen
        else:
            ends, state = max(int(d["end_ts"]), now_s - 1), "resolved"
        alerts.append({"labels": _labels(d, rule), "annotations": {"summary": describe(d)},
                       "startsAt": _iso(d["start_ts"]), "endsAt": _iso(ends)})
        done.append((d["id"], state))
    if alerts:
        try:
            requests.post(url + "/api/v2/alerts", json=alerts, timeout=5).raise_for_status()
        except requests.RequestException as exc:
            log.warning("Störungen nicht an Alertmanager gemeldet (nächster Versuch beim nächsten Eingang): %s", exc)
            done = [(i, s) for i, s in done if s == "skipped"]
    for dist_id, state in done:
        ex("UPDATE disturbances SET posted_state = ?, posted_at = ? WHERE id = ?", (state, now_s, dist_id))
    return len(alerts)


# -- Alarm-Historie ------------------------------------------------------------------------------------------
def sync_events(ids: set[int] | None = None) -> int:
    """Störungen als Zeile in ``alert_events`` spiegeln (Fingerprint ``disturbance:<id>``).

    So zählen sie überall mit, wo Ausfälle ausgewertet werden: Ausfallübersicht, Standort-Verlauf, PDF-Bericht,
    aktive Alarme, Bestätigen. Beginn und Ende sind sekundengenau (exact_*), ein Nachrechnen entfällt.
    """
    if ids is None:
        ids = g.pop("disturbances_touched", set())
    if not ids:
        return 0
    rules = repo.alert_rules()
    now_s = repo.now()
    marks = ", ".join("?" for _ in ids)
    rows = q("SELECT d.*, p.hostname AS probe_name, s.name AS site_name FROM disturbances d "
             "LEFT JOIN probes p ON p.id = d.probe_id LEFT JOIN sites s ON s.id = d.site_id "
             f"WHERE d.id IN ({marks})", tuple(sorted(ids)))
    for d in rows:
        if d["kind"] == "loss" and not d.get("lost"):
            continue
        labels = _labels(d, rules.get(RULE_OF[d["kind"]]) or {})
        status = "firing" if d["end_ts"] is None else "resolved"
        fp = f"disturbance:{d['id']}"
        existing = q1("SELECT id FROM alert_events WHERE fingerprint = ?", (fp,))
        values = (labels["alertname"], labels["severity"], status, json.dumps(labels, sort_keys=True), describe(d),
                  d["start_ts"], d["end_ts"], d["start_ts"], d["end_ts"], now_s, now_s)
        if existing:
            ex("UPDATE alert_events SET alertname = ?, severity = ?, status = ?, labels = ?, summary = ?, starts_at = ?, "
               "ends_at = ?, exact_start = ?, exact_end = ?, refined_at = ?, updated_at = ? WHERE id = ?",
               (*values, existing["id"]))
        else:
            ins("INSERT INTO alert_events (alertname, severity, status, labels, summary, starts_at, ends_at, "
                "exact_start, exact_end, refined_at, updated_at, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*values, fp))
    return len(rows)


def after_ingest(probe: dict, samples: dict[str, list[tuple[int, float]]], checks: dict[str, dict]) -> None:
    """Vom Ingest aufgerufen; Fehler hier dürfen das Speichern der Messwerte nie verhindern."""
    try:
        track(probe, samples, checks)
        close_stale()
        sync_events()
        post_pending()
    except Exception:   # noqa: BLE001 – Auswertung ist Zusatz, Messwerte sind schon gespeichert
        log.exception("Störungserkennung für Probe %s fehlgeschlagen", probe.get("id"))


def housekeeping(now_s: int | None = None) -> None:
    """Beim Heartbeat: verwaiste Störungen schließen und laufende bei Alertmanager aktuell halten."""
    try:
        close_stale(now_s)
        sync_events()
        post_pending(now_s)
    except Exception:  # noqa: BLE001 – der Heartbeat selbst darf daran nie scheitern
        log.exception("Störungen nicht aktualisiert")
