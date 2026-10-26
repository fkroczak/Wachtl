"""Admin-API (JSON) für Dashboard-Graphen und Automatisierung. Session-basiert."""
from __future__ import annotations

import json

from flask import Blueprint, jsonify, request, url_for

from . import repo
from . import findings as finding_service
from . import reports as report_service
from .db import q, q1
from .security import check_csrf, current_user, login_required
from .services import alerts as alert_service
from .services import notices
from .services import vm

bp = Blueprint("api_admin", __name__, url_prefix="/api/v1")


@bp.before_request
def _csrf():
    check_csrf()


def _probe_or_404(probe_id: int) -> dict | None:
    return q1("SELECT * FROM probes WHERE id = ?", (probe_id,))


def _hop_arg() -> int | None:
    """Optionaler Hop (Pfad-Checks); ungültige Werte -> ValueError."""
    raw = request.args.get("hop")
    if raw in (None, ""):
        return None
    hop = int(raw)
    if not 1 <= hop <= 64:
        raise ValueError(raw)
    return hop


@bp.get("/sites")
@login_required(api=True)
def sites():
    return jsonify(q("SELECT id, name, customer_no, description FROM sites ORDER BY name"))


@bp.get("/probes")
@login_required(api=True)
def probes():
    rows = q(
        "SELECT p.id, p.hostname, p.site_id, s.name AS site_name, p.status, p.kind, p.deregistered_at, p.version, "
        "p.last_seen, p.buffer_items FROM probes p JOIN sites s ON s.id = p.site_id ORDER BY s.name, p.hostname"
    )
    for r in rows:
        r["online"] = repo.probe_online(r)
    return jsonify(rows)


@bp.get("/checks")
@login_required(api=True)
def checks():
    rows = q("SELECT id, name, type, target, role, interval_s, timeout_ms, params, enabled FROM checks ORDER BY id")
    for r in rows:
        r["params"] = json.loads(r["params"] or "{}")
    return jsonify(rows)


@bp.get("/probes/<int:probe_id>/bandwidth")
@login_required(api=True)
def bandwidth(probe_id: int):
    since = request.args.get("since", repo.now() - 30 * 86400, type=int)
    return jsonify(q("SELECT * FROM bandwidth_runs WHERE probe_id = ? AND ts >= ? ORDER BY ts DESC LIMIT 5000",
                     (probe_id, since)))


@bp.get("/probes/<int:probe_id>/rtp")
@login_required(api=True)
def rtp_runs(probe_id: int):
    since = request.args.get("since", repo.now() - 30 * 86400, type=int)
    return jsonify(q("SELECT * FROM rtp_runs WHERE probe_id = ? AND ts >= ? ORDER BY ts DESC LIMIT 5000",
                     (probe_id, since)))


@bp.get("/probes/<int:probe_id>/paths")
@login_required(api=True)
def paths(probe_id: int):
    rows = q("SELECT * FROM path_runs WHERE probe_id = ? ORDER BY ts DESC LIMIT 500", (probe_id,))
    for r in rows:
        r["hops"] = json.loads(r["hops"])
    return jsonify(rows)


@bp.post("/probes/<int:probe_id>/checks/<int:check_id>/run")
@login_required("operator", api=True)
def run_check(probe_id: int, check_id: int):
    probe = _probe_or_404(probe_id)
    if probe is None:
        return jsonify(error="Probe nicht gefunden"), 404
    check = repo.check_map_for_probe({**probe, "site_id": probe["site_id"]}).get(str(check_id))
    if check is None or check["type"] not in ("iperf", "speedtest", "rtp", "path", "netscan"):
        return jsonify(error="Check gehört nicht zur Probe oder ist kein Bandbreiten-, Sprach- oder Pfad-Check"), 404
    ctype = "retrace" if check["type"] == "path" else "run_check"
    cid = repo.queue_command(probe_id, ctype, check_id, current_user()["username"])
    repo.audit(current_user()["username"], f"probe.{ctype}", f"probe:{probe_id}", check["name"])
    return jsonify(command_id=cid), 202


@bp.get("/probes/<int:probe_id>/checks/<int:check_id>/series")
@login_required(api=True)
def series(probe_id: int, check_id: int):
    if _probe_or_404(probe_id) is None:
        return jsonify(error="Probe nicht gefunden"), 404
    range_key = request.args.get("range", "1h")
    if range_key not in vm.RANGES:
        return jsonify(error=f"range muss einer von {list(vm.RANGES)} sein"), 400
    try:
        hop = _hop_arg()
    except ValueError:
        return jsonify(error="hop muss zwischen 1 und 64 liegen"), 400
    try:
        at = _int_arg("at")
    except ValueError:
        return jsonify(error="at muss eine Unix-Zeit in Sekunden sein"), 400
    try:
        return jsonify({**vm.ping_series(probe_id, check_id, range_key, hop, at), "thr": repo.graph_thresholds()})
    except vm.VMError as exc:
        return jsonify(error=str(exc)), 502


@bp.get("/probes/<int:probe_id>/checks/<int:check_id>/stats")
@login_required(api=True)
def stats(probe_id: int, check_id: int):
    if _probe_or_404(probe_id) is None:
        return jsonify(error="Probe nicht gefunden"), 404
    try:
        hop = _hop_arg()
    except ValueError:
        return jsonify(error="hop muss zwischen 1 und 64 liegen"), 400
    try:
        return jsonify(vm.ping_stats(probe_id, check_id, hop))
    except vm.VMError as exc:
        return jsonify(error=str(exc)), 502


@bp.get("/status")
@login_required(api=True)
def status():
    try:
        live = vm.live_status()
    except vm.VMError as exc:
        return jsonify(error=str(exc)), 502
    return jsonify([{"probe": p, "check_id": c, **v} for (p, c), v in live.items()])


@bp.get("/check-status")
@login_required(api=True)
def check_status():
    """Zustand jeder Messung (Ping, Pfad, iperf3, WAN) je aktiver Probe – wie „Messungen mit Problemen“."""
    from .services import checkstatus

    try:
        live = vm.live_status()
    except vm.VMError:
        live = {}
    probes = q("SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id "
               "WHERE p.status = 'active' ORDER BY s.name, p.hostname")
    states = checkstatus.overview(probes, live)
    return jsonify([
        {"probe_id": p["id"], "hostname": p["hostname"], "online": repo.probe_online(p), "check_id": st.check["id"],
         "name": st.check["name"], "type": st.kind, "state": st.state, "detail": st.detail, "ts": st.ts}
        for p in probes for st in states[p["id"]]
    ])


@bp.get("/client-findings")
@login_required(api=True)
def client_findings():
    """Client-Hinweise der Probes: aktive immer, behobene der letzten ``days`` Tage (Standard 7)."""
    try:
        days = min(max(int(request.args.get("days", 7)), 1), 400)
        probe_id = int(request.args["probe"]) if request.args.get("probe") else None
    except ValueError:
        return jsonify(error="days bzw. probe muss eine Zahl sein"), 400
    items = finding_service.search(probe_id=probe_id, since=repo.now() - days * 86400, limit=500)
    return jsonify([finding_service.api_item(r) for r in items])


def _notice_url(item: dict) -> str:
    """Wohin ein Klick auf den Hinweis führt: Graph zum Zeitpunkt, sonst Probe, sonst die Liste."""
    try:
        probe_id = int(item.get("probe_id") or 0)
        check_id = int(item.get("check_id") or 0)
    except ValueError:
        probe_id = check_id = 0
    if probe_id and check_id and item["source"] == "alert":
        check = q1("SELECT type FROM checks WHERE id = ?", (check_id,))
        if check and check["type"] == "ping":
            return url_for("web.target", probe_id=probe_id, check_id=check_id, at=item["ts"])
    if probe_id and q1("SELECT id FROM probes WHERE id = ?", (probe_id,)):
        return url_for("web.probe", probe_id=probe_id, tab="meldungen" if item["source"] == "finding" else "alarme")
    return url_for("web.outages_view") if item["source"] == "alert" else url_for("web.findings_view")


@bp.get("/notifications")
@login_required(api=True)
def notifications():
    """Live-Benachrichtigungen im Web-UI: Ereignisse nach dem Stand ``a`` (Alarme) und ``f`` (Client-Hinweise).

    Ohne Stand nur der aktuelle Stand – beim ersten Aufruf werden keine alten Ereignisse nachgeholt.
    """
    current = notices.cursor()
    try:
        a = int(request.args["a"])
        f = int(request.args["f"])
    except (KeyError, ValueError):
        return jsonify(cursor=current, items=[], active=notices.active_count())
    # Stand höher als die Datenbank (Server neu eingerichtet): neu anfangen
    if a > current["a"] or f > current["f"]:
        return jsonify(cursor=current, items=[], active=notices.active_count())
    items = notices.since(a, f)
    for item in items:
        item["url"] = _notice_url(item)
    cursor = {"a": max([a] + [i["id"] for i in items if i["source"] == "alert"]),
              "f": max([f] + [i["id"] for i in items if i["source"] == "finding"])}
    return jsonify(cursor=cursor, items=items, active=notices.active_count())


@bp.get("/alerts")
@login_required(api=True)
def alert_list():
    state = request.args.get("status", "firing")
    rows = q(
        "SELECT * FROM alert_events WHERE status = ? ORDER BY starts_at DESC LIMIT 500", (state,)
    )
    for r in rows:
        r["labels"] = json.loads(r["labels"])
    return jsonify(rows)


@bp.post("/alerts/<int:event_id>/ack")
@login_required("operator", api=True)
def ack(event_id: int):
    event = q1("SELECT * FROM alert_events WHERE id = ?", (event_id,))
    if event is None:
        return jsonify(error="Alarm nicht gefunden"), 404
    data = request.get_json(silent=True) or {}
    hours = data.get("hours", 4)
    hours = min(max(hours if isinstance(hours, int) else 4, 1), 168)
    user = current_user()
    try:
        silence = alert_service.acknowledge(event, user["username"], hours, str(data.get("comment", ""))[:500])
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 502
    repo.audit(user["username"], "alert.ack", f"alert:{event_id}", f"{hours} h")
    return jsonify(silence_id=silence)


# -- Störungsmeldungen für die Graph-Markierungen (Pfad laut docs/STOERUNGSMELDUNGEN.md) ------
reports_bp = Blueprint("api_reports", __name__, url_prefix="/api")


def _int_arg(name: str, default: int | None = None) -> int | None:
    raw = request.args.get(name, "")
    if raw == "":
        return default
    return int(raw)


@reports_bp.get("/reports")
@login_required(api=True)
def reports():
    try:
        until = _int_arg("to", repo.now())
        since = _int_arg("from", until - 86400)
        probe_id = _int_arg("probe_id")
        site_id = _int_arg("site_id")
    except ValueError:
        return jsonify(error="from, to, probe_id und site_id müssen ganze Zahlen sein"), 400
    if since > until:
        return jsonify(error="from muss vor to liegen"), 400
    return jsonify(reports=report_service.for_chart(since, until, probe_id, site_id))
