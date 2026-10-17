"""Admin-API (JSON) für Dashboard-Graphen und Automatisierung. Session-basiert."""
from __future__ import annotations

import json

from flask import Blueprint, jsonify, request

from . import repo
from . import reports as report_service
from .db import q, q1
from .security import check_csrf, current_user, login_required
from .services import alerts as alert_service
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
    since = int(request.args.get("since", repo.now() - 30 * 86400) or 0)
    return jsonify(q("SELECT * FROM bandwidth_runs WHERE probe_id = ? AND ts >= ? ORDER BY ts DESC LIMIT 5000",
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
    if check is None or check["type"] not in ("iperf", "speedtest", "path"):
        return jsonify(error="Check gehört nicht zur Probe oder ist kein Bandbreiten-/Pfad-Check"), 404
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
        return jsonify(vm.ping_series(probe_id, check_id, range_key, hop, at))
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
    hours = min(max(int(data.get("hours", 4)), 1), 168)
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
