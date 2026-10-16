"""Admin-API (JSON) für Dashboard-Graphen und Automatisierung. Session-basiert."""
from __future__ import annotations

import json

from flask import Blueprint, jsonify, request

from . import repo
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


@bp.get("/sites")
@login_required(api=True)
def sites():
    return jsonify(q("SELECT id, name, customer_no, description FROM sites ORDER BY name"))


@bp.get("/probes")
@login_required(api=True)
def probes():
    rows = q(
        "SELECT p.id, p.hostname, p.site_id, s.name AS site_name, p.status, p.version, p.last_seen, "
        "p.buffer_items FROM probes p JOIN sites s ON s.id = p.site_id ORDER BY s.name, p.hostname"
    )
    for r in rows:
        r["online"] = repo.probe_online(r)
    return jsonify(rows)


@bp.get("/checks")
@login_required(api=True)
def checks():
    return jsonify(q("SELECT id, name, type, target, role, interval_s, timeout_ms, enabled FROM checks ORDER BY id"))


@bp.get("/probes/<int:probe_id>/checks/<int:check_id>/series")
@login_required(api=True)
def series(probe_id: int, check_id: int):
    if _probe_or_404(probe_id) is None:
        return jsonify(error="Probe nicht gefunden"), 404
    range_key = request.args.get("range", "1h")
    if range_key not in vm.RANGES:
        return jsonify(error=f"range muss einer von {list(vm.RANGES)} sein"), 400
    try:
        return jsonify(vm.ping_series(probe_id, check_id, range_key))
    except vm.VMError as exc:
        return jsonify(error=str(exc)), 502


@bp.get("/probes/<int:probe_id>/checks/<int:check_id>/stats")
@login_required(api=True)
def stats(probe_id: int, check_id: int):
    if _probe_or_404(probe_id) is None:
        return jsonify(error="Probe nicht gefunden"), 404
    try:
        return jsonify(vm.ping_stats(probe_id, check_id))
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
