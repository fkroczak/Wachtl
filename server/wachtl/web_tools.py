"""Web-UI der Werkzeuge (docs/WERKZEUGE.md): Einzeltest starten, Fortschritt und Ergebnis abfragen."""
from __future__ import annotations

from flask import abort, jsonify, render_template, request

from . import repo
from .db import q, q1
from .security import current_user, login_required
from .services import tools as tool_service
from .web import bp


def _probes() -> list[dict]:
    """Probes, von denen ein Test laufen kann: Server-Probe zuerst, dann nach Standort und Name."""
    rows = q("SELECT p.id, p.hostname, p.kind, p.last_seen, p.site_id, s.name AS site_name FROM probes p "
             "JOIN sites s ON s.id = p.site_id WHERE p.status = 'active' ORDER BY s.name, p.hostname")
    for r in rows:
        r["online"] = repo.probe_online(r)
    rows.sort(key=lambda r: (r["kind"] != "server", not r["online"]))
    return rows


@bp.get("/werkzeuge")
@login_required()
def tools():
    probes = _probes()
    wanted = request.args.get("probe", type=int)
    current = next((p for p in probes if p["id"] == wanted), None) or next((p for p in probes if p["online"]), None) \
        or (probes[0] if probes else None)
    tool = request.args.get("werkzeug", "ping")
    if tool not in tool_service.TOOLS:
        tool = "ping"
    history = [{**j, "label": tool_service.TOOLS[j["tool"]][0]} for j in tool_service.recent(15)]
    return render_template("tools.html", probes=probes, current=current, tool=tool, TOOLS=tool_service.TOOLS,
                           DNS_TYPES=tool_service.DNS_TYPES, history=history,
                           prefill=request.args.get("ziel", "")[:200])


@bp.post("/werkzeuge/start")
@login_required("operator", api=True)
def tool_start():
    data = request.get_json(silent=True) or request.form.to_dict()
    probe = q1("SELECT * FROM probes WHERE id = ? AND status = 'active'", (int(data.get("probe") or 0),))
    if probe is None:
        return jsonify(error="Bitte eine aktive Probe wählen."), 400
    tool = str(data.get("tool") or "")
    try:
        target, args = tool_service.clean(tool, data)
    except tool_service.ToolError as exc:
        return jsonify(error=str(exc)), 400
    user = current_user()["username"]
    job_id = tool_service.create(probe["id"], tool, target, args, user)
    repo.audit(user, f"tool.{tool}", f"probe:{probe['id']}", target)
    job = q1("SELECT * FROM tool_jobs WHERE id = ?", (job_id,))
    return jsonify(job=tool_service.view(job), online=repo.probe_online(probe), kind=probe["kind"]), 201


@bp.get("/werkzeuge/auftrag/<int:job_id>")
@login_required(api=True)
def tool_job(job_id: int):
    tool_service.expire()
    job = q1("SELECT * FROM tool_jobs WHERE id = ?", (job_id,)) or abort(404)
    return jsonify(job=tool_service.view(job))




