"""Web-Dashboard und Verwaltung (Server-gerendert, Jinja)."""
from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from datetime import datetime

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   session, url_for)

from . import repo
from .db import ex, ins, q, q1
from .security import (ROLE_LABELS, ROLES, check_csrf, csrf_token, current_user, has_role, hash_password,
                       hash_token, login_required, login_user, new_secret, password_problem, try_login,
                       verify_password)
from . import checktypes, standardpaket
from .services import alertgen
from .services import alerts as alert_service
from .services import checkstatus, notify, outages, pathanalysis, vm
from .services import settings as settings_service

log = logging.getLogger(__name__)
bp = Blueprint("web", __name__)


# -- Template-Hilfen ---------------------------------------------------------
@bp.app_context_processor
def inject():
    return {
        "user": current_user(),
        "csrf_token": csrf_token,
        "has_role": has_role,
        "ROLE_LABELS": ROLE_LABELS,
        "CHECK_ROLES": repo.CHECK_ROLES,
        "probe_online": repo.probe_online,
        "check_url": check_url,
    }


def check_url(probe: dict, check: dict) -> str:
    """Detailseite eines Checks auf einer Probe – je nach Art Ziel, Pfad oder Bandbreite."""
    if check["type"] == "path":
        return url_for("web.path_view", probe_id=probe["id"], check_id=check["id"])
    if check["type"] in checktypes.SCHEDULED_TYPES:
        return url_for("web.bandwidth_view", probe_id=probe["id"], check_id=check["id"])
    return url_for("web.target", probe_id=probe["id"], check_id=check["id"])


@bp.app_template_filter("dt")
def fmt_dt(ts):
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S") if ts else "–"


@bp.app_template_filter("ago")
def fmt_ago(ts):
    if not ts:
        return "nie"
    d = int(time.time()) - int(ts)
    if d < 60:
        return f"vor {d} s"
    if d < 3600:
        return f"vor {d // 60} min"
    if d < 86400:
        return f"vor {d // 3600} h"
    return f"vor {d // 86400} Tagen"


SEVERITY_LABELS = {"critical": "kritisch", "warning": "Warnung", "info": "Info"}


@bp.app_template_filter("severity")
def fmt_severity(v):
    return SEVERITY_LABELS.get(v, v or "–")


def _missing(v) -> bool:
    """None oder fehlender Wert (Jinja-Undefined, z. B. wenn ein Ziel gar nicht antwortet)."""
    from jinja2 import Undefined

    return v is None or isinstance(v, Undefined)


@bp.app_template_filter("ms")
def fmt_ms(v):
    return "–" if _missing(v) else (f"{v:.2f} ms" if v < 10 else f"{v:.1f} ms")


@bp.app_template_filter("pct")
def fmt_pct(v):
    return "–" if _missing(v) else f"{v:.1f} %"


@bp.app_template_filter("mbps")
def fmt_mbps(v):
    if _missing(v):
        return "–"
    return f"{v:.0f} Mbit/s" if v >= 100 else f"{v:.1f} Mbit/s"


@bp.app_template_filter("duration")
def fmt_duration(seconds):
    seconds = int(seconds or 0)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min {seconds % 60:02d} s"
    if seconds < 86400:
        return f"{seconds // 3600} h {seconds % 3600 // 60:02d} min"
    return f"{seconds // 86400} d {seconds % 86400 // 3600} h"


@bp.app_template_filter("fromjson")
def fromjson(v):
    return json.loads(v) if v else {}


@bp.before_request
def _csrf():
    if request.endpoint != "web.login":
        check_csrf()


def _live() -> tuple[dict, bool]:
    try:
        return vm.live_status(), True
    except vm.VMError as exc:
        log.warning("Live-Status nicht verfügbar: %s", exc)
        return {}, False


def _cell_state(v: dict | None) -> str:
    if not v or v.get("up") is None:
        return "unknown"
    if v["up"] == 0:
        return "down"
    if (v.get("loss") or 0) > 2:
        return "warn"
    return "ok"


def _regen_rules() -> None:
    try:
        alertgen.write_rules()
    except OSError as exc:
        log.error("Regeldatei konnte nicht geschrieben werden: %s", exc)
        flash("Alarmregeln konnten nicht aktualisiert werden (siehe Log).", "error")


# -- Anmeldung -------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("csrf_token") != session.get("csrf"):
            flash("Sitzung abgelaufen, bitte erneut versuchen.", "error")
            return redirect(url_for("web.login"))
        user, error = try_login(request.form.get("username", "").strip(), request.form.get("password", ""))
        if user:
            login_user(user)
            repo.audit(user["username"], "login")
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("web.overview"))
        repo.audit(request.form.get("username", "")[:64], "login.failed", detail=request.remote_addr or "")
        flash(error, "error")
    return render_template("login.html")


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))


@bp.route("/account", methods=["GET", "POST"])
@login_required()
def account():
    if request.method == "POST":
        user = q1("SELECT * FROM users WHERE id = ?", (current_user()["id"],))
        new = request.form.get("new_password", "")
        if not verify_password(user["password_hash"], request.form.get("old_password", "")):
            flash("Altes Passwort ist falsch.", "error")
        elif problem := password_problem(new):
            flash(problem, "error")
        else:
            ex("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user["id"]))
            repo.audit(user["username"], "user.password")
            flash("Passwort geändert.", "ok")
    return render_template("account.html")


# -- Dashboard ---------------------------------------------------------------
@bp.get("/")
@login_required()
def overview():
    sites = q("SELECT * FROM sites ORDER BY name")
    probes = q(
        "SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id ORDER BY s.name, p.hostname"
    )
    live, live_ok = _live()
    active = [p for p in probes if p["status"] == "active"]
    states = checkstatus.overview(active, live)
    per_probe = {p["id"]: checkstatus.counts(states[p["id"]]) for p in active}
    site_stats = {s["id"]: {"probes": 0, "online": 0, "problems": 0} for s in sites}
    problems = []      # (Probe, CheckState) – jede Messung, die gerade nicht funktioniert
    offline = []       # Probes ohne Heartbeat: ihre Checks liefern zwangsläufig nichts
    bandwidth = []     # (Probe, CheckState) aller Bandbreiten-Checks
    for p in probes:
        site_stats[p["site_id"]]["probes"] += 1
        if p["status"] != "active":
            continue
        if repo.probe_online(p):
            site_stats[p["site_id"]]["online"] += 1
            for st in states[p["id"]]:
                if st.problem:
                    problems.append((p, st))
        else:
            offline.append(p)
        site_stats[p["site_id"]]["problems"] += sum(1 for st in states[p["id"]] if st.problem)
        bandwidth += [(p, st) for st in states[p["id"]] if st.kind in checktypes.SCHEDULED_TYPES]
    problems.sort(key=lambda item: (("down", "stale", "warn").index(item[1].state), item[0]["hostname"]))
    alerts = q("SELECT * FROM alert_events WHERE status = 'firing' ORDER BY starts_at DESC LIMIT 50")
    return render_template(
        "overview.html", sites=sites, probes=probes, per_probe=per_probe, site_stats=site_stats,
        alerts=alerts, live_ok=live_ok, problems=problems, offline=offline, bandwidth=bandwidth,
        KIND_LABELS=checkstatus.KIND_LABELS,
    )


@bp.get("/sites/<int:site_id>")
@login_required()
def site(site_id: int):
    s = q1("SELECT * FROM sites WHERE id = ?", (site_id,)) or abort(404)
    probes = q(
        "SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id "
        "WHERE p.site_id = ? ORDER BY p.hostname",
        (site_id,),
    )
    live, live_ok = _live()
    states = checkstatus.overview(probes, live)
    all_checks: dict[int, dict] = {}
    matrix = {}
    for p in probes:
        for st in states[p["id"]]:
            all_checks.setdefault(st.check["id"], st.check)
            matrix[(st.check["id"], p["id"])] = st
    order = {"ping": 0, "path": 1, "iperf": 2, "speedtest": 3}
    return render_template(
        "site.html", site=s, probes=probes,
        checks=sorted(all_checks.values(), key=lambda c: (order.get(c["type"], 9), c["id"])),
        matrix=matrix, live_ok=live_ok, KIND_LABELS=checkstatus.KIND_LABELS,
    )


def _probe_or_404(probe_id: int) -> dict:
    return q1(
        "SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.id = ?", (probe_id,)
    ) or abort(404)


def _probe_check_or_404(probe: dict, check_id: int, types: tuple[str, ...]) -> dict:
    c = q1("SELECT * FROM checks WHERE id = ?", (check_id,)) or abort(404)
    if c["type"] not in types:
        abort(404)
    return c


@bp.get("/probes/<int:probe_id>")
@login_required()
def probe(probe_id: int):
    p = _probe_or_404(probe_id)
    checks = repo.checks_for_probe(p)
    live, live_ok = _live()
    rows = [(c, live.get((str(p["id"]), str(c["id"])))) for c in checks if c["type"] == "ping"]
    paths = []
    for c in (c for c in checks if c["type"] == "path"):
        run = q1("SELECT * FROM path_runs WHERE probe_id = ? AND check_id = ? ORDER BY ts DESC, id DESC LIMIT 1",
                 (probe_id, c["id"]))
        paths.append((c, run, json.loads(run["hops"]) if run else []))
    bandwidth = []
    for c in (c for c in checks if c["type"] in checktypes.SCHEDULED_TYPES):
        last = {d: q1("SELECT * FROM bandwidth_runs WHERE probe_id = ? AND check_id = ? AND direction = ? "
                      "ORDER BY ts DESC, id DESC LIMIT 1", (probe_id, c["id"], d)) for d in ("down", "up")}
        pending = q1("SELECT id FROM probe_commands WHERE probe_id = ? AND check_id = ? AND delivered_at IS NULL",
                     (probe_id, c["id"]))
        params = checktypes.merged(c["type"], json.loads(c["params"] or "{}"))
        bandwidth.append((c, last, pending, params))
    alerts = [
        a for a in q("SELECT * FROM alert_events ORDER BY starts_at DESC LIMIT 500")
        if json.loads(a["labels"]).get("probe") == str(probe_id)
    ][:20]
    measure = settings_service.get()
    latest_paths, latest_bw = checkstatus.latest_runs([probe_id])
    states = checkstatus.probe_states(p, checks, live, latest_paths, latest_bw)
    return render_template(
        "probe.html", probe=p, rows=rows, paths=paths, bandwidth=bandwidth, cell_state=_cell_state,
        states=states, state_counts=checkstatus.counts(states), KIND_LABELS=checkstatus.KIND_LABELS,
        live_ok=live_ok, alerts=alerts, addresses=json.loads(p["addresses"] or "[]"),
        default_iperf_port=measure["probe_iperf_port"],
        iperf_endpoint=repo.probe_iperf_endpoint(p, measure["probe_iperf_port"]),
    )


@bp.post("/probes/<int:probe_id>/settings")
@login_required("admin")
def probe_settings(probe_id: int):
    p = _probe_or_404(probe_id)
    enabled = request.form.get("iperf_server") == "on"
    address = request.form.get("iperf_address", "").strip()
    try:
        port = int(request.form.get("iperf_port", 5201))
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        flash("Port muss zwischen 1 und 65535 liegen.", "error")
    elif address and not checktypes.valid_host(address):
        flash("Adresse ist keine gültige IP-Adresse und kein Hostname.", "error")
    else:
        ex("UPDATE probes SET iperf_server = ?, iperf_port = ?, iperf_address = ? WHERE id = ?",
           (enabled, port, address or None, probe_id))
        repo.audit(current_user()["username"], "probe.settings", f"probe:{probe_id}",
                   f"iperf3-Gegenstelle {'an' if enabled else 'aus'}, Port {port}, Adresse {address or 'automatisch'}")
        flash(f"Einstellungen für {p['hostname']} gespeichert – die Probe übernimmt sie mit dem nächsten Heartbeat.", "ok")
    return redirect(url_for("web.probe", probe_id=probe_id) + "#einstellungen")


@bp.post("/probes/<int:probe_id>/checks/<int:check_id>/run")
@login_required("operator")
def check_run(probe_id: int, check_id: int):
    p = _probe_or_404(probe_id)
    c = _probe_check_or_404(p, check_id, ("iperf", "speedtest", "path"))
    if str(check_id) not in repo.check_map_for_probe(p):
        abort(404)
    ctype = "retrace" if c["type"] == "path" else "run_check"
    repo.queue_command(probe_id, ctype, check_id, current_user()["username"])
    repo.audit(current_user()["username"], f"probe.{ctype}", f"probe:{probe_id}", c["name"])
    beat = settings_service.get()["heartbeat_interval_s"]
    flash(("Pfad wird neu ermittelt" if ctype == "retrace" else "Messung beauftragt")
          + f" – die Probe holt den Auftrag mit dem nächsten Heartbeat ab (≤ {beat} s).", "ok")
    nxt = request.form.get("next", "")
    return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("web.probe", probe_id=probe_id))


@bp.get("/probes/<int:probe_id>/path/<int:check_id>")
@login_required()
def path_view(probe_id: int, check_id: int):
    p = _probe_or_404(probe_id)
    c = _probe_check_or_404(p, check_id, ("path",))
    window = request.args.get("window", "5m")
    if window not in vm.HOP_WINDOWS:
        window = "5m"
    runs = q("SELECT * FROM path_runs WHERE probe_id = ? AND check_id = ? ORDER BY ts DESC, id DESC LIMIT 50",
             (probe_id, check_id))
    current = json.loads(runs[0]["hops"]) if runs else []
    try:
        measured, live_ok = vm.hop_table(probe_id, check_id, window), True
    except vm.VMError as exc:
        log.warning("Hop-Werte nicht abrufbar: %s", exc)
        measured, live_ok = {}, False
    rows = []
    hop_numbers = sorted({h["hop"] for h in current} | set(measured))
    trace = {h["hop"]: h for h in current}
    for n in hop_numbers:
        m = measured.get(n, {})
        ip = m.get("ip") or (trace.get(n) or {}).get("ip")
        rows.append({"hop": n, "ip": ip, "other_ips": m.get("other_ips", []), "loss": m.get("loss"),
                     "avg": m.get("avg"), "min": m.get("min"), "max": m.get("max"), "last": m.get("last"),
                     "jitter": m.get("jitter"), "sent": m.get("sent"),
                     "trace_rtt": (trace.get(n) or {}).get("rtt_ms"),
                     "segment": pathanalysis.segment(ip, n)})
    analysis = pathanalysis.analyze(rows, c["target"])
    history = []
    for r in runs:
        history.append({"run": r, "hops": json.loads(r["hops"])})
    return render_template(
        "path.html", probe=p, check=c, rows=rows, analysis=analysis, history=history, window=window,
        windows=vm.HOP_WINDOWS, live_ok=live_ok, params=checktypes.merged("path", json.loads(c["params"] or "{}")),
    )


@bp.get("/probes/<int:probe_id>/path/<int:check_id>/hop/<int:hop>")
@login_required()
def hop_view(probe_id: int, check_id: int, hop: int):
    p = _probe_or_404(probe_id)
    c = _probe_check_or_404(p, check_id, ("path",))
    if not 1 <= hop <= 64:
        abort(404)
    run = q1("SELECT hops FROM path_runs WHERE probe_id = ? AND check_id = ? ORDER BY ts DESC, id DESC LIMIT 1",
             (probe_id, check_id))
    ip = next((h["ip"] for h in json.loads(run["hops"]) if h["hop"] == hop), None) if run else None
    return render_template("target.html", probe=p, check=c, hop=hop, hop_ip=ip, ranges=list(vm.RANGES),
                           windows=vm.STAT_WINDOWS)


BW_RANGES = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "365d": 365 * 86400}


@bp.get("/probes/<int:probe_id>/bandwidth/<int:check_id>")
@login_required()
def bandwidth_view(probe_id: int, check_id: int):
    p = _probe_or_404(probe_id)
    c = _probe_check_or_404(p, check_id, checktypes.SCHEDULED_TYPES)
    range_key = request.args.get("range", "30d")
    if range_key not in BW_RANGES:
        range_key = "30d"
    since = repo.now() - BW_RANGES[range_key]
    runs = q("SELECT * FROM bandwidth_runs WHERE probe_id = ? AND check_id = ? AND ts >= ? ORDER BY ts DESC, id DESC "
             "LIMIT 5000", (probe_id, check_id, since))
    params = checktypes.merged(c["type"], json.loads(c["params"] or "{}"))
    stats = {}
    for d in ("down", "up"):
        values = sorted(r["mbps"] for r in runs if r["direction"] == d and r["mbps"] is not None and not r["error"])
        if values:
            stats[d] = {"count": len(values), "min": values[0], "max": values[-1],
                        "avg": sum(values) / len(values), "median": values[len(values) // 2]}
    chart = {
        "down": [[r["ts"] * 1000, r["mbps"]] for r in reversed(runs) if r["direction"] == "down" and r["mbps"] is not None],
        "up": [[r["ts"] * 1000, r["mbps"]] for r in reversed(runs) if r["direction"] == "up" and r["mbps"] is not None],
        "min_down": params.get("min_down_mbps") or 0, "min_up": params.get("min_up_mbps") or 0,
        "start": since * 1000, "end": repo.now() * 1000,
    }
    pending = q1("SELECT id FROM probe_commands WHERE probe_id = ? AND check_id = ? AND delivered_at IS NULL",
                 (probe_id, check_id))
    return render_template("bandwidth.html", probe=p, check=c, runs=runs[:50], stats=stats, chart=chart,
                           params=params, range_key=range_key, ranges=list(BW_RANGES), pending=pending,
                           summary=checktypes.summary(c, params))


OUTAGE_RANGES = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "365d": 365 * 86400}


@bp.get("/outages")
@login_required()
def outages_view():
    range_key = request.args.get("range", "7d")
    if range_key not in OUTAGE_RANGES:
        range_key = "7d"
    site = request.args.get("site") or None
    cause = request.args.get("cause") or None
    show_all = request.args.get("all") == "1"
    min_s = settings_service.get()["outage_min_s"]
    items = outages.load(repo.now() - OUTAGE_RANGES[range_key], site, min_s, include_consequences=show_all)
    if cause in outages.CAUSES:
        items = [o for o in items if o.cause == cause]
    return render_template(
        "outages.html", items=items, summary=outages.summarize(items), causes=outages.CAUSES,
        sites=q("SELECT * FROM sites ORDER BY name"), range_key=range_key, ranges=list(OUTAGE_RANGES),
        site=site, cause=cause, show_all=show_all, min_s=min_s,
    )


@bp.post("/probes/<int:probe_id>/status")
@login_required("admin")
def probe_status(probe_id: int):
    new = "disabled" if request.form.get("action") == "disable" else "active"
    p = q1("SELECT deregistered_at FROM probes WHERE id = ?", (probe_id,)) or abort(404)
    if new == "active" and p["deregistered_at"]:
        flash("Die Probe wurde deinstalliert und hat kein gültiges Token mehr – zum erneuten Messen neu installieren.",
              "error")
        return redirect(url_for("web.probe", probe_id=probe_id))
    ex("UPDATE probes SET status = ? WHERE id = ?", (new, probe_id))
    repo.audit(current_user()["username"], f"probe.{new}", f"probe:{probe_id}")
    flash("Probe deaktiviert – ihr Token wird abgelehnt." if new == "disabled" else "Probe aktiviert.", "ok")
    return redirect(url_for("web.probe", probe_id=probe_id))


@bp.post("/probes/<int:probe_id>/delete")
@login_required("admin")
def probe_delete(probe_id: int):
    p = q1("SELECT hostname FROM probes WHERE id = ?", (probe_id,)) or abort(404)
    ex("DELETE FROM check_assignments WHERE scope = 'probe' AND scope_id = ?", (probe_id,))
    ex("DELETE FROM probes WHERE id = ?", (probe_id,))
    repo.audit(current_user()["username"], "probe.delete", f"probe:{probe_id}", p["hostname"])
    flash(f"Probe {p['hostname']} gelöscht. Messdaten bleiben bis zum Ablauf der Aufbewahrung erhalten.", "ok")
    return redirect(url_for("web.overview"))


@bp.get("/probes/<int:probe_id>/checks/<int:check_id>")
@login_required()
def target(probe_id: int, check_id: int):
    p = q1(
        "SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.id = ?", (probe_id,)
    ) or abort(404)
    c = q1("SELECT * FROM checks WHERE id = ?", (check_id,)) or abort(404)
    return render_template("target.html", probe=p, check=c, hop=None, hop_ip=None, ranges=list(vm.RANGES),
                           windows=vm.STAT_WINDOWS)


# -- Alarme ---------------------------------------------------------------
@bp.get("/alerts")
@login_required()
def alerts():
    firing = q("SELECT * FROM alert_events WHERE status = 'firing' ORDER BY starts_at DESC LIMIT 200")
    history = q("SELECT * FROM alert_events WHERE status = 'resolved' ORDER BY starts_at DESC LIMIT 200")
    return render_template("alerts.html", firing=firing, history=history)


@bp.post("/alerts/<int:event_id>/ack")
@login_required("operator")
def alert_ack(event_id: int):
    event = q1("SELECT * FROM alert_events WHERE id = ?", (event_id,)) or abort(404)
    hours = min(max(int(request.form.get("hours", 4) or 4), 1), 168)
    try:
        alert_service.acknowledge(event, current_user()["username"], hours, request.form.get("comment", "")[:500])
        repo.audit(current_user()["username"], "alert.ack", f"alert:{event_id}", f"{hours} h")
        flash(f"Alarm bestätigt und für {hours} h stummgeschaltet.", "ok")
    except RuntimeError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.alerts"))


# -- Verwaltung --------------------------------------------------------------
@bp.get("/admin")
@login_required("admin")
def admin():
    sites = q("SELECT * FROM sites ORDER BY name")
    probes = q("SELECT id, hostname, site_id FROM probes ORDER BY hostname")
    site_map = {s["id"]: s for s in sites}
    probe_map = {p["id"]: p for p in probes}
    checks = q("SELECT * FROM checks ORDER BY id")
    assignments = defaultdict(list)
    for a in q("SELECT * FROM check_assignments"):
        assignments[a["check_id"]].append(repo.scope_label(a["scope"], a["scope_id"], site_map, probe_map))
    tokens = q(
        "SELECT t.*, s.name AS site_name FROM enrollment_tokens t JOIN sites s ON s.id = t.site_id "
        "WHERE t.revoked = FALSE AND t.expires_at > ? AND t.uses < t.max_uses AND t.probe_kind = 'probe' "
        "ORDER BY t.created_at DESC",
        (repo.now(),),
    )
    return render_template(
        "admin.html", sites=sites, probes=probes, checks=checks, assignments=assignments, tokens=tokens,
        rules=list(repo.alert_rules().values()), users=q("SELECT * FROM users ORDER BY username"),
        intervals=repo.ALLOWED_INTERVALS, roles=ROLES, notify_settings=notify.get_settings(),
        probe_setup=repo.probe_setup_file(current_app.config["PROBE_DIR"]),
        notify_enabled=bool(current_app.config.get("AM_CONFIG")),
        check_types=checktypes.TYPES, summary=checktypes.summary, merged=checktypes.merged,
        measure=settings_service.get(), measure_fields=settings_service.FIELDS,
        package=standardpaket.preview(current_app.config["PUBLIC_URL"]),
    )


@bp.post("/admin/standard-package")
@login_required("admin")
def standard_package():
    """Standardpaket anlegen: Ping, Traceroute, iperf3 und Speedtest mit einem Klick."""
    scope = request.form.get("scope", "all")
    scope_id = None
    if scope == "site":
        scope_id = int(request.form.get("site_id", 0) or 0)
        if not q1("SELECT id FROM sites WHERE id = ?", (scope_id,)):
            flash("Bitte einen Standort auswählen.", "error")
            return redirect(url_for("web.admin") + "#standardpaket")
    elif scope != "all":
        abort(400)
    keys = request.form.getlist("items")
    if not keys:
        flash("Bitte mindestens einen Check auswählen.", "error")
        return redirect(url_for("web.admin") + "#standardpaket")
    created, skipped = standardpaket.apply(keys, scope, scope_id, current_app.config["PUBLIC_URL"])
    user = current_user()["username"]
    for cid, item in created:
        repo.audit(user, "check.create", f"check:{cid}", f"Standardpaket: {item.name}")
    if created:
        _regen_rules()
        flash(f"Standardpaket: {len(created)} Checks angelegt ({', '.join(i.name for _, i in created)}). "
              "Die Probes übernehmen sie mit dem nächsten Heartbeat.", "ok")
    if skipped:
        flash("Nicht angelegt: " + "; ".join(skipped) + ".", "ok" if created else "error")
    return redirect(url_for("web.admin") + "#checks")


@bp.post("/admin/measure")
@login_required("admin")
def measure_update():
    values, errors = settings_service.parse(request.form)
    if errors:
        for e in errors:
            flash(e, "error")
    else:
        changed = settings_service.save(values)
        repo.audit(current_user()["username"], "measure.update", detail=", ".join(f"{k}={values[k]}" for k in changed))
        flash("Messeinstellungen gespeichert." if changed else "Keine Änderungen.", "ok")
    return redirect(url_for("web.admin") + "#messung")


@bp.post("/admin/sites")
@login_required("admin")
def site_create():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Name fehlt.", "error")
    elif q1("SELECT id FROM sites WHERE name = ?", (name,)):
        flash("Standort existiert bereits.", "error")
    else:
        ins(
            "INSERT INTO sites (name, customer_no, description, created_at) VALUES (?, ?, ?, ?)",
            (name, request.form.get("customer_no", "").strip() or None,
             request.form.get("description", "").strip() or None, repo.now()),
        )
        repo.audit(current_user()["username"], "site.create", name)
        flash(f"Standort {name} angelegt.", "ok")
    return redirect(url_for("web.admin") + "#standorte")


@bp.post("/admin/sites/<int:site_id>/delete")
@login_required("admin")
def site_delete(site_id: int):
    if q1("SELECT id FROM probes WHERE site_id = ? LIMIT 1", (site_id,)):
        flash("Standort hat noch Probes – erst Probes löschen.", "error")
    else:
        ex("DELETE FROM check_assignments WHERE scope = 'site' AND scope_id = ?", (site_id,))
        ex("DELETE FROM sites WHERE id = ?", (site_id,))
        repo.audit(current_user()["username"], "site.delete", f"site:{site_id}")
        flash("Standort gelöscht.", "ok")
        _regen_rules()
    return redirect(url_for("web.admin") + "#standorte")


@bp.post("/admin/tokens")
@login_required("admin")
def token_create():
    site_id = int(request.form.get("site_id", 0) or 0)
    s = q1("SELECT * FROM sites WHERE id = ?", (site_id,))
    if s is None:
        flash("Bitte zuerst einen Standort anlegen und auswählen.", "error")
        return redirect(url_for("web.admin") + "#enrollment")
    days = min(max(int(request.form.get("days", 7) or 7), 1), 90)
    max_uses = min(max(int(request.form.get("max_uses", 1) or 1), 1), 500)
    token = repo.create_enrollment_token(site_id, max_uses, days, current_user()["username"],
                                         request.form.get("description", ""))
    setup = repo.probe_setup_file(current_app.config["PROBE_DIR"])
    return render_template(
        "token_created.html", token=token, site=s, days=days, max_uses=max_uses,
        server_url=current_app.config["PUBLIC_URL"], pin=current_app.config["SPKI_PIN"],
        setup_name=setup.name if setup else None,
    )


@bp.post("/admin/tokens/package")
@login_required("admin")
def token_package():
    """ZIP mit Probe-Setup und vorbelegter wachtl-probe.ini (Server, Pin, Token)."""
    import io
    import zipfile

    token = request.form.get("token", "").strip()
    row = q1("SELECT t.*, s.name AS site_name FROM enrollment_tokens t JOIN sites s ON s.id = t.site_id "
             "WHERE t.token_hash = ?", (hash_token(token),)) if token else None
    if row is None or row["revoked"] or row["expires_at"] < repo.now():
        abort(400, "Token unbekannt, widerrufen oder abgelaufen.")
    setup = repo.probe_setup_file(current_app.config["PROBE_DIR"])
    if setup is None:
        abort(404, "Kein Probe-Setup auf dem Server hinterlegt.")
    ini = repo.probe_ini(current_app.config["PUBLIC_URL"], current_app.config["SPKI_PIN"], token,
                         request.form.get("proxy", "").strip())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(setup, setup.name)
        zf.writestr("wachtl-probe.ini", ini.encode("utf-8-sig"))
        zf.writestr("LIESMICH.txt", (
            "Wachtl Probe installieren\r\n\r\n"
            f"1. Beide Dateien in einen Ordner entpacken.\r\n2. {setup.name} als Administrator starten.\r\n"
            "   Server, Pin und Token sind bereits eingetragen – nur noch Weiter klicken.\r\n\r\n"
            f"Standort: {row['site_name']}\r\nDer Token gilt bis {datetime.fromtimestamp(row['expires_at']):%d.%m.%Y %H:%M}.\r\n"
        ).encode("utf-8-sig"))
    buf.seek(0)
    repo.audit(current_user()["username"], "token.package", f"site:{row['site_id']}")
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in row["site_name"])[:40]
    from flask import send_file

    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"Wachtl-Probe-{safe}.zip")


@bp.get("/admin/probe-setup")
@login_required("admin")
def probe_setup_download():
    """Probe-Setup ohne Vorbelegung (z. B. für die Softwareverteilung)."""
    setup = repo.probe_setup_file(current_app.config["PROBE_DIR"])
    if setup is None:
        abort(404, "Kein Probe-Setup auf dem Server hinterlegt.")
    from flask import send_file

    return send_file(setup, as_attachment=True, download_name=setup.name)


@bp.post("/admin/tokens/<int:token_id>/revoke")
@login_required("admin")
def token_revoke(token_id: int):
    ex("UPDATE enrollment_tokens SET revoked = TRUE WHERE id = ?", (token_id,))
    repo.audit(current_user()["username"], "token.revoke", f"token:{token_id}")
    flash("Enrollment-Token widerrufen.", "ok")
    return redirect(url_for("web.admin") + "#enrollment")


def _probe_names() -> dict[int, str]:
    return {p["id"]: f"{p['hostname']} ({p['site_name']})" for p in
            q("SELECT p.id, p.hostname, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id ORDER BY s.name, p.hostname")}


def _check_form_context(ctype: str, check: dict | None, values: dict | None = None,
                        errors: list | None = None) -> dict:
    ct = checktypes.TYPES[ctype]
    params = checktypes.merged(ctype, json.loads(check["params"] or "{}") if check else None)
    if values:
        params.update(values)
    # Fehler in der Reihenfolge der Felder im Formular, damit die Übersicht dem Lesefluss folgt
    order = ["name", "target", "role", "interval_s", "timeout_ms"] + [f.key for f in ct.fields] + ["scope"]
    errors = sorted(errors or [], key=lambda e: order.index(e.field) if getattr(e, "field", None) in order else len(order))
    groups: dict[str, list] = {}
    for f in ct.fields:
        groups.setdefault(f.group, []).append(f)
    assignment = None
    if check:
        assignment = q1("SELECT scope, scope_id FROM check_assignments WHERE check_id = ? ORDER BY id LIMIT 1",
                        (check["id"],))
    return {
        "ctype": ct, "check": check, "params": params, "groups": groups,
        "sites": q("SELECT * FROM sites ORDER BY name"),
        "probes": q("SELECT p.id, p.hostname, p.iperf_server, s.name AS site_name FROM probes p "
                    "JOIN sites s ON s.id = p.site_id ORDER BY s.name, p.hostname"),
        "intervals": repo.ALLOWED_INTERVALS, "assignment": assignment or {"scope": "all", "scope_id": None},
        "visible": checktypes.visible_keys(ctype, params),
        "errors": errors,
        "field_errors": {e.field: e for e in reversed(errors) if getattr(e, "field", None)},
    }


@bp.get("/admin/checks/new/<ctype>")
@login_required("admin")
def check_new(ctype: str):
    if ctype not in checktypes.TYPES:
        abort(404)
    return render_template("check_form.html", **_check_form_context(ctype, None))


@bp.get("/admin/checks/<int:check_id>/edit")
@login_required("admin")
def check_edit(check_id: int):
    c = q1("SELECT * FROM checks WHERE id = ?", (check_id,)) or abort(404)
    if c["type"] not in checktypes.TYPES:
        abort(404)
    return render_template("check_form.html", **_check_form_context(c["type"], c))


@bp.post("/admin/checks")
@login_required("admin")
def check_create():
    """Check anlegen oder (mit check_id) ändern – für alle Check-Typen."""
    f = request.form
    ctype = f.get("type", "ping")
    if ctype not in checktypes.TYPES:
        abort(400)
    check_id = int(f.get("check_id", 0) or 0)
    existing = q1("SELECT * FROM checks WHERE id = ?", (check_id,)) if check_id else None
    if check_id and (existing is None or existing["type"] != ctype):
        abort(404)
    name = f.get("name", "").strip()
    scope = f.get("scope", "all")
    scope_id = None
    if scope == "site":
        scope_id = int(f.get("site_id", 0) or 0)
    elif scope == "probe":
        scope_id = int(f.get("probe_id", 0) or 0)
    names = _probe_names()
    params, errors = checktypes.parse_params(ctype, f, probe_ids=set(names))
    FieldError = checktypes.FieldError
    if not name:
        errors.append(FieldError("Name fehlt.", "name"))
    if scope not in ("all", "site", "probe") or (scope != "all" and not scope_id):
        errors.append(FieldError("Zuweisung unvollständig.", "scope"))

    target, role, interval, timeout = "", checktypes.ROLE_DEFAULT[ctype], 3600, 60000
    if ctype in ("ping", "path"):
        target = f.get("target", "").strip()
        try:
            interval = int(f.get("interval_s", 1))
            timeout = int(f.get("timeout_ms", 1000))
        except ValueError:
            interval, timeout = -1, -1
        if not repo.valid_target(target) or (ctype == "path" and target == "gateway"):
            errors.append(FieldError("Ziel ist keine gültige IP-Adresse oder kein gültiger Hostname"
                                     + ("." if ctype == "path" else " und nicht 'gateway'."), "target"))
        if interval not in repo.ALLOWED_INTERVALS:
            errors.append(FieldError("Ungültiges Intervall.", "interval_s"))
        if not 100 <= timeout <= 5000:
            errors.append(FieldError("Timeout muss zwischen 100 und 5000 ms liegen.", "timeout_ms"))
        if ctype == "ping":
            role = f.get("role", "target")
            if role not in repo.CHECK_ROLES:
                errors.append(FieldError("Ungültige Rolle.", "role"))
    elif not errors:
        target = checktypes.target_for(ctype, params, names)
        interval = params["schedule_min"] * 60 if params["schedule_min"] else 3600
        timeout = params["timeout_s"] * 1000
        if ctype == "iperf" and params["peer"] == "probe" and scope == "probe" and scope_id == params["peer_probe_id"]:
            errors.append(FieldError("Eine Probe kann nicht gegen sich selbst messen.", "peer_probe_id"))

    if errors:
        # Fehler stehen gesammelt über dem Formular und jeweils am Feld (kein Flash)
        ctx = _check_form_context(ctype, existing, params, errors)
        ctx["form"] = f
        return render_template("check_form.html", **ctx), 400

    user = current_user()["username"]
    if existing:
        repo.update_check(check_id, name, target, role, interval, timeout, scope, scope_id, params)
        repo.audit(user, "check.update", f"check:{check_id}", f"{ctype} {target} {json.dumps(params, sort_keys=True)}")
        flash(f"Check {name} gespeichert. Probes übernehmen die Änderung mit dem nächsten Heartbeat.", "ok")
    else:
        check_id = repo.create_check(name, target, role, interval, timeout, scope, scope_id, ctype, params)
        repo.audit(user, "check.create", f"check:{check_id}", f"{ctype} {target} alle {interval} s")
        flash(f"Check {name} angelegt. Probes übernehmen ihn mit dem nächsten Heartbeat.", "ok")
    _regen_rules()
    return redirect(url_for("web.admin") + "#checks")


@bp.post("/admin/checks/<int:check_id>/toggle")
@login_required("admin")
def check_toggle(check_id: int):
    c = q1("SELECT * FROM checks WHERE id = ?", (check_id,)) or abort(404)
    ex("UPDATE checks SET enabled = ?, updated_at = ? WHERE id = ?", (not c["enabled"], repo.now(), check_id))
    repo.audit(current_user()["username"], "check.toggle", f"check:{check_id}", "aus" if c["enabled"] else "an")
    _regen_rules()
    return redirect(url_for("web.admin") + "#checks")


@bp.post("/admin/checks/<int:check_id>/delete")
@login_required("admin")
def check_delete(check_id: int):
    ex("DELETE FROM checks WHERE id = ?", (check_id,))
    repo.audit(current_user()["username"], "check.delete", f"check:{check_id}")
    flash("Check gelöscht.", "ok")
    _regen_rules()
    return redirect(url_for("web.admin") + "#checks")


@bp.post("/admin/rules")
@login_required("admin")
def rules_update():
    for r in repo.alert_rules().values():
        k = r["kind"]
        try:
            threshold = float(request.form.get(f"threshold_{k}", r["threshold"]))
            window_s = int(request.form.get(f"window_{k}", r["window_s"]))
            for_s = int(request.form.get(f"for_{k}", r["for_s"]))
        except ValueError:
            flash(f"Ungültiger Wert bei {r['name']}.", "error")
            return redirect(url_for("web.admin") + "#alarme")
        enabled = request.form.get(f"enabled_{k}") == "on"
        severity = request.form.get(f"severity_{k}", r["severity"])
        if severity not in ("warning", "critical", "info") or threshold < 0 or window_s < 0 or for_s < 0:
            flash(f"Ungültiger Wert bei {r['name']}.", "error")
            return redirect(url_for("web.admin") + "#alarme")
        ex(
            "UPDATE alert_rules SET threshold = ?, window_s = ?, for_s = ?, severity = ?, enabled = ?, updated_at = ? "
            "WHERE id = ?",
            (threshold, window_s, for_s, severity, enabled, repo.now(), r["id"]),
        )
    repo.audit(current_user()["username"], "rules.update")
    _regen_rules()
    flash("Alarmregeln gespeichert und an vmalert übergeben.", "ok")
    return redirect(url_for("web.admin") + "#alarme")


@bp.post("/admin/users")
@login_required("admin")
def user_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "readonly")
    problem = password_problem(password)
    if not username or role not in ROLES:
        flash("Benutzername oder Rolle ungültig.", "error")
    elif problem:
        flash(problem, "error")
    elif q1("SELECT id FROM users WHERE username = ?", (username,)):
        flash("Benutzer existiert bereits.", "error")
    else:
        ins(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, repo.now()),
        )
        repo.audit(current_user()["username"], "user.create", username, role)
        flash(f"Benutzer {username} angelegt.", "ok")
    return redirect(url_for("web.admin") + "#benutzer")


@bp.post("/admin/users/<int:user_id>/delete")
@login_required("admin")
def user_delete(user_id: int):
    if user_id == current_user()["id"]:
        flash("Das eigene Konto kann nicht gelöscht werden.", "error")
    else:
        u = q1("SELECT username FROM users WHERE id = ?", (user_id,)) or abort(404)
        ex("DELETE FROM users WHERE id = ?", (user_id,))
        repo.audit(current_user()["username"], "user.delete", u["username"])
        flash(f"Benutzer {u['username']} gelöscht.", "ok")
    return redirect(url_for("web.admin") + "#benutzer")


@bp.get("/admin/audit")
@login_required("admin")
def audit():
    return render_template("audit.html", rows=q("SELECT * FROM audit_log ORDER BY ts DESC LIMIT 500"))


@bp.post("/admin/notify")
@login_required("admin")
def notify_update():
    current = notify.get_settings()
    values = {k: request.form.get(k, "").strip() for k in notify.FIELDS}
    values["smtp_require_tls"] = "true" if request.form.get("smtp_require_tls") == "on" else "false"
    if not values["smtp_password"]:
        values["smtp_password"] = current.get("smtp_password", "")  # leer = unverändert
    if request.form.get("clear_password") == "on":
        values["smtp_password"] = ""
    errors = notify.validate(values)
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("web.admin") + "#benachrichtigungen")
    notify.save_settings(values)
    changed = [k for k in notify.FIELDS if values[k] != current.get(k, "")]
    shown = ", ".join("smtp_password" if k in notify.SECRET_FIELDS else f"{k}={values[k]}" for k in changed)
    repo.audit(current_user()["username"], "notify.update", detail=shown)
    try:
        notify.write_config()
        flash("Benachrichtigungen gespeichert und an Alertmanager übergeben.", "ok")
    except OSError as exc:
        log.error("Alertmanager-Konfiguration nicht geschrieben: %s", exc)
        flash("Gespeichert, aber die Alertmanager-Datei konnte nicht geschrieben werden (siehe Log).", "error")
    return redirect(url_for("web.admin") + "#benachrichtigungen")


@bp.post("/admin/notify/test")
@login_required("admin")
def notify_test():
    try:
        notify.send_test(current_user()["username"])
        repo.audit(current_user()["username"], "notify.test")
        flash("Testnachricht ausgelöst – sie kommt nach etwa 30 Sekunden bei allen Empfängern an.", "ok")
    except notify.NotifyError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.admin") + "#benachrichtigungen")
