"""Web-Dashboard und Verwaltung (Server-gerendert, Jinja)."""
from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template, request,
                   session, url_for)

from . import repo
from .db import ex, ins, q, q1
from .security import (ROLE_LABELS, ROLES, check_csrf, csrf_ok, csrf_token, current_user, has_role,
                       hash_password, hash_token, login_required, login_user, password_marker, password_problem,
                       try_login, verify_password)
from . import checktypes, httperrors, rtp, standardpaket
from . import findings as finding_service
from . import reports as report_service
from .services import alertgen
from .services import alerts as alert_service
from .services import checkstatus, notify, outages, pathanalysis, vm
from .services import settings as settings_service

log = logging.getLogger(__name__)
bp = Blueprint("web", __name__)


# -- Template-Hilfen ---------------------------------------------------------
@bp.app_context_processor
def inject():
    user = current_user()
    return {
        "user": user,
        "open_reports": report_service.count("open") if user else 0,
        "csrf_token": csrf_token,
        "has_role": has_role,
        "ROLE_LABELS": ROLE_LABELS,
        "CHECK_ROLES": repo.CHECK_ROLES,
        "probe_online": repo.probe_online,
        "check_url": check_url,
        "report_graph_url": report_graph_url,
        "alert_refs": alert_refs,
    }


def check_url(probe: dict, check: dict) -> str:
    """Detailseite eines Checks auf einer Probe – je nach Art Ziel, Pfad oder Bandbreite."""
    if check["type"] == "path":
        return url_for("web.path_view", probe_id=probe["id"], check_id=check["id"])
    if check["type"] == "rtp":
        return url_for("web.rtp_view", probe_id=probe["id"], check_id=check["id"])
    if check["type"] in checktypes.BANDWIDTH_TYPES:
        return url_for("web.bandwidth_view", probe_id=probe["id"], check_id=check["id"])
    return url_for("web.target", probe_id=probe["id"], check_id=check["id"])


def alert_refs(a: dict, with_probe: bool = True) -> list[tuple[str, str, str, str]]:
    """Probe, Standort und Ziel eines Alarms aus seinen Labels: (Art, Name, URL, aria-label) für Links."""
    lb = json.loads(a["labels"] or "{}")
    probe, site, check = (str(lb.get(k, "")) for k in ("probe", "site", "check_id"))
    probe_name = lb.get("probe_name") or probe
    refs = []
    if with_probe and probe.isdigit():
        refs.append(("Probe", probe_name, url_for("web.probe", probe_id=int(probe)), ""))
    if site.isdigit():
        refs.append(("Standort", lb.get("site_name") or site, url_for("web.site", site_id=int(site)), ""))
    if probe.isdigit() and check.isdigit():
        ctype = {"route_change": "path", "bandwidth_low": "iperf", "voip_quality": "rtp"}.get(lb.get("kind"), "ping")
        name = lb.get("target") or check
        refs.append(("Ziel", name, check_url({"id": int(probe)}, {"id": int(check), "type": ctype}),
                     f"{name} von {probe_name}"))
    return refs


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


@bp.app_template_filter("mos")
def fmt_mos(v):
    return "–" if _missing(v) else f"{v:.2f}"


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


@bp.app_template_filter("explain_error")
def explain_error(v):
    return httperrors.explain(v)


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
        if not csrf_ok():
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


@bp.get("/passwort-vergessen")
def password_forgot():
    # Windows-Server läuft ohne Docker direkt unter Windows, Linux-Server im Container
    return render_template("password_forgot.html", windows=os.name == "nt")


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))


THEMES = {"system": "Wie das System", "light": "Hell", "dark": "Dunkel"}
CONTRASTS = {"normal": "Standard", "high": "Erhöht"}


@bp.route("/account", methods=["GET", "POST"])
@login_required()
def account():
    user = q1("SELECT id, username, role, created_at, last_login, password_hash FROM users WHERE id = ?",
              (current_user()["id"],))
    if request.method == "POST":
        new = request.form.get("new_password", "")
        if not verify_password(user["password_hash"], request.form.get("old_password", "")):
            flash("Altes Passwort ist falsch.", "error")
        elif new != request.form.get("new_password2", new):
            flash("Die beiden neuen Passwörter stimmen nicht überein.", "error")
        elif problem := password_problem(new):
            flash(problem, "error")
        else:
            new_hash = hash_password(new)
            ex("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
            session["pwv"] = password_marker(new_hash)  # diese Sitzung bleibt, alle anderen enden
            repo.audit(user["username"], "user.password")
            flash("Passwort geändert.", "ok")
        return redirect(url_for("web.account"))
    return render_template("account.html", account=user)


@bp.route("/account/design", methods=["GET", "POST"])
@login_required()
def design():
    if request.method == "POST":
        theme, contrast = request.form.get("theme"), request.form.get("contrast")
        if theme not in THEMES or contrast not in CONTRASTS:
            abort(400)
        ex("UPDATE users SET theme = ?, contrast = ? WHERE id = ?", (theme, contrast, current_user()["id"]))
        g.pop("user_key", None)  # zwischengespeicherten Benutzer verwerfen
        flash("Design gespeichert.", "ok")
        return redirect(url_for("web.design"))
    return render_template("design.html", themes=THEMES, contrasts=CONTRASTS)


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
    voice = []         # (Probe, CheckState) aller Sprachtests
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
        bandwidth += [(p, st) for st in states[p["id"]] if st.kind in checktypes.BANDWIDTH_TYPES]
        voice += [(p, st) for st in states[p["id"]] if st.kind == "rtp"]
    problems.sort(key=lambda item: (("down", "stale", "warn").index(item[1].state), item[0]["hostname"]))
    alerts = q("SELECT * FROM alert_events WHERE status = 'firing' ORDER BY starts_at DESC LIMIT 50")
    since = repo.now() - 7 * 86400
    recent_reports = report_service.search("open", since=since, limit=5)
    client_findings = finding_service.search(since=repo.now() - 86400, limit=20)
    return render_template(
        "overview.html", sites=sites, probes=probes, per_probe=per_probe, site_stats=site_stats,
        client_findings=client_findings,
        alerts=alerts, live_ok=live_ok, problems=problems, offline=offline, bandwidth=bandwidth, voice=voice,
        KIND_LABELS=checkstatus.KIND_LABELS, recent_reports=recent_reports,
        recent_reports_total=report_service.count("open", since=since) if recent_reports else 0,
    )


def _sparkline(data: dict | None, target: str) -> dict | None:
    """Mini-Graph (SVG-Pfad, 120 × 30) aus Latenz-Median und Verlust je Minute der letzten Stunde."""
    rtt = [(t, v) for t, v in (data or {}).get("rtt", []) if v is not None]
    if not rtt:
        return None
    end = int(time.time())
    top = max(v for _, v in rtt) * 1.15 or 1

    def x(t: int) -> float:
        return round(max(0, 120 - (end - t) / 30), 1)

    d, prev = [], None
    for t, v in rtt:  # Lücke (keine Antwort) unterbricht die Linie
        d.append(f"{'L' if prev is not None and t - prev <= 90 else 'M'}{x(t)} {round(28 - v / top * 26, 1)}")
        prev = t
    loss = [(x(t), round(max(3, v * 0.3), 1)) for t, v in data.get("loss", []) if v]
    lo, hi = min(v for _, v in rtt), max(v for _, v in rtt)
    label = (f"Latenz-Median der letzten Stunde zu {target}: {fmt_ms(lo)} bis {fmt_ms(hi)}, "
             f"Paketverlust in {len(loss)} von 60 Minuten")
    return {"d": " ".join(d), "loss": loss, "label": label}


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
    try:
        sparks = vm.site_sparklines(site_id)
    except vm.VMError as exc:
        log.warning("Mini-Graphen nicht verfügbar: %s", exc)
        sparks = {}
    ids = {str(p["id"]) for p in probes}
    alerts = []
    for a in q("SELECT * FROM alert_events WHERE status = 'firing' ORDER BY starts_at DESC LIMIT 500"):
        labels = json.loads(a["labels"] or "{}")
        if labels.get("site") == str(site_id) or labels.get("probe") in ids:
            alerts.append({**a, "probe": labels.get("probe")})

    # je Probe ein Widget; Probes mit Problemen zuerst
    widgets, internet, bandwidth, problems = [], [], [], 0
    for p in probes:
        sts = states[p["id"]]
        active = p["status"] == "active"
        online = active and repo.probe_online(p)
        pings = [st for st in sts if st.kind == "ping"]
        ref = next((st for st in pings if st.check["role"] == "reference"), pings[0] if pings else None)
        p_alerts = [a for a in alerts if a["probe"] == str(p["id"])]
        issues = []
        if active and not online:
            issues.append(f"Probe offline – letzter Kontakt {fmt_ago(p['last_seen'])}")
            problems += 1
        elif active:
            issues += [f"{st.check['name']}: {st.detail or st.label}" for st in sts if st.problem]
            problems += sum(st.problem for st in sts)
            internet += [st for st in pings if st.check["role"] == "reference"]
        issues += [f"Alarm: {a['summary'] or a['alertname']}" for a in p_alerts]
        if active:
            bandwidth += [(p, st) for st in sts if st.kind in checktypes.BANDWIDTH_TYPES and st.ts]
        bad = (active and not online) or any(st.state == "down" for st in sts) or \
            any(a["severity"] == "critical" for a in p_alerts)
        level = "inactive" if not active else "bad" if bad else "warn" if issues else "ok"
        spark = sparks.get((str(p["id"]), str(ref.check["id"]))) if ref else None
        widgets.append({
            "probe": p, "online": online, "level": level, "issues": issues, "counts": checkstatus.counts(sts),
            "ref": ref, "jitter": (spark or {}).get("jitter"),
            "gateway": next((st for st in pings if st.check["role"] == "gateway"), None),
            "spark": _sparkline(spark, ref.check["name"]) if ref and active else None,
        })
    widgets.sort(key=lambda w: (("bad", "warn", "ok", "inactive").index(w["level"]), w["probe"]["hostname"]))
    if not internet:
        net = None
    elif all(st.state == "ok" for st in internet):
        net = "ok"
    else:
        net = "auffällig" if any(st.state in ("ok", "warn") for st in internet) else "gestört"
    # neueste Bandbreitenmessung, WAN-Speedtest vor iperf3
    bw = max(bandwidth, key=lambda i: (i[1].kind == "speedtest", i[1].ts), default=None)

    all_checks: dict[int, dict] = {}
    matrix = {}
    for p in probes:
        for st in states[p["id"]]:
            all_checks.setdefault(st.check["id"], st.check)
            matrix[(st.check["id"], p["id"])] = st
    order = {"ping": 0, "path": 1, "iperf": 2, "speedtest": 3, "rtp": 4}
    active = [p for p in probes if p["status"] == "active"]
    return render_template(
        "site.html", site=s, probes=probes, widgets=widgets, alerts=alerts, net=net, bw=bw,
        kpi={"active": len(active), "online": sum(repo.probe_online(p) for p in active), "problems": problems,
             "reports": report_service.count("open", site_id=site_id)},
        checks=sorted(all_checks.values(), key=lambda c: (order.get(c["type"], 9), c["id"])),
        matrix=matrix, live_ok=live_ok, KIND_LABELS=checkstatus.KIND_LABELS,
        reports=report_service.search(site_id=site_id, limit=10),
        client_findings=finding_service.search(site_id=site_id, since=repo.now() - 7 * 86400, limit=20),
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
    bandwidth, voice = [], []
    for c in (c for c in checks if c["type"] == "rtp"):
        last = q1("SELECT * FROM rtp_runs WHERE probe_id = ? AND check_id = ? ORDER BY ts DESC, id DESC LIMIT 1",
                  (probe_id, c["id"]))
        pending = q1("SELECT id FROM probe_commands WHERE probe_id = ? AND check_id = ? AND delivered_at IS NULL",
                     (probe_id, c["id"]))
        voice.append((c, last, pending, checktypes.merged("rtp", json.loads(c["params"] or "{}"))))
    for c in (c for c in checks if c["type"] in checktypes.BANDWIDTH_TYPES):
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
        "probe.html", probe=p, rows=rows, paths=paths, bandwidth=bandwidth, voice=voice, cell_state=_cell_state,
        states=states, state_counts=checkstatus.counts(states), KIND_LABELS=checkstatus.KIND_LABELS,
        live_ok=live_ok, alerts=alerts, addresses=json.loads(p["addresses"] or "[]"),
        default_iperf_port=measure["probe_iperf_port"], default_rtp_port=measure["probe_rtp_port"],
        iperf_endpoint=repo.probe_iperf_endpoint(p, measure["probe_iperf_port"]),
        reports=report_service.search(probe_id=probe_id, limit=10),
        client_findings=finding_service.search(probe_id=probe_id, since=repo.now() - 30 * 86400, limit=20),
        excluded_checks=repo.excluded_checks(p),
    )


@bp.post("/probes/<int:probe_id>/checks/<int:check_id>/remove")
@login_required("admin")
def probe_check_remove(probe_id: int, check_id: int):
    """Eine Messung bei dieser Probe entfernen: nur hier zugewiesen = löschen, sonst Ausnahme für diese Probe."""
    p = _probe_or_404(probe_id)
    c = q1("SELECT id, name FROM checks WHERE id = ?", (check_id,)) or abort(404)
    result = repo.remove_check_from_probe(check_id, p)
    user = current_user()["username"]
    if result == "deleted":
        repo.audit(user, "check.delete", f"check:{check_id}", f"{c['name']} (nur {p['hostname']} zugewiesen)")
        flash(f"Messung „{c['name']}“ gelöscht.", "ok")
    else:
        repo.audit(user, "check.exclude", f"check:{check_id}", f"{c['name']} für {p['hostname']} entfernt")
        flash(f"Messung „{c['name']}“ für {p['hostname']} entfernt. Andere Probes messen weiter.", "ok")
    _regen_rules()
    return redirect(url_for("web.probe", probe_id=probe_id) + "#messungen")


@bp.post("/probes/<int:probe_id>/checks/<int:check_id>/restore")
@login_required("admin")
def probe_check_restore(probe_id: int, check_id: int):
    p = _probe_or_404(probe_id)
    c = q1("SELECT id, name FROM checks WHERE id = ?", (check_id,)) or abort(404)
    ex("DELETE FROM check_assignments WHERE check_id = ? AND scope = 'exclude_probe' AND scope_id = ?",
       (check_id, probe_id))
    repo.audit(current_user()["username"], "check.include", f"check:{check_id}", f"{c['name']} für {p['hostname']}")
    flash(f"Messung „{c['name']}“ läuft wieder auf {p['hostname']}.", "ok")
    _regen_rules()
    return redirect(url_for("web.probe", probe_id=probe_id) + "#messungen")


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
                   f"Gegenstelle {'an' if enabled else 'aus'}, iperf3-Port {port}, Adresse {address or 'automatisch'}")
        flash(f"Einstellungen für {p['hostname']} gespeichert – die Probe übernimmt sie mit dem nächsten Heartbeat.", "ok")
    return redirect(url_for("web.probe", probe_id=probe_id) + "#einstellungen")


@bp.post("/probes/<int:probe_id>/checks/<int:check_id>/run")
@login_required("operator")
def check_run(probe_id: int, check_id: int):
    p = _probe_or_404(probe_id)
    c = _probe_check_or_404(p, check_id, checktypes.SCHEDULED_TYPES + ("path",))
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
                           windows=vm.STAT_WINDOWS, **_chart_reports(probe_id))


BW_RANGES = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "365d": 365 * 86400}


@bp.get("/probes/<int:probe_id>/bandwidth/<int:check_id>")
@login_required()
def bandwidth_view(probe_id: int, check_id: int):
    p = _probe_or_404(probe_id)
    c = _probe_check_or_404(p, check_id, checktypes.BANDWIDTH_TYPES)
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
        "reports": report_service.for_chart(since, repo.now(), probe_id),   # ts in Sekunden wie /api/reports
    }
    pending = q1("SELECT id FROM probe_commands WHERE probe_id = ? AND check_id = ? AND delivered_at IS NULL",
                 (probe_id, check_id))
    return render_template("bandwidth.html", probe=p, check=c, runs=runs[:50], stats=stats, chart=chart,
                           params=params, range_key=range_key, ranges=list(BW_RANGES), pending=pending,
                           summary=checktypes.summary(c, params))


@bp.get("/probes/<int:probe_id>/rtp/<int:check_id>")
@login_required()
def rtp_view(probe_id: int, check_id: int):
    """Sprachtest: MOS-Verlauf, Werte je Richtung und die letzten Tests."""
    p = _probe_or_404(probe_id)
    c = _probe_check_or_404(p, check_id, ("rtp",))
    range_key = request.args.get("range", "7d")
    if range_key not in BW_RANGES:
        range_key = "7d"
    since = repo.now() - BW_RANGES[range_key]
    runs = q("SELECT * FROM rtp_runs WHERE probe_id = ? AND check_id = ? AND ts >= ? ORDER BY ts DESC, id DESC "
             "LIMIT 5000", (probe_id, check_id, since))
    params = checktypes.merged("rtp", json.loads(c["params"] or "{}"))
    good = [r for r in runs if not r["error"] and r["mos"] is not None]
    stats = {}
    for key in ("mos", "rtt_ms", "jitter_ms", "loss_pct"):
        values = sorted(r[key] for r in good if r[key] is not None)
        if values:
            stats[key] = {"min": values[0], "max": values[-1], "avg": sum(values) / len(values),
                          "median": values[len(values) // 2]}
    stats["count"], stats["errors"] = len(good), len(runs) - len(good)
    stats["below"] = sum(1 for r in good if params["min_mos"] and r["mos"] < params["min_mos"])
    chart = {
        "mos": [[r["ts"] * 1000, r["mos"]] for r in reversed(good)],
        "min_mos": params["min_mos"] or 0, "start": since * 1000, "end": repo.now() * 1000,
        "reports": report_service.for_chart(since, repo.now(), probe_id),
    }
    pending = q1("SELECT id FROM probe_commands WHERE probe_id = ? AND check_id = ? AND delivered_at IS NULL",
                 (probe_id, check_id))
    return render_template("rtp.html", probe=p, check=c, runs=runs[:50], last=runs[0] if runs else None,
                           stats=stats, chart=chart, params=params, range_key=range_key, ranges=list(BW_RANGES),
                           pending=pending, summary=checktypes.summary(c, params), mos_label=rtp.mos_label,
                           codec=rtp.CODECS.get(params["codec"]))


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


# -- Störungsmeldungen --------------------------------------------------------
REPORTS_PER_PAGE = 50
REPORT_FILTERS = {"open": "offen", "done": "erledigt", "all": "alle"}


def report_graph_url(r: dict) -> str | None:
    """Graph um den Zeitpunkt der Meldung: Ziel-Seite des wichtigsten Ping-Checks der Probe.

    Reihenfolge: Internet-Referenz, Gateway, sonstiges Ziel – so sieht man sofort, ob die Leitung auffällig war.
    """
    from flask import g

    if not r.get("probe_id"):
        return None
    cache = g.setdefault("report_graph_checks", {})
    if r["probe_id"] not in cache:
        probe = q1("SELECT * FROM probes WHERE id = ?", (r["probe_id"],))
        pings = [c for c in repo.checks_for_probe(probe) if c["type"] == "ping"] if probe else []
        order = {"reference": 0, "gateway": 1, "target": 2}
        pings.sort(key=lambda c: (order.get(c["role"], 9), c["id"]))
        cache[r["probe_id"]] = pings[0]["id"] if pings else None
    check_id = cache[r["probe_id"]]
    if check_id is None:
        return url_for("web.probe", probe_id=r["probe_id"])
    return url_for("web.target", probe_id=r["probe_id"], check_id=check_id, at=r["occurred_at"])


def _int_param(name: str) -> int | None:
    try:
        return int(request.args.get(name, ""))
    except ValueError:
        return None


@bp.get("/meldungen")
@login_required()
def reports_view():
    status = request.args.get("status", "open")
    if status not in REPORT_FILTERS:
        status = "open"
    site_id = _int_param("site")
    probe_id = _int_param("probe")
    page = max(_int_param("page") or 1, 1)
    sel = None if status == "all" else status
    total = report_service.count(sel, site_id, probe_id)
    pages = max((total + REPORTS_PER_PAGE - 1) // REPORTS_PER_PAGE, 1)
    page = min(page, pages)
    items = report_service.search(sel, site_id, probe_id, limit=REPORTS_PER_PAGE, offset=(page - 1) * REPORTS_PER_PAGE)
    probe_filter = q1("SELECT id, hostname FROM probes WHERE id = ?", (probe_id,)) if probe_id else None
    args = {k: v for k, v in (("status", status), ("site", site_id), ("probe", probe_id)) if v is not None}
    return render_template(
        "reports.html", items=items, status=status, filters=REPORT_FILTERS, site_id=site_id, probe_id=probe_id,
        probe_filter=probe_filter, sites=q("SELECT * FROM sites ORDER BY name"), total=total, page=page, pages=pages,
        args=args,
    )


@bp.post("/meldungen/<int:report_id>/status")
@login_required("operator")
def report_status(report_id: int):
    r = report_service.get(report_id) or abort(404)
    action = request.form.get("action")
    if action not in ("done", "open"):
        abort(400, "Unbekannte Aktion.")
    user = current_user()["username"]
    note = request.form.get("note", "")
    report_service.set_status(r, action, user, note)
    what = f"{r['category_label']}, {r['probe_label']}, {fmt_dt(r['occurred_at'])}"
    if action == "done":
        repo.audit(user, "report.done", f"report:{report_id}", what + (f" – Notiz: {note.strip()[:500]}" if note.strip() else ""))
        flash(f"Meldung als erledigt markiert ({what}).", "ok")
    else:
        repo.audit(user, "report.reopen", f"report:{report_id}", what)
        flash(f"Meldung wieder geöffnet ({what}).", "ok")
    nxt = request.form.get("next", "")
    return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("web.reports_view"))


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
    _regen_rules()  # Offline-Alarm folgt dem Status
    flash("Probe deaktiviert – ihr Token wird abgelehnt." if new == "disabled" else "Probe aktiviert.", "ok")
    return redirect(url_for("web.probe", probe_id=probe_id))


@bp.post("/probes/<int:probe_id>/delete")
@login_required("admin")
def probe_delete(probe_id: int):
    p = q1("SELECT hostname FROM probes WHERE id = ?", (probe_id,)) or abort(404)
    ex("DELETE FROM check_assignments WHERE scope IN ('probe', 'exclude_probe') AND scope_id = ?", (probe_id,))
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
                           windows=vm.STAT_WINDOWS, **_chart_reports(probe_id))


def _chart_reports(probe_id: int) -> dict:
    """Zeitpunkt aus ?at= (Graph um eine Störungsmeldung herum), die Meldungen der Probe der letzten 30 Tage
    und die Alarmschwellen für die Legende."""
    now = repo.now()
    try:
        at = int(request.args.get("at", ""))
    except ValueError:
        at = None
    if at is not None and not now - 400 * 86400 <= at <= now + 300:
        at = None
    return {"at": at, "chart_reports": report_service.search(probe_id=probe_id, since=now - vm.RANGES["30d"],
                                                              limit=10),
            "thr": repo.graph_thresholds()}


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
    hours = min(max(request.form.get("hours", 4, type=int), 1), 168)
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
        url = (url_for("web.site", site_id=a["scope_id"]) if a["scope"] == "site" and a["scope_id"] in site_map
               else url_for("web.probe", probe_id=a["scope_id"])
               if a["scope"] in ("probe", "exclude_probe") and a["scope_id"] in probe_map
               else None)
        assignments[a["check_id"]].append((repo.scope_label(a["scope"], a["scope_id"], site_map, probe_map), url))
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
        scope_id = request.form.get("site_id", 0, type=int)
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


@bp.route("/admin/einrichtung", methods=["GET", "POST"])
@login_required("admin")
def setup_wizard():
    """Geführte Einrichtung: Standort, Messungen, Alarmierung und Setup für die PCs in einem Durchgang."""
    FieldError = checktypes.FieldError
    sites = q("SELECT * FROM sites ORDER BY name")
    public_url = current_app.config["PUBLIC_URL"]
    form = request.form if request.method == "POST" else {}
    current = notify.get_settings()
    errors: list = []
    if request.method == "POST":
        site_choice = form.get("site_id", "new")
        site_name = form.get("site_name", "").strip()
        site = None
        if site_choice == "new":
            if not site_name:
                errors.append(FieldError("Bitte einen Namen für den Standort angeben.", "site_name"))
            elif q1("SELECT id FROM sites WHERE name = ?", (site_name,)):
                errors.append(FieldError("Diesen Standort gibt es schon – bitte oben auswählen.", "site_name"))
        else:
            site = q1("SELECT * FROM sites WHERE id = ?", (int(site_choice) if site_choice.isdigit() else 0,))
            if site is None:
                errors.append(FieldError("Bitte einen Standort auswählen.", "site_id"))
        scope = form.get("scope", "all")
        if scope not in ("all", "site"):
            abort(400)
        values = {**current, **{k: form.get(k, "").strip() for k in ("email_to", "email_from", "smtp_smarthost",
                                                                       "teams_webhook_url")}}
        # Fehlertexte von notify.validate dem passenden Feld zuordnen (Anzeige am Feld)
        notify_field = {"E-Mail": "email_to", "SMTP": "smtp_smarthost", "Absender": "email_from", "Teams": "teams_webhook_url"}
        errors += [FieldError(e, next((f for k, f in notify_field.items() if e.startswith(k)), None))
                   for e in notify.validate(values)]
        try:
            max_uses = int(form.get("max_uses", ""))
            days = int(form.get("days", ""))
            if not (1 <= max_uses <= 500 and 1 <= days <= 90):
                raise ValueError
        except ValueError:
            errors.append(FieldError("PCs 1 bis 500, Gültigkeit 1 bis 90 Tage.", "max_uses"))
        proxy = form.get("proxy", "").strip()
        if proxy and not proxy.startswith(("http://", "https://")):
            errors.append(FieldError("Proxy bitte mit Schema angeben, z. B. http://proxy.kunde.local:3128.", "proxy"))
        if not errors:
            user = current_user()["username"]
            if site is None:
                sid = ins("INSERT INTO sites (name, customer_no, description, created_at) VALUES (?, ?, ?, ?)",
                          (site_name, form.get("customer_no", "").strip() or None, None, repo.now()))
                repo.audit(user, "site.create", site_name)
                site = q1("SELECT * FROM sites WHERE id = ?", (sid,))
            created, skipped = standardpaket.apply(form.getlist("items"), scope,
                                                   site["id"] if scope == "site" else None, public_url)
            for cid, item in created:
                repo.audit(user, "check.create", f"check:{cid}", f"Einrichtung: {item.name}")
            if created:
                _regen_rules()
            if any(values[k] != current.get(k, "") for k in notify.FIELDS):
                notify.save_settings(values)
                repo.audit(user, "notify.update", detail="Einrichtung")
                try:
                    notify.write_config()
                except OSError as exc:
                    log.error("Alertmanager-Konfiguration nicht geschrieben: %s", exc)
                    flash("Alarmierung gespeichert, aber die Alertmanager-Datei konnte nicht geschrieben werden.", "error")
            token = repo.create_enrollment_token(site["id"], max_uses, days, user,
                                                 form.get("description", "").strip() or "Geführte Einrichtung")
            flash(f"Standort {site['name']}: {len(created)} Messungen angelegt"
                  + (f", {len(skipped)} gab es schon" if skipped else "") + ". Jetzt das Setup herunterladen.", "ok")
            setup = repo.probe_setup_file(current_app.config["PROBE_DIR"])
            return render_template(
                "token_created.html", token=token, site=site, days=days, max_uses=max_uses, proxy=proxy,
                server_url=public_url, server_urls=repo.server_urls(), pin=current_app.config["SPKI_PIN"],
                setup_name=setup.name if setup else None,
            )
    return render_template(
        "einrichtung.html", sites=sites, form=form, notify_settings=current, errors=errors,
        field_errors={e.field: e for e in reversed(errors) if getattr(e, "field", None)},
        package=standardpaket.preview(public_url), check_types=checktypes.TYPES,
        rules=[r for r in repo.alert_rules().values() if r["enabled"]],
        probe_setup=repo.probe_setup_file(current_app.config["PROBE_DIR"]),
    )


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
    site_id = request.form.get("site_id", 0, type=int)
    s = q1("SELECT * FROM sites WHERE id = ?", (site_id,))
    if s is None:
        flash("Bitte zuerst einen Standort anlegen und auswählen.", "error")
        return redirect(url_for("web.admin") + "#enrollment")
    proxy = request.form.get("proxy", "").strip()
    if proxy and not proxy.startswith(("http://", "https://")):
        # vor dem Anlegen prüfen: sonst entsteht ein verwaister Token und eine Fehlerseite ohne Rückweg
        flash("Proxy bitte mit Schema angeben, z. B. http://proxy.kunde.local:3128", "error")
        return redirect(url_for("web.admin") + "#enrollment")
    days = min(max(request.form.get("days", 7, type=int), 1), 90)
    max_uses = min(max(request.form.get("max_uses", 1, type=int), 1), 500)
    token = repo.create_enrollment_token(site_id, max_uses, days, current_user()["username"],
                                         request.form.get("description", ""))
    if request.form.get("action") == "setup":
        # direkt das vorbelegte Setup – auf dem PC nur noch „Installieren“
        return _prefilled_setup_response(token, s, proxy)
    setup = repo.probe_setup_file(current_app.config["PROBE_DIR"])
    return render_template(
        "token_created.html", token=token, site=s, days=days, max_uses=max_uses,
        server_url=current_app.config["PUBLIC_URL"], server_urls=repo.server_urls(),
        pin=current_app.config["SPKI_PIN"], setup_name=setup.name if setup else None,
    )


def _prefilled_setup_response(token: str, site: dict, proxy: str):
    """Setup-Datei mit eingebauter Vorbelegung (alle Server-Adressen, Pin, Token, Proxy) als Download."""
    from flask import Response

    from . import setupfile

    setup = repo.probe_setup_file(current_app.config["PROBE_DIR"])
    if setup is None:
        abort(404, "Kein Setup auf dem Server hinterlegt.")
    if proxy and not proxy.startswith(("http://", "https://")):
        abort(400, "Proxy bitte mit Schema angeben, z. B. http://proxy.kunde.local:3128")
    try:
        block = setupfile.config_block(repo.server_urls(), current_app.config["SPKI_PIN"], token, site["name"], proxy)
    except ValueError as exc:
        abort(400, str(exc))
    stream, length = setupfile.prefilled(setup, block)
    repo.audit(current_user()["username"], "token.setup", f"site:{site['id']}", setup.name)
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in setupfile.ascii_text(site["name"]))[:40] or "Probe"
    return Response(stream, mimetype="application/vnd.microsoft.portable-executable", headers={
        "Content-Disposition": f'attachment; filename="WachtlSetup-{safe}.exe"',
        "Content-Length": str(length),
        "Cache-Control": "no-store",
    })


@bp.post("/admin/tokens/setup")
@login_required("admin")
def token_setup():
    """Vorbelegtes Setup für einen eben erzeugten Token (Seite „Enrollment-Token“)."""
    token = request.form.get("token", "").strip()
    row = q1("SELECT t.*, s.name AS site_name FROM enrollment_tokens t JOIN sites s ON s.id = t.site_id "
             "WHERE t.token_hash = ?", (hash_token(token),)) if token else None
    if row is None or row["revoked"] or row["expires_at"] < repo.now():
        abort(400, "Token unbekannt, widerrufen oder abgelaufen.")
    return _prefilled_setup_response(token, {"id": row["site_id"], "name": row["site_name"]},
                                     request.form.get("proxy", "").strip())


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
    ini = repo.probe_ini(",".join(repo.server_urls()), current_app.config["SPKI_PIN"], token,
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
        assignment = q1("SELECT scope, scope_id FROM check_assignments WHERE check_id = ? AND scope <> 'exclude_probe' "
                        "ORDER BY id LIMIT 1",
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
        timeout = checktypes.timeout_ms(ctype, params)
        if ctype in checktypes.PEER_TYPES and params["peer"] == "probe" and scope == "probe" \
                and scope_id == params["peer_probe_id"]:
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
    flash(f"Check {c['name']}: {'Aus' if c['enabled'] else 'Ein'}.", "ok")
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


@bp.post("/admin/users/<int:user_id>/password")
@login_required("admin")
def user_password(user_id: int):
    u = q1("SELECT username FROM users WHERE id = ?", (user_id,)) or abort(404)
    password = request.form.get("password", "")
    if problem := password_problem(password):
        flash(problem, "error")
    else:
        # neues Passwort hebt auch eine Sperre nach Fehlversuchen auf
        ex("UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL WHERE id = ?",
           (hash_password(password), user_id))
        repo.audit(current_user()["username"], "user.password_reset", u["username"])
        flash(f"Passwort für {u['username']} zurückgesetzt. Bitte das neue Passwort sicher weitergeben.", "ok")
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
    rows = q("SELECT * FROM audit_log ORDER BY ts DESC LIMIT 500")
    # Objekte wie "probe:5" auf ihre Seite verlinken, solange es sie noch gibt
    exists = {kind: {r["id"] for r in q(f"SELECT id FROM {table}")}
              for kind, table in (("site", "sites"), ("probe", "probes"), ("check", "checks"))}
    report_probe = {r["id"]: r["probe_id"] for r in q("SELECT id, probe_id FROM incident_reports")}
    links = {}
    for r in rows:
        kind, _, ident = (r["object"] or "").partition(":")
        if not ident.isdigit():
            continue
        i = int(ident)
        if kind == "site" and i in exists["site"]:
            links[r["object"]] = url_for("web.site", site_id=i)
        elif kind == "probe" and i in exists["probe"]:
            links[r["object"]] = url_for("web.probe", probe_id=i)
        elif kind == "check" and i in exists["check"]:
            links[r["object"]] = url_for("web.check_edit", check_id=i)
        elif kind == "report" and i in report_probe:
            links[r["object"]] = url_for("web.reports_view", status="all", probe=report_probe[i])
    return render_template("audit.html", rows=rows, links=links)


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
