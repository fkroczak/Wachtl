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
from .services import alertgen
from .services import alerts as alert_service
from .services import notify, vm

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
    }


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


@bp.app_template_filter("ms")
def fmt_ms(v):
    return "–" if v is None else (f"{v:.2f} ms" if v < 10 else f"{v:.1f} ms")


@bp.app_template_filter("pct")
def fmt_pct(v):
    return "–" if v is None else f"{v:.1f} %"


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
    per_probe: dict[str, dict[str, int]] = defaultdict(lambda: {"ok": 0, "warn": 0, "down": 0, "unknown": 0})
    for (probe_id, _check), v in live.items():
        per_probe[probe_id][_cell_state(v)] += 1
    site_stats = {s["id"]: {"probes": 0, "online": 0} for s in sites}
    for p in probes:
        site_stats[p["site_id"]]["probes"] += 1
        if repo.probe_online(p) and p["status"] == "active":
            site_stats[p["site_id"]]["online"] += 1
    alerts = q("SELECT * FROM alert_events WHERE status = 'firing' ORDER BY starts_at DESC LIMIT 50")
    return render_template(
        "overview.html", sites=sites, probes=probes, per_probe=per_probe, site_stats=site_stats,
        alerts=alerts, live_ok=live_ok,
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
    checks_by_probe = {p["id"]: {c["id"]: c for c in repo.checks_for_probe(p)} for p in probes}
    all_checks: dict[int, dict] = {}
    for cmap in checks_by_probe.values():
        all_checks.update(cmap)
    live, live_ok = _live()
    matrix = {
        (c_id, p["id"]): live.get((str(p["id"]), str(c_id)))
        for c_id in all_checks for p in probes if c_id in checks_by_probe[p["id"]]
    }
    return render_template(
        "site.html", site=s, probes=probes, checks=sorted(all_checks.values(), key=lambda c: c["id"]),
        matrix=matrix, cell_state=_cell_state, live_ok=live_ok,
    )


@bp.get("/probes/<int:probe_id>")
@login_required()
def probe(probe_id: int):
    p = q1(
        "SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.id = ?", (probe_id,)
    ) or abort(404)
    checks = repo.checks_for_probe(p)
    live, live_ok = _live()
    rows = [(c, live.get((str(p["id"]), str(c["id"])))) for c in checks]
    alerts = [
        a for a in q("SELECT * FROM alert_events ORDER BY starts_at DESC LIMIT 500")
        if json.loads(a["labels"]).get("probe") == str(probe_id)
    ][:20]
    return render_template("probe.html", probe=p, rows=rows, cell_state=_cell_state, live_ok=live_ok, alerts=alerts)


@bp.post("/probes/<int:probe_id>/status")
@login_required("admin")
def probe_status(probe_id: int):
    new = "disabled" if request.form.get("action") == "disable" else "active"
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
    return render_template("target.html", probe=p, check=c, ranges=list(vm.RANGES), windows=vm.STAT_WINDOWS)


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
        "WHERE t.revoked = FALSE AND t.expires_at > ? AND t.uses < t.max_uses ORDER BY t.created_at DESC",
        (repo.now(),),
    )
    return render_template(
        "admin.html", sites=sites, probes=probes, checks=checks, assignments=assignments, tokens=tokens,
        rules=list(repo.alert_rules().values()), users=q("SELECT * FROM users ORDER BY username"),
        intervals=repo.ALLOWED_INTERVALS, roles=ROLES, notify_settings=notify.get_settings(),
        probe_setup=repo.probe_setup_file(current_app.config["PROBE_DIR"]),
        notify_enabled=bool(current_app.config.get("AM_CONFIG")),
    )


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


@bp.post("/admin/checks")
@login_required("admin")
def check_create():
    f = request.form
    name, target, role = f.get("name", "").strip(), f.get("target", "").strip(), f.get("role", "target")
    try:
        interval = int(f.get("interval_s", 1))
        timeout = int(f.get("timeout_ms", 1000))
    except ValueError:
        interval, timeout = -1, -1
    scope = f.get("scope", "all")
    scope_id = None
    if scope == "site":
        scope_id = int(f.get("site_id", 0) or 0)
    elif scope == "probe":
        scope_id = int(f.get("probe_id", 0) or 0)
    errors = []
    if not name:
        errors.append("Name fehlt.")
    if not repo.valid_target(target):
        errors.append("Ziel ist keine gültige IP-Adresse, kein Hostname und nicht 'gateway'.")
    if role not in repo.CHECK_ROLES:
        errors.append("Ungültige Rolle.")
    if interval not in repo.ALLOWED_INTERVALS:
        errors.append("Ungültiges Intervall.")
    if not 100 <= timeout <= 5000:
        errors.append("Timeout muss zwischen 100 und 5000 ms liegen.")
    if scope not in ("all", "site", "probe") or (scope != "all" and not scope_id):
        errors.append("Zuweisung unvollständig.")
    if errors:
        for e in errors:
            flash(e, "error")
    else:
        cid = repo.create_check(name, target, role, interval, timeout, scope, scope_id)
        repo.audit(current_user()["username"], "check.create", f"check:{cid}", f"{target} alle {interval} s")
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
