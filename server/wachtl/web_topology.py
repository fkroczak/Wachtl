"""Web-UI der Switch-Topologie (docs/TOPOLOGIE.md): Baum, Switches, Switch-Detail, Probleme, Pfad, Assistent."""
from __future__ import annotations

import json
import logging

from flask import abort, flash, redirect, render_template, request, url_for

from . import repo, secretbox
from .db import ex, ins, q, q1
from .security import current_user, login_required
from .services import topology as topo_service
from .web import SITE_TABS, _live, bp

log = logging.getLogger(__name__)
VIEWS = {"baum": "Baum", "switche": "Switches", "probleme": "Probleme", "pfad": "Pfad suchen"}


def _site(site_id: int) -> dict:
    return q1("SELECT * FROM sites WHERE id = ?", (site_id,)) or abort(404)


def _switch(site_id: int, switch_id: int) -> dict:
    return q1("SELECT * FROM net_switches WHERE id = ? AND site_id = ?", (switch_id, site_id)) or abort(404)


def _poller() -> dict:
    """Zustand der Server-Probe, die die Switches abfragt."""
    p = q1("SELECT * FROM probes WHERE kind = 'server' ORDER BY id LIMIT 1")
    return {"probe": p, "online": bool(p and p["status"] == "active" and repo.probe_online(p))}


def _web_links(site_id: int, host: str) -> dict:
    """Weboberfläche und SSH des Switches: aus dem Netzwerkscan, sonst https://Adresse/."""
    from .services import netscan

    out = {"web": f"https://{host}/", "ssh": None}
    dev = q1("SELECT id, ip FROM net_devices WHERE site_id = ? AND ip = ? ORDER BY last_seen DESC LIMIT 1",
             (site_id, host))
    if dev:
        svcs = {s["service"]: s for s in q("SELECT * FROM net_services WHERE device_id = ?", (dev["id"],))}
        for kind in ("https", "http"):
            if kind in svcs:
                out["web"] = netscan.link_for(kind, host, svcs[kind]["port"])["url"]
                break
        if "ssh" in svcs:
            out["ssh"] = netscan.link_for("ssh", host, svcs["ssh"]["port"])["url"]
    return out


def _common(site: dict, view: str, topo=None) -> dict:
    counts = q1("SELECT COUNT(*) AS n FROM net_topo_findings WHERE site_id = ? AND active = TRUE AND ack_at IS NULL "
                "AND severity <> 'info'", (site["id"],))
    drafts = q("SELECT * FROM net_switches WHERE site_id = ? AND status = 'draft' ORDER BY id", (site["id"],))
    return {"site": site, "tabs": SITE_TABS, "tab": "topologie", "view": view, "views": VIEWS,
            "problem_count": int(counts["n"] or 0), "poller": _poller(), "drafts": drafts,
            "speed_text": topo_service.speed_text, "speed_short": topo_service.speed_short,
            "speed_class": topo_service.speed_class, "link_label": topo_service.link_label, "topo": topo}


@bp.get("/sites/<int:site_id>/topologie")
@login_required()
def topology(site_id: int):
    """Baum: Internet → Gateway → Switches → Geräte; rechts der gewählte Switch."""
    site = _site(site_id)
    topo = topo_service.build(site_id)
    if not topo.switches:
        return render_template("topology.html", lay=None, selected=None, **_common(site, "baum", topo))
    sel_id = request.args.get("switch", type=int)
    if sel_id not in topo.switches:
        sel_id = _first_switch(topo)
    selected = _switch_panel(site_id, topo, sel_id)
    lay = topo_service.layout(topo, show_devices=request.args.get("geraete", "1") != "0")
    return render_template("topology.html", lay=lay, selected=selected, show_devices=request.args.get("geraete", "1") != "0",
                           **_common(site, "baum", topo))


def _first_switch(topo) -> int:
    """Oberster Switch im Baum (meist der Core) – vorausgewählt im Seitenbereich."""
    stack = list(reversed(topo.roots))
    while stack:
        node = topo.nodes[stack.pop()]
        if node.switch_id is not None:
            return node.switch_id
        stack.extend(reversed(node.children))
    return next(iter(topo.switches))


def _switch_panel(site_id: int, topo, switch_id: int) -> dict:
    s = topo.switches[switch_id]
    node = topo.nodes[s["node"]]
    neighbors = []
    for p in sorted(s["ports"].values(), key=lambda p: p.index):
        if p.link:
            other = p.link.b if p.link.a == node.id else p.link.a
            neighbors.append({"port": p, "node": topo.nodes[other]})
    used = sum(1 for p in s["ports"].values() if p.physical and p.up)
    total = sum(1 for p in s["ports"].values() if p.physical)
    return {"row": s["row"], "node": node, "snap": s["snapshot"], "neighbors": neighbors, "used": used, "total": total,
            "ports": topo_service.faceplate(s["ports"]), "links": _web_links(site_id, s["row"]["host"]),
            "parent": topo.nodes.get(node.parent) if node.parent else None,
            "uplink": topo_service.link_label(topo, node) if node.parent else ""}


@bp.get("/sites/<int:site_id>/topologie/switche")
@login_required()
def topology_switches(site_id: int):
    """Switch-Karten: je Switch Uplink, Belegung, PoE, Aufschalten."""
    site = _site(site_id)
    topo = topo_service.build(site_id)
    cards = [_switch_panel(site_id, topo, sid) for sid in sorted(topo.switches, key=lambda i: topo.nodes[topo.switches[i]["node"]].label.lower())]
    unmanaged = [n for n in topo.nodes.values() if n.kind in ("unmanaged", "neighbor")]
    return render_template("topo_switches.html", cards=cards, unmanaged=unmanaged, **_common(site, "switche", topo))


@bp.get("/sites/<int:site_id>/topologie/switche/<int:switch_id>")
@login_required()
def topology_switch(site_id: int, switch_id: int):
    """Switch aufgeschaltet: Frontansicht, gewählter Port, Wachtl-Messung am Port, alle Ports."""
    site = _site(site_id)
    row = _switch(site_id, switch_id)
    if row["status"] == "draft":
        return redirect(url_for("web.topology_check", site_id=site_id, switch_id=switch_id))
    topo = topo_service.build(site_id)
    panel = _switch_panel(site_id, topo, switch_id)
    ports = topo.switches[switch_id]["ports"]
    sel = request.args.get("port", type=int)
    if sel not in ports:
        sel = next((p.index for p in sorted(ports.values(), key=lambda p: (-p.errors_24h, p.role != "access", p.index))
                    if p.physical and p.up), next(iter(ports), None))
    port = ports.get(sel)
    path = []
    node = panel["node"]
    while node.parent:
        node = topo.nodes[node.parent]
        path.insert(0, node)
    measure = _port_measurement(site_id, port) if port else None
    errors = q("SELECT if_index, ts, errors FROM net_port_errors WHERE switch_id = ? AND ts >= ? ORDER BY ts DESC LIMIT 20",
               (switch_id, repo.now() - 7 * 86400)) if port else []
    events = q("SELECT * FROM net_topo_events WHERE switch_id = ? ORDER BY ts DESC LIMIT 20", (switch_id,))
    creds = None
    try:
        creds = topo_service.credential_hint(secretbox.unseal(row["secret"]))
    except secretbox.SecretError as exc:
        creds = str(exc)
    return render_template("topo_switch.html", sw=panel, port=port, path=path, measure=measure, events=events,
                           port_errors=[e for e in errors if port and e["if_index"] == port.index], creds=creds,
                           all_ports=sorted(ports.values(), key=lambda p: (not p.physical, p.index)),
                           **_common(site, "switche", topo))


def _port_measurement(site_id: int, port) -> dict | None:
    """Läuft auf einem Gerät an diesem Port eine Wachtl-Probe? Dann ihre Messwerte zeigen."""
    from .services import checkstatus

    probes = q("SELECT p.*, s.name AS site_name FROM probes p JOIN sites s ON s.id = p.site_id WHERE p.site_id = ? "
               "AND p.status = 'active'", (site_id,))
    for d in port.devices:
        for p in probes:
            addrs = set(json.loads(p.get("addresses") or "[]")) | {p.get("last_ip")}
            name = (d.get("hostname") or "").split(".")[0].lower()
            if (d.get("ip") and d["ip"] in addrs) or (name and name == p["hostname"].lower()):
                live, _ok = _live()
                states = checkstatus.overview([p], live).get(p["id"], [])
                return {"probe": p, "device": d, "states": [st for st in states if st.kind in ("ping", "path")][:6]}
    return None


@bp.get("/sites/<int:site_id>/topologie/probleme")
@login_required()
def topology_problems(site_id: int):
    """Probleme: Baum mit nummerierten Markierungen und Liste der Befunde."""
    site = _site(site_id)
    topo = topo_service.build(site_id)
    items = topo_service.stored_findings(site_id, topo)
    lay = topo_service.layout(topo, show_devices=False) if topo.switches else None
    return render_template("topo_problems.html", items=items, lay=lay, **_common(site, "probleme", topo))


@bp.post("/sites/<int:site_id>/topologie/probleme/<int:finding_id>/bekannt")
@login_required("operator")
def topology_ack(site_id: int, finding_id: int):
    f = q1("SELECT * FROM net_topo_findings WHERE id = ? AND site_id = ?", (finding_id, site_id)) or abort(404)
    user = current_user()["username"]
    if f["ack_at"]:
        ex("UPDATE net_topo_findings SET ack_by = NULL, ack_at = NULL WHERE id = ?", (finding_id,))
        flash("Wieder als offen markiert.", "ok")
    else:
        ex("UPDATE net_topo_findings SET ack_by = ?, ack_at = ? WHERE id = ?", (user, repo.now(), finding_id))
        flash("Als bekannt markiert – erscheint wieder, sobald der Befund verschwindet und neu auftritt.", "ok")
    repo.audit(user, "topology.ack", f"finding:{finding_id}", f["title"])
    return redirect(url_for("web.topology_problems", site_id=site_id))


@bp.get("/sites/<int:site_id>/topologie/pfad")
@login_required()
def topology_path(site_id: int):
    """Pfad eines Geräts bis ins Internet mit Ports, Geschwindigkeiten und Fehlern."""
    site = _site(site_id)
    topo = topo_service.build(site_id)
    query = (request.args.get("geraet") or "").strip()[:100]
    hits = topo_service.find_device(topo, query) if query else []
    mac = request.args.get("mac") or (hits[0]["mac"] if len(hits) == 1 or (hits and query.lower() in (
        (hits[0].get("label") or "").lower(), hits[0].get("ip") or "", hits[0]["mac"].lower())) else None)
    path = topo_service.path_for(topo, mac) if mac else None
    measure = events = None
    if path:
        sid, pidx = topo.locations[mac]
        measure = _port_measurement(site_id, topo.switches[sid]["ports"][pidx])
        ids = [h["switch_id"] for h in path["hops"] if h.get("switch_id")]
        marks = ",".join("?" * len(ids))
        events = q(f"SELECT e.*, w.name, w.sys_name, w.host FROM net_topo_events e JOIN net_switches w ON w.id = e.switch_id "
                   f"WHERE e.switch_id IN ({marks}) AND (e.mac = ? OR e.kind <> 'mac_moved') ORDER BY e.ts DESC LIMIT 15",
                   ids + [mac]) if ids else []
    return render_template("topo_path.html", query=query, hits=hits, path=path, mac=mac, measure=measure,
                           events=events or [], **_common(site, "pfad", topo))


# -- Assistent: Switch mit Zugangsdaten anlegen ---------------------------------------------
def _suggestions(site_id: int, topo) -> list[dict]:
    """Vorschläge: per LLDP/CDP gefundene Switches ohne Zugangsdaten."""
    known = {r["host"] for r in q("SELECT host FROM net_switches WHERE site_id = ?", (site_id,))}
    out = []
    for n in topo.nodes.values():
        if n.kind == "neighbor" and n.ip and n.ip not in known:
            out.append({"host": n.ip, "name": n.label, "why": "per LLDP/CDP gefunden"})
    return out[:12]


def _wizard(site: dict, sw: dict | None, form: dict, errors: list, status: int = 200):
    from flask import render_template as rt

    topo = topo_service.build(site["id"])
    others = q("SELECT id, name, sys_name, host, snmp_version FROM net_switches WHERE site_id IN "
               "(SELECT id FROM sites) AND id <> ? ORDER BY site_id = ? DESC, name", (sw["id"] if sw else 0, site["id"]))
    existing = {}
    if sw:
        try:
            existing = secretbox.unseal(sw["secret"])
        except secretbox.SecretError:
            existing = {}
    return rt("topo_wizard.html", sw=sw, form=form, errors=errors, field_errors={e.field: e for e in errors if e.field},
              existing=existing, others=others, suggestions=_suggestions(site["id"], topo),
              SNMP_VERSIONS=topo_service.SNMP_VERSIONS, SEC_LEVELS=topo_service.SEC_LEVELS,
              AUTH_CHOICES=topo_service.AUTH_CHOICES, PRIV_CHOICES=topo_service.PRIV_CHOICES,
              sec_level=topo_service.sec_level, **_common(site, "switche")), status


@bp.route("/sites/<int:site_id>/topologie/switche/neu", methods=["GET", "POST"])
@login_required("admin")
def topology_new(site_id: int):
    """Assistent Schritt 1 und 2: Adresse und Zugangsdaten."""
    site = _site(site_id)
    if request.method == "GET":
        form = {"host": request.args.get("host", "")[:253], "name": request.args.get("name", "")[:80],
                "snmp_version": "2c", "copy_from": request.args.get("wie", "")}
        return _wizard(site, None, form, [])
    return _save_wizard(site, None)


@bp.route("/sites/<int:site_id>/topologie/switche/<int:switch_id>/zugang", methods=["GET", "POST"])
@login_required("admin")
def topology_edit(site_id: int, switch_id: int):
    site = _site(site_id)
    sw = _switch(site_id, switch_id)
    if request.method == "GET":
        try:
            creds = secretbox.unseal(sw["secret"])
        except secretbox.SecretError:
            creds = {"version": sw["snmp_version"]}
        form = {"host": sw["host"], "name": sw["name"] or "", "location": sw["location"] or "", "port": sw["port"],
                "snmp_version": creds.get("version", "2c"), "user": creds.get("user", ""),
                "sec_level": topo_service.sec_level(creds), "auth_proto": creds.get("auth_proto", "sha"),
                "priv_proto": creds.get("priv_proto", "aes"), "context": creds.get("context", "")}
        return _wizard(site, sw, form, [])
    return _save_wizard(site, sw)


def _save_wizard(site: dict, sw: dict | None):
    from .checktypes import FieldError, valid_host

    form = request.form
    errors: list = []
    host = (form.get("host") or "").strip()
    if not host or len(host) > 253 or not valid_host(host):
        errors.append(FieldError("Adresse: IP-Adresse oder Hostname des Switches eintragen.", "host"))
    try:
        port = int(form.get("port") or 161)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        errors.append(FieldError("UDP-Port: Zahl zwischen 1 und 65535 (Standard 161).", "port"))
        port = 161
    name = (form.get("name") or "").strip()[:80] or None
    location = (form.get("location") or "").strip()[:80] or None
    existing = {}
    if sw:
        try:
            existing = secretbox.unseal(sw["secret"])
        except secretbox.SecretError:
            existing = {}
    copy_id = form.get("copy_from", type=int)
    if copy_id:
        src = q1("SELECT * FROM net_switches WHERE id = ?", (copy_id,))
        try:
            creds = secretbox.unseal(src["secret"]) if src else None
        except secretbox.SecretError:
            creds = None
        if creds is None:
            errors.append(FieldError("Zugangsdaten übernehmen: der gewählte Switch hat keine lesbaren Zugangsdaten.",
                                     "copy_from"))
            creds = {"version": "2c"}
    else:
        creds, cred_errors = topo_service.parse_credentials(form, existing)
        errors += cred_errors
    dup = q1("SELECT id FROM net_switches WHERE site_id = ? AND host = ? AND port = ? AND id <> ?",
             (site["id"], host, port, sw["id"] if sw else 0))
    if dup:
        errors.append(FieldError("Adresse: dieser Switch ist an diesem Standort schon eingetragen.", "host"))
    if errors:
        return _wizard(site, sw, dict(form), errors, 422)
    ts = repo.now()
    secret = secretbox.seal(creds)
    user = current_user()["username"]
    if sw:
        ex("UPDATE net_switches SET host = ?, port = ?, name = ?, location = ?, snmp_version = ?, secret = ?, "
           "updated_at = ? WHERE id = ?", (host, port, name, location, creds["version"], secret, ts, sw["id"]))
        switch_id = sw["id"]
        repo.audit(user, "topology.switch_update", f"switch:{switch_id}", f"{host}, {topo_service.credential_hint(creds)}")
    else:
        switch_id = ins("INSERT INTO net_switches (site_id, name, host, port, snmp_version, secret, location, status, "
                        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)",
                        (site["id"], name, host, port, creds["version"], secret, location, ts, ts))
        repo.audit(user, "topology.switch_create", f"switch:{switch_id}", f"{host}, {topo_service.credential_hint(creds)}")
    return redirect(url_for("web.topology_check", site_id=site["id"], switch_id=switch_id))


@bp.get("/sites/<int:site_id>/topologie/switche/<int:switch_id>/pruefen")
@login_required("admin")
def topology_check(site_id: int, switch_id: int):
    """Assistent Schritt 3: Verbindung vom Wachtl-Server aus testen und Ergebnis zeigen."""
    from . import snmp, snmpcollect

    site = _site(site_id)
    sw = _switch(site_id, switch_id)
    result, error = None, None
    try:
        with snmp.Session(sw["host"], topo_service.credentials(sw), port=sw["port"], timeout=2.0, retries=1) as sess:
            snapshot = topo_service.clean_snapshot(snmpcollect.collect(sess))
        result = snmpcollect.summary(snapshot)
        topo_service.store_result(sw, snapshot, None, repo.now())
    except (snmp.SnmpError, secretbox.SecretError) as exc:
        error = str(exc)
        if sw["status"] != "draft":
            topo_service.store_result(sw, None, error, repo.now())
    except Exception:  # noqa: BLE001 – unerwartete Antwort des Switches: im Assistenten melden, nicht abstürzen
        log.exception("Switch %s: Test fehlgeschlagen", sw["host"])
        error = "Unerwartete Antwort des Switches – Details stehen im Server-Log."
    repo.audit(current_user()["username"], "topology.switch_test", f"switch:{switch_id}", error or "erfolgreich")
    sw = _switch(site_id, switch_id)
    try:
        hint = topo_service.credential_hint(secretbox.unseal(sw["secret"]))
    except secretbox.SecretError:
        hint = "–"
    return render_template("topo_check.html", sw=sw, result=result, error=error, hint=hint, **_common(site, "switche"))


@bp.post("/sites/<int:site_id>/topologie/switche/<int:switch_id>/aktivieren")
@login_required("admin")
def topology_activate(site_id: int, switch_id: int):
    sw = _switch(site_id, switch_id)
    ex("UPDATE net_switches SET status = 'active', poll_requested = ?, updated_at = ? WHERE id = ?",
       (repo.now(), repo.now(), switch_id))
    repo.audit(current_user()["username"], "topology.switch_activate", f"switch:{switch_id}", sw["host"])
    topo_service.refresh_findings(site_id, repo.now())
    flash(f"{topo_service.switch_label(sw)} wird jetzt alle {topo_service.POLL_MIN} Minuten abgefragt.", "ok")
    if request.form.get("next") == "neu":
        return redirect(url_for("web.topology_new", site_id=site_id, wie=switch_id))
    return redirect(url_for("web.topology_switch", site_id=site_id, switch_id=switch_id))


@bp.post("/sites/<int:site_id>/topologie/switche/<int:switch_id>/abfragen")
@login_required("operator")
def topology_poll(site_id: int, switch_id: int):
    sw = _switch(site_id, switch_id)
    ex("UPDATE net_switches SET poll_requested = ? WHERE id = ?", (repo.now(), switch_id))
    poller = _poller()
    flash(f"Abfrage von {topo_service.switch_label(sw)} beauftragt – das Ergebnis kommt in etwa 30 Sekunden."
          if poller["online"] else "Abfrage beauftragt. Die Server-Probe ist gerade nicht erreichbar; sie fragt ab, "
          "sobald sie wieder läuft.", "ok")
    return redirect(request.form.get("next") or url_for("web.topology_switch", site_id=site_id, switch_id=switch_id))


@bp.post("/sites/<int:site_id>/topologie/switche/<int:switch_id>/status")
@login_required("admin")
def topology_status(site_id: int, switch_id: int):
    sw = _switch(site_id, switch_id)
    new = "disabled" if sw["status"] == "active" else "active"
    ex("UPDATE net_switches SET status = ?, updated_at = ? WHERE id = ?", (new, repo.now(), switch_id))
    repo.audit(current_user()["username"], f"topology.switch_{new}", f"switch:{switch_id}", sw["host"])
    topo_service.refresh_findings(site_id, repo.now())
    flash("Abfrage pausiert." if new == "disabled" else "Abfrage wieder aktiv.", "ok")
    return redirect(url_for("web.topology_switch", site_id=site_id, switch_id=switch_id))


@bp.post("/sites/<int:site_id>/topologie/switche/<int:switch_id>/loeschen")
@login_required("admin")
def topology_delete(site_id: int, switch_id: int):
    sw = _switch(site_id, switch_id)
    ex("DELETE FROM net_switches WHERE id = ?", (switch_id,))
    ex("DELETE FROM net_topo_findings WHERE site_id = ? AND switch_id = ?", (site_id, switch_id))
    repo.audit(current_user()["username"], "topology.switch_delete", f"switch:{switch_id}", sw["host"])
    topo_service.refresh_findings(site_id, repo.now())
    flash(f"{topo_service.switch_label(sw)} und seine Zugangsdaten wurden gelöscht.", "ok")
    return redirect(url_for("web.topology_switches", site_id=site_id))
