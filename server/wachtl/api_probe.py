"""Probe-API: Enrollment, Konfiguration, Messwerte, Heartbeat."""
from __future__ import annotations

import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import random
import re
import zlib

from flask import Blueprint, abort, current_app, g, jsonify, request

from . import repo
from . import findings as finding_service
from . import reports as report_service
from .db import ex, ins, q1
from .security import hash_token, new_secret, probe_auth
from .services import alertgen
from .services import alerts as alert_service
from .services import disturbances as disturbance_service
from .services import notices as notice_service
from .services import ingest, vm

log = logging.getLogger(__name__)
bp = Blueprint("api_probe", __name__, url_prefix="/api/probe/v1")
BATCH_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _client_ip() -> str:
    # Hinter Traefik (Docker) steht die echte Adresse in X-Forwarded-For; unter Windows
    # nimmt der Collector die Verbindungen selbst an und ignoriert den Header.
    if current_app.config["TRUST_PROXY"]:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def _read_body() -> str:
    raw = request.get_data(cache=False)
    if request.headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(raw, current_app.config["MAX_INGEST_BYTES"])
            if d.unconsumed_tail:
                abort(413, "Batch zu groß")
        except (zlib.error, gzip.BadGzipFile):
            abort(400, "gzip-Daten ungültig")
    return raw.decode("utf-8", errors="replace")


def _regen_rules() -> None:
    """Alarmregeln neu schreiben (Offline-Alarm nur für aktive Probes); ein Fehler bricht die Anfrage nie ab."""
    try:
        alertgen.write_rules()
    except Exception:  # noqa: BLE001 – Registrierung/Abmeldung darf daran nicht scheitern
        log.exception("Alarmregeln konnten nicht neu geschrieben werden")


@bp.post("/enroll")
def enroll():
    data = request.get_json(silent=True) or {}
    token = str(data.get("enrollment_token", ""))
    hostname = str(data.get("hostname", "")).strip()
    if not token or not repo.valid_probe_hostname(hostname):
        return jsonify(error="enrollment_token und gültiger hostname erforderlich"), 400
    ts = repo.now()
    et = q1("SELECT * FROM enrollment_tokens WHERE token_hash = ?", (hash_token(token),))
    if et is None or et["revoked"] or et["expires_at"] < ts or et["uses"] >= et["max_uses"]:
        log.warning("Enrollment abgelehnt für %s von %s", hostname, _client_ip())
        return jsonify(error="Enrollment-Token ungültig, abgelaufen oder verbraucht"), 403

    site = q1("SELECT * FROM sites WHERE id = ?", (et["site_id"],))
    secret = new_secret()
    existing = q1("SELECT id, status, deregistered_at FROM probes WHERE site_id = ? AND hostname = ?",
                  (site["id"], hostname))
    if existing and existing["status"] == "disabled" and not existing["deregistered_at"]:
        # vom Admin deaktiviert: Token bleibt abgelehnt, auch bei Neuinstallation (sonst hebt jeder Token-Inhaber
        # die Sperre auf). Nach Deinstallation (deregistered_at) ist Neuinstallation erlaubt.
        log.warning("Enrollment abgelehnt für deaktivierte Probe %s von %s", hostname, _client_ip())
        return jsonify(error="Probe ist im Web-UI deaktiviert – dort zuerst aktivieren, dann neu installieren"), 403
    if existing:
        probe_id = existing["id"]
        action = "probe.reenroll"
        regen = existing["status"] != "active"   # deinstallierte Probe kommt zurück: Offline-Alarm wieder an
    else:
        probe_id = ins(
            "INSERT INTO probes (site_id, hostname, os, version, token_hash, status, kind, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', 'active', ?, ?)",
            (site["id"], hostname, str(data.get("os", ""))[:200], str(data.get("version", ""))[:50],
             et["probe_kind"] or "probe", ts),
        )
        action = "probe.enroll"
        regen = False
    probe_token = f"{probe_id}.{secret}"
    ex(
        "UPDATE probes SET token_hash = ?, status = 'active', kind = ?, deregistered_at = NULL, os = ?, version = ?, "
        "last_ip = ? WHERE id = ?",
        (hash_token(probe_token), et["probe_kind"] or "probe", str(data.get("os", ""))[:200],
         str(data.get("version", ""))[:50], _client_ip(), probe_id),
    )
    ex("UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ?", (et["id"],))
    repo.audit(f"probe:{hostname}", action, f"probe:{probe_id}", f"Standort {site['name']}, IP {_client_ip()}")
    if regen:
        _regen_rules()
    return jsonify(probe_id=probe_id, token=probe_token, site_name=site["name"]), 201


@bp.get("/config")
@probe_auth
def config():
    payload, etag = repo.probe_config(g.probe)
    if request.headers.get("If-None-Match", "").strip('"') == etag:
        return "", 304, {"ETag": f'"{etag}"'}
    resp = jsonify(payload)
    resp.headers["ETag"] = f'"{etag}"'
    return resp


@bp.post("/ingest")
@probe_auth
def ingest_batch():
    batch_id = request.headers.get("X-Batch-Id", "")
    if not BATCH_ID_RE.match(batch_id):
        return jsonify(error="X-Batch-Id fehlt oder ungültig"), 400
    full_id = f"{g.probe['id']}:{batch_id}"
    if q1("SELECT batch_id FROM ingest_batches WHERE batch_id = ?", (full_id,)):
        return "", 204  # bereits verarbeitet (Wiederholung nach Verbindungsabbruch)

    body = _read_body()
    checks = repo.check_map_for_probe(g.probe)
    result = ingest.process(body, g.probe, checks)
    if result.rejected:
        log.info("Probe %s: %d Zeilen verworfen %s", g.probe["id"], result.rejected, result.reasons)
    try:
        vm.import_lines(result.lines)
    except vm.VMError as exc:
        log.error("Ingest von Probe %s fehlgeschlagen: %s", g.probe["id"], exc)
        return jsonify(error="Speicher vorübergehend nicht verfügbar"), 503
    ex(
        "INSERT INTO ingest_batches (batch_id, probe_id, received_at) VALUES (?, ?, ?)",
        (full_id, g.probe["id"], repo.now()),
    )
    ex("UPDATE probes SET last_seen = ?, last_ip = ? WHERE id = ?", (repo.now(), _client_ip(), g.probe["id"]))
    if result.up:
        disturbance_service.after_ingest(g.probe, result.up, checks)
    if result.rejected and not result.accepted:
        return jsonify(accepted=0, rejected=result.rejected, reasons=result.reasons), 422
    return "", 204


@bp.post("/heartbeat")
@probe_auth
def heartbeat():
    data = request.get_json(silent=True) or {}
    ts = repo.now()
    buffer_items = int(data.get("buffer_items") or 0)
    uptime = int(data.get("uptime_s") or 0)
    if g.probe.get("uptime_s") and 0 <= uptime < int(g.probe["uptime_s"]):
        # Dienst neu gestartet: ältere aktive Hinweise kann die Probe nicht mehr auflösen
        finding_service.close_stale(g.probe["id"], ts - uptime, "Nicht mehr bestätigt – Wachtl-Dienst neu gestartet")
    ex(
        "UPDATE probes SET last_seen = ?, last_ip = ?, version = ?, os = ?, buffer_items = ?, uptime_s = ?, "
        "addresses = ? WHERE id = ?",
        (
            ts,
            _client_ip(),
            str(data.get("version", g.probe["version"] or ""))[:50],
            str(data.get("os", g.probe["os"] or ""))[:200],
            buffer_items,
            uptime,
            json.dumps(_addresses(data.get("addresses"))),
            g.probe["id"],
        ),
    )
    try:
        vm.import_lines(ingest.heartbeat_lines(g.probe, buffer_items, ts))
    except vm.VMError as exc:
        log.warning("Heartbeat-Metrik nicht gespeichert: %s", exc)
    if random.random() < 0.01:  # gelegentlich aufräumen, ohne eigenen Scheduler
        repo.prune()
    # laufende Störungen bei Alertmanager aktuell halten, verwaiste schließen – auch wenn gerade keine Pings kommen
    disturbance_service.housekeeping(ts)
    _, etag = repo.probe_config(g.probe)
    return jsonify(config_etag=etag, server_time=ts, commands=repo.take_commands(g.probe["id"]))


@bp.post("/deregister")
@probe_auth
def deregister():
    """Abmeldung durch den Deinstaller: Probe deaktivieren und ihr Token sofort ungültig machen.

    Messwerte und Verlauf bleiben bis zum Ablauf der Aufbewahrung erhalten; im Dashboard erscheint
    die Probe als „abgemeldet“ und kann dort gelöscht werden.
    """
    ts = repo.now()
    ex("UPDATE probes SET status = 'disabled', token_hash = ?, deregistered_at = ?, iperf_server = FALSE WHERE id = ?",
       ("deregistered:" + new_secret(16), ts, g.probe["id"]))
    ex("DELETE FROM probe_commands WHERE probe_id = ? AND delivered_at IS NULL", (g.probe["id"],))
    repo.audit(f"probe:{g.probe['hostname']}", "probe.deregister", f"probe:{g.probe['id']}",
               f"Deinstallation, IP {_client_ip()}")
    log.info("Probe %s (%s) hat sich abgemeldet", g.probe["id"], g.probe["hostname"])
    _regen_rules()
    return "", 204


@bp.post("/report")
@probe_auth
def report():
    """Störungsmeldung eines Benutzers (Tray-Symbol), zugestellt über den lokalen Wachtl-Dienst.

    201 = neu gespeichert, 200 = dieselbe report_id gab es schon (Nachlieferung).
    """
    try:
        values = report_service.validate(request.get_json(silent=True))
    except report_service.ReportError as exc:
        return jsonify(error=str(exc)), 400
    rid, created = report_service.store(g.probe, values)
    if created:
        log.info("Probe %s: Störungsmeldung %s (%s) von %s", g.probe["hostname"], rid, values["category"],
                 values["user"] or "unbekannt")
    return jsonify(id=rid), 201 if created else 200


@bp.post("/findings")
@probe_auth
def findings():
    """Client-Hinweise der Probe (Kabel getrennt, Link-Geschwindigkeit, Treiber …), siehe docs/CLIENT-HINWEISE.md.

    Upsert je finding_id; ungültige Einträge werden übersprungen und in ``errors`` genannt.
    """
    try:
        items, errors = finding_service.validate_batch(request.get_json(silent=True))
    except finding_service.FindingError as exc:
        return jsonify(error=str(exc)), 400
    new = 0
    for values in items:
        if finding_service.store(g.probe, values):
            new += 1
            log.info("Probe %s: Hinweis %s (%s) – %s", g.probe["hostname"], values["kind"], values["severity"],
                     values["title"])
    for e in errors:
        log.warning("Probe %s: Hinweis abgelehnt – %s", g.probe["hostname"], e)
    return jsonify(stored=len(items), new=new, rejected=len(errors), errors=errors[:10])


@bp.get("/notices")
@probe_auth
def probe_notices():
    """Nur für die Server-Probe: neue Störungen, Alarme und Client-Hinweise aller Standorte für das Tray-Symbol auf
    dem Wachtl-Server (siehe docs/BENACHRICHTIGUNGEN.md). Andere Probes sehen nur ihre eigenen Daten – 404."""
    if g.probe.get("kind") != "server":
        return jsonify(error="nicht gefunden"), 404
    current = notice_service.cursor()
    try:
        a, f = int(request.args["a"]), int(request.args["f"])
    except (KeyError, ValueError):
        a, f = current["a"], current["f"]
    if a > current["a"] or f > current["f"]:
        a, f = current["a"], current["f"]
    items = notice_service.since(a, f)
    cursor = {"a": max([a] + [i["id"] for i in items if i["source"] == "alert"]),
              "f": max([f] + [i["id"] for i in items if i["source"] == "finding"])}
    return jsonify(cursor=cursor, items=items, active=notice_service.active_alert_ids())


def _addresses(raw) -> list[str]:
    """Lokale IPv4-Adressen der Probe (für iperf3 zwischen Probes); Link-Local und Loopback entfallen."""
    out: list[str] = []
    for value in raw if isinstance(raw, list) else []:
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if ip.version == 4 and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified) and str(ip) not in out:
            out.append(str(ip))
    return out[:8]


def _own_check(check_id, types: tuple[str, ...]) -> dict:
    check = repo.check_map_for_probe(g.probe).get(str(check_id))
    if check is None or check["type"] not in types:
        abort(422, "check_id gehört nicht zu dieser Probe")
    return check


def _result_ts(raw) -> int:
    ts = repo.now()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return ts
    if value > 10**12:
        value //= 1000
    return value if ts - 8 * 86400 <= value <= ts + 300 else ts


def _num(value, lo: float, hi: float) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def _hop_list(raw) -> list[dict]:
    hops: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            hop = int(item.get("hop"))
        except (TypeError, ValueError):
            continue
        if not 1 <= hop <= ingest.MAX_HOPS:
            continue
        ip = None
        if item.get("ip"):
            try:
                ip = str(ipaddress.ip_address(str(item["ip"])))
            except ValueError:
                ip = None
        hops.append({"hop": hop, "ip": ip, "rtt_ms": _num(item.get("rtt_ms"), 0, 60000) if ip else None})
    hops.sort(key=lambda h: h["hop"])
    return hops


def path_differs(old: list[dict], new: list[dict]) -> bool:
    """Pfad gewechselt? Hops ohne Antwort zählen nicht als Wechsel (ICMP-Drosselung)."""
    old_map = {h["hop"]: h["ip"] for h in old}
    for h in new:
        before = old_map.get(h["hop"])
        if h["ip"] and before and h["ip"] != before:
            return True
    last_old = max((h["hop"] for h in old if h["ip"]), default=0)
    last_new = max((h["hop"] for h in new if h["ip"]), default=0)
    return bool(last_old and last_new and last_old != last_new)


@bp.post("/results/path")
@probe_auth
def result_path():
    data = request.get_json(silent=True) or {}
    check = _own_check(data.get("check_id"), ("path",))
    hops = _hop_list(data.get("hops"))
    if not hops:
        return jsonify(error="hops fehlen"), 400
    ts = _result_ts(data.get("ts"))
    reached = bool(data.get("reached"))
    path_hash = hashlib.sha256(json.dumps([[h["hop"], h["ip"]] for h in hops]).encode()).hexdigest()[:16]
    prev = q1(
        "SELECT hops, path_hash FROM path_runs WHERE probe_id = ? AND check_id = ? ORDER BY ts DESC, id DESC LIMIT 1",
        (g.probe["id"], check["id"]),
    )
    changed = bool(prev) and prev["path_hash"] != path_hash and path_differs(json.loads(prev["hops"]), hops)
    if prev and not changed:
        # gleicher Pfad: letzten Eintrag fortschreiben statt alle 10 Minuten eine neue Zeile.
        # Hops, die diesmal nicht geantwortet haben, behalten ihre bekannte Adresse.
        known = {h["hop"]: h["ip"] for h in json.loads(prev["hops"]) if h["ip"]}
        hops = [h if h["ip"] or h["hop"] not in known else {**h, "ip": known[h["hop"]], "stale": True} for h in hops]
        path_hash = hashlib.sha256(json.dumps([[h["hop"], h["ip"]] for h in hops]).encode()).hexdigest()[:16]
        last = q1("SELECT id FROM path_runs WHERE probe_id = ? AND check_id = ? ORDER BY ts DESC, id DESC LIMIT 1",
                  (g.probe["id"], check["id"]))
        ex(
            "UPDATE path_runs SET ts = ?, reached = ?, hops = ?, path_hash = ?, reason = ? WHERE id = ?",
            (ts, reached, json.dumps(hops), path_hash, str(data.get("reason", ""))[:40], last["id"]),
        )
    else:
        ins(
            "INSERT INTO path_runs (probe_id, check_id, first_ts, ts, reason, reached, hops, path_hash, changed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (g.probe["id"], check["id"], ts, ts, str(data.get("reason", ""))[:40], reached, json.dumps(hops), path_hash,
             changed),
        )
    lines = [ingest.server_lines("wachtl_path_hops", g.probe, check, len(hops), ts, {}),
             ingest.server_lines("wachtl_path_reached", g.probe, check, 1 if reached else 0, ts, {})]
    if changed:
        lines.append(ingest.server_lines("wachtl_path_change", g.probe, check, 1, ts, {}))
        log.info("Probe %s: Pfad zu %s geändert", g.probe["hostname"], check["target"])
    try:
        vm.import_lines(lines)
    except vm.VMError as exc:
        log.warning("Pfad-Metriken nicht gespeichert: %s", exc)
    return jsonify(changed=changed), 201


BANDWIDTH_KINDS = ("iperf", "speedtest")


@bp.post("/results/bandwidth")
@probe_auth
def result_bandwidth():
    data = request.get_json(silent=True) or {}
    check = _own_check(data.get("check_id"), BANDWIDTH_KINDS)
    ts = _result_ts(data.get("ts"))
    trigger = "manual" if data.get("trigger") == "manual" else "schedule"
    results = data.get("results") if isinstance(data.get("results"), list) else []
    lines: list[str] = []
    stored = 0
    for r in results[:4]:
        if not isinstance(r, dict) or r.get("direction") not in ("up", "down"):
            continue
        mbps = _num(r.get("mbps"), 0, 1_000_000)
        error = str(r.get("error") or "")[:500] or None
        ins(
            "INSERT INTO bandwidth_runs (probe_id, check_id, ts, kind, direction, peer, protocol, mbps, jitter_ms, "
            "loss_pct, retransmits, latency_ms, duration_s, trigger, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                g.probe["id"], check["id"], ts, check["type"], r["direction"], str(r.get("peer") or "")[:200],
                str(r.get("protocol") or "")[:10], mbps, _num(r.get("jitter_ms"), 0, 60000),
                _num(r.get("loss_pct"), 0, 100), int(_num(r.get("retransmits"), 0, 10**12) or 0),
                _num(r.get("latency_ms"), 0, 60000), _num(r.get("duration_s"), 0, 3600), trigger, error,
            ),
        )
        stored += 1
        extra = {"direction": r["direction"], "kind": check["type"]}
        if mbps is not None and not error:
            lines.append(ingest.server_lines("wachtl_bw_mbps", g.probe, check, mbps, ts, extra))
            for key, metric in (("jitter_ms", "wachtl_bw_jitter_ms"), ("loss_pct", "wachtl_bw_loss_pct"),
                                ("latency_ms", "wachtl_bw_latency_ms")):
                v = _num(r.get(key), 0, 60000)
                if v is not None:
                    lines.append(ingest.server_lines(metric, g.probe, check, v, ts, extra))
        lines.append(ingest.server_lines("wachtl_bw_ok", g.probe, check, 0 if error or mbps is None else 1, ts, extra))
    if not stored:
        return jsonify(error="keine gültigen Ergebnisse"), 400
    try:
        vm.import_lines(lines)
    except vm.VMError as exc:
        log.warning("Bandbreiten-Metriken nicht gespeichert: %s", exc)
    return jsonify(stored=stored), 201


RTP_METRICS = (("mos", "wachtl_rtp_mos"), ("rtt_ms", "wachtl_rtp_rtt_ms"), ("loss_pct", "wachtl_rtp_loss_pct"),
               ("jitter_ms", "wachtl_rtp_jitter_ms"))


@bp.post("/results/rtp")
@probe_auth
def result_rtp():
    """Ergebnis eines Sprachtests (RTP), siehe wachtl/rtp/__init__.py."""
    data = request.get_json(silent=True) or {}
    check = _own_check(data.get("check_id"), ("rtp",))
    ts = _result_ts(data.get("ts"))
    trigger = "manual" if data.get("trigger") == "manual" else "schedule"
    r = data.get("result") if isinstance(data.get("result"), dict) else None
    if r is None:
        return jsonify(error="result fehlt"), 400
    error = str(r.get("error") or "")[:500] or None
    mos = _num(r.get("mos"), 1, 5)
    mode = r.get("mode") if r.get("mode") in ("wachtl", "echo") else None

    def count(key: str) -> int | None:
        v = _num(r.get(key), 0, 10**7)
        return None if v is None else int(v)

    values = {
        "peer": str(r.get("peer") or "")[:200], "codec": str(r.get("codec") or "")[:10],
        "ptime_ms": count("ptime_ms"), "duration_s": _num(r.get("duration_s"), 0, 3600), "mode": mode,
        "sent": count("sent"), "received": count("received"),
        "rtt_ms": _num(r.get("rtt_ms"), 0, 60000), "rtt_max_ms": _num(r.get("rtt_max_ms"), 0, 60000),
        "loss_pct": _num(r.get("loss_pct"), 0, 100), "up_loss_pct": _num(r.get("up_loss_pct"), 0, 100),
        "down_loss_pct": _num(r.get("down_loss_pct"), 0, 100), "jitter_ms": _num(r.get("jitter_ms"), 0, 60000),
        "up_jitter_ms": _num(r.get("up_jitter_ms"), 0, 60000), "down_jitter_ms": _num(r.get("down_jitter_ms"), 0, 60000),
        "out_of_order": count("out_of_order"), "r_factor": _num(r.get("r_factor"), -200, 200), "mos": mos,
    }
    cols = ", ".join(values)
    ins(f"INSERT INTO rtp_runs (probe_id, check_id, ts, {cols}, trigger, error) "
        f"VALUES (?, ?, ?, {', '.join('?' * len(values))}, ?, ?)",
        (g.probe["id"], check["id"], ts, *values.values(), trigger, error))
    ok = not error and mos is not None
    lines = [ingest.server_lines("wachtl_rtp_ok", g.probe, check, 1 if ok else 0, ts, {})]
    if ok:
        for key, metric in RTP_METRICS:
            if values[key] is not None:
                lines.append(ingest.server_lines(metric, g.probe, check, values[key], ts, {}))
    try:
        vm.import_lines(lines)
    except vm.VMError as exc:
        log.warning("RTP-Metriken nicht gespeichert: %s", exc)
    return jsonify(stored=1), 201


@bp.post("/results/netscan")
@probe_auth
def result_netscan():
    """Ergebnis eines Netzwerkscans (docs/NETZWERKSCAN.md): Geräte, offene Ports, Dienste."""
    from .services import netscan

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON-Objekt erwartet"), 400
    check = _own_check(data.get("check_id"), ("netscan",))
    try:
        values = netscan.validate(data)
    except netscan.ScanError as exc:
        return jsonify(error=str(exc)), 400
    ts = _result_ts(data.get("ts"))
    netscan.store(g.probe, check, values, ts)
    if not values["error"]:
        from .services import topology

        try:
            topology.refresh_findings(int(g.probe["site_id"]), ts)     # gefundene Switches neu bewerten
        except Exception:  # noqa: BLE001 – Auswertung ist Zusatz, der Scan ist gespeichert
            log.exception("Switch-Erkennung nach dem Netzwerkscan fehlgeschlagen")
    lines = [ingest.server_lines("wachtl_netscan_ok", g.probe, check, 0 if values["error"] else 1, ts, {})]
    if not values["error"]:
        lines.append(ingest.server_lines("wachtl_netscan_hosts", g.probe, check, len(values["hosts"]), ts, {}))
    try:
        vm.import_lines(lines)
    except vm.VMError as exc:
        log.warning("Netzwerkscan-Metriken nicht gespeichert: %s", exc)
    log.info("Probe %s: Netzwerkscan %s – %d Geräte%s", g.probe["hostname"], check["target"], len(values["hosts"]),
             f", Fehler: {values['error']}" if values["error"] else "")
    return jsonify(stored=len(values["hosts"])), 201


@bp.get("/topology/jobs")
@probe_auth
def topology_jobs():
    """Fällige Switch-Abfragen (docs/TOPOLOGIE.md) – nur für die Server-Probe, sie bekommt die Zugangsdaten."""
    from .services import topology

    if g.probe.get("kind") != "server":
        return jsonify(error="Switch-Abfragen laufen nur über die Server-Probe"), 403
    return jsonify(jobs=topology.jobs(), poll_s=15)


@bp.post("/results/topology")
@probe_auth
def result_topology():
    """Ergebnis einer Switch-Abfrage: Momentaufnahme oder Fehlertext."""
    from .services import topology

    if g.probe.get("kind") != "server":
        return jsonify(error="Switch-Abfragen laufen nur über die Server-Probe"), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON-Objekt erwartet"), 400
    sw = q1("SELECT * FROM net_switches WHERE id = ?", (_int_or_none(data.get("switch_id")),))
    if sw is None:
        return jsonify(error="Switch unbekannt"), 422
    ts = _result_ts(data.get("ts"))
    kind = "quick" if data.get("kind") == "quick" else "full"
    error = data.get("error")
    snapshot = None
    if not error:
        try:
            snapshot = (topology.clean_quick if kind == "quick" else topology.clean_snapshot)(data.get("snapshot"))
        except ValueError as exc:
            error = str(exc)
    topology.store_result(sw, snapshot, str(error) if error else None, ts, kind)
    log.log(logging.INFO if error or kind == "full" else logging.DEBUG, "Switch %s (%s): %s", sw["id"], sw["host"],
            f"Fehler: {error}" if error else f"abgefragt ({kind})")
    return jsonify(stored=1), 201


@bp.post("/results/discovery")
@probe_auth
def result_discovery():
    """Rundruf der Server-Probe: Switches ohne SNMP im eigenen Netz (TP-Link Easy Smart, Netgear ProSAFE Plus)."""
    from .services import switchfind, topology

    if g.probe.get("kind") != "server":
        return jsonify(error="Der Rundruf läuft nur über die Server-Probe"), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON-Objekt erwartet"), 400
    ts = _result_ts(data.get("ts"))
    n = switchfind.store_discovery(int(g.probe["site_id"]), data.get("devices") or [], ts)
    topology.refresh_findings(int(g.probe["site_id"]), ts)
    return jsonify(stored=n), 201


def _int_or_none(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# -- intern: Alertmanager-Webhook ------------------------------------------
internal = Blueprint("api_internal", __name__, url_prefix="/api/internal")


@internal.post("/alertmanager")
def alertmanager_webhook():
    if request.headers.get("X-Forwarded-For"):
        # über Traefik von außen gekommen – der Webhook ist nur für Alertmanager im internen Netz
        return jsonify(error="nicht gefunden"), 404
    secret = current_app.config["WEBHOOK_SECRET"]
    if not secret or not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {secret}"):
        return jsonify(error="nicht autorisiert"), 401
    count = alert_service.store_webhook(request.get_json(silent=True) or {})
    return jsonify(stored=count)

