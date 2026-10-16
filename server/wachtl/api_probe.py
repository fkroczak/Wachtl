"""Probe-API: Enrollment, Konfiguration, Messwerte, Heartbeat."""
from __future__ import annotations

import gzip
import hmac
import logging
import random
import re
import zlib

from flask import Blueprint, abort, current_app, g, jsonify, request

from . import repo
from .db import ex, ins, q1
from .security import hash_token, new_secret, probe_auth
from .services import alerts as alert_service
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
    existing = q1("SELECT id FROM probes WHERE site_id = ? AND hostname = ?", (site["id"], hostname))
    if existing:
        probe_id = existing["id"]
        action = "probe.reenroll"
    else:
        probe_id = ins(
            "INSERT INTO probes (site_id, hostname, os, version, token_hash, status, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', 'active', ?)",
            (site["id"], hostname, str(data.get("os", ""))[:200], str(data.get("version", ""))[:50], ts),
        )
        action = "probe.enroll"
    probe_token = f"{probe_id}.{secret}"
    ex(
        "UPDATE probes SET token_hash = ?, status = 'active', os = ?, version = ?, last_ip = ? WHERE id = ?",
        (hash_token(probe_token), str(data.get("os", ""))[:200], str(data.get("version", ""))[:50], _client_ip(), probe_id),
    )
    ex("UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ?", (et["id"],))
    repo.audit(f"probe:{hostname}", action, f"probe:{probe_id}", f"Standort {site['name']}, IP {_client_ip()}")
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
    result = ingest.process(body, g.probe, repo.check_map_for_probe(g.probe))
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
    if result.rejected and not result.accepted:
        return jsonify(accepted=0, rejected=result.rejected, reasons=result.reasons), 422
    return "", 204


@bp.post("/heartbeat")
@probe_auth
def heartbeat():
    data = request.get_json(silent=True) or {}
    ts = repo.now()
    buffer_items = int(data.get("buffer_items") or 0)
    ex(
        "UPDATE probes SET last_seen = ?, last_ip = ?, version = ?, os = ?, buffer_items = ?, uptime_s = ? WHERE id = ?",
        (
            ts,
            _client_ip(),
            str(data.get("version", g.probe["version"] or ""))[:50],
            str(data.get("os", g.probe["os"] or ""))[:200],
            buffer_items,
            int(data.get("uptime_s") or 0),
            g.probe["id"],
        ),
    )
    try:
        vm.import_lines(ingest.heartbeat_lines(g.probe, buffer_items, ts))
    except vm.VMError as exc:
        log.warning("Heartbeat-Metrik nicht gespeichert: %s", exc)
    if random.random() < 0.01:  # gelegentlich aufräumen, ohne eigenen Scheduler
        repo.prune()
    _, etag = repo.probe_config(g.probe)
    return jsonify(config_etag=etag, server_time=ts)


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

