"""Wachtl – Netzwerk-Monitoring-Collector mit Web-Dashboard."""
from __future__ import annotations

import logging
import os
from datetime import timedelta

from flask import Flask, jsonify, render_template, request

__version__ = "0.9.4"


def _env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(f"WACHTL_{key}", default)


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_env("SECRET_KEY"),
        DATABASE_URL=_env("DATABASE_URL", "sqlite:///wachtl-dev.db"),
        VM_RAW_URL=_env("VM_RAW_URL", "http://vm-raw:8428"),
        VM_AGG_URL=_env("VM_AGG_URL", "http://vm-agg:8428"),
        VMALERT_URL=_env("VMALERT_URL", "http://vmalert:8880"),
        ALERTMANAGER_URL=_env("ALERTMANAGER_URL", "http://alertmanager:9093"),
        RULES_DIR=_env("RULES_DIR", "/rules"),
        AM_CONFIG=_env("AM_CONFIG", ""),
        INTERNAL_URL=_env("INTERNAL_URL", "http://app:8000"),
        TRUST_PROXY=_env("TRUST_PROXY", "1") == "1",
        WEBHOOK_SECRET=_env("WEBHOOK_SECRET", ""),
        PUBLIC_URL=_env("PUBLIC_URL", "https://wachtl.local"),
        # weitere Adressen des Servers (Namen und IPs), die Probes der Reihe nach versuchen
        SERVER_URLS=[u.strip() for u in (_env("SERVER_URLS", "") or "").split(",") if u.strip()],
        # lokale IP-Adressen automatisch ergänzen (Windows-Server; im Docker-Container wären es interne Adressen)
        AUTO_IPS=_env("AUTO_IPS", "0") == "1",
        SPKI_PIN=_env("SPKI_PIN", ""),
        CERT_FILE=_env("CERT_FILE", ""),   # nur zum Herunterladen unter /zertifikat
        PROBE_DIR=_env("PROBE_DIR", ""),
        IPERF_PORT=int(_env("IPERF_PORT", "5201") or 0),
        RTP_PORT=int(_env("RTP_PORT", "5004") or 0),     # RTP-Reflektor für Sprachtests, 0 = aus
        SERVER_PROBE=_env("SERVER_PROBE", "1") == "1",
        SERVER_PROBE_DIR=_env("SERVER_PROBE_DIR", ""),
        SERVER_PROBE_SITE=_env("SERVER_PROBE_SITE", "Wachtl-Server"),
        RAW_QUERY_MAX_S=int(_env("RAW_QUERY_MAX_S", str(6 * 3600))),
        MAX_INGEST_BYTES=20 * 1024 * 1024,
        MAX_CONTENT_LENGTH=25 * 1024 * 1024,
        SESSION_COOKIE_SECURE=_env("COOKIE_SECURE", "1") == "1",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="wachtl_session",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )
    if overrides:
        app.config.update(overrides)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("WACHTL_SECRET_KEY ist nicht gesetzt.")

    logging.basicConfig(
        level=_env("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    from .db import Database, close_conn

    app.extensions["wachtl_db"] = Database(app.config["DATABASE_URL"])
    app.teardown_appcontext(close_conn)

    from . import api_admin, api_probe, cli, web

    app.register_blueprint(api_probe.bp)
    app.register_blueprint(api_probe.internal)
    app.register_blueprint(api_admin.bp)
    app.register_blueprint(api_admin.reports_bp)
    app.register_blueprint(web.bp)
    cli.register(app)

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=__version__)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("X-Robots-Tag", "noindex, nofollow")  # internes Werkzeug, nie indexieren
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'",
        )
        return resp

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(500)
    def error_page(err):
        if request.path.startswith("/api/"):
            return jsonify(error=getattr(err, "description", str(err))), err.code
        message = {405: "Diese Adresse lässt sich so nicht aufrufen – bitte über die Seite und ihre Schaltflächen gehen.",
                   500: "Unerwarteter Fehler auf dem Server. Bitte erneut versuchen; bleibt der Fehler, steht die "
                        "Ursache im Server-Log."}.get(err.code, err.description)
        return render_template("error.html", code=err.code, message=message), err.code

    return app
