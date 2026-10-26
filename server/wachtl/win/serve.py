"""HTTPS-Server für Windows (ersetzt Traefik + Gunicorn aus dem Docker-Stack).

- HTTPS (Standard 443) mit dem selbstsignierten Zertifikat, TLS ≥ 1.2, HSTS
- optional HTTP (Standard 80), leitet nur auf HTTPS um
- intern http://127.0.0.1:8427 nur für den Alertmanager-Webhook und den Healthcheck

Läuft unter cheroot (reiner Python-WSGI-Server). Start: ``python -m wachtl.win.serve``
mit den Umgebungsvariablen aus ``Layout.app_env()``.
"""
from __future__ import annotations

import logging
import os
import signal
import ssl
import threading

log = logging.getLogger("wachtl.serve")
HSTS = "max-age=31536000"


def with_security_headers(app):
    def wrapped(environ, start_response):
        def sr(status, headers, exc_info=None):
            if not any(h[0].lower() == "strict-transport-security" for h in headers):
                headers.append(("Strict-Transport-Security", HSTS))
            return start_response(status, headers, exc_info)
        return app(environ, sr)
    return wrapped


def redirect_app(https_port: int):
    """Leitet jede HTTP-Anfrage auf dieselbe Adresse per HTTPS um."""
    def app(environ, start_response):
        host = environ.get("HTTP_HOST") or environ.get("SERVER_NAME", "localhost")
        if host.startswith("["):  # IPv6 [::1]:80
            host = host[: host.index("]") + 1]
        else:
            host = host.split(":")[0]
        port = "" if https_port == 443 else f":{https_port}"
        path = environ.get("PATH_INFO", "/") or "/"
        query = environ.get("QUERY_STRING")
        location = f"https://{host}{port}{path}" + (f"?{query}" if query else "")
        start_response("301 Moved Permanently", [("Location", location), ("Content-Length", "0")])
        return [b""]
    return app


def internal_only(app):
    """Interner Listener: nur Webhook und Healthcheck, alles andere 404."""
    def wrapped(environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == "/healthz" or path.startswith("/api/internal/"):
            return app(environ, start_response)
        start_response("404 Not Found", [("Content-Type", "text/plain"), ("Content-Length", "9")])
        return [b"Not Found"]
    return wrapped


def _mtime(path: str) -> float:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0


def tls_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


class _Servers:
    """Startet mehrere WSGI-Server in Threads und stoppt sie gemeinsam."""

    def __init__(self):
        self.servers: list = []
        self.threads: list[threading.Thread] = []
        self.tls: list[ssl.SSLContext] = []
        self.cert_files: tuple[str, str] | None = None
        self._cert_mtime = 0.0

    def watch_certificate(self, cert_file: str, key_file: str) -> None:
        self.cert_files = (cert_file, key_file)
        self._cert_mtime = _mtime(cert_file)

    def reload_certificate_if_changed(self) -> bool:
        """Erneuertes Zertifikat für neue Verbindungen übernehmen – ohne Neustart, ohne Verbindungsabbruch."""
        if not self.cert_files:
            return False
        mtime = _mtime(self.cert_files[0])
        if mtime == self._cert_mtime:
            return False
        try:
            for ctx in self.tls:
                ctx.load_cert_chain(*self.cert_files)
        except (OSError, ssl.SSLError):
            log.exception("Neues Zertifikat konnte nicht geladen werden – das bisherige bleibt aktiv")
            return False
        self._cert_mtime = mtime
        log.info("Zertifikat neu geladen: %s", self.cert_files[0])
        return True

    def add(self, server, name: str) -> None:
        self.servers.append(server)
        t = threading.Thread(target=self._run, args=(server, name), name=name, daemon=True)
        self.threads.append(t)

    @staticmethod
    def _run(server, name: str) -> None:
        try:
            server.start() if hasattr(server, "start") else server.serve_forever()
        except Exception:  # noqa: BLE001 – Fehler loggen, Supervisor startet neu
            log.exception("Server %s beendet", name)
            os._exit(3)

    def start(self) -> None:
        for t in self.threads:
            t.start()

    def stop(self) -> None:
        for s in self.servers:
            try:
                s.stop() if hasattr(s, "stop") else s.shutdown()
            except Exception:  # noqa: BLE001
                log.exception("Fehler beim Stoppen")


def build_servers(app, bind: str, https_port: int, http_port: int, internal_port: int,
                  cert_file: str, key_file: str, dev: bool = False) -> _Servers:
    servers = _Servers()
    public = with_security_headers(app)
    servers.watch_certificate(cert_file, key_file)
    if dev:
        ctx = tls_context(cert_file, key_file)
        servers.tls.append(ctx)
        servers.add(_dev_server(bind, https_port, public, ctx), "https")
        servers.add(_dev_server("127.0.0.1", internal_port, internal_only(app)), "internal")
        if http_port:
            servers.add(_dev_server(bind, http_port, redirect_app(https_port)), "http")
        return servers

    from cheroot import wsgi
    from cheroot.ssl.builtin import BuiltinSSLAdapter

    https = wsgi.Server((bind, https_port), public, numthreads=32, request_queue_size=64, timeout=30,
                        server_name="wachtl")
    adapter = BuiltinSSLAdapter(cert_file, key_file)
    adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
    servers.tls.append(adapter.context)
    https.ssl_adapter = adapter
    servers.add(https, "https")
    servers.add(wsgi.Server(("127.0.0.1", internal_port), internal_only(app), numthreads=4,
                            server_name="wachtl-internal"), "internal")
    if http_port:
        servers.add(wsgi.Server((bind, http_port), redirect_app(https_port), numthreads=4,
                                server_name="wachtl-redirect"), "http")
    return servers


def _dev_server(host: str, port: int, app, ctx: ssl.SSLContext | None = None):
    """Nur für Tests ohne cheroot: wsgiref mit Threads (nicht für den Produktivbetrieb)."""
    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

    class Quiet(WSGIRequestHandler):
        def log_message(self, *args):
            pass

    class Threading(ThreadingMixIn, WSGIServer):
        daemon_threads = True

    server = make_server(host, port, app, server_class=Threading, handler_class=Quiet)
    if ctx:
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    logging.basicConfig(level=os.environ.get("WACHTL_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from .. import create_app

    app = create_app()
    env = os.environ
    servers = build_servers(
        app,
        bind=env.get("WACHTL_BIND", "0.0.0.0"),
        https_port=int(env.get("WACHTL_HTTPS_PORT", "443")),
        http_port=int(env.get("WACHTL_HTTP_PORT", "0") or 0),
        internal_port=int(env.get("WACHTL_INTERNAL_PORT", "8427")),
        cert_file=env["WACHTL_CERT_FILE"],
        key_file=env["WACHTL_KEY_FILE"],
        dev=env.get("WACHTL_DEV_SERVER") == "1",
    )
    stop = threading.Event()

    def handler(signum, _frame):
        log.info("Stoppsignal %s", signum)
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), handler)

    servers.start()
    log.info("Wachtl hört auf HTTPS :%s, HTTP :%s, intern 127.0.0.1:%s",
             env.get("WACHTL_HTTPS_PORT"), env.get("WACHTL_HTTP_PORT") or "aus", env.get("WACHTL_INTERNAL_PORT"))
    ticks = 0
    while not stop.wait(1):
        ticks += 1
        if ticks % 60 == 0:
            servers.reload_certificate_if_changed()
    servers.stop()
    log.info("Webserver gestoppt")


if __name__ == "__main__":
    main()
