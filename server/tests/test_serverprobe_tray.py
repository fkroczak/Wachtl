"""Tray-Endpunkt der Server-Probe (Störungsmeldungen vom Windows-Server, docs/STOERUNGSMELDUNGEN.md)."""
import http.client
import json
import socket
import time

import pytest

from wachtl.serverprobe.tray import (PendingReports, ReportRejected, TrayEndpoint, TrayService, validate)

NOW = 1_800_000_000


def good(**extra):
    return {"occurred_at": NOW - 60, "category": "slow", "duration": "minutes",
            "description": "  Teams ruckelt  ", "user": "KUNDE\\mm", **extra}


def test_validate_bereinigt_und_prueft():
    v = validate(good(description="x" * 2000), NOW)
    assert v == {"occurred_at": NOW - 60, "category": "slow", "duration": "minutes",
                 "description": "x" * 1000, "user": "KUNDE\\mm"}
    assert validate(good(duration=None), NOW)["duration"] == "unknown"
    for bad, text in [(good(occurred_at=NOW - 8 * 86400), "7 Tage"), (good(occurred_at=NOW + 3600), "Zukunft"),
                      (good(occurred_at="jetzt"), "Zeitpunkt"), (good(occurred_at=True), "Zeitpunkt"),
                      (good(occurred_at=float("inf")), "Zeitpunkt"),
                      (good(category="kaputt"), "passiert"), (good(duration="ewig"), "Dauer"), ([], "Ungültig")]:
        with pytest.raises(ValueError, match=text):
            validate(bad, NOW)


def service(tmp_path, send, ready=True, clock=lambda: NOW):
    return TrayService(lambda: {"role": "server"}, send, PendingReports(tmp_path / "p.json"), "srv01",
                       ready=lambda: ready, clock=clock)


def test_meldung_wird_zugestellt(tmp_path):
    sent = []
    status, body = service(tmp_path, sent.append).report(good())
    assert (status, body) == (202, {"ok": True, "delivered": True})
    assert sent[0]["hostname"] == "srv01" and len(sent[0]["report_id"]) == 36
    assert sent[0]["description"] == "Teams ruckelt"


def test_ohne_server_wird_gepuffert_und_nachgeliefert(tmp_path):
    def offline(_):
        raise OSError("weg")

    svc = service(tmp_path, offline)
    assert svc.report(good()) == (202, {"ok": True, "delivered": False})
    assert svc.report(good(category="other")) == (202, {"ok": True, "delivered": False})
    assert svc.status() == {"role": "server", "pending_reports": 2}
    # Neustart: Puffer liegt in der Datei
    pending = PendingReports(tmp_path / "p.json")
    assert pending.flush(offline) == 2
    delivered = []
    assert pending.flush(delivered.append) == 0
    assert [r["category"] for r in delivered] == ["slow", "other"]
    assert not (tmp_path / "p.json").exists()


def test_abgelehnte_meldung_wird_verworfen(tmp_path):
    def reject(_):
        raise ReportRejected("occurred_at ungültig")

    assert service(tmp_path, reject).report(good()) == (400, {"error": "occurred_at ungültig"})
    pending = PendingReports(tmp_path / "q.json")
    pending.add({"report_id": "a"})
    assert pending.flush(reject) == 0


def test_nicht_registriert_und_ratenlimit(tmp_path):
    assert service(tmp_path, lambda r: None, ready=False).report(good())[0] == 409
    svc = service(tmp_path, lambda r: None)
    assert all(svc.report(good())[0] == 202 for _ in range(30))
    assert svc.report(good())[0] == 429
    assert svc.report(good(user="KUNDE\\anderer"))[0] == 202   # Limit gilt je Benutzer
    assert svc.report({"category": "slow"})[0] == 400   # Validierung zählt nicht gegen das Limit


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def endpoint(tmp_path):
    port = free_port()
    sent = []
    ep = TrayEndpoint(TrayService(lambda: {"role": "server", "name": "srv01"}, sent.append,
                                  PendingReports(tmp_path / "p.json"), "srv01"), port)
    assert ep.start()
    yield port, sent
    ep.stop()


def call(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"X-Wachtl-Tray": "1", "Host": f"127.0.0.1:{port}"}
    if body is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=h)
    r = conn.getresponse()
    data = json.loads(r.read() or b"{}")
    conn.close()
    return r.status, data


def test_http_status_und_meldung(endpoint):
    port, sent = endpoint
    assert call(port, "GET", "/tray/v1/status") == (200, {"role": "server", "name": "srv01", "pending_reports": 0})
    status, body = call(port, "POST", "/tray/v1/report", good(occurred_at=int(time.time())))
    assert status == 202 and body["delivered"] is True and sent[0]["category"] == "slow"
    assert call(port, "GET", "/tray/v1/report")[0] == 405
    assert call(port, "GET", "/gibtsnicht")[0] == 404


def test_http_schutz_gegen_browser(endpoint):
    port, sent = endpoint
    assert call(port, "GET", "/tray/v1/status", headers={"X-Wachtl-Tray": "0"})[0] == 403
    assert call(port, "GET", "/tray/v1/status", headers={"Host": f"evil.example:{port}"})[0] == 403
    assert call(port, "POST", "/tray/v1/report", good(), headers={"Content-Type": "text/plain"})[0] == 403
    assert call(port, "OPTIONS", "/tray/v1/report")[0] == 403
    status, _ = call(port, "POST", "/tray/v1/report", {"description": "x" * 20000, **good()})
    assert status == 400
    assert sent == []


def test_port_exklusiv(endpoint, tmp_path):
    port, _ = endpoint
    second = TrayEndpoint(TrayService(dict, lambda r: None, PendingReports(tmp_path / "x.json"), "x"), port)
    assert second.start() is False


def test_puffer_nicht_schreibbar(tmp_path):
    def offline(_):
        raise OSError("weg")

    (tmp_path / "p.json").mkdir()          # Datei kann nicht geschrieben werden
    assert service(tmp_path, offline).report(good())[0] == 500
