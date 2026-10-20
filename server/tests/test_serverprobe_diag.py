"""Client-Hinweise des Windows-Servers: wachtl-probe.exe diagnose als Kindprozess, Tray-Feed, Weiterleitung."""
import json
import subprocess
import sys
import threading
import time

from wachtl.serverprobe.diag import Diagnostics, FindingFeed, Rejected, parse_line
from wachtl.serverprobe.tray import PendingReports, TrayEndpoint, TrayService

from .test_serverprobe_tray import call, free_port


def finding(fid="f1", state="active", **kw):
    return {"finding_id": fid, "kind": "adapter_disabled", "severity": "critical", "state": state,
            "title": "Netzwerkkarte ausgeschaltet", "message": "m", "solution": "s", "balloon": "Kurz\nLösung: X",
            "adapter": "Ethernet", "details": {}, "detected_at": 1_792_230_000, "resolved_at": None, **kw}


def wait(cond, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return False


def fake_child(tmp_path, lines, exit_after=False):
    """Ein Python-Skript statt wachtl-probe.exe: schreibt die Zeilen und wartet auf das Ende von stdin."""
    script = tmp_path / "fake_diagnose.py"
    script.write_text(
        "import sys\n"
        f"for line in {lines!r}:\n    print(line, flush=True)\n"
        + ("" if exit_after else "sys.stdin.read()\n"), encoding="utf-8")

    def popen(args, **kw):
        assert args[1:] == ["diagnose"]
        return subprocess.Popen([sys.executable, "-I", str(script)], **kw)
    return popen


def test_feed_numbers_and_since():
    feed = FindingFeed(start_seq=100)
    assert feed.publish(finding("a")) == 101
    assert feed.publish(finding("b")) == 102
    assert feed.publish(finding("a", state="resolved")) == 103
    data = feed.since(0)
    assert [f["seq"] for f in data["findings"]] == [102, 103]
    assert data["latest_seq"] == 103 and data["start_seq"] == 100 and data["notify"] is True
    assert data["findings"][0]["balloon"] == "Kurz\nLösung: X"
    assert feed.since(103)["findings"] == []
    for i in range(60):
        feed.publish(finding(f"x{i}"))
    assert len(feed.since(0)["findings"]) == 50


def test_parse_line():
    assert parse_line(json.dumps(finding()))["kind"] == "adapter_disabled"
    assert parse_line("kein json") is None
    assert parse_line(json.dumps({"finding_id": "", "state": "active", "kind": "x"})) is None
    assert parse_line(json.dumps(finding(state="kaputt"))) is None


def test_child_findings_reach_tray_and_server(tmp_path):
    sent = []
    stop = threading.Event()
    lines = [json.dumps(finding("f1")), "Müll", json.dumps(finding("f2", kind="cable_unplugged"))]
    diag = Diagnostics("wachtl-probe.exe", lambda batch: sent.extend(batch), stop, popen=fake_child(tmp_path, lines))
    diag.start()
    try:
        assert wait(lambda: len(diag.feed.since(0)["findings"]) == 2)
        assert wait(lambda: {f["finding_id"] for f in sent} == {"f1", "f2"})
        assert all("balloon" not in f for f in sent)       # Kurzfassung nur fürs Tray
        assert set(diag.active) == {"f1", "f2"}
    finally:
        stop.set()
    assert wait(lambda: diag.proc is None)


def test_child_exit_resolves_active_and_restarts(tmp_path, monkeypatch):
    monkeypatch.setattr("wachtl.serverprobe.diag.RESTART_S", (0.2, 0.2))
    sent = []
    stop = threading.Event()
    diag = Diagnostics("wachtl-probe.exe", lambda batch: sent.extend(batch), stop,
                       popen=fake_child(tmp_path, [json.dumps(finding("f1"))], exit_after=True))
    diag.start()
    try:
        assert wait(lambda: any(f["finding_id"] == "f1" and f["state"] == "resolved" for f in sent))
        resolved = next(f for f in sent if f["state"] == "resolved")
        assert resolved["details"]["problem"] == "Netzwerkkarte ausgeschaltet"
    finally:
        stop.set()


def test_disable_stops_child_and_clears(tmp_path):
    stop = threading.Event()
    diag = Diagnostics("wachtl-probe.exe", lambda batch: None, stop, popen=fake_child(tmp_path, [json.dumps(finding())]))
    diag.start()
    try:
        assert wait(lambda: diag.active)
        diag.configure({"enabled": True, "notify": False})
        assert diag.feed.since(0)["notify"] is False
        diag.configure({"enabled": False, "notify": False})
        assert diag.active == {} and diag.feed.since(0)["findings"] == []
        assert wait(lambda: diag.proc is None)
    finally:
        stop.set()


def test_flush_keeps_on_error_and_drops_rejected():
    calls = []

    def send(batch):
        calls.append(len(batch))
        raise OSError("Server nicht erreichbar")
    diag = Diagnostics("x", send, threading.Event())
    for i in range(60):
        diag.handle(finding(f"f{i}"))
    assert diag.flush() == 60 and calls == [50]

    def reject(batch):
        raise Rejected("ungültig")
    diag.send = reject
    assert diag.flush() == 0


def test_tray_endpoint_serves_findings(tmp_path):
    feed = FindingFeed(start_seq=10)
    feed.publish(finding())
    port = free_port()
    ep = TrayEndpoint(TrayService(dict, lambda r: None, PendingReports(tmp_path / "p.json"), "srv",
                                  findings=feed.since), port)
    assert ep.start()
    try:
        status, body = call(port, "GET", "/tray/v1/findings?since=0")
        assert status == 200 and body["findings"][0]["kind"] == "adapter_disabled" and body["latest_seq"] == 11
        assert call(port, "GET", "/tray/v1/findings?since=11")[1]["findings"] == []
        assert call(port, "GET", "/tray/v1/findings", headers={"X-Wachtl-Tray": "0"})[0] == 403
    finally:
        ep.stop()
    # ohne Client-Hinweise (Docker, keine wachtl-probe.exe): 404, das Tray blendet den Menüpunkt aus
    port = free_port()
    ep = TrayEndpoint(TrayService(dict, lambda r: None, PendingReports(tmp_path / "q.json"), "srv"), port)
    assert ep.start()
    try:
        assert call(port, "GET", "/tray/v1/findings?since=0")[0] == 404
    finally:
        ep.stop()


def test_available_only_on_windows_with_exe(tmp_path):
    assert Diagnostics.available(None) is False
    assert Diagnostics.available(str(tmp_path / "fehlt.exe")) is False
