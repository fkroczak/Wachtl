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


def test_hinweise_aller_standorte_fuer_das_tray_symbol():
    from wachtl.serverprobe.tray import NoticeFeed

    feed = NoticeFeed(lambda: NOW)
    # Start: nur den Stand übernehmen, nichts Altes zeigen
    feed.accept({"cursor": {"a": 5, "f": 2}, "items": [], "active": [4]})
    assert feed.since(0)["findings"] == []
    assert feed.cursor == {"a": 5, "f": 2}

    def alert(i, state, **extra):
        return {"key": f"alert:{i}", "source": "alert", "id": i, "alertname": "WachtlTargetDown", "severity": "critical",
                "state": state, "title": "Ausfall: PC-01 (Zentrale)", "text": "Ausfall: 8.8.8.8 nicht erreichbar",
                "ts": NOW - 30, "end": None, **extra}

    feed.accept({"cursor": {"a": 7, "f": 3}, "active": [6], "items": [
        alert(6, "firing", probe_id="1", target="8.8.8.8"),
        alert(7, "resolved", end=NOW - 10, probe_id="2"),     # nachträglich erkannt: schon vorbei
        {"key": "finding:3", "source": "finding", "id": 3, "alertname": "cable_unplugged", "severity": "critical",
         "state": "firing", "title": "Netzwerkkabel getrennt – PC-02 (Filiale)", "text": "Kabel stecken", "ts": NOW},
    ]})
    out = feed.since(0)
    assert out["start_seq"] == NOW * 1000 and out["notify"] is True
    items = {f["finding_id"]: f for f in out["findings"]}
    assert items["outage:1:6"]["state"] == "active" and items["outage:1:6"]["event"] is False
    assert items["outage-late:2:7"]["event"] is True and items["finding:3"]["event"] is True
    assert items["outage:1:6"]["balloon"] == "Ausfall: 8.8.8.8 nicht erreichbar"
    latest = out["latest_seq"]
    # Alarm vom Server beendet: einmal „Beendet“, dann nicht mehr aktiv
    feed.accept({"cursor": {"a": 7, "f": 3}, "active": [], "items": []})
    later = feed.since(latest)["findings"]
    assert [(f["finding_id"], f["state"]) for f in later] == [("outage:1:6", "resolved")]
    assert later[0]["title"].startswith("Beendet: ")


def _down(i, probe="1", role="reference", target="1.1.1.1", alertname="WachtlTargetDown", state="firing", **extra):
    return {"key": f"alert:{i}", "source": "alert", "id": i, "alertname": alertname, "severity": "critical",
            "state": state, "title": "Ausfall: PC-01 (Zentrale)", "text": "Ausfall …", "ts": NOW - 20, "end": None,
            "probe_id": probe, "where": "PC-01 (Zentrale)", "role": role, "target": target, **extra}


def test_gleichzeitige_ausfaelle_einer_probe_werden_ein_hinweis():
    from wachtl.serverprobe.tray import NoticeFeed

    feed = NoticeFeed(lambda: NOW)
    feed.accept({"cursor": {"a": 0, "f": 0}, "items": [], "active": []})
    feed.accept({"cursor": {"a": 4, "f": 0}, "active": [1, 2, 3, 4], "items": [
        _down(1, target="1.1.1.1"), _down(2, target="8.8.8.8"), _down(3, role="gateway", target="192.168.1.1"),
        _down(4, alertname="WachtlWanDown", target=""),
    ]})
    active = {f["finding_id"]: f for f in feed.since(0)["findings"]}
    assert list(active) == ["outage:1:1"]
    entry = active["outage:1:1"]
    assert entry["title"] == "Lokales Netz gestört: PC-01 (Zentrale)" and entry["severity"] == "critical"
    assert "das Internet und 2 Ziele" in entry["message"]
    # ein weiteres Ziel fällt aus: derselbe Hinweis wird aktualisiert, kein neuer
    seq = feed.seq
    feed.accept({"cursor": {"a": 5, "f": 0}, "active": [1, 2, 3, 4, 5], "items": [_down(5, target="9.9.9.9")]})
    later = feed.since(seq)["findings"]
    assert [f["finding_id"] for f in later] == ["outage:1:1"] and "3 Ziele" in later[0]["message"]
    # erst wenn alle beendet sind: einmal „Beendet“
    seq = feed.seq
    feed.accept({"cursor": {"a": 5, "f": 0}, "active": [5], "items": []})
    assert feed.since(seq)["findings"] == []
    feed.accept({"cursor": {"a": 5, "f": 0}, "active": [], "items": []})
    done = feed.since(seq)["findings"]
    assert [(f["finding_id"], f["state"]) for f in done] == [("outage:1:1", "resolved")]


def test_eigene_netzwerkkarte_aus_ergibt_einen_klaren_hinweis():
    from wachtl.serverprobe.tray import NoticeFeed

    clock = [NOW]
    feed = NoticeFeed(lambda: clock[0])
    feed.own_probe = "1"
    feed.accept({"cursor": {"a": 0, "f": 0}, "items": [], "active": []})
    # ein Ausfall kommt noch vor der Erkennung an …
    feed.accept({"cursor": {"a": 1, "f": 0}, "active": [1], "items": [_down(1)]})
    seq = feed.seq
    # … dann fehlt die Default-Route: der Ausfall endet still, es bleibt „Keine Netzwerkverbindung“
    feed.set_link(False)
    out = feed.since(seq)["findings"]
    assert [(f["finding_id"], f["state"], f.get("quiet", False)) for f in out] == [
        ("outage:1:1", "resolved", True), ("link", "active", False)]
    assert out[1]["title"] == "Keine Netzwerkverbindung" and out[1]["severity"] == "critical"
    # weitere Ausfälle der eigenen Probe sind Folge davon; andere Probes zählen normal
    seq = feed.seq
    feed.accept({"cursor": {"a": 4, "f": 0}, "active": [1, 2, 3, 4], "items": [
        _down(2, role="gateway"), _down(3, alertname="WachtlWanDown"), _down(4, probe="7")]})
    assert [f["finding_id"] for f in feed.since(seq)["findings"]] == ["outage:7:4"]
    # wieder verbunden: einmal „wieder da“; nachträglich gemeldete Ausfälle aus der Zeit bleiben still
    clock[0] = NOW + 130
    seq = feed.seq
    feed.set_link(True)
    feed.set_link(True)
    feed.accept({"cursor": {"a": 5, "f": 0}, "active": [4], "items": [
        _down(5, state="resolved", end=NOW + 120)]})
    out = feed.since(seq)["findings"]
    assert [(f["finding_id"], f["state"]) for f in out] == [("link", "resolved")]
    assert "2 min 10 s" in out[0]["message"]


def test_link_loop_erst_nach_zwei_fehlschlaegen(tmp_path):
    import threading

    from wachtl.serverprobe.probe import ServerProbe

    stop = threading.Event()
    probe = ServerProbe("https://127.0.0.1", "", tmp_path, stop_event=stop)
    answers = iter([True, False])
    calls = []

    def has_route():
        calls.append(1)
        value = next(answers, False)
        if len(calls) >= 4:
            stop.set()
        return value

    probe.stop_event.wait = lambda timeout: stop.is_set()
    probe.link_loop(has_route)
    assert probe.notices.link_down_since is not None


WMI_UP = ('[{"GUID":"{AB-1}","NetConnectionID":"Ethernet","Name":"Intel(R) I219-V","PhysicalAdapter":true,'
          '"NetEnabled":true,"NetConnectionStatus":2,"ConfigManagerErrorCode":0},'
          '{"GUID":"{AB-2}","NetConnectionID":"Ethernet 2","Name":"Realtek","PhysicalAdapter":true,'
          '"NetEnabled":true,"NetConnectionStatus":7,"ConfigManagerErrorCode":0}]')
WMI_DISABLED = ('{"GUID":"{AB-1}","NetConnectionID":"Ethernet","Name":"Intel(R) I219-V","PhysicalAdapter":false,'
                '"NetEnabled":false,"NetConnectionStatus":0,"ConfigManagerErrorCode":22}')


def test_geraete_manager_auslesen():
    from wachtl.serverprobe.adapters import parse_wmi

    up = parse_wmi(WMI_UP)
    assert [(a["id"], a["name"], a["state"]) for a in up] == [("ab-1", "Ethernet", "up"), ("ab-2", "Ethernet 2", "unplugged")]
    assert parse_wmi(WMI_DISABLED)[0]["state"] == "disabled"     # einzelnes Objekt statt Liste
    assert parse_wmi("") == []


def test_netzwerkkarte_deaktiviert_und_wieder_aktiviert():
    from wachtl.serverprobe.adapters import AdapterWatch, parse_wmi

    watch = AdapterWatch()
    assert watch.update(parse_wmi(WMI_UP), NOW) == []          # Start: nur merken
    assert watch.update(None, NOW + 5) == []                     # nicht lesbar: nichts melden
    [f] = watch.update(parse_wmi(WMI_DISABLED), NOW + 10)
    assert (f["kind"], f["severity"], f["state"], f["adapter"]) == ("adapter_disabled", "critical", "active", "Ethernet")
    assert f["title"] == "Netzwerkkarte deaktiviert" and "keine Netzwerkverbindung mehr" in f["message"]
    assert watch.offline_explained
    # „Ethernet 2“ war nie verbunden: kein Hinweis, auch nicht, wenn es fehlt
    [r] = watch.update(parse_wmi(WMI_UP), NOW + 75)
    assert (r["finding_id"], r["state"], r["title"]) == (f["finding_id"], "resolved", "Netzwerkkarte wieder aktiviert")
    assert "1 min 5 s" in r["message"] and r["details"] == {"problem": "Netzwerkkarte deaktiviert"}
    assert not watch.offline_explained


def test_server_tray_zeigt_deaktivierte_karte_statt_ausfaellen(tmp_path):
    import threading

    from wachtl import findings
    from wachtl.serverprobe.adapters import parse_wmi
    from wachtl.serverprobe.probe import ServerProbe

    stop = threading.Event()
    probe = ServerProbe("https://127.0.0.1", "", tmp_path, stop_event=stop)
    probe.notices.own_probe = "1"
    probe.notices.accept({"cursor": {"a": 0, "f": 0}, "items": [], "active": []})
    sent = []
    probe.api = type("FakeApi", (), {"findings": lambda self, items: sent.extend(items) or {}})()
    # Ablauf: verbunden, dann Karte deaktiviert (Route weg), dann wieder aktiviert
    steps = iter([(True, WMI_UP), (False, WMI_DISABLED), (False, WMI_DISABLED), (False, WMI_DISABLED),
                  (True, WMI_UP)])
    current = {}

    def has_route():
        try:
            current["route"], current["wmi"] = next(steps)
        except StopIteration:
            stop.set()
        return current["route"]

    probe.stop_event.wait = lambda timeout: stop.is_set()
    probe.link_loop(has_route, lambda: parse_wmi(current["wmi"]))
    out = probe.notices.since(0)["findings"]
    states = [(f["finding_id"], f["state"]) for f in out]
    assert states == [("local:adapter_disabled:ab-1", "resolved")]        # je finding_id der letzte Stand
    assert out[0]["title"] == "Netzwerkkarte wieder aktiviert"
    assert "link" not in {f["finding_id"] for f in out}                    # kein zweiter, allgemeiner Hinweis
    assert [(f["kind"], f["state"]) for f in sent] == [("adapter_disabled", "active"), ("adapter_disabled", "resolved")]
    for f in sent:                                                          # der Server nimmt sie an
        findings.validate(f, now=f["detected_at"])
    # eigene Hinweise kommen über den Server nicht noch einmal ins Tray
    seq = probe.notices.seq
    probe.notices.accept({"cursor": {"a": 0, "f": 1}, "active": [], "items": [
        {"key": "finding:1", "source": "finding", "id": 1, "alertname": "adapter_disabled", "severity": "critical",
         "state": "firing", "title": "Netzwerkkarte deaktiviert – AFISZ-PC", "text": "", "ts": NOW, "probe_id": "1"}]})
    assert probe.notices.since(seq)["findings"] == []
