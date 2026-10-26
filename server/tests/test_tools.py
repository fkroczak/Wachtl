"""Werkzeuge (docs/WERKZEUGE.md): Eingaben prüfen, Auftrag Web → Probe → Ergebnis, Werkzeuge der Server-Probe."""
import struct
import unittest

from wachtl.db import ex, q1
from wachtl.serverprobe import icmp
from wachtl.serverprobe import tools as probe_tools
from wachtl.services import tools as svc

from .helpers import AppTestCase


class CleanTest(unittest.TestCase):
    def test_valid_and_invalid_input(self):
        self.assertEqual(svc.clean("ping", {"host": "8.8.8.8", "count": "5"})[1]["count"], 5)
        self.assertEqual(svc.clean("port", {"host": "srv", "ports": "443; 80 443"})[1]["ports"], [443, 80])
        self.assertEqual(svc.clean("http", {"url": "portal.kunde.de/login"})[0], "https://portal.kunde.de/login")
        target, args = svc.clean("dns", {"name": "192.168.1.10", "type": "A"})
        self.assertEqual((target, args["type"]), ("10.1.168.192.in-addr.arpa", "PTR"))
        for tool, form in (("ping", {"host": "8.8.8.8; rm -rf /"}), ("ping", {"host": "x", "count": "1000"}),
                           ("mtu", {"host": "x", "min": "1500", "max": "1400"}), ("port", {"host": "x", "ports": "0"}),
                           ("http", {"url": "ftp://x"}), ("dns", {"name": "x", "type": "ANY"}), ("rdp", {"host": "x"}),
                           ("dns", {"name": "x", "server": "dns.google"})):
            with self.assertRaises(svc.ToolError, msg=(tool, form)):
                svc.clean(tool, form)


class JobFlowTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.probe = self.enroll()
        self.auth = {"Authorization": f"Bearer {self.probe['token']}"}
        self.make_user()
        self.make_user("leser", "readonly")

    def start(self, **form):
        self.login()
        csrf = self.csrf_token()
        return self.client.post("/werkzeuge/start", json={"probe": self.probe["probe_id"], **form},
                                headers={"X-CSRF-Token": csrf})

    def csrf_token(self):
        import re

        html = self.client.get("/werkzeuge").get_data(as_text=True)
        return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)

    def test_start_take_progress_result(self):
        html = self.client.get("/werkzeuge").get_data(as_text=True)
        self.assertIn("/login", html)               # nicht angemeldet → Anmeldung
        r = self.start(tool="ping", host="8.8.8.8", count="3")
        self.assertEqual(r.status_code, 201, r.get_json())
        job = r.get_json()["job"]
        self.assertEqual((job["status"], job["label"], job["ahead"]), ("queued", "Ping", 0))
        page = self.client.get("/werkzeuge").get_data(as_text=True)
        for text in ("Werkzeuge", "Traceroute", "Zertifikat", "PC-01", "8.8.8.8"):
            self.assertIn(text, page)

        # Heartbeat meldet den wartenden Test, die Probe holt ihn ab
        hb = self.client.post("/api/probe/v1/heartbeat", json={"version": "1"}, headers=self.auth).get_json()
        self.assertEqual(hb["tools_pending"], 1)
        got = self.client.get("/api/probe/v1/tools/next", headers=self.auth).get_json()["job"]
        self.assertEqual((got["tool"], got["args"]["host"], got["args"]["count"]), ("ping", "8.8.8.8", 3))
        self.assertIsNone(self.client.get("/api/probe/v1/tools/next", headers=self.auth).get_json()["job"])

        # Fortschritt, dann Ergebnis
        url = f"/api/probe/v1/tools/{got['id']}"
        self.assertEqual(self.client.post(url, json={"progress": 0.5, "step": "Paket 2 von 3", "lines": ["a", "b"]},
                                          headers=self.auth).status_code, 200)
        view = self.client.get(f"/werkzeuge/auftrag/{got['id']}").get_json()["job"]
        self.assertEqual((view["status"], view["progress"], view["step"], view["output"]),
                         ("running", 0.5, "Paket 2 von 3", "a\nb"))
        result = {"headline": "Alle Pakete beantwortet", "verdict": "ok", "stats": {"sent": 3, "received": 3, "loss": 0},
                  "summary": [["Ziel", "<b>8.8.8.8</b>", "good"], ["x"]], "table": {"head": ["a"], "rows": [["1"]]}}
        self.client.post(url, json={"done": True, "ok": True, "result": result, "lines": ["c"]}, headers=self.auth)
        view = self.client.get(f"/werkzeuge/auftrag/{got['id']}").get_json()["job"]
        self.assertEqual(view["status"], "ok")
        self.assertEqual(view["result"]["summary"], [["Ziel", "<b>8.8.8.8</b>", "good"]])   # Text, das UI escaped
        self.assertEqual(view["output"], "a\nb\nc")
        # beendet: weitere Meldungen werden abgewiesen
        self.assertEqual(self.client.post(url, json={"progress": 1}, headers=self.auth).status_code, 409)
        # fremde Probe darf den Auftrag nicht melden
        token = self.make_token(self.make_site("Filiale"), "tok-2")
        other = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": token, "hostname": "PC-02",
                                                               "os": "Windows 11", "version": "1"}).get_json()
        self.assertEqual(self.client.post(url, json={"progress": 1},
                                          headers={"Authorization": f"Bearer {other['token']}"}).status_code, 409)

    def test_errors_rights_and_expiry(self):
        r = self.start(tool="ping", host="nicht gültig!")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Hostname", r.get_json()["error"])
        # Nur-lesen darf keine Tests starten
        self.client.post("/logout", data={"csrf_token": self.csrf_token()})
        self.login("leser")
        r = self.client.post("/werkzeuge/start", json={"probe": self.probe["probe_id"], "tool": "ping", "host": "1.1.1.1"},
                             headers={"X-CSRF-Token": self.csrf_token()})
        self.assertEqual(r.status_code, 403)
        self.assertIn("Tests starten dürfen", self.client.get("/werkzeuge").get_data(as_text=True))
        # nie abgeholt → nach 5 Minuten Fehler
        self.client.post("/logout", data={"csrf_token": self.csrf_token()})
        job_id = self.start(tool="trace", host="1.1.1.1").get_json()["job"]["id"]
        ex("UPDATE tool_jobs SET created_at = created_at - 400 WHERE id = ?", (job_id,))
        view = self.client.get(f"/werkzeuge/auftrag/{job_id}").get_json()["job"]
        self.assertEqual(view["status"], "error")
        self.assertIn("nicht abgeholt", view["error"])

    def test_one_job_at_a_time(self):
        a = self.start(tool="ping", host="1.1.1.1").get_json()["job"]["id"]
        b = self.start(tool="ping", host="8.8.8.8").get_json()["job"]
        self.assertEqual(b["ahead"], 1)
        self.assertEqual(self.client.get("/api/probe/v1/tools/next", headers=self.auth).get_json()["job"]["id"], a)
        self.assertIsNone(self.client.get("/api/probe/v1/tools/next", headers=self.auth).get_json()["job"])
        self.client.post(f"/api/probe/v1/tools/{a}", json={"done": True, "ok": False, "error": "x"}, headers=self.auth)
        self.assertEqual(self.client.get("/api/probe/v1/tools/next", headers=self.auth).get_json()["job"]["id"], b["id"])


class FakePinger:
    """Antwortet bis zur MTU ``mtu`` (DF), Router bis TTL ``hops``-1, danach das Ziel."""

    def __init__(self, mtu=1492, hops=3, lose=()):
        self.mtu, self.hops, self.lose, self.n = mtu, hops, set(lose), 0

    def __call__(self, ip, timeout, size, ttl, df=False):
        self.n += 1
        if self.n in self.lose:
            return icmp.Reply(False, error="TimedOut")
        if df and size + 28 > self.mtu:
            return icmp.Reply(False, error="PacketTooBig")
        if ttl < self.hops:
            return icmp.Reply(False, 1.0 * ttl, source=f"10.0.0.{ttl}", ttl_expired=True, error="TtlExpired")
        return icmp.Reply(True, 12.5, 57, ip)


def run(fn, args, **kw):
    steps = []
    ok, result, err = fn(args, lambda **r: steps.append(r), **kw)
    return ok, result, err, steps


class ServerProbeToolsTest(unittest.TestCase):
    def test_ping_counts_loss(self):
        ok, res, _err, steps = run(probe_tools.tool_ping, {"host": "8.8.8.8", "count": 4, "size": 32, "interval": 0.2},
                                   pinger=FakePinger(lose={2}), sleep=lambda s: None)
        self.assertTrue(ok)
        self.assertEqual((res["stats"]["sent"], res["stats"]["received"], res["stats"]["loss"]), (4, 3, 25.0))
        self.assertEqual(res["verdict"], "warn")
        self.assertEqual(steps[-1]["progress"], 1.0)
        self.assertIn("Paket 2 von 4: Zeitüberschreitung", [s.get("step") for s in steps])

    def test_mtu_finds_pppoe(self):
        ok, res, _err, _steps = run(probe_tools.tool_mtu, {"host": "8.8.8.8", "min": 576, "max": 1500, "tries": 1},
                                    pinger=FakePinger(mtu=1492))
        self.assertTrue(ok)
        self.assertEqual(res["headline"], "Pfad-MTU 1492 Byte")
        self.assertIn(["Einordnung", "PPPoE (DSL)", ""], res["summary"])

    def test_trace_lists_hops(self):
        ok, res, _err, _steps = run(probe_tools.tool_trace, {"host": "8.8.8.8", "max_hops": 10, "count": 2, "names": False},
                                    pinger=FakePinger(hops=3))
        self.assertTrue(ok)
        self.assertEqual([r[1] for r in res["table"]["rows"]], ["10.0.0.1", "10.0.0.2", "8.8.8.8"])
        self.assertEqual(res["headline"], "Ziel erreicht – 3 Hops")

    def test_dns_wire_format(self):
        qid, query = probe_tools.dns_query("kunde.de", 15)
        msg = bytearray(query)
        msg[2:4], msg[6:8] = b"\x81\x80", b"\x00\x01"
        msg += b"\xc0\x0c\x00\x0f\x00\x01" + struct.pack("!IH", 3600, 9) + b"\x00\x0a\x04mail\xc0\x0c"
        res = probe_tools.dns_parse(bytes(msg), qid)
        self.assertEqual(res["answers"][0]["data"], "10 mail.kunde.de.")
        ok, out, _err, _steps = run(probe_tools.tool_dns, {"name": "kunde.de", "type": "MX", "server": ""},
                                    ask=lambda s, n, t: probe_tools.dns_parse(bytes(msg), qid),
                                    resolvers=lambda: ["192.168.1.1"])
        self.assertTrue(ok)
        self.assertEqual(out["headline"], "1 Eintrag")
        self.assertEqual(out["table"]["rows"], [["kunde.de.", "MX", "3600", "10 mail.kunde.de."]])

    def test_run_reports_errors(self):
        sent = []
        probe_tools.run({"id": 1, "tool": "unbekannt", "args": {}}, sent.append)
        self.assertEqual((sent[-1]["done"], sent[-1]["ok"]), (True, False))
        self.assertIn("nicht unterstützt", sent[-1]["error"])
