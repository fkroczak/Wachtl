"""PDF-Bericht: Datensammlung, Einschätzung, Darstellung kurzer Ausfälle und die Routen /bericht(.pdf)."""
from __future__ import annotations

import base64
import json
import re
import sys
import types
import uuid
import zlib
from unittest import mock

from reportlab.graphics.shapes import Rect

from wachtl import repo
from wachtl.db import ins, q
from wachtl.services import report_data, report_pdf, vm

from .helpers import AppTestCase
from .test_ui_quality import lint

DAY = 86400


def pdf_text(pdf: bytes) -> str:
    """Grobe Textsuche im PDF: alle (komprimierten) Inhaltsströme entpacken."""
    out = []
    for m in re.finditer(rb"stream\r?\n(.*?)\s*endstream", pdf, re.S):
        raw = m.group(1).strip()
        try:
            if raw.endswith(b"~>"):   # reportlab: ASCII85 + Flate
                raw = base64.a85decode(raw[:-2])
            raw = zlib.decompress(raw)
        except (ValueError, zlib.error):
            pass
        out.append(raw.decode("latin-1"))
    out.append(re.sub(rb"stream\r?\n.*?endstream", b"", pdf, flags=re.S).decode("latin-1"))  # z. B. Links
    text = "\n".join(out)
    # Zeichenketten der Schrift (WinAnsi): \ddd oktal, \( \) \\ maskiert
    text = re.sub(r"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8)]).decode("cp1252", "replace"), text)
    return re.sub(r"\\([()\\])", r"\1", text)


class ReportBase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.now = repo.now()
        self.site = ins("INSERT INTO sites (name, customer_no, created_at) VALUES (?, ?, ?)",
                        ("Zentrale München", "K-1", self.now - 60 * DAY))
        self.p1 = self.probe("EMPFANG-PC")
        self.p2 = self.probe("BUCHHALTUNG")
        # Messdatenbank standardmäßig nicht erreichbar; einzelne Tests liefern Messreihen per Mock
        for name in ("report_ping_series", "report_hop_table", "up_samples"):
            p = mock.patch.object(vm, name, side_effect=vm.VMError("nicht erreichbar"))
            p.start()
            self.addCleanup(p.stop)

    def probe(self, host: str, site: int | None = None) -> int:
        return ins("INSERT INTO probes (site_id, hostname, token_hash, status, created_at, last_seen) "
                   "VALUES (?, ?, ?, 'active', ?, ?)", (site or self.site, host, uuid.uuid4().hex,
                                                         self.now - 60 * DAY, self.now))

    def event(self, alertname: str, probe: int, start: int, dur: int, role: str = "", target: str = "",
              check: str = "", site: int | None = None, exact: bool = True) -> int:
        host = q("SELECT hostname FROM probes WHERE id = ?", (probe,))[0]["hostname"]
        labels = {"probe": str(probe), "probe_name": host, "site": str(site or self.site),
                  "site_name": "Zentrale München", "check_id": check, "target": target, "role": role}
        # Alarm meldet spät und endet spät; die Rohdaten (exact_*) zeigen die echte Dauer
        return ins(
            "INSERT INTO alert_events (fingerprint, alertname, severity, status, labels, summary, starts_at, ends_at, "
            "updated_at, exact_start, exact_end, refined_at) "
            "VALUES (?, ?, 'critical', 'resolved', ?, ?, ?, ?, ?, ?, ?, ?)",
            (uuid.uuid4().hex, alertname, json.dumps(labels), alertname, start + 15, start + dur + 20, self.now,
             start if exact else None, start + dur if exact else None, self.now))

    def wan(self, start: int, dur: int, probes=None) -> None:
        for p in probes or (self.p1, self.p2):
            self.event("WachtlWanDown", p, start, dur)
            self.event("WachtlTargetDown", p, start, dur, "reference", "8.8.8.8", "2")

    def finding(self, probe: int, kind: str, ts: int) -> None:
        ins("INSERT INTO client_findings (probe_id, site_id, finding_id, kind, severity, state, adapter, title, "
            "message, details, detected_at, resolved_at, received_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'critical', 'resolved', 'Ethernet', 'Kabel', 'Kabel getrennt', '{}', ?, ?, ?, ?)",
            (probe, self.site, uuid.uuid4().hex, kind, ts, ts + 30, ts, ts))

    def user_report(self, probe: int, ts: int, text: str = "Internet weg") -> None:
        ins("INSERT INTO incident_reports (probe_id, site_id, report_id, occurred_at, received_at, category, duration, "
            "description, reported_user, hostname, status) VALUES (?, ?, ?, ?, ?, 'dropouts', 'short', ?, 'mm', ?, "
            "'open')", (probe, self.site, uuid.uuid4().hex, ts, ts, text, "PC"))

    def series(self, internet_loss_at: int | None = None, gateway_loss: bool = False):
        """Messreihen-Mock: Gateway sauber (oder mit Verlust), Internet mit Verlust in einem Abschnitt."""
        def fake(probe_id, start, end, step):
            out = {}
            for cid, role, target, base in (("1", "gateway", "gateway", 0.5), ("2", "reference", "8.8.8.8", 12.0),
                                            ("3", "reference", "1.1.1.1", 10.0)):
                s = {k: [] for k in ("avg", "max", "p10", "p90", "loss", "loss_max", "jitter", "loss_minutes",
                                     "lost_s")}
                for ts in range(start + step, end + 1, step):
                    hit = internet_loss_at is not None and ts - step < internet_loss_at <= ts
                    loss = 5.0 if hit and (role == "reference" or gateway_loss) else 0.0
                    s["avg"].append((ts, base))
                    s["max"].append((ts, base * 2))
                    s["p10"].append((ts, base * 0.9))
                    s["p90"].append((ts, base * 1.2))
                    s["loss"].append((ts, loss))
                    s["loss_max"].append((ts, loss * 2))
                    s["jitter"].append((ts, 1.0))
                    s["loss_minutes"].append((ts, 3 if loss else 0))
                    s["lost_s"].append((ts, 9 if loss else 0))
                out[cid] = {"role": role, "target": target, "series": s}
            return out
        return mock.patch.object(vm, "report_ping_series", side_effect=fake)


class ReportDataTest(ReportBase):
    def test_format(self):
        self.assertEqual(report_data.fmt_dur(5), "5 s")
        self.assertEqual(report_data.fmt_dur(133), "2 min 13 s")
        self.assertEqual(report_data.fmt_dur(3900), "1 h 05 min")
        self.assertEqual(report_data.fmt_num(0.256, "%"), "0,26 %")
        self.assertEqual(report_pdf.clean("a → b ≥ c ✓ ü € –"), "a -> b >= c ok ü € –")

    def test_cluster_joins_overlapping_and_close_outages(self):
        def o(site, start, dur, cause="wan", probe="1"):
            return {"site": site, "site_name": "S", "start": start, "duration": dur, "cause": cause,
                    "cause_label": cause, "consequence_of": None, "probe": probe, "probe_name": f"P{probe}",
                    "target": "", "ongoing": False, "a": start, "b": start + dur}
        items = [o("1", 100, 5), o("1", 103, 10, "reference"), o("1", 170, 5), o("1", 300, 5), o("2", 100, 5)]
        inc = report_data.cluster(items)
        self.assertEqual([(i["site"], i["start"], i["span"], i["duration"], i["parts"]) for i in inc],
                         [("1", 100, 75, 18, 2), ("2", 100, 5, 5, 1), ("1", 300, 5, 5, 1)])
        self.assertEqual(inc[0]["cause"], "wan")
        self.assertTrue(all(i["short"] for i in inc))   # kurze Aussetzer bleiben kurz

    def test_short_outage_is_counted_and_provider_verdict(self):
        t = self.now - 2 * DAY
        self.wan(t, 5)                          # 5-s-Ausfall an beiden PCs zugleich
        self.wan(t + 3600, 95)
        self.wan(t + 7200, 12)
        self.user_report(self.p1, t + 20)
        with self.series(internet_loss_at=t + 10 * 3600), \
                mock.patch.object(vm, "report_hop_table", return_value={}):
            data = report_data.collect(self.site, self.now - 7 * DAY, self.now)
        inc = data["incidents"]
        self.assertEqual(len(inc), 3)
        first = inc[0]
        self.assertEqual((first["start"], first["duration"], first["cause"]), (t, 5, "wan"))
        self.assertTrue(first["short"])
        self.assertEqual(first["probes"], ["BUCHHALTUNG", "EMPFANG-PC"])
        self.assertEqual(first["consequences"], 2)   # Referenz 8.8.8.8 an beiden PCs = Folge
        k = data["kpis"]
        self.assertEqual((k["incidents"], k["short"], k["severe"], k["down_s"]), (3, 2, 3, 112))
        self.assertLess(k["availability"], 100)
        self.assertEqual(k["longest"]["duration"], 95)
        self.assertEqual(data["verdict"]["key"], "provider")
        self.assertIn(data["verdict"]["confidence"], ("hoch", "mittel"))
        self.assertTrue(any("Gateway war dabei erreichbar" in b for b in data["verdict"]["bullets"]))
        # Schwankung: Internet mit Verlust, Gateway sauber -> Provider
        an = data["quality"][0]["anomalies"]
        self.assertTrue(an)
        self.assertEqual((an[0]["where"], an[0]["gw_state"]), ("provider", "sauber"))
        self.assertEqual(data["quality"][0]["internet_stats"]["loss_minutes"], 3)
        # Zeitstrahl enthält den 5-s-Ausfall, die Meldung und den Tag
        self.assertIn({"lane": "wan", "a": t, "b": t + 5, "consequence": False}, data["timeline"]["items"])
        self.assertEqual(data["timeline"]["reports"], [t + 20])
        self.assertEqual(sum(d["count"] for d in data["daily"]), 3)
        self.assertEqual(sum(data["hours"]), 3)

    def test_gateway_outage_on_all_pcs_points_to_lan(self):
        t = self.now - DAY
        for i in range(3):
            for p in (self.p1, self.p2):
                self.event("WachtlTargetDown", p, t + i * 3600, 40, "gateway", "gateway", "1")
                self.event("WachtlWanDown", p, t + i * 3600 + 1, 38)
        data = report_data.collect(self.site, self.now - 7 * DAY, self.now)
        self.assertEqual(data["verdict"]["key"], "lan")
        self.assertEqual(len(data["incidents"]), 3)
        self.assertEqual(data["incidents"][0]["cause"], "gateway")
        self.assertFalse(data["vm_ok"])
        self.assertTrue(data["notes"])

    def test_single_pc_with_cable_findings_points_to_pc(self):
        t = self.now - DAY
        for i in range(3):
            self.event("WachtlTargetDown", self.p2, t + i * 3600, 30, "gateway", "gateway", "1")
            self.finding(self.p2, "cable_unplugged", t + i * 3600)
        data = report_data.collect(self.site, self.now - 7 * DAY, self.now)
        self.assertEqual(data["verdict"]["key"], "pc")
        self.assertEqual(data["kpis"]["down_s"], 0)          # der andere PC kam ins Internet
        self.assertEqual(data["kpis"]["availability"], 100)
        self.assertEqual(len(data["findings"]), 3)
        self.assertTrue(all(f["customer_side"] for f in data["findings"]))

    def test_quiet_period_and_vm_down(self):
        data = report_data.collect(None, self.now - DAY, self.now)
        self.assertEqual(data["verdict"]["key"], "none")
        self.assertEqual(data["incidents"], [])
        self.assertEqual(data["meta"]["site_label"], "Alle Standorte")
        pdf = report_pdf.render(data)
        self.assertTrue(pdf.startswith(b"%PDF"))
        text = pdf_text(pdf)
        self.assertIn("Keine erheblichen Störungen", text)
        self.assertIn("Keine Störungen im Zeitraum.", text)

    def test_lan_anomaly_when_gateway_also_bad(self):
        t = self.now - DAY
        with self.series(internet_loss_at=t, gateway_loss=True):
            data = report_data.collect(self.site, self.now - 2 * DAY, self.now)
        an = data["quality"][0]["anomalies"]
        self.assertEqual(an[0]["where"], "lan")

    def test_other_sites_are_left_out(self):
        other = ins("INSERT INTO sites (name, created_at) VALUES (?, ?)", ("Filiale", self.now - 60 * DAY))
        op = self.probe("FILIALE-PC", other)
        self.event("WachtlWanDown", op, self.now - DAY, 50, site=other)
        self.assertEqual(report_data.collect(self.site, self.now - 7 * DAY, self.now)["incidents"], [])
        both = report_data.collect(None, self.now - 7 * DAY, self.now)
        self.assertEqual(len(both["incidents"]), 1)
        self.assertEqual(len(both["site_verdicts"]), 2)

    def test_netscan_section_optional(self):
        section = {"runs": 2, "last_scan": self.now, "devices": [
            {"id": 1, "site_name": "Zentrale München", "ip": "192.168.1.9", "mac": "AA:BB", "hostname": "rep",
             "vendor": "TP-Link", "label": "Repeater", "first_seen": self.now - DAY, "last_seen": self.now,
             "online": True, "returns": 7, "flags": ["irregular", "new"],
             "services": [{"port": 80, "service": "http", "label": "HTTP", "url": "http://192.168.1.9"}]}],
            "events": [{"ts": self.now, "kind": "ip_conflict", "kind_label": "IP-Konflikt", "ip": "192.168.1.9",
                        "detail": "zwei MAC", "device_label": "Repeater", "site_name": "Zentrale München"}]}
        fake = types.ModuleType("wachtl.services.netscan")
        fake.report_section = mock.Mock(return_value=section)
        with mock.patch.dict(sys.modules, {"wachtl.services.netscan": fake}), \
                mock.patch("wachtl.services.netscan", fake, create=True):
            data = report_data.collect(self.site, self.now - DAY, self.now, ["netzwerk"])
        fake.report_section.assert_called_once_with(self.site, self.now - DAY, self.now)
        self.assertEqual(data["netscan"]["devices"][0]["returns"], 7)
        text = pdf_text(report_pdf.render(data))
        self.assertIn("Repeater", text)
        self.assertIn("http://192.168.1.9", text)
        # ohne Abschnitt kein Aufruf
        fake.report_section.reset_mock()
        with mock.patch.dict(sys.modules, {"wachtl.services.netscan": fake}):
            report_data.collect(self.site, self.now - DAY, self.now, ["stoerungen"])
        fake.report_section.assert_not_called()


class ReportPdfTest(ReportBase):
    def test_five_second_outage_visible_in_30_day_timeline(self):
        t = self.now - 10 * DAY
        self.wan(t, 5)
        data = report_data.collect(self.site, self.now - 30 * DAY, self.now)
        d = report_pdf.timeline_drawing(data)
        red = [s for s in d.contents if isinstance(s, Rect) and s.fillColor is not None
               and s.fillColor.hexval() == report_pdf.BAD.hexval()]
        self.assertEqual(len(red), 2)                   # je PC ein Balken
        self.assertTrue(all(r.width >= report_pdf.MIN_W for r in red))

    def test_full_report_renders(self):
        t = self.now - 3 * DAY
        self.wan(t, 5)
        self.event("WachtlTargetDown", self.p1, t + 600, 300, "target", "fileserver", "9")
        self.event("WachtlPacketLossCritical", self.p1, t + 900, 400, "reference", "1.1.1.1", "3")
        self.event("WachtlPacketLossAny", self.p2, t + 5000, 2, "reference", "8.8.8.8", "2")  # einzelner verlorener Ping
        self.finding(self.p2, "link_flapping", t)
        self.user_report(self.p1, t + 10, "Teams <b>bricht</b> ab")
        hops = [{"hop": 1, "ip": "192.168.1.1"}, {"hop": 2, "ip": "62.155.1.1"}, {"hop": 3, "ip": "1.1.1.1"}]
        ins("INSERT INTO path_runs (probe_id, check_id, first_ts, ts, reason, reached, hops, path_hash, changed) "
            "VALUES (?, 7, ?, ?, 'schedule', TRUE, ?, 'h1', FALSE)", (self.p1, t - DAY, self.now, json.dumps(hops)))
        ins("INSERT INTO bandwidth_runs (probe_id, check_id, ts, kind, direction, mbps, trigger) "
            "VALUES (?, 8, ?, 'speedtest', 'down', 95.5, 'schedule')", (self.p1, t))
        ins("INSERT INTO rtp_runs (probe_id, check_id, ts, mos, loss_pct, jitter_ms, rtt_ms) "
            "VALUES (?, 9, ?, 3.2, 1.5, 12, 30)", (self.p1, t))
        table = {1: {"ip": "192.168.1.1", "loss": 0.0, "avg": 0.5, "max": 2, "jitter": 0.1, "other_ips": []},
                 2: {"ip": "62.155.1.1", "loss": 6.0, "avg": 9.0, "max": 30, "jitter": 2, "other_ips": []},
                 3: {"ip": "1.1.1.1", "loss": 6.5, "avg": 10.0, "max": 40, "jitter": 2, "other_ips": []}}
        with self.series(internet_loss_at=t), mock.patch.object(vm, "report_hop_table", return_value=table):
            data = report_data.collect(self.site, self.now - 7 * DAY, self.now,
                                       meta={"customer": "Muster GmbH", "author": "Techniker",
                                             "remark": "Ticket 4711 → bitte prüfen"})
        self.assertEqual(data["paths"][0]["loss_origin"]["hop"], 2)
        self.assertEqual(data["paths"][0]["loss_origin"]["where"], "provider")
        self.assertEqual(data["bandwidth"][0]["stats"]["count"], 1)
        self.assertEqual(data["voice"][0]["below"], 1)
        loss = [o for o in data["outages"] if o["cause"] == "loss"]
        self.assertEqual(loss[0]["role"], "reference")
        pdf = report_pdf.render(data, invariant=True)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 10000)
        text = pdf_text(pdf)
        for needle in ("Internetanschluss / Provider", "Muster GmbH", "Ticket 4711 -", "bitte prüfen", "Zeitstrahl",
                       "Pfadanalyse", "Verlust beginnt ab Hop 2 (62.155.1.1)", "5 s", "kurz", "Anhang",
                       "fileserver", "bricht", "Seite 1 von"):
            self.assertIn(needle, text, needle)
        self.assertEqual(report_pdf.render(data, invariant=True), pdf)   # reproduzierbar

    def test_incident_list_is_capped(self):
        start = self.now - 20 * DAY
        rows = []
        for i in range(report_data.MAX_INCIDENTS + 5):
            rows.append(self.event("WachtlWanDown", self.p1, start + i * 600, 5))
        data = report_data.collect(self.site, self.now - 30 * DAY, self.now, ["stoerungen"])
        self.assertEqual(len(data["incidents"]), report_data.MAX_INCIDENTS + 5)
        text = pdf_text(report_pdf.render(data))
        self.assertIn("Liste gekürzt", text)


class ReportRouteTest(ReportBase):
    def setUp(self):
        super().setUp()
        self.make_user("leser", "readonly")

    def test_requires_login(self):
        for url in ("/bericht", "/bericht.pdf"):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 302, url)
            self.assertIn("/login", r.headers["Location"])

    def test_form_page(self):
        self.login("leser")
        r = self.client.get("/bericht")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("PDF erstellen", html)
        self.assertIn("Zentrale München", html)
        self.assertIn('value="leser"', html)          # Erstellt von = angemeldeter Benutzer
        self.assertEqual(lint(html), [])
        # von/bis serverseitig ausgeblendet, solange kein eigener Zeitraum gewählt ist
        self.assertRegex(html, r'data-show-if="range:custom"[^>]*hidden')

    def test_pdf_download_for_readonly(self):
        self.wan(self.now - 3600, 5)
        self.login("leser")
        r = self.client.get(f"/bericht.pdf?site={self.site}&range=24h&kunde=Muster&teile=1&teil_stoerungen=1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "application/pdf")
        day = __import__("datetime").datetime.fromtimestamp(self.now).strftime("%Y%m%d")
        self.assertEqual(r.headers["Content-Disposition"],
                         f'attachment; filename="Wachtl-Bericht-Zentrale-Muenchen-{day}.pdf"')
        self.assertTrue(r.data.startswith(b"%PDF"))
        text = pdf_text(r.data)
        self.assertIn("Muster", text)
        self.assertNotIn("Pfadanalyse", text)          # nur gewählte Teile
        audit = q("SELECT * FROM audit_log WHERE action = 'report.pdf'")
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["username"], "leser")
        self.assertEqual(audit[0]["object"], f"site:{self.site}")

    def test_all_sites_and_custom_period(self):
        self.login("leser")
        r = self.client.get("/bericht.pdf?range=custom&von=2026-01-01T00:00&bis=2026-01-08T12:30")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Alle-Standorte", r.headers["Content-Disposition"])

    def test_invalid_input(self):
        self.login("leser")
        cases = {
            "range=custom": "Von: bitte Datum",
            "range=custom&von=2026-02-01T00:00&bis=2026-01-01T00:00": "Bis muss nach Von",
            "range=custom&von=2024-01-01T00:00&bis=2025-06-01T00:00": "höchstens 400 Tage",
            "site=999": "Diesen Standort gibt es nicht",
            "site=abc": "Diesen Standort gibt es nicht",
        }
        for query, message in cases.items():
            r = self.client.get(f"/bericht.pdf?{query}")
            self.assertEqual(r.status_code, 400, query)
            html = r.get_data(as_text=True)
            self.assertIn(message, html, query)
            self.assertIn('aria-invalid="true"', html)
            self.assertEqual(lint(html), [], query)
        self.assertEqual(q("SELECT * FROM audit_log WHERE action = 'report.pdf'"), [])

    def test_user_text_is_sanitized(self):
        self.login("leser")
        r = self.client.get("/bericht.pdf?range=24h&bemerkung=" + "x" * 2000 + "%00%07&ersteller=A%0B%0CB")
        self.assertEqual(r.status_code, 200)
        text = pdf_text(r.data)
        self.assertIn("x" * 50, text)
        self.assertNotIn("x" * 1001, text)
