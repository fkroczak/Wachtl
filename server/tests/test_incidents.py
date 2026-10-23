"""Störungen: Bündelung gleichzeitiger Ausfälle, Analyse aus den Rohdaten, Dashboard und Detailseite."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from tests.helpers import AppTestCase
from wachtl import repo
from wachtl.db import ins
from wachtl.services import incidents, outages


def outage(start, end, probe="1", target="1.1.1.1", cause="target", site="1", role="target"):
    return outages.Outage(id=0, cause=cause, probe=probe, probe_name=f"PC-{probe}", site=site, site_name="Zentrale",
                          target=target, check_id="1", start=start, end=end, summary="", role=role)


def series(start, end, down=(), lost=(), rtt=10.0, probe="1", check_id="1", target="x", role="target", hop=""):
    """Eine Messreihe im Format von vm.window_series: 1-s-Schritte, ``down`` = Bereich ohne Antwort."""
    labels = {"probe": probe, "probe_name": f"PC-{probe}", "check_id": check_id, "target": target, "role": role}
    if hop:
        labels.update(hop=hop, hop_ip=f"10.0.0.{int(hop)}")
    up, r = {}, {}
    for t in range(start, end):
        miss = any(a <= t < b for a, b in down) or t in lost
        up[t] = 0.0 if miss else 1.0
        if not miss:
            r[t] = rtt
    return (probe, check_id, hop), {"labels": labels, "up": up, "rtt": r, "ips": {labels.get("hop_ip")} - {None}}


class ClusterTest(unittest.TestCase):
    def test_simultaneous_outages_are_one_incident(self):
        now = repo.now()
        items = [outage(now - 1000, now - 990, target="1.1.1.1"), outage(now - 998, now - 985, target="8.8.8.8"),
                 outage(now - 960, now - 950, target="9.9.9.9"),          # 25 s später: noch dieselbe Störung
                 outage(now - 500, now - 495, target="1.1.1.1"),          # eigene Störung
                 outage(now - 999, now - 990, site="2")]                  # anderer Standort
        incs = incidents.cluster(items)
        self.assertEqual(len(incs), 3)
        first = [i for i in incs if i.site == "1" and i.start == now - 1000][0]
        self.assertEqual((first.start, first.end, first.duration), (now - 1000, now - 950, 50))
        self.assertEqual(first.targets, ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        self.assertEqual(incs[0].start, now - 500)   # neueste zuerst

    def test_active_outage_keeps_incident_open(self):
        now = repo.now()
        incs = incidents.cluster([outage(now - 100, None), outage(now - 90, now - 80, target="8.8.8.8")])
        self.assertEqual(len(incs), 1)
        self.assertIsNone(incs[0].end)
        self.assertEqual(incs[0].end_key, 0)

    def test_main_cause_is_highest(self):
        now = repo.now()
        inc = incidents.cluster([outage(now - 100, now - 90, cause="reference", role="reference"),
                                 outage(now - 100, now - 90, cause="wan", target="", role="")])[0]
        self.assertEqual(inc.main.cause, "wan")
        self.assertEqual(incidents.lane_of(inc.items[1]), "reference")

    def test_nice_window(self):
        lo, hi, tick = incidents.nice_window(1000, 1015)
        self.assertLessEqual(lo, 1000 - 30)
        self.assertGreaterEqual(hi, 1015 + 30)
        self.assertEqual((lo % tick, hi % tick), (0, 0))
        self.assertTrue(4 <= (hi - lo) // tick <= 12)


class AnalyzeTest(AppTestCase):
    """Ein 15-s-Ausfall: Gateway und Provider-Gateway antworten, alles im Internet nicht."""

    def setUp(self):
        super().setUp()
        self.now = repo.now() - 3600
        self.core = (self.now, self.now + 15)
        w0, w1, _ = incidents.nice_window(*self.core)
        down = [self.core]
        self.raw = dict([
            series(w0, w1, target="192.168.1.1", role="gateway", check_id="1"),
            series(w0, w1, target="100.64.0.1", role="provider", check_id="2"),
            series(w0, w1, down=down, target="1.1.1.1", role="reference", check_id="3", rtt=12),
            series(w0, w1, down=down, target="8.8.8.8", role="reference", check_id="4"),
            series(w0, w1, down=[(self.now + 2, self.now + 15)], target="81.0.0.1", role="datacenter", check_id="5"),
            series(w0, w1, target="x", check_id="6", hop="01"),
            series(w0, w1, target="x", check_id="6", hop="02"),
            series(w0, w1, down=down, target="x", check_id="6", hop="03"),
            series(w0, w1, down=down, target="x", check_id="6", hop="04"),
            series(w0, w1, down=[(w0, w1)], target="x", check_id="6", hop="05"),   # antwortet nie (ICMP aus)
        ])
        p = mock.patch("wachtl.services.vm.window_series", return_value=self.raw)
        p.start()
        self.addCleanup(p.stop)

    def test_diagnosis_points_behind_provider(self):
        a = incidents.analyze(1, *self.core)
        self.assertEqual(a["step"], 1)
        lanes = {(ln.check_id, ln.hop): ln for ln in a["lanes"]}
        self.assertEqual(lanes[("1", None)].status, "ok")
        self.assertEqual(lanes[("3", None)].status, "down")
        self.assertEqual(lanes[("3", None)].down, [self.core])
        self.assertEqual(lanes[("6", 5)].status, "silent")
        texts = " ".join(t for _, t in a["probes"][0]["findings"])
        self.assertIn("Netz des Providers antwortete, das Internet dahinter nicht", texts)
        self.assertIn("100.64.0.1", texts)
        self.assertIn("ab Hop 3 (10.0.0.3) keine Antwort", texts)
        self.assertIn("zwischen Hop 2 und Hop 3", texts)
        # Reihenfolge der Spuren: Weg nach außen, Hops zuletzt
        roles = [ln.role for ln in a["lanes"] if ln.hop is None]
        self.assertEqual(roles[:2], ["gateway", "provider"])
        self.assertTrue(all(ln.hop is not None for ln in a["lanes"][-5:]))

    def test_gateway_down_is_local(self):
        for key, entry in self.raw.items():
            if entry["labels"]["role"] == "gateway":
                entry["up"] = {t: 0.0 if self.core[0] <= t < self.core[1] else 1.0 for t in entry["up"]}
        texts = " ".join(t for _, t in incidents.analyze(1, *self.core)["probes"][0]["findings"])
        self.assertIn("lokalen Netz", texts)

    def test_runs_and_text(self):
        a = incidents.analyze(1, *self.core)
        ln = next(ln for ln in a["lanes"] if ln.check_id == "3")
        runs = incidents.lane_runs(ln, a["start"], a["end"])
        self.assertEqual([r[2] for r in runs], ["s-ok", "s-down", "s-ok"])
        self.assertTrue(incidents.lane_line(ln, a["start"], a["end"]).startswith("M"))
        from wachtl.web import fmt_duration, fmt_dt
        text = incidents.provider_text("Zentrale", *self.core, a, fmt_dt, fmt_duration)
        self.assertIn("1.1.1.1 [Referenz (Internet)]: 100 % Verlust, keine Antwort", text)
        self.assertIn("(15 s)", text)
        self.assertIn("192.168.1.1 [Gateway]: erreichbar, kein Verlust", text)


class PagesTest(AnalyzeTest):
    def setUp(self):
        super().setUp()
        self.site = self.make_site()
        labels = {"probe": "1", "probe_name": "PC-1", "site": str(self.site), "site_name": "Zentrale",
                  "check_id": "3", "target": "1.1.1.1", "role": "reference"}
        ins("INSERT INTO alert_events (fingerprint, alertname, severity, status, labels, summary, starts_at, ends_at, "
            "updated_at, refined_at) VALUES ('f1', 'WachtlTargetDown', 'critical', 'resolved', ?, 'down', ?, ?, ?, ?)",
            (json.dumps(labels), self.core[0], self.core[1], self.core[1], repo.now()))
        self.make_user()
        self.login()
        for target, value in (("wachtl.services.vm.live_status", {}), ("wachtl.services.vm.loss_lanes",
                                                                         {"reference": [(self.now - 60, 0.25)]})):
            p = mock.patch(target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def test_dashboard_links_to_analysis(self):
        html = self.client.get("/").get_data(as_text=True)
        url = f"/stoerungen/{self.site}/{self.core[0]}/{self.core[1]}"
        self.assertIn(f'<a href="{url}">', html)                  # Liste (Tastatur)
        self.assertIn(f'data-href="{url}"', html)                 # Marke in der Zeitleiste
        self.assertIn('class="h3"', html)                         # 25 % Verlust in der Minute
        self.assertIn("Internet", html)
        self.assertEqual(self.client.get("/?range=7d").status_code, 200)
        self.assertEqual(self.client.get("/?range=quatsch&site=99").status_code, 200)

    def test_incident_page(self):
        html = self.client.get(f"/stoerungen/{self.site}/{self.core[0]}/{self.core[1]}").get_data(as_text=True)
        self.assertIn("Störung am", html)
        self.assertIn("Einordnung", html)
        self.assertIn("Upstream des Providers", html)
        self.assertIn('class="s-down"', html)
        self.assertIn("Für den Provider", html)
        self.assertIn("ausgefallen", html)
        # beliebiger Zeitraum ohne Alarm: Analyse trotzdem möglich
        html = self.client.get(f"/stoerungen/{self.site}/{self.core[0] - 100}/{self.core[0] - 90}").get_data(as_text=True)
        self.assertIn("Zeitraum", html)
        # ungültig
        self.assertEqual(self.client.get(f"/stoerungen/{self.site}/{self.core[1]}/{self.core[0]}").status_code, 404)
        self.assertEqual(self.client.get(f"/stoerungen/99/{self.core[0]}/{self.core[1]}").status_code, 404)

    def test_csv_and_list(self):
        r = self.client.get(f"/stoerungen/{self.site}/{self.core[0]}/{self.core[1]}/daten.csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers["Content-Disposition"])
        body = r.get_data(as_text=True)
        self.assertIn("Zeit;Probe;Ziel;Rolle;Hop", body)
        self.assertIn(";1.1.1.1;Referenz (Internet);;;0;", body)
        html = self.client.get("/stoerungen").get_data(as_text=True)
        self.assertIn(f"/stoerungen/{self.site}/{self.core[0]}/{self.core[1]}", html)
        self.assertIn("1.1.1.1", html)

    def test_vm_down(self):
        from wachtl.services import vm
        with mock.patch("wachtl.services.vm.window_series", side_effect=vm.VMError("weg")):
            html = self.client.get(f"/stoerungen/{self.site}/{self.core[0]}/{self.core[1]}").get_data(as_text=True)
        self.assertIn("nicht abrufbar", html)
        self.assertIn("1.1.1.1", html)   # Ausfälle aus den Alarmen bleiben sichtbar
