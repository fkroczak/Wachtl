import os

import yaml

from wachtl import repo
from wachtl.db import ex
from wachtl.services import alertgen

from .helpers import AppTestCase


class AlertGenTest(AppTestCase):
    def rules(self):
        groups = alertgen.build_rules()["groups"]
        return {g["name"]: g["rules"] for g in groups}

    def test_recording_rules_present(self):
        names = [r["record"] for r in self.rules()["wachtl-recording"]]
        self.assertIn("wachtl:ping_rtt_ms:avg_1m", names)
        self.assertIn("wachtl:ping_loss_ratio_1m", names)
        self.assertIn("wachtl:hop_rtt_ms:quantiles_1m", names)

    def test_target_down_one_rule_per_interval(self):
        repo.create_check("Server", "10.0.0.5", "target", 5, 1000, "all", None)
        alerts = [r for r in self.rules()["wachtl-alerts"] if r["alert"] == "WachtlTargetDown"]
        self.assertEqual(sorted(a["labels"]["interval"] for a in alerts), ["1", "5"])
        # Standard: ab 5 s ohne Antwort. 1-s-Ping = 5 Pings in Folge, 5-s-Ping = mindestens 2 Pings
        one = next(a for a in alerts if a["labels"]["interval"] == "1")
        self.assertIn("[5500ms]", one["expr"])
        self.assertIn(">= 5", one["expr"])
        five = next(a for a in alerts if a["labels"]["interval"] == "5")
        self.assertIn("[12500ms]", five["expr"])
        self.assertIn(">= 2", five["expr"])
        # Unterabfrage: jede Sekunde der letzten 20 s, damit kurze Ausfälle zwischen zwei Auswertungen nicht fehlen
        self.assertTrue(five["expr"].startswith("count_over_time(("))
        self.assertIn(f")[{alertgen.LOOKBACK_S}s:1s]) > 0", five["expr"])

    def test_outage_window(self):
        self.assertEqual(alertgen.outage_window(5, 1), (5, "5500ms"))
        self.assertEqual(alertgen.outage_window(5, 2), (3, "7000ms"))
        self.assertEqual(alertgen.outage_window(5, 60), (2, "150000ms"))
        self.assertEqual(alertgen.outage_window(0, 1), (2, "2500ms"))

    def test_wan_down_uses_seconds_of_slowest_reference(self):
        alerts = {r["alert"]: r for r in self.rules()["wachtl-alerts"]}
        self.assertIn("[5500ms]", alerts["WachtlWanDown"]["expr"])
        self.assertIn('role="reference"', alerts["WachtlWanDown"]["expr"])
        repo.create_check("Quad9", "9.9.9.9", "reference", 5, 1000, "all", None)
        alerts = {r["alert"]: r for r in self.rules()["wachtl-alerts"]}
        self.assertIn("[12500ms]", alerts["WachtlWanDown"]["expr"])

    def test_disabled_rule_and_thresholds(self):
        ex("UPDATE alert_rules SET enabled = FALSE WHERE kind = 'latency_high'")
        ex("UPDATE alert_rules SET threshold = 5 WHERE kind = 'packet_loss_warning'")
        alerts = {r["alert"]: r for r in self.rules()["wachtl-alerts"]}
        self.assertNotIn("WachtlLatencyHigh", alerts)
        self.assertIn("> 5", alerts["WachtlPacketLoss"]["expr"])
        self.assertEqual(alerts["WachtlPacketLoss"]["for"], "60s")
        self.assertEqual(alerts["WachtlWanDown"]["labels"]["cause"], "wan")

    def test_write_rules_creates_valid_yaml(self):
        path = alertgen.write_rules(reload=False)
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertEqual(len(data["groups"]), 2)
