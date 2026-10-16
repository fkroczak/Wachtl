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

    def test_target_down_one_rule_per_interval(self):
        repo.create_check("Server", "10.0.0.5", "target", 5, 1000, "all", None)
        alerts = [r for r in self.rules()["wachtl-alerts"] if r["alert"] == "WachtlTargetDown"]
        self.assertEqual(sorted(a["labels"]["interval"] for a in alerts), ["1", "5"])
        five = next(a for a in alerts if a["labels"]["interval"] == "5")
        self.assertIn("[17500ms]", five["expr"])
        self.assertIn(">= 3", five["expr"])

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
