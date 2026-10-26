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

    def test_probe_offline_skips_inactive_probes(self):
        expr = lambda: next(r["expr"] for r in self.rules()["wachtl-alerts"] if r["alert"] == "WachtlProbeOffline")
        self.assertIn("wachtl_probe_last_seen[24h]", expr())
        site = self.make_site()
        self.make_token(site, max_uses=2)
        for host in ("PC-01", "PC-02"):
            self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "tok-1", "hostname": host})
        b = 2
        ex("UPDATE probes SET status = 'disabled' WHERE id = ?", (b,))
        self.assertIn(f'wachtl_probe_last_seen{{probe!~"{b}"}}[24h]', expr())

    def test_outages_not_from_vmalert(self):
        # Ausfälle und jeden Paketverlust erkennt der Server beim Eingang der Rohdaten (services/disturbances.py),
        # auch nachgelieferte – vmalert sähe die zu spät
        repo.create_check("Server", "10.0.0.5", "target", 5, 1000, "all", None)
        alerts = {r["alert"] for r in self.rules()["wachtl-alerts"]}
        self.assertNotIn("WachtlTargetDown", alerts)
        self.assertNotIn("WachtlWanDown", alerts)
        self.assertNotIn("WachtlPacketLossAny", alerts)
        self.assertIn("WachtlPacketLoss", alerts)

    def test_disabled_rule_and_thresholds(self):
        ex("UPDATE alert_rules SET enabled = FALSE WHERE kind = 'latency_high'")
        ex("UPDATE alert_rules SET threshold = 5 WHERE kind = 'packet_loss_warning'")
        alerts = {r["alert"]: r for r in self.rules()["wachtl-alerts"]}
        self.assertNotIn("WachtlLatencyHigh", alerts)
        self.assertIn("> 5", alerts["WachtlPacketLoss"]["expr"])
        self.assertEqual(alerts["WachtlPacketLoss"]["for"], "60s")

    def test_write_rules_creates_valid_yaml(self):
        path = alertgen.write_rules(reload=False)
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertEqual(len(data["groups"]), 2)
