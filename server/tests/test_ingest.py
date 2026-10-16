import time
import unittest

from wachtl.services import ingest

PROBE = {"id": 7, "hostname": "PC-01", "site_id": 2, "site_name": "Zentrale"}
CHECKS = {"3": {"id": 3, "target": "8.8.8.8", "role": "reference"}}


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time() * 1000)

    def test_rewrites_labels_from_server_data(self):
        body = f'wachtl_ping_rtt_ms{{check_id="3",target="evil",probe="99"}} 12.5 {self.now}\n'
        res = ingest.process(body, PROBE, CHECKS, self.now)
        self.assertEqual(res.accepted, 1)
        line = res.lines[0]
        self.assertIn('probe="7"', line)
        self.assertIn('target="8.8.8.8"', line)
        self.assertIn('role="reference"', line)
        self.assertNotIn("evil", line)
        self.assertNotIn('probe="99"', line)

    def test_rejects_unknown_check_metric_and_old_samples(self):
        old = self.now - 9 * 86400 * 1000
        body = "\n".join([
            f'wachtl_ping_rtt_ms{{check_id="4"}} 1 {self.now}',
            f'other_metric{{check_id="3"}} 1 {self.now}',
            f'wachtl_ping_up{{check_id="3"}} 1 {old}',
            f'wachtl_ping_up{{check_id="3"}} NaN {self.now}',
            "kaputt",
            f'wachtl_ping_up{{check_id="3"}} 0 {self.now}',
        ])
        res = ingest.process(body, PROBE, CHECKS, self.now)
        self.assertEqual(res.accepted, 1)
        self.assertEqual(res.reasons, {"check_id": 1, "metric": 1, "timestamp": 1, "value": 1, "format": 1})

    def test_accepts_seconds_timestamp(self):
        res = ingest.process(f'wachtl_ping_up{{check_id="3"}} 1 {self.now // 1000}', PROBE, CHECKS, self.now)
        self.assertEqual(res.accepted, 1)
        self.assertTrue(res.lines[0].endswith(str(self.now // 1000 * 1000)))

    def test_escapes_label_values(self):
        probe = dict(PROBE, site_name='Lager "Nord"')
        res = ingest.process(f'wachtl_ping_up{{check_id="3"}} 1 {self.now}', probe, CHECKS, self.now)
        self.assertIn('site_name="Lager \\"Nord\\""', res.lines[0])

    def test_heartbeat_lines(self):
        lines = ingest.heartbeat_lines(PROBE, 12, 1700000000)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("wachtl_probe_last_seen{"))
        self.assertTrue(lines[0].endswith(" 1700000000 1700000000000"))


if __name__ == "__main__":
    unittest.main()
