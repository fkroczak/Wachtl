import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "devtools"))
import fake_vm  # noqa: E402


class FakeVmQuantilesTest(unittest.TestCase):
    """Der Demo-/E2E-Ersatz muss die Graph-Abfragen (Quantile, avg by phi) verstehen."""

    def setUp(self):
        fake_vm.STORE.clear()
        key = ("wachtl_ping_rtt_ms", (("check_id", "2"), ("probe", "1")))
        fake_vm.STORE[key] = [(float(t), float(t)) for t in range(1, 11)]  # Werte 1..10

    def test_raw_and_agg_quantiles(self):
        raw = fake_vm.evaluate('avg by (phi) (quantiles_over_time("phi", 0.1, 0.5, 0.9, '
                               'wachtl_ping_rtt_ms{probe="1",check_id="2"}[60s]))', 10)
        self.assertEqual({k["phi"]: round(v, 2) for k, v in raw}, {"0.1": 1.9, "0.5": 5.5, "0.9": 9.1})
        agg = fake_vm.evaluate('avg by (phi) (avg_over_time(wachtl:ping_rtt_ms:quantiles_1m{probe="1"}[600s]))', 10)
        self.assertEqual(sorted(k["phi"] for k, _ in agg), ["0.1", "0.25", "0.75", "0.9"])
        self.assertEqual(fake_vm.evaluate('avg(avg_over_time(wachtl_hop_rtt_ms{probe="1",hop="01"}[60s]))', 10), [])
