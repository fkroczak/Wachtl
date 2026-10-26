"""Störungen aus den Rohdaten: nachgelieferte Ausfälle, jeder verlorene Ping, WAN, Meldung an Alertmanager."""
import json
import time
from unittest import mock

from wachtl.db import ex, q, q1
from wachtl.services import alerts as alert_service
from wachtl.services import checkstatus, disturbances, outages

from .helpers import AppTestCase


class DisturbanceTest(AppTestCase):
    def setUp(self):
        super().setUp()
        self.data = self.enroll()
        self.headers = {"Authorization": f"Bearer {self.data['token']}"}
        cfg = self.client.get("/api/probe/v1/config", headers=self.headers).get_json()
        self.pings = {c["target"]: c["id"] for c in cfg["checks"] if c["type"] == "ping"}
        self.batch = 0

    def send(self, start_s: int, ups: dict[str, list[int]]):
        """Je Ziel eine Folge von Ping-Ergebnissen (1/0) im Sekundentakt ab start_s hochladen."""
        lines = []
        for target, values in ups.items():
            for i, v in enumerate(values):
                lines.append(f'wachtl_ping_up{{check_id="{self.pings[target]}"}} {v} {(start_s + i) * 1000}')
        self.batch += 1
        r = self.client.post("/api/probe/v1/ingest", data="\n".join(lines),
                             headers={**self.headers, "X-Batch-Id": f"b-{self.batch}"})
        self.assertEqual(r.status_code, 204)

    def rows(self, kind=None):
        sql, params = "SELECT * FROM disturbances", ()
        if kind:
            sql, params = sql + " WHERE kind = ?", (kind,)
        return q(sql + " ORDER BY id", params)

    def test_buffered_outage_is_detected_late(self):
        # PC 10 min ohne Netz gewesen: Gateway und alle Referenzen 30 s ohne Antwort, Werte kommen erst jetzt
        t0 = int(time.time()) - 600
        series = [1] * 10 + [0] * 30 + [1] * 20
        self.send(t0, {t: series for t in self.pings})
        downs = self.rows("down")
        self.assertEqual(len(downs), 4)
        self.assertTrue(all(d["start_ts"] == t0 + 10 and d["end_ts"] == t0 + 40 for d in downs))
        self.assertTrue(all(d["late"] for d in downs))
        wan = self.rows("wan")
        self.assertEqual([(w["start_ts"], w["end_ts"]) for w in wan], [(t0 + 10, t0 + 40)])
        self.assertEqual(self.rows("loss"), [])
        # Ausfallübersicht: Gateway ist die Ursache, Internet und Ziele sind Folgen
        items = outages.load(t0 - 60)
        self.assertEqual([o.cause for o in items], ["gateway"])
        self.assertEqual((items[0].start, items[0].end), (t0 + 10, t0 + 40))
        self.assertIn("nachträglich erkannt", items[0].summary)
        self.assertEqual(len(outages.load(t0 - 60, include_consequences=True)), 5)  # 4 Ziele + WAN

    def test_every_lost_ping_counts(self):
        t0 = int(time.time()) - 300
        self.send(t0, {"8.8.8.8": [1] * 20 + [0] + [1] * 100})
        loss = self.rows("loss")
        self.assertEqual(len(loss), 1)
        self.assertEqual((loss[0]["lost"], loss[0]["start_ts"], loss[0]["end_ts"]), (1, t0 + 20, t0 + 21))
        self.assertEqual(self.rows("down"), [])
        items = outages.load(t0 - 60)
        self.assertEqual([o.cause for o in items], ["packetloss"])
        self.assertIn("1 Ping ohne Antwort", items[0].summary)

    def test_loss_episode_collects_until_quiet(self):
        t0 = int(time.time()) - 400
        # drei Aussetzer innerhalb einer Minute, dann Ruhe: eine Störung mit 3 von 41 Pings
        values = [1] * 5 + [0] + [1] * 19 + [0, 0] + [1] * 18 + [0] + [1] * 100
        self.send(t0, {"1.1.1.1": values})
        loss = self.rows("loss")
        self.assertEqual(len(loss), 1)
        self.assertEqual((loss[0]["lost"], loss[0]["sent"]), (4, 41))
        self.assertEqual((loss[0]["start_ts"], loss[0]["end_ts"]), (t0 + 5, t0 + 46))
        self.assertAlmostEqual(disturbances.loss_pct(loss[0]), 400 / 41)

    def test_outage_spanning_batches(self):
        t0 = int(time.time()) - 120
        self.send(t0, {"9.9.9.9": [1] * 5 + [0] * 3})
        self.assertEqual(self.rows(), [])              # erst 3 s ohne Antwort: noch kein Ausfall
        self.send(t0 + 8, {"9.9.9.9": [0] * 4})
        open_ = self.rows("down")
        self.assertEqual([(d["start_ts"], d["end_ts"]) for d in open_], [(t0 + 5, None)])
        ev = q1("SELECT * FROM alert_events WHERE fingerprint = ?", (f"disturbance:{open_[0]['id']}",))
        self.assertEqual((ev["alertname"], ev["status"]), ("WachtlTargetDown", "firing"))
        self.send(t0 + 12, {"9.9.9.9": [1] * 5})
        d = self.rows("down")[0]
        self.assertEqual(d["end_ts"], t0 + 12)
        ev = q1("SELECT * FROM alert_events WHERE fingerprint = ?", (f"disturbance:{d['id']}",))
        self.assertEqual((ev["status"], ev["exact_start"], ev["exact_end"]), ("resolved", t0 + 5, t0 + 12))
        # Wiederholung desselben Zeitraums ändert nichts
        self.send(t0 + 12, {"9.9.9.9": [1] * 5})
        self.assertEqual(len(self.rows()), 1)

    def test_short_gap_is_loss_not_outage(self):
        t0 = int(time.time()) - 300
        self.send(t0, {"gateway": [1] * 5 + [0] * 4 + [1] * 70})   # 4 s: unter der Ausfallgrenze von 5 s
        self.assertEqual(self.rows("down"), [])
        self.assertEqual(self.rows("loss")[0]["lost"], 4)

    def test_wan_needs_all_references(self):
        t0 = int(time.time()) - 300
        self.send(t0, {"8.8.8.8": [1] * 5 + [0] * 20 + [1] * 5, "1.1.1.1": [1] * 30, "9.9.9.9": [1] * 5 + [0] * 20 + [1] * 5})
        self.assertEqual(self.rows("wan"), [])
        self.assertEqual(len(self.rows("down")), 2)

    def test_stale_outage_is_closed(self):
        # Probe hat sich während eines Ausfalls abgeschaltet: offener Ausfall endet mit dem letzten Ping
        t0 = int(time.time()) - 200
        self.send(t0, {"9.9.9.9": [1] * 5 + [0] * 10})
        self.assertIsNone(self.rows("down")[0]["end_ts"])
        disturbances.close_stale(int(time.time()) + disturbances.STALE_S)
        disturbances.sync_events(set(r["id"] for r in self.rows()))
        self.assertEqual(self.rows("down")[0]["end_ts"], t0 + 15)
        self.assertEqual(q1("SELECT status FROM alert_events")["status"], "resolved")

    def test_alertmanager_gets_late_outage_as_firing_then_resolved(self):
        self.app.config["ALERTMANAGER_URL"] = "http://am"
        t0 = int(time.time()) - 600
        with mock.patch("wachtl.services.disturbances.requests.post") as post:
            self.send(t0, {"9.9.9.9": [1] * 5 + [0] * 10 + [1] * 5})
        self.assertEqual(post.call_count, 1)
        alert = post.call_args.kwargs["json"][0]
        self.assertEqual(alert["labels"]["alertname"], "WachtlTargetDown")
        self.assertEqual(alert["labels"]["target"], "9.9.9.9")
        self.assertIn("nachträglich erkannt", alert["annotations"]["summary"])
        # schon beendet, aber noch nie gemeldet: erst aktiv, sonst stellt Alertmanager nichts zu
        self.assertGreater(alert["endsAt"], alert["startsAt"])
        self.assertEqual(self.rows("down")[0]["posted_state"], "resolved")
        # Webhook mit derselben Störung legt keinen zweiten Eintrag an
        alert_service.store_webhook({"alerts": [{**alert, "status": "firing", "fingerprint": "x"}]})
        self.assertEqual(q1("SELECT COUNT(*) AS n FROM alert_events")["n"], 1)

    def test_alertmanager_loss_respects_rule(self):
        self.app.config["ALERTMANAGER_URL"] = "http://am"
        ex("UPDATE alert_rules SET enabled = FALSE WHERE kind = 'packet_loss_any'")
        with mock.patch("wachtl.services.disturbances.requests.post") as post:
            self.send(int(time.time()) - 300, {"8.8.8.8": [1, 0] + [1] * 80})
        post.assert_not_called()
        self.assertEqual(self.rows("loss")[0]["posted_state"], "skipped")
        # in der Übersicht steht der Verlust trotzdem
        self.assertEqual([o.cause for o in outages.load(int(time.time()) - 400)], ["packetloss"])

    def test_alertmanager_down_keeps_retrying(self):
        self.app.config["ALERTMANAGER_URL"] = "http://am"
        import requests
        with mock.patch("wachtl.services.disturbances.requests.post", side_effect=requests.ConnectionError("weg")):
            self.send(int(time.time()) - 60, {"9.9.9.9": [1] + [0] * 10})
        self.assertIsNone(self.rows("down")[0]["posted_state"])
        with mock.patch("wachtl.services.disturbances.requests.post") as post:
            disturbances.post_pending()
        self.assertEqual(post.call_count, 1)
        self.assertEqual(self.rows("down")[0]["posted_state"], "firing")
        labels = json.loads(q1("SELECT labels FROM alert_events")["labels"])
        self.assertEqual(labels["kind"], "target_down")


class LossStateTest(AppTestCase):
    def test_any_loss_is_warning(self):
        state = checkstatus._ping_state({"id": 1, "created_at": 0}, {"up": 1, "rtt": 10, "loss": 0.004}, 1000)
        self.assertEqual(state.state, "warn")
        self.assertIn("0.004 %", state.detail)
        self.assertEqual(checkstatus._ping_state({"id": 1, "created_at": 0}, {"up": 1, "loss": 0}, 1000).state, "ok")


class NotificationApiTest(AppTestCase):
    def test_web_feed_starts_at_now_then_delivers_new_events(self):
        self.make_user()
        self.login()
        data = self.enroll()
        headers = {"Authorization": f"Bearer {data['token']}"}
        cfg = self.client.get("/api/probe/v1/config", headers=headers).get_json()
        cid = next(c["id"] for c in cfg["checks"] if c["target"] == "8.8.8.8")
        first = self.client.get("/api/v1/notifications").get_json()
        self.assertEqual(first["items"], [])
        t0 = int(time.time()) - 120
        body = "\n".join(f'wachtl_ping_up{{check_id="{cid}"}} {0 if i == 3 else 1} {(t0 + i) * 1000}' for i in range(90))
        self.client.post("/api/probe/v1/ingest", data=body, headers={**headers, "X-Batch-Id": "n-1"})
        c = first["cursor"]
        feed = self.client.get(f"/api/v1/notifications?a={c['a']}&f={c['f']}").get_json()
        self.assertEqual(len(feed["items"]), 1)
        item = feed["items"][0]
        self.assertTrue(item["title"].startswith("Paketverlust: PC-01"))
        self.assertIn("1 Ping ohne Antwort", item["text"])
        self.assertIn(f"/probes/{data['probe_id']}/checks/{cid}?at=", item["url"])
        again = self.client.get(f"/api/v1/notifications?a={feed['cursor']['a']}&f={feed['cursor']['f']}").get_json()
        self.assertEqual(again["items"], [])

    def test_probe_notices_only_for_server_probe(self):
        data = self.enroll()
        headers = {"Authorization": f"Bearer {data['token']}"}
        self.assertEqual(self.client.get("/api/probe/v1/notices", headers=headers).status_code, 404)
        ex("UPDATE probes SET kind = 'server' WHERE id = ?", (data["probe_id"],))
        r = self.client.get("/api/probe/v1/notices", headers=headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.get_json()), {"cursor", "items", "active"})
