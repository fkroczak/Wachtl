import gzip
import time

from wachtl.db import ex, q1

from .helpers import AppTestCase


class ProbeApiTest(AppTestCase):
    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_enroll_creates_probe_and_consumes_token(self):
        data = self.enroll()
        self.assertEqual(data["site_name"], "Zentrale")
        self.assertTrue(data["token"].startswith(f"{data['probe_id']}."))
        # Token mit max_uses=1 ist verbraucht
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "tok-1", "hostname": "PC-02"})
        self.assertEqual(r.status_code, 403)

    def test_enroll_rejects_expired_and_bad_hostname(self):
        site = self.make_site()
        self.make_token(site, token="alt", expires_in=-10)
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "alt", "hostname": "PC-01"})
        self.assertEqual(r.status_code, 403)
        self.make_token(site, token="neu")
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "neu", "hostname": "bad host!"})
        self.assertEqual(r.status_code, 400)

    def test_reenroll_same_host_rotates_token(self):
        site = self.make_site()
        self.make_token(site, token="multi", max_uses=5)
        first = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "multi", "hostname": "PC-01"}).get_json()
        second = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": "multi", "hostname": "PC-01"}).get_json()
        self.assertEqual(first["probe_id"], second["probe_id"])
        self.assertEqual(self.client.get("/api/probe/v1/config", headers=self.auth(first["token"])).status_code, 401)
        self.assertEqual(self.client.get("/api/probe/v1/config", headers=self.auth(second["token"])).status_code, 200)

    def test_config_contains_default_checks_and_supports_etag(self):
        data = self.enroll()
        r = self.client.get("/api/probe/v1/config", headers=self.auth(data["token"]))
        self.assertEqual(r.status_code, 200)
        cfg = r.get_json()
        self.assertEqual({c["target"] for c in cfg["checks"]}, {"gateway", "8.8.8.8", "1.1.1.1"})
        self.assertTrue(all(c["interval_s"] == 1 for c in cfg["checks"]))
        r2 = self.client.get("/api/probe/v1/config", headers={**self.auth(data["token"]), "If-None-Match": r.headers["ETag"]})
        self.assertEqual(r2.status_code, 304)

    def test_auth_failures(self):
        data = self.enroll()
        self.assertEqual(self.client.get("/api/probe/v1/config").status_code, 401)
        self.assertEqual(self.client.get("/api/probe/v1/config", headers=self.auth(data["token"] + "x")).status_code, 401)
        ex("UPDATE probes SET status = 'disabled' WHERE id = ?", (data["probe_id"],))
        self.assertEqual(self.client.get("/api/probe/v1/config", headers=self.auth(data["token"])).status_code, 403)

    def test_ingest_gzip_dedupe_and_label_rewrite(self):
        data = self.enroll()
        check_id = self.client.get("/api/probe/v1/config", headers=self.auth(data["token"])).get_json()["checks"][1]["id"]
        now_ms = int(time.time() * 1000)
        body = f'wachtl_ping_rtt_ms{{check_id="{check_id}"}} 11.2 {now_ms}\nwachtl_ping_up{{check_id="{check_id}"}} 1 {now_ms}\n'
        headers = {**self.auth(data["token"]), "X-Batch-Id": "b-1", "Content-Encoding": "gzip"}
        r = self.client.post("/api/probe/v1/ingest", data=gzip.compress(body.encode()), headers=headers)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(len(self.imported), 2)
        self.assertIn(f'probe="{data["probe_id"]}"', self.imported[0])
        self.assertIn('probe_name="PC-01"', self.imported[0])
        # Wiederholung desselben Batches wird nicht erneut gespeichert
        r = self.client.post("/api/probe/v1/ingest", data=gzip.compress(body.encode()), headers=headers)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(len(self.imported), 2)

    def test_ingest_requires_batch_id_and_reports_rejections(self):
        data = self.enroll()
        r = self.client.post("/api/probe/v1/ingest", data="x", headers=self.auth(data["token"]))
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/probe/v1/ingest", data='wachtl_ping_up{check_id="999"} 1 1700000000000',
                             headers={**self.auth(data["token"]), "X-Batch-Id": "b-2"})
        self.assertEqual(r.status_code, 422)

    def test_ingest_returns_503_when_storage_down(self):
        from unittest import mock

        from wachtl.services import vm

        data = self.enroll()
        with mock.patch("wachtl.services.vm.import_lines", side_effect=vm.VMError("weg")):
            r = self.client.post("/api/probe/v1/ingest", data="", headers={**self.auth(data["token"]), "X-Batch-Id": "b-3"})
        self.assertEqual(r.status_code, 503)
        self.assertIsNone(q1("SELECT batch_id FROM ingest_batches WHERE batch_id LIKE '%b-3'"))

    def test_heartbeat_updates_probe(self):
        data = self.enroll()
        r = self.client.post("/api/probe/v1/heartbeat", json={"version": "0.1.1", "buffer_items": 42, "uptime_s": 99},
                             headers=self.auth(data["token"]))
        self.assertEqual(r.status_code, 200)
        self.assertIn("config_etag", r.get_json())
        p = q1("SELECT * FROM probes WHERE id = ?", (data["probe_id"],))
        self.assertEqual((p["version"], p["buffer_items"], p["uptime_s"]), ("0.1.1", 42, 99))
        self.assertTrue(any(line.startswith("wachtl_probe_last_seen") for line in self.imported))
