import os
from unittest import mock

import yaml

from wachtl import bootstrap
from wachtl.db import q1
from wachtl.services import notify

from .helpers import AppTestCase


class NotifyTest(AppTestCase):
    def load(self):
        with open(self.app.config["AM_CONFIG"], encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_config_without_channels_has_history_webhook(self):
        notify.write_config(reload=False)
        cfg = self.load()
        names = [r["name"] for r in cfg["receivers"]]
        self.assertEqual(names, ["wachtl-history", "notify"])
        hook = cfg["receivers"][0]["webhook_configs"][0]
        self.assertEqual(hook["url"], "http://127.0.0.1:8427/api/internal/alertmanager")
        self.assertEqual(hook["http_config"]["authorization"]["credentials"], "hook-secret")
        self.assertNotIn("global", cfg)
        self.assertEqual(len(cfg["inhibit_rules"]), 6)

    def test_email_and_teams(self):
        notify.save_settings({"email_to": "a@x.de, b@x.de", "email_from": "w@x.de", "smtp_smarthost": "mail:587",
                              "smtp_username": "u", "smtp_password": "p'w\"", "smtp_require_tls": "true",
                              "teams_webhook_url": "https://teams.example/hook"})
        notify.write_config(reload=False)
        cfg = self.load()
        self.assertEqual(cfg["global"]["smtp_auth_password"], "p'w\"")  # Sonderzeichen sicher escaped
        self.assertTrue(cfg["global"]["smtp_require_tls"])
        recv = cfg["receivers"][1]
        self.assertEqual([e["to"] for e in recv["email_configs"]], ["a@x.de", "b@x.de"])
        self.assertEqual(recv["msteamsv2_configs"][0]["webhook_url"], "https://teams.example/hook")

    def test_validate(self):
        self.assertEqual(notify.validate({"email_to": "", "teams_webhook_url": ""}), [])
        errs = notify.validate({"email_to": "it@x.de", "email_from": "x", "smtp_smarthost": "mail",
                                "teams_webhook_url": "http://unsicher"})
        self.assertEqual(len(errs), 3)

    def test_import_from_env_only_once(self):
        with mock.patch.dict(os.environ, {"ALERT_EMAIL_TO": "it@x.de", "TEAMS_WEBHOOK_URL": ""}):
            self.assertTrue(notify.import_from_env())
        self.assertEqual(notify.get_settings()["email_to"], "it@x.de")
        with mock.patch.dict(os.environ, {"ALERT_EMAIL_TO": "anders@x.de"}):
            self.assertFalse(notify.import_from_env())
        self.assertEqual(notify.get_settings()["email_to"], "it@x.de")

    def test_bootstrap_with_settings_and_admin(self):
        msgs = bootstrap.initialize(admin_password="ein-langes-passwort", reload=False,
                                    notify_settings={"teams_webhook_url": "https://t.example/h"})
        self.assertTrue(any("admin" in m for m in msgs))
        self.assertIsNotNone(q1("SELECT id FROM users WHERE username = 'admin'"))
        self.assertEqual(notify.get_settings()["teams_webhook_url"], "https://t.example/h")
        self.assertTrue(os.path.exists(self.app.config["AM_CONFIG"]))
        with self.assertRaises(ValueError):
            bootstrap.set_user("x", "kurz", "admin")

    def test_web_form_keeps_password_and_audits(self):
        self.make_user()
        self.login()
        tok = self.session_csrf()
        form = {"email_to": "it@x.de", "email_from": "w@x.de", "smtp_smarthost": "mail:587", "smtp_username": "u",
                "smtp_password": "geheim", "smtp_require_tls": "on", "teams_webhook_url": "", "csrf_token": tok}
        self.client.post("/admin/notify", data=form)
        form["smtp_password"] = ""
        self.client.post("/admin/notify", data=form)
        self.assertEqual(notify.get_settings()["smtp_password"], "geheim")
        audit = q1("SELECT detail FROM audit_log WHERE action = 'notify.update' ORDER BY id LIMIT 1")
        self.assertIn("smtp_password", audit["detail"])
        self.assertNotIn("geheim", audit["detail"])
        self.assertEqual(self.load()["receivers"][1]["email_configs"][0]["to"], "it@x.de")

    def test_send_test_posts_alert(self):
        self.app.config["ALERTMANAGER_URL"] = "http://am"
        with mock.patch("wachtl.services.notify.requests.post") as post:
            post.return_value.raise_for_status.return_value = None
            notify.send_test("admin")
        url, kwargs = post.call_args.args[0], post.call_args.kwargs
        self.assertEqual(url, "http://am/api/v2/alerts")
        self.assertEqual(kwargs["json"][0]["labels"]["alertname"], "WachtlTest")
