"""Gemeinsame Test-Basis: Flask-App mit SQLite-Datei und temporärem Regelverzeichnis."""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from wachtl import create_app
from wachtl import repo
from wachtl.db import get_conn, get_db, ins
from wachtl.security import hash_password, hash_token


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app(
            {
                "SECRET_KEY": "test",
                "DATABASE_URL": f"sqlite:///{os.path.join(self.tmp, 'test.db')}",
                "RULES_DIR": os.path.join(self.tmp, "rules"),
                "AM_CONFIG": os.path.join(self.tmp, "am", "alertmanager.yml"),
                "INTERNAL_URL": "http://127.0.0.1:8427",
                "VMALERT_URL": "",
                "ALERTMANAGER_URL": "",
                "WEBHOOK_SECRET": "hook-secret",
                "SESSION_COOKIE_SECURE": False,
                "TESTING": True,
            }
        )
        self.ctx = self.app.app_context()
        self.ctx.push()
        get_db().migrate(get_conn())
        repo.seed_defaults()
        self.client = self.app.test_client()
        self.imported: list[str] = []
        patcher = mock.patch("wachtl.services.vm.import_lines", side_effect=self.imported.extend)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.ctx.pop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- Hilfen -------------------------------------------------------------
    def make_site(self, name="Zentrale") -> int:
        return ins("INSERT INTO sites (name, created_at) VALUES (?, ?)", (name, repo.now()))

    def make_token(self, site_id: int, token="tok-1", max_uses=1, expires_in=3600) -> str:
        ins(
            "INSERT INTO enrollment_tokens (site_id, token_hash, expires_at, max_uses, uses, revoked, created_at) "
            "VALUES (?, ?, ?, ?, 0, FALSE, ?)",
            (site_id, hash_token(token), repo.now() + expires_in, max_uses, repo.now()),
        )
        return token

    def enroll(self, hostname="PC-01", token=None) -> dict:
        site_id = self.make_site()
        token = token or self.make_token(site_id)
        r = self.client.post("/api/probe/v1/enroll", json={"enrollment_token": token, "hostname": hostname,
                                                         "os": "Windows 11", "version": "0.1.0"})
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def make_user(self, username="admin", role="admin", password="sehr-geheimes-pw") -> None:
        ins(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, repo.now()),
        )

    def csrf(self) -> str:
        html = self.client.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def login(self, username="admin", password="sehr-geheimes-pw"):
        return self.client.post("/login", data={"username": username, "password": password,
                                                "csrf_token": self.csrf()})

    def session_csrf(self) -> str:
        with self.client.session_transaction() as s:
            return s["csrf"]
