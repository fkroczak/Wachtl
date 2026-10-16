"""Dünne Datenbankschicht für PostgreSQL (Produktion) und SQLite (Tests, Entwicklung).

SQL wird mit ``?`` als Platzhalter geschrieben und für PostgreSQL automatisch
auf ``%s`` umgesetzt. Alle Zeitstempel sind Unix-Sekunden (BIGINT), JSON wird als
TEXT gespeichert – so bleibt das Schema auf beiden Datenbanken identisch.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from importlib import resources
from typing import Any, Iterable

from flask import current_app, g

log = logging.getLogger(__name__)

_MIGRATION_LOCK_ID = 470113


class Database:
    def __init__(self, url: str):
        self.url = url
        self.is_postgres = url.startswith(("postgresql://", "postgres://"))
        if not self.is_postgres and not url.startswith("sqlite://"):
            raise ValueError(f"Nicht unterstützte Datenbank-URL: {url}")

    # -- Verbindung -------------------------------------------------------
    def connect(self):
        if self.is_postgres:
            import psycopg
            from psycopg.rows import dict_row

            return psycopg.connect(self.url, autocommit=True, row_factory=dict_row)
        path = self.url[len("sqlite:///"):] or ":memory:"
        conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _sql(self, sql: str) -> str:
        # psycopg wertet jedes % als Platzhalter – wörtliche % (LIKE 'notify.%') verdoppeln
        return sql.replace("%", "%%").replace("?", "%s") if self.is_postgres else sql

    # -- Abfragen ---------------------------------------------------------
    def query(self, conn, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        cur = conn.execute(self._sql(sql), tuple(params))
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def one(self, conn, sql: str, params: Iterable[Any] = ()) -> dict | None:
        rows = self.query(conn, sql, params)
        return rows[0] if rows else None

    def execute(self, conn, sql: str, params: Iterable[Any] = ()) -> int:
        cur = conn.execute(self._sql(sql), tuple(params))
        return cur.rowcount

    def insert(self, conn, sql: str, params: Iterable[Any] = ()) -> int:
        """INSERT ausführen und die neue ``id`` zurückgeben."""
        cur = conn.execute(self._sql(sql + " RETURNING id"), tuple(params))
        row = cur.fetchone()
        return int(row["id"] if isinstance(row, dict) else row[0])

    # -- Migrationen ------------------------------------------------------
    def migrate(self, conn) -> list[int]:
        """Alle noch nicht angewendeten SQL-Migrationen einspielen."""
        if self.is_postgres:
            conn.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_ID,))
        try:
            if not self.is_postgres:
                conn.execute("PRAGMA journal_mode = WAL")  # parallele Leser neben einem Schreiber
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version ("
                "version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL)"
            )
            done = {r["version"] for r in self.query(conn, "SELECT version FROM schema_version")}
            applied: list[int] = []
            files = sorted(
                f for f in resources.files("wachtl.migrations").iterdir() if f.name.endswith(".sql")
            )
            for f in files:
                version = int(f.name.split("_", 1)[0])
                if version in done:
                    continue
                sql = f.read_text(encoding="utf-8")
                if not self.is_postgres:
                    sql = sql.replace("BIGSERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                log.info("Wende Migration %s an", f.name)
                self._run_script(conn, sql)
                self.execute(
                    conn,
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, int(time.time())),
                )
                applied.append(version)
            return applied
        finally:
            if self.is_postgres:
                conn.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_ID,))

    def _run_script(self, conn, sql: str) -> None:
        if self.is_postgres:
            with conn.transaction():
                conn.execute(sql)
        else:
            conn.executescript("BEGIN;" + sql + ";COMMIT;")


# -- Flask-Integration -----------------------------------------------------
def get_db() -> Database:
    return current_app.extensions["wachtl_db"]


def get_conn():
    if "db_conn" not in g:
        g.db_conn = get_db().connect()
    return g.db_conn


def close_conn(_exc=None) -> None:
    conn = g.pop("db_conn", None)
    if conn is not None:
        conn.close()


def q(sql: str, params: Iterable[Any] = ()) -> list[dict]:
    return get_db().query(get_conn(), sql, params)


def q1(sql: str, params: Iterable[Any] = ()) -> dict | None:
    return get_db().one(get_conn(), sql, params)


def ex(sql: str, params: Iterable[Any] = ()) -> int:
    return get_db().execute(get_conn(), sql, params)


def ins(sql: str, params: Iterable[Any] = ()) -> int:
    return get_db().insert(get_conn(), sql, params)
