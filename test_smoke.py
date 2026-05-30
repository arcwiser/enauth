import asyncio
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
import sqlite3
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from utils.crypto import compute_signature, verify_signature, is_valid_hwid

try:
    from routes.admin import cleanup_runtime_state, TEMP_2FA_SESSIONS
except ModuleNotFoundError:
    cleanup_runtime_state = None
    TEMP_2FA_SESSIONS = {}


MIN_SCHEMA = """
CREATE TABLE applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    version TEXT NOT NULL
);
CREATE TABLE licenses (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    app_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TEXT
);
CREATE TABLE admin_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE reseller_sessions (
    id TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE portal_sessions (
    id TEXT PRIMARY KEY,
    license_id TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    license_id TEXT NOT NULL,
    hwid TEXT NOT NULL,
    ip TEXT NOT NULL,
    app_id TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    app_id TEXT,
    action TEXT NOT NULL,
    ip TEXT,
    hwid TEXT,
    details TEXT,
    timestamp TEXT
);
"""


class _AsyncCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    async def fetchone(self):
        return self._cursor.fetchone()

    async def fetchall(self):
        return self._cursor.fetchall()


class _AsyncConn:
    def __init__(self, path):
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row

    async def executescript(self, sql):
        self._conn.executescript(sql)

    async def execute(self, sql, params=()):
        return _AsyncCursor(self._conn.execute(sql, params))

    async def commit(self):
        self._conn.commit()

    async def close(self):
        self._conn.close()


class SmokeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db_path = path
        self.db = _AsyncConn(self.db_path)
        await self.db.executescript(MIN_SCHEMA)

        app_id = "app-1"
        lic_id = "lic-1"
        await self.db.execute(
            "INSERT INTO applications (id, name, secret_key, version) VALUES (?, ?, ?, ?)",
            (app_id, "Smoke App", "a" * 64, "1.0.0"),
        )
        await self.db.execute(
            "INSERT INTO licenses (id, key, app_id, status, expires_at) VALUES (?, ?, ?, ?, ?)",
            (lic_id, "AAAAAA-BBBBBB-CCCCCC-DDDDDD-EEEEEE-FFFFFF", app_id, "active", "2099-01-01 00:00:00"),
        )
        await self.db.execute(
            "INSERT INTO admin_sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
            ("admin-session", "user-1", "admin-token", "2000-01-01 00:00:00"),
        )
        await self.db.execute(
            "INSERT INTO auth_sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
            ("auth-session", "user-1", "auth-token", "2000-01-01 00:00:00"),
        )
        await self.db.execute(
            "INSERT INTO reseller_sessions (id, reseller_id, token, expires_at) VALUES (?, ?, ?, ?)",
            ("reseller-session", "reseller-1", "reseller-token", "2000-01-01 00:00:00"),
        )
        await self.db.execute(
            "INSERT INTO portal_sessions (id, license_id, token, expires_at) VALUES (?, ?, ?, ?)",
            ("portal-session", lic_id, "portal-token", "2000-01-01 00:00:00"),
        )
        await self.db.execute(
            "INSERT INTO sessions (id, token, license_id, hwid, ip, app_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("client-session", "client-token", lic_id, "hwid-1", "127.0.0.1", app_id, "2000-01-01 00:00:00"),
        )
        stale = (datetime.now(timezone.utc) - timedelta(days=31)).strftime("%Y-%m-%d %H:%M:%S")
        await self.db.execute(
            "INSERT INTO logs (license_key, app_id, action, ip, hwid, details, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("AAAAAA-BBBBBB-CCCCCC-DDDDDD-EEEEEE-FFFFFF", app_id, "login", "127.0.0.1", "hwid-1", "stale", stale),
        )
        await self.db.commit()

        TEMP_2FA_SESSIONS.clear()
        TEMP_2FA_SESSIONS["temp-token"] = {
            "user_id": "user-1",
            "role": "owner",
            "expires": datetime.now(timezone.utc) - timedelta(minutes=1),
        }

    async def asyncTearDown(self):
        await self.db.close()
        os.remove(self.db_path)
        TEMP_2FA_SESSIONS.clear()

    async def test_cleanup_runtime_state_prunes_expired_records(self):
        if cleanup_runtime_state is None:
            self.skipTest("server deps unavailable in this shell")
        await cleanup_runtime_state(self.db)

        async with self.db.execute("SELECT COUNT(*) FROM admin_sessions") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        async with self.db.execute("SELECT COUNT(*) FROM auth_sessions") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        async with self.db.execute("SELECT COUNT(*) FROM reseller_sessions") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        async with self.db.execute("SELECT COUNT(*) FROM portal_sessions") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        async with self.db.execute("SELECT COUNT(*) FROM sessions") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        async with self.db.execute("SELECT COUNT(*) FROM logs") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        self.assertEqual(TEMP_2FA_SESSIONS, {})

    def test_signature_roundtrip(self):
        sig = compute_signature("secret", "payload", 123, "app")
        self.assertTrue(verify_signature("secret", "payload", 123, sig, "app"))
        self.assertFalse(verify_signature("secret", "payload", 123, sig, "other"))

    def test_hwid_validation(self):
        self.assertTrue(is_valid_hwid("a" * 64))
        self.assertTrue(is_valid_hwid("b" * 128))
        self.assertFalse(is_valid_hwid("short"))


if __name__ == "__main__":
    unittest.main()
