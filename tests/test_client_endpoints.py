import base64
import importlib
import json
import logging
import os
import shutil
import sys
import time
import uuid
import unittest
from pathlib import Path

import aiosqlite

from utils.crypto import compute_signature, decrypt_payload, encrypt_payload, hash_license_key, mask_license_key


MODULES_TO_RESET = [
    "database",
    "routes.client",
    "utils.logger",
]


class _FakeClient:
    def __init__(self, host: str):
        self.host = host


class _FakeRequest:
    def __init__(self, host: str = "127.0.0.1", headers: dict | None = None):
        self.client = _FakeClient(host)
        self.headers = headers or {}


class ClientEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.workdir = Path(__file__).resolve().parent / f"_client-{uuid.uuid4().hex}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.workdir / "enauth.db"
        self.log_path = self.workdir / "server.log"

        os.environ["DB_PATH"] = str(self.db_path)
        os.environ["LOG_FILE"] = str(self.log_path)
        os.environ["LOG_LEVEL"] = "INFO"
        os.environ["LOG_MAX_BYTES"] = str(1024 * 1024)
        os.environ["LOG_BACKUP_COUNT"] = "1"
        os.environ["DEBUG"] = "false"
        os.environ["TIMESTAMP_TOLERANCE"] = "60"
        os.environ["SESSION_DURATION"] = "86400"
        os.environ["MAX_LOGIN_STRIKES"] = "5"
        os.environ["NONCE_CACHE_SIZE"] = "10000"
        os.environ["NONCE_TTL"] = "120"
        os.environ["LICENSE_KEY_PEPPER"] = "test-license-pepper-that-is-long-enough"

        for name in MODULES_TO_RESET:
            sys.modules.pop(name, None)

        self.database = importlib.import_module("database")
        self.client = importlib.import_module("routes.client")
        await self.database.init_db()

    async def asyncTearDown(self):
        logger = logging.getLogger("root")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        shutil.rmtree(self.workdir, ignore_errors=True)

    async def _seed_app(self):
        app_id = "app-1"
        secret = "a" * 64
        license_id = "lic-1"
        license_key = "ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF"
        file_id = "file-1"

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                "INSERT INTO applications (id, name, secret_key, version) VALUES (?, ?, ?, ?)",
                (app_id, "Test App", secret, "1.0.0"),
            )
            await db.execute(
                """
                INSERT INTO licenses (id, key, key_hash, app_id, status, max_hwids, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (license_id, mask_license_key(license_key), hash_license_key(license_key), app_id, "active", 2, "2099-12-31 23:59:59"),
            )
            await db.execute(
                "INSERT INTO app_files (id, app_id, name, content, is_secret) VALUES (?, ?, ?, ?, ?)",
                (file_id, app_id, "payload.bin", b"hello world", 0),
            )
            await db.commit()

        return {
            "app_id": app_id,
            "secret": secret,
            "license_id": license_id,
            "license_key": license_key,
            "file_id": file_id,
        }

    def _encrypted_request(self, app_id: str, secret: str, payload: dict, nonce: str | None = None):
        ts = int(time.time())
        data = encrypt_payload(payload, secret)
        sig = compute_signature(secret, data, ts, app_id)
        return self.client.EncryptedRequest(
            app_id=app_id,
            data=data,
            sig=sig,
            ts=ts,
            nonce=nonce or uuid.uuid4().hex,
        )

    def _decrypt_response(self, response, secret: str):
        body = json.loads(response.body.decode("utf-8"))
        return decrypt_payload(body["data"], secret)

    async def test_login_validate_heartbeat_and_download(self):
        seeded = await self._seed_app()
        fake_request = _FakeRequest(headers={"User-Agent": "EnAuthTest/1.0"})

        login_req = self._encrypted_request(
            seeded["app_id"],
            seeded["secret"],
            {
                "version": "1.0.0",
                "license_key": seeded["license_key"],
                "hwid": "a" * 64,
            },
        )

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            login_resp = await self.client.client_login.__wrapped__(
                request=fake_request,
                req=login_req,
                db=db,
            )

            login_payload = self._decrypt_response(login_resp, seeded["secret"])
            self.assertTrue(login_payload["success"])
            self.assertIn("token", login_payload)

            async with db.execute(
                "SELECT token, hwid, ip, expires_at FROM sessions WHERE token = ?",
                (login_payload["token"],),
            ) as cur:
                session = await cur.fetchone()
            self.assertIsNotNone(session)
            self.assertEqual(session["ip"], "127.0.0.1")

            validate_req = self._encrypted_request(
                seeded["app_id"],
                seeded["secret"],
                {"token": login_payload["token"]},
            )
            validate_resp = await self.client.client_validate.__wrapped__(
                request=fake_request,
                req=validate_req,
                db=db,
            )
            validate_payload = self._decrypt_response(validate_resp, seeded["secret"])
            self.assertTrue(validate_payload["success"])
            self.assertEqual(validate_payload["expires_at"], session["expires_at"])

            heartbeat_req = self._encrypted_request(
                seeded["app_id"],
                seeded["secret"],
                {"token": login_payload["token"]},
            )
            heartbeat_resp = await self.client.client_heartbeat.__wrapped__(
                request=fake_request,
                req=heartbeat_req,
                db=db,
            )
            heartbeat_payload = self._decrypt_response(heartbeat_resp, seeded["secret"])
            self.assertTrue(heartbeat_payload["success"])

            download_req = self._encrypted_request(
                seeded["app_id"],
                seeded["secret"],
                {"token": login_payload["token"], "name": "payload.bin"},
            )
            download_resp = await self.client.client_download.__wrapped__(
                request=fake_request,
                req=download_req,
                db=db,
            )
            download_payload = self._decrypt_response(download_resp, seeded["secret"])
            self.assertTrue(download_payload["success"])
            self.assertEqual(download_payload["name"], "payload.bin")
            self.assertEqual(base64.b64decode(download_payload["data"]), b"hello world")


if __name__ == "__main__":
    unittest.main()
