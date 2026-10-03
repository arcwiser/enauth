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
        os.environ["REQUIRE_SESSION_HWID"] = "false"
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
                {"token": login_payload["token"], "hwid": "a" * 64},
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
                {"token": login_payload["token"], "hwid": "a" * 64},
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
                {"token": login_payload["token"], "hwid": "a" * 64, "name": "payload.bin"},
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

    async def test_session_is_revoked_when_hwid_changes(self):
        seeded = await self._seed_app()
        fake_request = _FakeRequest(headers={"User-Agent": "EnAuthTest/1.0"})

        login_req = self._encrypted_request(
            seeded["app_id"], seeded["secret"],
            {"version": "1.0.0", "license_key": seeded["license_key"], "hwid": "a" * 64},
        )
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            login_resp = await self.client.client_login.__wrapped__(fake_request, login_req, db)
            token = self._decrypt_response(login_resp, seeded["secret"])["token"]

            validate_req = self._encrypted_request(
                seeded["app_id"], seeded["secret"],
                {"token": token, "hwid": "b" * 64},
            )
            validate_resp = await self.client.client_validate.__wrapped__(fake_request, validate_req, db)
            validate_payload = self._decrypt_response(validate_resp, seeded["secret"])
            self.assertFalse(validate_payload["success"])
            self.assertEqual(validate_payload["message"], "SESSION_IDENTITY_MISMATCH")

            async with db.execute("SELECT COUNT(*) FROM sessions WHERE token=?", (token,)) as cur:
                self.assertEqual((await cur.fetchone())[0], 0)

    async def test_paused_product_does_not_block_an_online_product(self):
        seeded = await self._seed_app()
        fake_request = _FakeRequest(headers={"User-Agent": "EnAuthTest/1.0"})
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                "INSERT INTO products(id, app_id, name, level, is_paused) VALUES(?,?,?,?,?)",
                ("product-1", seeded["app_id"], "Product One", "one", 1),
            )
            await db.execute(
                "INSERT INTO products(id, app_id, name, level, is_paused) VALUES(?,?,?,?,?)",
                ("product-2", seeded["app_id"], "Product Two", "two", 0),
            )
            for product_id in ("product-1", "product-2"):
                await db.execute(
                    "INSERT INTO license_products(id, license_id, product_id, expires_at) VALUES(?,?,?,?)",
                    (f"ent-{product_id}", seeded["license_id"], product_id, "2099-12-31 23:59:59"),
                )
            await db.commit()

            paused_req = self._encrypted_request(
                seeded["app_id"], seeded["secret"],
                {"license_key": seeded["license_key"], "hwid": "b" * 64, "level": "one"},
            )
            paused_resp = await self.client.client_login.__wrapped__(fake_request, paused_req, db)
            self.assertEqual(self._decrypt_response(paused_resp, seeded["secret"])["message"], "PRODUCT_PAUSED")

            online_req = self._encrypted_request(
                seeded["app_id"], seeded["secret"],
                {"license_key": seeded["license_key"], "hwid": "b" * 64, "level": "two"},
            )
            online_resp = await self.client.client_login.__wrapped__(fake_request, online_req, db)
            self.assertTrue(self._decrypt_response(online_resp, seeded["secret"])["success"])

    async def test_paused_entitlement_blocks_only_that_license_product(self):
        seeded = await self._seed_app()
        fake_request = _FakeRequest(headers={"User-Agent": "EnAuthTest/1.0"})
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO products(id,app_id,name,level) VALUES(?,?,?,?)",
                             ("product-1", seeded["app_id"], "Product", "one"))
            await db.execute(
                """INSERT INTO license_products(id,license_id,product_id,expires_at,is_paused)
                   VALUES(?,?,?,?,1)""",
                ("ent-1", seeded["license_id"], "product-1", "2099-12-31 23:59:59"),
            )
            await db.commit()
            req = self._encrypted_request(seeded["app_id"], seeded["secret"], {
                "license_key": seeded["license_key"], "hwid": "c" * 64, "level": "one"
            })
            response = await self.client.client_login.__wrapped__(fake_request, req, db)
            self.assertEqual(self._decrypt_response(response, seeded["secret"])["message"], "ENTITLEMENT_PAUSED")


if __name__ == "__main__":
    unittest.main()
