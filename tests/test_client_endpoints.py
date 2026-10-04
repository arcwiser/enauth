import importlib
import base64
import hashlib
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from utils.crypto import (
    compute_signature, decrypt_bytes, decrypt_payload, derive_session_download_secret,
    encrypt_payload, hash_license_key, mask_license_key,
)


MODULES_TO_RESET = [
    "database",
    "routes.client",
    "utils.logger",
    "utils.response_signing",
]


class _FakeClient:
    def __init__(self, host: str):
        self.host = host


class _FakeRequest:
    def __init__(self, host: str = "127.0.0.1", headers: dict | None = None,
                 path: str = "/api/client/test"):
        self.client = _FakeClient(host)
        self.headers = headers or {}
        self.url = type("FakeUrl", (), {"path": path})()


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
        os.environ["ALLOW_LEGACY_PROTOCOL"] = "true"
        os.environ["LICENSE_KEY_PEPPER"] = "test-license-pepper-that-is-long-enough"
        os.environ["RESPONSE_SIGNING_KEY_PATH"] = str(self.workdir / "response-signing-key.pem")

        for name in MODULES_TO_RESET:
            sys.modules.pop(name, None)

        self.database = importlib.import_module("database")
        self.client = importlib.import_module("routes.client")
        self.response_signing = importlib.import_module("utils.response_signing")
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

    def _v2_request(self, app_id: str, payload: dict, nonce: str | None = None):
        encoded = base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return self.client.EncryptedRequest(
            protocol=2, app_id=app_id, payload=encoded,
            ts=int(time.time()), nonce=nonce or uuid.uuid4().hex,
        )

    def _verify_v2_response(self, response, endpoint: str, nonce: str):
        body = json.loads(response.body.decode("utf-8"))
        self.assertEqual(body["protocol"], 2)
        self.assertEqual(body["endpoint"], endpoint)
        self.assertEqual(body["request_nonce"], nonce)
        message = (
            f'v2|{body["app_id"]}|{endpoint}|{nonce}|{body["ts"]}|'
            f'{body["valid_until"]}|{body["payload"]}'
        )
        raw_key = bytes.fromhex(self.response_signing.response_public_key_hex())
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(raw_key[:32], "big"), int.from_bytes(raw_key[32:], "big"),
            ec.SECP256R1(),
        ).public_key()
        raw_sig = base64.b64decode(body["server_sig"], validate=True)
        der_sig = encode_dss_signature(
            int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big")
        )
        public_key.verify(der_sig, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return json.loads(base64.b64decode(body["payload"], validate=True))

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
            self.assertEqual(download_payload["encryption"], "AES-256-GCM-SESSION-v1")
            self.assertEqual(download_payload["sha256"], hashlib.sha256(b"hello world").hexdigest())
            download_secret = derive_session_download_secret(
                seeded["secret"], login_payload["token"], "a" * 64, seeded["file_id"]
            )
            self.assertEqual(decrypt_bytes(download_payload["data"], download_secret), b"hello world")

            wrong_session_secret = derive_session_download_secret(
                seeded["secret"], "different-session", "a" * 64, seeded["file_id"]
            )
            with self.assertRaises(ValueError):
                decrypt_bytes(download_payload["data"], wrong_session_secret)

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

    async def test_session_cannot_cross_application_boundary(self):
        seeded = await self._seed_app()
        fake_request = _FakeRequest(headers={"User-Agent": "EnAuthTest/1.0"})
        other_secret = "b" * 64

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                "INSERT INTO applications (id, name, secret_key, version) VALUES (?, ?, ?, ?)",
                ("app-2", "Other App", other_secret, "1.0.0"),
            )
            await db.commit()

            login_req = self._encrypted_request(
                seeded["app_id"], seeded["secret"],
                {"version": "1.0.0", "license_key": seeded["license_key"], "hwid": "a" * 64},
            )
            login_resp = await self.client.client_login.__wrapped__(fake_request, login_req, db)
            token = self._decrypt_response(login_resp, seeded["secret"])["token"]

            cross_app_req = self._encrypted_request(
                "app-2", other_secret, {"token": token, "hwid": "a" * 64},
            )
            response = await self.client.client_validate.__wrapped__(fake_request, cross_app_req, db)
            payload = self._decrypt_response(response, other_secret)
            self.assertFalse(payload["success"])
            self.assertEqual(payload["message"], "SESSION_EXPIRED")

    async def test_protected_request_rechecks_license_status(self):
        seeded = await self._seed_app()
        fake_request = _FakeRequest(headers={"User-Agent": "EnAuthTest/1.0"})

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            login_req = self._encrypted_request(
                seeded["app_id"], seeded["secret"],
                {"version": "1.0.0", "license_key": seeded["license_key"], "hwid": "a" * 64},
            )
            login_resp = await self.client.client_login.__wrapped__(fake_request, login_req, db)
            token = self._decrypt_response(login_resp, seeded["secret"])["token"]
            await db.execute("UPDATE licenses SET status='banned' WHERE id=?", (seeded["license_id"],))
            await db.commit()

            validate_req = self._encrypted_request(
                seeded["app_id"], seeded["secret"], {"token": token, "hwid": "a" * 64},
            )
            response = await self.client.client_validate.__wrapped__(fake_request, validate_req, db)
            payload = self._decrypt_response(response, seeded["secret"])
            self.assertFalse(payload["success"])
            self.assertEqual(payload["message"], "BANNED_KEY")
            async with db.execute("SELECT COUNT(*) FROM sessions WHERE token=?", (token,)) as cur:
                self.assertEqual((await cur.fetchone())[0], 0)

    async def test_invalid_signature_does_not_consume_nonce(self):
        seeded = await self._seed_app()
        req = self._encrypted_request(seeded["app_id"], seeded["secret"], {"version": "1.0.0"})
        req.sig = "0" * 64

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            with self.assertRaises(Exception):
                await self.client.parse_request(req, db)
            async with db.execute("SELECT COUNT(*) FROM request_nonces") as cur:
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

    async def test_protocol_v2_login_validate_and_download_without_app_secret(self):
        seeded = await self._seed_app()
        login_path = "/api/client/login"
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            login_req = self._v2_request(seeded["app_id"], {
                "version": "1.0.0", "license_key": seeded["license_key"], "hwid": "d" * 64,
            })
            login_resp = await self.client.client_login.__wrapped__(
                _FakeRequest(path=login_path), login_req, db
            )
            login = self._verify_v2_response(login_resp, login_path, login_req.nonce)
            self.assertTrue(login["success"])

            validate_path = "/api/client/validate"
            validate_req = self._v2_request(seeded["app_id"], {
                "token": login["token"], "hwid": "d" * 64,
            })
            validate_resp = await self.client.client_validate.__wrapped__(
                _FakeRequest(path=validate_path), validate_req, db
            )
            validated = self._verify_v2_response(validate_resp, validate_path, validate_req.nonce)
            self.assertTrue(validated["success"])
            self.assertNotEqual(validated["token"], login["token"])
            self.assertIsNone(await self.client.get_app_session(db, login["token"], seeded["app_id"]))

            download_path = "/api/client/download"
            ticket_path = "/api/client/download-ticket"
            ticket_req = self._v2_request(seeded["app_id"], {
                "token": validated["token"], "hwid": "d" * 64, "name": "payload.bin",
            })
            ticket_resp = await self.client.client_download_ticket.__wrapped__(
                _FakeRequest(path=ticket_path), ticket_req, db
            )
            ticket = self._verify_v2_response(ticket_resp, ticket_path, ticket_req.nonce)
            self.assertTrue(ticket["success"])
            substituted_req = self._v2_request(seeded["app_id"], {
                "token": ticket["token"], "hwid": "d" * 64, "name": "other.bin",
                "ticket": ticket["ticket"],
            })
            substituted_resp = await self.client.client_download.__wrapped__(
                _FakeRequest(path=download_path), substituted_req, db
            )
            substituted = self._verify_v2_response(
                substituted_resp, download_path, substituted_req.nonce
            )
            self.assertEqual(substituted["message"], "INVALID_DOWNLOAD_TICKET")
            download_req = self._v2_request(seeded["app_id"], {
                "token": ticket["token"], "hwid": "d" * 64, "name": "payload.bin",
                "ticket": ticket["ticket"],
            })
            download_resp = await self.client.client_download.__wrapped__(
                _FakeRequest(path=download_path), download_req, db
            )
            download = self._verify_v2_response(download_resp, download_path, download_req.nonce)
            self.assertEqual(download["encryption"], "TLS-SIGNED-SESSION-v2")
            self.assertEqual(base64.b64decode(download["data"], validate=True), b"hello world")
            self.assertNotEqual(download["token"], validated["token"])

            replay_req = self._v2_request(seeded["app_id"], {
                "token": download["token"], "hwid": "d" * 64, "name": "payload.bin",
                "ticket": ticket["ticket"],
            })
            replay_resp = await self.client.client_download.__wrapped__(
                _FakeRequest(path=download_path), replay_req, db
            )
            replay = self._verify_v2_response(replay_resp, download_path, replay_req.nonce)
            self.assertEqual(replay["message"], "INVALID_DOWNLOAD_TICKET")

    async def test_product_version_policy_blocks_compromised_client(self):
        seeded = await self._seed_app()
        path = "/api/client/login"
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                """INSERT INTO products
                   (id,app_id,name,level,required_client_version,blocked_client_versions)
                   VALUES(?,?,?,?,?,?)""",
                ("product-v", seeded["app_id"], "Protected", "protected", "2.0.0", '["1.0.0"]'),
            )
            await db.execute(
                "INSERT INTO license_products(id,license_id,product_id,expires_at) VALUES(?,?,?,?)",
                ("ent-v", seeded["license_id"], "product-v", "2099-12-31 23:59:59"),
            )
            await db.commit()
            req = self._v2_request(seeded["app_id"], {
                "version": "1.0.0", "license_key": seeded["license_key"],
                "hwid": "f" * 64, "product_id": "product-v",
            })
            response = await self.client.client_login.__wrapped__(_FakeRequest(path=path), req, db)
            payload = self._verify_v2_response(response, path, req.nonce)
            self.assertEqual(payload["message"], "OUTDATED_VERSION")
            self.assertEqual(payload["required_version"], "2.0.0")

    async def test_protocol_v2_replay_and_fake_license_are_rejected(self):
        seeded = await self._seed_app()
        path = "/api/client/login"
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            fake_req = self._v2_request(seeded["app_id"], {
                "version": "1.0.0", "license_key": "FAKE-KEY", "hwid": "e" * 64,
            })
            fake_resp = await self.client.client_login.__wrapped__(_FakeRequest(path=path), fake_req, db)
            self.assertEqual(
                self._verify_v2_response(fake_resp, path, fake_req.nonce)["message"], "INVALID_KEY"
            )
            with self.assertRaises(Exception) as replay:
                await self.client.parse_request(fake_req, db, path)
            self.assertIn("REPLAY_ATTACK", str(replay.exception))

    async def test_protocol_v2_response_tampering_breaks_signature(self):
        seeded = await self._seed_app()
        path = "/api/client/init"
        req = self._v2_request(seeded["app_id"], {"version": "1.0.0"})
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            response = await self.client.client_init.__wrapped__(_FakeRequest(path=path), req, db)
        body = json.loads(response.body.decode("utf-8"))
        decoded = json.loads(base64.b64decode(body["payload"]))
        decoded["success"] = not decoded["success"]
        body["payload"] = base64.b64encode(
            json.dumps(decoded, separators=(",", ":")).encode()
        ).decode()
        response.body = json.dumps(body).encode()
        with self.assertRaises(InvalidSignature):
            self._verify_v2_response(response, path, req.nonce)

    async def test_legacy_protocol_can_be_disabled_after_migration(self):
        seeded = await self._seed_app()
        req = self._encrypted_request(
            seeded["app_id"], seeded["secret"], {"version": "1.0.0"}
        )
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            previous = self.client.ALLOW_LEGACY_PROTOCOL
            self.client.ALLOW_LEGACY_PROTOCOL = False
            try:
                with self.assertRaises(Exception) as rejected:
                    await self.client.parse_request(req, db, "/api/client/init")
                self.assertIn("CLIENT_UPDATE_REQUIRED", str(rejected.exception))
            finally:
                self.client.ALLOW_LEGACY_PROTOCOL = previous


if __name__ == "__main__":
    unittest.main()
