import importlib
import io
import os
import shutil
import sys
import uuid
import unittest
from pathlib import Path
import logging

import aiosqlite
import pyotp
from fastapi import HTTPException
from fastapi import Request, Response, UploadFile

from utils.crypto import hash_password, encrypt_license_key, decrypt_license_key


MODULES_TO_RESET = [
    "main",
    "database",
    "routes.admin",
    "routes.client",
    "routes.status",
    "utils.logger",
    "utils.response_signing",
]


class AdminSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.workdir = Path(__file__).resolve().parent / f"_tmp-{uuid.uuid4().hex}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.workdir / "enauth.db"
        self.log_path = self.workdir / "server.log"

        os.environ["DB_PATH"] = str(self.db_path)
        os.environ["LOG_FILE"] = str(self.log_path)
        os.environ["LOG_LEVEL"] = "INFO"
        os.environ["LOG_MAX_BYTES"] = str(1024 * 1024)
        os.environ["LOG_BACKUP_COUNT"] = "1"
        os.environ["DEBUG"] = "false"
        os.environ["TEMP_2FA_TTL_MINUTES"] = "5"
        os.environ["LICENSE_KEY_PEPPER"] = "test-license-pepper-that-is-long-enough"
        os.environ["BACKUP_DIR"] = str(self.workdir / "backups")
        os.environ["BACKUP_RETENTION"] = "2"
        os.environ["RESPONSE_SIGNING_KEY_PATH"] = str(self.workdir / "response-signing-key.pem")

        for name in MODULES_TO_RESET:
            sys.modules.pop(name, None)

        self.database = importlib.import_module("database")
        self.admin = importlib.import_module("routes.admin")
        self.status_routes = importlib.import_module("routes.status")
        await self.database.init_db()

    async def asyncTearDown(self):
        logger = logging.getLogger("root")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        shutil.rmtree(self.workdir, ignore_errors=True)

    async def _create_admin_user(self, username="admin", role="owner", two_factor_enabled=1):
        secret = pyotp.random_base32()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            user_id = "user-1"
            await db.execute(
                """
                INSERT INTO admin_users (id, username, password_hash, role, two_factor_enabled, two_factor_secret)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, hash_password("Password123!"), role, two_factor_enabled, secret),
            )
            await db.commit()
        return user_id, secret

    async def test_require_panel_owner_blocks_non_owner_admins(self):
        with self.assertRaises(HTTPException) as ctx:
            self.admin.require_panel_owner({"_source": "admin_users", "role": "admin"})
        self.assertEqual(ctx.exception.status_code, 403)

        with self.assertRaises(HTTPException) as ctx:
            self.admin.require_panel_owner({"_source": "auth_users", "role": "owner"})
        self.assertEqual(ctx.exception.status_code, 403)

        self.assertIsNone(
            self.admin.require_panel_owner({"_source": "admin_users", "role": "owner"})
        )

    async def test_two_factor_temp_session_persists_and_verifies(self):
        user_id, secret = await self._create_admin_user()

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            temp_token = await self.admin.create_temp_2fa_session(db, user_id, "owner")

            async with db.execute(
                "SELECT token, user_id, role FROM temp_2fa_sessions WHERE token = ?",
                (temp_token,),
            ) as cur:
                row = await cur.fetchone()

            self.assertIsNotNone(row)
            self.assertEqual(row["user_id"], user_id)
            self.assertEqual(row["role"], "owner")

            response = Response()
            result = await self.admin.verify_two_factor.__wrapped__(
                response=response,
                body=self.admin.TwoFactorVerifyBody(
                    temp_token=temp_token,
                    code=pyotp.TOTP(secret).now(),
                ),
                db=db,
            )

            self.assertEqual(result["username"], "admin")
            cookie = response.headers.get("set-cookie", "")
            self.assertIn("enauth_admin_session=", cookie)
            session_token = cookie.split("enauth_admin_session=", 1)[1].split(";", 1)[0]

            async with db.execute(
                "SELECT COUNT(*) FROM temp_2fa_sessions WHERE token = ?",
                (temp_token,),
            ) as cur:
                remaining = (await cur.fetchone())[0]
            self.assertEqual(remaining, 0)

            async with db.execute(
                "SELECT COUNT(*) FROM admin_sessions WHERE token = ?",
                (session_token,),
            ) as cur:
                sessions = (await cur.fetchone())[0]
            self.assertEqual(sessions, 1)

    async def test_admin_session_expiry_logout_cookie_and_login_limit_policy(self):
        user_id, _ = await self._create_admin_user(two_factor_enabled=0)
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                "INSERT INTO admin_sessions(id,user_id,token,expires_at) VALUES(?,?,?,?)",
                ("expired-session", user_id, "expired-token", "2000-01-01 00:00:00"),
            )
            await db.execute(
                "INSERT INTO admin_sessions(id,user_id,token,expires_at) VALUES(?,?,?,datetime('now','+1 hour'))",
                ("active-session", user_id, "active-token"),
            )
            await db.commit()

            def cookie_request(token: str):
                return Request({
                    "type": "http", "method": "GET", "scheme": "https",
                    "path": "/api/admin/auth/me", "raw_path": b"/api/admin/auth/me",
                    "query_string": b"", "headers": [(b"cookie", f"enauth_admin_session={token}".encode())],
                    "client": ("127.0.0.1", 12345), "server": ("testserver", 443),
                })

            with self.assertRaises(HTTPException) as expired:
                await self.admin.require_admin(cookie_request("expired-token"), authorization=None, db=db)
            self.assertEqual(expired.exception.status_code, 401)
            authenticated = await self.admin.require_admin(
                cookie_request("active-token"), authorization=None, db=db,
            )
            self.assertEqual(authenticated["id"], user_id)

            login_response = Response()
            result = await self.admin.admin_login.__wrapped__(
                response=login_response, request=None,
                body=self.admin.LoginBody(username="admin", password="Password123!"), db=db,
            )
            self.assertEqual(result["username"], "admin")
            cookie = login_response.headers["set-cookie"].lower()
            self.assertIn("httponly", cookie)
            self.assertIn("secure", cookie)
            self.assertIn("samesite=strict", cookie)
            self.assertIn("path=/", cookie)

            logout_response = Response()
            await self.admin.admin_logout(logout_response, user=authenticated, db=db)
            async with db.execute("SELECT COUNT(*) FROM admin_sessions WHERE user_id=?", (user_id,)) as cur:
                self.assertEqual((await cur.fetchone())[0], 0)
            removal = logout_response.headers["set-cookie"].lower()
            self.assertIn("enauth_admin_session=", removal)
            self.assertIn("max-age=0", removal)

        limits = self.admin.limiter._route_limits["routes.admin.admin_login"]
        self.assertEqual(str(limits[0].limit), "8 per 1 minute")
        self.assertIs(limits[0].key_func, importlib.import_module("routes.client").get_ip)

    async def test_mfa_cannot_be_bypassed_or_replayed(self):
        user_id, secret = await self._create_admin_user(two_factor_enabled=1)
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            login_response = Response()
            challenge = await self.admin.admin_login.__wrapped__(
                response=login_response, request=None,
                body=self.admin.LoginBody(username="admin", password="Password123!"), db=db,
            )
            self.assertTrue(challenge["two_factor_required"])
            self.assertNotIn("set-cookie", login_response.headers)
            async with db.execute("SELECT COUNT(*) FROM admin_sessions WHERE user_id=?", (user_id,)) as cur:
                self.assertEqual((await cur.fetchone())[0], 0)

            with self.assertRaises(HTTPException) as wrong_code:
                await self.admin.verify_two_factor.__wrapped__(
                    response=Response(), request=None,
                    body=self.admin.TwoFactorVerifyBody(
                        temp_token=challenge["temp_token"], code="000000",
                    ), db=db,
                )
            self.assertEqual(wrong_code.exception.status_code, 401)
            async with db.execute("SELECT COUNT(*) FROM admin_sessions WHERE user_id=?", (user_id,)) as cur:
                self.assertEqual((await cur.fetchone())[0], 0)

            async with db.execute(
                "SELECT two_factor_secret FROM admin_users WHERE id=?", (user_id,)
            ) as cur:
                stored_secret = (await cur.fetchone())["two_factor_secret"]
            self.assertEqual(stored_secret, secret)
            valid_code = pyotp.TOTP(stored_secret).now()
            await self.admin.verify_two_factor.__wrapped__(
                response=Response(), request=None,
                body=self.admin.TwoFactorVerifyBody(
                    temp_token=challenge["temp_token"], code=valid_code,
                ), db=db,
            )
            with self.assertRaises(HTTPException) as replay:
                await self.admin.verify_two_factor.__wrapped__(
                    response=Response(), request=None,
                    body=self.admin.TwoFactorVerifyBody(
                        temp_token=challenge["temp_token"], code=valid_code,
                    ), db=db,
                )
            self.assertEqual(replay.exception.status_code, 401)
            async with db.execute("SELECT COUNT(*) FROM admin_sessions WHERE user_id=?", (user_id,)) as cur:
                self.assertEqual((await cur.fetchone())[0], 1)

    async def test_cleanup_removes_expired_temp_2fa_sessions(self):
        user_id, _ = await self._create_admin_user(two_factor_enabled=0)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                """
                INSERT INTO temp_2fa_sessions (id, user_id, role, token, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                ("temp-1", user_id, "owner", "expired-token", "2000-01-01 00:00:00"),
            )
            await db.commit()

            await self.admin.cleanup_runtime_state(db)

            async with db.execute(
                "SELECT COUNT(*) FROM temp_2fa_sessions WHERE token = ?",
                ("expired-token",),
            ) as cur:
                remaining = (await cur.fetchone())[0]

        self.assertEqual(remaining, 0)

    async def test_database_backup_is_verified_and_retained(self):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            first = await self.admin.create_backup(user={"role": "owner"}, db=db)
            second = await self.admin.create_backup(user={"role": "owner"}, db=db)
            third = await self.admin.create_backup(user={"role": "owner"}, db=db)

        backup_dir = self.workdir / "backups"
        files = list(backup_dir.glob("enauth-*.db"))
        self.assertEqual(len(files), 2)
        self.assertIn(third["name"], {path.name for path in files})
        async with aiosqlite.connect(backup_dir / third["name"]) as backup_db:
            async with backup_db.execute("PRAGMA integrity_check") as cur:
                self.assertEqual((await cur.fetchone())[0], "ok")

        listing = await self.admin.list_backups(user={"role": "owner"})
        self.assertEqual(len(listing["backups"]), 2)
        self.assertGreater(second["size_bytes"], 0)

    async def test_discord_key_is_app_bound_hashed_and_shown_once(self):
        user_id, _ = await self._create_admin_user(two_factor_enabled=0)
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                "INSERT INTO applications(id,name,secret_key,owner_user_id) VALUES(?,?,?,?)",
                ("app-discord", "Discord App", "s" * 64, user_id),
            )
            await db.commit()
            result = await self.admin.create_discord_integration(
                self.admin.CreateDiscordIntegrationBody(app_id="app-discord"),
                user={"id": user_id, "role": "owner"}, db=db,
            )
            self.assertTrue(result["key"].startswith("enauth_discord_"))
            async with db.execute("SELECT key_hash,key_prefix,app_id FROM discord_integrations") as cur:
                stored = await cur.fetchone()
        self.assertEqual(stored["app_id"], "app-discord")
        self.assertNotEqual(stored["key_hash"], result["key"])
        self.assertEqual(stored["key_hash"], __import__("hashlib").sha256(result["key"].encode()).hexdigest())

    async def test_server_response_signature_uses_public_key_verification(self):
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        signing = importlib.import_module("utils.response_signing")
        signing.ensure_response_signing_key()
        message = "app|123|encrypted"
        raw = base64.b64decode(signing.sign_response(message))
        public_hex = signing.response_public_key_hex()
        numbers = ec.EllipticCurvePublicNumbers(
            int(public_hex[:64], 16), int(public_hex[64:], 16), ec.SECP256R1()
        )
        numbers.public_key().verify(
            encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
            message.encode(), ec.ECDSA(hashes.SHA256()),
        )

    async def test_password_reset_token_is_not_written_to_logs(self):
        await self._create_admin_user(two_factor_enabled=0)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            result = await self.admin.request_password_reset.__wrapped__(
                body=self.admin.PasswordResetRequestBody(username="admin"),
                db=db,
            )

            self.assertIsNone(result["token"])

        log_text = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn("Password reset token for", log_text)
        self.assertIn("Password reset requested for admin", log_text)

    async def test_portal_downloads_are_opt_in_and_product_scoped(self):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)", ("app-1", "App", "s" * 64))
            await db.execute("INSERT INTO products(id,app_id,name,level) VALUES(?,?,?,?)", ("p-1", "app-1", "Loader", "loader"))
            await db.execute("INSERT INTO licenses(id,key,key_hash,app_id) VALUES(?,?,?,?)", ("l-1", "masked", "h" * 64, "app-1"))
            await db.execute(
                "INSERT INTO app_files(id,app_id,name,content,portal_visible,product_id) VALUES(?,?,?,?,?,?)",
                ("f-1", "app-1", "loader.exe", b"safe", 0, "p-1"),
            )
            await db.commit()
            lic = {"id": "l-1", "app_id": "app-1"}

            with self.assertRaises(HTTPException) as private_error:
                await self.admin.portal_download_file("f-1", lic=lic, db=db)
            self.assertEqual(private_error.exception.status_code, 404)

            await db.execute("UPDATE app_files SET portal_visible=1 WHERE id='f-1'")
            await db.commit()
            with self.assertRaises(HTTPException) as unowned_error:
                await self.admin.portal_download_file("f-1", lic=lic, db=db)
            self.assertEqual(unowned_error.exception.status_code, 404)

            await db.execute(
                "INSERT INTO license_products(id,license_id,product_id) VALUES(?,?,?)",
                ("e-1", "l-1", "p-1"),
            )
            await db.commit()
            response = await self.admin.portal_download_file("f-1", lic=lic, db=db)
            self.assertEqual(response.headers["content-disposition"].split(";")[0], 'attachment')

    async def test_public_status_does_not_expose_application_secrets(self):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)", ("app-1", "Public App", "top-secret"))
            await db.execute(
                "INSERT INTO products(id,app_id,name,level,service_status,status_message) VALUES(?,?,?,?,?,?)",
                ("p-1", "app-1", "Loader", "loader", "maintenance", "Updating safely"),
            )
            await db.commit()
            result = await self.status_routes.public_status("app-1", db)
        encoded = str(result)
        self.assertNotIn("top-secret", encoded)
        self.assertEqual(result["overall_status"], "maintenance")

    async def test_custom_status_color_is_strictly_validated(self):
        valid = self.admin.UpdateProductBody(service_status="Updating servers", status_color="#12aBef")
        self.assertEqual(valid.status_color, "#12abef")
        with self.assertRaises(ValueError):
            self.admin.UpdateProductBody(service_status="Online", status_color="red; background:url(x)")

    async def test_license_keys_use_authenticated_reversible_storage(self):
        original = "ABCDEF-123456-ABCDEF-123456-ABCDEF-123456"
        encrypted = encrypt_license_key(original)
        self.assertNotIn(original, encrypted)
        self.assertEqual(decrypt_license_key(encrypted), original)
        tampered = encrypted[:-2] + ("AA" if encrypted[-2:] != "AA" else "BB")
        with self.assertRaises(Exception):
            decrypt_license_key(tampered)

    async def test_reseller_signin_returns_a_working_session(self):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                "INSERT INTO resellers(id,username,password_hash,balance) VALUES(?,?,?,?)",
                ("reseller-1", "seller", hash_password("Password123!"), 25),
            )
            await db.commit()
            result = await self.admin.reseller_signin.__wrapped__(
                request=None,
                body=self.admin.LoginBody(username="seller", password="Password123!"), db=db,
            )
            self.assertTrue(result["token"])
            async with db.execute("SELECT 1 FROM reseller_sessions WHERE token=?", (result["token"],)) as cur:
                self.assertIsNotNone(await cur.fetchone())

    async def test_loader_publish_archives_previous_release(self):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)", ("app-1", "App", "z" * 64))
            await db.commit()
            caller = {"id": "owner-1", "username": "owner", "role": "owner", "_source": "admin_users"}
            first = await self.admin.upload_loader_release(
                app_id="app-1", version="1.0.0", logical_name="loader.exe",
                release_notes="first", file=UploadFile(filename="loader.exe", file=io.BytesIO(b"MZfirst")),
                user=caller, db=db,
            )
            second = await self.admin.upload_loader_release(
                app_id="app-1", version="1.1.0", logical_name="loader.exe",
                release_notes="second", file=UploadFile(filename="loader.exe", file=io.BytesIO(b"MZsecond")),
                user=caller, db=db,
            )
            self.assertEqual(second["replaced_file_id"], first["id"])
            async with db.execute(
                "SELECT release_version,is_active,is_archived FROM app_files ORDER BY release_version"
            ) as cur:
                rows = await cur.fetchall()
            self.assertEqual([(r["release_version"], r["is_active"], r["is_archived"]) for r in rows],
                             [("1.0.0", 0, 1), ("1.1.0", 1, 0)])

    async def test_security_control_center_and_lockdown_do_not_expose_secrets(self):
        caller = {"id": "owner-1", "username": "owner", "role": "owner", "_source": "admin_users"}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)",
                             ("app-sec", "Secure App", "never-return-this-secret"))
            await db.execute("INSERT INTO licenses(id,key,key_hash,app_id) VALUES(?,?,?,?)",
                             ("lic-sec", "masked", "a" * 64, "app-sec"))
            await db.execute(
                """INSERT INTO sessions(id,token,license_id,hwid,ip,app_id,expires_at,token_expires_at,protocol)
                   VALUES(?,?,?,?,?,?,datetime('now','+1 hour'),datetime('now','+5 minutes'),2)""",
                ("sess-sec", "token-sec", "lic-sec", "h" * 64, "127.0.0.1", "app-sec"),
            )
            await db.commit()
            overview = await self.admin.security_control_center(user=caller, db=db)
            self.assertEqual(overview["applications"][0]["active_sessions"], 1)
            self.assertNotIn("never-return-this-secret", str(overview))

            with self.assertRaises(HTTPException):
                await self.admin.emergency_app_lockdown(
                    "app-sec", self.admin.EmergencyLockdownBody(reason="incident", confirmation="wrong"),
                    user=caller, db=db,
                )
            result = await self.admin.emergency_app_lockdown(
                "app-sec", self.admin.EmergencyLockdownBody(
                    reason="Suspected credential theft", confirmation="LOCK app-sec"),
                user=caller, db=db,
            )
            self.assertEqual(result["revoked_sessions"], 1)
            events = await self.admin.list_security_events(
                app_id="app-sec", severity="critical", search=None, limit=20, offset=0,
                user=caller, db=db,
            )
            self.assertEqual(events["items"][0]["action"], "emergency_lockdown")
            async with db.execute("SELECT is_paused FROM applications WHERE id='app-sec'") as cur:
                app = await cur.fetchone()
            self.assertEqual(app["is_paused"], 1)

    async def test_api_key_rotation_invalidates_old_key_and_reveals_new_key_once(self):
        user_id, _ = await self._create_admin_user(two_factor_enabled=0)
        caller = {"id": user_id, "username": "admin", "role": "owner", "_source": "admin_users"}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            created = await self.admin.create_api_key(
                self.admin.CreateApiKeyBody(name="CI", scopes="apps.read"), user=caller, db=db,
            )
            old_hash = __import__("hashlib").sha256(created["key"].encode()).hexdigest()
            rotated = await self.admin.rotate_api_key(created["id"], user=caller, db=db)
            self.assertNotEqual(rotated["key"], created["key"])
            async with db.execute("SELECT key_hash,last_used,is_active FROM api_keys WHERE id=?", (created["id"],)) as cur:
                stored = await cur.fetchone()
            self.assertNotEqual(stored["key_hash"], old_hash)
            self.assertEqual(stored["key_hash"], __import__("hashlib").sha256(rotated["key"].encode()).hexdigest())
            self.assertEqual(stored["is_active"], 1)

    async def test_license_csv_export_reveals_authorized_keys_and_escapes_formulas(self):
        caller = {"id": "owner-1", "username": "owner", "role": "owner", "_source": "admin_users"}
        license_key = "EXPORT-ABCDEF-123456"
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)",
                             ("app-export", "Export App", "x" * 64))
            await db.execute(
                """INSERT INTO licenses(id,key,key_hash,key_ciphertext,app_id,notes,metadata)
                   VALUES(?,?,?,?,?,?,?)""",
                ("lic-export", "EXPORT…3456", "b" * 64, encrypt_license_key(license_key),
                 "app-export", "=unsafe formula", "customer-1"),
            )
            await db.commit()
            response = await self.admin.export_licenses_csv(
                app_id="app-export", status=None, search=None, product_id=None, expired=None, ids=None,
                user=caller, db=db,
            )
            content = b"".join([chunk async for chunk in response.body_iterator]).decode("utf-8-sig")
            self.assertIn(license_key, content)
            self.assertIn("Lifetime", content)
            self.assertIn("'=unsafe formula", content)
            self.assertEqual(response.headers["cache-control"], "no-store, private")
            await db.execute(
                "INSERT INTO licenses(id,key,key_hash,key_ciphertext,app_id) VALUES(?,?,?,?,?)",
                ("lic-other", "OTHER…9999", "c" * 64, encrypt_license_key("OTHER-KEY-999999"), "app-export"),
            )
            await db.commit()
            selected_response = await self.admin.export_licenses_csv(
                app_id=None, status=None, search=None, product_id=None, expired=None, ids="lic-export",
                user=caller, db=db,
            )
            selected_content = b"".join(
                [chunk async for chunk in selected_response.body_iterator]
            ).decode("utf-8-sig")
            self.assertIn(license_key, selected_content)
            self.assertNotIn("OTHER-KEY-999999", selected_content)

    async def test_license_csv_import_previews_then_creates_entitlements(self):
        caller = {"id": "owner-1", "username": "owner", "role": "owner", "_source": "admin_users"}
        csv_data = (
            "license_key,app_id,product_ids,status,expires,max_hwids,notes,metadata\n"
            "IMPORTED-KEY-123456,app-import,product-import,active,Lifetime,2,migrated,customer-7\n"
        ).encode()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)",
                             ("app-import", "Import App", "i" * 64))
            await db.execute("INSERT INTO products(id,app_id,name,level) VALUES(?,?,?,?)",
                             ("product-import", "app-import", "Product", "premium"))
            await db.commit()
            preview = await self.admin.preview_license_import(
                file=UploadFile(filename="licenses.csv", file=io.BytesIO(csv_data)), user=caller, db=db,
            )
            self.assertEqual(preview, {"valid_count": 1, "error_count": 0, "errors": []})
            result = await self.admin.import_licenses_csv(
                confirm=True, file=UploadFile(filename="licenses.csv", file=io.BytesIO(csv_data)),
                user=caller, db=db,
            )
            self.assertEqual(result["imported"], 1)
            async with db.execute(
                """SELECT l.max_hwids,l.expires_at,lp.product_id FROM licenses l
                   JOIN license_products lp ON lp.license_id=l.id WHERE l.app_id='app-import'"""
            ) as cur:
                imported = await cur.fetchone()
            self.assertEqual(imported["max_hwids"], 2)
            self.assertIsNone(imported["expires_at"])
            self.assertEqual(imported["product_id"], "product-import")

    async def test_license_templates_save_apply_data_and_delete(self):
        caller = {"id": "owner-1", "username": "owner", "role": "owner", "_source": "admin_users"}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)", ("app-t", "App", "t" * 64))
            await db.execute("INSERT INTO products(id,app_id,name,level) VALUES(?,?,?,?)", ("prod-t", "app-t", "Pro", "pro"))
            await db.commit()
            created = await self.admin.save_license_template(
                self.admin.LicenseTemplateBody(app_id="app-t", name="Monthly Pro", product_ids=["prod-t"],
                                               duration_hours=720, max_hwids=2, key_prefix="vip"),
                user=caller, db=db,
            )
            rows = await self.admin.list_license_templates(user=caller, db=db)
            self.assertEqual(rows[0]["product_ids"], ["prod-t"])
            self.assertEqual(rows[0]["key_prefix"], "VIP")
            self.assertEqual(rows[0]["duration_hours"], 720)
            self.assertEqual((await self.admin.delete_license_template(created["id"], user=caller, db=db))["ok"], True)

    async def test_download_incident_workspace_lists_and_clears_warnings(self):
        caller = {"id": "owner-1", "username": "owner", "role": "owner", "_source": "admin_users"}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO applications(id,name,secret_key) VALUES(?,?,?)", ("app-v", "Secure App", "v" * 64))
            await db.execute("INSERT INTO licenses(id,key,key_hash,app_id) VALUES(?,?,?,?)", ("lic-v", "WARN…1234", "d" * 64, "app-v"))
            await db.execute(
                """INSERT INTO download_violations(app_id,license_id,hwid,warning_count,last_reason,last_ip)
                   VALUES(?,?,?,?,?,?)""", ("app-v", "lic-v", "h" * 64, 2, "REPLAY", "127.0.0.1"),
            )
            await db.commit()
            rows = await self.admin.list_download_violations(app_id="app-v", limit=100, user=caller, db=db)
            self.assertEqual(rows[0]["warning_count"], 2)
            self.assertEqual(rows[0]["last_reason"], "REPLAY")
            result = await self.admin.clear_download_violation("app-v", "lic-v", "h" * 64, user=caller, db=db)
            self.assertTrue(result["ok"])
            self.assertEqual(await self.admin.list_download_violations(app_id="app-v", limit=100, user=caller, db=db), [])

    async def test_cross_tenant_resources_are_invisible_and_immutable(self):
        tenant_a = {"id": "tenant-a", "username": "tenant-a", "role": "owner", "_source": "auth_users"}
        tenant_b = {"id": "tenant-b", "username": "tenant-b", "role": "owner", "_source": "auth_users"}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            for tenant in (tenant_a, tenant_b):
                await db.execute(
                    "INSERT INTO auth_users(id,username,password_hash,role) VALUES(?,?,?,?)",
                    (tenant["id"], tenant["username"], "hash", "owner"),
                )
            await db.execute(
                "INSERT INTO applications(id,name,secret_key,owner_user_id) VALUES(?,?,?,?)",
                ("app-a", "Tenant A App", "a" * 64, tenant_a["id"]),
            )
            await db.execute(
                "INSERT INTO applications(id,name,secret_key,owner_user_id) VALUES(?,?,?,?)",
                ("app-b", "Tenant B App", "b" * 64, tenant_b["id"]),
            )
            await db.execute("INSERT INTO products(id,app_id,name,level) VALUES(?,?,?,?)",
                             ("product-a", "app-a", "A Product", "a"))
            await db.execute("INSERT INTO products(id,app_id,name,level) VALUES(?,?,?,?)",
                             ("product-b", "app-b", "B Product", "b"))
            await db.execute("INSERT INTO licenses(id,key,key_hash,app_id) VALUES(?,?,?,?)",
                             ("license-a", "A…KEY", "1" * 64, "app-a"))
            await db.execute("INSERT INTO licenses(id,key,key_hash,app_id) VALUES(?,?,?,?)",
                             ("license-b", "B…KEY", "2" * 64, "app-b"))
            await db.execute(
                "INSERT INTO app_files(id,app_id,name,content) VALUES(?,?,?,?)",
                ("file-a", "app-a", "a.bin", b"a"),
            )
            await db.execute(
                "INSERT INTO app_files(id,app_id,name,content) VALUES(?,?,?,?)",
                ("file-b", "app-b", "b.bin", b"b"),
            )
            await db.execute(
                """INSERT INTO sessions(id,token,license_id,hwid,ip,app_id,expires_at)
                   VALUES(?,?,?,?,?,?,datetime('now','+1 hour'))""",
                ("session-a", "token-a", "license-a", "a" * 64, "127.0.0.1", "app-a"),
            )
            await db.execute(
                """INSERT INTO sessions(id,token,license_id,hwid,ip,app_id,expires_at)
                   VALUES(?,?,?,?,?,?,datetime('now','+1 hour'))""",
                ("session-b", "token-b", "license-b", "b" * 64, "127.0.0.2", "app-b"),
            )
            await db.execute("INSERT INTO logs(app_id,action,details) VALUES(?,?,?)",
                             ("app-a", "tenant_a_event", "private-a"))
            await db.execute("INSERT INTO logs(app_id,action,details) VALUES(?,?,?)",
                             ("app-b", "tenant_b_event", "private-b"))
            await db.execute(
                "INSERT INTO resellers(id,username,password_hash,owner_user_id) VALUES(?,?,?,?)",
                ("reseller-a", "reseller-a", "hash", tenant_a["id"]),
            )
            await db.execute(
                "INSERT INTO resellers(id,username,password_hash,owner_user_id) VALUES(?,?,?,?)",
                ("reseller-b", "reseller-b", "hash", tenant_b["id"]),
            )
            await db.execute(
                "INSERT INTO device_fingerprints(id,license_id,fingerprint) VALUES(?,?,?)",
                ("device-b", "license-b", "fingerprint-b"),
            )
            await db.commit()

            apps = await self.admin.list_apps(user=tenant_a, db=db)
            products = await self.admin.list_products(user=tenant_a, db=db)
            licenses = await self.admin.list_licenses(user=tenant_a, db=db)
            files = await self.admin.list_files(user=tenant_a, db=db)
            sessions = await self.admin.list_sessions(user=tenant_a, db=db)
            logs = await self.admin.list_logs(user=tenant_a, db=db)
            resellers = await self.admin.list_resellers(user=tenant_a, db=db)

            self.assertEqual({row["id"] for row in apps}, {"app-a"})
            self.assertEqual({row["id"] for row in products}, {"product-a"})
            self.assertEqual({row["id"] for row in licenses}, {"license-a"})
            self.assertEqual({row["id"] for row in files}, {"file-a"})
            self.assertEqual({row["id"] for row in sessions}, {"session-a"})
            self.assertEqual({row["action"] for row in logs}, {"tenant_a_event"})
            self.assertEqual({row["id"] for row in resellers}, {"reseller-a"})

            async def assert_hidden(awaitable):
                with self.assertRaises(HTTPException) as error:
                    await awaitable
                self.assertEqual(error.exception.status_code, 404)

            await assert_hidden(self.admin.regen_secret("app-b", user=tenant_a, db=db))
            await assert_hidden(self.admin.update_app(
                "app-b", self.admin.UpdateAppBody(name="stolen"), user=tenant_a, db=db,
            ))
            await assert_hidden(self.admin.ban_license("license-b", user=tenant_a, db=db))
            await assert_hidden(self.admin.update_file_visibility(
                "file-b", self.admin.FileVisibilityBody(portal_visible=True), user=tenant_a, db=db,
            ))
            await assert_hidden(self.admin.reseller_ban_key(
                "license-b", reseller={"id": "reseller-a"}, db=db,
            ))
            await assert_hidden(self.admin.portal_name_device(
                "device-b", self.admin.PortalDeviceNameBody(name="stolen"),
                lic={"id": "license-a"}, db=db,
            ))

            async with db.execute("SELECT name,secret_key FROM applications WHERE id='app-b'") as cur:
                foreign_app = await cur.fetchone()
            async with db.execute("SELECT status FROM licenses WHERE id='license-b'") as cur:
                foreign_license = await cur.fetchone()
            async with db.execute("SELECT portal_visible FROM app_files WHERE id='file-b'") as cur:
                foreign_file = await cur.fetchone()
            self.assertEqual((foreign_app["name"], foreign_app["secret_key"]), ("Tenant B App", "b" * 64))
            self.assertEqual(foreign_license["status"], "active")
            self.assertEqual(foreign_file["portal_visible"], 0)

    async def test_tenant_cannot_search_admin_identities_or_global_health(self):
        tenant = {"id": "tenant-a", "username": "tenant-a", "role": "owner", "_source": "auth_users"}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("INSERT INTO admin_users(id,username,password_hash,role) VALUES(?,?,?,?)",
                             ("global-admin", "global-secret-admin", "hash", "owner"))
            await db.commit()
            result = await self.admin.global_search(
                query="global-secret-admin", category="users", limit=20, offset=0,
                user=tenant, db=db,
            )
            self.assertEqual(result["items"], [])
            with self.assertRaises(HTTPException) as activity_error:
                await self.admin.activity_timeline(
                    "user", "global-admin", user=tenant, db=db,
                )
            self.assertEqual(activity_error.exception.status_code, 403)
            with self.assertRaises(HTTPException) as health_error:
                await self.admin.require_owner(tenant)
            self.assertEqual(health_error.exception.status_code, 403)
            health_route = next(
                route for route in self.admin.router.routes
                if getattr(route, "path", None) == "/api/admin/operations/health"
            )
            self.assertIn(self.admin.require_owner, [dependency.call for dependency in health_route.dependant.dependencies])


if __name__ == "__main__":
    unittest.main()
