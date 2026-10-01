import importlib
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
from fastapi import Response

from utils.crypto import hash_password, encrypt_license_key, decrypt_license_key


MODULES_TO_RESET = [
    "main",
    "database",
    "routes.admin",
    "routes.client",
    "routes.status",
    "utils.logger",
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


if __name__ == "__main__":
    unittest.main()
