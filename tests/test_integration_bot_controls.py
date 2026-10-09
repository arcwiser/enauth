import os
import hashlib
import importlib
import unittest
from datetime import datetime, timedelta, timezone

import aiosqlite
from fastapi import HTTPException
from starlette.requests import Request

os.environ.setdefault("LICENSE_KEY_PEPPER", "test-license-pepper-that-is-long-enough")

from database import SCHEMA
from routes import integrations
from utils.crypto import encrypt_license_key, hash_license_key, mask_license_key


class DiscordIntegrationControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = await aiosqlite.connect(":memory:")
        self.db.row_factory = aiosqlite.Row
        await self.db.executescript(SCHEMA)
        await self.db.execute(
            "INSERT INTO applications(id,name,secret_key) VALUES('app-1','Test','secret')"
        )
        await self.db.execute(
            "INSERT INTO products(id,app_id,name,level) VALUES('product-1','app-1','One','one')"
        )
        await self.db.execute(
            "INSERT INTO products(id,app_id,name,level) VALUES('product-2','app-1','Two','two')"
        )
        self.keys = [
            "AAAAAA-BBBBBB-CCCCCC-DDDDDD-EEEEEE-FFFFFF",
            "GGGGGG-HHHHHH-IIIIII-JJJJJJ-KKKKKK-LLLLLL",
        ]
        expiry = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        for index, raw_key in enumerate(self.keys, 1):
            license_id = f"license-{index}"
            await self.db.execute(
                """INSERT INTO licenses(id,key,key_hash,key_ciphertext,app_id,expires_at)
                   VALUES(?,?,?,?,?,?)""",
                (license_id, mask_license_key(raw_key), hash_license_key(raw_key),
                 encrypt_license_key(raw_key), "app-1", expiry),
            )
            await self.db.execute(
                "INSERT INTO license_products(id,license_id,product_id,expires_at) VALUES(?,?,?,?)",
                (f"entitlement-{index}", license_id, "product-1", expiry),
            )
        await self.db.commit()
        self.api_key = {"id": "api-1", "role": "owner", "scopes": "admin"}

    async def asyncTearDown(self):
        await self.db.close()

    async def _discord_key(self):
        await importlib.import_module("migrations.0010_discord_integrations").apply(self.db)
        key = "enauth_discord_" + "d" * 43
        await self.db.execute(
            "INSERT INTO discord_integrations(id,app_id,key_hash,key_prefix) VALUES(?,?,?,?)",
            ("discord-1", "app-1", hashlib.sha256(key.encode()).hexdigest(), key[:20]),
        )
        await self.db.commit()
        return key

    async def _owner_api_key(self, scopes, role="owner"):
        raw = "enauth_" + "a" * 43
        await self.db.execute(
            "INSERT INTO admin_users(id,username,password_hash,role) VALUES(?,?,?,?)",
            ("api-owner", "owner", "unused", role),
        )
        await self.db.execute(
            "INSERT INTO api_keys(id,user_id,key_hash,key_prefix,name,scopes) VALUES(?,?,?,?,?,?)",
            ("api-test", "api-owner", hashlib.sha256(raw.encode()).hexdigest(), raw[:20], "Test", scopes),
        )
        await self.db.commit()
        return raw

    def _request(self, path, method="GET", app_id=None):
        return Request({"type": "http", "method": method, "path": path, "headers": [],
                        "path_params": {"app_id": app_id} if app_id else {}})

    async def test_discord_key_cannot_access_global_resources_or_other_apps(self):
        raw = await self._discord_key()
        await self.db.execute("INSERT INTO applications(id,name,secret_key) VALUES('app-2','Private','secret-2')")
        await self.db.commit()
        for method, path, scope in [
            ("GET", "/api/integrations/variables", "read"),
            ("PUT", "/api/integrations/variables", "admin"),
            ("DELETE", "/api/integrations/variables/private", "admin"),
            ("GET", "/api/integrations/resellers", "resellers.read"),
            ("POST", "/api/integrations/resellers/reseller-1/credit", "resellers.credit"),
        ]:
            with self.subTest(path=path, method=method), self.assertRaises(HTTPException) as error:
                await integrations.require_scope(scope)(self._request(path, method), None, raw, self.db)
            self.assertEqual(error.exception.status_code, 403)
        with self.assertRaises(HTTPException) as error:
            await integrations.require_scope("apps.read")(
                self._request("/api/integrations/apps/app-2", app_id="app-2"), None, raw, self.db,
            )
        self.assertEqual(error.exception.status_code, 403)
        scoped_key = await integrations.require_scope("apps.read")(
            self._request("/api/integrations/apps"), None, raw, self.db,
        )
        self.assertEqual([row["id"] for row in await integrations.apps(scoped_key, self.db)], ["app-1"])
        await self.db.execute("UPDATE discord_integrations SET is_active=0")
        await self.db.commit()
        with self.assertRaises(HTTPException) as error:
            await integrations.require_scope("apps.read")(
                self._request("/api/integrations/apps"), None, raw, self.db,
            )
        self.assertEqual(error.exception.status_code, 401)

    async def test_read_scopes_cannot_reveal_saved_license_credentials(self):
        raw = await self._owner_api_key("licenses.read")
        request = self._request("/api/integrations/apps/app-1/licenses", app_id="app-1")
        key = await integrations.require_scope("licenses.read")(request, raw, None, self.db)
        for scopes in ("read", "write", "licenses.read"):
            key["scopes"] = scopes
            with self.subTest(scopes=scopes):
                rows = await integrations.licenses("app-1", None, 25, key, self.db)
                history = await integrations.license_history("app-1", "license-1", 50, key, self.db)
                self.assertNotIn(self.keys[0], str(rows))
                self.assertNotIn(self.keys[1], str(rows))
                self.assertNotIn(self.keys[0], str(history))
                self.assertFalse(integrations.has_scope(key, "licenses.reveal"))
        with self.assertRaises(HTTPException) as error:
            await integrations.require_scope("licenses.reveal")(request, raw, None, self.db)
        self.assertEqual(error.exception.status_code, 403)
        key["scopes"] = "licenses.read,licenses.reveal"
        rows = await integrations.licenses("app-1", None, 25, key, self.db)
        self.assertEqual({row["key"] for row in rows}, set(self.keys))
        self.assertTrue(integrations.has_scope({"scopes": "licenses.generate"}, "licenses.generate"))
        self.assertFalse(integrations.has_scope({"scopes": "licenses.generate"}, "licenses.reveal"))
        self.assertFalse(integrations.has_scope({"scopes": "licenses.generate"}, "apps.modify"))

    async def test_reseller_role_cannot_use_integration_api(self):
        raw = await self._owner_api_key("admin", role="reseller")
        with self.assertRaises(HTTPException) as error:
            await integrations.require_scope("licenses.generate")(
                self._request("/api/integrations/apps/app-1/licenses", "POST", "app-1"), raw, None, self.db,
            )
        self.assertEqual(error.exception.status_code, 403)

    async def test_add_product_and_reveal_it_in_license_details(self):
        result = await integrations.add_license_product(
            "app-1", self.keys[0], integrations.EntitlementAddBody(product_id="product-2", duration_hours=48),
            self.api_key, self.db,
        )
        self.assertEqual(result["product"], "Two")
        details = await integrations.license_details("app-1", self.keys[0], self.api_key, self.db)
        self.assertEqual({item["product_id"] for item in details["products"]}, {"product-1", "product-2"})

    async def test_extend_product_all_and_show_each_key_history(self):
        result = await integrations.extend_product_license(
            "app-1", "product-1", "all", integrations.ExtendBody(hours=24), self.api_key, self.db
        )
        self.assertEqual(result["affected"], 2)
        for raw_key in self.keys:
            history = await integrations.license_history("app-1", raw_key, 50, self.api_key, self.db)
            self.assertEqual(history["events"][0]["action"], "integration_product_extended")

    async def test_pause_preview_and_resume_with_compensation(self):
        await integrations.pause_app(
            "app-1", integrations.PauseBody(reason="Maintenance"), self.api_key, self.db
        )
        preview = await integrations.resume_app_preview("app-1", 48, self.api_key, self.db)
        self.assertEqual(preview["affected_licenses"], 2)
        self.assertEqual(preview["compensation_seconds"], 48 * 3600)
        result = await integrations.resume_app(
            "app-1", integrations.ResumeBody(compensation_hours=48), self.api_key, self.db
        )
        self.assertEqual(result["affected_licenses"], 2)
        history = await integrations.license_history("app-1", self.keys[0], 50, self.api_key, self.db)
        self.assertIn("integration_compensation", {event["action"] for event in history["events"]})


if __name__ == "__main__":
    unittest.main()
