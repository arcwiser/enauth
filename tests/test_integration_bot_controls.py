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
        # Production databases contain this migrated credential column. Keeping it
        # in the fixture catches accidental SELECT * exposure in integration APIs.
        await self.db.execute("ALTER TABLE licenses ADD COLUMN client_password_hash TEXT")
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
        await self.db.execute(
            "UPDATE licenses SET client_password_hash='never-return-this' WHERE id='license-1'"
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
                        "path_params": {"app_id": app_id} if app_id else {},
                        "client": ("127.0.0.1", 12345)})

    async def test_api_key_app_binding_ip_allowlist_and_usage_counter(self):
        raw = await self._owner_api_key("apps.read")
        await self.db.execute("INSERT INTO applications(id,name,secret_key) VALUES('app-2','Other','secret-2')")
        await self.db.execute(
            "UPDATE api_keys SET app_id='app-1',allowed_ips=? WHERE id='api-test'",
            ('["127.0.0.0/8"]',),
        )
        await self.db.commit()
        with self.assertRaises(HTTPException) as wrong_app:
            await integrations.require_scope("apps.read")(
                self._request("/api/integrations/apps/app-2", app_id="app-2"), raw, None, self.db)
        self.assertEqual(wrong_app.exception.status_code, 403)
        with self.assertRaises(HTTPException) as global_create:
            await integrations.require_scope("apps.create")(
                self._request("/api/integrations/apps", "POST"), raw, None, self.db)
        self.assertEqual(global_create.exception.status_code, 403)
        denied_request = Request({"type": "http", "method": "GET",
                                  "path": "/api/integrations/apps/app-1", "headers": [],
                                  "path_params": {"app_id": "app-1"},
                                  "client": ("203.0.113.5", 12345)})
        with self.assertRaises(HTTPException) as wrong_ip:
            await integrations.require_scope("apps.read")(denied_request, raw, None, self.db)
        self.assertEqual(wrong_ip.exception.status_code, 403)
        key = await integrations.require_scope("apps.read")(
            self._request("/api/integrations/apps/app-1", app_id="app-1"), raw, None, self.db)
        self.assertEqual(key["app_id"], "app-1")
        async with self.db.execute("SELECT usage_count,last_ip FROM api_keys WHERE id='api-test'") as cur:
            usage = await cur.fetchone()
        self.assertEqual((usage["usage_count"], usage["last_ip"]), (1, "127.0.0.1"))

    async def test_api_key_rate_limit_is_enforced_atomically(self):
        raw = await self._owner_api_key("apps.read")
        await self.db.execute(
            "UPDATE api_keys SET rate_limit_per_minute=2 WHERE id='api-test'"
        )
        await self.db.commit()
        dependency = integrations.require_scope("apps.read")
        request = self._request("/api/integrations/apps/app-1", app_id="app-1")
        first = await dependency(request, raw, None, self.db)
        second = await dependency(request, raw, None, self.db)
        self.assertEqual(first["rate_limit_remaining"], 1)
        self.assertEqual(second["rate_limit_remaining"], 0)
        with self.assertRaises(HTTPException) as limited:
            await dependency(request, raw, None, self.db)
        self.assertEqual(limited.exception.status_code, 429)
        self.assertEqual(limited.exception.headers["X-RateLimit-Remaining"], "0")
        self.assertEqual(limited.exception.headers["X-RateLimit-Limit"], "2")
        self.assertGreaterEqual(int(limited.exception.headers["Retry-After"]), 1)
        self.assertLessEqual(int(limited.exception.headers["Retry-After"]), 60)
        async with self.db.execute(
            "SELECT usage_count,rate_window_count FROM api_keys WHERE id='api-test'"
        ) as cur:
            usage = await cur.fetchone()
        self.assertEqual((usage["usage_count"], usage["rate_window_count"]), (2, 2))

    async def test_narrow_resource_scopes_authorize_only_matching_routes(self):
        raw = await self._owner_api_key("logs.read")
        request = self._request("/api/integrations/apps/app-1/logs", app_id="app-1")
        authorized = await integrations.require_scope("logs.read")(request, raw, None, self.db)
        self.assertEqual(authorized["scopes"], "logs.read")
        with self.assertRaises(HTTPException) as denied:
            await integrations.require_scope("builds.read")(request, raw, None, self.db)
        self.assertEqual(denied.exception.status_code, 403)
        self.assertTrue(integrations.has_scope({"scopes": "read"}, "sessions.read"))
        self.assertTrue(integrations.has_scope({"scopes": "write"}, "sessions.modify"))
        self.assertTrue(integrations.has_scope({"scopes": "write"}, "news.modify"))
        self.assertFalse(integrations.has_scope({"scopes": "write"}, "news.delete"))
        self.assertFalse(integrations.has_scope({"scopes": "write"}, "variables.secrets"))

    async def test_narrow_key_can_inspect_itself_without_apps_read(self):
        raw = await self._owner_api_key("licenses.generate")
        await self.db.execute("UPDATE api_keys SET app_id='app-1' WHERE id='api-test'")
        await self.db.commit()
        request = self._request("/api/integrations/credential")
        key = await integrations.require_scope()(request, raw, None, self.db)
        document = await integrations.integration_credential(key)
        self.assertEqual(document["app_id"], "app-1")
        self.assertTrue(document["policy"]["app_bound"])
        self.assertTrue(document["capabilities"]["licenses.generate"])
        self.assertFalse(document["capabilities"]["apps.read"])
        self.assertNotIn("key_hash", str(document))
        app_document = await integrations.integration_capabilities("app-1", key, self.db)
        self.assertEqual(app_document["app_id"], "app-1")
        with self.assertRaises(HTTPException) as foreign:
            await integrations.require_scope()(
                self._request("/api/integrations/apps/app-2/capabilities", app_id="app-2"),
                raw, None, self.db,
            )
        self.assertEqual(foreign.exception.status_code, 403)

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

    async def test_ambiguous_dual_integration_credentials_are_rejected(self):
        with self.assertRaises(HTTPException) as error:
            await integrations.require_scope("apps.read")(
                self._request("/api/integrations/apps/app-1", app_id="app-1"),
                "enauth_" + "a" * 43,
                "enauth_discord_" + "d" * 43,
                self.db,
            )
        self.assertEqual(error.exception.status_code, 400)

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
        self.assertTrue(integrations.has_scope({"scopes": "write"}, "licenses.modify"))
        self.assertFalse(integrations.has_scope({"scopes": "write"}, "licenses.delete"))
        self.assertTrue(integrations.has_scope({"scopes": "licenses.delete"}, "licenses.delete"))
        self.assertFalse(integrations.has_scope({"scopes": "write"}, "products.delete"))
        self.assertTrue(integrations.has_scope({"scopes": "products.*"}, "products.delete"))
        self.assertFalse(integrations.has_scope({"scopes": "write"}, "apps.secrets"))
        self.assertTrue(integrations.has_scope({"scopes": "apps.secrets"}, "apps.secrets"))

    async def test_generation_idempotency_replays_same_encrypted_keys(self):
        body = integrations.GenerateBody(
            product_level="one", duration_hours=24, count=2, max_hwids=2,
            notes="idempotent batch",
        )
        first = await integrations.generate(
            "app-1", body, "generation-request-0001", self.api_key, self.db,
        )
        second = await integrations.generate(
            "app-1", body, "generation-request-0001", self.api_key, self.db,
        )
        self.assertEqual(second, first)
        async with self.db.execute("SELECT COUNT(*) FROM licenses WHERE app_id='app-1'") as cur:
            self.assertEqual((await cur.fetchone())[0], 4)
        async with self.db.execute(
            "SELECT result_json FROM api_idempotency_keys WHERE operation='licenses.generate'"
        ) as cur:
            reference = (await cur.fetchone())["result_json"]
        for item in first["created"]:
            self.assertNotIn(item["key"], reference)
            self.assertIn(item["id"], reference)

        with self.assertRaises(HTTPException) as conflict:
            await integrations.generate(
                "app-1", integrations.GenerateBody(product_level="one", count=1),
                "generation-request-0001", self.api_key, self.db,
            )
        self.assertEqual(conflict.exception.status_code, 409)
        async with self.db.execute("SELECT COUNT(*) FROM licenses WHERE app_id='app-1'") as cur:
            self.assertEqual((await cur.fetchone())[0], 4)

        with self.assertRaises(HTTPException) as invalid:
            await integrations.generate("app-1", body, "short", self.api_key, self.db)
        self.assertEqual(invalid.exception.status_code, 400)

    async def test_variable_scopes_keep_secret_values_separate(self):
        await self.db.execute(
            "INSERT INTO variables(id,name,value,is_secret) VALUES('var-secret','TOKEN','top-secret',1)"
        )
        await self.db.commit()
        read_key = {"id": "reader", "scopes": "variables.read"}
        rows = await integrations.variables(read_key, self.db)
        self.assertEqual(rows[0]["value"], "<secret>")
        reveal_key = {"id": "revealer", "scopes": "variables.read,variables.secrets"}
        rows = await integrations.variables(reveal_key, self.db)
        self.assertEqual(rows[0]["value"], "top-secret")

        modify_key = {"id": "modifier", "scopes": "variables.modify"}
        await integrations.set_variable(
            integrations.NamedValueBody(name="PUBLIC", value="visible", is_secret=False),
            modify_key, self.db,
        )
        with self.assertRaises(HTTPException) as secret_denied:
            await integrations.set_variable(
                integrations.NamedValueBody(name="PRIVATE", value="hidden", is_secret=True),
                modify_key, self.db,
            )
        self.assertEqual(secret_denied.exception.status_code, 403)
        with self.assertRaises(HTTPException) as declassify_denied:
            await integrations.set_variable(
                integrations.NamedValueBody(name="TOKEN", value="replacement", is_secret=False),
                modify_key, self.db,
            )
        self.assertEqual(declassify_denied.exception.status_code, 403)
        secret_key = {"id": "secret-writer", "scopes": "variables.modify,variables.secrets"}
        result = await integrations.set_variable(
            integrations.NamedValueBody(name="PRIVATE", value="hidden", is_secret=True),
            secret_key, self.db,
        )
        self.assertTrue(result["ok"])

    async def test_read_scope_can_inspect_level_metadata_without_secret_fields(self):
        read_key = {"id": "api-read", "role": "owner", "scopes": "licenses.read"}
        details = await integrations.license_details("app-1", self.keys[0], read_key, self.db)
        self.assertFalse(details["key_revealed"])
        self.assertEqual(details["key"], mask_license_key(self.keys[0]))
        self.assertEqual(details["levels"], ["one"])
        self.assertEqual(details["products"][0]["name"], "One")
        self.assertNotIn("key_hash", details)
        self.assertNotIn("key_ciphertext", details)
        self.assertNotIn("client_password_hash", details)
        self.assertNotIn("never-return-this", str(details))

        rows = await integrations.licenses("app-1", None, 25, read_key, self.db)
        first = next(row for row in rows if row["id"] == "license-1")
        self.assertEqual(first["levels"], ["one"])
        self.assertEqual(first["products"][0]["level"], "one")

        reveal_key = {"id": "api-reveal", "role": "owner",
                      "scopes": "licenses.read,licenses.reveal"}
        revealed = await integrations.license_details("app-1", "license-1", reveal_key, self.db)
        self.assertTrue(revealed["key_revealed"])
        self.assertEqual(revealed["key"], self.keys[0])

    async def test_license_inventory_supports_stable_pagination_and_filters(self):
        await self.db.execute("UPDATE licenses SET status='banned' WHERE id='license-2'")
        await self.db.execute(
            "INSERT INTO license_products(id,license_id,product_id) VALUES('ent-two-page','license-2','product-2')"
        )
        await self.db.commit()
        read_key = {"id": "page-reader", "scopes": "licenses.read"}
        first = await integrations.license_page(
            "app-1", limit=1, offset=0, _key=read_key, db=self.db,
        )
        self.assertEqual(first["pagination"]["total"], 2)
        self.assertTrue(first["pagination"]["has_more"])
        self.assertEqual(first["pagination"]["next_offset"], 1)
        second = await integrations.license_page(
            "app-1", limit=1, offset=1, _key=read_key, db=self.db,
        )
        self.assertNotEqual(first["items"][0]["id"], second["items"][0]["id"])
        self.assertFalse(second["pagination"]["has_more"])

        banned = await integrations.license_page(
            "app-1", status="banned", product_level="two", _key=read_key, db=self.db,
        )
        self.assertEqual(banned["pagination"]["total"], 1)
        self.assertEqual(banned["items"][0]["id"], "license-2")
        self.assertEqual(set(banned["items"][0]["levels"]), {"one", "two"})
        legacy_page = await integrations.licenses(
            "app-1", None, 1, read_key, self.db, offset=1,
        )
        self.assertEqual(legacy_page[0]["id"], second["items"][0]["id"])
        with self.assertRaises(HTTPException) as invalid:
            await integrations.license_page(
                "app-1", status="unknown", _key=read_key, db=self.db,
            )
        self.assertEqual(invalid.exception.status_code, 400)

    async def test_blacklist_alias_revokes_and_restores_license(self):
        modified = await integrations.blacklist("app-1", "license-1", self.api_key, self.db)
        self.assertEqual(modified["status"], "banned")
        async with self.db.execute("SELECT status FROM licenses WHERE id='license-1'") as cur:
            self.assertEqual((await cur.fetchone())["status"], "banned")
        restored = await integrations.unblacklist("app-1", "license-1", self.api_key, self.db)
        self.assertEqual(restored["status"], "active")

    async def test_bulk_license_actions_are_atomic_and_clean_related_state(self):
        body = integrations.BulkLicenseBody(
            identifiers=["license-1", "license-2", "license-1"]
        )
        with self.assertRaises(HTTPException) as missing:
            await integrations.bulk_blacklist(
                "app-1", integrations.BulkLicenseBody(
                    identifiers=["license-1", "missing-license"]
                ),
                self.api_key, self.db,
            )
        self.assertEqual(missing.exception.status_code, 404)
        async with self.db.execute("SELECT status FROM licenses WHERE id='license-1'") as cur:
            self.assertEqual((await cur.fetchone())["status"], "active")

        blacklisted = await integrations.bulk_blacklist("app-1", body, self.api_key, self.db)
        self.assertEqual(blacklisted["affected"], 2)
        restored = await integrations.bulk_unblacklist("app-1", body, self.api_key, self.db)
        self.assertEqual(restored["affected"], 2)
        await self.db.executemany(
            "INSERT INTO hwids(license_id,hwid_hash) VALUES(?,?)",
            [("license-1", "1" * 64), ("license-2", "2" * 64)],
        )
        await self.db.executemany(
            "INSERT INTO device_fingerprints(id,license_id,fingerprint) VALUES(?,?,?)",
            [("fp-1", "license-1", "fingerprint-1"),
             ("fp-2", "license-2", "fingerprint-2")],
        )
        await self.db.commit()
        reset = await integrations.bulk_reset_hwid("app-1", body, self.api_key, self.db)
        self.assertEqual(reset["affected"], 2)
        for table in ("hwids", "device_fingerprints"):
            async with self.db.execute(f"SELECT COUNT(*) FROM {table}") as cur:
                self.assertEqual((await cur.fetchone())[0], 0)

        with self.assertRaises(ValueError):
            integrations.BulkLicenseDeleteBody(identifiers=["license-1"], confirm="no")
        deleted = await integrations.bulk_delete_licenses(
            "app-1",
            integrations.BulkLicenseDeleteBody(
                identifiers=["license-1", "license-2"], confirm="DELETE"
            ),
            self.api_key, self.db,
        )
        self.assertEqual(deleted["deleted"], 2)
        async with self.db.execute("SELECT COUNT(*) FROM licenses WHERE app_id='app-1'") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)

    async def test_api_key_updates_license_properties_and_revokes_banned_sessions(self):
        await self.db.execute(
            "INSERT INTO hwids(license_id,hwid_hash) VALUES('license-1',?)", ("a" * 64,)
        )
        await self.db.execute(
            """INSERT INTO sessions(id,token,license_id,hwid,ip,app_id,product_id,expires_at)
               VALUES('session-update','token-update','license-1',?,'127.0.0.1','app-1',
                      'product-1',datetime('now','+1 hour'))""",
            ("a" * 64,),
        )
        await self.db.commit()
        allowed = await integrations.update_license(
            "app-1", "license-1", integrations.LicenseUpdateBody(max_hwids=1),
            self.api_key, self.db,
        )
        self.assertEqual(allowed["updated_fields"], ["max_hwids"])

        expiry = datetime.now(timezone.utc) + timedelta(days=30)
        result = await integrations.update_license(
            "app-1", "license-1",
            integrations.LicenseUpdateBody(
                status="banned", expires_at=expiry, max_hwids=2, notes="API managed",
                metadata={"customer": "example", "flags": ["priority"]},
            ),
            self.api_key, self.db,
        )
        self.assertEqual(set(result["updated_fields"]),
                         {"status", "expires_at", "max_hwids", "notes", "metadata"})
        async with self.db.execute("SELECT COUNT(*) FROM sessions WHERE id='session-update'") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        details = await integrations.license_details(
            "app-1", "license-1", {"id": "reader", "scopes": "licenses.read"}, self.db,
        )
        self.assertEqual(details["status"], "banned")
        self.assertEqual(details["max_hwids"], 2)
        self.assertEqual(details["notes"], "API managed")
        self.assertEqual(details["metadata"]["customer"], "example")

    async def test_license_update_rejects_hwid_limit_below_current_bindings(self):
        await self.db.execute("UPDATE licenses SET max_hwids=3 WHERE id='license-1'")
        await self.db.executemany(
            "INSERT INTO hwids(license_id,hwid_hash) VALUES('license-1',?)",
            [("a" * 64,), ("b" * 64,)],
        )
        await self.db.commit()
        with self.assertRaises(HTTPException) as error:
            await integrations.update_license(
                "app-1", "license-1", integrations.LicenseUpdateBody(max_hwids=1),
                self.api_key, self.db,
            )
        self.assertEqual(error.exception.status_code, 409)

    async def test_api_key_manages_product_level_lifecycle(self):
        created = await integrations.create_product(
            "app-1", integrations.ProductCreateBody(name="Enterprise", level="Enterprise-V1"),
            self.api_key, self.db,
        )
        product_id = created["id"]
        self.assertEqual(created["level"], "enterprise-v1")
        await self.db.execute(
            "INSERT INTO license_products(id,license_id,product_id) VALUES(?,?,?)",
            ("ent-enterprise", "license-1", product_id),
        )
        await self.db.execute(
            """INSERT INTO sessions(id,token,license_id,hwid,ip,app_id,product_id,expires_at)
               VALUES('session-enterprise','token-enterprise','license-1',?,'127.0.0.1',
                      'app-1',?,datetime('now','+1 hour'))""",
            ("e" * 64, product_id),
        )
        await self.db.commit()

        updated = await integrations.update_product(
            "app-1", product_id,
            integrations.ProductUpdateBody(
                name="Enterprise Plus", level="enterprise-v2", is_active=False,
                required_client_version="2.4.0", blocked_client_versions=["2.3.0", "2.3.0"],
                version_kill_switch=True,
            ),
            self.api_key, self.db,
        )
        self.assertEqual(updated["revoked_sessions"], 1)
        products = await integrations.integration_products(
            "app-1", {"id": "reader", "scopes": "products.read"}, self.db,
        )
        enterprise = next(item for item in products if item["id"] == product_id)
        self.assertEqual(enterprise["name"], "Enterprise Plus")
        self.assertEqual(enterprise["level"], "enterprise-v2")
        self.assertEqual(enterprise["blocked_client_versions"], ["2.3.0"])
        self.assertEqual(enterprise["version_kill_switch"], 1)

        with self.assertRaises(HTTPException) as confirmation:
            await integrations.delete_product(
                "app-1", product_id, False, self.api_key, self.db,
            )
        self.assertEqual(confirmation.exception.status_code, 409)
        deleted = await integrations.delete_product(
            "app-1", product_id, True, self.api_key, self.db,
        )
        self.assertEqual(deleted["deleted_entitlements"], 1)
        async with self.db.execute("SELECT COUNT(*) FROM products WHERE id=?", (product_id,)) as cur:
            self.assertEqual((await cur.fetchone())[0], 0)

    async def test_api_key_pauses_and_resumes_one_product_with_compensation(self):
        await self.db.execute(
            """INSERT INTO sessions(id,token,license_id,hwid,ip,app_id,product_id,expires_at)
               VALUES('session-product-pause','token-product-pause','license-1',?,'127.0.0.1',
                      'app-1','product-1',datetime('now','+1 hour'))""",
            ("f" * 64,),
        )
        await self.db.commit()
        paused = await integrations.pause_product(
            "app-1", "product-1", integrations.PauseBody(reason="Product maintenance"),
            self.api_key, self.db,
        )
        self.assertEqual(paused["affected_licenses"], 2)
        self.assertEqual(paused["revoked_sessions"], 1)
        forced_pause = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        await self.db.execute("UPDATE products SET paused_at=? WHERE id='product-1'", (forced_pause,))
        await self.db.commit()
        preview = await integrations.product_resume_preview(
            "app-1", "product-1", 1,
            {"id": "product-reader", "scopes": "products.read"}, self.db,
        )
        self.assertGreaterEqual(preview["downtime_seconds"], 2 * 3600)
        self.assertEqual(preview["compensation_seconds"], 3600)
        resumed = await integrations.resume_product(
            "app-1", "product-1", integrations.ResumeBody(compensation_hours=1),
            self.api_key, self.db,
        )
        self.assertEqual(resumed["level"], "one")
        async with self.db.execute(
            "SELECT is_paused,service_status FROM products WHERE id='product-1'"
        ) as cur:
            state = await cur.fetchone()
        self.assertEqual((state["is_paused"], state["service_status"]), (0, "operational"))

    async def test_api_key_manages_application_lifecycle_and_secret_rotation(self):
        created = await integrations.create_app(
            integrations.AppCreateBody(name="API Application", version="2.0.0"),
            self.api_key, self.db,
        )
        app_id = created["id"]
        initial_secret = created["secret_key"]
        self.assertTrue(created["secret_revealed_once"])
        self.assertGreaterEqual(len(initial_secret), 64)
        updated = await integrations.update_app(
            app_id,
            integrations.AppUpdateBody(
                name="Managed Application", version="2.1.0",
                download_violation_action="warn_ban", download_violation_limit=4,
            ),
            self.api_key, self.db,
        )
        self.assertIn("download_violation_action", updated["updated_fields"])
        rotated = await integrations.rotate_app_secret(app_id, self.api_key, self.db)
        self.assertNotEqual(rotated["secret_key"], initial_secret)
        async with self.db.execute(
            "SELECT name,version,secret_key,download_violation_limit FROM applications WHERE id=?",
            (app_id,),
        ) as cur:
            stored = await cur.fetchone()
        self.assertEqual((stored["name"], stored["version"], stored["download_violation_limit"]),
                         ("Managed Application", "2.1.0", 4))
        self.assertEqual(stored["secret_key"], rotated["secret_key"])

        await self.db.execute(
            "INSERT INTO products(id,app_id,name,level) VALUES('managed-product',?,'Managed','managed')",
            (app_id,),
        )
        await self.db.commit()
        with self.assertRaises(HTTPException) as confirmation:
            await integrations.delete_app(app_id, False, self.api_key, self.db)
        self.assertEqual(confirmation.exception.status_code, 409)
        deleted = await integrations.delete_app(app_id, True, self.api_key, self.db)
        self.assertEqual(deleted["deleted"]["products"], 1)
        async with self.db.execute("SELECT COUNT(*) FROM applications WHERE id=?", (app_id,)) as cur:
            self.assertEqual((await cur.fetchone())[0], 0)

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
        self.assertEqual(result["level"], "two")
        details = await integrations.license_details("app-1", self.keys[0], self.api_key, self.db)
        self.assertEqual({item["product_id"] for item in details["products"]}, {"product-1", "product-2"})

    async def test_api_key_manages_one_level_without_affecting_other_levels(self):
        added = await integrations.add_license_product(
            "app-1", "license-1",
            integrations.EntitlementAddBody(product_id="product-2", duration_hours=48),
            self.api_key, self.db,
        )
        await self.db.execute(
            """INSERT INTO sessions
               (id,token,license_id,hwid,ip,app_id,product_id,expires_at)
               VALUES(?,?,?,?,?,?,?,datetime('now','+1 hour'))""",
            ("session-two", "token-two", "license-1", "h" * 64, "127.0.0.1",
             "app-1", "product-2"),
        )
        await self.db.commit()

        paused = await integrations.pause_license_product(
            "app-1", "license-1", "product-2",
            integrations.PauseBody(reason="Level maintenance"), self.api_key, self.db,
        )
        self.assertEqual(paused["reason"], "Level maintenance")
        async with self.db.execute("SELECT COUNT(*) FROM sessions WHERE id='session-two'") as cur:
            self.assertEqual((await cur.fetchone())[0], 0)
        async with self.db.execute(
            "SELECT is_paused,pause_reason FROM license_products WHERE license_id='license-1' AND product_id='product-2'"
        ) as cur:
            state = await cur.fetchone()
        self.assertEqual((state["is_paused"], state["pause_reason"]), (1, "Level maintenance"))

        forced_pause = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        await self.db.execute(
            "UPDATE license_products SET paused_at=? WHERE license_id='license-1' AND product_id='product-2'",
            (forced_pause,),
        )
        await self.db.commit()
        resumed = await integrations.resume_license_product(
            "app-1", "license-1", "product-2",
            integrations.ResumeBody(compensation_hours=1), self.api_key, self.db,
        )
        self.assertGreaterEqual(resumed["downtime_seconds"], 2 * 3600)
        self.assertEqual(resumed["compensation_seconds"], 3600)
        self.assertEqual(resumed["level"], "two")

        removed = await integrations.remove_license_product(
            "app-1", "license-1", "product-2", self.api_key, self.db,
        )
        self.assertEqual(removed["level"], "two")
        details = await integrations.license_details("app-1", "license-1", self.api_key, self.db)
        self.assertEqual(details["levels"], ["one"])
        self.assertEqual(added["license_id"], details["id"])

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
